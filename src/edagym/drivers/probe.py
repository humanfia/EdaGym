"""Side-effect-bounded module and version probing."""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, SupportsIndex

from edagym.canonical import canonical_digest
from edagym.drivers.closure import (
    ExecutionClosureKind,
    ExecutionClosureRequirementRef,
    ResolvedExecutionClosure,
    SiteContainerExecutionClosure,
    descriptor_execution_closure,
    execution_closure_digest,
    trusted_immutable_executable,
    trusted_path_execution_closure,
)
from edagym.drivers.deployment import (
    BackendDeploymentConfiguration,
    HostModuleConfiguration,
    SiteContainerConfiguration,
)
from edagym.drivers.model import (
    BackendDefinition,
    BackendProbe,
    ExecutableInvocationMode,
    QualificationState,
    UnavailableReason,
    Vendor,
)
from edagym.drivers.rootless_image import (
    RootlessImageConfiguration,
    inspect_rootless_image_tool,
    resolve_rootless_image_execution_closure,
)
from edagym.drivers.site_container import (
    inspect_site_container_tool,
    resolve_site_container_execution_closure,
    site_container_license_environment,
)
from edagym.executors.licenses import LicenseLease, LicenseUnavailable

_BASH = Path("/bin/bash")
_MODULE_INITIALIZER = Path("/etc/profile.d/modules.sh")
VERSION_PROBE_TIMEOUT_SECONDS = 20
_MAX_VERSION_OUTPUT_BYTES = 1024 * 1024


class AuthorizedBackendResolutionReason(StrEnum):
    """Secret-free cause of an authorized commercial resolution failure."""

    BINDING_MISMATCH = "binding_mismatch"
    LICENSE_LEASE_UNAVAILABLE = "license_lease_unavailable"
    MODULE_METADATA_UNAVAILABLE = "module_metadata_unavailable"
    MODULE_METADATA_CHANGED = "module_metadata_changed"
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    EXECUTABLE_IDENTITY_CHANGED = "executable_identity_changed"
    HOST_RUNTIME_DEPENDENCY_UNAVAILABLE = "host_runtime_dependency_unavailable"
    VERSION_PROBE_FAILED = "version_probe_failed"
    EULA_ACCEPTANCE_REQUIRED = "eula_acceptance_required"


class AuthorizedBackendResolutionError(RuntimeError):
    """An explicitly authorized commercial installation could not be resolved."""

    def __init__(self, reason: AuthorizedBackendResolutionReason) -> None:
        self.reason = reason
        super().__init__(f"authorized commercial resolution failed: {reason.value}")


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedInstallation:
    definition: BackendDefinition
    module_name: str | None
    executable_name: str
    environment: dict[str, str]
    version_label: str
    modulefile_digest: str | None
    version_output_digest: str
    execution_closure: ResolvedExecutionClosure
    deployment_record_digest: str | None = None

    @property
    def executable_path(self) -> Path:
        return self.execution_closure.entrypoint_path

    @property
    def executable_digest(self) -> str:
        return self.execution_closure.evidence.entrypoint_digest

    @property
    def executable_invocation_mode(self) -> ExecutableInvocationMode:
        modes = {
            ExecutionClosureKind.DESCRIPTOR: ExecutableInvocationMode.DESCRIPTOR_BOUND,
            ExecutionClosureKind.ROOTLESS_IMAGE: ExecutableInvocationMode.ROOTLESS_IMAGE,
            ExecutionClosureKind.TRUSTED_PATH: ExecutableInvocationMode.TRUSTED_PATH,
            ExecutionClosureKind.SITE_CONTAINER: ExecutableInvocationMode.SITE_CONTAINER,
        }
        return modes[self.execution_closure.evidence.kind]

    @property
    def execution_closure_digest(self) -> str:
        return execution_closure_digest(self.execution_closure.evidence)

    @property
    def package_manifest_digest(self) -> str | None:
        runtime = self.execution_closure.rootless_image_runtime
        return None if runtime is None else runtime.package_manifest_digest

    @property
    def deployment_attestation_digest(self) -> str:
        return deployment_attestation_digest(
            tool_id=self.definition.tool_id,
            driver_digest=self.definition.driver_digest,
            deployment_record_digest=self.deployment_record_digest,
            tool_version=self.version_label,
            executable_digest=self.executable_digest,
            execution_closure_digest_value=self.execution_closure_digest,
            version_output_digest=self.version_output_digest,
            modulefile_digest=self.modulefile_digest,
            invocation_mode=self.executable_invocation_mode,
            package_manifest_digest=self.package_manifest_digest,
        )

    def __repr__(self) -> str:
        return (
            "ResolvedInstallation("
            f"tool_id={self.definition.tool_id!r}, "
            f"version_label={self.version_label!r}, "
            "selection=<restricted>, environment=<restricted>)"
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("resolved backend installations cannot be serialized")


def probe_backend(
    definition: BackendDefinition,
    *,
    deployment_configuration: BackendDeploymentConfiguration | None = None,
    rootless_image_configuration: RootlessImageConfiguration | None = None,
) -> tuple[BackendProbe, ResolvedInstallation | None]:
    """Resolve one backend only from explicit deployment state or fixed system paths."""

    if definition.vendor is not Vendor.OPEN_SOURCE:
        return _probe_commercial_metadata(definition, deployment_configuration), None

    if deployment_configuration is not None and rootless_image_configuration is not None:
        return _probe_failure(definition, UnavailableReason.POLICY_UNAVAILABLE), None
    if rootless_image_configuration is not None:
        resolved = _resolve_rootless_image(definition, rootless_image_configuration)
        if resolved is None:
            return _probe_failure(definition, UnavailableReason.VERSION_PROBE_FAILED), None
        return _probe_success(definition, resolved), resolved

    if deployment_configuration is not None:
        if (
            not isinstance(deployment_configuration, HostModuleConfiguration)
            or deployment_configuration.tool_id != definition.tool_id
            or not deployment_configuration.revalidate()
        ):
            return _probe_failure(definition, UnavailableReason.POLICY_UNAVAILABLE), None
        module_name = deployment_configuration.module_name
        if not _module_available(module_name):
            return _probe_failure(definition, UnavailableReason.MODULE_UNAVAILABLE), None
        try:
            resolved, executable_found = _resolve_module(
                definition,
                module_name,
                deployment_record_digest=deployment_configuration.deployment_digest,
            )
        except subprocess.CalledProcessError:
            return _probe_failure(definition, UnavailableReason.MODULE_LOAD_FAILED), None
        if resolved is not None:
            return _probe_success(definition, resolved), resolved
        reason = (
            UnavailableReason.VERSION_PROBE_FAILED
            if executable_found
            else UnavailableReason.EXECUTABLE_UNAVAILABLE
        )
        return _probe_failure(definition, reason), None

    saw_executable = False
    for executable_name in definition.executable_candidates:
        executable = shutil.which(executable_name, path="/usr/local/bin:/usr/bin:/bin")
        if executable is None:
            continue
        saw_executable = True
        resolved = _resolve_direct(definition, executable_name, Path(executable))
        if resolved is not None:
            return _probe_success(definition, resolved), resolved
    reason = (
        UnavailableReason.VERSION_PROBE_FAILED
        if saw_executable
        else UnavailableReason.EXECUTABLE_UNAVAILABLE
    )
    return _probe_failure(definition, reason), None


def _resolve_rootless_image(
    definition: BackendDefinition,
    configuration: RootlessImageConfiguration,
) -> ResolvedInstallation | None:
    recipe = configuration.recipe
    if (
        len(definition.executable_candidates) != 1
        or Path(recipe.tool_entrypoint).name != definition.executable_candidates[0]
    ):
        return None
    requirement = ExecutionClosureRequirementRef(
        requirement_id=f"{definition.tool_id}_rootless_image",
        requirement_digest=recipe.requirement_digest,
    )
    closure = resolve_rootless_image_execution_closure(
        requirement,
        configuration,
        scratch_root=_probe_scratch_root(),
    )
    if closure is None:
        return None
    version_output = inspect_rootless_image_tool(
        closure,
        configuration,
        definition.version_arguments,
        accepted_exit_codes=definition.accepted_version_exit_codes,
        scratch_root=_probe_scratch_root(),
    )
    if version_output is None:
        return None
    version_identity = _version_identity(version_output, definition.version_identity_pattern)
    if version_identity is None:
        return None
    runtime = closure.rootless_image_runtime
    if runtime is None or not configuration.revalidate() or not closure.revalidate():
        return None
    executable_name = definition.executable_candidates[0]
    version_label = _version_label(version_identity)
    return ResolvedInstallation(
        definition=definition,
        module_name=None,
        executable_name=executable_name,
        environment=dict(runtime.host_environment),
        version_label=version_label,
        modulefile_digest=None,
        version_output_digest=_version_probe_digest(
            definition,
            executable_name=executable_name,
            executable_digest=closure.evidence.entrypoint_digest,
            module_name=None,
            modulefile_digest=None,
            version_label=version_label,
            version_identity=version_identity,
            execution_closure_digest=execution_closure_digest(closure.evidence),
        ),
        execution_closure=closure,
        deployment_record_digest=recipe.requirement_digest,
    )


def resolve_authorized_commercial_backend(
    definition: BackendDefinition,
    metadata_probe: BackendProbe,
    license_lease: LicenseLease,
    *,
    deployment_configuration: BackendDeploymentConfiguration,
) -> tuple[BackendProbe, ResolvedInstallation]:
    """Resolve and version a commercial tool only under an active opaque lease."""

    if definition.workload_use_requires_eula_acceptance:
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.EULA_ACCEPTANCE_REQUIRED
        )
    if (
        definition.vendor is Vendor.OPEN_SOURCE
        or metadata_probe.state is not QualificationState.DETECTED
        or metadata_probe.tool_id != definition.tool_id
        or metadata_probe.vendor is not definition.vendor
        or metadata_probe.capabilities != definition.capabilities
        or metadata_probe.host_support_mode is not definition.host_support_mode
        or metadata_probe.driver_digest != definition.driver_digest
        or deployment_configuration.tool_id != definition.tool_id
        or not deployment_configuration.revalidate()
    ):
        raise AuthorizedBackendResolutionError(AuthorizedBackendResolutionReason.BINDING_MISMATCH)
    try:
        environment = license_lease._process_environment()
    except LicenseUnavailable:
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.LICENSE_LEASE_UNAVAILABLE
        ) from None

    module_name = deployment_configuration.module_name
    try:
        current_module_digest = _digest_bytes(_module_show(module_name))
    except (OSError, subprocess.SubprocessError):
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.MODULE_METADATA_UNAVAILABLE
        ) from None
    if metadata_probe.deployment_attestation_digest != _metadata_attestation_digest(
        definition,
        deployment_configuration,
        current_module_digest,
    ):
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.MODULE_METADATA_CHANGED
        )
    resolved = _resolve_authorized_environment(
        definition,
        module_name,
        current_module_digest,
        environment,
        deployment_configuration=deployment_configuration,
    )
    if not deployment_configuration.revalidate():
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.EXECUTABLE_IDENTITY_CHANGED
        )
    return _probe_success(definition, resolved), resolved


def _probe_commercial_metadata(
    definition: BackendDefinition,
    configuration: BackendDeploymentConfiguration | None,
) -> BackendProbe:
    if (
        configuration is None
        or configuration.tool_id != definition.tool_id
        or not configuration.revalidate()
    ):
        return _probe_failure(definition, UnavailableReason.POLICY_UNAVAILABLE)
    module_name = configuration.module_name
    if not _module_available(module_name):
        return _probe_failure(definition, UnavailableReason.MODULE_UNAVAILABLE)
    try:
        modulefile_digest = _digest_bytes(_module_show(module_name))
    except subprocess.CalledProcessError:
        return _probe_failure(definition, UnavailableReason.MODULE_LOAD_FAILED)
    if not configuration.revalidate():
        return _probe_failure(definition, UnavailableReason.POLICY_UNAVAILABLE)
    return BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.DETECTED,
        deployment_attestation_digest=_metadata_attestation_digest(
            definition,
            configuration,
            modulefile_digest,
        ),
        host_support_mode=definition.host_support_mode,
        driver_digest=definition.driver_digest,
    )


def _probe_success(
    definition: BackendDefinition,
    resolved: ResolvedInstallation,
) -> BackendProbe:
    return BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.INVOCABLE,
        tool_version=resolved.version_label,
        deployment_attestation_digest=resolved.deployment_attestation_digest,
        host_support_mode=definition.host_support_mode,
        driver_digest=definition.driver_digest,
    )


def _metadata_attestation_digest(
    definition: BackendDefinition,
    configuration: BackendDeploymentConfiguration,
    modulefile_digest: str,
) -> str:
    return canonical_digest(
        {
            "tool_id": definition.tool_id,
            "driver_digest": definition.driver_digest,
            "deployment_id": configuration.deployment_id,
            "deployment_digest": configuration.deployment_digest,
            "modulefile_digest": modulefile_digest,
        },
        domain="backend-deployment-metadata-attestation-v1",
    )


def deployment_attestation_digest(
    *,
    tool_id: str,
    driver_digest: str,
    deployment_record_digest: str | None,
    tool_version: str,
    executable_digest: str,
    execution_closure_digest_value: str,
    version_output_digest: str,
    modulefile_digest: str | None,
    invocation_mode: ExecutableInvocationMode,
    package_manifest_digest: str | None = None,
) -> str:
    """Derive the opaque public identity of one exact resolved installation."""

    return canonical_digest(
        {
            "tool_id": tool_id,
            "driver_digest": driver_digest,
            "deployment_record_digest": deployment_record_digest,
            "tool_version": tool_version,
            "executable_digest": executable_digest,
            "execution_closure_digest": execution_closure_digest_value,
            "version_output_digest": version_output_digest,
            "modulefile_digest": modulefile_digest,
            "invocation_mode": invocation_mode,
            "package_manifest_digest": package_manifest_digest,
        },
        domain="backend-deployment-attestation-v1",
    )


def _probe_failure(
    definition: BackendDefinition,
    reason: UnavailableReason,
) -> BackendProbe:
    return BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.UNAVAILABLE,
        host_support_mode=definition.host_support_mode,
        driver_digest=definition.driver_digest,
        reason=reason,
    )


def _module_available(module_name: str) -> bool:
    command = (
        "source /etc/profile.d/modules.sh >/dev/null 2>&1 && "
        'module -t avail "$1" 2>&1 | grep -Fx -- "$1" >/dev/null'
    )
    result = subprocess.run(
        (_BASH, "--noprofile", "--norc", "-c", command, "edagym-module", module_name),
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd="/",
        timeout=VERSION_PROBE_TIMEOUT_SECONDS,
        check=False,
    )
    return result.returncode == 0


def _resolve_module(
    definition: BackendDefinition,
    module_name: str,
    *,
    deployment_record_digest: str,
) -> tuple[ResolvedInstallation | None, bool]:
    executable_found = False
    for executable_name in definition.executable_candidates:
        environment = _module_environment(module_name)
        executable = _module_command_path(module_name, executable_name)
        if executable is None:
            continue
        executable_found = True
        inspection = _inspect_executable(
            executable,
            definition.version_arguments,
            environment,
            definition.version_identity_pattern,
            accepted_exit_codes=definition.accepted_version_exit_codes,
        )
        if inspection is None:
            continue
        version_identity, executable_digest = inspection
        execution_closure = descriptor_execution_closure(executable, executable_digest)
        module_show = _module_show(module_name)
        modulefile_digest = _digest_bytes(module_show)
        version_label = _version_label(version_identity)
        return ResolvedInstallation(
            definition=definition,
            module_name=module_name,
            executable_name=executable_name,
            environment=environment,
            version_label=version_label,
            modulefile_digest=modulefile_digest,
            version_output_digest=_version_probe_digest(
                definition,
                executable_name=executable_name,
                executable_digest=executable_digest,
                module_name=module_name,
                modulefile_digest=modulefile_digest,
                version_label=version_label,
                version_identity=version_identity,
                execution_closure_digest=execution_closure_digest(execution_closure.evidence),
            ),
            execution_closure=execution_closure,
            deployment_record_digest=deployment_record_digest,
        ), True
    return None, executable_found


def _resolve_authorized_environment(
    definition: BackendDefinition,
    module_name: str,
    modulefile_digest: str,
    environment: dict[str, str],
    *,
    deployment_configuration: BackendDeploymentConfiguration,
) -> ResolvedInstallation:
    if isinstance(deployment_configuration, SiteContainerConfiguration):
        configuration = deployment_configuration
        requirement = configuration.requirement
        required_closure = resolve_site_container_execution_closure(
            requirement,
            configuration,
            modulefile_digest=modulefile_digest,
            source_environment=environment,
        )
        if required_closure is None:
            raise AuthorizedBackendResolutionError(
                AuthorizedBackendResolutionReason.HOST_RUNTIME_DEPENDENCY_UNAVAILABLE
            )
        version_output = inspect_site_container_tool(
            required_closure,
            configuration,
            definition.version_arguments,
            _probe_scratch_root(),
            site_container_license_environment(environment),
            accepted_exit_codes=definition.accepted_version_exit_codes,
        )
        if version_output is None:
            raise AuthorizedBackendResolutionError(
                AuthorizedBackendResolutionReason.VERSION_PROBE_FAILED
            )
        version_identity = _version_identity(
            version_output,
            definition.version_identity_pattern,
        )
        if version_identity is None:
            raise AuthorizedBackendResolutionError(
                AuthorizedBackendResolutionReason.VERSION_PROBE_FAILED
            )
        if not required_closure.revalidate():
            raise AuthorizedBackendResolutionError(
                AuthorizedBackendResolutionReason.EXECUTABLE_IDENTITY_CHANGED
            )
        evidence = required_closure.evidence
        if not isinstance(evidence, SiteContainerExecutionClosure):
            raise AuthorizedBackendResolutionError(
                AuthorizedBackendResolutionReason.EXECUTABLE_IDENTITY_CHANGED
            )
        runtime = required_closure.site_container_runtime
        if runtime is None:
            raise AuthorizedBackendResolutionError(
                AuthorizedBackendResolutionReason.EXECUTABLE_IDENTITY_CHANGED
            )
        executable_name = definition.executable_candidates[0]
        version_label = _version_label(version_identity)
        return ResolvedInstallation(
            definition=definition,
            module_name=module_name,
            executable_name=executable_name,
            environment=dict(runtime.tool_environment),
            version_label=version_label,
            modulefile_digest=modulefile_digest,
            version_output_digest=_version_probe_digest(
                definition,
                executable_name=executable_name,
                executable_digest=evidence.entrypoint_digest,
                module_name=module_name,
                modulefile_digest=modulefile_digest,
                version_label=version_label,
                version_identity=version_identity,
                execution_closure_digest=execution_closure_digest(evidence),
            ),
            execution_closure=required_closure,
            deployment_record_digest=configuration.deployment_digest,
        )
    search_path = environment.get("PATH", "")
    executable_found = False
    missing_runtime_dependency = False
    for executable_name in definition.executable_candidates:
        executable_value = shutil.which(executable_name, path=search_path)
        if executable_value is None:
            continue
        executable_found = True
        executable = Path(executable_value)
        if _has_missing_absolute_script_interpreter(executable):
            missing_runtime_dependency = True
            continue
        inspection = _inspect_executable(
            executable,
            definition.version_arguments,
            environment,
            definition.version_identity_pattern,
            accepted_exit_codes=definition.accepted_version_exit_codes,
        )
        execution_closure: ResolvedExecutionClosure | None = None
        if inspection is None:
            trusted_executable = _trusted_immutable_executable(executable)
            if trusted_executable is not None:
                execution_closure = trusted_path_execution_closure(trusted_executable)
                inspection = _inspect_executable(
                    trusted_executable,
                    definition.version_arguments,
                    environment,
                    definition.version_identity_pattern,
                    accepted_exit_codes=definition.accepted_version_exit_codes,
                    trusted_path=True,
                )
        else:
            trusted_executable = None
        if inspection is None:
            continue
        version_identity, executable_digest = inspection
        if execution_closure is None:
            execution_closure = descriptor_execution_closure(executable, executable_digest)
        elif execution_closure.evidence.entrypoint_digest != executable_digest:
            continue
        version_label = _version_label(version_identity)
        return ResolvedInstallation(
            definition=definition,
            module_name=module_name,
            executable_name=executable_name,
            environment=environment,
            version_label=version_label,
            modulefile_digest=modulefile_digest,
            version_output_digest=_version_probe_digest(
                definition,
                executable_name=executable_name,
                executable_digest=executable_digest,
                module_name=module_name,
                modulefile_digest=modulefile_digest,
                version_label=version_label,
                version_identity=version_identity,
                execution_closure_digest=execution_closure_digest(execution_closure.evidence),
            ),
            execution_closure=execution_closure,
            deployment_record_digest=deployment_configuration.deployment_digest,
        )
    if not executable_found:
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.EXECUTABLE_UNAVAILABLE
        )
    if missing_runtime_dependency:
        raise AuthorizedBackendResolutionError(
            AuthorizedBackendResolutionReason.HOST_RUNTIME_DEPENDENCY_UNAVAILABLE
        )
    raise AuthorizedBackendResolutionError(AuthorizedBackendResolutionReason.VERSION_PROBE_FAILED)


def _resolve_direct(
    definition: BackendDefinition,
    executable_name: str,
    executable: Path,
) -> ResolvedInstallation | None:
    environment = _clean_environment()
    inspection = _inspect_executable(
        executable,
        definition.version_arguments,
        environment,
        definition.version_identity_pattern,
        accepted_exit_codes=definition.accepted_version_exit_codes,
    )
    if inspection is None:
        return None
    version_identity, executable_digest = inspection
    execution_closure = descriptor_execution_closure(executable, executable_digest)
    version_label = _version_label(version_identity)
    return ResolvedInstallation(
        definition=definition,
        module_name=None,
        executable_name=executable_name,
        environment=environment,
        version_label=version_label,
        modulefile_digest=None,
        version_output_digest=_version_probe_digest(
            definition,
            executable_name=executable_name,
            executable_digest=executable_digest,
            module_name=None,
            modulefile_digest=None,
            version_label=version_label,
            version_identity=version_identity,
            execution_closure_digest=execution_closure_digest(execution_closure.evidence),
        ),
        execution_closure=execution_closure,
    )


def _module_environment(module_name: str) -> dict[str, str]:
    command = 'source /etc/profile.d/modules.sh >/dev/null 2>&1 && module load "$1" && env -0'
    completed = subprocess.run(
        (_BASH, "--noprofile", "--norc", "-c", command, "edagym-module", module_name),
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd="/",
        timeout=VERSION_PROBE_TIMEOUT_SECONDS,
        check=True,
    )
    environment: dict[str, str] = {}
    for item in completed.stdout.split(b"\0"):
        if not item or b"=" not in item:
            continue
        name, value = item.split(b"=", 1)
        decoded_name = name.decode("utf-8")
        if decoded_name in {"BASH_FUNC_module%%", "_"}:
            continue
        environment[decoded_name] = value.decode("utf-8")
    return environment


def _module_command_path(module_name: str, executable_name: str) -> Path | None:
    command = (
        "source /etc/profile.d/modules.sh >/dev/null 2>&1 && "
        'module load "$1" >/dev/null 2>&1 && command -v -- "$2"'
    )
    completed = subprocess.run(
        (
            _BASH,
            "--noprofile",
            "--norc",
            "-c",
            command,
            "edagym-module",
            module_name,
            executable_name,
        ),
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd="/",
        timeout=VERSION_PROBE_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        return None
    candidate = Path(completed.stdout.decode().strip())
    if not candidate.is_absolute() or not candidate.is_file():
        return None
    return candidate


def _module_show(module_name: str) -> bytes:
    command = 'source /etc/profile.d/modules.sh >/dev/null 2>&1 && module --redirect show "$1"'
    completed = subprocess.run(
        (_BASH, "--noprofile", "--norc", "-c", command, "edagym-module", module_name),
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd="/",
        timeout=VERSION_PROBE_TIMEOUT_SECONDS,
        check=True,
    )
    return completed.stdout


def _inspect_executable(
    executable: Path,
    arguments: tuple[str, ...],
    environment: dict[str, str],
    version_identity_pattern: str | None,
    *,
    accepted_exit_codes: tuple[int, ...],
    trusted_path: bool = False,
) -> tuple[bytes, str] | None:
    if trusted_path:
        trusted_executable = _trusted_immutable_executable(executable)
        if trusted_executable is None:
            return None
        executable = trusted_executable
    try:
        descriptor = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with tempfile.TemporaryDirectory(
            prefix="edagym-version-probe-",
            dir=_probe_scratch_root(),
        ) as workspace_name:
            workspace = Path(workspace_name)
            home = workspace / "home"
            temporary = workspace / "tmp"
            home.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            output_path = workspace / "version-output.bin"
            child_environment = dict(environment)
            child_environment.update(
                {
                    "HOME": str(home),
                    "TMPDIR": str(temporary),
                    "XDG_CACHE_HOME": str(home / ".cache"),
                    "XDG_CONFIG_HOME": str(home / ".config"),
                }
            )
            with output_path.open("xb") as output:
                executable_reference = (
                    os.fspath(executable) if trusted_path else f"/proc/self/fd/{descriptor}"
                )
                process = subprocess.Popen(
                    (os.fspath(executable), *arguments),
                    executable=executable_reference,
                    cwd=workspace,
                    env=child_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    pass_fds=(() if trusted_path else (descriptor,)),
                    start_new_session=True,
                    preexec_fn=_apply_probe_limits,
                )
                try:
                    try:
                        exit_code = process.wait(timeout=VERSION_PROBE_TIMEOUT_SECONDS)
                    except subprocess.TimeoutExpired:
                        _kill_process_group(process.pid)
                        process.wait()
                        return None
                finally:
                    _kill_process_group(process.pid)
                    if process.poll() is None:
                        process.wait()
            if exit_code not in accepted_exit_codes:
                return None
            output_descriptor = os.open(
                output_path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                if not stat.S_ISREG(os.fstat(output_descriptor).st_mode):
                    return None
                version = os.read(output_descriptor, _MAX_VERSION_OUTPUT_BYTES + 1)
            finally:
                os.close(output_descriptor)
            if not version.strip() or len(version) > _MAX_VERSION_OUTPUT_BYTES:
                return None
            version = _normalize_version_output(version, process.pid)
            version_identity = _version_identity(version, version_identity_pattern)
            if version_identity is None:
                return None
            if trusted_path and _digest_regular_file(executable) != f"sha256:{digest.hexdigest()}":
                return None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        os.close(descriptor)
    return version_identity, f"sha256:{digest.hexdigest()}"


def _trusted_immutable_executable(path: Path) -> Path | None:
    return trusted_immutable_executable(path)


def _has_missing_absolute_script_interpreter(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            first_line = stream.readline(4096)
    except OSError:
        return False
    if not first_line.startswith(b"#!"):
        return False
    try:
        interpreter = Path(first_line[2:].strip().split(maxsplit=1)[0].decode("utf-8"))
    except (IndexError, UnicodeDecodeError):
        return False
    return interpreter.is_absolute() and not os.access(interpreter, os.X_OK)


def _clean_environment() -> dict[str, str]:
    account_name = pwd.getpwuid(os.getuid()).pw_name
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,95}", account_name) is None:
        raise ValueError("probe account identity is unavailable")
    return {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": account_name,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "USER": account_name,
    }


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _version_label(output: bytes) -> str:
    lines = [line.strip() for line in output.decode("utf-8", errors="replace").splitlines()]
    nonempty = [line for line in lines if line]
    semantic = next(
        (line for line in nonempty if any(character.isalnum() for character in line)),
        nonempty[0],
    )
    return semantic.strip(" *")[:120]


def _normalize_version_output(output: bytes, process_id: int) -> bytes:
    process_token = str(process_id).encode("ascii")
    return re.sub(
        rb"(?<![0-9])" + re.escape(process_token) + rb"(?![0-9])",
        b"PROCESS_ID",
        output,
    )


def _version_identity(output: bytes, pattern: str | None) -> bytes | None:
    if pattern is None:
        return output
    matches = tuple(re.finditer(pattern.encode("ascii"), output, flags=re.MULTILINE))
    if len(matches) != 1:
        return None
    identity = matches[0].group(0).strip()
    return identity or None


def _version_probe_digest(
    definition: BackendDefinition,
    *,
    executable_name: str,
    executable_digest: str,
    module_name: str | None,
    modulefile_digest: str | None,
    version_label: str,
    version_identity: bytes,
    execution_closure_digest: str,
) -> str:
    return canonical_digest(
        {
            "tool_id": definition.tool_id,
            "version_arguments": definition.version_arguments,
            "accepted_version_exit_codes": definition.accepted_version_exit_codes,
            "version_identity_digest": _digest_bytes(version_identity),
            "version_label": version_label,
            "executable_name": executable_name,
            "executable_digest": executable_digest,
            "module_name": module_name,
            "modulefile_digest": modulefile_digest,
            "execution_closure_digest": execution_closure_digest,
        },
        domain="backend-version-probe-v1",
    )


def _digest_regular_file(path: Path) -> str | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def _probe_scratch_root() -> Path:
    root = Path.cwd() / "temp"
    root.mkdir(mode=0o700, exist_ok=True)
    metadata = root.stat()
    if (
        root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise OSError("probe scratch root is not private to the current user")
    return root


def _apply_probe_limits() -> None:
    os.umask(0o077)
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (_MAX_VERSION_OUTPUT_BYTES, _MAX_VERSION_OUTPUT_BYTES),
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _kill_process_group(process_group: int) -> None:
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return
