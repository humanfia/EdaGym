"""Path-free execution-closure evidence with private runtime revalidation."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, SupportsIndex

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.executors.podman import rootless_podman_command
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.environment import (
    ExecutableName,
    FilesystemPolicy,
    FilesystemScope,
    ResourceLimits,
)

_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,95}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MAX_SYMLINK_DEPTH = 32
ROOTLESS_IMAGE_PROBE_LIMITS = ResourceLimits(
    cpu_millicores=4000,
    memory_bytes=8 * 1024**3,
    pids=512,
    disk_bytes=64 * 1024**2,
    wall_seconds=30,
)
ROOTLESS_IMAGE_FILE_SIZE_LIMIT_BYTES = ROOTLESS_IMAGE_PROBE_LIMITS.disk_bytes
_ROOTLESS_SUPERVISOR_ENTRYPOINT = "/usr/bin/python3"


class ExecutionClosureKind(StrEnum):
    DESCRIPTOR = "descriptor"
    ROOTLESS_IMAGE = "rootless_image"
    TRUSTED_PATH = "trusted_path"
    SITE_CONTAINER = "site_container"


class SiteContainerOperatingSystem(StrEnum):
    ORACLE_LINUX_7 = "oraclelinux7"
    ALMA_LINUX_8 = "almalinux8"
    ALMA_LINUX_9 = "almalinux9"


class SiteContainerLauncherKind(StrEnum):
    SITE_WRAPPER = "site_wrapper"
    PODMAN = "podman"


class ClosureComponent(StrictModel):
    role: Identifier
    digest: Digest
    symlink_chain_digest: Digest


class DescriptorExecutionClosure(StrictModel):
    kind: Literal[ExecutionClosureKind.DESCRIPTOR] = ExecutionClosureKind.DESCRIPTOR
    entrypoint_digest: Digest


class TrustedPathExecutionClosure(StrictModel):
    kind: Literal[ExecutionClosureKind.TRUSTED_PATH] = ExecutionClosureKind.TRUSTED_PATH
    entrypoint_digest: Digest
    entrypoint_symlink_chain_digest: Digest
    components: tuple[ClosureComponent, ...] = ()

    @field_validator("components")
    @classmethod
    def normalize_components(
        cls,
        value: tuple[ClosureComponent, ...],
    ) -> tuple[ClosureComponent, ...]:
        roles = [component.role for component in value]
        if len(roles) != len(set(roles)):
            raise ValueError("execution closure component roles must be unique")
        return tuple(sorted(value, key=lambda component: component.role))


class SiteContainerExecutionClosure(StrictModel):
    kind: Literal[ExecutionClosureKind.SITE_CONTAINER] = ExecutionClosureKind.SITE_CONTAINER
    requirement_id: Identifier
    requirement_digest: Digest
    deployment_id: Identifier
    deployment_digest: Digest
    operating_system: SiteContainerOperatingSystem
    launcher_kind: SiteContainerLauncherKind
    launcher_digest: Digest
    launcher_symlink_chain_digest: Digest
    image_inspector_digest: Digest
    image_inspector_symlink_chain_digest: Digest
    image_digest: Digest
    modulefile_digest: Digest
    entrypoint_digest: Digest
    entrypoint_symlink_chain_digest: Digest
    components: tuple[ClosureComponent, ...] = ()
    tool_closure_digest: Digest
    tool_environment_digest: Digest

    @field_validator("components")
    @classmethod
    def normalize_components(
        cls,
        value: tuple[ClosureComponent, ...],
    ) -> tuple[ClosureComponent, ...]:
        roles = [component.role for component in value]
        if len(roles) != len(set(roles)):
            raise ValueError("site-container closure component roles must be unique")
        return tuple(sorted(value, key=lambda component: component.role))

    @model_validator(mode="after")
    def validate_tool_closure_digest(self) -> Self:
        expected = site_tool_closure_digest(
            self.entrypoint_digest,
            self.entrypoint_symlink_chain_digest,
            self.components,
        )
        if self.tool_closure_digest != expected:
            raise ValueError("site-container tool closure digest is not canonical")
        return self


class RootlessImageExecutionClosure(StrictModel):
    """The immutable image closes dependencies; an inventory is additional evidence."""

    kind: Literal[ExecutionClosureKind.ROOTLESS_IMAGE] = ExecutionClosureKind.ROOTLESS_IMAGE
    requirement_id: Identifier
    requirement_digest: Digest
    launcher_digest: Digest
    launcher_symlink_chain_digest: Digest
    image_digest: Digest
    entrypoint_digest: Digest
    entrypoints_digest: Digest
    package_manifest_digest: Digest | None = None


class ImageToolEntrypoint(StrictModel):
    """One private in-image program resolved and hashed by the trusted probe."""

    executable: ExecutableName
    path: Annotated[str, Field(min_length=2, max_length=4096, repr=False)]
    content_digest: Digest

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not path.is_absolute()
            or path.as_posix() != value
            or any(part in {".", ".."} for part in path.parts[1:])
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("an image program requires a normalized absolute entrypoint")
        return value


ExecutionClosure = Annotated[
    DescriptorExecutionClosure
    | RootlessImageExecutionClosure
    | TrustedPathExecutionClosure
    | SiteContainerExecutionClosure,
    Field(discriminator="kind"),
]


class ExecutionClosureRequirementRef(StrictModel):
    """Opaque public identity of a private, deployment-owned closure recipe."""

    requirement_id: Identifier
    requirement_digest: Digest


def _validate_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path == PurePosixPath(".")
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("closure component paths must be normalized and relative")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class ClosureRecipeComponent:
    """Private path recipe component; never embedded in portable models."""

    role: str
    relative_path: str

    def __post_init__(self) -> None:
        if len(self.role) > 96 or _IDENTIFIER.fullmatch(self.role) is None:
            raise ValueError("closure component roles must be normalized identifiers")
        object.__setattr__(self, "relative_path", _validate_relative_path(self.relative_path))

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("execution closure recipes cannot be serialized")


@dataclass(frozen=True, slots=True)
class ClosureEnvironmentBinding:
    """Private mapping from one injected environment name to a closure role."""

    variable_name: str
    component_role: str

    def __post_init__(self) -> None:
        if _ENVIRONMENT_NAME.fullmatch(self.variable_name) is None:
            raise ValueError("closure environment bindings require normalized names")
        if len(self.component_role) > 96 or _IDENTIFIER.fullmatch(self.component_role) is None:
            raise ValueError("closure environment bindings require normalized roles")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("execution closure recipes cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class SiteContainerExecutionRecipe:
    """Private recipe used to resolve a container-bound installation."""

    operating_system: SiteContainerOperatingSystem
    root_environment_variable: str
    entrypoint_relative_path: str
    components: tuple[ClosureRecipeComponent, ...]
    tool_environment_names: tuple[str, ...]
    environment_bindings: tuple[ClosureEnvironmentBinding, ...] = ()

    def __post_init__(self) -> None:
        if _ENVIRONMENT_NAME.fullmatch(self.root_environment_variable) is None:
            raise ValueError("closure roots require a normalized environment variable")
        object.__setattr__(
            self,
            "entrypoint_relative_path",
            _validate_relative_path(self.entrypoint_relative_path),
        )
        roles = [item.role for item in self.components]
        paths = [item.relative_path for item in self.components]
        binding_names = [item.variable_name for item in self.environment_bindings]
        binding_roles = [item.component_role for item in self.environment_bindings]
        environment_names = set(self.tool_environment_names)
        if (
            not self.components
            or len(roles) != len(set(roles))
            or len(paths) != len(set(paths))
            or self.entrypoint_relative_path in set(paths)
            or len(binding_names) != len(set(binding_names))
            or any(role not in set(roles) for role in binding_roles)
            or len(environment_names) != len(self.tool_environment_names)
            or any(_ENVIRONMENT_NAME.fullmatch(name) is None for name in environment_names)
            or self.root_environment_variable in environment_names
            or environment_names & set(binding_names)
        ):
            raise ValueError("site-container closure recipe is not canonical")
        object.__setattr__(self, "components", tuple(sorted(self.components, key=lambda x: x.role)))
        object.__setattr__(self, "tool_environment_names", tuple(sorted(environment_names)))
        object.__setattr__(
            self,
            "environment_bindings",
            tuple(sorted(self.environment_bindings, key=lambda x: x.variable_name)),
        )

    @property
    def requirement_digest(self) -> Digest:
        return canonical_digest(
            {
                "kind": ExecutionClosureKind.SITE_CONTAINER,
                "operating_system": self.operating_system,
                "root_environment_variable": self.root_environment_variable,
                "entrypoint_relative_path": self.entrypoint_relative_path,
                "components": tuple(
                    {"role": item.role, "relative_path": item.relative_path}
                    for item in self.components
                ),
                "tool_environment_names": self.tool_environment_names,
                "environment_bindings": tuple(
                    {
                        "variable_name": item.variable_name,
                        "component_role": item.component_role,
                    }
                    for item in self.environment_bindings
                ),
            },
            domain="execution-closure-requirement-v1",
        )

    def __repr__(self) -> str:
        return "SiteContainerExecutionRecipe(paths=<restricted>, environment=<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("execution closure recipes cannot be serialized")


def site_tool_closure_digest(
    entrypoint_digest: str,
    entrypoint_symlink_chain_digest: str,
    components: tuple[ClosureComponent, ...],
) -> Digest:
    return canonical_digest(
        {
            "entrypoint_digest": entrypoint_digest,
            "entrypoint_symlink_chain_digest": entrypoint_symlink_chain_digest,
            "components": components,
        },
        domain="site-container-tool-closure-v1",
    )


def execution_closure_digest(closure: ExecutionClosure) -> Digest:
    return canonical_digest(closure, domain="execution-closure-v1")


@dataclass(frozen=True, slots=True)
class _ResolvedClosureFile:
    role: str
    path: Path
    digest: str
    symlink_chain_digest: str

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("resolved execution closure files cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class SiteContainerRuntime:
    operating_system: SiteContainerOperatingSystem
    launcher_kind: SiteContainerLauncherKind
    deployment_id: str
    deployment_digest: str
    host_environment: Mapping[str, str]
    tool_environment: Mapping[str, str]
    tool_entrypoint: str
    engine_path: Path
    image_reference: str
    image_digest: str
    container_user: str
    readonly_mounts: tuple[tuple[Path, str], ...]

    def __post_init__(self) -> None:
        if (
            not self.tool_entrypoint.startswith("/")
            or len(self.deployment_id) > 96
            or _IDENTIFIER.fullmatch(self.deployment_id) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.deployment_digest) is None
            or not self.engine_path.is_absolute()
            or not self.image_reference
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_digest) is None
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,95}", self.container_user) is None
            or any(
                not source.is_absolute()
                or not target.startswith("/")
                or "\x00" in target
                or ":" in target
                for source, target in self.readonly_mounts
            )
            or any(
                not name
                or "\x00" in name
                or "=" in name
                or "\x00" in value
                or "\n" in value
                or "\r" in value
                for environment in (
                    self.host_environment,
                    self.tool_environment,
                )
                for name, value in environment.items()
            )
        ):
            raise ValueError("site-container runtime values must be bounded process inputs")
        object.__setattr__(
            self,
            "host_environment",
            MappingProxyType(dict(self.host_environment)),
        )
        object.__setattr__(
            self,
            "tool_environment",
            MappingProxyType(dict(self.tool_environment)),
        )

    def __repr__(self) -> str:
        return (
            "SiteContainerRuntime("
            f"operating_system={self.operating_system.value!r}, "
            "environment=<restricted>, entrypoint=<restricted>, image=<restricted>)"
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("site-container runtime state cannot be serialized")

    def environment_file_bytes(self, license_environment: Mapping[str, str]) -> bytes:
        if set(self.tool_environment) & set(license_environment):
            raise ValueError("license and tool environments must have disjoint ownership")
        if any(
            not name
            or "\x00" in name
            or "=" in name
            or "\x00" in value
            or "\n" in value
            or "\r" in value
            for name, value in license_environment.items()
        ):
            raise ValueError("license environment contains an unsafe process boundary")
        environment = {**self.tool_environment, **license_environment}
        if self.launcher_kind is SiteContainerLauncherKind.PODMAN:
            return "".join(
                f"{name}={value}\n" for name, value in sorted(environment.items())
            ).encode("utf-8")
        return "".join(
            f"export {name}={shlex.quote(value)}\n" for name, value in sorted(environment.items())
        ).encode("utf-8")

    def invocation_arguments(
        self,
        workspace: Path,
        environment_file: Path,
        tool_arguments: tuple[str, ...],
    ) -> tuple[str, ...]:
        return site_container_arguments(
            self.launcher_kind,
            self.operating_system,
            workspace,
            environment_file,
            (self.tool_entrypoint, *tool_arguments),
            image_reference=self.image_reference,
            container_user=self.container_user,
            readonly_mounts=self.readonly_mounts,
        )

    def revalidate_image(self) -> bool:
        try:
            completed = subprocess.run(
                (
                    os.fspath(self.engine_path),
                    "image",
                    "inspect",
                    "--format",
                    "{{.Digest}}",
                    self.image_reference,
                ),
                env=self.host_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd="/",
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0 and completed.stdout.strip() == self.image_digest.encode(
            "ascii"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RootlessImageRuntime:
    """Private rootless runtime state for one immutable open-tool image."""

    engine_path: Path
    host_environment: Mapping[str, str]
    image_reference: str
    image_digest: str
    tool_entrypoint: str
    tool_entrypoint_digest: str
    package_manifest: bytes | None = None
    package_manifest_digest: str | None = None
    supervisor_entrypoint: str = _ROOTLESS_SUPERVISOR_ENTRYPOINT
    supporting_entrypoints: tuple[ImageToolEntrypoint, ...] = ()

    def __post_init__(self) -> None:
        entrypoint = PurePosixPath(self.tool_entrypoint)
        supervisor = PurePosixPath(self.supervisor_entrypoint)
        supporting_names = tuple(item.executable for item in self.supporting_entrypoints)
        if (
            not self.engine_path.is_absolute()
            or not self.image_reference.endswith(f"@{self.image_digest}")
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_digest) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.tool_entrypoint_digest) is None
            or (self.package_manifest is None) != (self.package_manifest_digest is None)
            or (
                self.package_manifest is not None
                and (
                    not self.package_manifest
                    or len(self.package_manifest) > 1024 * 1024
                    or f"sha256:{hashlib.sha256(self.package_manifest).hexdigest()}"
                    != self.package_manifest_digest
                )
            )
            or not entrypoint.is_absolute()
            or any(part in {"", ".", ".."} for part in entrypoint.parts[1:])
            or "\x00" in self.tool_entrypoint
            or not supervisor.is_absolute()
            or any(part in {"", ".", ".."} for part in supervisor.parts[1:])
            or "\x00" in self.supervisor_entrypoint
            or len(supporting_names) != len(set(supporting_names))
            or entrypoint.name in supporting_names
            or any(
                not name
                or "\x00" in name
                or "=" in name
                or "\x00" in value
                or "\n" in value
                or "\r" in value
                for name, value in self.host_environment.items()
            )
        ):
            raise ValueError("rootless-image runtime inputs are not bounded")
        object.__setattr__(
            self,
            "host_environment",
            MappingProxyType(dict(self.host_environment)),
        )
        object.__setattr__(
            self, "supporting_entrypoints",
            tuple(sorted(self.supporting_entrypoints, key=lambda item: item.executable)),
        )

    @property
    def entrypoints_digest(self) -> Digest:
        return canonical_digest(
            {
                "primary": {"path": self.tool_entrypoint, "digest": self.tool_entrypoint_digest},
                "supporting": self.supporting_entrypoints,
                "supervisor": self.supervisor_entrypoint,
            },
            domain="rootless-image-entrypoints-v1",
        )

    def executable_path(self, executable: str) -> str:
        """Resolve only the exact programs already bound by this closure."""

        if executable == PurePosixPath(self.tool_entrypoint).name:
            return self.tool_entrypoint
        for entrypoint in self.supporting_entrypoints:
            if executable == entrypoint.executable:
                return entrypoint.path
        raise ValueError("executable is absent from the image tool closure")

    def __repr__(self) -> str:
        return "RootlessImageRuntime(paths=<restricted>, image=<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("rootless-image runtime state cannot be serialized")

    def invocation_arguments(
        self,
        workspace: Path,
        tool_arguments: tuple[str, ...],
        *,
        resources: ResourceLimits = ROOTLESS_IMAGE_PROBE_LIMITS,
    ) -> tuple[str, ...]:
        return rootless_image_arguments(
            workspace,
            self.image_reference,
            self.tool_entrypoint,
            tool_arguments,
            resources=resources,
        )

    def revalidate_image(self) -> bool:
        try:
            completed = subprocess.run(
                (
                    os.fspath(self.engine_path),
                    "image",
                    "inspect",
                    "--format",
                    "{{.Digest}}",
                    self.image_reference,
                ),
                env=self.host_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd="/",
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0 and completed.stdout.strip() == self.image_digest.encode(
            "ascii"
        )


def rootless_image_arguments(
    workspace: Path,
    image_reference: str,
    entrypoint: str,
    arguments: tuple[str, ...],
    *,
    resources: ResourceLimits = ROOTLESS_IMAGE_PROBE_LIMITS,
) -> tuple[str, ...]:
    """Compile the sole bounded rootless-image invocation."""

    entrypoint_path = PurePosixPath(entrypoint)
    if (
        not workspace.is_absolute()
        or not image_reference
        or "\x00" in image_reference
        or not entrypoint_path.is_absolute()
        or any(part in {"", ".", ".."} for part in entrypoint_path.parts[1:])
        or any("\x00" in item for item in arguments)
    ):
        raise ValueError("rootless-image invocation inputs are not bounded")
    return rootless_podman_command(
        podman_path=Path("/usr/bin/podman"),
        resources=resources,
        filesystem=FilesystemPolicy(workspace_target="/workspace", artifact_target="/artifacts"),
        workspace=workspace,
        artifact_directory=None,
        asset_paths={},
        scope=FilesystemScope.TOOL,
        image=image_reference,
        environment_fd=None,
        executable=entrypoint,
        arguments=arguments,
        exact_entrypoint=True,
        hermetic_process_environment=True,
        private_staging=True,
    )[1:]


def site_container_arguments(
    launcher_kind: SiteContainerLauncherKind,
    operating_system: SiteContainerOperatingSystem,
    workspace: Path,
    environment_file: Path,
    command: tuple[str, ...],
    *,
    image_reference: str | None = None,
    container_user: str | None = None,
    readonly_mounts: tuple[tuple[Path, str], ...] = (),
) -> tuple[str, ...]:
    if (
        not workspace.is_absolute()
        or not environment_file.is_absolute()
        or not command
        or any("\x00" in item for item in command)
    ):
        raise ValueError("site-container invocation inputs must be bounded")
    if launcher_kind is SiteContainerLauncherKind.PODMAN:
        if (
            image_reference is None
            or container_user is None
            or not image_reference
            or not readonly_mounts
        ):
            raise ValueError("direct Podman execution requires an immutable private binding")
        container_workspace = f"/home/{container_user}/work"
        mounts = tuple(
            argument
            for source, target in readonly_mounts
            for argument in ("--volume", f"{source}:{target}:ro")
        )
        return (
            "run",
            "--pull=never",
            "--userns=keep-id",
            "--systemd=false",
            "--cgroups=disabled",
            "--sdnotify=ignore",
            "--network=host",
            "--env-file",
            os.fspath(environment_file),
            *mounts,
            "--volume",
            f"{workspace}:{container_workspace}:rw",
            "--workdir",
            container_workspace,
            image_reference,
            *command,
        )
    if launcher_kind is not SiteContainerLauncherKind.SITE_WRAPPER:
        raise ValueError("unsupported site-container launcher kind")
    return (
        "run",
        "--os",
        operating_system.value,
        "--env",
        os.fspath(environment_file),
        "--workdir",
        os.fspath(workspace),
        "--network",
        "yes",
        "--",
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
        'cd "$HOME/work" && exec "$@"',
        "edagym-tool",
        *command,
    )


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedExecutionClosure:
    """Runtime paths paired exactly with their path-free closure evidence."""

    evidence: ExecutionClosure
    entrypoint_path: Path
    files: tuple[_ResolvedClosureFile, ...]
    site_container_runtime: SiteContainerRuntime | None = None
    rootless_image_runtime: RootlessImageRuntime | None = None

    def __post_init__(self) -> None:
        if not self.entrypoint_path.is_absolute() or not self.files:
            raise ValueError("resolved execution closures require absolute runtime paths")
        entrypoints = [item for item in self.files if item.role == "entrypoint"]
        if len(entrypoints) != 1 or entrypoints[0].path != self.entrypoint_path:
            raise ValueError("resolved execution closure requires one exact entrypoint")
        if isinstance(self.evidence, DescriptorExecutionClosure):
            if (
                self.site_container_runtime is not None
                or self.rootless_image_runtime is not None
                or len(self.files) != 1
                or entrypoints[0].digest != self.evidence.entrypoint_digest
            ):
                raise ValueError("descriptor closure evidence does not match its runtime file")
            return
        if isinstance(self.evidence, TrustedPathExecutionClosure):
            components = {
                item.role: (item.digest, item.symlink_chain_digest)
                for item in self.files
                if item.role != "entrypoint"
            }
            expected = {
                item.role: (item.digest, item.symlink_chain_digest)
                for item in self.evidence.components
            }
            if (
                self.site_container_runtime is not None
                or self.rootless_image_runtime is not None
                or entrypoints[0].digest != self.evidence.entrypoint_digest
                or entrypoints[0].symlink_chain_digest
                != self.evidence.entrypoint_symlink_chain_digest
                or components != expected
            ):
                raise ValueError("trusted-path closure evidence does not match runtime files")
            return
        if isinstance(self.evidence, RootlessImageExecutionClosure):
            rootless_runtime = self.rootless_image_runtime
            if (
                self.site_container_runtime is not None
                or rootless_runtime is None
                or len(self.files) != 1
                or entrypoints[0].digest != self.evidence.launcher_digest
                or entrypoints[0].symlink_chain_digest
                != self.evidence.launcher_symlink_chain_digest
                or rootless_runtime.engine_path != self.entrypoint_path
                or rootless_runtime.image_digest != self.evidence.image_digest
                or rootless_runtime.tool_entrypoint_digest != self.evidence.entrypoint_digest
                or rootless_runtime.entrypoints_digest != self.evidence.entrypoints_digest
                or rootless_runtime.package_manifest_digest != self.evidence.package_manifest_digest
            ):
                raise ValueError("rootless-image closure evidence does not match its runtime")
            return
        runtime = self.site_container_runtime
        resolved_by_role = {item.role: item for item in self.files}
        tool_entrypoint = resolved_by_role.get("tool_entrypoint")
        image_inspector = resolved_by_role.get("image_inspector")
        components = {
            role: (item.digest, item.symlink_chain_digest)
            for role, item in resolved_by_role.items()
            if role not in {"entrypoint", "tool_entrypoint", "image_inspector"}
        }
        expected_components = {
            item.role: (item.digest, item.symlink_chain_digest) for item in self.evidence.components
        }
        if (
            runtime is None
            or self.rootless_image_runtime is not None
            or tool_entrypoint is None
            or image_inspector is None
            or len(resolved_by_role) != len(self.files)
            or entrypoints[0].digest != self.evidence.launcher_digest
            or entrypoints[0].symlink_chain_digest != self.evidence.launcher_symlink_chain_digest
            or image_inspector.path != runtime.engine_path
            or image_inspector.digest != self.evidence.image_inspector_digest
            or image_inspector.symlink_chain_digest
            != self.evidence.image_inspector_symlink_chain_digest
            or tool_entrypoint.digest != self.evidence.entrypoint_digest
            or tool_entrypoint.symlink_chain_digest != self.evidence.entrypoint_symlink_chain_digest
            or components != expected_components
            or runtime.operating_system is not self.evidence.operating_system
            or runtime.launcher_kind is not self.evidence.launcher_kind
            or runtime.deployment_id != self.evidence.deployment_id
            or runtime.deployment_digest != self.evidence.deployment_digest
            or runtime.image_digest != self.evidence.image_digest
            or canonical_digest(
                dict(runtime.tool_environment),
                domain="site-container-tool-environment-v1",
            )
            != self.evidence.tool_environment_digest
        ):
            raise ValueError("site-container closure evidence does not match its launcher")

    def __repr__(self) -> str:
        return f"ResolvedExecutionClosure(kind={self.evidence.kind.value!r}, paths=<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("resolved execution closures cannot be serialized")

    @property
    def host_entrypoint_digest(self) -> str:
        return next(item.digest for item in self.files if item.role == "entrypoint")

    def revalidate(self) -> bool:
        files_valid = all(
            _regular_file_digest(item.path) == item.digest
            and _symlink_chain_digest(item.path) == item.symlink_chain_digest
            for item in self.files
        )
        runtime = self.site_container_runtime
        rootless_runtime = self.rootless_image_runtime
        return (
            files_valid
            and (runtime is None or runtime.revalidate_image())
            and (rootless_runtime is None or rootless_runtime.revalidate_image())
        )


def descriptor_execution_closure(
    entrypoint: Path,
    entrypoint_digest: str,
) -> ResolvedExecutionClosure:
    chain_digest = _symlink_chain_digest(entrypoint)
    return ResolvedExecutionClosure(
        evidence=DescriptorExecutionClosure(entrypoint_digest=entrypoint_digest),
        entrypoint_path=entrypoint,
        files=(
            _ResolvedClosureFile(
                role="entrypoint",
                path=entrypoint,
                digest=entrypoint_digest,
                symlink_chain_digest=chain_digest,
            ),
        ),
    )


def trusted_path_execution_closure(
    entrypoint: Path,
    components: tuple[tuple[str, Path], ...] = (),
) -> ResolvedExecutionClosure | None:
    paths = (("entrypoint", entrypoint), *components)
    resolved_files: list[_ResolvedClosureFile] = []
    for role, path in paths:
        digest = _regular_file_digest(path)
        if digest is None or not _trusted_immutable_path(path, executable=role == "entrypoint"):
            return None
        resolved_files.append(
            _ResolvedClosureFile(
                role=role,
                path=path,
                digest=digest,
                symlink_chain_digest=_symlink_chain_digest(path),
            )
        )
    entrypoint_file = resolved_files[0]
    evidence = TrustedPathExecutionClosure(
        entrypoint_digest=entrypoint_file.digest,
        entrypoint_symlink_chain_digest=entrypoint_file.symlink_chain_digest,
        components=tuple(
            ClosureComponent(
                role=item.role,
                digest=item.digest,
                symlink_chain_digest=item.symlink_chain_digest,
            )
            for item in resolved_files[1:]
        ),
    )
    return ResolvedExecutionClosure(
        evidence=evidence,
        entrypoint_path=entrypoint,
        files=tuple(resolved_files),
    )


def rootless_image_execution_closure(
    requirement: ExecutionClosureRequirementRef,
    *,
    engine: Path,
    host_environment: Mapping[str, str],
    image_reference: str,
    image_digest: str,
    tool_entrypoint: str,
    tool_entrypoint_digest: str,
    package_manifest: bytes | None = None,
    package_manifest_digest: str | None = None,
    supervisor_entrypoint: str = _ROOTLESS_SUPERVISOR_ENTRYPOINT,
    supporting_entrypoints: tuple[ImageToolEntrypoint, ...] = (),
) -> ResolvedExecutionClosure | None:
    """Bind one root-owned runtime and immutable image to a tool entrypoint.

    A deployment may additionally supply a verified package inventory. The image
    digest closes the runtime dependencies whether or not that inventory exists.
    """

    launcher_digest = _regular_file_digest(engine)
    if launcher_digest is None or not _trusted_immutable_path(engine, executable=True):
        return None
    launcher_chain_digest = _symlink_chain_digest(engine)
    runtime = RootlessImageRuntime(
        engine_path=engine,
        host_environment=host_environment,
        image_reference=image_reference,
        image_digest=image_digest,
        tool_entrypoint=tool_entrypoint,
        tool_entrypoint_digest=tool_entrypoint_digest,
        package_manifest=package_manifest,
        package_manifest_digest=package_manifest_digest,
        supervisor_entrypoint=supervisor_entrypoint,
        supporting_entrypoints=supporting_entrypoints,
    )
    if not runtime.revalidate_image():
        return None
    evidence = RootlessImageExecutionClosure(
        requirement_id=requirement.requirement_id,
        requirement_digest=requirement.requirement_digest,
        launcher_digest=launcher_digest,
        launcher_symlink_chain_digest=launcher_chain_digest,
        image_digest=image_digest,
        entrypoint_digest=tool_entrypoint_digest,
        entrypoints_digest=runtime.entrypoints_digest,
        package_manifest_digest=package_manifest_digest,
    )
    return ResolvedExecutionClosure(
        evidence=evidence,
        entrypoint_path=engine,
        files=(
            _ResolvedClosureFile(
                role="entrypoint",
                path=engine,
                digest=launcher_digest,
                symlink_chain_digest=launcher_chain_digest,
            ),
        ),
        rootless_image_runtime=runtime,
    )


def site_container_execution_closure(
    requirement: ExecutionClosureRequirementRef,
    recipe: SiteContainerExecutionRecipe,
    *,
    launcher: Path,
    image_inspector: Path,
    image_reference: str,
    image_digest: str,
    modulefile_digest: str,
    host_environment: Mapping[str, str],
    tool_environment: Mapping[str, str],
    deployment_id: str,
    deployment_digest: str,
    launcher_kind: SiteContainerLauncherKind = SiteContainerLauncherKind.SITE_WRAPPER,
    container_user: str = "edagym",
    readonly_mounts: tuple[tuple[Path, str], ...] = (),
) -> ResolvedExecutionClosure | None:
    """Resolve a private recipe into path-free evidence and revalidatable runtime state."""

    if recipe.requirement_digest != requirement.requirement_digest:
        return None
    root_value = tool_environment.get(recipe.root_environment_variable)
    if root_value is None:
        return None
    root = Path(root_value)
    if not root.is_absolute():
        return None
    tool_entrypoint = root / recipe.entrypoint_relative_path
    component_paths = {
        component.role: root / component.relative_path for component in recipe.components
    }
    reserved_roles = {"entrypoint", "image_inspector", "tool_entrypoint"}
    if reserved_roles & set(component_paths):
        return None
    runtime_environment = dict(tool_environment)
    for binding in recipe.environment_bindings:
        runtime_environment[binding.variable_name] = os.fspath(
            component_paths[binding.component_role]
        )
    paths = (
        ("entrypoint", launcher, True),
        ("image_inspector", image_inspector, True),
        ("tool_entrypoint", tool_entrypoint, True),
        *((role, path, False) for role, path in component_paths.items()),
    )
    resolved_files: list[_ResolvedClosureFile] = []
    for role, path, executable in paths:
        digest = _regular_file_digest(path)
        if digest is None or not _trusted_immutable_path(path, executable=executable):
            return None
        resolved_files.append(
            _ResolvedClosureFile(
                role=role,
                path=path,
                digest=digest,
                symlink_chain_digest=_symlink_chain_digest(path),
            )
        )
    files_by_role = {item.role: item for item in resolved_files}
    tool_file = files_by_role["tool_entrypoint"]
    launcher_file = files_by_role["entrypoint"]
    inspector_file = files_by_role["image_inspector"]
    components = tuple(
        ClosureComponent(
            role=role,
            digest=files_by_role[role].digest,
            symlink_chain_digest=files_by_role[role].symlink_chain_digest,
        )
        for role in sorted(component_paths)
    )
    runtime = SiteContainerRuntime(
        operating_system=recipe.operating_system,
        launcher_kind=launcher_kind,
        deployment_id=deployment_id,
        deployment_digest=deployment_digest,
        host_environment=host_environment,
        tool_environment=runtime_environment,
        tool_entrypoint=os.fspath(tool_entrypoint),
        engine_path=image_inspector,
        image_reference=image_reference,
        image_digest=image_digest,
        container_user=container_user,
        readonly_mounts=readonly_mounts,
    )
    evidence = SiteContainerExecutionClosure(
        requirement_id=requirement.requirement_id,
        requirement_digest=requirement.requirement_digest,
        deployment_id=deployment_id,
        deployment_digest=deployment_digest,
        operating_system=recipe.operating_system,
        launcher_kind=launcher_kind,
        launcher_digest=launcher_file.digest,
        launcher_symlink_chain_digest=launcher_file.symlink_chain_digest,
        image_inspector_digest=inspector_file.digest,
        image_inspector_symlink_chain_digest=inspector_file.symlink_chain_digest,
        image_digest=image_digest,
        modulefile_digest=modulefile_digest,
        entrypoint_digest=tool_file.digest,
        entrypoint_symlink_chain_digest=tool_file.symlink_chain_digest,
        components=components,
        tool_closure_digest=site_tool_closure_digest(
            tool_file.digest,
            tool_file.symlink_chain_digest,
            components,
        ),
        tool_environment_digest=canonical_digest(
            runtime_environment,
            domain="site-container-tool-environment-v1",
        ),
    )
    resolved = ResolvedExecutionClosure(
        evidence=evidence,
        entrypoint_path=launcher,
        files=tuple(resolved_files),
        site_container_runtime=runtime,
    )
    return resolved if resolved.revalidate() else None


def trusted_immutable_executable(path: Path) -> Path | None:
    if not _trusted_immutable_path(path, executable=True):
        return None
    return Path(os.path.normpath(path))


def _trusted_immutable_path(path: Path, *, executable: bool) -> bool:
    try:
        if not path.is_absolute():
            return False
        original = Path(os.path.normpath(path))
        resolved = path.resolve(strict=True)
        chain = (resolved, *resolved.parents, *original.parents)
        for component in chain:
            metadata = component.stat()
            if metadata.st_uid == os.getuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        resolved_metadata = resolved.stat()
        if not stat.S_ISREG(resolved_metadata.st_mode):
            return False
        if executable and not os.access(path, os.X_OK):
            return False
    except OSError:
        return False
    return True


def _regular_file_digest(path: Path) -> str | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def _symlink_chain_digest(path: Path) -> str:
    current = Path(os.path.normpath(path))
    chain: list[dict[str, object]] = []
    for _ in range(_MAX_SYMLINK_DEPTH):
        metadata = current.lstat()
        if not stat.S_ISLNK(metadata.st_mode):
            chain.append({"kind": "regular", "digest": _regular_file_digest(current)})
            break
        target = os.readlink(current)
        chain.append(
            {
                "kind": "symlink",
                "target_digest": f"sha256:{hashlib.sha256(os.fsencode(target)).hexdigest()}",
            }
        )
        target_path = Path(target)
        current = target_path if target_path.is_absolute() else current.parent / target_path
        current = Path(os.path.normpath(current))
    else:
        raise OSError("execution closure symlink depth exceeds its bound")
    return canonical_digest(chain, domain="execution-closure-symlink-chain-v1")
