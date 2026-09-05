"""Private resolution and bounded probing for site-container tool closures."""

from __future__ import annotations

import hashlib
import os
import re
import resource
import signal
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path

from edagym.drivers.closure import (
    ExecutionClosureRequirementRef,
    ResolvedExecutionClosure,
    SiteContainerExecutionRecipe,
    site_container_arguments,
    site_container_execution_closure,
    trusted_immutable_executable,
)
from edagym.drivers.deployment import (
    SiteContainerConfiguration,
    broker_image_identity_matches,
)

_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BASE_ENVIRONMENT_NAMES = frozenset({"LANG", "LC_ALL", "LOGNAME", "PATH", "USER"})
_EXCLUDED_TOOL_ENVIRONMENT_NAMES = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "CONTAINER_HOME",
        "DISPLAY",
        "ENV",
        "GIT_CONFIG_GLOBAL",
        "HOME",
        "HOST_WORKDIR_PATH",
        "OLDPWD",
        "PROMPT_COMMAND",
        "PS1",
        "PWD",
        "PYTHONSTARTUP",
        "SHLVL",
        "XAUTHORITY",
        "_",
    }
)
_VERSION_BEGIN = b"\nEDAGYM_VERSION_OUTPUT_BEGIN_41C02A6B\n"
_VERSION_END = b"\nEDAGYM_VERSION_OUTPUT_END_41C02A6B\n"
_VERSION_CAPTURE_SCRIPT = (
    "printf '\\nEDAGYM_VERSION_OUTPUT_BEGIN_41C02A6B\\n'; "
    '"$@"; status=$?; '
    "printf '\\nEDAGYM_VERSION_OUTPUT_END_41C02A6B\\n'; "
    'exit "$status"'
)
_PROCESS_TIMEOUT_SECONDS = 30
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def resolve_site_container_execution_closure(
    requirement: ExecutionClosureRequirementRef,
    configuration: SiteContainerConfiguration,
    *,
    modulefile_digest: str,
    source_environment: dict[str, str],
) -> ResolvedExecutionClosure | None:
    """Attest a host-selected tool closure for execution in one immutable image."""

    recipe = configuration.recipe
    broker = configuration.broker
    if (
        not configuration.revalidate()
        or recipe.requirement_digest != requirement.requirement_digest
        or broker.operating_system is not recipe.operating_system
        or trusted_immutable_executable(broker.launcher) is None
        or trusted_immutable_executable(broker.image_inspector) is None
        or not broker_image_identity_matches(broker)
    ):
        return None
    try:
        tool_environment = _filtered_tool_environment(source_environment, recipe)
        root_value = tool_environment.get(recipe.root_environment_variable)
        if root_value is None:
            return None
        root = Path(root_value)
        closure_paths = (
            root / recipe.entrypoint_relative_path,
            *(root / item.relative_path for item in recipe.components),
        )
        mount_sources = tuple(source for source, _ in broker.readonly_mounts)
        if any(
            not any(path == source or source in path.parents for source in mount_sources)
            or not broker.path_has_trusted_owner(path)
            for path in closure_paths
        ):
            return None
        closure = site_container_execution_closure(
            requirement,
            recipe,
            launcher=broker.launcher,
            image_inspector=broker.image_inspector,
            image_reference=broker.image_reference,
            image_digest=broker.image_digest,
            modulefile_digest=modulefile_digest,
            host_environment=broker.host_environment,
            tool_environment=tool_environment,
            deployment_id=broker.deployment_id,
            deployment_digest=broker.deployment_digest,
            launcher_kind=broker.launcher_kind,
            container_user=broker.container_user,
            readonly_mounts=broker.readonly_mounts,
        )
        if closure is None or not configuration.revalidate() or not closure.revalidate():
            return None
        return closure
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def inspect_site_container_tool(
    closure: ResolvedExecutionClosure,
    configuration: SiteContainerConfiguration,
    arguments: tuple[str, ...],
    scratch_root: Path,
    license_environment: Mapping[str, str],
    *,
    accepted_exit_codes: tuple[int, ...],
) -> bytes | None:
    """Return only the framed tool output from a closure-bound version invocation."""

    runtime = closure.site_container_runtime
    if runtime is None or not configuration.revalidate() or not closure.revalidate():
        return None
    try:
        with tempfile.TemporaryDirectory(
            prefix="edagym-site-version-",
            dir=_validated_scratch_root(scratch_root),
        ) as workspace_name:
            workspace = Path(workspace_name)
            workspace.chmod(0o700)
            environment_file = workspace / "tool-environment.sh"
            _write_bytes(
                environment_file,
                runtime.environment_file_bytes(license_environment),
            )
            command = (
                "/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                _VERSION_CAPTURE_SCRIPT,
                "edagym-version",
                runtime.tool_entrypoint,
                *arguments,
            )
            mount_descriptors = configuration.open_mount_descriptors()
            try:
                output = _run_bounded(
                    closure.entrypoint_path,
                    site_container_arguments(
                        runtime.launcher_kind,
                        runtime.operating_system,
                        workspace,
                        environment_file,
                        command,
                        image_reference=runtime.image_reference,
                        container_user=runtime.container_user,
                        readonly_mounts=runtime.readonly_mounts,
                    ),
                    runtime.host_environment,
                    workspace,
                    accepted_exit_codes=accepted_exit_codes,
                )
            finally:
                for descriptor in mount_descriptors:
                    os.close(descriptor)
            if (
                output is None
                or not configuration.revalidate()
                or not closure.revalidate()
            ):
                return None
            start = output.find(_VERSION_BEGIN)
            end = output.find(_VERSION_END, start + len(_VERSION_BEGIN))
            if start < 0 or end < 0 or output.find(_VERSION_BEGIN, start + 1) >= 0:
                return None
            version = output[start + len(_VERSION_BEGIN) : end]
            return version if version.strip() else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _filtered_tool_environment(
    source: dict[str, str],
    recipe: SiteContainerExecutionRecipe,
) -> dict[str, str]:
    selected = _BASE_ENVIRONMENT_NAMES | {
        recipe.root_environment_variable,
        *recipe.tool_environment_names,
    }
    if not selected.issubset(source):
        raise ValueError("site-container tool environment is incomplete")
    if any(
        name in _EXCLUDED_TOOL_ENVIRONMENT_NAMES
        or name.startswith("BASH_FUNC_")
        or name.startswith("SNPS_CONTAINER")
        or name in {"LOADEDMODULES", "MODULES_LMCONFLICT", "_LMFILES_"}
        or _is_license_environment_name(name)
        for name in selected
    ):
        raise ValueError("license environment must use the lease channel")
    return {
        name: source[name]
        for name in sorted(selected)
        if name not in _EXCLUDED_TOOL_ENVIRONMENT_NAMES
        and not name.startswith("BASH_FUNC_")
        and not name.startswith("SNPS_CONTAINER")
        and name not in {"LOADEDMODULES", "MODULES_LMCONFLICT", "_LMFILES_"}
        and not _is_license_environment_name(name)
        and _ENVIRONMENT_NAME.fullmatch(name) is not None
        and "\x00" not in source[name]
        and "\n" not in source[name]
        and "\r" not in source[name]
    }


def site_container_license_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Project only license-bearing variables from an active lease environment."""

    return {
        name: value
        for name, value in sorted(source.items())
        if _ENVIRONMENT_NAME.fullmatch(name) is not None
        and _is_license_environment_name(name)
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
    }


def _is_license_environment_name(name: str) -> bool:
    upper = name.upper()
    return (
        "LICENSE" in upper
        or upper.endswith("_LIC_FILE")
        or upper in {"CDS_LIC_FILE", "LM_LICENSE_FILE", "SNPSLMD_LICENSE_FILE"}
    )


def _write_bytes(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _run_bounded(
    executable: Path,
    arguments: tuple[str, ...],
    environment: Mapping[str, str],
    workspace: Path,
    *,
    accepted_exit_codes: tuple[int, ...] = (0,),
) -> bytes | None:
    output_path = workspace / f"site-output-{hashlib.sha256(os.urandom(16)).hexdigest()}.bin"
    with output_path.open("xb") as output_stream:
        os.fchmod(output_stream.fileno(), 0o600)
        try:
            process = subprocess.Popen(
                (os.fspath(executable), *arguments),
                executable=os.fspath(executable),
                cwd=workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output_stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                preexec_fn=_apply_limits,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            try:
                return_code = process.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                _kill_process_group(process.pid)
                process.wait()
                return None
        finally:
            _kill_process_group(process.pid)
            if process.poll() is None:
                process.wait()
    if return_code not in accepted_exit_codes:
        return None
    descriptor = os.open(output_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
        ):
            return None
        os.fchmod(descriptor, 0o600)
        output_bytes = os.read(descriptor, _MAX_OUTPUT_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            return None
    finally:
        os.close(descriptor)
    return output_bytes if len(output_bytes) <= _MAX_OUTPUT_BYTES else None


def _validated_scratch_root(root: Path) -> Path:
    if root.is_symlink():
        raise ValueError("site-container scratch root cannot be a symbolic link")
    resolved = root.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("site-container scratch root must be private to its owner")
    return resolved


def _apply_limits() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_OUTPUT_BYTES, _MAX_OUTPUT_BYTES))


def _kill_process_group(process_group: int) -> None:
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return
