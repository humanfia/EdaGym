"""Canonical rootless Podman command construction."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from edagym.specs.environment import FilesystemPolicy, FilesystemScope, ResourceLimits

_ENTRYPOINT = re.compile(
    r"^(?:/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9][A-Za-z0-9._+-]*|"
    r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127})$"
)
_VOLUME_SEPARATORS = frozenset({"\x00", "\n", "\r", ":", ","})


class RootlessControlFile(StrEnum):
    COMPOSITE_RECIPE = "composite_recipe"
    COMPOSITE_SUPERVISOR = "composite_supervisor"


class PodmanCommand(StrEnum):
    RUN = "run"
    CREATE = "create"


class PodmanContainment(StrEnum):
    RUNTIME = "runtime"
    DELEGATED_SCOPE = "delegated_scope"


ROOTLESS_CONTROL_TARGETS = MappingProxyType(
    {
        RootlessControlFile.COMPOSITE_RECIPE: "/run/edagym-control/recipe.json",
        RootlessControlFile.COMPOSITE_SUPERVISOR: "/run/edagym-control/supervisor.py",
    }
)


def rootless_resources_supported(resources: ResourceLimits) -> bool:
    """Resource admission and launch share the available enforcement mechanisms."""

    return (
        resources.io_read_bytes_per_second is None
        and resources.io_write_bytes_per_second is None
    )


def rootless_podman_command(
    *,
    podman_path: Path,
    resources: ResourceLimits,
    filesystem: FilesystemPolicy,
    workspace: Path,
    artifact_directory: Path | None,
    temporary_directory: Path | None = None,
    asset_paths: Mapping[str, Path],
    scope: FilesystemScope,
    image: str,
    environment_fd: int | None,
    executable: str,
    arguments: Sequence[str],
    working_directory: str = ".",
    interactive: bool = False,
    container_name: str | None = None,
    container_labels: Mapping[str, str] | None = None,
    exact_entrypoint: bool = False,
    hermetic_process_environment: bool = False,
    control_files: Mapping[RootlessControlFile, Path] | None = None,
    command_kind: PodmanCommand = PodmanCommand.RUN,
    cidfile: Path | None = None,
    private_staging: bool = False,
    log_max_bytes: int | None = None,
    containment: PodmanContainment = PodmanContainment.RUNTIME,
) -> tuple[str, ...]:
    """Derive the sole rootless container command from resolved policy."""

    if not rootless_resources_supported(resources):
        raise ValueError("rootless device IO limit enforcement is unavailable")
    cpu_limit = f"{resources.cpu_millicores // 1000}.{resources.cpu_millicores % 1000:03d}"
    command = [
        os.fspath(podman_path),
        command_kind.value,
        "--pull=never",
        "--network=none",
        "--http-proxy=false",
        "--cgroupns=private",
        "--ipc=none",
        "--pid=private",
        "--uts=private",
        "--read-only",
        "--image-volume=ignore",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--userns=keep-id:uid=0,gid=0",
        f"--pids-limit={resources.pids}",
        f"--memory={resources.memory_bytes}",
        f"--cpus={cpu_limit}",
        "--ulimit=core=0:0",
        f"--ulimit=fsize={resources.disk_bytes}:{resources.disk_bytes}",
        _volume_argument(
            workspace,
            filesystem.workspace_target,
            readonly=False,
            extra_options=("Z",) if private_staging else (),
        ),
    ]
    if containment is PodmanContainment.DELEGATED_SCOPE:
        command.append("--cgroups=split")
    else:
        command.append(f"--timeout={resources.wall_seconds}")
    if temporary_directory is None:
        command.append("--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m")
    else:
        command.extend(
            (
                "--read-only-tmpfs=false",
                _volume_argument(
                    temporary_directory,
                    "/tmp",
                    readonly=False,
                    extra_options=("noexec", "nosuid", "nodev"),
                ),
                _volume_argument(
                    temporary_directory,
                    "/var/tmp",
                    readonly=False,
                    extra_options=("noexec", "nosuid", "nodev"),
                ),
            )
        )
    if interactive:
        command.append("--interactive")
    if log_max_bytes is not None:
        if log_max_bytes <= 0:
            raise ValueError("container log retention requires a positive byte limit")
        command.extend(("--log-driver=k8s-file", f"--log-opt=max-size={log_max_bytes}"))
    if cidfile is not None:
        if not cidfile.is_absolute() or any(
            character in os.fspath(cidfile) for character in "\x00\n\r"
        ):
            raise ValueError("container receipt requires an absolute safe path")
        command.append(f"--cidfile={cidfile}")
    if container_name is not None:
        command.append(f"--name={container_name}")
    for name, value in sorted((container_labels or {}).items()):
        if not name or any(character in name + value for character in "\x00\n\r="):
            raise ValueError("container labels must not contain separators")
        command.append(f"--label={name}={value}")
    if exact_entrypoint:
        if not _ENTRYPOINT.fullmatch(executable):
            raise ValueError("an exact container entrypoint must be a normalized executable")
        command.append(f"--entrypoint={executable}")
    if hermetic_process_environment:
        command.extend(
            (
                "--unsetenv-all",
                "--env=PATH=/usr/local/bin:/usr/bin:/bin",
                "--env=LANG=C.UTF-8",
                "--env=LC_ALL=C.UTF-8",
                "--env=LD_PRELOAD=",
                "--env=PYTHONHOME=",
                "--env=PYTHONPATH=",
                "--env=BASH_ENV=",
                "--env=ENV=",
            )
        )
    if artifact_directory is not None:
        command.append(
            _volume_argument(
                artifact_directory,
                filesystem.artifact_target,
                readonly=False,
            )
        )
    for mount in filesystem.readonly_assets:
        if mount.scope is scope:
            command.append(
                _volume_argument(
                    asset_paths[mount.asset_id],
                    mount.target,
                    readonly=True,
                )
            )
    if control_files:
        if set(control_files) != set(RootlessControlFile):
            raise ValueError("sealed composite control files must be complete")
        for role in RootlessControlFile:
            command.append(
                _volume_argument(
                    control_files[role],
                    ROOTLESS_CONTROL_TARGETS[role],
                    readonly=True,
                )
            )
    guest_working = filesystem.workspace_target
    if working_directory != ".":
        guest_working = f"{guest_working}/{working_directory}"
    command.append(f"--workdir={guest_working}")
    if environment_fd is not None:
        command.append(f"--env-file=/proc/self/fd/{environment_fd}")
    command.append(image)
    if not exact_entrypoint:
        command.append(executable)
    command.extend(arguments)
    return tuple(command)


def _volume_argument(
    source: Path,
    target: str,
    *,
    readonly: bool,
    extra_options: tuple[str, ...] = (),
) -> str:
    source_text = os.fspath(source)
    if (
        not source.is_absolute()
        or not target.startswith("/")
        or any(separator in source_text for separator in _VOLUME_SEPARATORS)
        or any(separator in target for separator in _VOLUME_SEPARATORS)
    ):
        raise ValueError("container mount paths contain an unsafe volume separator")
    mode = "ro" if readonly else "rw"
    options = ",".join((mode, *extra_options))
    return f"--volume={source_text}:{target}:{options}"
