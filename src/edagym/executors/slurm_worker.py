"""Digest-bound compute-node launcher; dependencies are injected as verified code."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

MANIFEST_BYTES: bytes
CAPTURE_ASSET_IDENTITY: Callable[[Path], Any]
FILE_IDENTITY: Callable[[os.stat_result], tuple[int, ...]]


def _open_directory(binding: dict[str, object]) -> int:
    path = binding["path"]
    if not isinstance(path, str):
        raise ValueError("invalid directory path")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != binding["owner"]
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or Path(path).resolve(strict=True) != Path(path)
    ):
        os.close(descriptor)
        raise ValueError("directory identity changed")
    return descriptor


def _revalidate_directory(binding: dict[str, object], descriptor: int) -> None:
    path = binding["path"]
    if not isinstance(path, str):
        raise ValueError("invalid directory path")
    observed = os.stat(path, follow_symlinks=False)
    opened = os.fstat(descriptor)
    if (
        (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_mode)
        != (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode)
        or stat.S_IMODE(observed.st_mode) & 0o022
    ):
        raise ValueError("directory path changed before launch")


def _open_asset(path: str, expected_digest: str) -> int:
    capture = globals().get("CAPTURE_ASSET_IDENTITY")
    file_identity = globals().get("FILE_IDENTITY")
    if not callable(capture) or not callable(file_identity):
        raise ValueError("asset identity verifier is unavailable")
    captured = capture(Path(path))
    if captured.restricted_digest != expected_digest:
        raise ValueError("asset identity changed")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    if stat.S_ISDIR(captured.root_identity[2]):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    if file_identity(os.fstat(descriptor)) != captured.root_identity:
        os.close(descriptor)
        raise ValueError("asset root changed")
    return descriptor


def _revalidate_asset(path: str, expected_digest: str, descriptor: int) -> None:
    capture = globals().get("CAPTURE_ASSET_IDENTITY")
    file_identity = globals().get("FILE_IDENTITY")
    if not callable(capture) or not callable(file_identity):
        raise ValueError("asset identity verifier is unavailable")
    captured = capture(Path(path))
    if (
        captured.restricted_digest != expected_digest
        or file_identity(os.fstat(descriptor)) != captured.root_identity
    ):
        raise ValueError("asset changed before launch")


def _open_executable(path: str, expected_digest: str) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    metadata = os.fstat(descriptor)
    digest = hashlib.sha256()
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & stat.S_IXUSR
        or metadata.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or f"sha256:{digest.hexdigest()}" != expected_digest
    ):
        os.close(descriptor)
        raise ValueError("runtime identity changed")
    return descriptor


def _fd_path(descriptor: int) -> str:
    os.set_inheritable(descriptor, True)
    return f"/proc/self/fd/{descriptor}"


def run() -> None:
    manifest_bytes = globals().get("MANIFEST_BYTES")
    if not isinstance(manifest_bytes, bytes):
        raise ValueError("launch manifest is unavailable")
    manifest = json.loads(manifest_bytes)
    workspace = _open_directory(manifest["workspace"])
    artifacts = _open_directory(manifest["artifact_directory"])
    control = _open_directory(manifest["control_directory"])
    image = _open_asset(manifest["image_path"], manifest["image_digest"])
    apptainer = _open_executable(
        manifest["apptainer_path"],
        manifest["apptainer_digest"],
    )
    asset_descriptors: list[tuple[dict[str, object], int]] = []
    for asset in manifest["assets"]:
        asset_descriptors.append(
            (asset, _open_asset(asset["path"], asset["restricted_digest"]))
        )
    payload_environment = [
        f"{entry['name']}={entry['value']}" for entry in manifest["payload_environment"]
    ]
    command = [
        manifest["apptainer_path"],
        "exec",
        "--containall",
        "--cleanenv",
        "--no-eval",
        "--no-home",
        "--no-mount",
        "hostfs,cwd,home,tmp,bind-paths",
        "--net",
        "--network",
        "none",
        "--writable-tmpfs",
        "--pids-limit",
        str(manifest["pids"]),
        "--cwd",
        manifest["working_directory"],
        "--bind",
        f"{manifest['workspace']['path']}:{manifest['workspace_target']}:rw",
        "--bind",
        f"{manifest['artifact_directory']['path']}:{manifest['artifact_target']}:rw",
        "--bind",
        f"{manifest['control_directory']['path']}:{manifest['control_target']}:rw",
    ]
    for asset, _descriptor in asset_descriptors:
        command.extend(("--bind", f"{asset['path']}:{asset['target']}:ro"))
    command.extend(
        (
            manifest["image_path"],
            "/bin/sh",
            "-c",
            (
                "umask 077; test -x /usr/bin/env || exit 70; "
                ': > "$1"; shift; exec /usr/bin/env -i "$@"'
            ),
            "edagym-payload",
            (
                f"{manifest['control_target']}/edagym-payload-started-"
                f"{manifest['control_nonce']}"
            ),
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            f"HOME={manifest['workspace_target']}",
            f"PWD={manifest['working_directory']}",
            f"TMPDIR={manifest['workspace_target']}/.tmp",
            f"XDG_CACHE_HOME={manifest['workspace_target']}/.cache",
            f"XDG_CONFIG_HOME={manifest['workspace_target']}/.config",
            *payload_environment,
            manifest["payload_executable"],
            *manifest["payload_arguments"],
        )
    )
    file_size = manifest["file_size_bytes"]
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    environment = {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }
    try:
        _revalidate_directory(manifest["workspace"], workspace)
        _revalidate_directory(manifest["artifact_directory"], artifacts)
        _revalidate_directory(manifest["control_directory"], control)
        _revalidate_asset(manifest["image_path"], manifest["image_digest"], image)
        for asset, descriptor in asset_descriptors:
            asset_path = asset["path"]
            asset_digest = asset["restricted_digest"]
            if not isinstance(asset_path, str) or not isinstance(asset_digest, str):
                raise ValueError("asset launch identity is invalid")
            _revalidate_asset(asset_path, asset_digest, descriptor)
        os.execve(_fd_path(apptainer), command, environment)
    finally:
        for descriptor in (
            workspace,
            artifacts,
            control,
            image,
            apptainer,
            *(item[1] for item in asset_descriptors),
        ):
            os.close(descriptor)


if __name__ == "__main__":
    run()
