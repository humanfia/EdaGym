"""Trusted argv-only supervisor for a sealed composite evaluator recipe."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_CHUNK_SIZE = 1024 * 1024
_FIXED_IMAGE_TOOL_DIRECTORIES = ("/usr/local/bin", "/usr/bin", "/bin")
_IMAGE_EXECUTABLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        return 2
    recipe_path, report_path = arguments
    report: dict[str, object]
    try:
        recipe = _load_recipe(Path(recipe_path))
        command_reports = _execute(recipe)
        report = {
            "schema_version": 1,
            "status": "completed",
            "commands": command_reports,
        }
    except Exception:
        report = {
            "schema_version": 1,
            "status": "driver_error",
            "commands": [],
        }
    try:
        _write_report(report_path, report)
    except OSError:
        return 2
    return 0


def _load_recipe(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        content = stream.read(8 * 1024 * 1024 + 1)
    if len(content) > 8 * 1024 * 1024:
        raise ValueError("composite recipe exceeds its bound")
    value = json.loads(content)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or set(value) - {"schema_version", "tool_resolution", "commands"}
        or value.get("tool_resolution", "absolute") not in {"absolute", "fixed_image_path"}
    ):
        raise ValueError("invalid composite recipe")
    commands = value.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("composite recipe requires commands")
    return value


def _execute(recipe: dict[str, object]) -> list[dict[str, object]]:
    raw_commands = recipe["commands"]
    if not isinstance(raw_commands, list):
        raise TypeError("invalid command collection")
    reports: list[dict[str, object]] = []
    for raw in raw_commands:
        if not isinstance(raw, dict):
            raise TypeError("invalid command")
        resolution = recipe.get("tool_resolution", "absolute")
        if not isinstance(resolution, str):
            raise TypeError("invalid tool resolution")
        report = _execute_one(raw, tool_resolution=resolution)
        reports.append(report)
        if report["failure"] is not None or report["exit_code"] != 0:
            break
    return reports


def _execute_one(
    raw: dict[str, object],
    *,
    tool_resolution: str,
) -> dict[str, object]:
    if set(raw) != {
        "kind",
        "identity_digest",
        "executable",
        "arguments",
        "environment",
    }:
        raise ValueError("invalid command fields")
    identity_digest = raw.get("identity_digest")
    executable = raw.get("executable")
    arguments = raw.get("arguments")
    environment = raw.get("environment")
    if (
        not isinstance(identity_digest, str)
        or not isinstance(executable, str)
        or not isinstance(arguments, list)
        or not all(isinstance(item, str) for item in arguments)
        or not isinstance(environment, dict)
        or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
        )
    ):
        raise ValueError("invalid command boundary")
    executable_descriptor: int | None = None
    if raw.get("kind") == "workspace":
        executable_descriptor = _open_workspace_executable(executable)
        executable = f"/proc/self/fd/{executable_descriptor}"
    elif raw.get("kind") != "tool":
        raise ValueError("invalid command kind")
    elif tool_resolution == "absolute":
        if not Path(executable).is_absolute():
            raise ValueError("host tool executable must be absolute")
    elif tool_resolution == "fixed_image_path":
        executable_descriptor = _open_fixed_image_executable(executable)
        executable = f"/proc/self/fd/{executable_descriptor}"
    else:
        raise ValueError("invalid tool resolution")

    with tempfile.TemporaryDirectory(prefix=".edagym-command-", dir=".") as temporary:
        stdout_path = Path(temporary) / "stdout.bin"
        stderr_path = Path(temporary) / "stderr.bin"
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                completed = subprocess.run(
                    (executable, *arguments),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=environment,
                    check=False,
                    close_fds=True,
                    pass_fds=(() if executable_descriptor is None else (executable_descriptor,)),
                )
            exit_code: int | None = completed.returncode
            failure: str | None = None
        except OSError:
            stdout_path.touch(exist_ok=True)
            stderr_path.touch(exist_ok=True)
            exit_code = None
            failure = "spawn_failed"
        finally:
            if executable_descriptor is not None:
                os.close(executable_descriptor)
        stdout_digest, stdout_size = _copy_and_digest(stdout_path, sys.stdout.buffer)
        stderr_digest, stderr_size = _copy_and_digest(stderr_path, sys.stderr.buffer)
    return {
        "identity_digest": identity_digest,
        "exit_code": exit_code,
        "failure": failure,
        "stdout_digest": stdout_digest,
        "stdout_size_bytes": stdout_size,
        "stderr_digest": stderr_digest,
        "stderr_size_bytes": stderr_size,
    }


def _open_workspace_executable(value: str) -> int:
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("workspace executable must be a normalized relative path")
    parent = os.open(
        ".",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for part in path.parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        descriptor = os.open(
            path.parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            os.close(descriptor)
            raise ValueError("workspace command is not an executable regular file")
        return descriptor
    finally:
        os.close(parent)


def _open_fixed_image_executable(value: str) -> int:
    if not _IMAGE_EXECUTABLE.fullmatch(value):
        raise ValueError("image tool executable must be an opaque name")
    for directory in _FIXED_IMAGE_TOOL_DIRECTORIES:
        try:
            parent = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError:
            continue
        try:
            try:
                descriptor = os.open(
                    value,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
            except OSError:
                continue
            metadata = os.fstat(descriptor)
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == 0
                and metadata.st_mode & 0o111
                and not metadata.st_mode & 0o022
            ):
                return descriptor
            os.close(descriptor)
        finally:
            os.close(parent)
    raise ValueError("image tool executable is outside the fixed trusted path")


def _copy_and_digest(path: Path, destination: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            destination.write(chunk)
    destination.flush()
    return f"sha256:{digest.hexdigest()}", size


def _write_report(relative: str, report: dict[str, object]) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("report path must be normalized and relative")
    encoded = json.dumps(
        report,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    parent = os.open(
        ".",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for part in path.parts[:-1]:
            with suppress(FileExistsError):
                os.mkdir(part, mode=0o700, dir_fd=parent)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            metadata = os.fstat(child)
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                os.close(child)
                raise OSError("report directory is not privately controlled")
            os.close(parent)
            parent = child
        descriptor = os.open(
            path.parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(parent)


if __name__ == "__main__":
    raise SystemExit(main())
