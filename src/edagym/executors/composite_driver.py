"""Trusted argv-only supervisor for a sealed composite evaluator recipe."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import stat
import subprocess
import sys
from contextlib import suppress
from pathlib import Path, PurePosixPath

_CHUNK_SIZE = 1024 * 1024


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
        or set(value) - {"schema_version", "commands"}
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
        report = _execute_one(raw)
        reports.append(report)
        if report["failure"] is not None or report["exit_code"] != 0:
            break
    return reports


def _execute_one(raw: dict[str, object]) -> dict[str, object]:
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
    elif not Path(executable).is_absolute():
        raise ValueError("resolved tool executable must be absolute")

    try:
        process = subprocess.Popen(
            (executable, *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            pass_fds=(() if executable_descriptor is None else (executable_descriptor,)),
        )
    except OSError:
        exit_code: int | None = None
        failure: str | None = "spawn_failed"
        stdout_digest = stderr_digest = f"sha256:{hashlib.sha256(b'').hexdigest()}"
        stdout_size = stderr_size = 0
    else:
        with process:
            (stdout_digest, stdout_size), (stderr_digest, stderr_size) = _stream_output(process)
            exit_code = process.wait()
            failure = None
    finally:
        if executable_descriptor is not None:
            os.close(executable_descriptor)
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


def _stream_output(process: subprocess.Popen[bytes]) -> tuple[tuple[str, int], tuple[str, int]]:
    """Retain partial diagnostics even when the command or supervisor is killed."""

    assert process.stdout is not None and process.stderr is not None
    destinations = (sys.stdout.buffer, sys.stderr.buffer)
    digests = (hashlib.sha256(), hashlib.sha256())
    sizes = [0, 0]
    with selectors.DefaultSelector() as selector:
        for index, stream in enumerate((process.stdout, process.stderr)):
            selector.register(stream, selectors.EVENT_READ, index)
        while selector.get_map():
            for key, _ in selector.select():
                index = key.data
                content = os.read(key.fd, _CHUNK_SIZE)
                if not content:
                    selector.unregister(key.fileobj)
                    continue
                digests[index].update(content)
                sizes[index] += len(content)
                destinations[index].write(content)
                destinations[index].flush()
    return (
        (f"sha256:{digests[0].hexdigest()}", sizes[0]),
        (f"sha256:{digests[1].hexdigest()}", sizes[1]),
    )


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
