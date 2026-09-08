"""Owner-only runtime sinks and atomic immutable document publication."""

from __future__ import annotations

import os
import secrets
import stat
import subprocess
from contextlib import suppress
from pathlib import Path

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class PrivateStorageError(ValueError):
    """Private state could not be accessed without crossing its storage boundary."""


def require_runtime_sink(path: Path) -> Path:
    """Reject repository state sinks except untracked development scratch in temp."""

    absolute = Path(os.path.abspath(path.expanduser()))
    for ancestor in (absolute, *absolute.parents):
        if not (ancestor / ".git").exists():
            continue
        relative = absolute.relative_to(ancestor)
        if not relative.parts or relative.parts[0] != "temp":
            raise PrivateStorageError("runtime state must be outside a Git worktree")
        try:
            result = subprocess.run(
                ["git", "-c", "core.fsmonitor=false", "ls-files", "-z", "--", relative.as_posix()],
                cwd=ancestor,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                env={
                    "PATH": os.defpath,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                },
            )
        except (OSError, subprocess.TimeoutExpired):
            raise PrivateStorageError("runtime sink repository ownership is unavailable") from None
        if result.returncode or result.stdout:
            raise PrivateStorageError("runtime state cannot overwrite indexed paths")
        break
    return absolute


def private_directory(path: Path, *, create: bool = False) -> Path:
    absolute = require_runtime_sink(path)
    descriptor = _directory_descriptor(absolute, create=create)
    os.close(descriptor)
    return absolute


def read_private(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    absolute = require_runtime_sink(path)
    parent = _directory_descriptor(absolute.parent)
    try:
        descriptor = os.open(absolute.name, _FILE_FLAGS, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            _check_owner(metadata, directory=False)
            if metadata.st_size > max_bytes:
                raise PrivateStorageError("private document exceeds its size limit")
            data = stream.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise PrivateStorageError("private document exceeds its size limit")
            return data
    except OSError:
        raise PrivateStorageError("private document is unavailable") from None
    finally:
        os.close(parent)


def write_private(path: Path, content: bytes, *, replace: bool = False) -> None:
    """Publish a complete file after fsync; immutable writes allow exact retries."""

    absolute = require_runtime_sink(path)
    parent = _directory_descriptor(absolute.parent, create=True)
    temporary = f".pending-{secrets.token_hex(16)}"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            with suppress(FileNotFoundError):
                _check_owner(
                    os.stat(absolute.name, dir_fd=parent, follow_symlinks=False), directory=False
                )
            os.replace(temporary, absolute.name, src_dir_fd=parent, dst_dir_fd=parent)
        else:
            try:
                os.link(
                    temporary,
                    absolute.name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
            except FileExistsError:
                if read_private(absolute, max_bytes=max(1, len(content))) != content:
                    raise PrivateStorageError(
                        "immutable private document already differs"
                    ) from None
        os.fsync(parent)
    except OSError:
        raise PrivateStorageError("private document publication failed") from None
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def _directory_descriptor(path: Path, *, create: bool = False) -> int:
    descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
    try:
        components = path.parts[1:]
        for component in components:
            if create:
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        _check_owner(os.fstat(descriptor), directory=True)
        return descriptor
    except (OSError, PrivateStorageError):
        os.close(descriptor)
        raise PrivateStorageError(
            "private directory is absent, linked, or not owner-only"
        ) from None


def _check_owner(metadata: os.stat_result, *, directory: bool) -> None:
    correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if (
        not correct_type
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or (not directory and metadata.st_nlink != 1)
    ):
        raise PrivateStorageError("private state requires exclusive owner-only storage")
