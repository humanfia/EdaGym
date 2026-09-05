"""Bounded process transport for a controller-authorized authoring executable."""

from __future__ import annotations

import errno
import hashlib
import os
import selectors
import stat
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from edagym.specs.common import Digest


class RestrictedProviderProcessError(RuntimeError):
    """A provider process could not be measured or exchanged safely."""


@dataclass(frozen=True, slots=True)
class ExecutableSnapshot:
    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int
    content_digest: Digest


def provider_environment(
    overrides: Mapping[str, str] | None,
    executable_search_path: str,
) -> dict[str, str]:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": executable_search_path,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "XDG_CACHE_HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "XDG_DATA_HOME": "/nonexistent",
    }
    protected = frozenset(environment) | {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "SHELLOPTS",
        "SSLKEYLOGFILE",
    }
    if overrides is not None:
        for key, value in overrides.items():
            if (
                not key
                or key in protected
                or "=" in key
                or "\x00" in key
                or "\x00" in value
                or "\r" in key
                or "\n" in key
                or "\r" in value
                or "\n" in value
                or not key.isascii()
            ):
                raise ValueError("provider environment contains an invalid entry")
            environment[key] = value
    return environment


def open_trusted_executable(
    executable: Path,
    expected_content_digest: Digest,
) -> tuple[int, ExecutableSnapshot]:
    try:
        descriptor = os.open(
            executable,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise RestrictedProviderProcessError("provider executable is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        snapshot = _snapshot_fd(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not metadata.st_mode & stat.S_IXUSR
        ):
            raise RestrictedProviderProcessError("provider executable is not trusted")
        if snapshot.content_digest != expected_content_digest:
            raise RestrictedProviderProcessError(
                "provider executable digest is not controller-authorized"
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, snapshot


def invoke_trusted_executable(
    executable_fd: int,
    before: ExecutableSnapshot,
    payload: bytes,
    *,
    environment: Mapping[str, str],
    maximum_output_bytes: int,
    timeout_seconds: int,
) -> bytes:
    try:
        process = subprocess.Popen(
            (f"/proc/self/fd/{executable_fd}",),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            cwd="/",
            pass_fds=(executable_fd,),
            env=environment,
        )
        output = _bounded_exchange(
            process,
            payload,
            maximum_output_bytes=maximum_output_bytes,
            timeout_seconds=timeout_seconds,
        )
        after = _snapshot_fd(executable_fd)
    except (OSError, subprocess.SubprocessError) as error:
        raise RestrictedProviderProcessError("provider invocation failed") from error
    if after != before:
        raise RestrictedProviderProcessError("provider executable changed during invocation")
    if process.returncode != 0:
        raise RestrictedProviderProcessError("provider rejected the request")
    return output


def _snapshot_fd(descriptor: int) -> ExecutableSnapshot:
    before = os.fstat(descriptor)
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, 64 * 1024, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise RestrictedProviderProcessError("provider executable changed while measured")
    return ExecutableSnapshot(
        device=after.st_dev,
        inode=after.st_ino,
        mode=after.st_mode,
        owner_uid=after.st_uid,
        owner_gid=after.st_gid,
        link_count=after.st_nlink,
        size=after.st_size,
        modified_ns=after.st_mtime_ns,
        changed_ns=after.st_ctime_ns,
        content_digest=f"sha256:{digest.hexdigest()}",
    )


def _bounded_exchange(
    process: subprocess.Popen[bytes],
    payload: bytes,
    *,
    maximum_output_bytes: int,
    timeout_seconds: int,
) -> bytes:
    if process.stdin is None or process.stdout is None:
        process.kill()
        process.wait()
        raise RestrictedProviderProcessError("provider transport pipes are unavailable")
    stdin = process.stdin
    stdout = process.stdout
    os.set_blocking(stdin.fileno(), False)
    os.set_blocking(stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(stdin, selectors.EVENT_WRITE)
    selector.register(stdout, selectors.EVENT_READ)
    output = bytearray()
    written = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout_seconds)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(process.args, timeout_seconds)
            for key, mask in events:
                if key.fileobj is stdin and mask & selectors.EVENT_WRITE:
                    try:
                        count = os.write(stdin.fileno(), payload[written : written + 64 * 1024])
                    except BrokenPipeError:
                        count = 0
                        written = len(payload)
                    written += count
                    if written == len(payload):
                        selector.unregister(stdin)
                        stdin.close()
                elif key.fileobj is stdout and mask & selectors.EVENT_READ:
                    try:
                        chunk = os.read(stdout.fileno(), 64 * 1024)
                    except OSError as error:
                        if error.errno == errno.EAGAIN:
                            continue
                        raise
                    if not chunk:
                        selector.unregister(stdout)
                        stdout.close()
                    else:
                        output.extend(chunk)
                        if len(output) > maximum_output_bytes:
                            raise RestrictedProviderProcessError(
                                "provider response exceeds its bound"
                            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout_seconds)
        process.wait(timeout=remaining)
        return bytes(output)
    except Exception:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        if not stdin.closed:
            stdin.close()
        if not stdout.closed:
            stdout.close()


__all__ = [
    "RestrictedProviderProcessError",
    "invoke_trusted_executable",
    "open_trusted_executable",
    "provider_environment",
]
