"""Descriptor-safe runtime projection of finite participant operation inputs."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path, PurePosixPath

from edagym.canonical import canonical_digest
from edagym.executors.model import ExecutionResult
from edagym.specs.common import Digest
from edagym.specs.operation import ParticipantOperationBinding


def participant_operation_input_digest(
    workspace: Path,
    operation: ParticipantOperationBinding,
    *,
    maximum_bytes: int,
) -> Digest:
    """Bind an operation to a stable, bounded snapshot of its workspace inputs."""

    return _project_operation_inputs(
        workspace,
        operation,
        maximum_bytes=maximum_bytes,
        destination=None,
    )


def materialize_participant_operation_inputs(
    workspace: Path,
    destination: Path,
    operation: ParticipantOperationBinding,
    *,
    maximum_bytes: int,
) -> Digest:
    """Copy the exact hashed input closure into an executor-issued workspace."""

    return _project_operation_inputs(
        workspace,
        operation,
        maximum_bytes=maximum_bytes,
        destination=destination,
    )


def materialize_participant_operation_outputs(
    workspace: Path,
    destination: Path,
    operation: ParticipantOperationBinding,
    execution: ExecutionResult,
    *,
    maximum_bytes: int,
) -> None:
    """Copy only CAS-verified declared outputs back to the participant workspace."""

    collected = {item.logical_id: item for item in execution.outputs}
    declarations = {item.logical_id: item for item in operation.outputs}
    if not set(collected) <= set(declarations):
        raise ValueError("participant operation returned an undeclared output")
    source_root = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    destination_root = os.open(
        destination,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    total = 0
    try:
        _require_private_directory(source_root)
        _require_private_directory(destination_root)
        for logical_id, declaration in sorted(declarations.items()):
            output = collected.get(logical_id)
            if output is None:
                if declaration.required:
                    raise ValueError("participant operation omitted a required output")
                continue
            source = _open_input(source_root, declaration.path)
            try:
                before = os.fstat(source)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) & 0o077
                ):
                    raise ValueError("participant operation output is not a private file")
                parent, name = _open_destination_parent(destination_root, declaration.path)
                temporary_name = f".edagym-output-{secrets.token_hex(12)}"
                temporary: int | None = None
                try:
                    temporary = os.open(
                        temporary_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | os.O_CLOEXEC,
                        0o600,
                        dir_fd=parent,
                    )
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := os.read(source, 1024 * 1024):
                        digest.update(chunk)
                        _write_all(temporary, chunk)
                        size += len(chunk)
                        total += len(chunk)
                        if total > maximum_bytes:
                            raise ValueError("participant operation outputs exceed the disk bound")
                    os.fsync(temporary)
                    after = os.fstat(source)
                    if (
                        _file_identity(before) != _file_identity(after)
                        or f"sha256:{digest.hexdigest()}" != output.blob.digest
                        or size != output.blob.size_bytes
                    ):
                        raise ValueError("participant operation output changed after collection")
                    os.replace(
                        temporary_name,
                        name,
                        src_dir_fd=parent,
                        dst_dir_fd=parent,
                    )
                    temporary_name = ""
                finally:
                    if temporary is not None:
                        os.close(temporary)
                    if temporary_name:
                        with suppress(FileNotFoundError):
                            os.unlink(temporary_name, dir_fd=parent)
                    os.close(parent)
            finally:
                os.close(source)
    finally:
        os.close(source_root)
        os.close(destination_root)


def _project_operation_inputs(
    workspace: Path,
    operation: ParticipantOperationBinding,
    *,
    maximum_bytes: int,
    destination: Path | None,
) -> Digest:

    entries: list[dict[str, object]] = []
    total = 0
    root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    destination_root = (
        None
        if destination is None
        else os.open(
            destination,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    )
    try:
        _require_private_directory(root)
        if destination_root is not None:
            _require_private_directory(destination_root)
        for relative in operation.candidate_input_paths:
            descriptor = _open_input(root, relative)
            projected: int | None = None
            try:
                before = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) & 0o022
                ):
                    raise ValueError("participant operation input is not a safe regular file")
                if destination_root is not None:
                    projected = _open_new_destination(
                        destination_root,
                        relative,
                        executable=bool(stat.S_IMODE(before.st_mode) & 0o111),
                    )
                digest = hashlib.sha256()
                size = 0
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                    if projected is not None:
                        _write_all(projected, chunk)
                    size += len(chunk)
                    total += len(chunk)
                    if total > maximum_bytes:
                        raise ValueError("participant operation inputs exceed the disk bound")
                after = os.fstat(descriptor)
                if projected is not None:
                    os.fsync(projected)
            finally:
                if projected is not None:
                    os.close(projected)
                os.close(descriptor)
            if _file_identity(before) != _file_identity(after):
                raise ValueError("participant operation input changed while it was hashed")
            entries.append(
                {
                    "content_digest": f"sha256:{digest.hexdigest()}",
                    "executable": bool(stat.S_IMODE(before.st_mode) & 0o111),
                    "path": relative,
                    "size_bytes": size,
                }
            )
    finally:
        os.close(root)
        if destination_root is not None:
            os.close(destination_root)
    input_manifest_digest = canonical_digest(
        entries,
        domain="participant-operation-input-manifest-v1",
    )
    return canonical_digest(
        {
            "operation_digest": operation.digest,
            "input_manifest_digest": input_manifest_digest,
        },
        domain="participant-operation-input-v1",
    )


def _open_input(root: int, relative: str) -> int:
    parts = PurePosixPath(relative).parts
    parent = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            _require_private_directory(child)
            os.close(parent)
            parent = child
        return os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
    finally:
        os.close(parent)


def _open_new_destination(
    root: int,
    relative: str,
    *,
    executable: bool,
) -> int:
    parent, name = _open_destination_parent(root, relative)
    try:
        return os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o700 if executable else 0o600,
            dir_fd=parent,
        )
    finally:
        os.close(parent)


def _open_destination_parent(root: int, relative: str) -> tuple[int, str]:
    parts = PurePosixPath(relative).parts
    parent = os.dup(root)
    try:
        for part in parts[:-1]:
            with suppress(FileExistsError):
                os.mkdir(part, mode=0o700, dir_fd=parent)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            _require_private_directory(child)
            os.close(parent)
            parent = child
        return parent, parts[-1]
    except BaseException:
        os.close(parent)
        raise


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("short write while materializing participant operation data")
        view = view[written:]


def _require_private_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("participant operation input directory is not private")


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
