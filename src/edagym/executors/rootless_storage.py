"""Unprivileged bounded filesystems for rootless executor writable mounts."""

from __future__ import annotations

import fcntl
import hashlib
import os
import secrets
import stat
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from enum import StrEnum
from pathlib import Path
from typing import Any, Self, SupportsIndex

from pydantic import model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.local import ExecutorUnavailable
from edagym.executors.protocol import InvocationStorageReceipt
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel

_MINIMUM_FILESYSTEM_BYTES = 32 * 1024 * 1024
_OPERATION_TIMEOUT_SECONDS = 30
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_STORAGE_LOCK_NAME = ".rootless-storage.lock"
_STORAGE_RECORD_NAME = "storage.json"
_STORAGE_RECORD_LIMIT = 64 * 1024
_CONTROL_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
}


class _StoragePhase(StrEnum):
    CREATING = "creating"
    ACTIVE = "active"
    RELEASING = "releasing"


class _StorageRecord(StrictModel):
    schema_version: SchemaVersion = 1
    phase: _StoragePhase
    invocation_id: Identifier
    run_id: Digest
    environment_spec_digest: Digest
    executor_id: Identifier
    executor_implementation_digest: Digest
    provider_capability_digest: Digest
    provider_maximum_bytes: int
    maximum_bytes: int
    backing_identity_digest: Digest | None = None
    receipt: InvocationStorageReceipt | None = None

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        durable = self.phase in {_StoragePhase.ACTIVE, _StoragePhase.RELEASING}
        if durable != (self.backing_identity_digest is not None):
            raise ValueError("durable storage requires its backing identity")
        if durable != (self.receipt is not None):
            raise ValueError("durable storage requires its invocation receipt")
        if self.maximum_bytes < _MINIMUM_FILESYSTEM_BYTES:
            raise ValueError("storage record quota is below the filesystem minimum")
        if self.maximum_bytes > self.provider_maximum_bytes:
            raise ValueError("storage record quota exceeds its deployment ceiling")
        return self


class RootlessStorageLease:
    """Process-owned mounted filesystem whose whole capacity is the run quota."""

    __slots__ = (
        "_backing_file",
        "_backing_identity_digest",
        "_closed",
        "_lock",
        "_maximum_bytes",
        "_mountpoint",
        "_provider",
        "_runtime_root",
        "artifact_directory",
        "filesystem_identity_digest",
        "invocation_id",
        "receipt",
        "temporary_directory",
        "workspace",
    )

    def __init__(
        self,
        *,
        backing_file: Path,
        backing_identity_digest: Digest,
        mountpoint: Path,
        runtime_root: Path,
        provider: RootlessStorageProvider,
        maximum_bytes: int,
        workspace: Path,
        artifact_directory: Path,
        temporary_directory: Path,
        filesystem_identity_digest: Digest,
        invocation_id: Identifier,
        receipt: InvocationStorageReceipt,
    ) -> None:
        self._backing_file = backing_file
        self._backing_identity_digest = backing_identity_digest
        self._mountpoint = mountpoint
        self._runtime_root = runtime_root
        self._provider = provider
        self._maximum_bytes = maximum_bytes
        self.workspace = workspace
        self.artifact_directory = artifact_directory
        self.temporary_directory = temporary_directory
        self.filesystem_identity_digest = filesystem_identity_digest
        self.invocation_id = invocation_id
        self.receipt = receipt
        self._closed = False
        self._lock = threading.Lock()

    @property
    def maximum_bytes(self) -> int:
        return self._maximum_bytes

    @property
    def identity_digest(self) -> Digest:
        return self.receipt.digest

    @property
    def active(self) -> bool:
        with self._lock:
            return not self._closed

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._provider._release(self)
            self._closed = True

    def __enter__(self) -> RootlessStorageLease:
        if self._closed:
            raise RuntimeError("rootless storage lease is closed")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "RootlessStorageLease(<mounted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("rootless storage leases cannot be serialized")

    def _matches(
        self,
        workspace: Path,
        artifact_directory: Path,
        *,
        maximum_bytes: int,
    ) -> bool:
        with self._lock:
            if (
                self._closed
                or workspace != self.workspace
                or artifact_directory != self.artifact_directory
                or maximum_bytes != self._maximum_bytes
            ):
                return False
            try:
                workspace_metadata = workspace.stat(follow_symlinks=False)
                artifact_metadata = artifact_directory.stat(follow_symlinks=False)
                temporary_metadata = self.temporary_directory.stat(follow_symlinks=False)
                filesystem = os.statvfs(workspace)
            except OSError:
                return False
            total_bytes = filesystem.f_frsize * filesystem.f_blocks
            return (
                all(
                    stat.S_ISDIR(metadata.st_mode)
                    and metadata.st_uid == os.getuid()
                    and stat.S_IMODE(metadata.st_mode) == _PRIVATE_DIRECTORY_MODE
                    for metadata in (
                        workspace_metadata,
                        artifact_metadata,
                        temporary_metadata,
                    )
                )
                and workspace_metadata.st_dev == artifact_metadata.st_dev
                == temporary_metadata.st_dev
                and 0 < total_bytes <= maximum_bytes
                and _filesystem_identity_digest(workspace, filesystem)
                == self.filesystem_identity_digest
                and _directory_identity_digest(workspace)
                == self.receipt.workspace_identity_digest
                and _directory_identity_digest(artifact_directory)
                == self.receipt.artifact_directory_identity_digest
                and _directory_identity_digest(self.temporary_directory)
                == self.receipt.temporary_directory_identity_digest
                and self.receipt.storage_instance_digest
                == _storage_instance_digest(
                    invocation_id=self.receipt.invocation_id,
                    run_id=self.receipt.run_id,
                    provider_capability_digest=self.receipt.provider_capability_digest,
                    backing_identity_digest=self._backing_identity_digest,
                )
            )


class RootlessStorageProvider:
    """Create a private fuse2fs filesystem for one rootless invocation."""

    def __init__(
        self,
        *,
        maximum_quota_bytes: int,
        mkfs_path: Path = Path("/usr/sbin/mkfs.ext4"),
        fuse2fs_path: Path = Path("/usr/bin/fuse2fs"),
        fusermount_path: Path = Path("/usr/bin/fusermount3"),
    ) -> None:
        if (
            type(maximum_quota_bytes) is not int
            or maximum_quota_bytes < _MINIMUM_FILESYSTEM_BYTES
        ):
            raise ExecutorUnavailable("rootless storage deployment ceiling is invalid")
        self._maximum_quota_bytes = maximum_quota_bytes
        self._mkfs_path = mkfs_path
        self._fuse2fs_path = fuse2fs_path
        self._fusermount_path = fusermount_path
        self._runtime_digests = {
            "fuse2fs": _trusted_executable_digest(fuse2fs_path),
            "fusermount3": _trusted_executable_digest(fusermount_path),
            "mkfs_ext4": _trusted_executable_digest(mkfs_path),
        }

    @property
    def capability_digest(self) -> Digest:
        return canonical_digest(
            {
                "runtimes": self._runtime_digests,
                "filesystem": "ext4-fuse-whole-filesystem-quota-v1",
                "maximum_quota_bytes": self._maximum_quota_bytes,
            },
            domain="rootless-storage-capability-v1",
        )

    def create(
        self,
        *,
        runtime_root: Path,
        invocation_id: Identifier,
        run_id: Digest,
        environment_spec_digest: Digest,
        executor_id: Identifier,
        executor_implementation_digest: Digest,
        maximum_bytes: int,
    ) -> RootlessStorageLease:
        """Create and mount one exact aggregate quota beneath a private owner root."""

        _require_private_directory(runtime_root)
        if (
            type(maximum_bytes) is not int
            or maximum_bytes < _MINIMUM_FILESYSTEM_BYTES
            or maximum_bytes > self._maximum_quota_bytes
        ):
            raise ExecutorUnavailable("rootless disk quota is too small for ext4 metadata")
        self._revalidate()
        expected = _StorageRecord(
            phase=_StoragePhase.CREATING,
            invocation_id=invocation_id,
            run_id=run_id,
            environment_spec_digest=environment_spec_digest,
            executor_id=executor_id,
            executor_implementation_digest=executor_implementation_digest,
            provider_capability_digest=self.capability_digest,
            provider_maximum_bytes=self._maximum_quota_bytes,
            maximum_bytes=maximum_bytes,
        )
        with _storage_guard(runtime_root):
            lease_root = runtime_root / invocation_id
            if lease_root.exists():
                if not (lease_root / _STORAGE_RECORD_NAME).exists():
                    _remove_recordless_empty_lease_root(lease_root)
                    return self._create_new(runtime_root, lease_root, expected)
                record = _load_storage_record(lease_root)
                _require_record_binding(record, expected)
                if record.phase is _StoragePhase.ACTIVE:
                    return self._recover_active(runtime_root, lease_root, record)
                if record.phase is _StoragePhase.CREATING:
                    self._cleanup_creating(lease_root, record)
                else:
                    self._cleanup_releasing(lease_root, record)
            return self._create_new(runtime_root, lease_root, expected)

    def recover(
        self,
        *,
        runtime_root: Path,
        invocation_id: Identifier,
        run_id: Digest,
        environment_spec_digest: Digest,
        executor_id: Identifier,
        executor_implementation_digest: Digest,
        maximum_bytes: int,
    ) -> RootlessStorageLease | None:
        """Authoritatively reopen an existing lease without creating one."""

        _require_private_directory(runtime_root)
        if (
            type(maximum_bytes) is not int
            or maximum_bytes < _MINIMUM_FILESYSTEM_BYTES
            or maximum_bytes > self._maximum_quota_bytes
        ):
            raise ExecutorUnavailable("rootless disk quota is outside deployment policy")
        self._revalidate()
        expected = _StorageRecord(
            phase=_StoragePhase.CREATING,
            invocation_id=invocation_id,
            run_id=run_id,
            environment_spec_digest=environment_spec_digest,
            executor_id=executor_id,
            executor_implementation_digest=executor_implementation_digest,
            provider_capability_digest=self.capability_digest,
            provider_maximum_bytes=self._maximum_quota_bytes,
            maximum_bytes=maximum_bytes,
        )
        with _storage_guard(runtime_root):
            lease_root = runtime_root / invocation_id
            if not lease_root.exists():
                return None
            if not (lease_root / _STORAGE_RECORD_NAME).exists():
                _remove_recordless_empty_lease_root(lease_root)
                return None
            record = _load_storage_record(lease_root)
            _require_record_binding(record, expected)
            if record.phase is _StoragePhase.CREATING:
                self._cleanup_creating(lease_root, record)
                return None
            if record.phase is _StoragePhase.RELEASING:
                self._cleanup_releasing(lease_root, record)
                return None
            return self._recover_active(runtime_root, lease_root, record)

    def _create_new(
        self,
        runtime_root: Path,
        lease_root: Path,
        creating: _StorageRecord,
    ) -> RootlessStorageLease:
        try:
            lease_root.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            raise ExecutorUnavailable("rootless storage invocation already exists") from None
        backing_file = lease_root / "workspace.ext4"
        mountpoint = lease_root / "mount"
        descriptor: int | None = None
        try:
            _write_storage_record(lease_root, creating)
            descriptor = os.open(
                backing_file,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                _PRIVATE_FILE_MODE,
            )
            os.ftruncate(descriptor, creating.maximum_bytes)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            mountpoint.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            _run_checked(
                self._mkfs_path,
                self._runtime_digests["mkfs_ext4"],
                ("-q", "-F", os.fspath(backing_file)),
            )
            _run_checked(
                self._fuse2fs_path,
                self._runtime_digests["fuse2fs"],
                (
                    "-o",
                    "rw,nosuid,nodev,fakeroot",
                    os.fspath(backing_file),
                    os.fspath(mountpoint),
                ),
            )
            if not os.path.ismount(mountpoint):
                raise ExecutorUnavailable("rootless storage runtime did not mount its filesystem")
            os.chown(mountpoint, os.getuid(), os.getgid())
            os.chmod(mountpoint, _PRIVATE_DIRECTORY_MODE)
            workspace = mountpoint / "workspace"
            artifact_directory = mountpoint / "artifacts"
            temporary_directory = mountpoint / "temporary"
            workspace.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            artifact_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            temporary_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            backing_identity = _backing_identity_digest(
                backing_file,
                maximum_bytes=creating.maximum_bytes,
            )
            receipt = _storage_receipt(
                creating,
                mountpoint,
                backing_identity_digest=backing_identity,
                predecessor_receipt_digest=None,
            )
            active = creating.model_copy(
                update={
                    "phase": _StoragePhase.ACTIVE,
                    "backing_identity_digest": backing_identity,
                    "receipt": receipt,
                }
            )
            _write_storage_record(lease_root, active)
            return self._lease(runtime_root, lease_root, active)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            self._cleanup_creating(lease_root, creating)
            raise

    def _recover_active(
        self,
        runtime_root: Path,
        lease_root: Path,
        record: _StorageRecord,
    ) -> RootlessStorageLease:
        backing_file = lease_root / "workspace.ext4"
        mountpoint = lease_root / "mount"
        if record.backing_identity_digest is None or record.receipt is None:
            raise ExecutorUnavailable("active rootless storage record is incomplete")
        if (
            _backing_identity_digest(
                backing_file,
                maximum_bytes=record.maximum_bytes,
            )
            != record.backing_identity_digest
        ):
            raise ExecutorUnavailable("rootless storage backing identity changed")
        was_mounted = os.path.ismount(mountpoint)
        if not was_mounted:
            _require_empty_private_directory(mountpoint)
            _run_checked(
                self._fuse2fs_path,
                self._runtime_digests["fuse2fs"],
                (
                    "-o",
                    "rw,nosuid,nodev,fakeroot",
                    os.fspath(backing_file),
                    os.fspath(mountpoint),
                ),
            )
            if not os.path.ismount(mountpoint):
                raise ExecutorUnavailable("rootless storage recovery did not remount")
            os.chown(mountpoint, os.getuid(), os.getgid())
            os.chmod(mountpoint, _PRIVATE_DIRECTORY_MODE)
        current_receipt = _storage_receipt(
            record,
            mountpoint,
            backing_identity_digest=record.backing_identity_digest,
            predecessor_receipt_digest=(
                record.receipt.predecessor_receipt_digest
                if was_mounted
                else record.receipt.digest
            ),
        )
        if was_mounted and current_receipt != record.receipt:
            raise ExecutorUnavailable("mounted rootless storage identity changed")
        if current_receipt != record.receipt:
            record = record.model_copy(update={"receipt": current_receipt})
            _write_storage_record(lease_root, record)
        return self._lease(runtime_root, lease_root, record)

    def _lease(
        self,
        runtime_root: Path,
        lease_root: Path,
        record: _StorageRecord,
    ) -> RootlessStorageLease:
        receipt = record.receipt
        backing_identity = record.backing_identity_digest
        if receipt is None or backing_identity is None:
            raise ExecutorUnavailable("rootless storage record is not active")
        mountpoint = lease_root / "mount"
        return RootlessStorageLease(
            backing_file=lease_root / "workspace.ext4",
            backing_identity_digest=backing_identity,
            mountpoint=mountpoint,
            runtime_root=runtime_root,
            provider=self,
            maximum_bytes=record.maximum_bytes,
            workspace=mountpoint / "workspace",
            artifact_directory=mountpoint / "artifacts",
            temporary_directory=mountpoint / "temporary",
            filesystem_identity_digest=receipt.filesystem_identity_digest,
            invocation_id=record.invocation_id,
            receipt=receipt,
        )

    def _cleanup_creating(
        self,
        lease_root: Path,
        record: _StorageRecord,
    ) -> None:
        if record.phase is not _StoragePhase.CREATING:
            raise ExecutorUnavailable("active rootless storage cannot be discarded as incomplete")
        mountpoint = lease_root / "mount"
        self._unmount(mountpoint)
        _remove_incomplete_storage_nodes(lease_root, record.maximum_bytes)

    def _release(self, lease: RootlessStorageLease) -> None:
        with _storage_guard(lease._runtime_root):
            lease_root = lease._mountpoint.parent
            if not lease_root.exists():
                return
            record = _load_storage_record(lease_root)
            if (
                record.phase not in {_StoragePhase.ACTIVE, _StoragePhase.RELEASING}
                or record.receipt is None
                or record.receipt.storage_instance_digest
                != lease.receipt.storage_instance_digest
                or record.backing_identity_digest != lease._backing_identity_digest
            ):
                raise ExecutorUnavailable("rootless storage release authority changed")
            if record.phase is _StoragePhase.ACTIVE:
                self._unmount(lease._mountpoint)
                record = record.model_copy(update={"phase": _StoragePhase.RELEASING})
                _write_storage_record(lease_root, record)
            self._cleanup_releasing(lease_root, record)

    def _cleanup_releasing(
        self,
        lease_root: Path,
        record: _StorageRecord,
    ) -> None:
        if record.phase is not _StoragePhase.RELEASING:
            raise ExecutorUnavailable("non-releasing storage cannot use release recovery")
        self._unmount(lease_root / "mount")
        _remove_releasing_storage_nodes(lease_root, record)

    def _unmount(self, mountpoint: Path) -> None:
        if not os.path.ismount(mountpoint):
            return
        completed = _run(
            self._fusermount_path,
            self._runtime_digests["fusermount3"],
            ("-u", os.fspath(mountpoint)),
        )
        if completed.returncode != 0 or os.path.ismount(mountpoint):
            raise ExecutorUnavailable("bounded rootless filesystem could not be unmounted")

    def _revalidate(self) -> None:
        observed = {
            "fuse2fs": _trusted_executable_digest(self._fuse2fs_path),
            "fusermount3": _trusted_executable_digest(self._fusermount_path),
            "mkfs_ext4": _trusted_executable_digest(self._mkfs_path),
        }
        if observed != self._runtime_digests:
            raise ExecutorUnavailable("rootless storage runtime identity changed")


@contextmanager
def _storage_guard(runtime_root: Path) -> Iterator[None]:
    descriptor = os.open(
        runtime_root / _STORAGE_LOCK_NAME,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        _PRIVATE_FILE_MODE,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            or metadata.st_nlink != 1
        ):
            raise ExecutorUnavailable("rootless storage lock is not private")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _load_storage_record(lease_root: Path) -> _StorageRecord:
    record_path = lease_root / _STORAGE_RECORD_NAME
    try:
        descriptor = os.open(record_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("rootless storage record is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > _STORAGE_RECORD_LIMIT
        ):
            raise ExecutorUnavailable("rootless storage record is not private")
        content = bytearray()
        while len(content) <= metadata.st_size:
            block = os.read(descriptor, metadata.st_size + 1 - len(content))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if len(content) != metadata.st_size or _stable_identity(after) != _stable_identity(
            metadata
        ):
            raise ExecutorUnavailable("rootless storage record changed while reading")
        record = _StorageRecord.model_validate_json(content)
        if canonical_bytes(record) != content:
            raise ExecutorUnavailable("rootless storage record is not canonical")
        return record
    except (ValueError, TypeError):
        raise ExecutorUnavailable("rootless storage record is invalid") from None
    finally:
        os.close(descriptor)


def _write_storage_record(lease_root: Path, record: _StorageRecord) -> None:
    content = canonical_bytes(record)
    if len(content) > _STORAGE_RECORD_LIMIT:
        raise ExecutorUnavailable("rootless storage record exceeds its byte limit")
    temporary_name = f".storage-{secrets.token_hex(12)}"
    directory = os.open(
        lease_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    descriptor: int | None = None
    try:
        _require_private_directory_descriptor(directory)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            _PRIVATE_FILE_MODE,
            dir_fd=directory,
        )
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            _STORAGE_RECORD_NAME,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=directory)
        os.close(directory)


def _require_record_binding(record: _StorageRecord, expected: _StorageRecord) -> None:
    if (
        record.invocation_id != expected.invocation_id
        or record.run_id != expected.run_id
        or record.environment_spec_digest != expected.environment_spec_digest
        or record.executor_id != expected.executor_id
        or record.executor_implementation_digest != expected.executor_implementation_digest
        or record.provider_capability_digest != expected.provider_capability_digest
        or record.provider_maximum_bytes != expected.provider_maximum_bytes
        or record.maximum_bytes != expected.maximum_bytes
    ):
        raise ExecutorUnavailable("rootless storage record belongs to another invocation")


def _storage_receipt(
    record: _StorageRecord,
    mountpoint: Path,
    *,
    backing_identity_digest: Digest,
    predecessor_receipt_digest: Digest | None,
) -> InvocationStorageReceipt:
    if not os.path.ismount(mountpoint):
        raise ExecutorUnavailable("rootless storage filesystem is not mounted")
    workspace = mountpoint / "workspace"
    artifact_directory = mountpoint / "artifacts"
    temporary_directory = mountpoint / "temporary"
    for directory in (workspace, artifact_directory, temporary_directory):
        _require_private_directory(directory)
    filesystem = os.statvfs(mountpoint)
    total_bytes = filesystem.f_frsize * filesystem.f_blocks
    if total_bytes <= 0 or total_bytes > record.maximum_bytes:
        raise ExecutorUnavailable("bounded rootless filesystem reports an invalid quota")
    return InvocationStorageReceipt(
        run_id=record.run_id,
        invocation_id=record.invocation_id,
        environment_spec_digest=record.environment_spec_digest,
        executor_id=record.executor_id,
        executor_implementation_digest=record.executor_implementation_digest,
        provider_capability_digest=record.provider_capability_digest,
        storage_instance_digest=_storage_instance_digest(
            invocation_id=record.invocation_id,
            run_id=record.run_id,
            provider_capability_digest=record.provider_capability_digest,
            backing_identity_digest=backing_identity_digest,
        ),
        filesystem_identity_digest=_filesystem_identity_digest(mountpoint, filesystem),
        workspace_identity_digest=_directory_identity_digest(workspace),
        artifact_directory_identity_digest=_directory_identity_digest(artifact_directory),
        temporary_directory_identity_digest=_directory_identity_digest(temporary_directory),
        quota_bytes=record.maximum_bytes,
        provider_maximum_bytes=record.provider_maximum_bytes,
        reported_capacity_bytes=total_bytes,
        predecessor_receipt_digest=predecessor_receipt_digest,
    )


def _backing_identity_digest(path: Path, *, maximum_bytes: int) -> Digest:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ExecutorUnavailable("rootless storage backing file is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
        or metadata.st_nlink != 1
        or metadata.st_size != maximum_bytes
    ):
        raise ExecutorUnavailable("rootless storage backing file identity is invalid")
    return canonical_digest(
        {
            "device": str(metadata.st_dev),
            "inode": str(metadata.st_ino),
            "owner": str(metadata.st_uid),
            "mode": stat.S_IMODE(metadata.st_mode),
            "links": metadata.st_nlink,
            "size": metadata.st_size,
        },
        domain="rootless-storage-backing-identity-v1",
    )


def _storage_instance_digest(
    *,
    invocation_id: Identifier,
    run_id: Digest,
    provider_capability_digest: Digest,
    backing_identity_digest: Digest,
) -> Digest:
    return canonical_digest(
        {
            "invocation_id": invocation_id,
            "run_id": run_id,
            "provider_capability_digest": provider_capability_digest,
            "backing_identity_digest": backing_identity_digest,
        },
        domain="rootless-storage-instance-v1",
    )


def _remove_incomplete_storage_nodes(lease_root: Path, maximum_bytes: int) -> None:
    _require_storage_children(lease_root)
    backing = lease_root / "workspace.ext4"
    mountpoint = lease_root / "mount"
    if backing.exists():
        _backing_identity_digest(backing, maximum_bytes=maximum_bytes)
        backing.unlink()
    if mountpoint.exists():
        _require_empty_private_directory(mountpoint)
        mountpoint.rmdir()
    record_path = lease_root / _STORAGE_RECORD_NAME
    record_path.unlink(missing_ok=True)
    lease_root.rmdir()


def _remove_releasing_storage_nodes(lease_root: Path, record: _StorageRecord) -> None:
    _require_storage_children(lease_root)
    backing = lease_root / "workspace.ext4"
    mountpoint = lease_root / "mount"
    if backing.exists():
        if record.backing_identity_digest != _backing_identity_digest(
            backing,
            maximum_bytes=record.maximum_bytes,
        ):
            raise ExecutorUnavailable("rootless storage backing changed before release")
        backing.unlink()
    if mountpoint.exists():
        _require_empty_private_directory(mountpoint)
        mountpoint.rmdir()
    (lease_root / _STORAGE_RECORD_NAME).unlink(missing_ok=True)
    lease_root.rmdir()


def _remove_recordless_empty_lease_root(lease_root: Path) -> None:
    _require_empty_private_directory(lease_root)
    lease_root.rmdir()


def _require_storage_children(lease_root: Path) -> None:
    _require_private_directory(lease_root)
    allowed = {_STORAGE_RECORD_NAME, "workspace.ext4", "mount"}
    try:
        names = {child.name for child in lease_root.iterdir()}
    except OSError:
        raise ExecutorUnavailable("rootless storage directory cannot be inspected") from None
    if not names <= allowed:
        raise ExecutorUnavailable("rootless storage directory contains an unknown object")


def _require_empty_private_directory(path: Path) -> None:
    _require_private_directory(path)
    try:
        if any(path.iterdir()):
            raise ExecutorUnavailable("rootless storage mountpoint is not empty")
    except OSError:
        raise ExecutorUnavailable("rootless storage mountpoint cannot be inspected") from None


def _require_private_directory_descriptor(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise ExecutorUnavailable("rootless storage directory is not private")


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("short write while committing rootless storage state")
        view = view[written:]


def _trusted_executable_digest(path: Path) -> Digest:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("rootless storage runtime is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not metadata.st_mode & stat.S_IXUSR
        ):
            raise ExecutorUnavailable("rootless storage runtime is untrusted")
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def _require_private_directory(path: Path) -> None:
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ExecutorUnavailable("rootless storage owner root is unavailable") from None
    if (
        not path.is_absolute()
        or canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise ExecutorUnavailable("rootless storage owner root must be private and canonical")


def _run_checked(path: Path, expected_digest: Digest, arguments: tuple[str, ...]) -> None:
    completed = _run(path, expected_digest, arguments)
    if completed.returncode != 0:
        raise ExecutorUnavailable("rootless storage runtime rejected the filesystem")


def _run(
    path: Path,
    expected_digest: Digest,
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    descriptor: int | None = None
    try:
        descriptor = _open_trusted_executable(path, expected_digest)
        executable = f"/proc/self/fd/{descriptor}"
        return subprocess.run(
            (executable, *arguments),
            executable=executable,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_CONTROL_ENVIRONMENT,
            pass_fds=(descriptor,),
            timeout=_OPERATION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ExecutorUnavailable("rootless storage runtime failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_trusted_executable(path: Path, expected_digest: Digest) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("rootless storage runtime is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not metadata.st_mode & stat.S_IXUSR
            or f"sha256:{digest.hexdigest()}" != expected_digest
        ):
            raise ExecutorUnavailable("rootless storage runtime is untrusted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _filesystem_identity_digest(path: Path, filesystem: os.statvfs_result) -> Digest:
    metadata = path.stat(follow_symlinks=False)
    return canonical_digest(
        {
            "device": str(metadata.st_dev),
            "filesystem_id": str(filesystem.f_fsid),
            "fragment_size": filesystem.f_frsize,
            "blocks": filesystem.f_blocks,
        },
        domain="rootless-storage-filesystem-identity-v1",
    )


def _directory_identity_digest(path: Path) -> Digest:
    metadata = path.stat(follow_symlinks=False)
    return canonical_digest(
        {
            "device": str(metadata.st_dev),
            "inode": str(metadata.st_ino),
            "owner": str(metadata.st_uid),
            "mode": stat.S_IMODE(metadata.st_mode),
        },
        domain="executor-storage-directory-identity-v1",
    )
