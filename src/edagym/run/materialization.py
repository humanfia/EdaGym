"""Descriptor-safe materialization of verified artifact manifests."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import IO, Literal

from edagym.run.artifact_model import (
    ArtifactManifest,
    ManifestEntry,
)
from edagym.run.artifacts import (
    ArtifactIntegrityError,
    ArtifactStoreError,
    ContentAddressedStore,
)

_CHUNK_SIZE = 1024 * 1024
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


def restore_manifest(
    store: ContentAddressedStore,
    manifest: ArtifactManifest,
    destination: Path,
) -> None:
    """Materialize and atomically publish a verified tree at a new path.

    Failed private staging trees are retained. Deleting by pathname would let a
    same-UID process substitute unrelated content during failure handling.
    """

    destination_name = destination.name
    if destination_name in {"", ".", ".."}:
        raise ArtifactStoreError("restore destination must name a new child directory")
    parent_descriptor = _open_owned_directory_path(destination.parent)
    staging_name = ""
    staging_descriptor = -1
    staging_identity: tuple[int, int] | None = None
    try:
        staging_name = _create_restore_staging_directory(parent_descriptor)
        created_metadata = os.stat(
            staging_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(created_metadata.st_mode):
            raise ArtifactIntegrityError("restore staging directory has an invalid type")
        staging_identity = _directory_identity(created_metadata)
        staging_descriptor = _open_secure_directory_at(parent_descriptor, staging_name)
        if _directory_identity(os.fstat(staging_descriptor)) != staging_identity:
            raise ArtifactIntegrityError("restore staging directory changed during creation")
        _populate_manifest(store, manifest, staging_descriptor)
        _require_owned_nonwritable_directory_fd(parent_descriptor)
        if not _directory_entry_matches(
            parent_descriptor,
            staging_name,
            staging_identity,
        ):
            raise ArtifactIntegrityError("restore staging directory changed while populated")
        _rename_directory_no_replace(
            parent_descriptor,
            staging_name,
            destination_name,
        )
        if not _directory_entry_matches(
            parent_descriptor,
            destination_name,
            staging_identity,
        ):
            raise ArtifactIntegrityError("published restore has an unexpected identity")
        os.fsync(parent_descriptor)
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        os.close(parent_descriptor)


def populate_disposable_empty_directory(
    store: ContentAddressedStore,
    manifest: ArtifactManifest,
    destination: Path,
) -> None:
    """Populate an existing private empty directory owned by a disposable lease.

    Failure may leave a partial tree. The caller must discard the complete lease
    rather than attempting pathname cleanup or reuse.
    """

    descriptor = _open_owned_directory_path(destination)
    try:
        before = _stable_directory_identity(
            _require_secure_fd(descriptor, regular=False)
        )
        if os.listdir(descriptor):
            raise ArtifactStoreError("disposable restore destination is not empty")
        _populate_manifest(store, manifest, descriptor)
        after = _stable_directory_identity(
            _require_secure_fd(descriptor, regular=False)
        )
        if after != before:
            raise ArtifactIntegrityError(
                "disposable restore destination identity changed"
            )
    finally:
        os.close(descriptor)


def _populate_manifest(
    store: ContentAddressedStore,
    manifest: ArtifactManifest,
    destination_descriptor: int,
) -> None:
    for entry in manifest.entries:
        _restore_manifest_entry(store, destination_descriptor, entry)
    _verify_restored_tree(destination_descriptor, manifest)
    _require_secure_fd(destination_descriptor, regular=False)
    os.fsync(destination_descriptor)


def _create_restore_staging_directory(parent_descriptor: int) -> str:
    for _attempt in range(128):
        name = f".edagym-restore-{os.urandom(16).hex()}"
        try:
            os.mkdir(name, mode=_DIRECTORY_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        os.fsync(parent_descriptor)
        return name
    raise ArtifactStoreError("restore staging identity could not be allocated")


def _rename_directory_no_replace(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise ArtifactStoreError(
            "atomic no-replace directory publication is unavailable"
        ) from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_descriptor,
        os.fsencode(source_name),
        parent_descriptor,
        os.fsencode(destination_name),
        1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), destination_name)
    raise OSError(error_number, os.strerror(error_number), destination_name)


def _restore_manifest_entry(
    store: ContentAddressedStore,
    destination_descriptor: int,
    entry: ManifestEntry,
) -> None:
    parts = PurePosixPath(entry.path).parts
    parent_descriptor = os.dup(destination_descriptor)
    try:
        for part in parts[:-1]:
            child_descriptor = _open_or_create_secure_directory_at(
                parent_descriptor,
                part,
            )
            os.close(parent_descriptor)
            parent_descriptor = child_descriptor
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            _FILE_MODE,
            dir_fd=parent_descriptor,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as target:
                with store.verified_reader(
                    entry.blob,
                    maximum_bytes=entry.blob.size_bytes,
                ) as source:
                    while chunk := source.read(_CHUNK_SIZE):
                        _write_all(target, chunk)
                target.flush()
            os.fchmod(descriptor, _private_restore_mode(entry.mode))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _verify_restored_tree(
    destination_descriptor: int,
    manifest: ArtifactManifest,
) -> None:
    expected = {entry.path: entry for entry in manifest.entries}
    allowed_directories = {
        parent.as_posix()
        for entry in manifest.entries
        for parent in PurePosixPath(entry.path).parents
        if parent != PurePosixPath(".")
    }
    seen: set[str] = set()

    def verify_directory(directory_descriptor: int, prefix: PurePosixPath) -> None:
        identity = _file_identity(os.fstat(directory_descriptor))
        names = sorted(os.listdir(directory_descriptor))
        for name in names:
            relative = prefix / name
            relative_name = relative.as_posix()
            metadata = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISDIR(metadata.st_mode):
                if relative_name not in allowed_directories:
                    raise ArtifactIntegrityError(
                        "restored tree contains an unexpected directory"
                    )
                child_descriptor = _open_secure_directory_at(directory_descriptor, name)
                try:
                    if _file_identity(os.fstat(child_descriptor)) != _file_identity(
                        metadata
                    ):
                        raise ArtifactIntegrityError(
                            "restored directory changed while it was verified"
                        )
                    verify_directory(child_descriptor, relative)
                finally:
                    os.close(child_descriptor)
                continue
            entry = expected.get(relative_name)
            if entry is None or not stat.S_ISREG(metadata.st_mode):
                raise ArtifactIntegrityError("restored tree contains an unexpected entry")
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if _file_identity(opened) != _file_identity(metadata):
                    raise ArtifactIntegrityError("restored file changed while it was opened")
                actual = hashlib.sha256()
                size = 0
                while chunk := os.read(descriptor, _CHUNK_SIZE):
                    size += len(chunk)
                    if size > entry.blob.size_bytes:
                        raise ArtifactIntegrityError(
                            "restored file exceeds its manifest size"
                        )
                    actual.update(chunk)
                after = os.fstat(descriptor)
                if _file_identity(after) != _file_identity(opened):
                    raise ArtifactIntegrityError(
                        "restored file changed while it was verified"
                    )
                if (
                    size != entry.blob.size_bytes
                    or f"sha256:{actual.hexdigest()}" != entry.blob.digest
                    or stat.S_IMODE(after.st_mode) != _private_restore_mode(entry.mode)
                ):
                    raise ArtifactIntegrityError(
                        "restored file disagrees with its manifest"
                    )
            finally:
                os.close(descriptor)
            seen.add(relative_name)
        if (
            names != sorted(os.listdir(directory_descriptor))
            or _file_identity(os.fstat(directory_descriptor)) != identity
        ):
            raise ArtifactIntegrityError(
                "restored directory changed while it was verified"
            )

    verify_directory(destination_descriptor, PurePosixPath())
    if seen != expected.keys():
        raise ArtifactIntegrityError("restored tree is incomplete")


def _open_owned_directory_path(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = -1
    try:
        descriptor = os.open(
            "/",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        for part in absolute.parts[1:]:
            child_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child_descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactStoreError("owned directory path cannot be opened safely") from error
    try:
        _require_owned_nonwritable_directory_fd(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_secure_directory_at(parent_descriptor: int, name: str) -> int:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
    except OSError as error:
        raise ArtifactStoreError("artifact directory cannot be opened safely") from error
    try:
        _require_secure_fd(descriptor, regular=False)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_secure_directory_at(parent_descriptor: int, name: str) -> int:
    created = False
    created_identity: tuple[int, int] | None = None
    try:
        os.mkdir(name, mode=_DIRECTORY_MODE, dir_fd=parent_descriptor)
        created = True
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ArtifactIntegrityError("restored directory was replaced during creation")
        created_identity = _directory_identity(metadata)
    except FileExistsError:
        pass
    descriptor = _open_secure_directory_at(parent_descriptor, name)
    if created_identity is not None and (
        _directory_identity(os.fstat(descriptor)) != created_identity
    ):
        os.close(descriptor)
        raise ArtifactIntegrityError("restored directory was replaced during creation")
    if created:
        os.fsync(parent_descriptor)
    return descriptor


def _require_secure_fd(descriptor: int, *, regular: bool) -> os.stat_result:
    metadata = os.fstat(descriptor)
    expected = stat.S_ISREG(metadata.st_mode) if regular else stat.S_ISDIR(metadata.st_mode)
    if not expected or metadata.st_uid != os.getuid():
        raise ArtifactStoreError("artifact storage objects must be owned and correctly typed")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ArtifactStoreError("artifact storage objects cannot grant group or other access")
    return metadata


def _require_owned_nonwritable_directory_fd(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ArtifactStoreError("directory must be owned and not broadly writable")


def _write_all(stream: IO[bytes], content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = stream.write(view)
        if written is None or written == 0:
            raise OSError("short artifact-store write")
        view = view[written:]


def _private_restore_mode(mode: Literal[0o644, 0o755]) -> Literal[0o600, 0o700]:
    return 0o700 if mode == 0o755 else 0o600


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _directory_entry_matches(
    parent_descriptor: int,
    name: str,
    identity: tuple[int, int],
) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and _directory_identity(metadata) == identity


__all__ = ["populate_disposable_empty_directory", "restore_manifest"]
