"""Standard-library asset identity capture shared with delayed workers."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_FILE_READ_BYTES = 1024 * 1024
_ASSET_MANIFEST_DOMAIN = "participant-asset-manifest-v1"
MAX_ASSET_CAPTURE_ENTRIES = 4_096
MAX_ASSET_CAPTURE_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_ASSET_CAPTURE_DEPTH = 32
MAX_ASSET_CAPTURE_PATH_BYTES = 4_096

FileIdentity = tuple[int, int, int, int, int, int, int, int]


class AssetIdentityError(ValueError):
    """An asset could not be captured as a stable restricted identity."""


@dataclass(frozen=True)
class CapturedAssetIdentity:
    path: Path
    restricted_digest: str
    root_identity: FileIdentity


@dataclass(frozen=True)
class CapturedAssetDescriptor:
    restricted_digest: str
    root_identity: FileIdentity


@dataclass(slots=True)
class _CaptureBudget:
    entries: int = 0
    total_bytes: int = 0

    def account(
        self,
        metadata: os.stat_result,
        *,
        relative_path: PurePosixPath | None,
        depth: int,
    ) -> None:
        if depth > MAX_ASSET_CAPTURE_DEPTH:
            raise AssetIdentityError("asset closure exceeds the capture depth limit")
        if relative_path is not None and len(os.fsencode(relative_path.as_posix())) > (
            MAX_ASSET_CAPTURE_PATH_BYTES
        ):
            raise AssetIdentityError("asset closure exceeds the path length limit")
        self.entries += 1
        if self.entries > MAX_ASSET_CAPTURE_ENTRIES:
            raise AssetIdentityError("asset closure exceeds the entry limit")
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_size < 0 or metadata.st_size > (
                MAX_ASSET_CAPTURE_TOTAL_BYTES - self.total_bytes
            ):
                raise AssetIdentityError("asset closure exceeds the byte limit")
            self.total_bytes += metadata.st_size


def capture_asset_identity(path: Path) -> CapturedAssetIdentity:
    """Capture content, mode, and root-object identity without following links."""

    if not isinstance(path, Path) or not path.is_absolute() or path == Path("/"):
        raise AssetIdentityError("asset path must be an absolute non-root path")
    if (
        ":" in os.fspath(path)
        or "\x00" in os.fspath(path)
        or len(os.fsencode(path)) > MAX_ASSET_CAPTURE_PATH_BYTES
    ):
        raise AssetIdentityError("asset path contains an unsafe mount character")
    try:
        resolved = path.resolve(strict=True)
        if path != resolved:
            raise AssetIdentityError("asset path must not contain symbolic links")
        metadata = path.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise AssetIdentityError("assets cannot be symbolic links")
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except AssetIdentityError:
        raise
    except (OSError, RuntimeError):
        raise AssetIdentityError("asset cannot be opened safely") from None
    try:
        opened = os.fstat(descriptor)
        if file_identity(metadata) != file_identity(opened):
            raise AssetIdentityError("asset changed while it was opened")
        captured = capture_asset_descriptor(descriptor)
        return CapturedAssetIdentity(
            path=resolved,
            restricted_digest=captured.restricted_digest,
            root_identity=captured.root_identity,
        )
    except AssetIdentityError:
        raise
    except (OSError, RuntimeError, UnicodeError, ValueError):
        raise AssetIdentityError("asset closure cannot be captured safely") from None
    finally:
        os.close(descriptor)


def capture_asset_descriptor(descriptor: int) -> CapturedAssetDescriptor:
    """Capture the asset rooted at an already-open read descriptor."""

    try:
        opened = os.fstat(descriptor)
        _require_asset_mode(opened)
        budget = _CaptureBudget()
        budget.account(opened, relative_path=None, depth=0)
        if stat.S_ISREG(opened.st_mode):
            _require_single_link(opened)
            restricted_digest = _digest_file_descriptor(descriptor, opened)
        elif stat.S_ISDIR(opened.st_mode):
            manifest = {
                "root_mode": stat.S_IMODE(opened.st_mode),
                "entries": _directory_entries(
                    descriptor,
                    prefix=PurePosixPath(),
                    depth=0,
                    budget=budget,
                ),
            }
            restricted_digest = _manifest_digest(manifest)
        else:
            raise AssetIdentityError("assets must be regular files or directories")
        identity = file_identity(os.fstat(descriptor))
        if identity != file_identity(opened):
            raise AssetIdentityError("asset changed while it was captured")
        return CapturedAssetDescriptor(
            restricted_digest=restricted_digest,
            root_identity=identity,
        )
    except AssetIdentityError:
        raise
    except (OSError, RuntimeError, UnicodeError, ValueError):
        raise AssetIdentityError("asset descriptor cannot be captured safely") from None


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_entries(
    directory_descriptor: int,
    *,
    prefix: PurePosixPath,
    depth: int,
    budget: _CaptureBudget,
) -> list[dict[str, object]]:
    before = os.fstat(directory_descriptor)
    _require_asset_mode(before)
    names = _bounded_directory_names(directory_descriptor)
    entries: list[dict[str, object]] = []
    for name in names:
        if not name or name in {".", ".."} or "/" in name:
            raise AssetIdentityError("asset contains an invalid directory entry")
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise AssetIdentityError("asset trees cannot contain links or special files")
        _require_asset_mode(metadata)
        if stat.S_ISREG(metadata.st_mode):
            _require_single_link(metadata)
        relative = prefix / name
        budget.account(metadata, relative_path=relative, depth=depth + 1)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_descriptor,
            )
            try:
                if file_identity(os.fstat(child)) != file_identity(metadata):
                    raise AssetIdentityError("asset directory changed while opened")
                entries.append(
                    {
                        "path": relative.as_posix(),
                        "kind": "directory",
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "size_bytes": 0,
                        "content_digest": None,
                    }
                )
                entries.extend(
                    _directory_entries(
                        child,
                        prefix=relative,
                        depth=depth + 1,
                        budget=budget,
                    )
                )
            finally:
                os.close(child)
            continue
        child = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_descriptor,
        )
        try:
            if file_identity(os.fstat(child)) != file_identity(metadata):
                raise AssetIdentityError("asset file changed while opened")
            content_digest = _digest_file_descriptor(child, metadata)
        finally:
            os.close(child)
        entries.append(
            {
                "path": relative.as_posix(),
                "kind": "file",
                "mode": stat.S_IMODE(metadata.st_mode),
                "size_bytes": metadata.st_size,
                "content_digest": content_digest,
            }
        )
    if names != _bounded_directory_names(directory_descriptor) or file_identity(
        os.fstat(directory_descriptor)
    ) != file_identity(before):
        raise AssetIdentityError("asset tree changed while it was captured")
    return entries


def _require_asset_mode(metadata: os.stat_result) -> None:
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AssetIdentityError("assets cannot be broadly writable")


def _require_single_link(metadata: os.stat_result) -> None:
    if metadata.st_nlink != 1:
        raise AssetIdentityError("asset files cannot have multiple hard links")


def _digest_file_descriptor(descriptor: int, expected: os.stat_result) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = expected.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, _FILE_READ_BYTES))
        if not chunk:
            raise AssetIdentityError("asset file ended before its captured size")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise AssetIdentityError("asset file grew beyond its captured size")
    if file_identity(os.fstat(descriptor)) != file_identity(expected):
        raise AssetIdentityError("asset changed while it was hashed")
    return f"sha256:{digest.hexdigest()}"


def _bounded_directory_names(descriptor: int) -> list[str]:
    names: list[str] = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > MAX_ASSET_CAPTURE_ENTRIES:
                raise AssetIdentityError("asset directory exceeds the entry limit")
    return sorted(names)


def _manifest_digest(manifest: dict[str, object]) -> str:
    canonical = json.dumps(
        manifest,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    material = b"edagym\x00" + _ASSET_MANIFEST_DOMAIN.encode() + b"\x00" + canonical
    return f"sha256:{hashlib.sha256(material).hexdigest()}"
