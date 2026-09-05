"""Descriptor-safe materialization of restricted qualification assets."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from edagym.drivers.fixtures.model import FixtureAssetInput
from edagym.executors.asset_identity import (
    MAX_ASSET_CAPTURE_DEPTH,
    MAX_ASSET_CAPTURE_ENTRIES,
    MAX_ASSET_CAPTURE_PATH_BYTES,
    MAX_ASSET_CAPTURE_TOTAL_BYTES,
)
from edagym.executors.assets import (
    AssetSnapshot,
    AssetValidationError,
    asset_content_digest,
    revalidate_asset_closure,
)

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_EXECUTABLE_MODE = 0o700


@dataclass(frozen=True, slots=True, repr=False)
class MaterializedQualificationAsset:
    asset_id: str
    target: Path
    restricted_digest: str
    materialized_digest: str

    def __repr__(self) -> str:
        return (
            "MaterializedQualificationAsset("
            f"asset_id={self.asset_id!r}, restricted_digest={self.restricted_digest!r})"
        )


@dataclass(slots=True)
class _MaterializationBudget:
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
            raise AssetValidationError("qualification asset exceeds the copy depth limit")
        if relative_path is not None and len(os.fsencode(relative_path.as_posix())) > (
            MAX_ASSET_CAPTURE_PATH_BYTES
        ):
            raise AssetValidationError("qualification asset exceeds the copy path limit")
        self.entries += 1
        if self.entries > MAX_ASSET_CAPTURE_ENTRIES:
            raise AssetValidationError("qualification asset exceeds the copy entry limit")
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_size < 0 or metadata.st_size > (
                MAX_ASSET_CAPTURE_TOTAL_BYTES - self.total_bytes
            ):
                raise AssetValidationError("qualification asset exceeds the copy byte limit")
            self.total_bytes += metadata.st_size


def materialize_qualification_assets(
    workspace: Path,
    declarations: tuple[FixtureAssetInput, ...],
    snapshots: Mapping[str, AssetSnapshot],
) -> tuple[MaterializedQualificationAsset, ...]:
    """Copy the exact prevalidated closure without exposing its source path."""

    required = {item.asset_id for item in declarations}
    if set(snapshots) != required:
        raise AssetValidationError("qualification asset grant differs from its fixture closure")
    revalidate_asset_closure(snapshots, writable_paths=(workspace,))
    try:
        materialized: list[MaterializedQualificationAsset] = []
        workspace_descriptor = _open_private_workspace(workspace)
        try:
            for declaration in declarations:
                snapshot = snapshots[declaration.asset_id]
                relative = PurePosixPath(declaration.path)
                parent = _open_private_parent(workspace_descriptor, relative.parts[:-1])
                try:
                    _copy_snapshot(snapshot, parent, relative.name)
                finally:
                    os.close(parent)
                target = workspace / declaration.path
                materialized_digest = asset_content_digest(target)
                _require_private_tree(target)
                materialized.append(
                    MaterializedQualificationAsset(
                        asset_id=declaration.asset_id,
                        target=target,
                        restricted_digest=snapshot.restricted_digest,
                        materialized_digest=materialized_digest,
                    )
                )
        finally:
            os.close(workspace_descriptor)
    except AssetValidationError:
        raise
    except OSError:
        raise AssetValidationError("qualification asset materialization failed safely") from None
    revalidate_asset_closure(snapshots, writable_paths=(workspace,))
    return tuple(materialized)


def revalidate_materialized_qualification_assets(
    assets: tuple[MaterializedQualificationAsset, ...],
    snapshots: Mapping[str, AssetSnapshot],
    workspace: Path,
) -> bool:
    try:
        revalidate_asset_closure(snapshots, writable_paths=(workspace,))
        for item in assets:
            _require_private_tree(item.target)
            if asset_content_digest(item.target) != item.materialized_digest:
                return False
        return True
    except (AssetValidationError, OSError, ValueError):
        return False


def _open_private_workspace(workspace: Path) -> int:
    descriptor = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        before = os.fstat(descriptor)
        _require_owned_directory(before, "qualification workspace")
        os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
        after = os.fstat(descriptor)
        if (
            _object_identity(after) != _object_identity(before)
            or stat.S_IMODE(after.st_mode) != _PRIVATE_DIRECTORY_MODE
        ):
            raise AssetValidationError("qualification workspace changed while secured")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_private_parent(root: int, parts: tuple[str, ...]) -> int:
    parent = os.dup(root)
    try:
        for part in parts:
            if not part or part in {".", ".."} or "/" in part or "\x00" in part:
                raise AssetValidationError("qualification asset has an invalid target path")
            with suppress(FileExistsError):
                os.mkdir(part, mode=_PRIVATE_DIRECTORY_MODE, dir_fd=parent)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            try:
                before = os.fstat(child)
                _require_owned_directory(before, "qualification asset target directory")
                os.fchmod(child, _PRIVATE_DIRECTORY_MODE)
                after = os.fstat(child)
                if (
                    _object_identity(after) != _object_identity(before)
                    or stat.S_IMODE(after.st_mode) != _PRIVATE_DIRECTORY_MODE
                ):
                    raise AssetValidationError(
                        "qualification asset target directory changed while secured"
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        return parent
    except BaseException:
        os.close(parent)
        raise


def _copy_snapshot(snapshot: AssetSnapshot, destination: int, name: str) -> None:
    source = os.open(
        snapshot.path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        metadata = os.fstat(source)
        if not snapshot.matches_descriptor(source):
            raise AssetValidationError("qualification asset changed before materialization")
        _require_safe_source(metadata)
        budget = _MaterializationBudget()
        budget.account(metadata, relative_path=None, depth=0)
        if stat.S_ISREG(metadata.st_mode):
            _copy_file_at(source, destination, name, metadata)
        elif stat.S_ISDIR(metadata.st_mode):
            os.mkdir(name, mode=_PRIVATE_DIRECTORY_MODE, dir_fd=destination)
            destination = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=destination,
            )
            try:
                opened = os.fstat(destination)
                _require_owned_directory(opened, "materialized qualification asset directory")
                os.fchmod(destination, _PRIVATE_DIRECTORY_MODE)
                secured = os.fstat(destination)
                if (
                    _object_identity(secured) != _object_identity(opened)
                    or stat.S_IMODE(secured.st_mode) != _PRIVATE_DIRECTORY_MODE
                ):
                    raise AssetValidationError(
                        "materialized qualification asset directory changed while secured"
                    )
                _copy_directory(
                    source,
                    destination,
                    prefix=PurePosixPath(),
                    depth=0,
                    budget=budget,
                )
                _require_private_directory_descriptor(destination)
            finally:
                os.close(destination)
        else:
            raise AssetValidationError("qualification assets must be regular files or directories")
        if _identity(os.fstat(source)) != _identity(metadata):
            raise AssetValidationError("qualification asset changed during materialization")
    finally:
        os.close(source)


def _copy_directory(
    source: int,
    destination: int,
    *,
    prefix: PurePosixPath,
    depth: int,
    budget: _MaterializationBudget,
) -> None:
    names = _bounded_source_names(source, budget)
    for name in names:
        if name in {".", ".."} or "/" in name or "\x00" in name:
            raise AssetValidationError("qualification asset contains an invalid entry")
        before = os.stat(name, dir_fd=source, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise AssetValidationError("qualification asset trees cannot contain links")
        _require_safe_source(before)
        relative = prefix / name
        budget.account(before, relative_path=relative, depth=depth + 1)
        child = os.open(
            name,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
            | (os.O_DIRECTORY if stat.S_ISDIR(before.st_mode) else os.O_NONBLOCK),
            dir_fd=source,
        )
        try:
            if _identity(os.fstat(child)) != _identity(before):
                raise AssetValidationError("qualification asset changed while opened")
            if stat.S_ISDIR(before.st_mode):
                os.mkdir(name, mode=_PRIVATE_DIRECTORY_MODE, dir_fd=destination)
                target = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=destination,
                )
                try:
                    opened = os.fstat(target)
                    _require_owned_directory(opened, "materialized qualification asset directory")
                    os.fchmod(target, _PRIVATE_DIRECTORY_MODE)
                    secured = os.fstat(target)
                    if (
                        _object_identity(secured) != _object_identity(opened)
                        or stat.S_IMODE(secured.st_mode) != _PRIVATE_DIRECTORY_MODE
                    ):
                        raise AssetValidationError(
                            "materialized qualification asset directory changed while secured"
                        )
                    _copy_directory(
                        child,
                        target,
                        prefix=relative,
                        depth=depth + 1,
                        budget=budget,
                    )
                    _require_private_directory_descriptor(target)
                finally:
                    os.close(target)
            elif stat.S_ISREG(before.st_mode):
                _copy_file_at(child, destination, name, before)
            if _identity(os.fstat(child)) != _identity(before):
                raise AssetValidationError("qualification asset changed during materialization")
        finally:
            os.close(child)
    if names != _bounded_source_names(source, budget, account_entries=False):
        raise AssetValidationError("qualification asset directory changed during materialization")


def _bounded_source_names(
    descriptor: int,
    budget: _MaterializationBudget,
    *,
    account_entries: bool = True,
) -> list[str]:
    names: list[str] = []
    maximum = MAX_ASSET_CAPTURE_ENTRIES - budget.entries if account_entries else (
        MAX_ASSET_CAPTURE_ENTRIES
    )
    with os.scandir(descriptor) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > maximum:
                raise AssetValidationError("qualification asset exceeds the copy entry limit")
    return sorted(names)


def _copy_file_at(
    source: int,
    destination_directory: int,
    name: str,
    metadata: os.stat_result,
) -> None:
    mode = (
        _PRIVATE_EXECUTABLE_MODE
        if metadata.st_mode & stat.S_IXUSR
        else _PRIVATE_FILE_MODE
    )
    destination = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=destination_directory,
    )
    try:
        opened = os.fstat(destination)
        _require_owned_regular(opened, "materialized qualification asset file")
        os.fchmod(destination, mode)
        secured = os.fstat(destination)
        if (
            _object_identity(secured) != _object_identity(opened)
            or stat.S_IMODE(secured.st_mode) != mode
        ):
            raise AssetValidationError(
                "materialized qualification asset file changed while secured"
            )
        _copy_file_bytes(source, destination, metadata.st_size)
        completed = os.fstat(destination)
        _require_owned_regular(completed, "materialized qualification asset file")
        if (
            _object_identity(completed) != _object_identity(opened)
            or stat.S_IMODE(completed.st_mode) != mode
        ):
            raise AssetValidationError(
                "materialized qualification asset file changed while copied"
            )
    finally:
        os.close(destination)


def _copy_file_bytes(source: int, destination: int, expected_size: int) -> None:
    remaining = expected_size
    while remaining:
        block = os.read(source, min(remaining, 1024 * 1024))
        if not block:
            raise AssetValidationError("qualification asset ended during materialization")
        view = memoryview(block)
        while view:
            written = os.write(destination, view)
            view = view[written:]
        remaining -= len(block)
    if os.read(source, 1):
        raise AssetValidationError("qualification asset grew during materialization")
    os.fsync(destination)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _object_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _require_safe_source(metadata: os.stat_result) -> None:
    if metadata.st_uid != os.getuid():
        raise AssetValidationError("qualification assets must be owned by the current user")
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise AssetValidationError("qualification asset files cannot have multiple links")
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise AssetValidationError("qualification asset contains a special file")


def _require_owned_directory(metadata: os.stat_result, role: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise AssetValidationError(f"{role} must be a current-user-owned directory")


def _require_owned_regular(metadata: os.stat_result, role: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise AssetValidationError(f"{role} must be a single-link current-user-owned file")


def _require_private_directory_descriptor(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    _require_owned_directory(metadata, "materialized qualification asset directory")
    if stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise AssetValidationError("materialized qualification asset directory is not private")


def _require_private_tree(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        _require_private_tree_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _require_private_tree_descriptor(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if stat.S_ISREG(metadata.st_mode):
        _require_owned_regular(metadata, "materialized qualification asset file")
        expected = (
            _PRIVATE_EXECUTABLE_MODE
            if metadata.st_mode & stat.S_IXUSR
            else _PRIVATE_FILE_MODE
        )
        if stat.S_IMODE(metadata.st_mode) != expected:
            raise AssetValidationError("materialized qualification asset file is not private")
        return
    _require_private_directory_descriptor(descriptor)
    names = sorted(os.listdir(descriptor))
    for name in names:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise AssetValidationError("materialized qualification asset has an invalid entry")
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if not (stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode)):
            raise AssetValidationError(
                "materialized qualification asset contains a link or special file"
            )
        child = os.open(
            name,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
            | (os.O_DIRECTORY if stat.S_ISDIR(before.st_mode) else os.O_NONBLOCK),
            dir_fd=descriptor,
        )
        try:
            if _identity(os.fstat(child)) != _identity(before):
                raise AssetValidationError(
                    "materialized qualification asset changed while opened"
                )
            _require_private_tree_descriptor(child)
            if _identity(os.fstat(child)) != _identity(before):
                raise AssetValidationError(
                    "materialized qualification asset changed during validation"
                )
        finally:
            os.close(child)
    if names != sorted(os.listdir(descriptor)):
        raise AssetValidationError(
            "materialized qualification asset directory changed during validation"
        )
