"""Descriptor-safe identity and launch validation for restricted assets."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Never, SupportsIndex

from edagym.executors.asset_identity import (
    AssetIdentityError,
    FileIdentity,
    capture_asset_identity,
)
from edagym.executors.asset_identity import (
    file_identity as _file_identity,
)
from edagym.executors.asset_policy import AssetSourcePolicy, AssetSourcePolicyError
from edagym.specs.common import Digest
from edagym.specs.environment import EnvironmentSpec, FilesystemScope


class AssetValidationError(ValueError):
    """A resolved asset closure is unsafe, incomplete, or stale."""


class AssetSnapshot:
    """Opaque launch binding whose representation never reveals its host path."""

    __slots__ = (
        "_path",
        "_restricted_digest",
        "_root_identity",
        "_source_policy",
        "_source_policy_identity",
    )
    _path: Path
    _restricted_digest: Digest
    _root_identity: FileIdentity
    _source_policy: AssetSourcePolicy
    _source_policy_identity: Digest

    def __init__(
        self,
        *,
        path: Path,
        restricted_digest: Digest,
        root_identity: FileIdentity,
        source_policy: AssetSourcePolicy,
    ) -> None:
        if type(source_policy) is not AssetSourcePolicy or not source_policy.revalidate():
            raise AssetValidationError("asset snapshot requires a current source authority")
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_restricted_digest", restricted_digest)
        object.__setattr__(self, "_root_identity", root_identity)
        object.__setattr__(self, "_source_policy", source_policy)
        object.__setattr__(
            self,
            "_source_policy_identity",
            source_policy.identity_digest,
        )

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("asset snapshots are immutable")

    @property
    def path(self) -> Path:
        """Return the runtime-only canonical source path."""

        return self._path

    @property
    def restricted_digest(self) -> Digest:
        return self._restricted_digest

    @property
    def source_policy_identity(self) -> Digest:
        return self._source_policy_identity

    def matches_descriptor(self, descriptor: int) -> bool:
        """Return whether an opened launch grant is the captured root object."""

        try:
            return _file_identity(os.fstat(descriptor)) == self._root_identity
        except OSError:
            return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AssetSnapshot):
            return NotImplemented
        return (
            self._path == other._path
            and self._restricted_digest == other._restricted_digest
            and self._root_identity == other._root_identity
            and self._source_policy_identity == other._source_policy_identity
        )

    def __repr__(self) -> str:
        return f"AssetSnapshot(restricted_digest={self._restricted_digest!r})"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("asset snapshots cannot be serialized")

    def __reduce__(self) -> Never:
        raise TypeError("asset snapshots cannot be serialized")


def asset_content_digest(path: Path) -> Digest:
    """Return the canonical restricted content identity for an asset source."""

    try:
        return capture_asset_identity(path).restricted_digest
    except AssetIdentityError as error:
        raise AssetValidationError(str(error)) from None


def validate_asset_closure(
    environment: EnvironmentSpec,
    asset_paths: Mapping[str, Path],
    scope: FilesystemScope,
    *,
    source_policy: AssetSourcePolicy,
    protected_paths: Sequence[Path] = (),
    writable_paths: Sequence[Path] = (),
) -> Mapping[str, AssetSnapshot]:
    """Bind the exact scoped closure and all host-mount separation invariants."""

    expected = {
        mount.asset_id for mount in environment.filesystem.readonly_assets if mount.scope is scope
    }
    if set(asset_paths) != expected:
        raise AssetValidationError("asset resolver did not provide the exact scoped closure")
    if type(source_policy) is not AssetSourcePolicy or not source_policy.revalidate():
        raise AssetValidationError("asset resolver lacks a current source authority")

    protected, writable = _resolved_runtime_paths(protected_paths, writable_paths)

    bindings = {binding.asset_id: binding for binding in environment.assets}
    snapshots: dict[str, AssetSnapshot] = {}
    for asset_id in sorted(asset_paths):
        snapshot = _capture_asset(
            asset_paths[asset_id],
            source_policy=source_policy,
            protected_paths=protected,
            writable_paths=writable,
        )
        binding = bindings.get(asset_id)
        if binding is None or snapshot.restricted_digest != binding.restricted_digest:
            raise AssetValidationError("asset content differs from its restricted digest")
        snapshots[asset_id] = snapshot
    _validate_mount_separation(snapshots, protected, writable)
    if not source_policy.revalidate():
        raise AssetValidationError("asset source authority changed during binding")
    return MappingProxyType(snapshots)


def revalidate_asset_closure(
    snapshots: Mapping[str, AssetSnapshot],
    *,
    protected_paths: Sequence[Path] = (),
    writable_paths: Sequence[Path] = (),
) -> None:
    """Fail if any bound asset changed before the launch boundary."""

    protected, writable = _resolved_runtime_paths(protected_paths, writable_paths)
    current_snapshots: dict[str, AssetSnapshot] = {}
    for asset_id, snapshot in snapshots.items():
        source_policy = snapshot._source_policy
        if (
            source_policy.identity_digest != snapshot.source_policy_identity
            or not source_policy.revalidate()
        ):
            raise AssetValidationError("asset source authority changed after binding")
        current = _capture_asset(
            snapshot.path,
            source_policy=source_policy,
            protected_paths=protected,
            writable_paths=writable,
        )
        if current != snapshot:
            raise AssetValidationError("asset changed after binding")
        current_snapshots[asset_id] = current
    _validate_mount_separation(current_snapshots, protected, writable)


def _capture_asset(
    path: Path,
    *,
    source_policy: AssetSourcePolicy,
    protected_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
) -> AssetSnapshot:
    try:
        resolved = source_policy.require_source(
            path,
            protected_paths=protected_paths,
            writable_paths=writable_paths,
        )
        captured = capture_asset_identity(resolved)
    except (AssetIdentityError, AssetSourcePolicyError) as error:
        raise AssetValidationError(str(error)) from None
    return AssetSnapshot(
        path=captured.path,
        restricted_digest=captured.restricted_digest,
        root_identity=captured.root_identity,
        source_policy=source_policy,
    )


def _resolved_host_path(path: Path, role: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise AssetValidationError(f"{role} must be absolute")
    if ":" in os.fspath(path) or "\x00" in os.fspath(path):
        raise AssetValidationError(f"{role} contains an unsafe mount character")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise AssetValidationError(f"{role} cannot be resolved safely") from None
    if resolved != path:
        raise AssetValidationError(f"{role} must not contain symbolic links")
    return resolved


def _resolved_runtime_paths(
    protected_paths: Sequence[Path],
    writable_paths: Sequence[Path],
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    protected = tuple(_resolved_host_path(path, "protected path") for path in protected_paths)
    writable = tuple(_resolved_host_path(path, "writable path") for path in writable_paths)
    for position, path in enumerate(writable):
        if any(_paths_overlap(path, other) for other in writable[position + 1 :]):
            raise AssetValidationError("writable runtime mounts must be disjoint")
        if any(_paths_overlap(path, other) for other in protected):
            raise AssetValidationError("writable runtime mounts overlap protected state")
    return protected, writable


def _validate_mount_separation(
    snapshots: Mapping[str, AssetSnapshot],
    protected: tuple[Path, ...],
    writable: tuple[Path, ...],
) -> None:
    ordered = tuple(snapshots.values())
    try:
        other_identities = tuple(
            _file_identity(path.stat(follow_symlinks=False))[:2] for path in (*protected, *writable)
        )
    except OSError:
        raise AssetValidationError("runtime mount changed during validation") from None
    for position, snapshot in enumerate(ordered):
        if any(
            snapshot._root_identity[:2] == other._root_identity[:2]
            or _paths_overlap(snapshot.path, other.path)
            for other in ordered[position + 1 :]
        ):
            raise AssetValidationError("asset sources must be pairwise disjoint")
        if (
            any(_paths_overlap(snapshot.path, other) for other in (*protected, *writable))
            or snapshot._root_identity[:2] in other_identities
        ):
            raise AssetValidationError("asset source overlaps another runtime mount")


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents
