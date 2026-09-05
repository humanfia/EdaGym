"""Opaque system authority for bounded restricted-asset source selection."""

from __future__ import annotations

import hashlib
import os
import pwd
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, SupportsIndex

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest

_MOUNTINFO_PATH = Path("/proc/self/mountinfo")
_MAX_MOUNTINFO_BYTES = 1024 * 1024
_SENSITIVE_HOME_NAMES = (
    ".aws",
    ".azure",
    ".codex",
    ".config",
    ".gnupg",
    ".kube",
    ".ssh",
)
_POLICY_ISSUER = object()


class AssetSourcePolicyError(ValueError):
    """The trusted source policy is stale or rejects an asset root."""


@dataclass(frozen=True, slots=True)
class _SystemSourceAuthority:
    identity_digest: Digest
    account_home: Path
    mount_bindings: tuple[tuple[Path, Digest], ...]
    broad_roots: tuple[Path, ...]
    sensitive_roots: tuple[Path, ...]

    def continues(self, earlier: _SystemSourceAuthority) -> bool:
        """Whether the authority issued earlier still describes this system.

        Mounts come and go during normal operation: container runtimes and
        executor-issued bounded filesystems mount beneath private roots and are
        unmounted when their invocation is released or recovered. A vanished
        mount cannot widen source selection because broad roots are recomputed
        from the live mount table at every use, but a mount point that still
        exists must carry the exact binding it had at issue: a replaced mount
        changes what an already-selected source path resolves to.
        """

        current_points = {path for path, _ in self.mount_bindings}
        current_bindings = set(self.mount_bindings)
        return (
            self.account_home == earlier.account_home
            and self.sensitive_roots == earlier.sensitive_roots
            and all(
                path not in current_points or (path, binding_digest) in current_bindings
                for path, binding_digest in earlier.mount_bindings
            )
        )


class AssetSourcePolicy:
    """Nonserializable authority for one exact system and deployment snapshot."""

    __slots__ = (
        "_additional_broad_roots",
        "_authority_revalidator",
        "_identity_digest",
        "_system_authority",
    )

    def __init__(
        self,
        *,
        issuer: object,
        system_authority: _SystemSourceAuthority,
        additional_broad_roots: tuple[Path, ...],
        authority_identity_digest: Digest | None,
        authority_revalidator: Callable[[], bool] | None,
    ) -> None:
        if issuer is not _POLICY_ISSUER:
            raise TypeError("asset source policies require a trusted system authority")
        self._system_authority = system_authority
        self._additional_broad_roots = additional_broad_roots
        self._authority_revalidator = authority_revalidator
        self._identity_digest = canonical_digest(
            {
                "system_authority_digest": system_authority.identity_digest,
                "additional_root_digests": tuple(
                    _private_path_digest(path) for path in additional_broad_roots
                ),
                "registry_authority_digest": authority_identity_digest,
            },
            domain="asset-source-policy-v1",
        )

    @property
    def identity_digest(self) -> Digest:
        return self._identity_digest

    def revalidate(self) -> bool:
        try:
            current = _read_system_source_authority()
            return current.continues(self._system_authority) and (
                self._authority_revalidator is None or self._authority_revalidator()
            )
        except (OSError, ValueError):
            return False

    def require_source(
        self,
        path: Path,
        *,
        protected_paths: tuple[Path, ...],
        writable_paths: tuple[Path, ...],
    ) -> Path:
        """Resolve one leaf and reject broad or sensitive source selections."""

        current_authority = _read_system_source_authority()
        if not current_authority.continues(self._system_authority) or (
            self._authority_revalidator is not None and not self._authority_revalidator()
        ):
            raise AssetSourcePolicyError("asset source policy changed before use")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise AssetSourcePolicyError("asset source cannot be resolved safely") from None
        if not path.is_absolute() or resolved != path:
            raise AssetSourcePolicyError("asset source must be an absolute non-symlink path")
        broad_roots = (
            *current_authority.broad_roots,
            *self._additional_broad_roots,
        )
        if any(resolved == root or resolved in root.parents for root in broad_roots):
            raise AssetSourcePolicyError("asset source selects a broad protected root")
        if any(
            _paths_overlap(resolved, root)
            for root in (
                *current_authority.sensitive_roots,
                *protected_paths,
                *writable_paths,
            )
        ):
            raise AssetSourcePolicyError("asset source overlaps sensitive runtime state")
        return resolved

    def __repr__(self) -> str:
        return "AssetSourcePolicy(<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("asset source policies cannot be serialized")

    def __reduce__(self) -> Never:
        raise TypeError("asset source policies cannot be serialized")

    def __copy__(self) -> Never:
        raise TypeError("asset source policies cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> Never:
        raise TypeError("asset source policies cannot be copied")


def load_system_asset_source_policy() -> AssetSourcePolicy:
    """Read the trusted process mount and account authorities by descriptor."""

    return _issue_asset_source_policy(
        additional_broad_roots=(),
        authority_identity_digest=None,
        authority_revalidator=None,
    )


def _issue_asset_source_policy(
    *,
    additional_broad_roots: Iterable[Path],
    authority_identity_digest: Digest | None,
    authority_revalidator: Callable[[], bool] | None,
) -> AssetSourcePolicy:
    roots = _canonical_existing_roots(additional_broad_roots)
    if (authority_identity_digest is None) != (authority_revalidator is None):
        raise AssetSourcePolicyError("asset policy registry authority is incomplete")
    return AssetSourcePolicy(
        issuer=_POLICY_ISSUER,
        system_authority=_read_system_source_authority(),
        additional_broad_roots=roots,
        authority_identity_digest=authority_identity_digest,
        authority_revalidator=authority_revalidator,
    )


def _read_system_source_authority() -> _SystemSourceAuthority:
    payload = _read_mountinfo()
    mount_bindings = _mount_bindings(payload)
    mount_roots = tuple(path for path, _ in mount_bindings)
    account = pwd.getpwuid(os.getuid())
    home = Path(account.pw_dir)
    if not home.is_absolute():
        raise AssetSourcePolicyError("account home is not an absolute path")
    try:
        resolved_home = home.resolve(strict=True)
    except (OSError, RuntimeError):
        raise AssetSourcePolicyError("account home cannot be resolved safely") from None
    sensitive_candidates = tuple(resolved_home / name for name in _SENSITIVE_HOME_NAMES)
    sensitive: set[Path] = set(sensitive_candidates)
    for candidate in sensitive_candidates:
        try:
            sensitive.add(candidate.resolve(strict=True))
        except (OSError, RuntimeError):
            continue
    ordered_sensitive = tuple(sorted(sensitive, key=os.fspath))
    broad = tuple(sorted({Path("/"), resolved_home, *mount_roots}, key=os.fspath))
    identity_digest = canonical_digest(
        {
            "mountinfo_content_digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
            "mount_binding_digests": tuple(
                binding_digest for _, binding_digest in mount_bindings
            ),
            "broad_root_digests": tuple(_private_path_digest(path) for path in broad),
            "sensitive_root_digests": tuple(
                _private_path_digest(path) for path in ordered_sensitive
            ),
        },
        domain="asset-source-system-authority-v1",
    )
    return _SystemSourceAuthority(
        identity_digest=identity_digest,
        account_home=resolved_home,
        mount_bindings=mount_bindings,
        broad_roots=broad,
        sensitive_roots=ordered_sensitive,
    )


def _read_mountinfo() -> bytes:
    descriptor = os.open(_MOUNTINFO_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        identity = _authority_descriptor_identity(before)
        if not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.getuid()}:
            raise AssetSourcePolicyError("system mount authority is not a trusted descriptor")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_MOUNTINFO_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_MOUNTINFO_BYTES:
                raise AssetSourcePolicyError("system mount authority exceeds its byte limit")
        if _authority_descriptor_identity(os.fstat(descriptor)) != identity:
            raise AssetSourcePolicyError("system mount authority changed while read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _mount_bindings(payload: bytes) -> tuple[tuple[Path, Digest], ...]:
    bindings: set[tuple[Path, Digest]] = set()
    lines = payload.splitlines()
    if not lines:
        raise AssetSourcePolicyError("system mount authority is empty")
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or b"-" not in fields[6:]:
            raise AssetSourcePolicyError("system mount authority is malformed")
        separator = fields.index(b"-", 6)
        if separator + 3 >= len(fields):
            raise AssetSourcePolicyError("system mount authority is malformed")
        raw = _unescape_mount_field(fields[4])
        path = Path(os.fsdecode(raw))
        if not path.is_absolute() or Path(os.path.normpath(path)) != path:
            raise AssetSourcePolicyError("system mount authority contains an invalid root")
        binding_digest = canonical_digest(
            {
                "device": fields[2].decode("ascii"),
                "filesystem_root": _unescape_mount_field(fields[3]).hex(),
                "mount_point_digest": _private_path_digest(path),
                "filesystem_type": fields[separator + 1].decode("ascii"),
                "mount_source": _unescape_mount_field(fields[separator + 2]).hex(),
            },
            domain="asset-source-mount-binding-v1",
        )
        bindings.add((path, binding_digest))
    return tuple(sorted(bindings, key=lambda item: (os.fspath(item[0]), item[1])))


def _unescape_mount_field(value: bytes) -> bytes:
    result = bytearray()
    position = 0
    escapes = {b"040": 0x20, b"011": 0x09, b"012": 0x0A, b"134": 0x5C}
    while position < len(value):
        if value[position] != 0x5C:
            result.append(value[position])
            position += 1
            continue
        encoded = value[position + 1 : position + 4]
        replacement = escapes.get(encoded)
        if replacement is None:
            raise AssetSourcePolicyError("system mount authority has an invalid escape")
        result.append(replacement)
        position += 4
    return bytes(result)


def _canonical_existing_roots(roots: Iterable[Path]) -> tuple[Path, ...]:
    resolved: set[Path] = set()
    for root in roots:
        if not isinstance(root, Path) or not root.is_absolute() or root == Path("/"):
            raise AssetSourcePolicyError("registry asset roots must be absolute non-root paths")
        try:
            canonical = root.resolve(strict=True)
        except (OSError, RuntimeError):
            raise AssetSourcePolicyError("registry asset root cannot be resolved safely") from None
        if canonical != root:
            raise AssetSourcePolicyError("registry asset roots cannot contain symbolic links")
        resolved.add(canonical)
    return tuple(sorted(resolved, key=os.fspath))


def _private_path_digest(path: Path) -> Digest:
    return canonical_digest(
        {"path_bytes": os.fsencode(path).hex()},
        domain="asset-source-private-path-v1",
    )


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _authority_descriptor_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )
