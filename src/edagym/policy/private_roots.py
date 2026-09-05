"""Descriptor-bound permission audit for release-owned private roots."""

from __future__ import annotations

import hashlib
import os
import stat
from collections import Counter
from dataclasses import asdict
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Never, Self

from pydantic import field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.policy.repository import (
    AuditMode,
    AuditReport,
    AuditStatus,
    RepositoryPolicy,
    bind_repository_snapshot,
)
from edagym.specs.common import Digest, JcsNonNegativeInt, StrictModel

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
_MAXIMUM_SCAN_DEPTH = 128
_MAXIMUM_SCAN_ENTRIES = 1_000_000
_CANONICAL_REPOSITORY_PRIVATE_ROOTS = (
    ".edagym",
    ".edagym-state",
    "artifacts",
    "runs",
    "workspaces",
)
_REGISTRATION_TOKEN = object()
_AUDIT_TOKEN = object()


class PrivateRootRole(StrEnum):
    AUTHORING_MATERIALIZATION = "authoring_materialization"
    AUTHORING_PROVIDER_SOURCE = "authoring_provider_source"
    BACKEND_DEPLOYMENT_REGISTRY = "backend_deployment_registry"
    BACKEND_QUALIFICATION_SOURCE_REGISTRY = "backend_qualification_source_registry"
    BACKEND_QUALIFICATION_STORE = "backend_qualification_store"
    CAMPAIGN_ARTIFACT_STORE = "campaign_artifact_store"
    COMMAND_ARTIFACT_STORE = "command_artifact_store"
    EXECUTOR_DEPLOYMENT_REGISTRY = "executor_deployment_registry"
    EXECUTOR_QUALIFICATION_STORE = "executor_qualification_store"
    FLOW_QUALIFICATION_STORE = "flow_qualification_store"
    PARTICIPANT_SESSION_STORE = "participant_session_store"
    REPOSITORY_PRIVATE_ROOT = "repository_private_root"


REQUIRED_RELEASE_PRIVATE_ROOT_ROLES = frozenset(
    {
        PrivateRootRole.AUTHORING_MATERIALIZATION,
        PrivateRootRole.AUTHORING_PROVIDER_SOURCE,
        PrivateRootRole.BACKEND_DEPLOYMENT_REGISTRY,
        PrivateRootRole.BACKEND_QUALIFICATION_SOURCE_REGISTRY,
        PrivateRootRole.BACKEND_QUALIFICATION_STORE,
        PrivateRootRole.CAMPAIGN_ARTIFACT_STORE,
        PrivateRootRole.COMMAND_ARTIFACT_STORE,
        PrivateRootRole.EXECUTOR_DEPLOYMENT_REGISTRY,
        PrivateRootRole.EXECUTOR_QUALIFICATION_STORE,
        PrivateRootRole.FLOW_QUALIFICATION_STORE,
        PrivateRootRole.PARTICIPANT_SESSION_STORE,
    }
)


class PrivateRootKind(StrEnum):
    DIRECTORY = "directory"
    REGULAR_FILE = "regular_file"
    SYMLINK = "symlink"
    OTHER = "other"


class PrivateRootAuditStatus(StrEnum):
    PASS = "pass"
    VIOLATION = "violation"
    INCOMPLETE = "incomplete"


class ExposedModeCount(StrictModel):
    entry_kind: PrivateRootKind
    exposed_mode: int
    count: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_mode(self) -> Self:
        if self.entry_kind is PrivateRootKind.SYMLINK:
            raise ValueError("symlink mode bits are not permission evidence")
        if self.exposed_mode <= 0 or self.exposed_mode & ~0o077:
            raise ValueError("exposed mode must contain only group or world permission bits")
        if not self.count:
            raise ValueError("exposed mode summaries require a positive count")
        return self


class PrivateRootSummary(StrictModel):
    roles: tuple[PrivateRootRole, ...]
    root_kind: PrivateRootKind
    source_identity_digests: tuple[Digest, ...]
    tree_identity_digest: Digest
    directory_count: JcsNonNegativeInt
    regular_file_count: JcsNonNegativeInt
    symlink_count: JcsNonNegativeInt
    other_count: JcsNonNegativeInt
    owner_mismatch_count: JcsNonNegativeInt
    hardlink_ambiguity_count: JcsNonNegativeInt
    unstable_entry_count: JcsNonNegativeInt
    exposed_modes: tuple[ExposedModeCount, ...]

    @field_validator("roles")
    @classmethod
    def normalize_roles(
        cls,
        value: tuple[PrivateRootRole, ...],
    ) -> tuple[PrivateRootRole, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("private-root identities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.value))

    @field_validator("source_identity_digests")
    @classmethod
    def normalize_source_identities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("private-root identities must be unique and non-empty")
        return tuple(sorted(value))

    @field_validator("exposed_modes")
    @classmethod
    def normalize_exposed_modes(
        cls,
        value: tuple[ExposedModeCount, ...],
    ) -> tuple[ExposedModeCount, ...]:
        identities = [(item.entry_kind, item.exposed_mode) for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("private-root exposed mode summaries must be unique")
        return tuple(sorted(value, key=lambda item: (item.entry_kind.value, item.exposed_mode)))


class PrivateRootAuditReport(StrictModel):
    repository_snapshot_digest: Digest
    policy_digest: Digest
    roots: tuple[PrivateRootSummary, ...]
    missing_roles: tuple[PrivateRootRole, ...]
    status: PrivateRootAuditStatus

    @field_validator("roots")
    @classmethod
    def normalize_roots(
        cls,
        value: tuple[PrivateRootSummary, ...],
    ) -> tuple[PrivateRootSummary, ...]:
        identities = [item.tree_identity_digest for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("private-root summaries must have unique physical identities")
        return tuple(sorted(value, key=lambda item: item.tree_identity_digest))

    @field_validator("missing_roles")
    @classmethod
    def normalize_missing_roles(
        cls,
        value: tuple[PrivateRootRole, ...],
    ) -> tuple[PrivateRootRole, ...]:
        if len(value) != len(set(value)):
            raise ValueError("missing private-root roles must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def derive_status(self) -> Self:
        present = {role for root in self.roots for role in root.roles}
        expected_missing = tuple(
            sorted(REQUIRED_RELEASE_PRIVATE_ROOT_ROLES - present, key=lambda item: item.value)
        )
        violation = any(
            root.owner_mismatch_count
            or root.hardlink_ambiguity_count
            or root.other_count
            or root.symlink_count
            or root.exposed_modes
            for root in self.roots
        )
        incomplete = any(root.unstable_entry_count for root in self.roots)
        expected_status = (
            PrivateRootAuditStatus.VIOLATION
            if violation
            else PrivateRootAuditStatus.INCOMPLETE
            if expected_missing or incomplete
            else PrivateRootAuditStatus.PASS
        )
        if self.missing_roles != expected_missing or self.status is not expected_status:
            raise ValueError("private-root audit status must be mechanically derived")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="release-private-root-audit-v1")


class PrivateRootRegistration:
    """Nonserializable authority over one already-validated private root source."""

    __slots__ = (
        "_descriptor",
        "_root_identity",
        "_root_kind",
        "role",
        "source_identity_digest",
    )

    def __init__(
        self,
        token: object,
        *,
        role: PrivateRootRole,
        descriptor: int,
        root_identity: tuple[int, ...],
        root_kind: PrivateRootKind,
        source_identity_digest: Digest,
    ) -> None:
        if token is not _REGISTRATION_TOKEN:
            raise TypeError("private-root registrations require a canonical live source")
        self.role = role
        self.source_identity_digest = source_identity_digest
        self._descriptor = descriptor
        self._root_identity = root_identity
        self._root_kind = root_kind

    def _consume_descriptor(self) -> int:
        if self._descriptor < 0:
            raise RuntimeError("private-root registrations are one-shot authorities")
        descriptor = os.dup(self._descriptor)
        os.close(self._descriptor)
        self._descriptor = -1
        return descriptor

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def __del__(self) -> None:
        self.close()

    def __reduce__(self) -> Never:
        raise TypeError("private-root registrations cannot be serialized")


class VerifiedPrivateRootAudit:
    """Nonserializable proof that one audit came from live registered roots."""

    __slots__ = ("report",)

    def __init__(self, token: object, report: PrivateRootAuditReport) -> None:
        if token is not _AUDIT_TOKEN:
            raise TypeError("verified private-root audits require the canonical scanner")
        self.report = report

    def __reduce__(self) -> Never:
        raise TypeError("verified private-root audits cannot be serialized")


def _bind_private_root_from_descriptor(
    role: PrivateRootRole,
    descriptor: int,
    source_identity_digest: Digest,
) -> PrivateRootRegistration:
    """Retain a one-shot duplicate of a semantic owner's verified descriptor."""

    retained = os.dup(descriptor)
    try:
        metadata = os.fstat(retained)
        root_kind = _entry_kind(metadata.st_mode)
        if root_kind not in {PrivateRootKind.DIRECTORY, PrivateRootKind.REGULAR_FILE}:
            raise ValueError("registered private sources must be directories or regular files")
        return PrivateRootRegistration(
            _REGISTRATION_TOKEN,
            role=role,
            descriptor=retained,
            root_identity=_node_identity(metadata),
            root_kind=root_kind,
            source_identity_digest=source_identity_digest,
        )
    except BaseException:
        os.close(retained)
        raise


def audit_private_roots(
    repository: Path,
    repository_audit: AuditReport,
    registrations: tuple[PrivateRootRegistration, ...],
) -> VerifiedPrivateRootAudit:
    """Audit canonical repository roots plus exact registered external roots."""

    if (
        type(repository_audit) is not AuditReport
        or repository_audit.mode is not AuditMode.RELEASE
        or repository_audit.status is not AuditStatus.PASS
        or repository_audit.snapshot is None
        or not repository_audit.snapshot.is_clean
    ):
        raise ValueError("private-root audit requires a passing clean repository audit")
    if any(type(item) is not PrivateRootRegistration for item in registrations):
        raise TypeError("private-root audit accepts only canonical registrations")
    if any(item._descriptor < 0 for item in registrations):
        raise RuntimeError("private-root registrations are one-shot authorities")

    with bind_repository_snapshot(repository, repository_audit.snapshot) as binding:
        repository_registrations = _repository_private_roots(binding._descriptor)
        all_registrations = (*repository_registrations, *registrations)
        grouped: dict[tuple[int, ...], list[PrivateRootRegistration]] = {}
        for registration in all_registrations:
            grouped.setdefault(registration._root_identity, []).append(registration)
        summaries = tuple(_scan_registered_group(group) for group in grouped.values())
        binding.verify()

    present = {role for root in summaries for role in root.roles}
    missing = tuple(
        sorted(REQUIRED_RELEASE_PRIVATE_ROOT_ROLES - present, key=lambda item: item.value)
    )
    violation = any(
        root.owner_mismatch_count
        or root.hardlink_ambiguity_count
        or root.other_count
        or root.symlink_count
        or root.exposed_modes
        for root in summaries
    )
    incomplete = any(root.unstable_entry_count for root in summaries)
    report = PrivateRootAuditReport(
        repository_snapshot_digest=repository_audit.snapshot.digest,
        policy_digest=_private_root_policy_digest(),
        roots=summaries,
        missing_roles=missing,
        status=(
            PrivateRootAuditStatus.VIOLATION
            if violation
            else PrivateRootAuditStatus.INCOMPLETE
            if missing or incomplete
            else PrivateRootAuditStatus.PASS
        ),
    )
    return VerifiedPrivateRootAudit(_AUDIT_TOKEN, report)


def project_private_root_audit(
    verified: VerifiedPrivateRootAudit,
) -> PrivateRootAuditReport:
    if type(verified) is not VerifiedPrivateRootAudit:
        raise TypeError("private-root projection requires canonical scanner authority")
    return verified.report


def _repository_private_roots(
    root_descriptor: int,
) -> tuple[PrivateRootRegistration, ...]:
    registrations: list[PrivateRootRegistration] = []
    try:
        for relative in _CANONICAL_REPOSITORY_PRIVATE_ROOTS:
            try:
                metadata = os.stat(relative, dir_fd=root_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            kind = _entry_kind(metadata.st_mode)
            flags = (
                _DIRECTORY_FLAGS
                if kind is PrivateRootKind.DIRECTORY
                else _FILE_FLAGS
                if kind is PrivateRootKind.REGULAR_FILE
                else os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            descriptor = os.open(relative, flags, dir_fd=root_descriptor)
            try:
                if _stat_identity(os.fstat(descriptor)) != _stat_identity(metadata):
                    raise RuntimeError("repository private root changed while opening")
                retained = os.dup(descriptor)
                registrations.append(
                    PrivateRootRegistration(
                        _REGISTRATION_TOKEN,
                        role=PrivateRootRole.REPOSITORY_PRIVATE_ROOT,
                        descriptor=retained,
                        root_identity=_node_identity(metadata),
                        root_kind=kind,
                        source_identity_digest=canonical_digest(
                            {
                                "policy_digest": _private_root_policy_digest(),
                                "root_class": "repository-private-root",
                            },
                            domain="repository-private-root-registration-v1",
                        ),
                    )
                )
            finally:
                os.close(descriptor)
    except BaseException:
        for registration in registrations:
            registration.close()
        raise
    return tuple(registrations)


def _scan_registered_group(
    registrations: list[PrivateRootRegistration],
) -> PrivateRootSummary:
    exemplar = registrations[0]
    if any(item._root_kind is not exemplar._root_kind for item in registrations):
        for registration in registrations:
            registration.close()
        return _unstable_summary(registrations)
    descriptors: list[int] = []
    try:
        for registration in registrations:
            descriptors.append(registration._consume_descriptor())
        descriptor = descriptors[0]
        before = tuple(os.fstat(item) for item in descriptors)
        if (
            any(
                _node_identity(metadata) != registration._root_identity
                for metadata, registration in zip(before, registrations, strict=True)
            )
            or any(
                _node_identity(metadata) != exemplar._root_identity for metadata in before
            )
        ):
            return _unstable_summary(registrations)
        snapshot = (
            _scan_directory(descriptor)
            if exemplar._root_kind is PrivateRootKind.DIRECTORY
            else _scan_single_node(descriptor, exemplar._root_kind)
        )
        if any(
            _stat_identity(os.fstat(item)) != _stat_identity(metadata)
            for item, metadata in zip(descriptors, before, strict=True)
        ):
            return _unstable_summary(registrations)
    except (OSError, RuntimeError):
        return _unstable_summary(registrations)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    roles = tuple(sorted({item.role for item in registrations}, key=lambda item: item.value))
    sources = tuple(sorted({item.source_identity_digest for item in registrations}))
    return PrivateRootSummary(
        roles=roles,
        root_kind=exemplar._root_kind,
        source_identity_digests=sources,
        tree_identity_digest=snapshot.tree_digest,
        directory_count=snapshot.counts[PrivateRootKind.DIRECTORY],
        regular_file_count=snapshot.counts[PrivateRootKind.REGULAR_FILE],
        symlink_count=snapshot.counts[PrivateRootKind.SYMLINK],
        other_count=snapshot.counts[PrivateRootKind.OTHER],
        owner_mismatch_count=snapshot.owner_mismatch_count,
        hardlink_ambiguity_count=snapshot.hardlink_ambiguity_count,
        unstable_entry_count=snapshot.unstable_entry_count,
        exposed_modes=tuple(
            ExposedModeCount(entry_kind=kind, exposed_mode=mode, count=count)
            for (kind, mode), count in sorted(
                snapshot.exposed_modes.items(),
                key=lambda item: (item[0][0].value, item[0][1]),
            )
        ),
    )


class _TreeSnapshot:
    __slots__ = (
        "counts",
        "exposed_modes",
        "hardlink_ambiguity_count",
        "owner_mismatch_count",
        "tree_digest",
        "unstable_entry_count",
    )

    def __init__(
        self,
        *,
        counts: Counter[PrivateRootKind],
        exposed_modes: Counter[tuple[PrivateRootKind, int]],
        owner_mismatch_count: int,
        hardlink_ambiguity_count: int,
        unstable_entry_count: int,
        tree_digest: Digest,
    ) -> None:
        self.counts = counts
        self.exposed_modes = exposed_modes
        self.owner_mismatch_count = owner_mismatch_count
        self.hardlink_ambiguity_count = hardlink_ambiguity_count
        self.unstable_entry_count = unstable_entry_count
        self.tree_digest = tree_digest


def _scan_directory(root_descriptor: int) -> _TreeSnapshot:
    counts: Counter[PrivateRootKind] = Counter()
    exposed_modes: Counter[tuple[PrivateRootKind, int]] = Counter()
    owner_mismatches = 0
    hardlink_ambiguities = 0
    unstable = 0
    entries = 0
    digest = hashlib.sha256(b"edagym\x00private-root-tree-v1\x00")

    def visit(descriptor: int, prefix: PurePosixPath, depth: int) -> None:
        nonlocal entries, hardlink_ambiguities, owner_mismatches, unstable
        if depth > _MAXIMUM_SCAN_DEPTH:
            raise RuntimeError("private-root scan depth exceeded")
        before = _stat_identity(os.fstat(descriptor))
        names = tuple(sorted(os.listdir(descriptor)))
        for name in names:
            entries += 1
            if entries > _MAXIMUM_SCAN_ENTRIES:
                raise RuntimeError("private-root scan entry limit exceeded")
            relative = prefix / name
            first = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            kind = _entry_kind(first.st_mode)
            counts[kind] += 1
            if first.st_uid != os.getuid():
                owner_mismatches += 1
            if kind is PrivateRootKind.REGULAR_FILE and first.st_nlink != 1:
                hardlink_ambiguities += 1
            if kind is not PrivateRootKind.SYMLINK:
                exposed = stat.S_IMODE(first.st_mode) & 0o077
                if exposed:
                    exposed_modes[(kind, exposed)] += 1
            digest.update(_tree_entry_identity(relative, first))
            if kind is PrivateRootKind.DIRECTORY:
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
                try:
                    if _stat_identity(os.fstat(child)) != _stat_identity(first):
                        unstable += 1
                        continue
                    visit(child, relative, depth + 1)
                finally:
                    os.close(child)
            elif kind is PrivateRootKind.REGULAR_FILE:
                child = os.open(name, _FILE_FLAGS, dir_fd=descriptor)
                try:
                    if _stat_identity(os.fstat(child)) != _stat_identity(first):
                        unstable += 1
                finally:
                    os.close(child)
            second = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _stat_identity(second) != _stat_identity(first):
                unstable += 1
        if tuple(sorted(os.listdir(descriptor))) != names or _stat_identity(
            os.fstat(descriptor)
        ) != before:
            unstable += 1

    root = os.fstat(root_descriptor)
    counts[PrivateRootKind.DIRECTORY] += 1
    if root.st_uid != os.getuid():
        owner_mismatches += 1
    exposed = stat.S_IMODE(root.st_mode) & 0o077
    if exposed:
        exposed_modes[(PrivateRootKind.DIRECTORY, exposed)] += 1
    digest.update(_tree_entry_identity(PurePosixPath("."), root))
    visit(root_descriptor, PurePosixPath(), 0)
    return _TreeSnapshot(
        counts=counts,
        exposed_modes=exposed_modes,
        owner_mismatch_count=owner_mismatches,
        hardlink_ambiguity_count=hardlink_ambiguities,
        unstable_entry_count=unstable,
        tree_digest=f"sha256:{digest.hexdigest()}",
    )


def _scan_single_node(
    descriptor: int,
    kind: PrivateRootKind,
) -> _TreeSnapshot:
    metadata = os.fstat(descriptor)
    counts: Counter[PrivateRootKind] = Counter({kind: 1})
    exposed_modes: Counter[tuple[PrivateRootKind, int]] = Counter()
    if kind is not PrivateRootKind.SYMLINK:
        exposed = stat.S_IMODE(metadata.st_mode) & 0o077
        if exposed:
            exposed_modes[(kind, exposed)] += 1
    digest = hashlib.sha256(b"edagym\x00private-root-tree-v1\x00")
    digest.update(_tree_entry_identity(PurePosixPath("."), metadata))
    return _TreeSnapshot(
        counts=counts,
        exposed_modes=exposed_modes,
        owner_mismatch_count=int(metadata.st_uid != os.getuid()),
        hardlink_ambiguity_count=int(
            kind is PrivateRootKind.REGULAR_FILE and metadata.st_nlink != 1
        ),
        unstable_entry_count=0,
        tree_digest=f"sha256:{digest.hexdigest()}",
    )


def _unstable_summary(
    registrations: list[PrivateRootRegistration],
) -> PrivateRootSummary:
    return PrivateRootSummary(
        roles=tuple(sorted({item.role for item in registrations}, key=lambda item: item.value)),
        root_kind=registrations[0]._root_kind,
        source_identity_digests=tuple(
            sorted({item.source_identity_digest for item in registrations})
        ),
        tree_identity_digest=canonical_digest(
            {
                "sources": tuple(
                    sorted(item.source_identity_digest for item in registrations)
                ),
                "root_identities": tuple(
                    sorted(
                        tuple(str(value) for value in item._root_identity)
                        for item in registrations
                    )
                ),
            },
            domain="unavailable-private-root-scan-v1",
        ),
        directory_count=0,
        regular_file_count=0,
        symlink_count=0,
        other_count=0,
        owner_mismatch_count=0,
        hardlink_ambiguity_count=0,
        unstable_entry_count=1,
        exposed_modes=(),
    )


def _tree_entry_identity(
    relative_path: PurePosixPath,
    metadata: os.stat_result,
) -> bytes:
    path_digest = hashlib.sha256(os.fsencode(relative_path.as_posix())).hexdigest()
    entry_digest = canonical_digest(
        {
            "relative_path_digest": f"sha256:{path_digest}",
            "kind": _entry_kind(metadata.st_mode),
            "identity": tuple(str(value) for value in _stat_identity(metadata)),
        },
        domain="private-root-entry-identity-v1",
    )
    return bytes.fromhex(entry_digest.removeprefix("sha256:"))


def _entry_kind(mode: int) -> PrivateRootKind:
    if stat.S_ISDIR(mode):
        return PrivateRootKind.DIRECTORY
    if stat.S_ISREG(mode):
        return PrivateRootKind.REGULAR_FILE
    if stat.S_ISLNK(mode):
        return PrivateRootKind.SYMLINK
    return PrivateRootKind.OTHER


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _node_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _private_root_policy_digest() -> Digest:
    return canonical_digest(
        {
            "repository_policy": asdict(RepositoryPolicy()),
            "required_roles": tuple(
                sorted(REQUIRED_RELEASE_PRIVATE_ROOT_ROLES, key=lambda item: item.value)
            ),
            "directory_mode_mask": 0o077,
            "symlink_policy": "reject-no-follow",
            "maximum_depth": _MAXIMUM_SCAN_DEPTH,
            "maximum_entries": _MAXIMUM_SCAN_ENTRIES,
        },
        domain="release-private-root-policy-v1",
    )
