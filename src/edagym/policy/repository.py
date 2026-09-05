"""Repository boundary audits with metadata-only diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path, PurePosixPath
from typing import IO, Annotated, Never, Self

from pydantic import StringConstraints, model_validator

from edagym.canonical import canonical_digest
from edagym.policy.secrets import (
    matching_content_rules,
    sensitive_path_rule,
    sensitive_root_tree_entry_rule,
    sensitive_tree_entry_rule,
)
from edagym.specs.common import Digest, StrictModel

_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_LFS_POINTER = re.compile(
    rb"\Aversion https://git-lfs\.github\.com/spec/v1\r?\n"
    rb"oid sha256:(?P<oid>[0-9a-f]{64})\r?\n"
    rb"size (?P<size>[0-9]+)\r?\n?\Z"
)
_IO_CHUNK_SIZE = 64 * 1024
_METADATA_PREFIX_SIZE = 8 * 1024
_GIT_EXECUTABLE = "/usr/bin/git"
_GIT_LFS_EXECUTABLE = "/usr/bin/git-lfs"
_EMPTY_CONTENT_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

GitObjectId = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"),
]


class GitObjectFormat(StrEnum):
    SHA1 = "sha1"
    SHA256 = "sha256"


class RepositorySnapshot(StrictModel):
    """Exact Git state and scan scope observed by one repository audit."""

    object_format: GitObjectFormat
    commit_id: GitObjectId
    tree_id: GitObjectId
    index_tree_id: GitObjectId
    worktree_tree_id: GitObjectId | None
    index_state_digest: Digest
    worktree_state_digest: Digest
    ref_set_digest: Digest
    reflog_record_digest: Digest
    lfs_object_inventory_digest: Digest
    scan_scope_digest: Digest

    @model_validator(mode="after")
    def validate_object_format(self) -> Self:
        expected_width = 40 if self.object_format is GitObjectFormat.SHA1 else 64
        object_ids = (
            self.commit_id,
            self.tree_id,
            self.index_tree_id,
            self.worktree_tree_id,
        )
        if any(value is not None and len(value) != expected_width for value in object_ids):
            raise ValueError("repository object ids must match the declared object format")
        if self.worktree_tree_id is not None and self.worktree_tree_id != self.index_tree_id:
            raise ValueError("a verified worktree tree must equal its index tree")
        return self

    @property
    def is_clean(self) -> bool:
        return (
            self.tree_id == self.index_tree_id == self.worktree_tree_id
            and self.worktree_state_digest == _EMPTY_CONTENT_DIGEST
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="repository-snapshot-v2")


class AuditMode(StrEnum):
    COMMIT = "commit"
    RELEASE = "release"


class AuditStatus(StrEnum):
    PASS = "pass"
    VIOLATION = "violation"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class AuditExitCode(IntEnum):
    PASS = 0
    VIOLATION = 1
    INVALID_INVOCATION = 2
    INCOMPLETE = 3
    ERROR = 3


class FindingScope(StrEnum):
    REPOSITORY_CONFIG = "repository-config"
    INDEX_PATH = "index-path"
    INDEX_OBJECT = "index-object"
    TRACKED_PATH = "tracked-path"
    TRACKED_OBJECT = "tracked-object"
    OBJECT_DATABASE = "object-database"
    GIT_REF = "git-ref"
    GIT_REFLOG = "git-reflog"
    GIT_LFS = "git-lfs"
    EXTERNAL_SCANNER = "external-scanner"


class IssueScope(StrEnum):
    REPOSITORY = "repository"
    INDEX = "index"
    REFS = "refs"
    REFLOGS = "reflogs"
    OBJECT_DATABASE = "object-database"
    GIT_LFS = "git-lfs"
    EXTERNAL_SCANNER = "external-scanner"


class IssueSeverity(StrEnum):
    INCOMPLETE = "incomplete"
    ERROR = "error"


class CoverageScope(StrEnum):
    REPOSITORY_IGNORE = "repository-ignore"
    REPOSITORY_STORAGE = "repository-storage"
    REPOSITORY_INTEGRITY = "repository-integrity"
    INDEX_PATHS = "index-paths"
    INDEX_OBJECTS = "index-objects"
    TRACKED_PATHS = "tracked-paths"
    TRACKED_OBJECTS = "tracked-objects"
    GIT_REFS = "git-refs"
    GIT_REFLOGS = "git-reflogs"
    OBJECT_DATABASE = "object-database"
    GIT_LFS = "git-lfs"
    EXTERNAL_SCANNER = "external-scanner"


class CoverageStatus(StrEnum):
    COMPLETE = "complete"
    NOT_REQUIRED = "not-required"
    NOT_USED = "not-used"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class PolicyFinding:
    """A violation location containing no matched content."""

    rule_id: str
    scope: FindingScope
    path: str | None = None
    object_id: str | None = None

    def as_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "scope": self.scope.value}


@dataclass(frozen=True, slots=True)
class AuditIssue:
    """A fixed diagnostic describing unavailable or invalid audit evidence."""

    code: str
    scope: IssueScope
    severity: IssueSeverity

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "scope": self.scope.value,
            "severity": self.severity.value,
        }


@dataclass(frozen=True, slots=True)
class CoverageEvidence:
    scope: CoverageScope
    status: CoverageStatus

    def as_dict(self) -> dict[str, str]:
        return {"scope": self.scope.value, "status": self.status.value}


@dataclass(frozen=True, slots=True)
class AuditReport:
    mode: AuditMode
    status: AuditStatus
    findings: tuple[PolicyFinding, ...]
    issues: tuple[AuditIssue, ...]
    coverage: tuple[CoverageEvidence, ...]
    snapshot: RepositorySnapshot | None

    @property
    def exit_code(self) -> AuditExitCode:
        return AuditExitCode[self.status.name]

    @property
    def digest(self) -> Digest:
        return canonical_digest(self.as_dict(), domain="repository-audit-report-v2")

    def as_dict(self) -> dict[str, object]:
        return {
            "coverage": [item.as_dict() for item in self.coverage],
            "findings": [item.as_dict() for item in self.findings],
            "issues": [item.as_dict() for item in self.issues],
            "mode": self.mode.value,
            "snapshot": (
                None if self.snapshot is None else self.snapshot.model_dump(mode="json")
            ),
            "status": self.status.value,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    def to_text(self) -> str:
        lines = [f"repository-audit mode={self.mode.value} status={self.status.value}"]
        for item in self.coverage:
            lines.append(f"coverage scope={item.scope.value} status={item.status.value}")
        for finding in self.findings:
            fields = [
                "finding",
                f"scope={finding.scope.value}",
                f"rule={finding.rule_id}",
            ]
            lines.append(" ".join(fields))
        for issue in self.issues:
            lines.append(
                f"issue scope={issue.scope.value} severity={issue.severity.value} code={issue.code}"
            )
        return "\n".join(lines)


_SNAPSHOT_BINDING_TOKEN = object()


class RepositorySnapshotBinding:
    """Nonserializable ownership of one descriptor-bound audited Git state."""

    __slots__ = ("_descriptor", "_root", "snapshot")

    def __init__(
        self,
        token: object,
        descriptor: int,
        root: Path,
        snapshot: RepositorySnapshot,
    ) -> None:
        if token is not _SNAPSHOT_BINDING_TOKEN:
            raise TypeError("repository snapshot bindings are issued by repository policy")
        self._descriptor = descriptor
        self._root = root
        self.snapshot = snapshot

    @property
    def root(self) -> Path:
        if self._descriptor < 0:
            raise RuntimeError("repository snapshot binding is closed")
        return self._root

    def verify(self) -> None:
        if self._descriptor < 0 or _capture_repository_state(self._root).snapshot != self.snapshot:
            raise RuntimeError("repository snapshot changed after its audit")

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> RepositorySnapshotBinding:
        self.verify()
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()

    def __reduce__(self) -> Never:
        raise TypeError("repository snapshot bindings cannot be serialized")


def bind_repository_snapshot(
    repository: str | os.PathLike[str],
    snapshot: RepositorySnapshot,
) -> RepositorySnapshotBinding:
    """Open a repository only when its complete live state matches an audit snapshot."""

    if type(snapshot) is not RepositorySnapshot:
        raise TypeError("repository binding requires the canonical snapshot type")
    root, descriptor = _open_repository(Path(repository))
    try:
        if _capture_repository_state(root).snapshot != snapshot:
            raise RuntimeError("repository does not match its audited snapshot")
        return RepositorySnapshotBinding(
            _SNAPSHOT_BINDING_TOKEN,
            descriptor,
            root,
            snapshot,
        )
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(frozen=True, slots=True)
class RepositoryPolicy:
    """Canonical repository boundary policy."""

    required_temp_ignore: str = "/temp/"
    required_private_ignores: tuple[str, ...] = (
        "/.edagym/",
        "/.edagym-state/",
        "/.env",
        "/.env.*",
        "/artifacts/",
        "/auth.json",
        "/credentials/",
        "/runs/",
        "/secrets/",
        "/workspaces/",
    )
    scanner_config: str = ".gitleaks.toml"
    external_scanner_executable: str = "/usr/bin/gitleaks"


@dataclass(frozen=True, slots=True)
class _GitEntry:
    mode: str
    object_id: str
    path: str
    stage: int = 0


@dataclass(frozen=True, slots=True)
class _ObjectDescription:
    object_id: str
    object_type: str
    size: int


@dataclass(frozen=True, slots=True)
class _LfsFile:
    path: Path
    relative_path: str
    object_id: str | None


@dataclass(frozen=True, slots=True)
class _CapturedRepositoryState:
    snapshot: RepositorySnapshot
    index_entries: tuple[_GitEntry, ...]
    tracked_entries: tuple[_GitEntry, ...]
    ref_records: bytes
    reflog_inventory: bytes
    lfs_object_inventory: bytes
    object_descriptions: tuple[_ObjectDescription, ...]
    index_clean: bool
    worktree_clean: bool


@dataclass(frozen=True, slots=True)
class _TreeHit:
    rule_id: str
    name: str


@dataclass(frozen=True, slots=True)
class _ObjectScan:
    object_id: str
    object_type: str
    content_rules: frozenset[str]
    lfs_object_id: str | None
    lfs_object_size: int | None
    commit_tree_id: str | None
    tree_hits: tuple[_TreeHit, ...]
    root_tree_hits: tuple[_TreeHit, ...]
    has_temp_tree: bool
    targets_temp: bool
    target_path_rule: str | None


class _GitFailure(RuntimeError):
    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(operation)


class _ObjectProtocolFailure(RuntimeError):
    pass


def audit_repository(
    repository: str | os.PathLike[str],
    mode: AuditMode = AuditMode.COMMIT,
    *,
    policy: RepositoryPolicy | None = None,
) -> AuditReport:
    """Audit one Git repository and return a secret-safe, deterministic report."""

    active_policy = policy or RepositoryPolicy()
    findings: set[PolicyFinding] = set()
    issues: set[AuditIssue] = set()
    coverage: dict[CoverageScope, CoverageStatus] = {}

    try:
        root, root_descriptor = _open_repository(Path(repository))
    except (_GitFailure, OSError):
        issues.add(AuditIssue("not-a-git-repository", IssueScope.REPOSITORY, IssueSeverity.ERROR))
        return _build_report(mode, findings, issues, coverage, snapshot=None)

    try:
        return _audit_open_repository(
            root,
            mode,
            active_policy,
            findings,
            issues,
            coverage,
        )
    finally:
        os.close(root_descriptor)


def _audit_open_repository(
    root: Path,
    mode: AuditMode,
    policy: RepositoryPolicy,
    findings: set[PolicyFinding],
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
) -> AuditReport:
    state: _CapturedRepositoryState | None = None
    try:
        state = _capture_repository_state(root)
    except (_GitFailure, _ObjectProtocolFailure):
        issues.add(
            AuditIssue(
                "repository-snapshot-unavailable",
                IssueScope.REPOSITORY,
                IssueSeverity.ERROR,
            )
        )

    index_entries = () if state is None else state.index_entries
    try:
        if state is None:
            raise _GitFailure("index-snapshot-unavailable")
        _audit_repository_files(root, index_entries, policy, findings, issues, coverage)
        for entry in index_entries:
            if entry.stage != 0:
                findings.add(
                    PolicyFinding(
                        "unmerged-index-entry",
                        FindingScope.INDEX_PATH,
                        path=entry.path,
                        object_id=entry.object_id,
                    )
                )
        _audit_entries(
            root,
            index_entries,
            FindingScope.INDEX_PATH,
            FindingScope.INDEX_OBJECT,
            findings,
        )
        coverage[CoverageScope.INDEX_PATHS] = CoverageStatus.COMPLETE
        coverage[CoverageScope.INDEX_OBJECTS] = CoverageStatus.COMPLETE
    except (_GitFailure, _ObjectProtocolFailure):
        issues.add(AuditIssue("index-audit-failed", IssueScope.INDEX, IssueSeverity.ERROR))
        coverage[CoverageScope.REPOSITORY_IGNORE] = CoverageStatus.INCOMPLETE
        coverage[CoverageScope.INDEX_PATHS] = CoverageStatus.INCOMPLETE
        coverage[CoverageScope.INDEX_OBJECTS] = CoverageStatus.INCOMPLETE

    try:
        if state is None:
            raise _GitFailure("head-snapshot-unavailable")
        _audit_entries(
            root,
            state.tracked_entries,
            FindingScope.TRACKED_PATH,
            FindingScope.TRACKED_OBJECT,
            findings,
        )
        coverage[CoverageScope.TRACKED_PATHS] = CoverageStatus.COMPLETE
        coverage[CoverageScope.TRACKED_OBJECTS] = CoverageStatus.COMPLETE
    except (_GitFailure, _ObjectProtocolFailure):
        issues.add(AuditIssue("tracked-audit-failed", IssueScope.INDEX, IssueSeverity.ERROR))
        coverage[CoverageScope.TRACKED_PATHS] = CoverageStatus.INCOMPLETE
        coverage[CoverageScope.TRACKED_OBJECTS] = CoverageStatus.INCOMPLETE

    if mode is AuditMode.RELEASE:
        if state is None or not state.index_clean:
            issues.add(AuditIssue("release-index-dirty", IssueScope.INDEX, IssueSeverity.ERROR))
        if state is None or not state.worktree_clean:
            issues.add(
                AuditIssue("release-worktree-dirty", IssueScope.REPOSITORY, IssueSeverity.ERROR)
            )
        _audit_release(root, policy, findings, issues, coverage, state)
    else:
        coverage[CoverageScope.GIT_REFS] = CoverageStatus.NOT_REQUIRED
        coverage[CoverageScope.GIT_REFLOGS] = CoverageStatus.NOT_REQUIRED
        coverage[CoverageScope.REPOSITORY_STORAGE] = CoverageStatus.NOT_REQUIRED
        coverage[CoverageScope.REPOSITORY_INTEGRITY] = CoverageStatus.NOT_REQUIRED
        coverage[CoverageScope.OBJECT_DATABASE] = CoverageStatus.NOT_REQUIRED
        coverage[CoverageScope.GIT_LFS] = CoverageStatus.NOT_REQUIRED
        _run_external_scanner(
            root,
            policy,
            findings,
            issues,
            coverage,
            state,
        )

    try:
        final_state = _capture_repository_state(root)
    except (_GitFailure, _ObjectProtocolFailure):
        final_state = None
    if state is None or final_state is None or final_state.snapshot != state.snapshot:
        issues.add(
            AuditIssue(
                "repository-snapshot-changed",
                IssueScope.REPOSITORY,
                IssueSeverity.INCOMPLETE,
            )
        )
        if mode is AuditMode.RELEASE:
            coverage[CoverageScope.REPOSITORY_INTEGRITY] = CoverageStatus.INCOMPLETE

    return _build_report(
        mode,
        findings,
        issues,
        coverage,
        snapshot=None if state is None else state.snapshot,
    )


def _audit_repository_files(
    root: Path,
    entries: tuple[_GitEntry, ...],
    policy: RepositoryPolicy,
    findings: set[PolicyFinding],
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
) -> None:
    ignore_lines: set[bytes] = set()
    private_ignores = {
        entry.encode("utf-8") for entry in policy.required_private_ignores
    }
    try:
        ignore_bytes = _indexed_file_bytes(root, entries, ".gitignore")
        ignore_lines = set(ignore_bytes.splitlines())
        exact_ignore = policy.required_temp_ignore.encode("utf-8") in ignore_lines
    except LookupError:
        exact_ignore = False
    except (_GitFailure, _ObjectProtocolFailure):
        issues.add(
            AuditIssue(
                "repository-ignore-read-failed",
                IssueScope.REPOSITORY,
                IssueSeverity.ERROR,
            )
        )
        coverage[CoverageScope.REPOSITORY_IGNORE] = CoverageStatus.INCOMPLETE
        return
    if not exact_ignore:
        findings.add(
            PolicyFinding("repository-temp-ignore-missing", FindingScope.REPOSITORY_CONFIG)
        )
    if not private_ignores.issubset(ignore_lines):
        findings.add(
            PolicyFinding("repository-private-ignore-missing", FindingScope.REPOSITORY_CONFIG)
        )
    coverage[CoverageScope.REPOSITORY_IGNORE] = CoverageStatus.COMPLETE


def _indexed_file_bytes(
    root: Path, entries: tuple[_GitEntry, ...], path: str
) -> bytes:
    matching = [entry for entry in entries if entry.path == path and entry.stage == 0]
    if len(matching) != 1 or matching[0].mode != "100644":
        raise LookupError(path)
    data = _run_git(root, "cat-file", "blob", matching[0].object_id)
    if len(data) > 1024 * 1024:
        raise _ObjectProtocolFailure
    return data


def _audit_entries(
    root: Path,
    entries: tuple[_GitEntry, ...],
    path_scope: FindingScope,
    object_scope: FindingScope,
    findings: set[PolicyFinding],
) -> None:
    by_object: dict[str, list[_GitEntry]] = {}
    for entry in entries:
        _audit_path(entry.path, path_scope, findings)
        if entry.mode == "160000":
            findings.add(
                PolicyFinding("submodule-not-audited", path_scope, entry.path, entry.object_id)
            )
            continue
        by_object.setdefault(entry.object_id, []).append(entry)

    scans = _scan_objects(
        root,
        tuple(_ObjectDescription(object_id, "blob", 0) for object_id in sorted(by_object)),
    )
    for scan in scans:
        object_entries = by_object[scan.object_id]
        representative_path = min(entry.path for entry in object_entries)
        for rule_id in scan.content_rules:
            findings.add(
                PolicyFinding(rule_id, object_scope, representative_path, scan.object_id)
            )
        for entry in object_entries:
            if entry.mode == "120000" and _symlink_targets_temp(scan):
                findings.add(
                    PolicyFinding("symlink-targets-temp", path_scope, entry.path, entry.object_id)
                )
            if entry.mode == "120000" and scan.target_path_rule is not None:
                findings.add(
                    PolicyFinding(
                        f"symlink-target-{scan.target_path_rule}",
                        path_scope,
                        entry.path,
                        entry.object_id,
                    )
                )


def _audit_path(path: str, scope: FindingScope, findings: set[PolicyFinding]) -> None:
    normalized = PurePosixPath(path.replace("\\", "/"))
    if normalized.parts and normalized.parts[0].casefold() == "temp":
        findings.add(PolicyFinding("tracked-temp-path", scope, path))
    rule_id = sensitive_path_rule(path)
    if rule_id is not None:
        findings.add(PolicyFinding(rule_id, scope, path))


def _symlink_targets_temp(scan: _ObjectScan) -> bool:
    return scan.object_type == "blob" and scan.targets_temp


def _audit_release(
    root: Path,
    policy: RepositoryPolicy,
    findings: set[PolicyFinding],
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
    state: _CapturedRepositoryState | None,
) -> None:
    _audit_storage_shape(root, issues, coverage)
    _audit_git_integrity(root, issues, coverage)
    _inspect_refs_and_reflogs(
        root,
        None if state is None else state.ref_records,
        None if state is None else state.reflog_inventory,
        findings,
        issues,
        coverage,
    )

    object_scans: tuple[_ObjectScan, ...] = ()
    try:
        if state is None:
            raise _ObjectProtocolFailure
        object_scans = _scan_objects(root, state.object_descriptions)
        _add_object_findings(object_scans, findings)
        coverage[CoverageScope.OBJECT_DATABASE] = CoverageStatus.COMPLETE
    except (_GitFailure, _ObjectProtocolFailure):
        issues.add(
            AuditIssue(
                "object-database-audit-failed",
                IssueScope.OBJECT_DATABASE,
                IssueSeverity.ERROR,
            )
        )
        coverage[CoverageScope.OBJECT_DATABASE] = CoverageStatus.INCOMPLETE

    _audit_lfs(
        root,
        object_scans,
        issues,
        findings,
        coverage,
        None if state is None else state.lfs_object_inventory,
    )
    _run_external_scanner(root, policy, findings, issues, coverage, state)


def _audit_storage_shape(
    root: Path,
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
) -> None:
    try:
        shallow = os.fsdecode(
            _run_git(root, "rev-parse", "--is-shallow-repository").strip()
        )
        if shallow not in {"true", "false"}:
            raise _ObjectProtocolFailure
        if shallow == "true":
            issues.add(
                AuditIssue(
                    "shallow-repository",
                    IssueScope.REPOSITORY,
                    IssueSeverity.INCOMPLETE,
                )
            )

        partial_clone = subprocess.run(
            [
                _GIT_EXECUTABLE,
                "config",
                "--local",
                "--get-regexp",
                r"^(extensions\.partialClone|remote\..*\.promisor)$",
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env=_git_environment(),
        )
        if partial_clone.returncode == 0:
            issues.add(
                AuditIssue(
                    "partial-repository",
                    IssueScope.REPOSITORY,
                    IssueSeverity.INCOMPLETE,
                )
            )
        elif partial_clone.returncode != 1:
            raise _GitFailure("partial-clone-check")

        common_dir = _git_directory(root, common=True)
        alternates = common_dir / "objects" / "info" / "alternates"
        if os.path.lexists(alternates) or os.environ.get("GIT_ALTERNATE_OBJECT_DIRECTORIES"):
            issues.add(
                AuditIssue(
                    "alternate-object-storage",
                    IssueScope.REPOSITORY,
                    IssueSeverity.INCOMPLETE,
                )
            )
        coverage[CoverageScope.REPOSITORY_STORAGE] = CoverageStatus.COMPLETE
    except (_GitFailure, _ObjectProtocolFailure, OSError):
        issues.add(
            AuditIssue(
                "repository-storage-audit-failed",
                IssueScope.REPOSITORY,
                IssueSeverity.ERROR,
            )
        )
        coverage[CoverageScope.REPOSITORY_STORAGE] = CoverageStatus.INCOMPLETE


def _audit_git_integrity(
    root: Path,
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
) -> None:
    result = subprocess.run(
        [_GIT_EXECUTABLE, "fsck", "--full", "--strict"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=_git_environment(),
    )
    if result.returncode == 0:
        coverage[CoverageScope.REPOSITORY_INTEGRITY] = CoverageStatus.COMPLETE
        return
    issues.add(
        AuditIssue(
            "repository-integrity-check-failed",
            IssueScope.REPOSITORY,
            IssueSeverity.INCOMPLETE,
        )
    )
    coverage[CoverageScope.REPOSITORY_INTEGRITY] = CoverageStatus.INCOMPLETE


def _inspect_refs_and_reflogs(
    root: Path,
    ref_records: bytes | None,
    expected_reflog_inventory: bytes | None,
    findings: set[PolicyFinding],
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
) -> None:
    try:
        if ref_records is None:
            raise _ObjectProtocolFailure
        for rule_id in matching_content_rules((ref_records,)):
            findings.add(PolicyFinding(rule_id, FindingScope.GIT_REF))
        for record in ref_records.splitlines():
            _object_id, separator, raw_ref_name = record.partition(b"\0")
            if not separator:
                raise _ObjectProtocolFailure
            if sensitive_path_rule(os.fsdecode(raw_ref_name)) is not None:
                findings.add(PolicyFinding("sensitive-ref-name", FindingScope.GIT_REF))
        coverage[CoverageScope.GIT_REFS] = CoverageStatus.COMPLETE
    except (_GitFailure, _ObjectProtocolFailure):
        issues.add(AuditIssue("git-ref-audit-failed", IssueScope.REFS, IssueSeverity.ERROR))
        coverage[CoverageScope.GIT_REFS] = CoverageStatus.INCOMPLETE

    try:
        if expected_reflog_inventory is None:
            raise _ObjectProtocolFailure
        for rule_id in _reflog_content_rules(root):
            findings.add(PolicyFinding(rule_id, FindingScope.GIT_REFLOG))
        if _reflog_inventory(root) != expected_reflog_inventory:
            raise _ObjectProtocolFailure
        coverage[CoverageScope.GIT_REFLOGS] = CoverageStatus.COMPLETE
    except (_GitFailure, _ObjectProtocolFailure, OSError):
        issues.add(AuditIssue("git-reflog-audit-failed", IssueScope.REFLOGS, IssueSeverity.ERROR))
        coverage[CoverageScope.GIT_REFLOGS] = CoverageStatus.INCOMPLETE


def _reflog_content_rules(root: Path) -> frozenset[str]:
    matched: set[str] = set()
    git_directories = {_git_directory(root, common=False), _git_directory(root, common=True)}
    for git_directory in sorted(git_directories):
        logs = git_directory / "logs"
        if not logs.exists():
            continue
        if logs.is_symlink() or not logs.is_dir():
            raise OSError
        for directory, directory_names, file_names in os.walk(logs, followlinks=False):
            directory_names.sort()
            file_names.sort()
            if any((Path(directory) / name).is_symlink() for name in directory_names):
                raise OSError
            for file_name in file_names:
                path = Path(directory) / file_name
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode) or path.is_symlink():
                    raise OSError
                with path.open("rb") as stream:
                    matched.update(
                        matching_content_rules(iter(lambda: stream.read(_IO_CHUNK_SIZE), b""))
                    )
                after = path.lstat()
                if _file_identity(before) != _file_identity(after):
                    raise _ObjectProtocolFailure
    return frozenset(matched)


def _add_object_findings(
    scans: tuple[_ObjectScan, ...], findings: set[PolicyFinding]
) -> None:
    commit_root_trees = {
        scan.commit_tree_id for scan in scans if scan.commit_tree_id is not None
    }
    for scan in scans:
        if scan.object_id in commit_root_trees:
            for hit in scan.root_tree_hits:
                findings.add(
                    PolicyFinding(
                        hit.rule_id,
                        FindingScope.OBJECT_DATABASE,
                        path=hit.name,
                        object_id=scan.object_id,
                    )
                )
        for rule_id in scan.content_rules:
            findings.add(
                PolicyFinding(rule_id, FindingScope.OBJECT_DATABASE, object_id=scan.object_id)
            )
        for hit in scan.tree_hits:
            findings.add(
                PolicyFinding(
                    hit.rule_id,
                    FindingScope.OBJECT_DATABASE,
                    path=hit.name,
                    object_id=scan.object_id,
                )
            )
        if scan.object_id in commit_root_trees and scan.has_temp_tree:
            findings.add(
                PolicyFinding(
                    "historical-temp-path",
                    FindingScope.OBJECT_DATABASE,
                    path="temp",
                    object_id=scan.object_id,
                )
            )


def _audit_lfs(
    root: Path,
    scans: tuple[_ObjectScan, ...],
    issues: set[AuditIssue],
    findings: set[PolicyFinding],
    coverage: dict[CoverageScope, CoverageStatus],
    expected_inventory: bytes | None,
) -> None:
    pointer_sizes: dict[str, set[int]] = {}
    for scan in scans:
        if scan.lfs_object_id is not None and scan.lfs_object_size is not None:
            pointer_sizes.setdefault(scan.lfs_object_id, set()).add(scan.lfs_object_size)
    try:
        git_common_dir_raw = _run_git(root, "rev-parse", "--git-common-dir")
        git_common_dir = Path(os.fsdecode(git_common_dir_raw.rstrip(b"\n")))
        if not git_common_dir.is_absolute():
            git_common_dir = root / git_common_dir
        lfs_objects_root = git_common_dir / "lfs" / "objects"
        local_files = tuple(_local_lfs_files(lfs_objects_root))
        local_objects = tuple(
            item for item in local_files if item.object_id is not None
        )
        inventory_stable = (
            expected_inventory is not None
            and _lfs_object_inventory(root) == expected_inventory
        )
    except (_GitFailure, OSError, _ObjectProtocolFailure):
        issues.add(AuditIssue("git-lfs-audit-failed", IssueScope.GIT_LFS, IssueSeverity.ERROR))
        coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE
        return

    if not inventory_stable:
        issues.add(
            AuditIssue(
                "git-lfs-inventory-changed",
                IssueScope.GIT_LFS,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE

    lfs_is_used = bool(pointer_sizes or local_files)
    if not lfs_is_used:
        if inventory_stable:
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.NOT_USED
        return

    git_lfs = Path(_GIT_LFS_EXECUTABLE)
    if not _trusted_executable(git_lfs):
        issues.add(AuditIssue("git-lfs-unavailable", IssueScope.GIT_LFS, IssueSeverity.INCOMPLETE))
        coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE
    else:
        result = subprocess.run(
            [os.fspath(git_lfs), "fsck", "--dry-run", "--objects", "--pointers"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env=_git_environment(),
        )
        if result.returncode != 0:
            issues.add(
                AuditIssue("git-lfs-fsck-failed", IssueScope.GIT_LFS, IssueSeverity.INCOMPLETE)
            )
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE

    local_ids = {item.object_id for item in local_objects}
    for pointer_id, expected_sizes in pointer_sizes.items():
        if len(expected_sizes) != 1:
            findings.add(
                PolicyFinding(
                    "git-lfs-pointer-size-conflict",
                    FindingScope.GIT_LFS,
                    object_id=f"sha256:{pointer_id}",
                )
            )
        if pointer_id not in local_ids:
            issues.add(
                AuditIssue(
                    "git-lfs-object-unavailable",
                    IssueScope.GIT_LFS,
                    IssueSeverity.INCOMPLETE,
                )
            )
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE

    for item in local_files:
        object_id = item.object_id
        path = item.path
        if object_id is None:
            findings.add(
                PolicyFinding(
                    "git-lfs-object-layout-invalid",
                    FindingScope.GIT_LFS,
                    path=item.relative_path,
                )
            )
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or path.is_symlink():
                raise OSError
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                rules = matching_content_rules(_hashing_chunks(stream, digest.update))
            after = path.lstat()
            if _file_identity(before) != _file_identity(after):
                raise _ObjectProtocolFailure
        except OSError:
            issues.add(
                AuditIssue("git-lfs-object-read-failed", IssueScope.GIT_LFS, IssueSeverity.ERROR)
            )
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE
            continue
        except _ObjectProtocolFailure:
            issues.add(
                AuditIssue("git-lfs-object-changed", IssueScope.GIT_LFS, IssueSeverity.INCOMPLETE)
            )
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE
            continue
        if object_id is not None and digest.hexdigest() != object_id:
            issues.add(
                AuditIssue(
                    "git-lfs-object-hash-mismatch",
                    IssueScope.GIT_LFS,
                    IssueSeverity.INCOMPLETE,
                )
            )
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE
        pointer_expected_sizes = (
            None if object_id is None else pointer_sizes.get(object_id)
        )
        if pointer_expected_sizes is not None and before.st_size not in pointer_expected_sizes:
            issues.add(
                AuditIssue(
                    "git-lfs-object-size-mismatch",
                    IssueScope.GIT_LFS,
                    IssueSeverity.INCOMPLETE,
                )
            )
            coverage[CoverageScope.GIT_LFS] = CoverageStatus.INCOMPLETE
        for rule_id in rules:
            findings.add(
                PolicyFinding(
                    rule_id,
                    FindingScope.GIT_LFS,
                    path=item.relative_path if object_id is None else None,
                    object_id=(
                        None if object_id is None else f"sha256:{object_id}"
                    ),
                )
            )

    if CoverageScope.GIT_LFS not in coverage:
        coverage[CoverageScope.GIT_LFS] = CoverageStatus.COMPLETE


def _local_lfs_files(root: Path) -> Iterator[_LfsFile]:
    if not root.exists():
        return
    if root.is_symlink():
        raise OSError
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        if any((Path(directory) / name).is_symlink() for name in directory_names):
            raise OSError
        for file_name in file_names:
            path = Path(directory) / file_name
            if path.is_symlink() or not path.is_file():
                raise OSError
            relative_path = path.relative_to(root)
            parts = relative_path.parts
            object_id = (
                file_name
                if re.fullmatch(r"[0-9a-f]{64}", file_name)
                and len(parts) == 3
                and parts[0] == file_name[:2]
                and parts[1] == file_name[2:4]
                else None
            )
            yield _LfsFile(path, relative_path.as_posix(), object_id)


def _hashing_chunks(
    stream: IO[bytes], update_digest: Callable[[bytes], object]
) -> Iterator[bytes]:
    while chunk := stream.read(_IO_CHUNK_SIZE):
        update_digest(chunk)
        yield chunk


def _run_external_scanner(
    root: Path,
    policy: RepositoryPolicy,
    findings: set[PolicyFinding],
    issues: set[AuditIssue],
    coverage: dict[CoverageScope, CoverageStatus],
    state: _CapturedRepositoryState | None,
) -> None:
    scanner_config = root / policy.scanner_config
    scanner = Path(policy.external_scanner_executable)
    try:
        if state is None:
            raise _ObjectProtocolFailure
        indexed_config = _indexed_file_bytes(root, state.index_entries, policy.scanner_config)
        config_metadata = scanner_config.lstat()
        working_config = scanner_config.read_bytes()
    except (LookupError, OSError, _GitFailure, _ObjectProtocolFailure):
        indexed_config = b""
        working_config = b"invalid"
        config_metadata = None
    if (
        config_metadata is None
        or not stat.S_ISREG(config_metadata.st_mode)
        or scanner_config.is_symlink()
        or working_config != indexed_config
        or not _strict_scanner_config(indexed_config)
    ):
        issues.add(
            AuditIssue(
                "external-scanner-config-unavailable",
                IssueScope.EXTERNAL_SCANNER,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.INCOMPLETE
        return
    if not scanner.is_absolute() or not _trusted_executable(scanner):
        issues.add(
            AuditIssue(
                "external-scanner-unavailable",
                IssueScope.EXTERNAL_SCANNER,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.INCOMPLETE
        return

    process = subprocess.Popen(
        [
            os.fspath(scanner),
            "stdin",
            "--no-banner",
            "--no-color",
            "--redact",
            "--ignore-gitleaks-allow",
            "--config",
            policy.scanner_config,
            "--exit-code",
            "1",
        ],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_git_environment(),
    )
    if process.stdin is None:
        process.kill()
        issues.add(
            AuditIssue(
                "external-scanner-execution-failed",
                IssueScope.EXTERNAL_SCANNER,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.INCOMPLETE
        return
    corpus_complete = True
    try:
        if state is None:
            raise _ObjectProtocolFailure
        _write_release_corpus(
            root,
            process.stdin,
            state.object_descriptions,
            state.ref_records,
        )
    except (BrokenPipeError, OSError, _GitFailure, _ObjectProtocolFailure):
        corpus_complete = False
    finally:
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError):
            corpus_complete = False
    return_code = process.wait()
    try:
        config_unchanged = scanner_config.read_bytes() == indexed_config
    except OSError:
        config_unchanged = False
    if not corpus_complete:
        issues.add(
            AuditIssue(
                "external-scanner-corpus-incomplete",
                IssueScope.EXTERNAL_SCANNER,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.INCOMPLETE
    elif not config_unchanged:
        issues.add(
            AuditIssue(
                "external-scanner-config-changed",
                IssueScope.EXTERNAL_SCANNER,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.INCOMPLETE
    elif return_code == 0:
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.COMPLETE
    elif return_code == 1:
        findings.add(
            PolicyFinding("external-scanner-detection", FindingScope.EXTERNAL_SCANNER)
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.COMPLETE
    else:
        issues.add(
            AuditIssue(
                "external-scanner-execution-failed",
                IssueScope.EXTERNAL_SCANNER,
                IssueSeverity.INCOMPLETE,
            )
        )
        coverage[CoverageScope.EXTERNAL_SCANNER] = CoverageStatus.INCOMPLETE


def _write_release_corpus(
    root: Path,
    stream: IO[bytes],
    object_descriptions: tuple[_ObjectDescription, ...],
    ref_records: bytes,
) -> None:
    for description in object_descriptions:
        stream.write(
            _run_git(root, "cat-file", description.object_type, description.object_id)
        )
        stream.write(b"\n")
    stream.write(ref_records)
    stream.write(b"\n")
    for path in _reflog_paths(root):
        with path.open("rb") as source:
            while chunk := source.read(_IO_CHUNK_SIZE):
                stream.write(chunk)
        stream.write(b"\n")
    lfs_root = _git_directory(root, common=True) / "lfs" / "objects"
    for item in _local_lfs_files(lfs_root):
        with item.path.open("rb") as source:
            while chunk := source.read(_IO_CHUNK_SIZE):
                stream.write(chunk)
        stream.write(b"\n")


def _reflog_paths(root: Path) -> Iterator[Path]:
    git_directories = {_git_directory(root, common=False), _git_directory(root, common=True)}
    for git_directory in sorted(git_directories):
        logs = git_directory / "logs"
        if not logs.exists():
            continue
        if logs.is_symlink() or not logs.is_dir():
            raise OSError
        for directory, directory_names, file_names in os.walk(logs, followlinks=False):
            directory_names.sort()
            file_names.sort()
            if any((Path(directory) / name).is_symlink() for name in directory_names):
                raise OSError
            for file_name in file_names:
                path = Path(directory) / file_name
                if path.is_symlink() or not path.is_file():
                    raise OSError
                yield path


def _strict_scanner_config(data: bytes) -> bool:
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    extend = document.get("extend")
    if not isinstance(extend, dict) or extend.get("useDefault") is not True:
        return False

    def contains_suppression(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                str(key).casefold() in {"allowlist", "allowlists"}
                or contains_suppression(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(contains_suppression(item) for item in value)
        return False

    return not contains_suppression(document)


def _repository_root(candidate: Path) -> Path:
    output = _run_git(candidate, "rev-parse", "--show-toplevel")
    decoded = os.fsdecode(output.rstrip(b"\n"))
    if not decoded:
        raise _GitFailure("repository-root")
    return Path(decoded).resolve()


def _open_repository(candidate: Path) -> tuple[Path, int]:
    resolved = _repository_root(candidate)
    descriptor = os.open(
        resolved,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        before = resolved.stat()
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise OSError("repository root changed while it was opened")
        descriptor_root = Path(f"/proc/self/fd/{descriptor}")
        if not descriptor_root.exists():
            raise OSError("descriptor filesystem is unavailable")
        observed = _repository_root(descriptor_root).stat()
        if (observed.st_dev, observed.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("opened directory is not the repository root")
        return descriptor_root, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _capture_repository_state(root: Path) -> _CapturedRepositoryState:
    object_format = _object_format(root)
    commit_id = os.fsdecode(
        _run_git(root, "rev-parse", "--verify", "HEAD^{commit}").strip()
    )
    _validate_object_id(commit_id, object_format)
    tree_id = os.fsdecode(
        _run_git(root, "rev-parse", "--verify", f"{commit_id}^{{tree}}").strip()
    )
    _validate_object_id(tree_id, object_format)

    raw_index = _run_git(root, "ls-files", "--stage", "-z")
    index_entries = _parse_index_entries(raw_index, object_format)
    index_tree_id = os.fsdecode(_run_git(root, "write-tree").strip())
    _validate_object_id(index_tree_id, object_format)
    status = _run_git(
        root,
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    untracked = _run_git(root, "ls-files", "--others", "--exclude-standard", "-z")
    index_clean = (
        index_tree_id == tree_id
        and _git_diff_is_clean(root, "diff-index", "--quiet", "--cached", commit_id, "--")
    )
    tracked_worktree_clean = _git_diff_is_clean(
        root,
        "diff-files",
        "--quiet",
        "--ignore-submodules=none",
        "--",
    )
    worktree_tree_id = index_tree_id if tracked_worktree_clean and not untracked else None
    worktree_clean = index_clean and tracked_worktree_clean and not status

    ref_records = _ref_records(root, object_format)
    reflog_inventory = _reflog_inventory(root)
    lfs_object_inventory = _lfs_object_inventory(root)
    descriptions = _all_objects(root, object_format=object_format)
    ref_set_digest = _bytes_digest(ref_records)
    reflog_record_digest = _bytes_digest(reflog_inventory)
    lfs_object_inventory_digest = _bytes_digest(lfs_object_inventory)
    scan_scope_digest = canonical_digest(
        {
            "lfs_object_inventory_digest": lfs_object_inventory_digest,
            "object_format": object_format.value,
            "objects": tuple(
                {
                    "object_id": item.object_id,
                    "object_type": item.object_type,
                    "size": item.size,
                }
                for item in descriptions
            ),
            "ref_set_digest": ref_set_digest,
            "reflog_record_digest": reflog_record_digest,
        },
        domain="repository-audit-scan-scope-v2",
    )
    snapshot = RepositorySnapshot(
        object_format=object_format,
        commit_id=commit_id,
        tree_id=tree_id,
        index_tree_id=index_tree_id,
        worktree_tree_id=worktree_tree_id,
        index_state_digest=_bytes_digest(raw_index),
        worktree_state_digest=_bytes_digest(status),
        ref_set_digest=ref_set_digest,
        reflog_record_digest=reflog_record_digest,
        lfs_object_inventory_digest=lfs_object_inventory_digest,
        scan_scope_digest=scan_scope_digest,
    )
    if (
        os.fsdecode(_run_git(root, "rev-parse", "--verify", "HEAD^{commit}").strip())
        != commit_id
        or _run_git(root, "ls-files", "--stage", "-z") != raw_index
        or os.fsdecode(_run_git(root, "write-tree").strip()) != index_tree_id
        or _run_git(
            root,
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        != status
    ):
        raise _ObjectProtocolFailure
    return _CapturedRepositoryState(
        snapshot=snapshot,
        index_entries=index_entries,
        tracked_entries=_head_entries(root, snapshot),
        ref_records=ref_records,
        reflog_inventory=reflog_inventory,
        lfs_object_inventory=lfs_object_inventory,
        object_descriptions=descriptions,
        index_clean=index_clean,
        worktree_clean=worktree_clean,
    )


def _bytes_digest(data: bytes) -> Digest:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _validate_object_id(object_id: str, object_format: GitObjectFormat) -> None:
    expected_width = 40 if object_format is GitObjectFormat.SHA1 else 64
    if len(object_id) != expected_width or _OBJECT_ID.fullmatch(object_id) is None:
        raise _ObjectProtocolFailure


def _git_diff_is_clean(root: Path, *arguments: str) -> bool:
    result = subprocess.run(
        [_GIT_EXECUTABLE, *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=_git_environment(),
    )
    if result.returncode not in {0, 1}:
        raise _GitFailure(arguments[0] if arguments else "git-diff")
    return result.returncode == 0


def _ref_records(root: Path, object_format: GitObjectFormat) -> bytes:
    records = _run_git(
        root,
        "for-each-ref",
        "--sort=refname",
        "--format=%(objectname)%00%(refname)",
    )
    for record in records.splitlines():
        raw_object_id, separator, raw_ref = record.partition(b"\0")
        if not separator or not raw_ref:
            raise _ObjectProtocolFailure
        try:
            object_id = raw_object_id.decode("ascii")
        except UnicodeDecodeError as error:
            raise _ObjectProtocolFailure from error
        _validate_object_id(object_id, object_format)
    return records


def _reflog_inventory(root: Path) -> bytes:
    records: list[dict[str, object]] = []
    seen_directories: set[tuple[int, int]] = set()
    for role, git_directory in (
        ("worktree", _git_directory(root, common=False)),
        ("common", _git_directory(root, common=True)),
    ):
        directory_metadata = git_directory.stat()
        directory_identity = (directory_metadata.st_dev, directory_metadata.st_ino)
        if directory_identity in seen_directories:
            continue
        seen_directories.add(directory_identity)
        logs = git_directory / "logs"
        if not logs.exists():
            continue
        if logs.is_symlink() or not logs.is_dir():
            raise OSError
        for directory, directory_names, file_names in os.walk(logs, followlinks=False):
            directory_names.sort()
            file_names.sort()
            if any((Path(directory) / name).is_symlink() for name in directory_names):
                raise OSError
            for file_name in file_names:
                path = Path(directory) / file_name
                records.append(
                    {
                        "content_digest": _stable_file_digest(path),
                        "path": path.relative_to(logs).as_posix(),
                        "role": role,
                    }
                )
    return json.dumps(
        records,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _lfs_object_inventory(root: Path) -> bytes:
    lfs_root = _git_directory(root, common=True) / "lfs" / "objects"
    records = tuple(
        {
            "content_digest": _stable_file_digest(item.path),
            "object_id": item.object_id,
            "path": item.relative_path,
        }
        for item in _local_lfs_files(lfs_root)
    )
    return json.dumps(
        records,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _stable_file_digest(path: Path) -> Digest:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise OSError
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_IO_CHUNK_SIZE):
            digest.update(chunk)
    after = path.lstat()
    if _file_identity(before) != _file_identity(after):
        raise _ObjectProtocolFailure
    return f"sha256:{digest.hexdigest()}"


def _index_entries(root: Path) -> tuple[_GitEntry, ...]:
    return _parse_index_entries(
        _run_git(root, "ls-files", "--stage", "-z"),
        _object_format(root),
    )


def _parse_index_entries(
    output: bytes,
    object_format: GitObjectFormat,
) -> tuple[_GitEntry, ...]:
    entries: list[_GitEntry] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise _ObjectProtocolFailure
        mode, object_id, raw_stage = (os.fsdecode(field) for field in fields)
        _validate_object_id(object_id, object_format)
        try:
            stage = int(raw_stage)
        except ValueError as error:
            raise _ObjectProtocolFailure from error
        if stage not in {0, 1, 2, 3}:
            raise _ObjectProtocolFailure
        entries.append(_GitEntry(mode, object_id, os.fsdecode(raw_path), stage))
    return tuple(entries)


def _head_entries(root: Path, snapshot: RepositorySnapshot) -> tuple[_GitEntry, ...]:
    output = _run_git(
        root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        snapshot.tree_id,
    )
    entries: list[_GitEntry] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise _ObjectProtocolFailure
        mode, object_type, object_id = (os.fsdecode(field) for field in fields)
        if object_type not in {"blob", "commit"}:
            raise _ObjectProtocolFailure
        _validate_object_id(object_id, snapshot.object_format)
        entries.append(_GitEntry(mode, object_id, os.fsdecode(raw_path)))
    return tuple(entries)


def _all_objects(
    root: Path,
    *,
    object_format: GitObjectFormat | None = None,
) -> tuple[_ObjectDescription, ...]:
    active_format = object_format or _object_format(root)
    output = _run_git(
        root,
        "cat-file",
        "--batch-all-objects",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
    )
    descriptions: list[_ObjectDescription] = []
    for line in output.splitlines():
        fields = line.split(b" ")
        if len(fields) != 3:
            raise _ObjectProtocolFailure
        object_id, object_type, size = (os.fsdecode(field) for field in fields)
        if object_type not in {
            "blob",
            "commit",
            "tag",
            "tree",
        }:
            raise _ObjectProtocolFailure
        _validate_object_id(object_id, active_format)
        try:
            parsed_size = int(size)
        except ValueError as error:
            raise _ObjectProtocolFailure from error
        descriptions.append(_ObjectDescription(object_id, object_type, parsed_size))
    return tuple(sorted(descriptions, key=lambda item: item.object_id))


def _scan_objects(
    root: Path, descriptions: tuple[_ObjectDescription, ...]
) -> tuple[_ObjectScan, ...]:
    if not descriptions:
        return ()
    hash_width = 20 if _object_format(root) is GitObjectFormat.SHA1 else 32
    process = subprocess.Popen(
        [_GIT_EXECUTABLE, "cat-file", "--batch"],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=_git_environment(),
    )
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise _ObjectProtocolFailure

    scans: list[_ObjectScan] = []
    try:
        for description in descriptions:
            process.stdin.write(description.object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n")
            fields = header.split(b" ")
            if len(fields) != 3:
                raise _ObjectProtocolFailure
            returned_id, raw_type, raw_size = fields
            if os.fsdecode(returned_id) != description.object_id:
                raise _ObjectProtocolFailure
            object_type = os.fsdecode(raw_type)
            try:
                size = int(raw_size)
            except ValueError as error:
                raise _ObjectProtocolFailure from error
            if object_type != description.object_type or (
                description.size and size != description.size
            ):
                raise _ObjectProtocolFailure

            prefix = bytearray()
            tree_parser = _TreeParser(hash_width) if object_type == "tree" else None
            content_rules = matching_content_rules(
                _object_chunks(process.stdout, size, prefix, tree_parser)
            )
            if process.stdout.read(1) != b"\n":
                raise _ObjectProtocolFailure
            tree_hits: tuple[_TreeHit, ...] = ()
            root_tree_hits: tuple[_TreeHit, ...] = ()
            has_temp_tree = False
            if tree_parser is not None:
                tree_hits, root_tree_hits, has_temp_tree = tree_parser.finish()
            lfs_match = _LFS_POINTER.fullmatch(bytes(prefix)) if size <= len(prefix) else None
            lfs_object_id = os.fsdecode(lfs_match.group("oid")) if lfs_match else None
            lfs_object_size = int(lfs_match.group("size")) if lfs_match else None
            commit_tree_id = _commit_tree(bytes(prefix)) if object_type == "commit" else None
            scans.append(
                _ObjectScan(
                    description.object_id,
                    object_type,
                    content_rules,
                    lfs_object_id,
                    lfs_object_size,
                    commit_tree_id,
                    tree_hits,
                    root_tree_hits,
                    has_temp_tree,
                    _target_mentions_temp(bytes(prefix), size),
                    _target_path_rule(bytes(prefix), size),
                )
            )
    except (BrokenPipeError, OSError):
        raise _ObjectProtocolFailure from None
    finally:
        process.stdin.close()
        process.stdout.close()
        return_code = process.wait()
    if return_code != 0:
        raise _ObjectProtocolFailure
    return tuple(scans)


def _object_chunks(
    stream: IO[bytes],
    size: int,
    prefix: bytearray,
    tree_parser: _TreeParser | None,
) -> Iterator[bytes]:
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, _IO_CHUNK_SIZE))
        if not chunk:
            raise _ObjectProtocolFailure
        remaining -= len(chunk)
        if len(prefix) < _METADATA_PREFIX_SIZE:
            prefix.extend(chunk[: _METADATA_PREFIX_SIZE - len(prefix)])
        if tree_parser is not None:
            tree_parser.feed(chunk)
        yield chunk


class _TreeParser:
    def __init__(self, hash_width: int) -> None:
        self._hash_width = hash_width
        self._buffer = bytearray()
        self._hits: list[_TreeHit] = []
        self._root_hits: list[_TreeHit] = []
        self._has_temp_tree = False

    def feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        while True:
            space = self._buffer.find(b" ")
            if space < 0:
                return
            nul = self._buffer.find(b"\0", space + 1)
            if nul < 0 or len(self._buffer) < nul + 1 + self._hash_width:
                return
            mode = bytes(self._buffer[:space])
            raw_name = bytes(self._buffer[space + 1 : nul])
            del self._buffer[: nul + 1 + self._hash_width]
            name = os.fsdecode(raw_name)
            is_directory = mode in {b"040000", b"40000"}
            rule_id = sensitive_tree_entry_rule(name, is_directory=is_directory)
            if rule_id is not None:
                self._hits.append(_TreeHit(rule_id, name))
            root_rule_id = sensitive_root_tree_entry_rule(
                name,
                is_directory=is_directory,
            )
            if root_rule_id is not None:
                self._root_hits.append(_TreeHit(root_rule_id, name))
            if is_directory and name.casefold() == "temp":
                self._has_temp_tree = True

    def finish(self) -> tuple[tuple[_TreeHit, ...], tuple[_TreeHit, ...], bool]:
        if self._buffer:
            raise _ObjectProtocolFailure
        return tuple(self._hits), tuple(self._root_hits), self._has_temp_tree


def _commit_tree(prefix: bytes) -> str | None:
    first_line, separator, _rest = prefix.partition(b"\n")
    if not separator or not first_line.startswith(b"tree "):
        raise _ObjectProtocolFailure
    object_id = os.fsdecode(first_line[5:])
    if not _OBJECT_ID.fullmatch(object_id):
        raise _ObjectProtocolFailure
    return object_id


def _target_mentions_temp(prefix: bytes, size: int) -> bool:
    if size > len(prefix) or b"\0" in prefix:
        return False
    try:
        target = prefix.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return any(part.casefold() == "temp" for part in PurePosixPath(target).parts)


def _target_path_rule(prefix: bytes, size: int) -> str | None:
    if size > len(prefix) or b"\0" in prefix:
        return None
    try:
        target = prefix.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return sensitive_path_rule(target)


def _object_format(root: Path) -> GitObjectFormat:
    value = os.fsdecode(_run_git(root, "rev-parse", "--show-object-format").strip())
    try:
        return GitObjectFormat(value)
    except ValueError:
        raise _ObjectProtocolFailure from None


def _git_directory(root: Path, *, common: bool) -> Path:
    argument = "--git-common-dir" if common else "--git-dir"
    raw_path = os.fsdecode(_run_git(root, "rev-parse", argument).rstrip(b"\n"))
    if not raw_path:
        raise _ObjectProtocolFailure
    path = Path(raw_path)
    if not path.is_absolute():
        path = root / path
    return path


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _run_git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        [_GIT_EXECUTABLE, *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        env=_git_environment(),
    )
    if result.returncode != 0:
        raise _GitFailure(arguments[0] if arguments else "git")
    return result.stdout


def _git_environment() -> Mapping[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _trusted_executable(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == 0
        and metadata.st_mode & 0o022 == 0
        and metadata.st_mode & 0o111 != 0
    )


def _build_report(
    mode: AuditMode,
    findings: Iterable[PolicyFinding],
    issues: Iterable[AuditIssue],
    coverage: Mapping[CoverageScope, CoverageStatus],
    *,
    snapshot: RepositorySnapshot | None,
) -> AuditReport:
    sorted_findings = tuple(
        sorted(
            set(findings),
            key=lambda item: (
                item.scope.value,
                item.rule_id,
                item.path or "",
                item.object_id or "",
            ),
        )
    )
    sorted_issues = tuple(
        sorted(
            set(issues),
            key=lambda item: (item.severity.value, item.scope.value, item.code),
        )
    )
    coverage_evidence = tuple(
        CoverageEvidence(scope, coverage[scope]) for scope in sorted(coverage, key=str)
    )
    if any(issue.severity is IssueSeverity.ERROR for issue in sorted_issues):
        status = AuditStatus.ERROR
    elif any(issue.severity is IssueSeverity.INCOMPLETE for issue in sorted_issues):
        status = AuditStatus.INCOMPLETE
    elif sorted_findings:
        status = AuditStatus.VIOLATION
    else:
        status = AuditStatus.PASS
    return AuditReport(
        mode,
        status,
        sorted_findings,
        sorted_issues,
        coverage_evidence,
        snapshot,
    )
