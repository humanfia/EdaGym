from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import edagym.policy.repository as repository_policy
from edagym.policy.repository import (
    AuditExitCode,
    AuditMode,
    AuditStatus,
    CoverageScope,
    CoverageStatus,
    FindingScope,
    GitObjectFormat,
    RepositoryPolicy,
    RepositorySnapshot,
    audit_repository,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MISSING_SCANNER = "/nonexistent/edagym-gitleaks"


def _git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        input=input_bytes,
        capture_output=True,
        check=False,
        env={**os.environ, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result.stdout


def _repository(path: Path, *, exact_ignore: bool = True) -> Path:
    path.mkdir()
    _git(path, "init", "--quiet")
    _git(path, "config", "user.name", "Policy Test")
    _git(path, "config", "user.email", "policy@example.invalid")
    policy = RepositoryPolicy()
    temp_ignore = policy.required_temp_ignore if exact_ignore else "temp/"
    ignore = "\n".join((temp_ignore, *policy.required_private_ignores)) + "\n"
    (path / ".gitignore").write_text(ignore, encoding="utf-8")
    shutil.copyfile(PROJECT_ROOT / ".gitleaks.toml", path / ".gitleaks.toml")
    _git(path, "add", ".gitignore", ".gitleaks.toml")
    _git(path, "commit", "--quiet", "-m", "Initial policy")
    return path


def test_commit_audit_enforces_exact_ignore_and_index_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path / "repository", exact_ignore=False)
    secret_value = "".join(("mV7rQ2pL9xC4nK8s", "T5wB3yH6dF1jG0zA"))
    (repository / "safe.txt").write_text(f"api_key = {secret_value}\n", encoding="utf-8")
    (repository / "auth.json").write_text("{}\n", encoding="utf-8")
    (repository / "temp").mkdir()
    (repository / "temp" / "hidden.txt").write_text("not sensitive\n", encoding="utf-8")
    _git(repository, "add", "safe.txt")
    _git(repository, "add", "--force", "auth.json")
    _git(repository, "add", "--force", "temp/hidden.txt")
    (repository / ".gitignore").write_text("/temp/\n", encoding="utf-8")
    alternate_index = tmp_path / "alternate-index"
    monkeypatch.setenv("GIT_INDEX_FILE", os.fspath(alternate_index))
    _git(repository, "read-tree", "--empty")

    report = audit_repository(
        repository,
        AuditMode.COMMIT,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    rule_ids = {finding.rule_id for finding in report.findings}
    assert report.status is AuditStatus.INCOMPLETE
    assert report.exit_code is AuditExitCode.INCOMPLETE
    assert "repository-temp-ignore-missing" in rule_ids
    assert "tracked-temp-path" in rule_ids
    assert "credential-filename" in rule_ids
    assert "high-entropy-credential-assignment" in rule_ids
    assert secret_value not in report.to_json()
    assert secret_value not in report.to_text()


def test_commit_audit_requires_private_runtime_ignores(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")
    (repository / ".gitignore").write_text("/temp/\n", encoding="utf-8")
    runtime_state = repository / "runs" / "run.json"
    runtime_state.parent.mkdir()
    runtime_state.write_text("{}\n", encoding="utf-8")
    _git(repository, "add", ".gitignore")
    _git(repository, "add", "--force", "runs/run.json")

    report = audit_repository(repository, AuditMode.COMMIT)

    assert any(
        finding.rule_id == "repository-private-ignore-missing"
        for finding in report.findings
    )
    assert any(
        finding.rule_id == "runtime-state-directory"
        for finding in report.findings
    )


def test_release_audit_scans_unreachable_objects_without_secret_excerpts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repository_policy,
        "_GIT_LFS_EXECUTABLE",
        "/nonexistent/edagym-git-lfs",
    )
    repository = _repository(tmp_path / "repository")
    secret_value = "".join(("Q8mR2vX7kP4zN9cL", "5tH3wF6yB1dG0sJ"))
    payload = f"client_secret = {secret_value}\n".encode()
    object_id = (
        _git(repository, "hash-object", "-w", "--stdin", input_bytes=payload)
        .strip()
        .decode()
    )
    pack_base = repository / ".git" / "objects" / "pack" / "policy"
    _git(
        repository,
        "pack-objects",
        os.fspath(pack_base),
        input_bytes=f"{object_id}\n".encode(),
    )
    (repository / ".git" / "objects" / object_id[:2] / object_id[2:]).unlink()

    reflog_secret = "".join(("R4kN8xP2mV7cQ9wF", "5tH1yL6dB3sG0zJ"))
    _git(
        repository,
        "update-ref",
        "--create-reflog",
        "-m",
        f"access_token = {reflog_secret}",
        "refs/heads/audit",
        "HEAD",
    )

    lfs_secret = "".join(("Z6pM2xR8vK4nQ9cL", "5tH1wF7yB3dG0sJ"))
    lfs_payload = f"password = {lfs_secret}\n".encode()
    lfs_object_id = hashlib.sha256(lfs_payload).hexdigest()
    lfs_object_path = (
        repository
        / ".git"
        / "lfs"
        / "objects"
        / lfs_object_id[:2]
        / lfs_object_id[2:4]
        / lfs_object_id
    )
    lfs_object_path.parent.mkdir(parents=True)
    lfs_object_path.write_bytes(lfs_payload)
    unexpected_lfs_path = repository / ".git" / "lfs" / "objects" / "scratch"
    unexpected_lfs_path.write_bytes(lfs_payload)
    pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{lfs_object_id}\n"
        f"size {len(lfs_payload)}\n"
    )
    (repository / "large.bin").write_text(pointer, encoding="utf-8")
    _git(repository, "add", "large.bin")
    _git(repository, "commit", "--quiet", "-m", "Add large object pointer")

    report = audit_repository(
        repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    coverage = {item.scope: item.status for item in report.coverage}
    assert report.status is AuditStatus.INCOMPLETE
    assert any(
        finding.object_id == object_id
        and finding.rule_id == "high-entropy-credential-assignment"
        for finding in report.findings
    )
    assert any(
        finding.scope is FindingScope.GIT_REFLOG
        and finding.rule_id == "high-entropy-credential-assignment"
        for finding in report.findings
    )
    assert any(
        finding.scope is FindingScope.GIT_LFS
        and finding.rule_id == "high-entropy-credential-assignment"
        for finding in report.findings
    )
    assert any(
        finding.scope is FindingScope.GIT_LFS
        and finding.rule_id == "git-lfs-object-layout-invalid"
        for finding in report.findings
    )
    assert coverage[CoverageScope.GIT_REFS] is CoverageStatus.COMPLETE
    assert coverage[CoverageScope.GIT_REFLOGS] is CoverageStatus.COMPLETE
    assert coverage[CoverageScope.OBJECT_DATABASE] is CoverageStatus.COMPLETE
    assert coverage[CoverageScope.GIT_LFS] is CoverageStatus.INCOMPLETE
    assert coverage[CoverageScope.EXTERNAL_SCANNER] is CoverageStatus.INCOMPLETE
    assert secret_value not in report.to_json()
    assert secret_value not in report.to_text()
    assert reflog_secret not in report.to_json()
    assert reflog_secret not in report.to_text()
    assert lfs_secret not in report.to_json()
    assert lfs_secret not in report.to_text()


def test_release_audit_is_incomplete_without_required_external_scanner(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repository")

    report = audit_repository(
        repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    assert report.status is AuditStatus.INCOMPLETE
    assert report.exit_code is AuditExitCode.INCOMPLETE
    assert any(issue.code == "external-scanner-unavailable" for issue in report.issues)


def test_release_audit_handles_an_explicit_scanner_early_exit(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")

    report = audit_repository(
        repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(
            external_scanner_executable="/usr/bin/true",
        ),
    )

    coverage = {item.scope: item.status for item in report.coverage}
    assert coverage[CoverageScope.EXTERNAL_SCANNER] is CoverageStatus.INCOMPLETE
    assert report.status is AuditStatus.INCOMPLETE
    assert any(
        issue.code == "external-scanner-corpus-incomplete"
        for issue in report.issues
    )


def test_release_audit_binds_one_clean_commit_index_and_worktree(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")

    clean = audit_repository(
        repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    assert clean.snapshot is not None
    assert clean.snapshot.object_format is GitObjectFormat.SHA1
    assert (
        clean.snapshot.tree_id
        == clean.snapshot.index_tree_id
        == clean.snapshot.worktree_tree_id
    )

    (repository / "dirty.txt").write_text("indexed\n", encoding="utf-8")
    _git(repository, "add", "dirty.txt")
    (repository / "dirty.txt").write_text("working tree\n", encoding="utf-8")
    dirty = audit_repository(
        repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    assert dirty.status is AuditStatus.ERROR
    assert dirty.snapshot is not None
    assert dirty.snapshot.tree_id != dirty.snapshot.index_tree_id
    assert dirty.snapshot.worktree_tree_id is None
    assert {issue.code for issue in dirty.issues} >= {
        "release-index-dirty",
        "release-worktree-dirty",
    }


def test_release_audit_rejects_a_ref_set_change_during_the_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path / "repository")
    original_scanner = repository_policy._run_external_scanner

    def change_ref(root: Path, *arguments: object) -> None:
        commit_id = _git(root, "rev-parse", "HEAD").strip()
        _git(root, "update-ref", "refs/heads/concurrent", commit_id.decode("ascii"))
        original_scanner(root, *arguments)  # type: ignore[arg-type]

    monkeypatch.setattr(repository_policy, "_run_external_scanner", change_ref)
    report = audit_repository(
        repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    assert report.status is AuditStatus.INCOMPLETE
    assert any(issue.code == "repository-snapshot-changed" for issue in report.issues)


def test_snapshot_object_ids_must_match_the_declared_hash_format() -> None:
    empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()

    with pytest.raises(ValueError, match="object format"):
        RepositorySnapshot(
            object_format=GitObjectFormat.SHA256,
            commit_id="1" * 40,
            tree_id="2" * 40,
            index_tree_id="2" * 40,
            worktree_tree_id="2" * 40,
            index_state_digest=empty_digest,
            worktree_state_digest=empty_digest,
            ref_set_digest=empty_digest,
            reflog_record_digest=empty_digest,
            lfs_object_inventory_digest=empty_digest,
            scan_scope_digest=empty_digest,
        )


def test_audit_keeps_using_the_opened_repository_when_its_path_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path / "repository")
    original_commit = _git(repository, "rev-parse", "HEAD").strip().decode("ascii")
    moved = tmp_path / "opened-repository"
    original_audit = repository_policy._audit_repository_files

    def replace_path(root: Path, *arguments: object) -> None:
        original_audit(root, *arguments)  # type: ignore[arg-type]
        repository.rename(moved)
        replacement = _repository(repository)
        (replacement / "replacement.txt").write_text("different\n", encoding="utf-8")
        _git(replacement, "add", "replacement.txt")
        _git(replacement, "commit", "--quiet", "-m", "Replacement repository")

    monkeypatch.setattr(repository_policy, "_audit_repository_files", replace_path)
    report = audit_repository(
        repository,
        AuditMode.COMMIT,
        policy=RepositoryPolicy(external_scanner_executable=_MISSING_SCANNER),
    )

    assert report.snapshot is not None
    assert report.snapshot.commit_id == original_commit
    assert not any(issue.code == "repository-snapshot-changed" for issue in report.issues)
