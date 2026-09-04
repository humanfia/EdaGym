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
    RepositoryPolicy,
    audit_repository,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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

    report = audit_repository(repository, AuditMode.COMMIT)

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
    pointer = (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{lfs_object_id}\n"
        f"size {len(lfs_payload)}\n"
    )
    (repository / "large.bin").write_text(pointer, encoding="utf-8")
    _git(repository, "add", "large.bin")
    _git(repository, "commit", "--quiet", "-m", "Add large object pointer")

    report = audit_repository(repository, AuditMode.RELEASE)

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

    report = audit_repository(repository, AuditMode.RELEASE, policy=RepositoryPolicy())

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
