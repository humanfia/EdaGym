"""Release-private roots remain complete, owner-only, and path-free."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from edagym.policy.private_roots import (
    PrivateRootAuditStatus,
    PrivateRootRole,
    _bind_private_root_from_descriptor,
    audit_private_roots,
    project_private_root_audit,
)
from edagym.policy.repository import (
    AuditMode,
    AuditReport,
    AuditStatus,
    RepositoryPolicy,
    audit_repository,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        env={**os.environ, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def _release_repository(root: Path) -> tuple[Path, AuditReport]:
    root.mkdir(mode=0o700)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.name", "Private Root Test")
    _git(root, "config", "user.email", "private-root@example.invalid")
    policy = RepositoryPolicy()
    (root / ".gitignore").write_text(
        "\n".join((policy.required_temp_ignore, *policy.required_private_ignores)) + "\n",
        encoding="utf-8",
    )
    shutil.copyfile(_PROJECT_ROOT / ".gitleaks.toml", root / ".gitleaks.toml")
    _git(root, "add", ".gitignore", ".gitleaks.toml")
    _git(root, "commit", "--quiet", "-m", "Private root policy")
    audit = audit_repository(root, AuditMode.RELEASE)
    assert audit.status is AuditStatus.PASS
    return root, audit


def test_required_private_root_roles_cannot_be_omitted(tmp_path: Path) -> None:
    repository, audit = _release_repository(tmp_path / "repository")
    unrelated = repository / "temp" / "unrelated-user-material"
    unrelated.mkdir(parents=True, mode=0o755)

    evidence = project_private_root_audit(audit_private_roots(repository, audit, ()))

    assert evidence.status is PrivateRootAuditStatus.INCOMPLETE
    assert set(evidence.missing_roles)
    assert not evidence.roots


def test_registered_private_root_rejects_exposed_mode_bits(tmp_path: Path) -> None:
    repository, audit = _release_repository(tmp_path / "repository")
    private_root = tmp_path / "registered-private-root"
    private_root.mkdir(mode=0o700)
    evidence_file = private_root / "evidence.bin"
    evidence_file.write_bytes(b"opaque evidence")
    evidence_file.chmod(0o600)
    descriptor = os.open(
        private_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        registration = _bind_private_root_from_descriptor(
            PrivateRootRole.COMMAND_ARTIFACT_STORE,
            descriptor,
            "sha256:" + hashlib.sha256(b"registered source").hexdigest(),
        )
    finally:
        os.close(descriptor)
    evidence_file.chmod(0o644)

    evidence = project_private_root_audit(
        audit_private_roots(repository, audit, (registration,))
    )

    assert evidence.status is PrivateRootAuditStatus.VIOLATION
    assert sum(len(root.exposed_modes) for root in evidence.roots) == 1
    assert all("registered-private-root" not in root.model_dump_json() for root in evidence.roots)


def test_registration_scans_one_shot_descriptor_after_ancestor_rename(
    tmp_path: Path,
) -> None:
    repository, audit = _release_repository(tmp_path / "repository")
    shared_parent = tmp_path / "shared-parent"
    shared_parent.mkdir(mode=0o700)
    shared_parent.chmod(0o777)
    original = shared_parent / "private-root"
    original.mkdir(mode=0o700)
    retained_file = original / "retained.bin"
    retained_file.write_bytes(b"retained")
    retained_file.chmod(0o600)
    descriptor = os.open(
        original,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        registration = _bind_private_root_from_descriptor(
            PrivateRootRole.COMMAND_ARTIFACT_STORE,
            descriptor,
            "sha256:" + hashlib.sha256(b"descriptor source").hexdigest(),
        )
    finally:
        os.close(descriptor)

    original.rename(shared_parent / "retained-private-root")
    original.mkdir(mode=0o700)
    replacement = original / "replacement.bin"
    replacement.write_bytes(b"replacement")
    replacement.chmod(0o644)

    evidence = project_private_root_audit(
        audit_private_roots(repository, audit, (registration,))
    )
    registered = next(
        root
        for root in evidence.roots
        if PrivateRootRole.COMMAND_ARTIFACT_STORE in root.roles
    )
    assert registered.regular_file_count == 1
    assert not registered.exposed_modes
    with pytest.raises(RuntimeError, match="one-shot"):
        audit_private_roots(repository, audit, (registration,))
