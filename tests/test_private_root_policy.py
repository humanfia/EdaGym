"""Release-private roots remain complete, owner-only, and path-free."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from edagym.executors.deployment import load_executor_deployment_registry
from edagym.executors.qualification import commit_vm_executor_qualification
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
from edagym.release_executors import (
    VerifiedExecutorQualification,
    VmExecutorQualificationSource,
    verify_executor_qualification_source,
)
from edagym.release_private_roots import executor_private_root_registrations
from tests.test_executor_deployment import _document as executor_deployment_document
from tests.test_executor_qualification import _qualification as vm_executor_qualification

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

    evidence = project_private_root_audit(audit_private_roots(repository, audit, (registration,)))

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

    evidence = project_private_root_audit(audit_private_roots(repository, audit, (registration,)))
    registered = next(
        root for root in evidence.roots if PrivateRootRole.COMMAND_ARTIFACT_STORE in root.roles
    )
    assert registered.regular_file_count == 1
    assert not registered.exposed_modes
    with pytest.raises(RuntimeError, match="one-shot"):
        audit_private_roots(repository, audit, (registration,))


def test_executor_roles_register_only_from_live_registry_and_verified_receipt(
    tmp_path: Path,
) -> None:
    repository, audit = _release_repository(tmp_path / "repository")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    registry_path = private / "executor-deployment.json"
    registry_path.write_bytes(executor_deployment_document())
    registry_path.chmod(0o600)
    receipt, environment, store, plans = vm_executor_qualification(private / "qualification")
    commitment = commit_vm_executor_qualification(receipt, environment, plans, store)
    source = VmExecutorQualificationSource(
        receipt=receipt,
        commitment=commitment,
        environment=environment,
        plans=tuple(plans.values()),
    )

    assert executor_private_root_registrations(None, None) == ()
    with pytest.raises(TypeError, match="canonical replay"):
        VerifiedExecutorQualification(object(), receipt_digest=receipt.digest, store=store)

    verified = verify_executor_qualification_source(source, store)
    assert verified.receipt_digest == receipt.digest
    registry = load_executor_deployment_registry(registry_path)
    try:
        registrations = executor_private_root_registrations(registry, verified)
        try:
            assert {item.role for item in registrations} == {
                PrivateRootRole.EXECUTOR_DEPLOYMENT_REGISTRY,
                PrivateRootRole.EXECUTOR_QUALIFICATION_STORE,
            }
            evidence = project_private_root_audit(
                audit_private_roots(repository, audit, registrations)
            )
        finally:
            for registration in registrations:
                registration.close()
    finally:
        registry.close()

    assert evidence.status is PrivateRootAuditStatus.INCOMPLETE
    assert not {
        PrivateRootRole.EXECUTOR_DEPLOYMENT_REGISTRY,
        PrivateRootRole.EXECUTOR_QUALIFICATION_STORE,
    } & set(evidence.missing_roles)
    assert all(private.as_posix() not in root.model_dump_json() for root in evidence.roots)
