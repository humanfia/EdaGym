from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from edagym import release_commands
from edagym.policy.repository import AuditMode, AuditStatus, audit_repository
from edagym.release_commands import (
    ReleaseCommandInvocation,
    ReleaseCommandPurpose,
    ReleaseCommandReceipt,
    ReleaseEvidenceStatus,
    execute_release_command,
    project_release_command,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import (
    ArtifactClass,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    NoEncryption,
)


def _git(repository: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    return result.stdout


def _repository(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "--quiet")
    _git(path, "config", "user.name", "Release Test")
    _git(path, "config", "user.email", "release@example.invalid")
    ignores = (
        "/temp/",
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
    (path / ".gitignore").write_text("\n".join(ignores) + "\n", encoding="utf-8")
    shutil.copyfile(Path(__file__).parents[1] / ".gitleaks.toml", path / ".gitleaks.toml")
    _git(path, "add", ".gitignore", ".gitleaks.toml")
    _git(path, "commit", "--quiet", "-m", "Release fixture")
    return path


def _artifact_policy() -> ArtifactPolicy:
    disclosure = ArtifactDisclosure(
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    return ArtifactPolicy(
        quota_bytes=64 * 1024 * 1024,
        encryption=NoEncryption(),
        rules=tuple(
            ArtifactRetentionRule(
                artifact_class=artifact_class,
                retention_seconds=3600,
                allowed_disclosures=(disclosure,),
            )
            for artifact_class in ArtifactClass
        ),
    )


def test_release_command_runner_binds_real_execution_to_audit_and_cas(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path / "repository")
    audit = audit_repository(repository, AuditMode.RELEASE)
    assert audit.status is AuditStatus.PASS
    assert audit.snapshot is not None
    store = ContentAddressedStore(tmp_path / "store", policy=_artifact_policy())

    verified = execute_release_command(
        purpose=ReleaseCommandPurpose.FINAL_GIT_STATE,
        repository=repository,
        repository_audit=audit,
        input_subject_digest=audit.snapshot.digest,
        artifact_store=store,
        timeout_seconds=30,
    )
    evidence = project_release_command(verified)

    assert evidence.status is ReleaseEvidenceStatus.PASSED
    invocation = evidence.invocation_receipts[0]
    assert invocation.evidence is not None
    assert invocation.evidence.stdout_blob.size_bytes == 0
    assert invocation.evidence.stderr_blob.size_bytes == 0

    with pytest.raises(TypeError, match="verified CAS evidence"):
        project_release_command(verified.receipt)  # type: ignore[arg-type]
    assert isinstance(verified.receipt, ReleaseCommandReceipt)

    assert invocation.evidence_blob is not None
    store._blob_path(
        invocation.evidence_blob.digest,
        create_shard=False,
    ).unlink()
    with pytest.raises(ValueError, match="absent from its CAS"):
        project_release_command(verified)


def test_release_command_timeout_terminates_the_process_group(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")
    audit = audit_repository(repository, AuditMode.RELEASE)
    assert audit.status is AuditStatus.PASS
    assert audit.snapshot is not None
    store = ContentAddressedStore(tmp_path / "store", policy=_artifact_policy())
    child_record = tmp_path / "child.pid"
    executable = tmp_path / "git"
    executable.write_text(
        "#!/bin/sh\n"
        "sleep 30 &\n"
        f"printf '%s' \"$!\" > {child_record}\n"
        "wait\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)

    executable_digest = "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
    invocation = ReleaseCommandInvocation(
        tool_id="git",
        executable_digest=executable_digest,
        argv=("git", "status", "--porcelain=v1", "--untracked-files=all"),
    )
    descriptor = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        receipt, _stdout = release_commands._execute_release_invocation(
            invocation,
            descriptor=descriptor,
            repository=repository,
            store=store,
            timeout_seconds=1,
            include_release_environment=False,
            expected_environment_digest=None,
        )
    finally:
        os.close(descriptor)

    assert receipt.status is ReleaseEvidenceStatus.FAILED
    child_pid = int(child_record.read_text(encoding="ascii"))
    deadline = time.monotonic() + 2
    while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{child_pid}").exists()
