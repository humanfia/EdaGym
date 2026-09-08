"""Closed command plans and immutable receipts for release evidence."""

from __future__ import annotations

import hashlib
import os
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Never, Self

from pydantic import Field, StringConstraints, field_validator, model_validator

from edagym.authoring.contracts import parse_authoring_contract_output
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.policy.repository import (
    AuditMode,
    AuditReport,
    AuditStatus,
    RepositorySnapshot,
    bind_repository_snapshot,
)
from edagym.run.artifact_model import (
    BlobRef,
)
from edagym.run.artifacts import ArtifactStoreError, ContentAddressedStore
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    Redistribution,
    SchemaVersion,
    Sensitivity,
    StrictModel,
    Visibility,
)
from edagym.task_families.catalog import PUBLIC_TASK_CATALOG

_MAX_RELEASE_OUTPUT_BYTES = 64 * 1024 * 1024
_RELEASE_EXECUTABLE_PATHS: Mapping[str, Path] = {
    "git": Path("/usr/bin/git"),
    "go": Path("/usr/lib/golang/bin/go"),
    "python": Path("/usr/bin/python3.12"),
}


class ReleaseCommandPurpose(StrEnum):
    CLEAN_INSTALLATION = "clean_installation"
    AUTHORING_CONTRACT = "authoring_contract"
    SCHEMA_EXPORTS = "schema_exports"
    STATIC_ANALYSIS = "static_analysis"
    TEST_SUITE = "test_suite"
    VM_GUEST = "vm_guest"
    FINAL_GIT_STATE = "final_git_state"


_INSTALLATION_DEPENDENT_PURPOSES = frozenset(
    {
        ReleaseCommandPurpose.AUTHORING_CONTRACT,
        ReleaseCommandPurpose.SCHEMA_EXPORTS,
        ReleaseCommandPurpose.STATIC_ANALYSIS,
        ReleaseCommandPurpose.TEST_SUITE,
    }
)


def release_command_requires_installation(purpose: ReleaseCommandPurpose) -> bool:
    """Return whether a purpose executes against the clean installed wheel set."""

    return purpose in _INSTALLATION_DEPENDENT_PURPOSES


class ReleaseEvidenceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class CommandFailure(StrEnum):
    NONZERO_EXIT = "nonzero_exit"
    TIMED_OUT = "timed_out"
    INTERRUPTED = "interrupted"
    OUTPUT_REJECTED = "output_rejected"
    POLICY_REJECTED = "policy_rejected"


class CommandUnavailable(StrEnum):
    NOT_RUN = "not_run"
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    LICENSE_UNAVAILABLE = "license_unavailable"
    AUTHORIZATION_REQUIRED = "authorization_required"


CommandArgument = Annotated[str, StringConstraints(min_length=1, max_length=16_384)]


_RELEASE_COMMANDS: dict[
    ReleaseCommandPurpose,
    tuple[tuple[str, tuple[str, ...]], ...],
] = {
    ReleaseCommandPurpose.CLEAN_INSTALLATION: (
        (
            "python",
            (
                "python",
                "scripts/check_clean_install.py",
            ),
        ),
    ),
    ReleaseCommandPurpose.AUTHORING_CONTRACT: (
        (
            "python",
            (
                "python",
                "-m",
                "edagym.authoring",
                "contract",
            ),
        ),
    ),
    ReleaseCommandPurpose.SCHEMA_EXPORTS: (
        (
            "python",
            (
                "python",
                "scripts/check_schema_exports.py",
            ),
        ),
    ),
    ReleaseCommandPurpose.STATIC_ANALYSIS: (
        ("python", ("python", "-m", "ruff", "check", ".")),
        ("python", ("python", "-m", "mypy", "--no-incremental")),
    ),
    ReleaseCommandPurpose.TEST_SUITE: (("python", ("python", "-m", "pytest", "-q")),),
    ReleaseCommandPurpose.VM_GUEST: (
        ("go", ("go", "-C", "guest/edagym-vm-agent", "test", "./...")),
        ("go", ("go", "-C", "guest/edagym-vm-agent", "build", "-trimpath", "./...")),
    ),
    ReleaseCommandPurpose.FINAL_GIT_STATE: (
        (
            "git",
            (
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ),
        ),
    ),
}


class ReleaseCommandInvocation(StrictModel):
    """One argv-only executable identity in a closed release command plan."""

    tool_id: Identifier
    executable_digest: Digest
    argv: Annotated[tuple[CommandArgument, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_argv(self) -> Self:
        if self.argv[0] != self.tool_id or any("\0" in item for item in self.argv):
            raise ValueError("release command argv must start with its tool identity")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="release-command-invocation-v1")


class ReleaseCommandPlan(StrictModel):
    """Closed, repository-bound plan for one required release purpose."""

    schema_version: SchemaVersion = 1
    purpose: ReleaseCommandPurpose
    repository: RepositorySnapshot
    input_subject_digest: Digest
    installation_receipt_digest: Digest | None = None
    invocations: Annotated[tuple[ReleaseCommandInvocation, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_allowed_command(self) -> Self:
        observed = tuple((item.tool_id, item.argv) for item in self.invocations)
        if observed != _RELEASE_COMMANDS[self.purpose]:
            raise ValueError("release command plan does not match its canonical purpose")
        if (self.purpose in _INSTALLATION_DEPENDENT_PURPOSES) != (
            self.installation_receipt_digest is not None
        ):
            raise ValueError(
                "release command plan must bind exactly its clean installation prerequisite"
            )
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="release-command-plan-v1")


def release_command_plan(
    *,
    purpose: ReleaseCommandPurpose,
    repository: RepositorySnapshot,
    input_subject_digest: Digest,
    executable_digests: Mapping[str, Digest],
    installation_receipt_digest: Digest | None = None,
) -> ReleaseCommandPlan:
    """Construct the only argv set admitted for a release purpose."""

    command = _RELEASE_COMMANDS[purpose]
    required_tools = {tool_id for tool_id, _ in command}
    if set(executable_digests) != required_tools:
        raise ValueError("release command executable identities must exactly cover its tools")
    return ReleaseCommandPlan(
        purpose=purpose,
        repository=repository,
        input_subject_digest=input_subject_digest,
        installation_receipt_digest=installation_receipt_digest,
        invocations=tuple(
            ReleaseCommandInvocation(
                tool_id=tool_id,
                executable_digest=executable_digests[tool_id],
                argv=argv,
            )
            for tool_id, argv in command
        ),
    )


class ReleaseInvocationEvidence(StrictModel):
    """Canonical retained output manifest for one real command invocation."""

    schema_version: SchemaVersion = 1
    invocation_digest: Digest
    started_at: datetime
    finished_at: datetime
    exit_code: Annotated[int, Field(strict=True, ge=-255, le=255)] | None
    stdout_blob: BlobRef
    stderr_blob: BlobRef
    failure: CommandFailure | None

    @field_validator("started_at", "finished_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("release command timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("release command completion cannot precede its start")
        if self.exit_code is None:
            if self.failure not in {CommandFailure.TIMED_OUT, CommandFailure.INTERRUPTED}:
                raise ValueError("unfinished release commands require a terminal interruption")
        elif self.exit_code == 0:
            if self.failure not in {
                None,
                CommandFailure.OUTPUT_REJECTED,
                CommandFailure.POLICY_REJECTED,
            }:
                raise ValueError("zero-exit release command failure is invalid")
        elif self.failure is not CommandFailure.NONZERO_EXIT:
            raise ValueError("nonzero release commands require nonzero-exit failure")
        return self


class ReleaseInvocationReceipt(StrictModel):
    """Secret-safe reference to one retained invocation evidence manifest."""

    invocation_digest: Digest
    evidence: ReleaseInvocationEvidence | None = None
    evidence_blob: BlobRef | None = None
    unavailable: CommandUnavailable | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.unavailable is not None:
            if self.evidence is not None or self.evidence_blob is not None:
                raise ValueError("unavailable release commands cannot claim execution evidence")
            return self
        if self.evidence is None or self.evidence_blob is None:
            raise ValueError("executed release commands require retained CAS evidence")
        if self.evidence.invocation_digest != self.invocation_digest:
            raise ValueError("release command evidence targets a different invocation")
        encoded = canonical_bytes(self.evidence)
        expected_blob = BlobRef(
            digest=f"sha256:{hashlib.sha256(encoded).hexdigest()}",
            size_bytes=len(encoded),
        )
        if self.evidence_blob != expected_blob:
            raise ValueError("release command evidence blob identity is invalid")
        return self

    @property
    def status(self) -> ReleaseEvidenceStatus:
        if self.unavailable is not None:
            return ReleaseEvidenceStatus.UNAVAILABLE
        assert self.evidence is not None
        if self.evidence.failure is not None or self.evidence.exit_code != 0:
            return ReleaseEvidenceStatus.FAILED
        return ReleaseEvidenceStatus.PASSED


class ReleaseCommandReceipt(StrictModel):
    """Canonical source receipt whose result is derived, never caller-labelled."""

    schema_version: SchemaVersion = 1
    plan: ReleaseCommandPlan
    invocations: Annotated[tuple[ReleaseInvocationReceipt, ...], Field(min_length=1)]
    verified_public_catalog_digest: Digest | None = None
    installed_environment_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_plan_execution(self) -> Self:
        if tuple(item.invocation_digest for item in self.invocations) != tuple(
            item.digest for item in self.plan.invocations
        ):
            raise ValueError("release command receipts must exactly cover their plan in order")
        if self.plan.purpose is ReleaseCommandPurpose.FINAL_GIT_STATE and all(
            item.status is ReleaseEvidenceStatus.PASSED for item in self.invocations
        ):
            empty_output = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            if any(
                item.evidence is None
                or item.evidence.stdout_blob.digest != empty_output
                or item.evidence.stderr_blob.digest != empty_output
                for item in self.invocations
            ):
                raise ValueError("passing final Git state requires empty status output")
        if self.plan.purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT:
            if (self.status is ReleaseEvidenceStatus.PASSED) != (
                self.verified_public_catalog_digest is not None
            ):
                raise ValueError(
                    "passing authoring contract requires its public catalog digest"
                )
        elif self.verified_public_catalog_digest is not None:
            raise ValueError("only the authoring contract may carry a public catalog digest")
        if self.plan.purpose is ReleaseCommandPurpose.CLEAN_INSTALLATION:
            if (self.status is ReleaseEvidenceStatus.PASSED) != (
                self.installed_environment_digest is not None
            ):
                raise ValueError(
                    "passing clean installation requires its installed environment digest"
                )
        elif self.installed_environment_digest is not None:
            raise ValueError(
                "only clean installation may carry an installed environment digest"
            )
        return self

    @property
    def status(self) -> ReleaseEvidenceStatus:
        statuses = {item.status for item in self.invocations}
        if ReleaseEvidenceStatus.FAILED in statuses:
            return ReleaseEvidenceStatus.FAILED
        if ReleaseEvidenceStatus.UNAVAILABLE in statuses:
            return ReleaseEvidenceStatus.UNAVAILABLE
        return ReleaseEvidenceStatus.PASSED

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="release-command-receipt-v1")


_VERIFIED_RECEIPT_TOKEN = object()


class VerifiedReleaseCommandReceipt:
    """Nonserializable runner authority over one receipt and its exact CAS."""

    __slots__ = ("receipt", "store")

    def __init__(
        self,
        token: object,
        receipt: ReleaseCommandReceipt,
        store: ContentAddressedStore,
    ) -> None:
        if token is not _VERIFIED_RECEIPT_TOKEN:
            raise TypeError("verified release receipts are issued by the canonical runner")
        self.receipt = receipt
        self.store = store

    @property
    def artifact_policy_digest(self) -> Digest:
        return self.store.policy_digest

    def __reduce__(self) -> Never:
        raise TypeError("verified release receipts cannot be serialized")


def _verify_release_command_receipt(
    receipt: ReleaseCommandReceipt,
    store: ContentAddressedStore,
) -> VerifiedReleaseCommandReceipt:
    """Issue runner-local authority after verifying the complete CAS closure."""

    if type(receipt) is not ReleaseCommandReceipt:
        raise TypeError("release receipt verification requires the canonical receipt type")
    if type(store) is not ContentAddressedStore:
        raise TypeError("release receipt verification requires the concrete artifact store")
    try:
        for invocation in receipt.invocations:
            if invocation.evidence is None:
                continue
            assert invocation.evidence_blob is not None
            for reference in (
                invocation.evidence.stdout_blob,
                invocation.evidence.stderr_blob,
                invocation.evidence_blob,
            ):
                store.verify_disclosure(
                    reference,
                    artifact_class=ArtifactClass.EVIDENCE,
                    sensitivity=Sensitivity.INTERNAL,
                    visibility=Visibility.AUTHOR,
                    redistribution=Redistribution.RESTRICTED,
                )
            retained = store.read_bytes(
                invocation.evidence_blob,
                maximum_bytes=invocation.evidence_blob.size_bytes,
            )
            if retained != canonical_bytes(invocation.evidence):
                raise ValueError("release command evidence content is not canonical")
    except ArtifactStoreError as error:
        raise ValueError("release command evidence is absent from its CAS") from error
    return VerifiedReleaseCommandReceipt(
        _VERIFIED_RECEIPT_TOKEN,
        receipt,
        store,
    )


class ReleaseCommandExecutionError(RuntimeError):
    """A command suite could not preserve its audited repository or CAS boundary."""


def execute_release_commands(
    *,
    repository: Path,
    repository_audit: AuditReport,
    artifact_store: ContentAddressedStore,
    timeout_seconds: int,
) -> tuple[VerifiedReleaseCommandReceipt, ...]:
    """Run the complete release command set through the canonical local authority."""

    results: list[VerifiedReleaseCommandReceipt] = []
    installation = execute_release_command(
        purpose=ReleaseCommandPurpose.CLEAN_INSTALLATION,
        repository=repository,
        repository_audit=repository_audit,
        input_subject_digest=_release_input_subject(
            ReleaseCommandPurpose.CLEAN_INSTALLATION,
            repository_audit,
        ),
        artifact_store=artifact_store,
        timeout_seconds=timeout_seconds,
    )
    results.append(installation)
    for purpose in tuple(ReleaseCommandPurpose)[1:]:
        input_subject_digest = _release_input_subject(purpose, repository_audit)
        if (
            purpose in _INSTALLATION_DEPENDENT_PURPOSES
            and installation.receipt.status is not ReleaseEvidenceStatus.PASSED
        ):
            results.append(
                _unavailable_release_command(
                    purpose=purpose,
                    repository=repository,
                    repository_audit=repository_audit,
                    input_subject_digest=input_subject_digest,
                    artifact_store=artifact_store,
                    installation=installation,
                )
            )
            continue
        results.append(
            execute_release_command(
                purpose=purpose,
                repository=repository,
                repository_audit=repository_audit,
                input_subject_digest=input_subject_digest,
                artifact_store=artifact_store,
                timeout_seconds=timeout_seconds,
                installation=(
                    installation
                    if purpose in _INSTALLATION_DEPENDENT_PURPOSES
                    else None
                ),
            )
        )
    return tuple(results)


def _release_input_subject(
    purpose: ReleaseCommandPurpose,
    repository_audit: AuditReport,
) -> Digest:
    if repository_audit.snapshot is None:
        raise ReleaseCommandExecutionError("release audit has no repository snapshot")
    if purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT:
        return PUBLIC_TASK_CATALOG.digest
    return repository_audit.snapshot.digest


def execute_release_command(
    *,
    purpose: ReleaseCommandPurpose,
    repository: Path,
    repository_audit: AuditReport,
    input_subject_digest: Digest,
    artifact_store: ContentAddressedStore,
    timeout_seconds: int,
    installation: VerifiedReleaseCommandReceipt | None = None,
) -> VerifiedReleaseCommandReceipt:
    """Execute one canonical command purpose against its exact audited repository."""

    if (
        type(repository_audit) is not AuditReport
        or repository_audit.mode is not AuditMode.RELEASE
        or repository_audit.status is not AuditStatus.PASS
        or repository_audit.snapshot is None
        or not repository_audit.snapshot.is_clean
    ):
        raise ReleaseCommandExecutionError("release commands require one passing clean audit")
    if type(artifact_store) is not ContentAddressedStore:
        raise TypeError("release command execution requires the concrete artifact store")
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("release command timeout must be a positive integer")

    installation_receipt_digest: Digest | None = None
    installed_environment_digest: Digest | None = None
    if purpose in _INSTALLATION_DEPENDENT_PURPOSES:
        if type(installation) is not VerifiedReleaseCommandReceipt:
            raise ReleaseCommandExecutionError(
                "release command requires a runner-issued clean installation"
            )
        _verify_release_command_receipt(installation.receipt, installation.store)
        installation_source = installation.receipt
        if (
            installation_source.plan.purpose
            is not ReleaseCommandPurpose.CLEAN_INSTALLATION
            or installation_source.status is not ReleaseEvidenceStatus.PASSED
            or installation_source.plan.repository != repository_audit.snapshot
            or installation.store is not artifact_store
            or installation_source.installed_environment_digest is None
        ):
            raise ReleaseCommandExecutionError(
                "release command clean installation prerequisite is invalid"
            )
        installation_receipt_digest = installation_source.digest
        installed_environment_digest = installation_source.installed_environment_digest
    elif installation is not None:
        raise ValueError("release command does not accept an installation prerequisite")

    command = _RELEASE_COMMANDS[purpose]
    required_tools = {tool_id for tool_id, _argv in command}
    descriptors: dict[str, int] = {}
    executable_digests: dict[str, Digest] = {}
    try:
        for tool_id in sorted(required_tools):
            descriptor = _open_release_executable(_RELEASE_EXECUTABLE_PATHS[tool_id])
            descriptors[tool_id] = descriptor
            executable_digests[tool_id] = _descriptor_digest(descriptor)
        plan = release_command_plan(
            purpose=purpose,
            repository=repository_audit.snapshot,
            input_subject_digest=input_subject_digest,
            executable_digests=executable_digests,
            installation_receipt_digest=installation_receipt_digest,
        )
        with bind_repository_snapshot(repository, repository_audit.snapshot) as binding:
            receipts: list[ReleaseInvocationReceipt] = []
            catalog_digest: Digest | None = None
            for invocation in plan.invocations:
                binding.verify()
                receipt, stdout = _execute_release_invocation(
                    invocation,
                    descriptor=descriptors[invocation.tool_id],
                    repository=binding.root,
                    store=artifact_store,
                    timeout_seconds=timeout_seconds,
                    include_release_environment=(
                        purpose in _INSTALLATION_DEPENDENT_PURPOSES
                    ),
                    expected_environment_digest=installed_environment_digest,
                )
                binding.verify()
                receipts.append(receipt)
                if (
                    purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT
                    and receipt.status is ReleaseEvidenceStatus.PASSED
                ):
                    catalog_digest = _catalog_digest_from_output(receipt, stdout)
            produced_environment_digest = (
                _installed_environment_digest(binding.root)
                if purpose is ReleaseCommandPurpose.CLEAN_INSTALLATION
                and all(
                    item.status is ReleaseEvidenceStatus.PASSED for item in receipts
                )
                else None
            )
            source = ReleaseCommandReceipt(
                plan=plan,
                invocations=tuple(receipts),
                verified_public_catalog_digest=catalog_digest,
                installed_environment_digest=produced_environment_digest,
            )
        return _verify_release_command_receipt(source, artifact_store)
    except (ArtifactStoreError, OSError, RuntimeError, ValueError) as error:
        if isinstance(error, ReleaseCommandExecutionError):
            raise
        raise ReleaseCommandExecutionError("release command execution failed closed") from error
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def _unavailable_release_command(
    *,
    purpose: ReleaseCommandPurpose,
    repository: Path,
    repository_audit: AuditReport,
    input_subject_digest: Digest,
    artifact_store: ContentAddressedStore,
    installation: VerifiedReleaseCommandReceipt,
) -> VerifiedReleaseCommandReceipt:
    if (
        purpose not in _INSTALLATION_DEPENDENT_PURPOSES
        or repository_audit.snapshot is None
        or installation.receipt.plan.purpose
        is not ReleaseCommandPurpose.CLEAN_INSTALLATION
        or installation.receipt.plan.repository != repository_audit.snapshot
        or installation.store is not artifact_store
    ):
        raise ReleaseCommandExecutionError(
            "unavailable command requires its failed clean installation"
        )
    _verify_release_command_receipt(installation.receipt, installation.store)
    descriptors: dict[str, int] = {}
    try:
        command = _RELEASE_COMMANDS[purpose]
        for tool_id in sorted({tool for tool, _argv in command}):
            descriptors[tool_id] = _open_release_executable(
                _RELEASE_EXECUTABLE_PATHS[tool_id]
            )
        plan = release_command_plan(
            purpose=purpose,
            repository=repository_audit.snapshot,
            input_subject_digest=input_subject_digest,
            executable_digests={
                tool_id: _descriptor_digest(descriptor)
                for tool_id, descriptor in descriptors.items()
            },
            installation_receipt_digest=installation.receipt.digest,
        )
        with bind_repository_snapshot(repository, repository_audit.snapshot) as binding:
            binding.verify()
            source = ReleaseCommandReceipt(
                plan=plan,
                invocations=tuple(
                    ReleaseInvocationReceipt(
                        invocation_digest=invocation.digest,
                        unavailable=CommandUnavailable.DEPENDENCY_UNAVAILABLE,
                    )
                    for invocation in plan.invocations
                ),
            )
            binding.verify()
        return _verify_release_command_receipt(source, artifact_store)
    finally:
        for descriptor in descriptors.values():
            os.close(descriptor)


def _execute_release_invocation(
    invocation: ReleaseCommandInvocation,
    *,
    descriptor: int,
    repository: Path,
    store: ContentAddressedStore,
    timeout_seconds: int,
    include_release_environment: bool,
    expected_environment_digest: Digest | None,
) -> tuple[ReleaseInvocationReceipt, bytes]:
    executable_digest = _descriptor_digest(descriptor)
    if executable_digest != invocation.executable_digest:
        raise ReleaseCommandExecutionError("release executable changed before invocation")
    if expected_environment_digest is not None:
        _verify_installed_environment(repository, expected_environment_digest)
    started_at = datetime.now(UTC)
    with (
        tempfile.TemporaryDirectory(
            prefix="release-command-",
            dir=store.root.parent,
        ) as temporary,
        tempfile.TemporaryFile(dir=store.root) as stdout,
        tempfile.TemporaryFile(dir=store.root) as stderr,
    ):
        temporary_root = Path(temporary)
        process = subprocess.Popen(
            [f"/proc/self/fd/{descriptor}", *invocation.argv[1:]],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=_release_environment(
                temporary_root,
                include_release_environment=include_release_environment,
            ),
            shell=False,
            close_fds=True,
            pass_fds=(descriptor,),
            start_new_session=True,
        )
        try:
            try:
                exit_code: int | None = process.wait(timeout=timeout_seconds)
                failure = None if exit_code == 0 else CommandFailure.NONZERO_EXIT
            except subprocess.TimeoutExpired:
                _terminate_process_group(process)
                exit_code = None
                failure = CommandFailure.TIMED_OUT
        finally:
            _terminate_remaining_process_group(process.pid)
        finished_at = datetime.now(UTC)
        if (
            os.fstat(stdout.fileno()).st_size > _MAX_RELEASE_OUTPUT_BYTES
            or os.fstat(stderr.fileno()).st_size > _MAX_RELEASE_OUTPUT_BYTES
        ):
            raise ReleaseCommandExecutionError("release command output exceeds its bound")
        stdout_blob = store.put_file_descriptor(
            stdout.fileno(),
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )
        stderr_blob = store.put_file_descriptor(
            stderr.fileno(),
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )
        stdout.seek(0)
        stdout_bytes = stdout.read()

    evidence = ReleaseInvocationEvidence(
        invocation_digest=invocation.digest,
        started_at=started_at,
        finished_at=finished_at,
        exit_code=exit_code,
        stdout_blob=stdout_blob,
        stderr_blob=stderr_blob,
        failure=failure,
    )
    evidence_blob = store.put_bytes(
        canonical_bytes(evidence),
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    if _descriptor_digest(descriptor) != executable_digest:
        raise ReleaseCommandExecutionError("release executable changed during invocation")
    if expected_environment_digest is not None:
        _verify_installed_environment(repository, expected_environment_digest)
    return (
        ReleaseInvocationReceipt(
            invocation_digest=invocation.digest,
            evidence=evidence,
            evidence_blob=evidence_blob,
        ),
        stdout_bytes,
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise ReleaseCommandExecutionError(
                "release command process could not be reaped"
            ) from error


def _terminate_remaining_process_group(process_group: int) -> None:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    raise ReleaseCommandExecutionError(
        "release command descendants could not be terminated"
    )


def _catalog_digest_from_output(
    receipt: ReleaseInvocationReceipt,
    stdout: bytes,
) -> Digest:
    if receipt.status is not ReleaseEvidenceStatus.PASSED:
        raise ReleaseCommandExecutionError("catalog verification command did not pass")
    try:
        projection = parse_authoring_contract_output(stdout)
    except ValueError:
        raise ReleaseCommandExecutionError(
            "catalog verification did not emit its canonical digest"
        ) from None
    return projection.public_catalog_digest


def _open_release_executable(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("release executable paths must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        linked = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or stat.S_IMODE(opened.st_mode) & 0o022
            or not stat.S_IMODE(opened.st_mode) & 0o111
            or _executable_identity(opened) != _executable_identity(linked)
        ):
            raise OSError("release executable is not a stable trusted file")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _executable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _descriptor_digest(descriptor: int) -> Digest:
    before = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise OSError("release executable changed while it was hashed")
    return f"sha256:{digest.hexdigest()}"


def _verify_installed_environment(repository: Path, expected_digest: Digest) -> None:
    if _installed_environment_digest(repository) != expected_digest:
        raise ReleaseCommandExecutionError("installed release environment changed")


def _installed_environment_digest(repository: Path) -> Digest:
    site_packages = (
        repository
        / ".edagym-state"
        / "release-environment"
        / "lib"
        / "python3.12"
        / "site-packages"
    )
    first = _installed_environment_records(site_packages)
    second = _installed_environment_records(site_packages)
    if first != second:
        raise ReleaseCommandExecutionError(
            "installed release environment changed while it was inventoried"
        )
    return canonical_digest(first, domain="release-installed-environment-v1")


def _installed_environment_records(root: Path) -> tuple[dict[str, object], ...]:
    root_metadata = root.lstat()
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise ReleaseCommandExecutionError("installed release environment is not trusted")
    records: list[dict[str, object]] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(root)
        for name in directory_names:
            path = directory_path / name
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise ReleaseCommandExecutionError(
                    "installed release environment contains an untrusted directory"
                )
            records.append(
                {
                    "kind": "directory",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "path": (relative_directory / name).as_posix(),
                }
            )
        for name in file_names:
            path = directory_path / name
            before = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) & 0o022
            ):
                raise ReleaseCommandExecutionError(
                    "installed release environment contains an untrusted file"
                )
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            after = path.lstat()
            if _executable_identity(before) != _executable_identity(after):
                raise ReleaseCommandExecutionError(
                    "installed release environment file changed while it was read"
                )
            records.append(
                {
                    "content_digest": f"sha256:{digest.hexdigest()}",
                    "kind": "file",
                    "mode": stat.S_IMODE(before.st_mode),
                    "path": (relative_directory / name).as_posix(),
                    "size_bytes": before.st_size,
                }
            )
    return tuple(records)


def _release_environment(
    temporary_root: Path,
    *,
    include_release_environment: bool,
) -> Mapping[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "GOCACHE": os.fspath(temporary_root / "go-build"),
        "GOMODCACHE": os.fspath(temporary_root / "go-modules"),
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "TMPDIR": os.fspath(temporary_root),
        "XDG_CACHE_HOME": os.fspath(temporary_root / "cache"),
    }
    if include_release_environment:
        environment["PYTHONPATH"] = (
            ".edagym-state/release-environment/lib/python3.12/site-packages"
        )
    return environment


class ReleaseCommandEvidence(StrictModel):
    """Derived command projection retained by the release report."""

    purpose: ReleaseCommandPurpose
    plan_digest: Digest
    receipt_digest: Digest
    repository_identity_digest: Digest
    artifact_policy_digest: Digest
    input_subject_digest: Digest
    installation_receipt_digest: Digest | None = None
    verified_public_catalog_digest: Digest | None = None
    invocation_receipts: Annotated[tuple[ReleaseInvocationReceipt, ...], Field(min_length=1)]
    status: ReleaseEvidenceStatus

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT:
            if (self.status is ReleaseEvidenceStatus.PASSED) != (
                self.verified_public_catalog_digest is not None
            ):
                raise ValueError(
                    "passing authoring evidence requires its public catalog digest"
                )
        elif self.verified_public_catalog_digest is not None:
            raise ValueError("non-authoring commands cannot carry a public catalog digest")
        if (self.purpose in _INSTALLATION_DEPENDENT_PURPOSES) != (
            self.installation_receipt_digest is not None
        ):
            raise ValueError(
                "release command evidence must bind exactly its installation prerequisite"
            )
        statuses = {item.status for item in self.invocation_receipts}
        expected = (
            ReleaseEvidenceStatus.FAILED
            if ReleaseEvidenceStatus.FAILED in statuses
            else ReleaseEvidenceStatus.UNAVAILABLE
            if ReleaseEvidenceStatus.UNAVAILABLE in statuses
            else ReleaseEvidenceStatus.PASSED
        )
        if self.status is not expected:
            raise ValueError("release command status must be derived from invocation receipts")
        return self


def project_release_command(receipt: VerifiedReleaseCommandReceipt) -> ReleaseCommandEvidence:
    """Project one canonical receipt into release-report evidence."""

    if type(receipt) is not VerifiedReleaseCommandReceipt:
        raise TypeError("release command projection requires verified CAS evidence")
    source = receipt.receipt
    _verify_release_command_receipt(source, receipt.store)
    return ReleaseCommandEvidence(
        purpose=source.plan.purpose,
        plan_digest=source.plan.digest,
        receipt_digest=source.digest,
        repository_identity_digest=source.plan.repository.digest,
        artifact_policy_digest=receipt.artifact_policy_digest,
        input_subject_digest=source.plan.input_subject_digest,
        installation_receipt_digest=source.plan.installation_receipt_digest,
        verified_public_catalog_digest=source.verified_public_catalog_digest,
        invocation_receipts=source.invocations,
        status=source.status,
    )
