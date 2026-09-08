"""Evidence for journal replay, crash recovery, and CAS integrity."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID

import pytest

import edagym.run.artifacts as artifacts_module
import edagym.run.materialization as materialization_module
from edagym.canonical import canonical_bytes
from edagym.evaluation import (
    ArtifactEvidence,
    EvidenceKind,
    MeasurementEvidence,
    MeasurementProvenance,
    PassedOutcome,
    ScorerEligibility,
    ScorerEligibilityKind,
    ScoringDecision,
    StageResult,
)
from edagym.evaluation.scoring import measurement_sample_seeds
from edagym.resolution import resolve_run
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    PRIVATE_ARTIFACT_KEY_PROVIDER_ID,
    ArtifactIntegrityError,
    ArtifactManifest,
    ArtifactPolicyViolation,
    ArtifactQuotaExceeded,
    ArtifactStoreError,
    ContentAddressedStore,
    EncryptionKey,
    ManifestEntry,
    RetainedArtifact,
    manifest_tree,
)
from edagym.run.checkpoints import (
    CheckpointConsistencyError,
    UnsupportedCheckpointCapability,
    commit_workspace_checkpoint,
    require_filesystem_checkpoint,
    restore_workspace_checkpoint,
)
from edagym.run.journal import (
    EventConflict,
    InvalidTransition,
    JournalCorruption,
    RunJournal,
    replay,
)
from edagym.run.model import (
    ArtifactRecord,
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    BlobRef,
    CandidateSubmittedEvent,
    CandidateSubmittedPayload,
    EvaluationCompletedEvent,
    EvaluationCompletedPayload,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    ProducerKind,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunRecord,
    RunStartedEvent,
    RunStartedPayload,
    ScoringRecordedEvent,
    ScoringRecordedPayload,
    StopReason,
)
from edagym.specs.common import (
    ArtifactClass,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    ArtifactDisclosure,
    ArtifactPolicy,
    CheckpointCapability,
    ManagedEncryption,
)
from edagym.specs.session import ActorKind
from edagym.specs.task import TaskSpec
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    scalar_task_spec,
    session_spec,
    task_instance,
    task_spec,
)


def _header(task_override: TaskSpec | None = None) -> tuple[RunHeader, TaskSpec]:
    task = task_spec() if task_override is None else task_override
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session_spec(),
        trial_key="journal-0001",
    )
    return RunHeader.from_binding(plan.binding), task


def _started(header: RunHeader) -> RunStartedEvent:
    return RunStartedEvent(
        run_id=header.run_id,
        sequence=0,
        event_id=UUID("00000000-0000-0000-0000-000000000001"),
        timestamp=datetime(2026, 9, 4, tzinfo=UTC),
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=RunStartedPayload(binding_digest=header.binding.digest),
    )


def test_resolved_run_uses_the_session_actor_kind_identity() -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    session = session_spec()

    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="actor-kind-identity",
    )

    assert plan.binding.session.actors[0].kind is session.actors[0].kind
    assert type(plan.binding.session.actors[0].kind) is ActorKind


@pytest.mark.parametrize(
    "capability",
    (CheckpointCapability.APPLICATION, CheckpointCapability.VIRTUAL_MACHINE),
)
def test_non_filesystem_checkpoint_capabilities_fail_closed(
    capability: CheckpointCapability,
) -> None:
    with pytest.raises(UnsupportedCheckpointCapability):
        require_filesystem_checkpoint(capability)


def _candidate(header: RunHeader) -> CandidateSubmittedEvent:
    return CandidateSubmittedEvent(
        run_id=header.run_id,
        sequence=1,
        event_id=UUID("00000000-0000-0000-0000-000000000002"),
        timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
        producer=ProducerKind.PARTICIPANT,
        actor="solver",
        visibility=Visibility.AUTHOR,
        payload=CandidateSubmittedPayload(
            candidate_id="candidate_a",
            candidate_digest=digest("candidate-a"),
        ),
    )


def _confidential_policy() -> ArtifactPolicy:
    base_policy = environment_spec().artifact_policy
    disclosure = ArtifactDisclosure(
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    return ArtifactPolicy(
        quota_bytes=base_policy.quota_bytes,
        encryption=ManagedEncryption(
            provider_id="test_encryption",
            policy_digest=digest("test-encryption-policy"),
        ),
        rules=tuple(
            rule.model_copy(update={"allowed_disclosures": (disclosure,)})
            for rule in base_policy.rules
        ),
    )


def test_journal_recovers_truncated_tail_and_enforces_idempotency(tmp_path: Path) -> None:
    root = tmp_path
    header, task = _header()
    journal = RunJournal.create(root, header, task)
    started = _started(header)
    submitted = _candidate(header)
    assert journal.append(started).next_sequence == 1
    assert journal.append(started).next_sequence == 1
    assert journal.append(submitted).next_sequence == 2

    with journal.events_path.open("ab") as stream:
        stream.write(b'{"incomplete":')
        stream.flush()
        os.fsync(stream.fileno())
    ended = RunEndedEvent(
        run_id=header.run_id,
        sequence=2,
        event_id=UUID("00000000-0000-0000-0000-000000000003"),
        timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
    )
    state = journal.append(ended)
    assert state.next_sequence == 3
    assert state.terminal_reason is StopReason.EXPLICIT_CANCEL
    assert state.candidates[0].candidate_id == "candidate_a"
    assert len(journal.read_events()) == 3

    conflict = submitted.model_copy(
        update={
            "payload": CandidateSubmittedPayload(
                candidate_id="candidate_b",
                candidate_digest=digest("candidate-b"),
            )
        }
    )
    with pytest.raises(EventConflict):
        journal.append(conflict)
    with pytest.raises(InvalidTransition):
        journal.append(
            ended.model_copy(
                update={
                    "sequence": 3,
                    "event_id": UUID("00000000-0000-0000-0000-000000000004"),
                }
            )
        )


def test_journal_transaction_owns_sequence_and_interaction_direction(tmp_path: Path) -> None:
    header, task = _header()
    journal = RunJournal.create(tmp_path, header, task)
    journal.append(_started(header))

    state = journal.transact(
        lambda current: _candidate(header).model_copy(
            update={"sequence": current.next_sequence}
        )
    )
    assert state.next_sequence == 2

    invalid = InteractionRecordedEvent(
        run_id=header.run_id,
        sequence=2,
        event_id=UUID("00000000-0000-0000-0000-000000000005"),
        timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
        producer=ProducerKind.PARTICIPANT,
        actor="solver",
        visibility=Visibility.PARTICIPANT,
        payload=InteractionRecordedPayload(
            direction=InteractionDirection.PARTICIPANT_INPUT,
            interaction_id="wrong_direction",
        ),
    )
    with pytest.raises(InvalidTransition, match="direction"):
        journal.append(invalid)


def test_journal_records_are_hash_chained_and_expose_an_anchor(tmp_path: Path) -> None:
    header, task = _header()
    journal = RunJournal.create(tmp_path, header, task)
    empty_digest = journal.integrity_digest()
    journal.append(_started(header))
    committed_digest = journal.integrity_digest()
    assert committed_digest != empty_digest
    archived = journal.record()
    assert archived.integrity_digest == committed_digest
    assert archived.events == journal.read_events()
    assert RunRecord.model_validate_json(canonical_bytes(archived)) == archived

    record = json.loads(journal.events_path.read_bytes())
    record["events"][0]["timestamp"] = "2026-09-04T00:00:01Z"
    journal.events_path.write_bytes(canonical_bytes(record) + b"\n")
    with pytest.raises(JournalCorruption, match="invalid durable record"):
        journal.read_events()


def test_verifier_success_requires_a_completed_hard_gate(tmp_path: Path) -> None:
    base_task = task_spec()
    task_document = base_task.model_dump(mode="python")
    task_document["evaluation"]["stages"] = tuple(
        stage
        for stage in task_document["evaluation"]["stages"]
        if stage["stage_id"] == "functional"
    )
    task_document["measurements"] = ()
    task = TaskSpec.model_validate(task_document)
    header, task = _header(task)
    invalid = RunJournal.create(tmp_path / "invalid", header, task)
    invalid.append(_started(header))
    invalid.append(_candidate(header))
    premature_scoring = ScoringRecordedEvent(
        run_id=header.run_id,
        sequence=2,
        event_id=UUID("00000000-0000-0000-0000-000000000009"),
        timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
        producer=ProducerKind.EVALUATOR,
        visibility=Visibility.AUTHOR,
        payload=ScoringRecordedPayload(
            candidate_id="candidate_a",
            decision=ScoringDecision(
                eligibility=ScorerEligibility(
                    state=ScorerEligibilityKind.NOT_CONFIGURED
                )
            ),
        ),
    )
    with pytest.raises(InvalidTransition, match="eligibility"):
        invalid.append(premature_scoring)
    false_success = RunEndedEvent(
        run_id=header.run_id,
        sequence=2,
        event_id=UUID("00000000-0000-0000-0000-000000000010"),
        timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=RunEndedPayload(
            reason=StopReason.VERIFIER_SUCCESS,
            successful_candidate_id="candidate_a",
        ),
    )
    with pytest.raises(InvalidTransition, match="hard gate"):
        invalid.append(false_success)

    valid = RunJournal.create(tmp_path / "valid", header, task)
    valid.append(_started(header))
    valid.append(_candidate(header))
    valid.append(
        EvaluationStartedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID("00000000-0000-0000-0000-000000000011"),
            timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationStartedPayload(
                stage_id="functional",
                candidate_id="candidate_a",
                job_id="job_functional",
            ),
        )
    )
    for sequence, job_state in (
        (3, JobStateKind.RUNNING),
        (4, JobStateKind.COMPLETED),
    ):
        valid.append(
            JobStateChangedEvent(
                run_id=header.run_id,
                sequence=sequence,
                event_id=UUID(f"00000000-0000-0000-0000-00000000001{sequence}"),
                timestamp=datetime(2026, 9, 4, 0, 0, sequence, tzinfo=UTC),
                producer=ProducerKind.EXECUTOR,
                visibility=Visibility.AUTHOR,
                payload=JobStateChangedPayload(
                    job_id="job_functional",
                    state=job_state,
                ),
            )
        )
    valid.append(
        EvaluationCompletedEvent(
            run_id=header.run_id,
            sequence=5,
            event_id=UUID("00000000-0000-0000-0000-000000000015"),
            timestamp=datetime(2026, 9, 4, 0, 0, 5, tzinfo=UTC),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationCompletedPayload(
                candidate_id="candidate_a",
                job_id="job_functional",
                result=StageResult(
                    stage_id="functional",
                    outcome=PassedOutcome(),
                ),
            ),
        )
    )
    success = false_success.model_copy(
        update={
            "sequence": 7,
            "event_id": UUID("00000000-0000-0000-0000-000000000017"),
            "timestamp": datetime(2026, 9, 4, 0, 0, 7, tzinfo=UTC),
        }
    )
    with pytest.raises(InvalidTransition, match="scoring decision"):
        valid.append(success.model_copy(update={"sequence": 6}))
    valid.append(
        premature_scoring.model_copy(
            update={
                "sequence": 6,
                "event_id": UUID("00000000-0000-0000-0000-000000000016"),
                "timestamp": datetime(2026, 9, 4, 0, 0, 6, tzinfo=UTC),
            }
        )
    )
    with pytest.raises(InvalidTransition, match="scored candidate"):
        valid.append(
            EvaluationStartedEvent(
                run_id=header.run_id,
                sequence=7,
                event_id=UUID("00000000-0000-0000-0000-000000000018"),
                timestamp=datetime(2026, 9, 4, 0, 0, 7, tzinfo=UTC),
                producer=ProducerKind.EVALUATOR,
                visibility=Visibility.AUTHOR,
                payload=EvaluationStartedPayload(
                    stage_id="functional",
                    candidate_id="candidate_a",
                    job_id="job_after_scoring",
                ),
            )
        )
    run_state = valid.append(success)
    assert run_state.successful_candidate_id == "candidate_a"
    assert run_state.terminal_reason is StopReason.VERIFIER_SUCCESS


def test_replay_rejects_forged_task_measurement_scorer_and_evaluator_bindings() -> None:
    task = scalar_task_spec()
    header, task = _header(task)
    binding = header.binding
    first_evaluator = binding.evaluators[0]
    forged_bindings = (
        binding.model_copy(
            update={
                "task": binding.task.model_copy(update={"family": "forged_family"})
            }
        ),
        binding.model_copy(update={"measurement_schema_digest": digest("forged-schema")}),
        binding.model_copy(update={"scorer_revision_digest": digest("forged-scorer")}),
        binding.model_copy(
            update={
                "evaluators": (
                    first_evaluator.model_copy(
                        update={"revision_digest": digest("forged-evaluator")}
                    ),
                    *binding.evaluators[1:],
                )
            }
        ),
    )

    for forged_binding in forged_bindings:
        with pytest.raises(JournalCorruption):
            replay(RunHeader.from_binding(forged_binding), task, ())


def test_journal_rejects_measurements_without_replay_provenance(tmp_path: Path) -> None:
    header, task = _header()
    journal = RunJournal.create(tmp_path, header, task)
    journal.append(_started(header))
    journal.append(_candidate(header))

    sequence = 2
    for stage_id in ("functional", "qor"):
        job_id = f"job_{stage_id}"
        journal.append(
            EvaluationStartedEvent(
                run_id=header.run_id,
                sequence=sequence,
                event_id=UUID(int=100 + sequence),
                timestamp=datetime(2026, 9, 4, 0, 0, sequence, tzinfo=UTC),
                producer=ProducerKind.EVALUATOR,
                visibility=Visibility.AUTHOR,
                payload=EvaluationStartedPayload(
                    stage_id=stage_id,
                    candidate_id="candidate_a",
                    job_id=job_id,
                ),
            )
        )
        sequence += 1
        for state in (JobStateKind.RUNNING, JobStateKind.COMPLETED):
            journal.append(
                JobStateChangedEvent(
                    run_id=header.run_id,
                    sequence=sequence,
                    event_id=UUID(int=100 + sequence),
                    timestamp=datetime(2026, 9, 4, 0, 0, sequence, tzinfo=UTC),
                    producer=ProducerKind.EXECUTOR,
                    visibility=Visibility.AUTHOR,
                    payload=JobStateChangedPayload(job_id=job_id, state=state),
                )
            )
            sequence += 1
        if stage_id == "functional":
            journal.append(
                EvaluationCompletedEvent(
                    run_id=header.run_id,
                    sequence=sequence,
                    event_id=UUID(int=100 + sequence),
                    timestamp=datetime(2026, 9, 4, 0, 0, sequence, tzinfo=UTC),
                    producer=ProducerKind.EVALUATOR,
                    visibility=Visibility.AUTHOR,
                    payload=EvaluationCompletedPayload(
                        candidate_id="candidate_a",
                        job_id=job_id,
                        result=StageResult(
                            stage_id=stage_id,
                            outcome=PassedOutcome(),
                        ),
                    ),
                )
            )
            sequence += 1

    evidence = ArtifactRecord(
        logical_id="qor_report",
        blob=BlobRef(digest=digest("qor-report"), size_bytes=17),
        media_type="application/json",
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    journal.append(
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=sequence,
            event_id=UUID(int=100 + sequence),
            timestamp=datetime(2026, 9, 4, 0, 0, sequence, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(record=evidence),
        )
    )
    sequence += 1
    without_provenance = EvaluationCompletedEvent(
        run_id=header.run_id,
        sequence=sequence,
        event_id=UUID(int=100 + sequence),
        timestamp=datetime(2026, 9, 4, 0, 0, sequence, tzinfo=UTC),
        producer=ProducerKind.EVALUATOR,
        visibility=Visibility.AUTHOR,
        artifact_refs=(evidence.logical_id,),
        payload=EvaluationCompletedPayload(
            candidate_id="candidate_a",
            job_id="job_qor",
            result=StageResult(
                stage_id="qor",
                outcome=PassedOutcome(),
                measurements=(
                    MeasurementEvidence(
                        measurement_id="cell_count",
                        samples=(Decimal(7),),
                    ),
                ),
                evidence=(
                    ArtifactEvidence(
                        kind=EvidenceKind.REPORT,
                        artifact_id=evidence.logical_id,
                    ),
                ),
            ),
        ),
    )
    with pytest.raises(InvalidTransition, match="complete provenance"):
        journal.append(without_provenance)

    specification = next(
        measurement
        for measurement in task.measurements
        if measurement.measurement_id == "cell_count"
    )
    tool = next(
        binding
        for binding in header.binding.environment.tools
        if binding.capability.value == "asic.synthesis"
    )
    raw_provenance = without_provenance.model_copy(
        update={
            "payload": without_provenance.payload.model_copy(
                update={
                    "result": without_provenance.payload.result.model_copy(
                        update={
                            "measurements": (
                                MeasurementEvidence(
                                    measurement_id="cell_count",
                                    samples=(Decimal(7),),
                                    provenance=MeasurementProvenance(
                                        unit=specification.unit,
                                        tool_id=tool.tool_id,
                                        tool_version=tool.tool_version,
                                        library_id=specification.library_id,
                                        library_digest=specification.library_digest,
                                        corner=specification.corner,
                                        mode=specification.mode,
                                        task_seed=header.binding.task.instance_seed,
                                        sample_seeds=measurement_sample_seeds(
                                            header.binding.task.instance_seed,
                                            specification.measurement_id,
                                            specification.repetitions,
                                        ),
                                        source_artifact_id=evidence.logical_id,
                                        source_digest=evidence.blob.digest,
                                    ),
                                ),
                            )
                        }
                    )
                }
            )
        }
    )
    with pytest.raises(InvalidTransition, match="sanitized measurement artifact"):
        journal.append(raw_provenance)


def test_encrypted_cas_commits_checkpoint_and_detects_corruption(tmp_path: Path) -> None:
    root = tmp_path
    policy = _confidential_policy()
    store = ContentAddressedStore(
        root,
        policy=policy,
        encryption_key=EncryptionKey(key_id="test_key", value=bytes(range(32))),
    )
    reference = store.put_bytes(
        b"durable checkpoint payload",
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    assert store.read_bytes(reference, maximum_bytes=1024) == b"durable checkpoint payload"
    manifest = ArtifactManifest(
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
        entries=(
            ManifestEntry(
                path="state/checkpoint.bin",
                blob=reference,
                mode=0o644,
            ),
        ),
    )
    committed = store.put_manifest(manifest)
    marker = store.commit_filesystem_checkpoint("checkpoint_a", committed)
    assert marker.checkpoint_kind is CheckpointCapability.FILESYSTEM
    assert marker.manifest_digest == manifest.digest

    hexadecimal = reference.digest.removeprefix("sha256:")
    blob_path = root / "blobs" / hexadecimal[:2] / hexadecimal[2:]
    encoded = bytearray(blob_path.read_bytes())
    encoded[-1] ^= 1
    blob_path.write_bytes(encoded)
    with pytest.raises(ArtifactIntegrityError):
        store.verify(reference)
    with pytest.raises(ArtifactIntegrityError):
        store.load_filesystem_checkpoint("checkpoint_a")


def test_private_cas_openers_share_a_durable_key_and_reject_key_loss(tmp_path: Path) -> None:
    policy = _confidential_policy().model_copy(update={
        "encryption": ManagedEncryption(
            provider_id=PRIVATE_ARTIFACT_KEY_PROVIDER_ID,
            policy_digest=digest("private-artifact-policy"),
        ),
    })
    root = tmp_path / "cas"
    root.mkdir(mode=0o700)
    with ThreadPoolExecutor(max_workers=2) as workers:
        openings = [workers.submit(ContentAddressedStore.open_private, root, policy=policy)
                    for _ in range(2)]
        stores = [opening.result() for opening in openings]
    diagnostic = b"FATAL: candidate.sv:7: expected counterexample\n"
    blob = stores[0].put_bytes(
        diagnostic, artifact_class=ArtifactClass.DIAGNOSTIC,
        sensitivity=Sensitivity.CONFIDENTIAL, visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    assert stores[1].read_bytes(blob, maximum_bytes=1024) == diagnostic
    reopened = ContentAddressedStore.open_private(root, policy=policy)
    assert reopened.read_bytes(blob, maximum_bytes=1024) == diagnostic
    key_path = tmp_path / "cas.key"
    key_path.unlink()
    with pytest.raises(ArtifactPolicyViolation):
        ContentAddressedStore.open_private(root, policy=policy)
    assert not key_path.exists()


def test_checkpoint_restore_requires_one_atomic_journal_commit(tmp_path: Path) -> None:
    header, task = _header()
    journal = RunJournal.create(tmp_path / "journal", header, task)
    journal.append(_started(header))
    environment = environment_spec()
    policy = environment.artifact_policy
    store = ContentAddressedStore(tmp_path / "cas", policy=policy)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "state.bin").write_bytes(b"checkpoint-state")

    marker, state = commit_workspace_checkpoint(
        store=store,
        journal=journal,
        environment=environment,
        workspace=workspace,
        checkpoint_id="checkpoint_a",
        artifact_id="checkpoint_manifest_a",
        parent_checkpoint_id=None,
        timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
        artifact_event_id=UUID("00000000-0000-0000-0000-000000000020"),
        checkpoint_event_id=UUID("00000000-0000-0000-0000-000000000021"),
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    assert state.checkpoint_ids == ("checkpoint_a",)
    repeated_marker, repeated_state = commit_workspace_checkpoint(
        store=store,
        journal=journal,
        environment=environment,
        workspace=workspace,
        checkpoint_id="checkpoint_a",
        artifact_id="checkpoint_manifest_a",
        parent_checkpoint_id=None,
        timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
        artifact_event_id=UUID("00000000-0000-0000-0000-000000000020"),
        checkpoint_event_id=UUID("00000000-0000-0000-0000-000000000021"),
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    assert repeated_marker == marker
    assert repeated_state.next_sequence == state.next_sequence
    destination = tmp_path / "restored"
    assert (
        restore_workspace_checkpoint(
            store=store,
            journal=journal,
            environment=environment,
            checkpoint_id="checkpoint_a",
            destination=destination,
        )
        == marker
    )
    assert (destination / "state.bin").read_bytes() == b"checkpoint-state"

    split_journal = RunJournal.create(tmp_path / "split-journal", header, task)
    split_journal.append(_started(header))
    committed_events = journal.read_events()
    split_journal.append(committed_events[1])
    split_journal.append(committed_events[2])
    with pytest.raises(CheckpointConsistencyError, match="share one durable commit"):
        restore_workspace_checkpoint(
            store=store,
            journal=split_journal,
            environment=environment,
            checkpoint_id="checkpoint_a",
            destination=tmp_path / "split-restore",
        )

    expected_anchor = journal.integrity_digest()
    records = journal.events_path.read_bytes().splitlines(keepends=True)
    assert len(records) == 2
    journal.events_path.write_bytes(records[0] + records[1][: len(records[1]) // 2])
    assert journal.integrity_digest() != expected_anchor
    with pytest.raises(CheckpointConsistencyError, match="durable journal commit"):
        restore_workspace_checkpoint(
            store=store,
            journal=journal,
            environment=environment,
            checkpoint_id="checkpoint_a",
            destination=tmp_path / "uncommitted",
        )


def test_cas_rejects_policy_downgrade_and_preserves_shared_live_blob(tmp_path: Path) -> None:
    policy = environment_spec().artifact_policy
    store = ContentAddressedStore(tmp_path, policy=policy)
    content = b"EDAGYMB1 plaintext prefix is ordinary content"
    blob = store.put_bytes(
        content,
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    assert store.read_bytes(blob, maximum_bytes=len(content)) == content

    hexadecimal = blob.digest.removeprefix("sha256:")
    blob_path = tmp_path / "blobs" / hexadecimal[:2] / hexadecimal[2:]
    encoded = bytearray(blob_path.read_bytes())
    encoded[-1] ^= 1
    blob_path.write_bytes(encoded)
    with pytest.raises(ArtifactIntegrityError):
        store.read_bytes(blob, maximum_bytes=len(content))

    with pytest.raises(ArtifactPolicyViolation, match="metadata"):
        ContentAddressedStore(
            tmp_path,
            policy=_confidential_policy(),
            encryption_key=EncryptionKey(key_id="test_key", value=bytes(range(32))),
        )

    live_root = tmp_path / "live"
    live_store = ContentAddressedStore(live_root, policy=policy)
    shared = live_store.put_bytes(
        b"shared",
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    first = ArtifactRecord(
        logical_id="first",
        blob=shared,
        media_type="application/octet-stream",
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    second = first.model_copy(update={"logical_id": "second"})
    now = datetime(2026, 9, 4, 1, 0, tzinfo=UTC)
    assert live_store.garbage_collect(
        (
            RetainedArtifact(record=first, recorded_at=now - timedelta(seconds=120)),
            RetainedArtifact(record=second, recorded_at=now - timedelta(seconds=30)),
        ),
        now=now,
    ) == ()
    removed = live_store.garbage_collect(
        (
            RetainedArtifact(record=first, recorded_at=now - timedelta(seconds=120)),
            RetainedArtifact(record=second, recorded_at=now - timedelta(seconds=120)),
        ),
        now=now,
    )
    assert removed == (shared.digest,)


def test_cas_rejects_credentials_and_non_author_infrastructure_details(
    tmp_path: Path,
) -> None:
    base_policy = environment_spec().artifact_policy
    protected = ArtifactDisclosure(
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    policy = ArtifactPolicy(
        quota_bytes=base_policy.quota_bytes,
        encryption=ManagedEncryption(
            provider_id="test_encryption",
            policy_digest=digest("test-dlp-encryption-policy"),
        ),
        rules=tuple(
            rule.model_copy(update={"allowed_disclosures": (protected,)})
            if rule.artifact_class
            in {ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE}
            else rule
            for rule in base_policy.rules
        ),
    )
    store = ContentAddressedStore(
        tmp_path / "private",
        policy=policy,
        encryption_key=EncryptionKey(key_id="test_key", value=bytes(range(32))),
    )
    raw_detail = (
        b"report=/mnt/na" b"s0/eda.libs/saed32/run.rpt "
        b"end" b"point=ht" b"tps://broker.in" b"ternal:8443 "
        b"LM_LICENSE_" b"FILE=27" b"000" b"@license.in" b"ternal"
    )
    raw = store.put_bytes(
        raw_detail,
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    assert store.read_bytes(raw, maximum_bytes=raw.size_bytes) == raw_detail

    disclosure_policy = base_policy
    disclosure_store = ContentAddressedStore(
        tmp_path / "disclosable",
        policy=disclosure_policy,
    )
    policy_identity = b'{"artifact_store_policy_digest":"sha256:' + b"0" * 64 + b'"}'
    safe = disclosure_store.put_bytes(
        policy_identity,
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    assert disclosure_store.read_bytes(safe, maximum_bytes=safe.size_bytes) == policy_identity
    with pytest.raises(ArtifactPolicyViolation, match="restricted disclosure policy"):
        disclosure_store.put_bytes(
            b'{"vendor_' b'license_file":"restricted_route"}',
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )
    with pytest.raises(ArtifactPolicyViolation, match="restricted disclosure policy"):
        disclosure_store.put_bytes(
            raw_detail,
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )
    measurement_disclosure = disclosure_policy.persistent_disclosure(
        ArtifactClass.MEASUREMENT
    )
    assert measurement_disclosure is not None
    with pytest.raises(ArtifactPolicyViolation, match="restricted disclosure policy"):
        store.verify_disclosure(
            raw,
            artifact_class=ArtifactClass.MEASUREMENT,
            sensitivity=measurement_disclosure.sensitivity,
            visibility=measurement_disclosure.visibility,
            redistribution=measurement_disclosure.redistribution,
        )
    with pytest.raises(ArtifactPolicyViolation, match="restricted disclosure policy"):
        disclosure_store.put_bytes(
            raw_detail,
            artifact_class=ArtifactClass.MEASUREMENT,
            sensitivity=measurement_disclosure.sensitivity,
            visibility=measurement_disclosure.visibility,
            redistribution=measurement_disclosure.redistribution,
        )
    with pytest.raises(ArtifactPolicyViolation, match="credential policy"):
        store.put_chunks(
            (b"api_" b"key=sk-012345", b"6789abcdefghijkl" b"mnopqrstuvwxyz"),
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.CONFIDENTIAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.FORBIDDEN,
        )


def test_cas_rejects_symlinked_namespaces_and_special_tree_entries(tmp_path: Path) -> None:
    policy = environment_spec().artifact_policy
    store_root = tmp_path / "cas"
    store = ContentAddressedStore(store_root, policy=policy)
    reference = store.put_bytes(
        b"trusted",
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    hexadecimal = reference.digest.removeprefix("sha256:")
    shard = store_root / "blobs" / hexadecimal[:2]
    moved_shard = tmp_path / "moved-shard"
    shard.rename(moved_shard)
    shard.symlink_to(moved_shard, target_is_directory=True)
    with pytest.raises(ArtifactStoreError, match="opened safely"):
        store.verify(reference)

    tree = tmp_path / "tree"
    tree.mkdir()
    fifo = tree / "blocking-input"
    os.mkfifo(fifo)
    with pytest.raises(ArtifactStoreError, match="links or special files"):
        manifest_tree(
            ContentAddressedStore(tmp_path / "safe-cas", policy=policy),
            tree,
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )


def test_manifest_capture_rejects_a_tree_that_changes_during_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = environment_spec().artifact_policy
    store = ContentAddressedStore(tmp_path / "cas", policy=policy)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "state.bin"
    source.write_bytes(b"initial-state")
    original_put = store.put_file_descriptor

    def put_and_mutate(
        descriptor: int,
        *,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> BlobRef:
        reference = original_put(
            descriptor,
            artifact_class=artifact_class,
            sensitivity=sensitivity,
            visibility=visibility,
            redistribution=redistribution,
        )
        source.write_bytes(b"changed-state")
        return reference

    monkeypatch.setattr(store, "put_file_descriptor", put_and_mutate)
    with pytest.raises(ArtifactIntegrityError, match="changed while it was captured"):
        manifest_tree(
            store,
            workspace,
            artifact_class=ArtifactClass.CHECKPOINT,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )


def test_checkpoint_retention_preserves_and_reclaims_the_complete_manifest(
    tmp_path: Path,
) -> None:
    policy = environment_spec().artifact_policy
    store = ContentAddressedStore(tmp_path / "cas", policy=policy)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "state.bin").write_bytes(b"retained-state")
    manifest = manifest_tree(
        store,
        workspace,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    committed = store.put_manifest(manifest)
    store.commit_filesystem_checkpoint("retained_checkpoint", committed)
    record = ArtifactRecord(
        logical_id="retained_manifest",
        blob=committed.blob,
        media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    now = datetime(2026, 9, 4, 1, 0, tzinfo=UTC)

    assert store.garbage_collect(
        (
            RetainedArtifact(
                record=record,
                recorded_at=now - timedelta(hours=2),
                checkpoint_pinned=True,
            ),
        ),
        now=now,
    ) == ()
    _, loaded = store.load_filesystem_checkpoint("retained_checkpoint")
    assert loaded == manifest

    removed = store.garbage_collect(
        (
            RetainedArtifact(
                record=record,
                recorded_at=now - timedelta(hours=2),
            ),
        ),
        now=now,
    )
    assert set(removed) == {committed.blob.digest, manifest.entries[0].blob.digest}
    with pytest.raises(ArtifactIntegrityError):
        store.load_filesystem_checkpoint("retained_checkpoint")


def test_cas_rejects_marker_identity_swaps_and_recovers_incoming_files(
    tmp_path: Path,
) -> None:
    policy = environment_spec().artifact_policy
    store_root = tmp_path / "cas"
    store = ContentAddressedStore(store_root, policy=policy)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "state.bin").write_bytes(b"state")
    manifest = manifest_tree(
        store,
        workspace,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    committed = store.put_manifest(manifest)
    marker = store.commit_filesystem_checkpoint("checkpoint_a", committed)
    marker_path = store_root / "checkpoints" / "checkpoint_a.json"
    untyped_marker = json.loads(marker_path.read_bytes())
    del untyped_marker["checkpoint_kind"]
    marker_path.write_bytes(canonical_bytes(untyped_marker) + b"\n")
    with pytest.raises(ArtifactIntegrityError, match="invalid"):
        store.load_filesystem_checkpoint("checkpoint_a")
    marker_path.write_bytes(canonical_bytes(marker) + b"\n")
    marker_path.rename(
        store_root / "checkpoints" / "checkpoint_b.json"
    )
    with pytest.raises(ArtifactIntegrityError, match="identity"):
        store.load_filesystem_checkpoint("checkpoint_b")

    incoming = store_root / "incoming-stale"
    incoming.write_bytes(b"abandoned")
    incoming.chmod(0o600)
    publish = store_root / "checkpoints" / "publish-stale"
    publish.write_bytes(b"abandoned")
    publish.chmod(0o600)
    store.stored_bytes()
    assert not incoming.exists()
    assert not publish.exists()

    tiny_policy = policy.model_copy(update={"quota_bytes": 1})
    tiny_store = ContentAddressedStore(tmp_path / "tiny-cas", policy=tiny_policy)
    with pytest.raises(ArtifactQuotaExceeded):
        tiny_store.put_bytes(
            b"",
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )


def test_restore_materializes_portable_modes_as_owner_only(tmp_path: Path) -> None:
    policy = environment_spec().artifact_policy
    store = ContentAddressedStore(tmp_path / "cas", policy=policy)
    content = store.put_bytes(
        b"restored-content",
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    manifest = ArtifactManifest(
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
        entries=(
            ManifestEntry(path="private.txt", blob=content, mode=0o644),
            ManifestEntry(path="bin/tool", blob=content, mode=0o755),
        ),
    )

    destination = tmp_path / "restore"
    artifacts_module.restore_manifest(store, manifest, destination)

    assert (destination / "private.txt").stat().st_mode & 0o777 == 0o600
    assert (destination / "bin" / "tool").stat().st_mode & 0o777 == 0o700


def test_restore_never_follows_replaced_or_ancestor_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = environment_spec().artifact_policy
    store = ContentAddressedStore(tmp_path / "cas", policy=policy)
    content = store.put_bytes(
        b"restored-content",
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    manifest = ArtifactManifest(
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
        entries=(ManifestEntry(path="nested/state.bin", blob=content, mode=0o644),),
    )

    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"keep")
    destination = tmp_path / "restore"
    original_write = materialization_module._write_all

    def interrupt_write(stream: object, payload: bytes) -> None:
        del stream, payload
        raise OSError("injected restore failure")

    monkeypatch.setattr(materialization_module, "_write_all", interrupt_write)
    with pytest.raises(OSError, match="injected restore failure"):
        artifacts_module.restore_manifest(store, manifest, destination)
    assert not destination.exists()
    retained_staging = tuple(tmp_path.glob(".edagym-restore-*"))
    assert len(retained_staging) == 1
    assert retained_staging[0].stat().st_mode & 0o077 == 0
    assert sentinel.read_bytes() == b"keep"
    assert tuple(outside.iterdir()) == (sentinel,)

    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ArtifactStoreError, match="opened safely"):
        artifacts_module.restore_manifest(store, manifest, linked_parent / "blocked")
    assert not (outside / "blocked").exists()

    monkeypatch.setattr(materialization_module, "_write_all", original_write)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    replacement.chmod(0o700)
    replacement_sentinel = replacement / "sentinel"
    replacement_sentinel.write_bytes(b"keep-replacement")
    replaced_destination = tmp_path / "real-restore"
    original_rename = materialization_module._rename_directory_no_replace

    def occupy_destination_before_publication(
        parent_descriptor: int,
        source_name: str,
        destination_name: str,
    ) -> None:
        replacement.rename(replaced_destination)
        original_rename(parent_descriptor, source_name, destination_name)

    monkeypatch.setattr(
        materialization_module,
        "_rename_directory_no_replace",
        occupy_destination_before_publication,
    )
    with pytest.raises(FileExistsError):
        artifacts_module.restore_manifest(store, manifest, replaced_destination)
    assert (replaced_destination / replacement_sentinel.name).read_bytes() == b"keep-replacement"
    assert len(tuple(tmp_path.glob(".edagym-restore-*"))) == 2
