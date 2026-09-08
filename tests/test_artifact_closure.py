"""Evidence that terminal RunRecords close over verified CAS plaintext."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from edagym.providers.model import ProviderSecurityBinding
from edagym.resolution import resolve_run
from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
    ManifestEntry,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ContentAddressedStore,
    EncryptionKey,
    artifact_policy_digest,
    candidate_snapshot_artifact_id,
)
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    CampaignTrialRunBinding,
    CandidateSubmittedEvent,
    CandidateSubmittedPayload,
    CheckpointCommittedEvent,
    CheckpointCommittedPayload,
    EventKind,
    ParticipantIncarnationBinding,
    ParticipantIncarnationStartedEvent,
    ParticipantIncarnationStartedPayload,
    ParticipantProcessIdentity,
    ProducerKind,
    ProviderRequestStartedEvent,
    ProviderRequestStartedPayload,
    ProviderResponseRecordedEvent,
    ProviderResponseRecordedPayload,
    RunCommit,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunRecord,
    RunStartedEvent,
    RunStartedPayload,
    StopReason,
    run_journal_anchor,
)
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    RuntimeSurfaceBinding,
)
from edagym.security.artifact_closure import (
    ArtifactClosureError,
    RunArtifactReferenceKind,
    verify_run_artifact_closure,
)
from edagym.security.canary import CanaryPolicy, CanaryReceipt
from edagym.security.canary_artifact import (
    PROVIDER_TRANSCRIPT_MEDIA_TYPE,
    ProviderCanaryEvidence,
    ProviderTranscriptRole,
    provider_transcript_artifact_id,
    store_provider_canary_evidence,
)
from edagym.security.runtime_surface import (
    RuntimeSurfaceIdentity,
    RuntimeSurfaceManifest,
)
from edagym.specs.common import (
    ArtifactClass,
    ProviderResponseStatus,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    EnvironmentSpec,
    ManagedEncryption,
)
from edagym.specs.task import TaskSpec
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def _record_with_checkpoint(
    root: Path,
) -> tuple[RunRecord, TaskSpec, ContentAddressedStore]:
    task = task_spec()
    base_environment = environment_spec()
    policy = ArtifactPolicy(
        quota_bytes=base_environment.artifact_policy.quota_bytes,
        encryption=ManagedEncryption(
            provider_id="closure_test_provider",
            policy_digest=digest("closure-test-key-policy"),
        ),
        rules=base_environment.artifact_policy.rules,
    )
    environment = EnvironmentSpec.model_validate(
        {
            **base_environment.model_dump(mode="python"),
            "artifact_policy": policy,
        }
    )
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session_spec(),
        trial_key="artifact-closure",
    )
    header = RunHeader.from_binding(plan.binding)
    store_root = root / "cas"
    store_root.mkdir(mode=0o700)
    store = ContentAddressedStore(
        store_root,
        policy=policy,
        encryption_key=EncryptionKey(key_id="closure_test_key", value=b"k" * 32),
    )
    plaintext = b"canonical checkpoint content"
    entry = store.put_bytes(
        plaintext,
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
        entries=(ManifestEntry(path="checkpoint.bin", blob=entry, mode=0o644),),
    )
    committed = store.put_manifest(manifest)
    marker = store.commit_filesystem_checkpoint("checkpoint_one", committed)
    artifact = ArtifactRecord(
        logical_id="checkpoint_manifest",
        blob=committed.blob,
        media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    timestamp = datetime(2026, 9, 4, tzinfo=UTC)
    events = (
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID(int=1),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID(int=2),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(record=artifact),
        ),
        CheckpointCommittedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID(int=3),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            artifact_refs=(artifact.logical_id,),
            payload=CheckpointCommittedPayload(
                checkpoint_id="checkpoint_one",
                manifest_digest=marker.manifest_digest,
            ),
        ),
        RunEndedEvent(
            run_id=header.run_id,
            sequence=3,
            event_id=UUID(int=4),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
        ),
    )
    record = RunRecord(
        header=header,
        commits=(
            RunCommit.from_events(
                previous_record_digest=run_journal_anchor(header),
                events=events,
            ),
        ),
    )
    return record, task, store


def _record_with_provider_exchange(
    root: Path,
    *,
    evidence_campaign_digest: str | None = None,
) -> tuple[RunRecord, TaskSpec, ContentAddressedStore]:
    task = task_spec()
    base_environment = environment_spec()
    protected = ArtifactDisclosure(
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    rules = tuple(
        ArtifactRetentionRule(
            artifact_class=rule.artifact_class,
            retention_seconds=rule.retention_seconds,
            allowed_disclosures=(
                (protected,)
                if rule.artifact_class in {ArtifactClass.EVIDENCE, ArtifactClass.TRAINING}
                else rule.allowed_disclosures
            ),
        )
        for rule in base_environment.artifact_policy.rules
    )
    policy = ArtifactPolicy(
        quota_bytes=base_environment.artifact_policy.quota_bytes,
        encryption=ManagedEncryption(
            provider_id="provider_closure_test",
            policy_digest=digest("provider-closure-key-policy"),
        ),
        rules=rules,
    )
    environment = EnvironmentSpec.model_validate(
        {
            **base_environment.model_dump(mode="python"),
            "artifact_policy": policy,
        }
    )
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    campaign = CampaignTrialRunBinding(
        campaign_digest=digest("provider-campaign"),
        schedule_digest=digest("provider-schedule"),
        scheduled_trial_digest=digest("provider-scheduled-trial"),
        paired_seed="1" * 32,
        repetition_index=0,
        route_id="provider_route",
        reasoning_effort="high",
        service_tier="fast",
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session_spec(),
        trial_key="provider-closure",
        campaign=campaign,
    )
    header = RunHeader.from_binding(plan.binding)
    store_root = root / "provider-cas"
    store_root.mkdir(mode=0o700)
    store = ContentAddressedStore(
        store_root,
        policy=policy,
        encryption_key=EncryptionKey(
            key_id="provider_closure_key",
            value=b"p" * 32,
        ),
    )
    provider_profile_digest = digest("provider-profile")
    provider_config_digest = digest("provider-config")
    budget_binding_digest = digest("provider-budget")
    manifest_campaign_digest = (
        campaign.campaign_digest
        if evidence_campaign_digest is None
        else evidence_campaign_digest
    )
    runtime_binding = RuntimeSurfaceBinding(
        campaign_digest=manifest_campaign_digest,
        campaign_schedule_digest=campaign.schedule_digest,
        scheduled_trial_digest=campaign.scheduled_trial_digest,
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        budget_binding_digest=budget_binding_digest,
        task_release_digest=header.binding.task.release_digest,
        environment_spec_digest=header.binding.environment.environment_spec_digest,
        session_spec_digest=header.binding.session.session_spec_digest,
        harness_digest=header.binding.session.actors[0].harness_digest,  # type: ignore[union-attr]
        harness_schema_digest=digest("provider-harness-schema"),
        executor_digest=header.binding.environment.executor_digest,
        export_policy_digest=digest("provider-export-policy"),
    )
    preflight_run_id = digest("provider-preflight-run")
    manifest = RuntimeSurfaceManifest(
        preflight_run_id=preflight_run_id,
        preflight_record_digest=digest("provider-preflight-record"),
        run_binding_digest=preflight_run_id,
        binding=runtime_binding,
        executor_receipt_digest=digest("provider-preflight-executor"),
        launcher_receipt_digest=digest("provider-preflight-launcher"),
        artifact_closure_receipt_digest=digest("provider-preflight-artifact-closure"),
        artifact_store_identity_digest=digest("provider-preflight-store"),
        surfaces=tuple(
            RuntimeSurfaceIdentity(
                surface=surface,
                identity_digest=digest(f"provider-surface-{surface.value}"),
            )
            for surface in REQUIRED_ISOLATION_SURFACES
        ),
    )
    canary_policy = CanaryPolicy(
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        budget_binding_digest=budget_binding_digest,
    )
    receipt = CanaryReceipt(
        attestation_id="a" * 32,
        policy_digest=canary_policy.digest,
        campaign_digest=manifest_campaign_digest,
        provider_profile_digest=provider_profile_digest,
        manifest_digest=manifest.digest,
        collection_evidence_digest=digest("provider-canary-collection"),
    )
    evidence = ProviderCanaryEvidence(
        policy=canary_policy,
        receipt=receipt,
        runtime_surface_manifest=manifest,
    )
    evidence_artifact = store_provider_canary_evidence(evidence, store)
    request_id = "provider_request_one"
    request_blob = store.put_bytes(
        b'{"input":[],"model":"test-route","store":false}',
        artifact_class=ArtifactClass.TRAINING,
        sensitivity=protected.sensitivity,
        visibility=protected.visibility,
        redistribution=protected.redistribution,
    )
    request_artifact = ArtifactRecord(
        logical_id=provider_transcript_artifact_id(
            request_id,
            ProviderTranscriptRole.REQUEST,
        ),
        blob=request_blob,
        media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
        artifact_class=ArtifactClass.TRAINING,
        sensitivity=protected.sensitivity,
        visibility=protected.visibility,
        redistribution=protected.redistribution,
    )
    response_blob = store.put_bytes(
        b'{"id":"response_one","model":"test-route","status":"completed"}',
        artifact_class=ArtifactClass.TRAINING,
        sensitivity=protected.sensitivity,
        visibility=protected.visibility,
        redistribution=protected.redistribution,
    )
    response_artifact = ArtifactRecord(
        logical_id=provider_transcript_artifact_id(
            request_id,
            ProviderTranscriptRole.RESPONSE,
        ),
        blob=response_blob,
        media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
        artifact_class=ArtifactClass.TRAINING,
        sensitivity=protected.sensitivity,
        visibility=protected.visibility,
        redistribution=protected.redistribution,
    )
    timestamp = datetime(2026, 9, 4, tzinfo=UTC)
    incarnation = ParticipantIncarnationBinding(
        generation=0,
        process=ParticipantProcessIdentity(
            process_id=1,
            start_time_ticks=1,
            boot_id_digest=digest("provider-boot"),
        ),
        workspace_identity_digest=digest("provider-workspace"),
        artifact_directory_identity_digest=digest("provider-artifacts"),
    )
    security = ProviderSecurityBinding(
        canary_receipt_digest=receipt.digest,
        runtime_surface_manifest_digest=manifest.digest,
        budget_binding_digest=budget_binding_digest,
    )
    events = (
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID(int=101),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        ),
        ParticipantIncarnationStartedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID(int=102),
            timestamp=timestamp,
            payload=ParticipantIncarnationStartedPayload(incarnation=incarnation),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID(int=103),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(record=request_artifact),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=3,
            event_id=UUID(int=104),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(record=evidence_artifact),
        ),
        ProviderRequestStartedEvent(
            run_id=header.run_id,
            sequence=4,
            event_id=UUID(int=105),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            artifact_refs=(request_artifact.logical_id, evidence_artifact.logical_id),
            payload=ProviderRequestStartedPayload(
                request_id=request_id,
                actor_id="solver",
                request_artifact_id=request_artifact.logical_id,
                security_evidence_artifact_id=evidence_artifact.logical_id,
                provider_profile_digest=provider_profile_digest,
                provider_config_digest=provider_config_digest,
                requested_model="test-route",
                requested_service_tier="fast",
                security_binding=security,
                reserved_input_tokens=128,
                reserved_output_tokens=64,
            ),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=5,
            event_id=UUID(int=106),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(record=response_artifact),
        ),
        ProviderResponseRecordedEvent(
            run_id=header.run_id,
            sequence=6,
            event_id=UUID(int=107),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            artifact_refs=(response_artifact.logical_id,),
            payload=ProviderResponseRecordedPayload(
                request_id=request_id,
                provider_reported_model="test-route",
                provider_reported_service_tier="fast",
                status=ProviderResponseStatus.COMPLETED,
            ),
        ),
        RunEndedEvent(
            run_id=header.run_id,
            sequence=7,
            event_id=UUID(int=108),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
        ),
    )
    anchor = run_journal_anchor(header)
    startup = RunCommit.from_events(previous_record_digest=anchor, events=events[:2])
    request = RunCommit.from_events(
        previous_record_digest=startup.record_digest,
        events=events[2:5],
    )
    response = RunCommit.from_events(
        previous_record_digest=request.record_digest,
        events=events[5:7],
    )
    ended = RunCommit.from_events(
        previous_record_digest=response.record_digest,
        events=events[7:],
    )
    return (
        RunRecord(header=header, commits=(startup, request, response, ended)),
        task,
        store,
    )


def test_artifact_closure_reopens_encrypted_plaintext_and_binds_exact_edges(
    tmp_path: Path,
) -> None:
    record, task, store = _record_with_checkpoint(tmp_path)
    receipt = verify_run_artifact_closure(record, task, store)

    assert receipt.run_record_digest == record.integrity_digest
    assert receipt.artifact_policy_digest == artifact_policy_digest(store.policy)
    assert tuple(artifact.logical_id for artifact in receipt.artifacts) == (
        "checkpoint_manifest",
    )
    assert len(receipt.reference_edges) == 1
    assert receipt.reference_edges[0].event_kind is EventKind.CHECKPOINT_COMMITTED
    assert receipt.reference_edges[0].reference_kind is RunArtifactReferenceKind.DECLARED
    assert receipt.reference_edges[0].artifact_ids == ("checkpoint_manifest",)
    assert receipt.digest.startswith("sha256:")
    assert str(tmp_path) not in receipt.model_dump_json()

    stored_blobs = tuple(path for path in store.blob_root.rglob("*") if path.is_file())
    assert stored_blobs
    assert all(b"canonical checkpoint content" not in path.read_bytes() for path in stored_blobs)


def test_artifact_closure_rejects_changed_ciphertext(tmp_path: Path) -> None:
    record, task, store = _record_with_checkpoint(tmp_path)
    blob_path = next(path for path in store.blob_root.rglob("*") if path.is_file())
    blob_path.write_bytes(b"changed encrypted bytes")
    blob_path.chmod(0o600)

    with pytest.raises(ArtifactClosureError, match="CAS content is invalid"):
        verify_run_artifact_closure(record, task, store)


def test_artifact_closure_reopens_provider_transcripts_and_canary_evidence(
    tmp_path: Path,
) -> None:
    record, task, store = _record_with_provider_exchange(tmp_path)

    receipt = verify_run_artifact_closure(record, task, store)

    provider_events = {
        EventKind.PROVIDER_REQUEST_STARTED,
        EventKind.PROVIDER_RESPONSE_RECORDED,
    }
    assert {
        edge.event_kind for edge in receipt.reference_edges if edge.event_kind in provider_events
    } == provider_events
    assert all(artifact.visibility is Visibility.AUTHOR for artifact in receipt.artifacts)
    assert str(tmp_path) not in receipt.model_dump_json()


def test_artifact_closure_rejects_canary_evidence_from_another_paid_trial(
    tmp_path: Path,
) -> None:
    record, task, store = _record_with_provider_exchange(
        tmp_path,
        evidence_campaign_digest=digest("another-provider-campaign"),
    )

    with pytest.raises(ArtifactClosureError, match="differs from the paid run binding"):
        verify_run_artifact_closure(record, task, store)


def test_artifact_closure_rejects_unreferenced_provider_artifacts(
    tmp_path: Path,
) -> None:
    record, task, store = _record_with_provider_exchange(tmp_path)
    orphan_blob = store.put_bytes(
        b'{"orphan":true}',
        artifact_class=ArtifactClass.TRAINING,
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    orphan = ArtifactRecord(
        logical_id=provider_transcript_artifact_id(
            "orphan_request",
            ProviderTranscriptRole.REQUEST,
        ),
        blob=orphan_blob,
        media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
        artifact_class=ArtifactClass.TRAINING,
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    timestamp = datetime(2026, 9, 4, tzinfo=UTC)
    orphan_event = ArtifactRecordedEvent(
        run_id=record.header.run_id,
        sequence=7,
        event_id=UUID(int=109),
        timestamp=timestamp,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=ArtifactRecordedPayload(record=orphan),
    )
    orphan_commit = RunCommit.from_events(
        previous_record_digest=record.commits[-2].record_digest,
        events=(orphan_event,),
    )
    ended = RunEndedEvent(
        run_id=record.header.run_id,
        sequence=8,
        event_id=UUID(int=110),
        timestamp=timestamp,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
    )
    ended_commit = RunCommit.from_events(
        previous_record_digest=orphan_commit.record_digest,
        events=(ended,),
    )
    with_orphan = RunRecord(
        header=record.header,
        commits=(*record.commits[:-1], orphan_commit, ended_commit),
    )

    with pytest.raises(ArtifactClosureError, match="do not match provider exchange"):
        verify_run_artifact_closure(with_orphan, task, store)


def test_artifact_closure_rejects_visible_provider_transcripts(tmp_path: Path) -> None:
    record, task, store = _record_with_provider_exchange(tmp_path)
    startup, request, response, ended = record.commits
    request_artifact_event = request.events[0]
    assert isinstance(request_artifact_event, ArtifactRecordedEvent)
    visible_record = request_artifact_event.payload.record.model_copy(
        update={"visibility": Visibility.PARTICIPANT}
    )
    visible_event = request_artifact_event.model_copy(
        update={"payload": ArtifactRecordedPayload(record=visible_record)}
    )
    changed_request = RunCommit.from_events(
        previous_record_digest=startup.record_digest,
        events=(visible_event, *request.events[1:]),
    )
    changed_response = RunCommit.from_events(
        previous_record_digest=changed_request.record_digest,
        events=response.events,
    )
    changed_end = RunCommit.from_events(
        previous_record_digest=changed_response.record_digest,
        events=ended.events,
    )
    visible = RunRecord(
        header=record.header,
        commits=(startup, changed_request, changed_response, changed_end),
    )

    with pytest.raises(ArtifactClosureError, match="run record is invalid"):
        verify_run_artifact_closure(visible, task, store)


def test_artifact_closure_requires_atomic_candidate_snapshot_registration(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session_spec(),
        trial_key="candidate-closure",
    )
    header = RunHeader.from_binding(plan.binding)
    store_root = tmp_path / "candidate-cas"
    store_root.mkdir(mode=0o700)
    store = ContentAddressedStore(store_root, policy=environment.artifact_policy)
    entry = store.put_bytes(
        b"module candidate; endmodule\n",
        artifact_class=ArtifactClass.CANDIDATE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    manifest = ArtifactManifest(
        artifact_class=ArtifactClass.CANDIDATE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
        entries=(ManifestEntry(path="design.sv", blob=entry, mode=0o644),),
    )
    committed = store.put_manifest(manifest)
    artifact = ArtifactRecord(
        logical_id=candidate_snapshot_artifact_id(header.run_id, "candidate_one"),
        blob=committed.blob,
        media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
        artifact_class=ArtifactClass.CANDIDATE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    timestamp = datetime(2026, 9, 4, tzinfo=UTC)
    started = RunStartedEvent(
        run_id=header.run_id,
        sequence=0,
        event_id=UUID(int=11),
        timestamp=timestamp,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.PUBLIC,
        payload=RunStartedPayload(binding_digest=header.binding.digest),
    )
    recorded = ArtifactRecordedEvent(
        run_id=header.run_id,
        sequence=1,
        event_id=UUID(int=12),
        timestamp=timestamp,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=ArtifactRecordedPayload(record=artifact),
    )
    submitted = CandidateSubmittedEvent(
        run_id=header.run_id,
        sequence=2,
        event_id=UUID(int=13),
        timestamp=timestamp,
        producer=ProducerKind.PARTICIPANT,
        actor="solver",
        visibility=Visibility.PARTICIPANT,
        payload=CandidateSubmittedPayload(
            candidate_id="candidate_one",
            candidate_digest=committed.blob.digest,
        ),
    )
    ended = RunEndedEvent(
        run_id=header.run_id,
        sequence=3,
        event_id=UUID(int=14),
        timestamp=timestamp,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.AUTHOR,
        payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
    )
    anchor = run_journal_anchor(header)
    started_commit = RunCommit.from_events(
        previous_record_digest=anchor,
        events=(started,),
    )
    candidate_commit = RunCommit.from_events(
        previous_record_digest=started_commit.record_digest,
        events=(recorded, submitted),
    )
    ended_commit = RunCommit.from_events(
        previous_record_digest=candidate_commit.record_digest,
        events=(ended,),
    )
    record = RunRecord(
        header=header,
        commits=(started_commit, candidate_commit, ended_commit),
    )

    receipt = verify_run_artifact_closure(record, task, store)
    candidate_edge = next(
        edge
        for edge in receipt.reference_edges
        if edge.reference_kind is RunArtifactReferenceKind.CANDIDATE_SNAPSHOT
    )
    assert candidate_edge.event_id == submitted.event_id
    assert candidate_edge.artifact_ids == (artifact.logical_id,)

    split_recorded = RunCommit.from_events(
        previous_record_digest=started_commit.record_digest,
        events=(recorded,),
    )
    split_submitted = RunCommit.from_events(
        previous_record_digest=split_recorded.record_digest,
        events=(submitted,),
    )
    split_ended = RunCommit.from_events(
        previous_record_digest=split_submitted.record_digest,
        events=(ended,),
    )
    non_atomic = RunRecord(
        header=header,
        commits=(started_commit, split_recorded, split_submitted, split_ended),
    )
    with pytest.raises(ArtifactClosureError, match="not atomically bound"):
        verify_run_artifact_closure(non_atomic, task, store)
