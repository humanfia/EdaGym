"""Content-verified, path-free closure receipts for terminal run artifacts."""

from __future__ import annotations

import hashlib
import os
import stat
from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ArtifactStoreError,
    ContentAddressedStore,
    candidate_snapshot_artifact_id,
)
from edagym.run.journal import JournalError, replay
from edagym.run.model import (
    ArtifactRecord,
    ArtifactRecordedEvent,
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    EventKind,
    HarnessRunActor,
    ProviderRequestStartedEvent,
    ProviderResponseRecordedEvent,
    RunRecord,
)
from edagym.security.canary_artifact import (
    PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE,
    PROVIDER_TRANSCRIPT_MEDIA_TYPE,
    ProviderCanaryEvidence,
    ProviderCanaryEvidenceError,
    ProviderTranscriptError,
    ProviderTranscriptRole,
    provider_transcript_artifact_id,
    verify_provider_canary_evidence,
    verify_provider_transcript_artifact,
)
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    Redistribution,
    SchemaVersion,
    Sensitivity,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import CheckpointCapability
from edagym.specs.task import TaskSpec


class ArtifactClosureError(RuntimeError):
    """The run record and concrete artifact store do not form one valid closure."""


class RunArtifactReferenceKind(StrEnum):
    DECLARED = "declared"
    CANDIDATE_SNAPSHOT = "candidate_snapshot"


class RunArtifactReferenceEdge(StrictModel):
    """One immutable journal edge to already-registered artifact identifiers."""

    sequence: JcsNonNegativeInt
    event_id: UUID
    event_kind: EventKind
    reference_kind: RunArtifactReferenceKind
    artifact_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]

    @field_validator("artifact_ids")
    @classmethod
    def require_unique_artifacts(cls, value: tuple[Identifier, ...]) -> tuple[Identifier, ...]:
        if len(value) != len(set(value)):
            raise ValueError("artifact reference edges cannot repeat an identifier")
        return value


class RunArtifactClosureReceipt(StrictModel):
    """Author-only proof that one terminal RunRecord closes over verified CAS bytes."""

    schema_version: SchemaVersion = 1
    run_id: Digest
    run_record_digest: Digest
    artifact_policy_digest: Digest
    artifact_store_identity_digest: Digest
    artifacts: tuple[ArtifactRecord, ...]
    reference_edges: tuple[RunArtifactReferenceEdge, ...]

    @field_validator("artifacts")
    @classmethod
    def normalize_artifacts(cls, value: tuple[ArtifactRecord, ...]) -> tuple[ArtifactRecord, ...]:
        identifiers = [record.logical_id for record in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("artifact closure identifiers must be unique")
        return tuple(sorted(value, key=lambda record: record.logical_id))

    @field_validator("reference_edges")
    @classmethod
    def normalize_edges(
        cls,
        value: tuple[RunArtifactReferenceEdge, ...],
    ) -> tuple[RunArtifactReferenceEdge, ...]:
        sequences = [edge.sequence for edge in value]
        event_ids = [edge.event_id for edge in value]
        if len(sequences) != len(set(sequences)) or len(event_ids) != len(set(event_ids)):
            raise ValueError("artifact closure event edges must be unique")
        return tuple(sorted(value, key=lambda edge: edge.sequence))

    @model_validator(mode="after")
    def require_registered_references(self) -> Self:
        registered = {record.logical_id for record in self.artifacts}
        referenced = {
            artifact_id for edge in self.reference_edges for artifact_id in edge.artifact_ids
        }
        if not referenced.issubset(registered):
            raise ValueError("artifact closure edge references an unregistered artifact")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="run-artifact-closure-receipt-v1")


def verify_run_artifact_closure(
    record: RunRecord,
    task: TaskSpec,
    store: ContentAddressedStore,
) -> RunArtifactClosureReceipt:
    """Verify every registered artifact through one descriptor-bound concrete CAS."""

    if type(record) is not RunRecord:
        raise TypeError("artifact closure verification requires a concrete RunRecord")
    if type(task) is not TaskSpec:
        raise TypeError("artifact closure verification requires a concrete TaskSpec")
    if type(store) is not ContentAddressedStore:
        raise TypeError("artifact closure verification requires the concrete artifact store")

    try:
        descriptor = os.open(
            store.root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ArtifactClosureError("artifact store root cannot be opened safely") from error
    try:
        store_identity = artifact_store_identity_digest(store, descriptor)
        try:
            state = replay(record.header, task, record.events)
        except JournalError as error:
            raise ArtifactClosureError("artifact closure run record is invalid") from error
        if state.terminal_reason is None:
            raise ArtifactClosureError("artifact closure requires a terminal run record")

        artifacts = tuple(
            event.payload.record
            for event in record.events
            if isinstance(event, ArtifactRecordedEvent)
        )
        if tuple(state.artifacts) != artifacts:
            raise ArtifactClosureError("artifact closure differs from replayed run state")
        try:
            for artifact in artifacts:
                store.verify_disclosure(
                    artifact.blob,
                    artifact_class=artifact.artifact_class,
                    sensitivity=artifact.sensitivity,
                    visibility=artifact.visibility,
                    redistribution=artifact.redistribution,
                )
        except ArtifactStoreError as error:
            raise ArtifactClosureError("artifact closure contains invalid CAS content") from error

        declared_edges = tuple(
            RunArtifactReferenceEdge(
                sequence=event.sequence,
                event_id=event.event_id,
                event_kind=event.kind,
                reference_kind=RunArtifactReferenceKind.DECLARED,
                artifact_ids=event.artifact_refs,
            )
            for event in record.events
            if event.artifact_refs
        )
        candidate_edges = _verify_candidate_snapshots(record, store, artifacts)
        _verify_checkpoint_manifests(record, store, artifacts)
        _verify_provider_artifacts(record, store, artifacts)
        if artifact_store_identity_digest(store, descriptor) != store_identity:
            raise ArtifactClosureError("artifact store identity changed during verification")
        return RunArtifactClosureReceipt(
            run_id=record.header.run_id,
            run_record_digest=record.integrity_digest,
            artifact_policy_digest=store.policy_digest,
            artifact_store_identity_digest=store_identity,
            artifacts=artifacts,
            reference_edges=(*declared_edges, *candidate_edges),
        )
    finally:
        os.close(descriptor)


def artifact_store_identity_digest(
    store: ContentAddressedStore,
    descriptor: int,
) -> Digest:
    """Return an opaque identity for one concrete store and its live root descriptor."""

    if type(store) is not ContentAddressedStore:
        raise TypeError("artifact store identity requires the concrete store")
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(store.root, follow_symlinks=False)
    except OSError as error:
        raise ArtifactClosureError("artifact store identity cannot be inspected") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) & 0o077
        or _stat_identity(opened) != _stat_identity(linked)
    ):
        raise ArtifactClosureError("artifact store root is not a private stable binding")
    identity = hashlib.sha256(b"edagym\x00artifact-store-root-identity-v1\x00")
    identity.update(_stat_identity_bytes(opened))
    root_identity_digest = f"sha256:{identity.hexdigest()}"
    return canonical_digest(
        {
            "metadata": store.metadata,
            "policy_digest": store.policy_digest,
            "root_identity_digest": root_identity_digest,
        },
        domain="runtime-artifact-store-identity-v1",
    )


def _verify_candidate_snapshots(
    record: RunRecord,
    store: ContentAddressedStore,
    artifacts: tuple[ArtifactRecord, ...],
) -> tuple[RunArtifactReferenceEdge, ...]:
    artifact_events = {
        event.payload.record.logical_id: event
        for event in record.events
        if isinstance(event, ArtifactRecordedEvent)
    }
    commit_by_event = {
        event.event_id: commit_index
        for commit_index, commit in enumerate(record.commits)
        for event in commit.events
    }
    edges: list[RunArtifactReferenceEdge] = []
    linked_artifacts: set[Identifier] = set()
    try:
        for event in record.events:
            if not isinstance(event, CandidateSubmittedEvent):
                continue
            logical_id = candidate_snapshot_artifact_id(
                record.header.run_id,
                event.payload.candidate_id,
            )
            artifact_event = artifact_events.get(logical_id)
            if artifact_event is None:
                raise ArtifactClosureError(
                    "candidate submission has no registered snapshot artifact"
                )
            artifact = artifact_event.payload.record
            if (
                commit_by_event[artifact_event.event_id] != commit_by_event[event.event_id]
                or artifact_event.sequence >= event.sequence
                or artifact.artifact_class is not ArtifactClass.CANDIDATE
                or artifact.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE
                or artifact.blob.digest != event.payload.candidate_digest
            ):
                raise ArtifactClosureError(
                    "candidate submission is not atomically bound to its snapshot"
                )
            manifest = store.read_manifest(artifact.blob)
            if (
                manifest.artifact_class is not artifact.artifact_class
                or manifest.sensitivity is not artifact.sensitivity
                or manifest.visibility is not artifact.visibility
                or manifest.redistribution is not artifact.redistribution
            ):
                raise ArtifactClosureError(
                    "candidate snapshot manifest weakens its artifact disclosure"
                )
            linked_artifacts.add(logical_id)
            edges.append(
                RunArtifactReferenceEdge(
                    sequence=event.sequence,
                    event_id=event.event_id,
                    event_kind=event.kind,
                    reference_kind=RunArtifactReferenceKind.CANDIDATE_SNAPSHOT,
                    artifact_ids=(logical_id,),
                )
            )
    except ArtifactStoreError as error:
        raise ArtifactClosureError("candidate snapshot CAS content is invalid") from error

    candidate_artifacts = {
        artifact.logical_id
        for artifact in artifacts
        if artifact.artifact_class is ArtifactClass.CANDIDATE
    }
    if candidate_artifacts != linked_artifacts:
        raise ArtifactClosureError("candidate snapshot artifacts do not match submissions")
    return tuple(edges)


def _verify_checkpoint_manifests(
    record: RunRecord,
    store: ContentAddressedStore,
    artifacts: tuple[ArtifactRecord, ...],
) -> None:
    artifact_events = {
        event.payload.record.logical_id: event
        for event in record.events
        if isinstance(event, ArtifactRecordedEvent)
    }
    commit_by_event = {
        event.event_id: commit_index
        for commit_index, commit in enumerate(record.commits)
        for event in commit.events
    }
    linked_artifacts: set[Identifier] = set()
    try:
        for event in record.events:
            if not isinstance(event, CheckpointCommittedEvent):
                continue
            artifact_id = event.artifact_refs[0]
            artifact_event = artifact_events.get(artifact_id)
            if artifact_event is None:
                raise ArtifactClosureError(
                    "checkpoint has no registered manifest artifact"
                )
            artifact = artifact_event.payload.record
            if (
                commit_by_event[artifact_event.event_id] != commit_by_event[event.event_id]
                or artifact_event.sequence >= event.sequence
                or artifact.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE
                or artifact.artifact_class is not ArtifactClass.CHECKPOINT
            ):
                raise ArtifactClosureError(
                    "checkpoint is not atomically bound to its manifest artifact"
                )
            if event.payload.checkpoint_kind is CheckpointCapability.FILESYSTEM:
                marker, manifest = store.load_filesystem_checkpoint(
                    event.payload.checkpoint_id
                )
            elif event.payload.driver_digest is not None:
                marker, manifest = store.load_application_checkpoint(
                    event.payload.checkpoint_id,
                    driver_digest=event.payload.driver_digest,
                )
            else:
                raise ArtifactClosureError("checkpoint implementation binding is invalid")
            if (
                marker.manifest_blob != artifact.blob
                or marker.manifest_digest != event.payload.manifest_digest
                or manifest.digest != event.payload.manifest_digest
                or manifest.artifact_class is not artifact.artifact_class
                or manifest.sensitivity is not artifact.sensitivity
                or manifest.visibility is not artifact.visibility
                or manifest.redistribution is not artifact.redistribution
            ):
                raise ArtifactClosureError(
                    "checkpoint marker, manifest, and journal evidence disagree"
                )
            linked_artifacts.add(artifact_id)
    except ArtifactStoreError as error:
        raise ArtifactClosureError("checkpoint manifest CAS content is invalid") from error

    checkpoint_artifacts = {
        artifact.logical_id
        for artifact in artifacts
        if artifact.artifact_class is ArtifactClass.CHECKPOINT
    }
    if checkpoint_artifacts != linked_artifacts:
        raise ArtifactClosureError(
            "checkpoint manifest artifacts do not match checkpoint events"
        )


def _verify_provider_artifacts(
    record: RunRecord,
    store: ContentAddressedStore,
    artifacts: tuple[ArtifactRecord, ...],
) -> None:
    artifact_events = {
        event.payload.record.logical_id: event
        for event in record.events
        if isinstance(event, ArtifactRecordedEvent)
    }
    commit_by_event = {
        event.event_id: commit_index
        for commit_index, commit in enumerate(record.commits)
        for event in commit.events
    }
    used_transcripts: set[Identifier] = set()
    used_canary_evidence: set[Identifier] = set()
    decoded_canary_evidence: dict[Identifier, ProviderCanaryEvidence] = {}

    try:
        for event in record.events:
            if isinstance(event, ProviderRequestStartedEvent):
                payload = event.payload
                expected_request_id = provider_transcript_artifact_id(
                    payload.request_id,
                    ProviderTranscriptRole.REQUEST,
                )
                if payload.request_artifact_id != expected_request_id:
                    raise ArtifactClosureError(
                        "provider request artifact identity is not canonical"
                    )
                request_artifact = _verify_atomic_provider_artifact(
                    event=event,
                    artifact_id=expected_request_id,
                    artifact_events=artifact_events,
                    commit_by_event=commit_by_event,
                    media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
                    artifact_class=ArtifactClass.TRAINING,
                    sensitivity=Sensitivity.CONFIDENTIAL,
                    visibility=Visibility.AUTHOR,
                    redistribution=Redistribution.FORBIDDEN,
                )
                verify_provider_transcript_artifact(
                    request_artifact,
                    store,
                    request_id=payload.request_id,
                    role=ProviderTranscriptRole.REQUEST,
                )
                used_transcripts.add(expected_request_id)

                evidence_id = payload.security_evidence_artifact_id
                evidence_event = artifact_events.get(evidence_id)
                if evidence_event is None:
                    raise ArtifactClosureError(
                        "provider request has no registered canary evidence artifact"
                    )
                evidence = decoded_canary_evidence.get(evidence_id)
                if evidence is None:
                    evidence = verify_provider_canary_evidence(
                        evidence_event.payload.record,
                        store,
                    )
                    decoded_canary_evidence[evidence_id] = evidence
                    if (
                        commit_by_event[evidence_event.event_id]
                        != commit_by_event[event.event_id]
                        or evidence_event.sequence >= event.sequence
                    ):
                        raise ArtifactClosureError(
                            "first provider request is not atomically bound to canary evidence"
                        )
                elif evidence_event.sequence >= event.sequence:
                    raise ArtifactClosureError(
                        "provider request precedes its canary evidence registration"
                    )
                if evidence.artifact_id != evidence_id:
                    raise ArtifactClosureError(
                        "provider canary evidence identity is not canonical"
                    )
                _verify_provider_canary_binding(record, event, evidence)
                used_canary_evidence.add(evidence_id)

            elif isinstance(event, ProviderResponseRecordedEvent):
                expected_response_id = provider_transcript_artifact_id(
                    event.payload.request_id,
                    ProviderTranscriptRole.RESPONSE,
                )
                if event.artifact_refs != (expected_response_id,):
                    raise ArtifactClosureError(
                        "provider response artifact identity is not canonical"
                    )
                response_artifact = _verify_atomic_provider_artifact(
                    event=event,
                    artifact_id=expected_response_id,
                    artifact_events=artifact_events,
                    commit_by_event=commit_by_event,
                    media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
                    artifact_class=ArtifactClass.TRAINING,
                    sensitivity=Sensitivity.CONFIDENTIAL,
                    visibility=Visibility.AUTHOR,
                    redistribution=Redistribution.FORBIDDEN,
                )
                verify_provider_transcript_artifact(
                    response_artifact,
                    store,
                    request_id=event.payload.request_id,
                    role=ProviderTranscriptRole.RESPONSE,
                )
                used_transcripts.add(expected_response_id)
    except (
        ArtifactStoreError,
        ProviderCanaryEvidenceError,
        ProviderTranscriptError,
    ) as error:
        raise ArtifactClosureError("provider artifact CAS content is invalid") from error

    recorded_transcripts = {
        artifact.logical_id
        for artifact in artifacts
        if artifact.media_type == PROVIDER_TRANSCRIPT_MEDIA_TYPE
        or artifact.logical_id.startswith("provider_transcript_")
    }
    recorded_canary_evidence = {
        artifact.logical_id
        for artifact in artifacts
        if artifact.media_type == PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE
        or artifact.logical_id.startswith("provider_canary_")
    }
    if recorded_transcripts != used_transcripts:
        raise ArtifactClosureError(
            "provider transcript artifacts do not match provider exchange events"
        )
    if recorded_canary_evidence != used_canary_evidence:
        raise ArtifactClosureError(
            "provider canary artifacts do not match provider request events"
        )


def _verify_atomic_provider_artifact(
    *,
    event: ProviderRequestStartedEvent | ProviderResponseRecordedEvent,
    artifact_id: Identifier,
    artifact_events: dict[Identifier, ArtifactRecordedEvent],
    commit_by_event: dict[UUID, int],
    media_type: str,
    artifact_class: ArtifactClass,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> ArtifactRecord:
    artifact_event = artifact_events.get(artifact_id)
    if artifact_event is None:
        raise ArtifactClosureError("provider exchange has no registered transcript artifact")
    artifact = artifact_event.payload.record
    if (
        commit_by_event[artifact_event.event_id] != commit_by_event[event.event_id]
        or artifact_event.sequence >= event.sequence
        or artifact.media_type != media_type
        or artifact.artifact_class is not artifact_class
        or artifact.sensitivity is not sensitivity
        or artifact.visibility is not visibility
        or artifact.redistribution is not redistribution
    ):
        raise ArtifactClosureError(
            "provider exchange is not atomically bound to its restricted transcript"
        )
    return artifact


def _verify_provider_canary_binding(
    record: RunRecord,
    event: ProviderRequestStartedEvent,
    evidence: ProviderCanaryEvidence,
) -> None:
    campaign = record.header.binding.campaign
    if campaign is None:
        raise ArtifactClosureError(
            "provider canary evidence requires a campaign trial run binding"
        )
    payload = event.payload
    security = payload.security_binding
    manifest = evidence.runtime_surface_manifest
    binding = manifest.binding
    actors = tuple(
        actor
        for actor in record.header.binding.session.actors
        if isinstance(actor, HarnessRunActor) and actor.actor_id == payload.actor_id
    )
    if (
        len(actors) != 1
        or security.canary_receipt_digest != evidence.receipt.digest
        or security.runtime_surface_manifest_digest != manifest.digest
        or security.budget_binding_digest != binding.budget_binding_digest
        or payload.provider_profile_digest != binding.provider_profile_digest
        or payload.provider_config_digest != binding.provider_config_digest
        or binding.campaign_digest != campaign.campaign_digest
        or binding.campaign_schedule_digest != campaign.schedule_digest
        or binding.scheduled_trial_digest != campaign.scheduled_trial_digest
        or binding.task_release_digest != record.header.binding.task.release_digest
        or binding.environment_spec_digest
        != record.header.binding.environment.environment_spec_digest
        or binding.session_spec_digest
        != record.header.binding.session.session_spec_digest
        or binding.executor_digest != record.header.binding.environment.executor_digest
        or binding.harness_digest != actors[0].harness_digest
    ):
        raise ArtifactClosureError(
            "provider canary evidence differs from the paid run binding"
        )


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stat_identity_bytes(metadata: os.stat_result) -> bytes:
    try:
        return b"".join(value.to_bytes(16, byteorder="big") for value in _stat_identity(metadata))
    except OverflowError as error:
        raise ArtifactClosureError("artifact store identity is outside its domain") from error
