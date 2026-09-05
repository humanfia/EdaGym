"""Checkpoint commit ordering across CAS markers and the run journal."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from edagym.evaluation.model import InfrastructureFailureOutcome, StageResult
from edagym.evaluation.promotion import outcome_promotes
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ArtifactIntegrityError,
    ArtifactManifest,
    CheckpointMarker,
    ContentAddressedStore,
    manifest_paths,
    manifest_tree,
    restore_manifest,
)
from edagym.run.journal import EventConflict, RunJournal, active_license_leases
from edagym.run.model import (
    ArtifactRecord,
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    CheckpointCommittedEvent,
    CheckpointCommittedPayload,
    EvaluationCompletedEvent,
    EvaluationCompletedPayload,
    EvaluationStartedEvent,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseLostEvent,
    LicenseLeaseLostPayload,
    ProducerKind,
    RunState,
)
from edagym.specs.common import ArtifactClass, Identifier, Redistribution, Sensitivity, Visibility
from edagym.specs.environment import CheckpointCapability, EnvironmentSpec


class CheckpointConsistencyError(ArtifactIntegrityError):
    """A CAS checkpoint marker and its journal commit disagree."""


class UnsupportedCheckpointCapability(RuntimeError):
    """The built-in runtime cannot create or restore the requested checkpoint kind."""


_TERMINAL_JOB_STATES = frozenset(
    {JobStateKind.COMPLETED, JobStateKind.FAILED, JobStateKind.CANCELLED}
)


def reconcile_interrupted_evaluations(
    *,
    journal: RunJournal,
    timestamp: datetime,
    event_id_factory: Callable[[], UUID],
) -> RunState:
    """Atomically close each evaluation whose controller ownership was lost."""

    events = journal.read_events()
    completed_job_ids = {
        event.payload.job_id for event in events if isinstance(event, EvaluationCompletedEvent)
    }
    unresolved = tuple(
        event
        for event in events
        if isinstance(event, EvaluationStartedEvent)
        and event.payload.job_id not in completed_job_ids
    )
    active_leases = active_license_leases(events)
    state = journal.state()
    for started in unresolved:
        job_states = {job.job_id: job.state for job in state.jobs}
        job_state = job_states[started.payload.job_id]
        acquisition = active_leases.get(started.payload.job_id)
        recovery_events = _interrupted_evaluation_events(
            journal=journal,
            sequence=state.next_sequence,
            started=started,
            job_is_terminal=job_state in _TERMINAL_JOB_STATES,
            acquisition=acquisition,
            timestamp=timestamp,
            event_id_factory=event_id_factory,
        )
        state = journal.append_events(recovery_events)
    return state


def _interrupted_evaluation_events(
    *,
    journal: RunJournal,
    sequence: int,
    started: EvaluationStartedEvent,
    job_is_terminal: bool,
    acquisition: LicenseLeaseAcquiredEvent | None,
    timestamp: datetime,
    event_id_factory: Callable[[], UUID],
) -> tuple[JobStateChangedEvent | LicenseLeaseLostEvent | EvaluationCompletedEvent, ...]:
    recovered: list[JobStateChangedEvent | LicenseLeaseLostEvent | EvaluationCompletedEvent] = []
    if not job_is_terminal:
        recovered.append(
            JobStateChangedEvent(
                run_id=journal.header.run_id,
                sequence=sequence + len(recovered),
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.EXECUTOR,
                visibility=Visibility.VERIFIER,
                payload=JobStateChangedPayload(
                    job_id=started.payload.job_id,
                    state=JobStateKind.FAILED,
                    reason_code="runner_restart",
                ),
            )
        )
    if acquisition is not None:
        recovered.append(
            LicenseLeaseLostEvent(
                run_id=journal.header.run_id,
                sequence=sequence + len(recovered),
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=LicenseLeaseLostPayload(**acquisition.payload.model_dump(mode="python")),
            )
        )
    recovered.append(
        EvaluationCompletedEvent(
            run_id=journal.header.run_id,
            sequence=sequence + len(recovered),
            event_id=event_id_factory(),
            timestamp=timestamp,
            producer=ProducerKind.EVALUATOR,
            visibility=started.visibility,
            payload=EvaluationCompletedPayload(
                candidate_id=started.payload.candidate_id,
                job_id=started.payload.job_id,
                result=StageResult(
                    stage_id=started.payload.stage_id,
                    outcome=InfrastructureFailureOutcome(),
                ),
            ),
        )
    )
    return tuple(recovered)


def require_filesystem_checkpoint(capability: CheckpointCapability) -> None:
    """Fail closed unless the controller can capture a quiescent filesystem tree."""

    if capability is not CheckpointCapability.FILESYSTEM:
        raise UnsupportedCheckpointCapability(
            f"checkpoint capability {capability.value!r} requires a different implementation"
        )


def _require_bound_filesystem_environment(
    journal: RunJournal,
    environment: EnvironmentSpec,
) -> None:
    if environment.digest != journal.header.binding.environment.environment_spec_digest:
        raise CheckpointConsistencyError("checkpoint environment does not match the run binding")
    require_filesystem_checkpoint(environment.checkpoint)


def _require_bound_application_environment(
    journal: RunJournal,
    environment: EnvironmentSpec,
) -> None:
    if environment.digest != journal.header.binding.environment.environment_spec_digest:
        raise CheckpointConsistencyError("checkpoint environment does not match the run binding")
    if (
        environment.checkpoint is not CheckpointCapability.APPLICATION
        or environment.application_checkpoint is None
    ):
        raise UnsupportedCheckpointCapability(
            "application checkpoint requires a bound application driver"
        )


def commit_workspace_checkpoint(
    *,
    store: ContentAddressedStore,
    journal: RunJournal,
    environment: EnvironmentSpec,
    workspace: Path,
    checkpoint_id: Identifier,
    artifact_id: Identifier,
    parent_checkpoint_id: Identifier | None,
    timestamp: datetime,
    artifact_event_id: UUID,
    checkpoint_event_id: UUID,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> tuple[CheckpointMarker, RunState]:
    """Commit a stable filesystem tree and its journal reference in durable order."""

    _require_bound_filesystem_environment(journal, environment)
    manifest = manifest_tree(
        store,
        workspace,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
    )
    return _commit_checkpoint_manifest(
        store=store,
        journal=journal,
        manifest=manifest,
        checkpoint_kind=CheckpointCapability.FILESYSTEM,
        driver_digest=None,
        checkpoint_id=checkpoint_id,
        artifact_id=artifact_id,
        parent_checkpoint_id=parent_checkpoint_id,
        timestamp=timestamp,
        artifact_event_id=artifact_event_id,
        checkpoint_event_id=checkpoint_event_id,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
    )


def commit_application_checkpoint(
    *,
    store: ContentAddressedStore,
    journal: RunJournal,
    environment: EnvironmentSpec,
    workspace: Path,
    checkpoint_id: Identifier,
    artifact_id: Identifier,
    parent_checkpoint_id: Identifier | None,
    timestamp: datetime,
    artifact_event_id: UUID,
    checkpoint_event_id: UUID,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> tuple[CheckpointMarker, RunState]:
    """Commit a driver-bound application database at an admitted stage boundary."""

    _require_bound_application_environment(journal, environment)
    binding = environment.application_checkpoint
    if binding is None:
        raise UnsupportedCheckpointCapability("application checkpoint binding is absent")
    state = journal.state()
    if not state.stage_results:
        raise CheckpointConsistencyError(
            "application checkpoint requires a completed evaluator boundary"
        )
    latest = state.stage_results[-1].result
    if latest.stage_id not in binding.after_stage_ids or not outcome_promotes(latest.outcome):
        raise CheckpointConsistencyError(
            "latest evaluator result is not an application checkpoint boundary"
        )
    manifest = manifest_paths(
        store,
        workspace,
        binding.capture_paths,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
    )
    return _commit_checkpoint_manifest(
        store=store,
        journal=journal,
        manifest=manifest,
        checkpoint_kind=CheckpointCapability.APPLICATION,
        driver_digest=binding.driver_digest,
        checkpoint_id=checkpoint_id,
        artifact_id=artifact_id,
        parent_checkpoint_id=parent_checkpoint_id,
        timestamp=timestamp,
        artifact_event_id=artifact_event_id,
        checkpoint_event_id=checkpoint_event_id,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
    )


def _commit_checkpoint_manifest(
    *,
    store: ContentAddressedStore,
    journal: RunJournal,
    manifest: ArtifactManifest,
    checkpoint_kind: Literal[
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    ],
    driver_digest: str | None,
    checkpoint_id: Identifier,
    artifact_id: Identifier,
    parent_checkpoint_id: Identifier | None,
    timestamp: datetime,
    artifact_event_id: UUID,
    checkpoint_event_id: UUID,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> tuple[CheckpointMarker, RunState]:
    committed = store.put_manifest(manifest)
    if checkpoint_kind is CheckpointCapability.FILESYSTEM:
        marker = store.commit_filesystem_checkpoint(checkpoint_id, committed)
    elif checkpoint_kind is CheckpointCapability.APPLICATION and driver_digest is not None:
        marker = store.commit_application_checkpoint(
            checkpoint_id,
            committed,
            driver_digest=driver_digest,
        )
    else:
        raise UnsupportedCheckpointCapability("checkpoint kind has no commit implementation")
    record = ArtifactRecord(
        logical_id=artifact_id,
        blob=committed.blob,
        media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
    )
    existing_state = _matching_checkpoint_commit(
        journal=journal,
        record=record,
        checkpoint_id=checkpoint_id,
        manifest_digest=marker.manifest_digest,
        parent_checkpoint_id=parent_checkpoint_id,
        timestamp=timestamp,
        artifact_event_id=artifact_event_id,
        checkpoint_event_id=checkpoint_event_id,
        visibility=visibility,
        checkpoint_kind=checkpoint_kind,
        driver_digest=driver_digest,
    )
    if existing_state is not None:
        return marker, existing_state
    try:
        state = journal.transact_events(
            lambda current: _checkpoint_events(
                journal=journal,
                sequence=current.next_sequence,
                record=record,
                checkpoint_id=checkpoint_id,
                manifest_digest=marker.manifest_digest,
                parent_checkpoint_id=parent_checkpoint_id,
                timestamp=timestamp,
                artifact_event_id=artifact_event_id,
                checkpoint_event_id=checkpoint_event_id,
                visibility=visibility,
                checkpoint_kind=checkpoint_kind,
                driver_digest=driver_digest,
            )
        )
    except EventConflict:
        recovered_state = _matching_checkpoint_commit(
            journal=journal,
            record=record,
            checkpoint_id=checkpoint_id,
            manifest_digest=marker.manifest_digest,
            parent_checkpoint_id=parent_checkpoint_id,
            timestamp=timestamp,
            artifact_event_id=artifact_event_id,
            checkpoint_event_id=checkpoint_event_id,
            visibility=visibility,
            checkpoint_kind=checkpoint_kind,
            driver_digest=driver_digest,
        )
        if recovered_state is None:
            raise
        state = recovered_state
    return marker, state


def _checkpoint_events(
    *,
    journal: RunJournal,
    sequence: int,
    record: ArtifactRecord,
    checkpoint_id: Identifier,
    manifest_digest: str,
    parent_checkpoint_id: Identifier | None,
    timestamp: datetime,
    artifact_event_id: UUID,
    checkpoint_event_id: UUID,
    visibility: Visibility,
    checkpoint_kind: Literal[
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    ],
    driver_digest: str | None,
) -> tuple[ArtifactRecordedEvent, CheckpointCommittedEvent]:
    return (
        ArtifactRecordedEvent(
            run_id=journal.header.run_id,
            sequence=sequence,
            event_id=artifact_event_id,
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=visibility,
            payload=ArtifactRecordedPayload(record=record),
        ),
        CheckpointCommittedEvent(
            run_id=journal.header.run_id,
            sequence=sequence + 1,
            event_id=checkpoint_event_id,
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=visibility,
            artifact_refs=(record.logical_id,),
            payload=CheckpointCommittedPayload(
                checkpoint_id=checkpoint_id,
                manifest_digest=manifest_digest,
                parent_checkpoint_id=parent_checkpoint_id,
                checkpoint_kind=checkpoint_kind,
                driver_digest=driver_digest,
            ),
        ),
    )


def _matching_checkpoint_commit(
    *,
    journal: RunJournal,
    record: ArtifactRecord,
    checkpoint_id: Identifier,
    manifest_digest: str,
    parent_checkpoint_id: Identifier | None,
    timestamp: datetime,
    artifact_event_id: UUID,
    checkpoint_event_id: UUID,
    visibility: Visibility,
    checkpoint_kind: Literal[
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    ],
    driver_digest: str | None,
) -> RunState | None:
    events = journal.read_events()
    by_id = {event.event_id: event for event in events}
    artifact_event = by_id.get(artifact_event_id)
    checkpoint_event = by_id.get(checkpoint_event_id)
    if artifact_event is None and checkpoint_event is None:
        return None
    if artifact_event is None or checkpoint_event is None:
        raise CheckpointConsistencyError("checkpoint journal commit is only partially present")
    if checkpoint_event.sequence != artifact_event.sequence + 1:
        raise CheckpointConsistencyError("checkpoint journal events are not adjacent")
    if not journal.events_committed_together((artifact_event.event_id, checkpoint_event.event_id)):
        raise CheckpointConsistencyError(
            "checkpoint journal events do not share one durable commit"
        )
    expected = _checkpoint_events(
        journal=journal,
        sequence=artifact_event.sequence,
        record=record,
        checkpoint_id=checkpoint_id,
        manifest_digest=manifest_digest,
        parent_checkpoint_id=parent_checkpoint_id,
        timestamp=timestamp,
        artifact_event_id=artifact_event_id,
        checkpoint_event_id=checkpoint_event_id,
        visibility=visibility,
        checkpoint_kind=checkpoint_kind,
        driver_digest=driver_digest,
    )
    if artifact_event != expected[0] or checkpoint_event != expected[1]:
        raise CheckpointConsistencyError("checkpoint event identity owns different content")
    return journal.state()


def restore_workspace_checkpoint(
    *,
    store: ContentAddressedStore,
    journal: RunJournal,
    environment: EnvironmentSpec,
    checkpoint_id: Identifier,
    destination: Path,
) -> CheckpointMarker:
    """Restore only a checkpoint committed by both the CAS and this run journal."""

    _require_bound_filesystem_environment(journal, environment)
    return _restore_checkpoint(
        store=store,
        journal=journal,
        checkpoint_id=checkpoint_id,
        destination=destination,
        checkpoint_kind=CheckpointCapability.FILESYSTEM,
        driver_digest=None,
    )


def restore_application_checkpoint(
    *,
    store: ContentAddressedStore,
    journal: RunJournal,
    environment: EnvironmentSpec,
    checkpoint_id: Identifier,
    destination: Path,
) -> CheckpointMarker:
    """Restore only a database committed by the environment's bound driver."""

    _require_bound_application_environment(journal, environment)
    binding = environment.application_checkpoint
    if binding is None:
        raise UnsupportedCheckpointCapability("application checkpoint binding is absent")
    return _restore_checkpoint(
        store=store,
        journal=journal,
        checkpoint_id=checkpoint_id,
        destination=destination,
        checkpoint_kind=CheckpointCapability.APPLICATION,
        driver_digest=binding.driver_digest,
    )


def _restore_checkpoint(
    *,
    store: ContentAddressedStore,
    journal: RunJournal,
    checkpoint_id: Identifier,
    destination: Path,
    checkpoint_kind: Literal[
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    ],
    driver_digest: str | None,
) -> CheckpointMarker:
    events = journal.read_events()
    commits = [
        event
        for event in events
        if isinstance(event, CheckpointCommittedEvent)
        and event.payload.checkpoint_id == checkpoint_id
    ]
    if len(commits) != 1:
        raise CheckpointConsistencyError(
            "checkpoint does not have exactly one durable journal commit"
        )
    commit = commits[0]
    if (
        commit.payload.checkpoint_kind is not checkpoint_kind
        or commit.payload.driver_digest != driver_digest
    ):
        raise CheckpointConsistencyError(
            "checkpoint event differs from the requested recovery implementation"
        )
    artifact_id = commit.artifact_refs[0]
    record_events = [
        event
        for event in events
        if isinstance(event, ArtifactRecordedEvent)
        and event.payload.record.logical_id == artifact_id
    ]
    if len(record_events) != 1:
        raise CheckpointConsistencyError(
            "checkpoint manifest does not have exactly one artifact registration"
        )
    record_event = record_events[0]
    if not journal.events_committed_together((record_event.event_id, commit.event_id)):
        raise CheckpointConsistencyError(
            "checkpoint registration and reference do not share one durable commit"
        )
    record = record_event.payload.record
    if checkpoint_kind is CheckpointCapability.FILESYSTEM:
        marker, manifest = store.load_filesystem_checkpoint(checkpoint_id)
    elif checkpoint_kind is CheckpointCapability.APPLICATION and driver_digest is not None:
        marker, manifest = store.load_application_checkpoint(
            checkpoint_id,
            driver_digest=driver_digest,
        )
    else:
        raise UnsupportedCheckpointCapability("checkpoint kind has no restore implementation")
    if (
        marker.manifest_blob != record.blob
        or record.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE
        or record.artifact_class is not ArtifactClass.CHECKPOINT
        or record.sensitivity is not manifest.sensitivity
        or record.visibility is not manifest.visibility
        or record.redistribution is not manifest.redistribution
    ):
        raise CheckpointConsistencyError(
            "checkpoint marker, manifest, and journal registration disagree"
        )
    restore_manifest(store, manifest, destination)
    return marker
