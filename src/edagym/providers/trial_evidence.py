"""Content-verified evidence and resource projection for campaign trial runs."""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime
from typing import Self

from pydantic import model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.model import ExecutionFailureKind
from edagym.executors.model import JobStateKind as ExecutorJobStateKind
from edagym.participants.workspace import ToolObservationOutcome
from edagym.providers.campaign_budget import CampaignResources
from edagym.providers.campaign_runner import TrialRunOutcome
from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
    BlobRef,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ContentAddressedStore,
)
from edagym.run.trial_journal import participant_tool_dispatches, participant_tool_usage, replay
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    CandidateSubmittedEvent,
    ControlTransferredEvent,
    InteractionDirection,
    InteractionRecordedEvent,
    JobStateChangedEvent,
    JobStateKind,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseLostEvent,
    LicenseLeaseReleasedEvent,
    ParticipantToolSettledEvent,
    ProducerKind,
    ProviderRequestStartedEvent,
    RunBinding,
    RunEndedEvent,
    RunEvent,
    RunRecord,
    RunState,
)
from edagym.security.artifact_closure import (
    RunArtifactClosureReceipt,
    verify_run_artifact_closure,
)
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    SchemaVersion,
    StrictModel,
)
from edagym.specs.task import TaskSpec

TOOL_EXECUTION_MEDIA_TYPE = "application/vnd.edagym.participant-tool-execution+json"
TERMINAL_EXECUTOR_STATES = frozenset(
    {
        ExecutorJobStateKind.COMPLETED,
        ExecutorJobStateKind.FAILED,
        ExecutorJobStateKind.CANCELLED,
        ExecutorJobStateKind.TIMED_OUT,
        ExecutorJobStateKind.LOST,
    }
)
_TERMINAL_RUN_JOB_STATES = frozenset(
    {JobStateKind.COMPLETED, JobStateKind.FAILED, JobStateKind.CANCELLED}
)


class ParticipantToolExecutionEvidence(StrictModel):
    """Secret-free execution facts linked to one journaled participant tool call."""

    schema_version: SchemaVersion = 1
    run_id: Digest
    request_interaction_id: Identifier
    invocation_digest: Digest
    input_manifest_digest: Digest
    operation_id: Identifier
    operation_digest: Digest
    tool_id: Identifier
    capability: Capability
    executor_id: Identifier
    outcome: ToolObservationOutcome
    executor_state: ExecutorJobStateKind | None = None
    failure: ExecutionFailureKind | None = None
    exit_code: int | None = None
    elapsed_milliseconds: JcsNonNegativeInt
    license_milliseconds: JcsNonNegativeInt
    stdout_artifact_id: Identifier | None = None
    stderr_artifact_id: Identifier | None = None
    output_artifact_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def validate_terminal_facts(self) -> ParticipantToolExecutionEvidence:
        has_streams = self.stdout_artifact_id is not None or self.stderr_artifact_id is not None
        if (self.stdout_artifact_id is None) != (self.stderr_artifact_id is None):
            raise ValueError("tool execution streams must be recorded together")
        if len(self.output_artifact_ids) != len(set(self.output_artifact_ids)):
            raise ValueError("tool execution output artifacts must be unique")
        if self.executor_state is None:
            if (
                has_streams
                or self.output_artifact_ids
                or self.failure is not None
                or self.exit_code is not None
            ):
                raise ValueError("an unlaunched tool cannot carry executor result facts")
            if self.outcome not in {
                ToolObservationOutcome.LICENSE_UNAVAILABLE,
                ToolObservationOutcome.INFRASTRUCTURE_FAILURE,
                ToolObservationOutcome.SECURITY_VIOLATION,
                ToolObservationOutcome.TIMEOUT,
            }:
                raise ValueError("an unlaunched tool requires a pre-execution failure")
        elif self.executor_state not in TERMINAL_EXECUTOR_STATES or not has_streams:
            raise ValueError("launched tool evidence requires a collected terminal result")
        if self.outcome is ToolObservationOutcome.PASSED and (
            self.executor_state is not ExecutorJobStateKind.COMPLETED
            or self.exit_code != 0
            or self.failure is not None
        ):
            raise ValueError("passed tool evidence requires a successful executor result")
        if self.license_milliseconds > self.elapsed_milliseconds:
            raise ValueError("license duration cannot exceed tool dispatch duration")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="participant-tool-execution-v1")


class CampaignTrialRunEvidence(StrictModel):
    """CAS-verified work and operation evidence projected from one terminal run."""

    schema_version: SchemaVersion = 1
    run_id: Digest
    run_record_digest: Digest
    run_binding: RunBinding
    run_state: RunState
    artifact_closure: RunArtifactClosureReceipt
    resources: CampaignResources
    participant_tool_executions: tuple[ParticipantToolExecutionEvidence, ...]

    @model_validator(mode="after")
    def validate_source_identity(self) -> Self:
        if (
            self.artifact_closure.run_id != self.run_id
            or self.artifact_closure.run_record_digest != self.run_record_digest
            or self.run_binding.digest != self.run_id
            or self.run_state.run_id != self.run_id
            or any(
                evidence.run_id != self.run_id
                for evidence in self.participant_tool_executions
            )
        ):
            raise ValueError("campaign trial evidence has inconsistent run identity")
        interaction_ids = tuple(
            evidence.request_interaction_id for evidence in self.participant_tool_executions
        )
        if len(interaction_ids) != len(set(interaction_ids)):
            raise ValueError("campaign trial evidence repeats a participant tool request")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="campaign-trial-run-evidence-v1")


class CampaignTrialResult(StrictModel):
    """Digest receipt joining one terminal run to its atomic campaign commit."""

    trial_id: Identifier
    run_id: Digest
    run_record_digest: Digest
    campaign_record_digest: Digest
    resources: CampaignResources
    outcome: TrialRunOutcome

    @model_validator(mode="after")
    def validate_run_identity(self) -> CampaignTrialResult:
        if self.outcome.run_id != self.run_id:
            raise ValueError("campaign trial receipt has inconsistent run identity")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="campaign-trial-result-v1")


def project_campaign_trial_run_evidence(
    record: RunRecord,
    task: TaskSpec,
    store: ContentAddressedStore,
) -> CampaignTrialRunEvidence:
    """Replay one terminal run and verify every resource and tool fact against its CAS."""

    if type(record) is not RunRecord:
        raise TypeError("campaign trial projection requires a concrete RunRecord")
    if type(task) is not TaskSpec:
        raise TypeError("campaign trial projection requires a concrete TaskSpec")
    if type(store) is not ContentAddressedStore:
        raise TypeError("campaign trial projection requires the concrete artifact store")
    closure = verify_run_artifact_closure(record, task, store)
    events = record.events
    state = replay(record.header, task, events)
    if not events or state.terminal_reason is None or not isinstance(events[-1], RunEndedEvent):
        raise ValueError("campaign trial projection requires a terminal run record")
    tool_executions = _participant_tool_executions(
        events,
        record=record,
        state=state,
        store=store,
    )
    return CampaignTrialRunEvidence(
        run_id=record.header.run_id,
        run_record_digest=record.integrity_digest,
        run_binding=record.header.binding,
        run_state=state,
        artifact_closure=closure,
        resources=_campaign_resources(events, state, store),
        participant_tool_executions=tool_executions,
    )


def _campaign_resources(
    events: Sequence[RunEvent],
    state: RunState,
    store: ContentAddressedStore,
) -> CampaignResources:
    wall_seconds = _ceiling_seconds(events[0].timestamp, events[-1].timestamp)
    tool_requests = tuple(
        event
        for event in events
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_REQUEST
    )
    action_events = tuple(
        event
        for event in events
        if isinstance(event, (CandidateSubmittedEvent, ControlTransferredEvent))
        or (
            isinstance(event, InteractionRecordedEvent)
            and event.payload.direction is InteractionDirection.PARTICIPANT_OUTPUT
        )
        or (isinstance(event, RunEndedEvent) and event.producer is ProducerKind.PARTICIPANT)
    )
    turns = len(action_events)
    last_action_sequence = max((event.sequence for event in action_events), default=-1)
    if (
        any(
            isinstance(event, ProviderRequestStartedEvent) and event.sequence > last_action_sequence
            for event in events
        )
        and events[-1].producer is not ProducerKind.PARTICIPANT
    ):
        turns += 1
    tool_usage = participant_tool_usage(events)
    return CampaignResources(
        turns=turns,
        tool_calls=len(tool_requests),
        wall_seconds=wall_seconds,
        eda_compute_seconds=math.ceil(
            (evaluator_elapsed_milliseconds(events) + tool_usage.eda_compute_milliseconds)
            / 1000
        ),
        license_seconds=math.ceil(
            (evaluator_license_milliseconds(events) + tool_usage.license_milliseconds)
            / 1000
        ),
        artifact_bytes=_artifact_bytes(state.artifacts, store),
    )


def _participant_tool_executions(
    events: Sequence[RunEvent],
    *,
    record: RunRecord,
    state: RunState,
    store: ContentAddressedStore,
) -> tuple[ParticipantToolExecutionEvidence, ...]:
    dispatches = participant_tool_dispatches(events)
    settlements = {
        request_id: dispatch.terminal
        for request_id, dispatch in dispatches.items()
        if isinstance(dispatch.terminal, ParticipantToolSettledEvent)
    }
    records = {
        event.payload.record.logical_id: event.payload.record
        for event in events
        if isinstance(event, ArtifactRecordedEvent)
        and event.payload.record.media_type == TOOL_EXECUTION_MEDIA_TYPE
    }
    expected_records = {
        settlement.payload.evidence_artifact_id for settlement in settlements.values()
    }
    if set(records) != expected_records:
        raise ValueError("participant tool evidence does not match settled dispatches")
    state_records = {artifact.logical_id: artifact for artifact in state.artifacts}
    operations = {
        item.operation_id: item
        for item in record.header.binding.environment.participant_operations
    }
    evidence: list[ParticipantToolExecutionEvidence] = []
    for request_id, settlement in settlements.items():
        if settlement is None:
            raise AssertionError("settled dispatch projection lost its terminal event")
        reservation = dispatches[request_id].reservation.payload
        artifact = records[settlement.payload.evidence_artifact_id]
        if artifact.artifact_class is not ArtifactClass.EVIDENCE:
            raise ValueError("participant tool evidence has the wrong artifact class")
        content = store.read_bytes(artifact.blob, maximum_bytes=artifact.blob.size_bytes)
        item = ParticipantToolExecutionEvidence.model_validate_json(content)
        if canonical_bytes(item) != content:
            raise ValueError("participant tool evidence is not canonical")
        if (
            item.run_id != record.header.run_id
            or item.request_interaction_id != request_id
            or item.invocation_digest != reservation.invocation_digest
            or item.operation_id != reservation.operation_id
            or item.operation_digest != reservation.operation_digest
            or item.input_manifest_digest != reservation.input_manifest_digest
            or item.operation_id not in operations
            or operations[item.operation_id].operation_digest != item.operation_digest
            or operations[item.operation_id].tool_id != item.tool_id
            or operations[item.operation_id].capability is not item.capability
            or item.tool_id != reservation.tool_id
            or item.capability is not reservation.capability
            or item.executor_id != reservation.executor_id
            or item.elapsed_milliseconds != settlement.payload.elapsed_milliseconds
            or item.license_milliseconds != settlement.payload.license_milliseconds
        ):
            raise ValueError("participant tool evidence differs from its settled dispatch")
        stream_ids = (item.stdout_artifact_id, item.stderr_artifact_id)
        if item.executor_state is not None and any(
            stream_id is None
            or stream_id not in state_records
            or state_records[stream_id].artifact_class is not ArtifactClass.DIAGNOSTIC
            for stream_id in stream_ids
        ):
            raise ValueError("participant tool evidence streams are not registered diagnostics")
        if any(
            artifact_id not in state_records
            or state_records[artifact_id].artifact_class
            not in {ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE}
            for artifact_id in item.output_artifact_ids
        ):
            raise ValueError("participant tool outputs are not registered operation artifacts")
        evidence.append(item)
    return tuple(sorted(evidence, key=lambda item: item.request_interaction_id))


def evaluator_elapsed_milliseconds(events: Sequence[RunEvent]) -> int:
    running: dict[str, datetime] = {}
    terminal: dict[str, datetime] = {}
    for event in events:
        if not isinstance(event, JobStateChangedEvent):
            continue
        if event.payload.state is JobStateKind.RUNNING:
            running.setdefault(event.payload.job_id, event.timestamp)
        elif event.payload.state in _TERMINAL_RUN_JOB_STATES:
            terminal[event.payload.job_id] = event.timestamp
    if set(running) != set(terminal):
        raise ValueError("terminal run has an incomplete evaluator duration")
    return sum(
        _datetime_milliseconds(started, terminal[job_id])
        for job_id, started in running.items()
    )


def evaluator_license_milliseconds(events: Sequence[RunEvent]) -> int:
    participant_invocations = {
        dispatch.reservation.payload.invocation_id
        for dispatch in participant_tool_dispatches(events).values()
    }
    active: dict[str, datetime] = {}
    elapsed = 0
    for event in events:
        if isinstance(event, LicenseLeaseAcquiredEvent):
            if event.payload.job_id in participant_invocations:
                continue
            active[event.payload.job_id] = event.timestamp
        elif isinstance(event, LicenseLeaseReleasedEvent | LicenseLeaseLostEvent):
            if event.payload.job_id in participant_invocations:
                continue
            started = active.pop(event.payload.job_id, None)
            if started is None:
                raise ValueError("license release has no acquisition")
            elapsed += _datetime_milliseconds(started, event.timestamp)
    if active:
        raise ValueError("terminal run has an unreleased evaluator license")
    return elapsed


def _artifact_bytes(
    records: Sequence[ArtifactRecord],
    store: ContentAddressedStore,
) -> int:
    blobs: dict[str, int] = {}

    def account(blob: BlobRef) -> None:
        prior = blobs.setdefault(blob.digest, blob.size_bytes)
        if prior != blob.size_bytes:
            raise ValueError("one artifact digest has inconsistent byte lengths")
        store.verify(blob)

    for record in records:
        account(record.blob)
        store.verify_disclosure(
            record.blob,
            artifact_class=record.artifact_class,
            sensitivity=record.sensitivity,
            visibility=record.visibility,
            redistribution=record.redistribution,
        )
    for record in records:
        if record.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE:
            continue
        content = store.read_bytes(record.blob, maximum_bytes=record.blob.size_bytes)
        manifest = ArtifactManifest.model_validate_json(content)
        if (
            canonical_bytes(manifest) != content
            or manifest.artifact_class is not record.artifact_class
            or manifest.sensitivity is not record.sensitivity
            or manifest.visibility is not record.visibility
            or manifest.redistribution is not record.redistribution
        ):
            raise ValueError("artifact manifest disagrees with its registration")
        for entry in manifest.entries:
            account(entry.blob)
    return sum(blobs.values())


def _ceiling_seconds(started: datetime, finished: datetime) -> int:
    return math.ceil(max(0.0, (finished - started).total_seconds()))


def _datetime_milliseconds(started: datetime, finished: datetime) -> int:
    return math.ceil(max(0.0, (finished - started).total_seconds()) * 1000)
