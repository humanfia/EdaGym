"""Budget accounting derived from immutable run events and artifact manifests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ContentAddressedStore,
)
from edagym.run.trial_journal import (
    TrialJournal,
    participant_tool_dispatches,
    participant_tool_usage,
    replay,
)
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    EvaluationStartedEvent,
    JobStateChangedEvent,
    JobStateKind,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseLostEvent,
    LicenseLeaseReleasedEvent,
    ProducerKind,
    StopReason,
)
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.session import SessionSpec
from edagym.specs.task import TaskSpec

_RUN_TERMINAL_STATES = frozenset(
    {JobStateKind.COMPLETED, JobStateKind.FAILED, JobStateKind.CANCELLED}
)


class RuntimeActionKind(StrEnum):
    PARTICIPANT = "participant"
    EVALUATION = "evaluation"


class RuntimeBudgetError(RuntimeError):
    """Run evidence cannot be accounted against its frozen budget."""


@dataclass(frozen=True, slots=True)
class RuntimeBudgetUsage:
    participant_turns: int
    provider_requests: int
    provider_input_tokens: int
    provider_output_tokens: int
    tool_calls: int
    experiments: int
    wall_seconds: float
    eda_compute_seconds: float
    license_seconds: float
    artifact_bytes: int


def budget_stop(
    action: RuntimeActionKind,
    *,
    journal: TrialJournal,
    task: TaskSpec,
    environment: EnvironmentSpec,
    session: SessionSpec,
    artifact_store: ContentAddressedStore,
    now: datetime,
    candidate_id: str | None = None,
) -> StopReason | None:
    """Project the first exhausted budget applicable to one pending action."""

    usage = budget_usage(
        journal=journal,
        task=task,
        artifact_store=artifact_store,
        now=now,
    )
    resources = session.resources
    if usage.artifact_bytes >= resources.max_artifact_bytes:
        return StopReason.STORAGE_BUDGET
    if usage.wall_seconds >= resources.max_wall_seconds:
        return StopReason.WALL_BUDGET
    if usage.eda_compute_seconds >= resources.max_eda_compute_seconds:
        return StopReason.EDA_COMPUTE_BUDGET
    if usage.license_seconds >= resources.max_license_seconds and environment.licenses:
        return StopReason.LICENSE_BUDGET
    if action is RuntimeActionKind.PARTICIPANT:
        if usage.participant_turns >= resources.max_turns:
            return StopReason.INTERACTION_BUDGET
        model_budget = session.model_budget
        if model_budget is not None and (
            usage.provider_requests >= model_budget.max_requests
            or usage.provider_input_tokens >= model_budget.max_total_input_tokens
            or usage.provider_output_tokens >= model_budget.max_total_output_tokens
            or usage.provider_input_tokens + usage.provider_output_tokens
            >= model_budget.max_total_tokens
        ):
            return StopReason.TOKEN_BUDGET
    if action is RuntimeActionKind.EVALUATION:
        if usage.tool_calls >= resources.max_tool_calls:
            return StopReason.TOOL_CALL_BUDGET
        evaluated = {
            event.payload.candidate_id
            for event in journal.read_events()
            if isinstance(event, EvaluationStartedEvent)
        }
        if (
            candidate_id is not None
            and candidate_id not in evaluated
            and usage.experiments >= resources.max_experiments
        ):
            return StopReason.EXPERIMENT_BUDGET
    return None


def active_runtime_stop(
    *,
    journal: TrialJournal,
    task: TaskSpec,
    environment: EnvironmentSpec,
    session: SessionSpec,
    artifact_store: ContentAddressedStore,
    now: datetime,
) -> StopReason | None:
    """Project only budgets that can terminate an already running invocation."""

    usage = budget_usage(
        journal=journal,
        task=task,
        artifact_store=artifact_store,
        now=now,
    )
    resources = session.resources
    if usage.wall_seconds >= resources.max_wall_seconds:
        return StopReason.WALL_BUDGET
    if usage.eda_compute_seconds >= resources.max_eda_compute_seconds:
        return StopReason.EDA_COMPUTE_BUDGET
    if usage.license_seconds >= resources.max_license_seconds and environment.licenses:
        return StopReason.LICENSE_BUDGET
    return None


def budget_usage(
    *,
    journal: TrialJournal,
    task: TaskSpec,
    artifact_store: ContentAddressedStore,
    now: datetime,
) -> RuntimeBudgetUsage:
    """Derive current usage solely from the journal and verified CAS closure."""

    events = journal.read_events()
    if not events:
        raise RuntimeBudgetError("budget usage requires a started run")
    state = replay(journal.header, task, events)
    starts = {
        event.payload.job_id: event
        for event in events
        if isinstance(event, EvaluationStartedEvent)
    }
    running: dict[str, datetime] = {}
    terminal: dict[str, datetime] = {}
    for event in events:
        if not isinstance(event, JobStateChangedEvent):
            continue
        if event.payload.state is JobStateKind.RUNNING:
            running.setdefault(event.payload.job_id, event.timestamp)
        if event.payload.state in _RUN_TERMINAL_STATES:
            terminal[event.payload.job_id] = event.timestamp
    eda_seconds = sum(
        max(0.0, (terminal.get(job_id, now) - started_at).total_seconds())
        for job_id, started_at in running.items()
    )
    participant_invocation_ids = {
        dispatch.reservation.payload.invocation_id
        for dispatch in participant_tool_dispatches(events).values()
    }
    active_license_leases: dict[str, datetime] = {}
    license_seconds = 0.0
    for event in events:
        if isinstance(event, LicenseLeaseAcquiredEvent):
            if event.payload.job_id not in participant_invocation_ids:
                active_license_leases[event.payload.job_id] = event.timestamp
        elif (
            isinstance(event, LicenseLeaseReleasedEvent | LicenseLeaseLostEvent)
            and event.payload.job_id not in participant_invocation_ids
        ):
            acquired_at = active_license_leases.pop(event.payload.job_id)
            license_seconds += max(
                0.0,
                (event.timestamp - acquired_at).total_seconds(),
            )
    license_seconds += sum(
        max(0.0, (now - acquired_at).total_seconds())
        for acquired_at in active_license_leases.values()
    )
    participant_usage = participant_tool_usage(events)
    eda_seconds += participant_usage.eda_compute_milliseconds / 1000
    license_seconds += participant_usage.license_milliseconds / 1000
    evaluated_candidates = {
        event.payload.candidate_id
        for event in events
        if isinstance(event, EvaluationStartedEvent)
    }
    artifacts = {
        event.payload.record.logical_id: event.payload.record
        for event in events
        if isinstance(event, ArtifactRecordedEvent)
    }
    provider_input_tokens = sum(
        request.usage.input_tokens
        if request.usage is not None
        else request.reserved_input_tokens
        for request in state.provider_requests
    )
    provider_output_tokens = sum(
        request.usage.output_tokens
        if request.usage is not None
        else request.reserved_output_tokens
        for request in state.provider_requests
    )
    return RuntimeBudgetUsage(
        participant_turns=sum(event.producer is ProducerKind.PARTICIPANT for event in events),
        provider_requests=len(state.provider_requests),
        provider_input_tokens=provider_input_tokens,
        provider_output_tokens=provider_output_tokens,
        tool_calls=len(starts),
        experiments=len(evaluated_candidates),
        wall_seconds=max(0.0, (now - events[0].timestamp).total_seconds()),
        eda_compute_seconds=eda_seconds,
        license_seconds=license_seconds,
        artifact_bytes=_artifact_bytes(tuple(artifacts.values()), artifact_store),
    )


def _artifact_bytes(
    records: tuple[ArtifactRecord, ...],
    artifact_store: ContentAddressedStore,
) -> int:
    blobs = {record.blob.digest: record.blob.size_bytes for record in records}
    for record in records:
        if record.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE:
            continue
        try:
            manifest = ArtifactManifest.model_validate_json(
                artifact_store.read_bytes(
                    record.blob,
                    maximum_bytes=record.blob.size_bytes,
                )
            )
            if (
                manifest.artifact_class is not record.artifact_class
                or manifest.sensitivity is not record.sensitivity
                or manifest.visibility is not record.visibility
                or manifest.redistribution is not record.redistribution
            ):
                raise RuntimeBudgetError(
                    "artifact registration does not match its manifest"
                )
        except Exception as error:
            raise RuntimeBudgetError(
                "artifact manifest cannot be accounted against its budget"
            ) from error
        for entry in manifest.entries:
            blobs.setdefault(entry.blob.digest, entry.blob.size_bytes)
    return sum(blobs.values())
