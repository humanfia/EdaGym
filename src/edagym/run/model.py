"""Typed commands and facts for manifest-bound interactive runs."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, TypeAdapter, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.evaluation.model import OutcomeKind
from edagym.executors.model import ExecutionResult, InvocationPlan, JobHandle
from edagym.run.artifact_model import CommittedManifest
from edagym.run.journal_storage import JournalCommit
from edagym.run.manifest import RunManifest
from edagym.specs.common import Digest, Identifier, StrictModel, Visibility, validate_relative_path


class EnginePhase(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    TERMINAL = "terminal"
    UNAVAILABLE = "unavailable"


class OperationPhase(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    TERMINAL = "terminal"


class IntentKind(StrEnum):
    EDIT = "edit"
    TOOL = "tool"
    SUBMIT = "submit"
    TRANSFER_CONTROL = "transfer_control"
    CHECKPOINT = "checkpoint"
    CANCEL = "cancel"


class EventKind(StrEnum):
    RUN_PREPARED = "run_prepared"
    RUN_STARTED = "run_started"
    RUN_UNAVAILABLE = "run_unavailable"
    CONTROL_TRANSFERRED = "control_transferred"
    WORKSPACE_COMMITTED = "workspace_committed"
    CHECKPOINT_COMMITTED = "checkpoint_committed"
    CANDIDATE_SUBMITTED = "candidate_submitted"
    OPERATION_PREPARED = "operation_prepared"
    OPERATION_RUNNING = "operation_running"
    OPERATION_TERMINAL = "operation_terminal"
    EVALUATION_COMPLETED = "evaluation_completed"
    QUALIFICATION_COMPLETED = "qualification_completed"
    RUN_CANCELLED = "run_cancelled"
    CANCEL_REQUESTED = "cancel_requested"
    RUN_COMPLETED = "run_completed"


class Principal(StrictModel):
    principal_id: Identifier
    allowed_run_ids: tuple[Identifier, ...] = ()
    allowed_visibilities: tuple[Visibility, ...] = (Visibility.PUBLIC, Visibility.PARTICIPANT)

    @field_validator("allowed_run_ids", "allowed_visibilities")
    @classmethod
    def normalize_grants(cls, value: tuple[Any, ...]) -> tuple[Any, ...]:
        if len(value) != len(set(value)):
            raise ValueError("principal grants must be unique")
        return tuple(sorted(value))


class EventCursor(StrictModel):
    sequence: int = Field(strict=True, ge=0)


class EditPayload(StrictModel):
    path: str
    content: str = Field(max_length=128 * 1024)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_relative_path(value)


class ToolPayload(StrictModel):
    tool_id: Identifier
    arguments: tuple[str, ...] = Field(default=(), max_length=4096)
    working_directory: str = "."

    @field_validator("working_directory")
    @classmethod
    def validate_directory(cls, value: str) -> str:
        return value if value == "." else validate_relative_path(value)

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(len(arg) > 16_384 or any(c in arg for c in "\x00\n\r") for arg in value):
            raise ValueError("tool arguments exceed the command boundary")
        return value


class SubmitPayload(StrictModel):
    candidate_id: Identifier


class TransferPayload(StrictModel):
    next_writer: Identifier


class CheckpointPayload(StrictModel):
    checkpoint_id: Identifier


class CancelPayload(StrictModel):
    pass


IntentPayload = (
    EditPayload | ToolPayload | SubmitPayload | TransferPayload | CheckpointPayload | CancelPayload
)
_INTENT_PAYLOADS: dict[IntentKind, type[StrictModel]] = {
    IntentKind.EDIT: EditPayload,
    IntentKind.TOOL: ToolPayload,
    IntentKind.SUBMIT: SubmitPayload,
    IntentKind.TRANSFER_CONTROL: TransferPayload,
    IntentKind.CHECKPOINT: CheckpointPayload,
    IntentKind.CANCEL: CancelPayload,
}


class InteractionIntent(StrictModel):
    intent_id: Identifier
    idempotency_key: Identifier
    actor_id: Identifier
    kind: IntentKind
    payload: IntentPayload = Field(default_factory=CancelPayload)

    @model_validator(mode="before")
    @classmethod
    def parse_payload(cls, value: Any) -> Any:
        if isinstance(value, dict) and "kind" in value:
            value = dict(value)
            kind = IntentKind(value["kind"])
            value["payload"] = _INTENT_PAYLOADS[kind].model_validate(value.get("payload", {}))
        return value

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if type(self.payload) is not _INTENT_PAYLOADS[self.kind]:
            raise ValueError("intent payload does not match its action")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            self.model_dump(exclude={"intent_id", "idempotency_key"}),
            domain="runtime-interaction-intent-v1",
        )


class IntentReceipt(StrictModel):
    intent_id: Identifier
    idempotency_key: Identifier
    intent_digest: Digest


class EventBase(StrictModel):
    sequence: int = Field(strict=True, ge=0)
    event_id: Identifier
    run_id: Identifier
    actor_id: Identifier | None = None
    visibility: Visibility = Visibility.PARTICIPANT
    intent: IntentReceipt | None = None
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("run event timestamps must be timezone-aware")
        return value.astimezone(UTC)


class PreparedPayload(StrictModel):
    manifest_digest: Digest


class ReasonPayload(StrictModel):
    reason: Identifier


class WorkspacePayload(StrictModel):
    workspace: CommittedManifest


class CheckpointCommittedPayload(WorkspacePayload):
    checkpoint_id: Identifier


class CandidatePayload(StrictModel):
    candidate_id: Identifier
    submission: CommittedManifest


class OperationPreparedPayload(StrictModel):
    plan: InvocationPlan
    input_manifest: CommittedManifest
    parent_id: Identifier | None = None


class OperationRunningPayload(StrictModel):
    operation_id: Identifier
    handle: JobHandle


class OperationTerminalPayload(StrictModel):
    operation_id: Identifier
    result: ExecutionResult
    workspace: CommittedManifest | None = None


class EvaluationPayload(StrictModel):
    candidate_id: Identifier
    outcome: OutcomeKind
    runnable: bool
    operation_ids: tuple[Identifier, ...] = Field(min_length=1)


class QualificationCompletedPayload(StrictModel):
    instance_id: Identifier
    evidence_digest: Digest


class RunPreparedEvent(EventBase):
    kind: Literal[EventKind.RUN_PREPARED] = EventKind.RUN_PREPARED
    payload: PreparedPayload


class RunStartedEvent(EventBase):
    kind: Literal[EventKind.RUN_STARTED] = EventKind.RUN_STARTED
    payload: WorkspacePayload


class RunUnavailableEvent(EventBase):
    kind: Literal[EventKind.RUN_UNAVAILABLE] = EventKind.RUN_UNAVAILABLE
    payload: ReasonPayload


class ControlTransferredEvent(EventBase):
    kind: Literal[EventKind.CONTROL_TRANSFERRED] = EventKind.CONTROL_TRANSFERRED
    payload: TransferPayload


class WorkspaceCommittedEvent(EventBase):
    kind: Literal[EventKind.WORKSPACE_COMMITTED] = EventKind.WORKSPACE_COMMITTED
    payload: WorkspacePayload


class CheckpointCommittedEvent(EventBase):
    kind: Literal[EventKind.CHECKPOINT_COMMITTED] = EventKind.CHECKPOINT_COMMITTED
    payload: CheckpointCommittedPayload


class CandidateSubmittedEvent(EventBase):
    kind: Literal[EventKind.CANDIDATE_SUBMITTED] = EventKind.CANDIDATE_SUBMITTED
    payload: CandidatePayload


class OperationPreparedEvent(EventBase):
    kind: Literal[EventKind.OPERATION_PREPARED] = EventKind.OPERATION_PREPARED
    payload: OperationPreparedPayload


class OperationRunningEvent(EventBase):
    kind: Literal[EventKind.OPERATION_RUNNING] = EventKind.OPERATION_RUNNING
    payload: OperationRunningPayload


class OperationTerminalEvent(EventBase):
    kind: Literal[EventKind.OPERATION_TERMINAL] = EventKind.OPERATION_TERMINAL
    payload: OperationTerminalPayload


class EvaluationCompletedEvent(EventBase):
    kind: Literal[EventKind.EVALUATION_COMPLETED] = EventKind.EVALUATION_COMPLETED
    payload: EvaluationPayload


class QualificationCompletedEvent(EventBase):
    kind: Literal[EventKind.QUALIFICATION_COMPLETED] = EventKind.QUALIFICATION_COMPLETED
    payload: QualificationCompletedPayload


class RunCancelledEvent(EventBase):
    kind: Literal[EventKind.RUN_CANCELLED] = EventKind.RUN_CANCELLED
    payload: ReasonPayload


class CancelRequestedEvent(EventBase):
    kind: Literal[EventKind.CANCEL_REQUESTED] = EventKind.CANCEL_REQUESTED
    payload: ReasonPayload


class RunCompletedEvent(EventBase):
    kind: Literal[EventKind.RUN_COMPLETED] = EventKind.RUN_COMPLETED
    payload: ReasonPayload


RunEvent = Annotated[
    RunPreparedEvent
    | RunStartedEvent
    | RunUnavailableEvent
    | ControlTransferredEvent
    | WorkspaceCommittedEvent
    | CheckpointCommittedEvent
    | CandidateSubmittedEvent
    | OperationPreparedEvent
    | OperationRunningEvent
    | OperationTerminalEvent
    | EvaluationCompletedEvent
    | QualificationCompletedEvent
    | CancelRequestedEvent
    | RunCancelledEvent
    | RunCompletedEvent,
    Field(discriminator="kind"),
]
RUN_EVENT: TypeAdapter[RunEvent] = TypeAdapter(RunEvent)


class RunCommit(JournalCommit[RunEvent]):
    """An atomic group of manifest-bound run facts."""

    @model_validator(mode="after")
    def validate_publication(self) -> Self:
        if (
            any(isinstance(event, QualificationCompletedEvent) for event in self.events)
            and len(self.events) != 1
        ):
            raise ValueError("qualification publication requires its own atomic commit")
        return self


class RunRecord(StrictModel):
    schema_version: Literal[2] = 2
    manifest: RunManifest
    commits: tuple[RunCommit, ...] = ()

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        from edagym.run.journal import journal_anchor, replay

        head = journal_anchor(self.manifest)
        for commit in self.commits:
            if commit.previous_record_digest != head:
                raise ValueError("run record hash chain is discontinuous")
            head = commit.record_digest
        replay(self.manifest, self.events)
        return self

    @property
    def events(self) -> tuple[RunEvent, ...]:
        return tuple(event for commit in self.commits for event in commit.events)

    @property
    def integrity_digest(self) -> Digest:
        from edagym.run.journal import journal_anchor

        return self.commits[-1].record_digest if self.commits else journal_anchor(self.manifest)

    def prefix(self, integrity_digest: Digest) -> RunRecord:
        from edagym.run.journal import journal_anchor

        if integrity_digest == journal_anchor(self.manifest):
            return RunRecord(manifest=self.manifest)
        for position, commit in enumerate(self.commits):
            if commit.record_digest == integrity_digest:
                return RunRecord(manifest=self.manifest, commits=self.commits[: position + 1])
        raise ValueError("requested journal prefix is absent from this run record")


class OperationState(StrictModel):
    prepared: OperationPreparedEvent
    running: OperationRunningEvent | None = None
    terminal: OperationTerminalEvent | None = None

    @property
    def phase(self) -> OperationPhase:
        if self.terminal is not None:
            return OperationPhase.TERMINAL
        return OperationPhase.RUNNING if self.running is not None else OperationPhase.PREPARED


class RunProjection(StrictModel):
    run_id: Identifier
    manifest_digest: Digest
    phase: EnginePhase
    control_owner: Identifier
    unavailable_reason: str | None = None
    terminal_reason: str | None = None
    accepted_intents: tuple[Identifier, ...] = ()
    last_checkpoint_id: Identifier | None = None
    next_sequence: int = Field(strict=True, ge=0)
    evaluations: tuple[EvaluationPayload, ...] = ()
    cancel_requested: bool = False
    qualification_instance_id: Identifier | None = None


class RunState(StrictModel):
    projection: RunProjection
    events: tuple[RunEvent, ...]
    operations: tuple[OperationState, ...] = ()
    workspace: CommittedManifest | None = None
    candidates: tuple[CandidatePayload, ...] = ()


class AcceptedEvent(StrictModel):
    run_id: Identifier
    intent_id: Identifier
    sequence: int = Field(strict=True, ge=0)
    event_id: Identifier
    kind: EventKind
    duplicate: bool = False


class EventStream(StrictModel):
    run_id: Identifier
    cursor: EventCursor
    events: tuple[RunEvent, ...]
    terminal: bool


class RunInterface(StrictModel):
    submission_paths: tuple[str, ...]
    tool_ids: tuple[Identifier, ...]
    writable: bool
