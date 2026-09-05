"""Immutable run binding and typed append-only event envelopes."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.evaluation.model import ScoringDecision, StageResult
from edagym.participant_tool_protocol import (
    participant_tool_invocation_id,
)
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    ModelLabel,
    ProviderResponseStatus,
    Redistribution,
    SchemaVersion,
    Seed128Hex,
    Sensitivity,
    ServiceTierLabel,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import CheckpointCapability
from edagym.specs.session import ActorKind as ActorKind


class ProducerKind(StrEnum):
    CONTROLLER = "controller"
    PARTICIPANT = "participant"
    EXECUTOR = "executor"
    EVALUATOR = "evaluator"
    POLICY = "policy"


class RunPurpose(StrEnum):
    """Closed execution purpose carried by the canonical run identity."""

    STANDARD = "standard"
    CAMPAIGN_TRIAL = "campaign_trial"
    SYNTHETIC_PREFLIGHT = "synthetic_preflight"


class EventKind(StrEnum):
    RUN_STARTED = "run_started"
    PARTICIPANT_INCARNATION_STARTED = "participant_incarnation_started"
    PARTICIPANT_INCARNATION_TERMINATED = "participant_incarnation_terminated"
    PARTICIPANT_INCARNATION_RESTORED = "participant_incarnation_restored"
    PROVIDER_REQUEST_STARTED = "provider_request_started"
    PROVIDER_RESPONSE_RECORDED = "provider_response_recorded"
    INTERACTION_RECORDED = "interaction_recorded"
    PARTICIPANT_TOOL_RESERVED = "participant_tool_reserved"
    PARTICIPANT_TOOL_SETTLED = "participant_tool_settled"
    PARTICIPANT_TOOL_LOST = "participant_tool_lost"
    CONTROL_TRANSFERRED = "control_transferred"
    CANDIDATE_SUBMITTED = "candidate_submitted"
    EVALUATION_STARTED = "evaluation_started"
    EVALUATION_COMPLETED = "evaluation_completed"
    SCORING_RECORDED = "scoring_recorded"
    LICENSE_LEASE_ACQUIRED = "license_lease_acquired"
    LICENSE_LEASE_DENIED = "license_lease_denied"
    LICENSE_LEASE_LOST = "license_lease_lost"
    LICENSE_LEASE_RELEASED = "license_lease_released"
    ARTIFACT_RECORDED = "artifact_recorded"
    CHECKPOINT_COMMITTED = "checkpoint_committed"
    JOB_STATE_CHANGED = "job_state_changed"
    POLICY_DECISION = "policy_decision"
    RUN_ENDED = "run_ended"


class StopReason(StrEnum):
    VERIFIER_SUCCESS = "verifier_success"
    WALL_BUDGET = "wall_budget"
    EDA_COMPUTE_BUDGET = "eda_compute_budget"
    EXPERIMENT_BUDGET = "experiment_budget"
    INTERACTION_BUDGET = "interaction_budget"
    TOOL_CALL_BUDGET = "tool_call_budget"
    TOKEN_BUDGET = "token_budget"
    LICENSE_BUDGET = "license_budget"
    STORAGE_BUDGET = "storage_budget"
    PROVIDER_BUDGET_OVERRUN = "provider_budget_overrun"
    EXPLICIT_CANCEL = "explicit_cancel"
    POLICY_FAILURE = "policy_failure"
    SECURITY_FAILURE = "security_failure"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    UNRANKABLE = "unrankable"


COMPARABLE_TRIAL_STOP_REASONS = frozenset(
    {
        StopReason.VERIFIER_SUCCESS,
        StopReason.UNRANKABLE,
        StopReason.WALL_BUDGET,
        StopReason.EDA_COMPUTE_BUDGET,
        StopReason.EXPERIMENT_BUDGET,
        StopReason.INTERACTION_BUDGET,
        StopReason.TOOL_CALL_BUDGET,
        StopReason.TOKEN_BUDGET,
        StopReason.LICENSE_BUDGET,
        StopReason.STORAGE_BUDGET,
    }
)


class InteractionDirection(StrEnum):
    PARTICIPANT_INPUT = "participant_input"
    PARTICIPANT_OUTPUT = "participant_output"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"


class JobStateKind(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CHECKPOINTING = "checkpointing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PolicyDecisionKind(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class LicenseDenialReason(StrEnum):
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    FEATURE_UNAVAILABLE = "feature_unavailable"
    INVALID_LEASE = "invalid_lease"
    PROVIDER_FAILURE = "provider_failure"


class BlobRef(StrictModel):
    digest: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0)]


class ArtifactRecord(StrictModel):
    logical_id: Identifier
    blob: BlobRef
    media_type: Annotated[str, Field(min_length=1, max_length=127)]
    artifact_class: ArtifactClass
    sensitivity: Sensitivity
    visibility: Visibility
    redistribution: Redistribution

    @model_validator(mode="after")
    def validate_persistence_policy(self) -> Self:
        if self.sensitivity is Sensitivity.SECRET:
            raise ValueError("secret artifacts cannot be persisted")
        if self.visibility is Visibility.PUBLIC and (
            self.sensitivity is not Sensitivity.PUBLIC
            or self.redistribution is not Redistribution.ALLOWED
        ):
            raise ValueError("public artifacts must be public and redistributable")
        return self


class TaskRunBinding(StrictModel):
    family: Identifier
    authoring_revision: Annotated[int, Field(strict=True, ge=1)]
    task_spec_digest: Digest
    instance_seed: Seed128Hex
    instance_digest: Digest
    release_digest: Digest


class ResolvedToolBinding(StrictModel):
    capability: Capability
    tool_id: Identifier
    tool_version: Annotated[str, Field(min_length=1, max_length=120)]
    driver_digest: Digest
    deployment_attestation_digest: Digest


class ResolvedParticipantOperationBinding(StrictModel):
    operation_id: Identifier
    operation_digest: Digest
    capability: Capability
    tool_id: Identifier


class ResolvedAssetBinding(StrictModel):
    asset_id: Identifier
    restricted_digest: Digest


class EnvironmentRunBinding(StrictModel):
    environment_spec_digest: Digest
    executor_id: Identifier
    executor_digest: Digest
    policy_digest: Digest
    tools: tuple[ResolvedToolBinding, ...]
    participant_operations: tuple[ResolvedParticipantOperationBinding, ...] = ()
    assets: tuple[ResolvedAssetBinding, ...] = ()

    @field_validator("tools")
    @classmethod
    def normalize_tools(
        cls, value: tuple[ResolvedToolBinding, ...]
    ) -> tuple[ResolvedToolBinding, ...]:
        capabilities = [item.capability for item in value]
        if not capabilities or len(capabilities) != len(set(capabilities)):
            raise ValueError("resolved tool capabilities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.capability.value))

    @field_validator("assets")
    @classmethod
    def normalize_assets(
        cls, value: tuple[ResolvedAssetBinding, ...]
    ) -> tuple[ResolvedAssetBinding, ...]:
        identifiers = [item.asset_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("resolved asset identifiers must be unique")
        return tuple(sorted(value, key=lambda item: item.asset_id))

    @field_validator("participant_operations")
    @classmethod
    def normalize_participant_operations(
        cls,
        value: tuple[ResolvedParticipantOperationBinding, ...],
    ) -> tuple[ResolvedParticipantOperationBinding, ...]:
        identifiers = [item.operation_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("resolved participant operation identifiers must be unique")
        return tuple(sorted(value, key=lambda item: item.operation_id))

    @model_validator(mode="after")
    def validate_participant_operation_tools(self) -> Self:
        tools = {(item.capability, item.tool_id) for item in self.tools}
        if any(
            (item.capability, item.tool_id) not in tools for item in self.participant_operations
        ):
            raise ValueError("resolved participant operation does not name a resolved tool")
        return self


class HumanRunActor(StrictModel):
    kind: Literal[ActorKind.HUMAN] = ActorKind.HUMAN
    actor_id: Identifier
    adapter_digest: Digest


class HarnessRunActor(StrictModel):
    kind: Literal[ActorKind.HARNESS] = ActorKind.HARNESS
    actor_id: Identifier
    harness_digest: Digest
    scaffold_digest: Digest
    requested_model_route: Annotated[str, Field(min_length=1, max_length=160)]


RunActor = Annotated[HumanRunActor | HarnessRunActor, Field(discriminator="kind")]


class SessionRunBinding(StrictModel):
    session_spec_digest: Digest
    actors: tuple[RunActor, ...]
    initial_writer: Identifier
    handoff_enabled: bool
    feedback_policy_digest: Digest
    budget_digest: Digest

    @field_validator("actors")
    @classmethod
    def normalize_actors(cls, value: tuple[RunActor, ...]) -> tuple[RunActor, ...]:
        identifiers = [item.actor_id for item in value]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("run actors must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.actor_id))

    @model_validator(mode="after")
    def validate_control(self) -> Self:
        actor_ids = {item.actor_id for item in self.actors}
        if self.initial_writer not in actor_ids:
            raise ValueError("initial writer must reference a run actor")
        if self.handoff_enabled != (len(actor_ids) > 1):
            raise ValueError("handoff is required exactly for multi-actor runs")
        return self


class EvaluatorRunBinding(StrictModel):
    evaluator_id: Identifier
    revision_digest: Digest


class RunLineage(StrictModel):
    parent_run_id: Digest | None = None
    parent_checkpoint_id: Identifier | None = None
    parent_candidate_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_lineage(self) -> Self:
        if self.parent_run_id is None and (
            self.parent_checkpoint_id is not None or self.parent_candidate_id is not None
        ):
            raise ValueError("checkpoint and candidate lineage require a parent run")
        return self


class CampaignTrialRunBinding(StrictModel):
    """Exact frozen campaign trial represented by this run."""

    campaign_digest: Digest
    schedule_digest: Digest
    scheduled_trial_digest: Digest
    paired_seed: Seed128Hex
    repetition_index: JcsNonNegativeInt
    route_id: Identifier
    reasoning_effort: Annotated[str, Field(min_length=1, max_length=32)]
    service_tier: ServiceTierLabel


class RunBinding(StrictModel):
    purpose: RunPurpose = RunPurpose.STANDARD
    task: TaskRunBinding
    environment: EnvironmentRunBinding
    session: SessionRunBinding
    evaluators: tuple[EvaluatorRunBinding, ...]
    measurement_schema_digest: Digest
    scorer_revision_digest: Digest | None = None
    trial_key: Identifier
    campaign: CampaignTrialRunBinding | None = None
    lineage: RunLineage = RunLineage()

    @model_validator(mode="after")
    def validate_purpose(self) -> Self:
        campaign_purpose = self.purpose in {
            RunPurpose.CAMPAIGN_TRIAL,
            RunPurpose.SYNTHETIC_PREFLIGHT,
        }
        if campaign_purpose != (self.campaign is not None):
            raise ValueError(
                "campaign trials and synthetic preflights require a campaign binding"
            )
        return self

    @field_validator("evaluators")
    @classmethod
    def normalize_evaluators(
        cls, value: tuple[EvaluatorRunBinding, ...]
    ) -> tuple[EvaluatorRunBinding, ...]:
        identifiers = [item.evaluator_id for item in value]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("run evaluator identities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.evaluator_id))

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="run-binding-v1")


class RunHeader(StrictModel):
    schema_version: SchemaVersion = 1
    run_id: Digest
    binding: RunBinding

    @model_validator(mode="after")
    def validate_run_id(self) -> Self:
        if self.run_id != self.binding.digest:
            raise ValueError("run_id must equal the canonical run binding digest")
        return self

    @classmethod
    def from_binding(cls, binding: RunBinding) -> RunHeader:
        return cls(run_id=binding.digest, binding=binding)


class RunStartedPayload(StrictModel):
    binding_digest: Digest


class ParticipantProcessIdentity(StrictModel):
    """Linux process incarnation used to prove controller replacement."""

    process_id: JcsPositiveInt
    start_time_ticks: JcsNonNegativeInt
    boot_id_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="participant-process-identity-v1")


class ParticipantIncarnationBinding(StrictModel):
    """Path-free identity of one participant controller and private workspace."""

    generation: JcsNonNegativeInt
    process: ParticipantProcessIdentity
    workspace_identity_digest: Digest
    artifact_directory_identity_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="participant-incarnation-binding-v1")


class ParticipantIncarnationStartedPayload(StrictModel):
    incarnation: ParticipantIncarnationBinding


class ParticipantIncarnationTerminatedPayload(StrictModel):
    incarnation_digest: Digest
    checkpoint_id: Identifier
    checkpoint_manifest_digest: Digest


class ParticipantIncarnationRestoredPayload(StrictModel):
    predecessor_incarnation_digest: Digest
    incarnation: ParticipantIncarnationBinding
    checkpoint_id: Identifier
    checkpoint_manifest_digest: Digest
    restored_manifest_digest: Digest

    @model_validator(mode="after")
    def validate_restored_manifest(self) -> Self:
        if self.restored_manifest_digest != self.checkpoint_manifest_digest:
            raise ValueError("restored workspace must equal the committed checkpoint manifest")
        return self


class InteractionRecordedPayload(StrictModel):
    direction: InteractionDirection
    interaction_id: Identifier
    related_interaction_id: Identifier | None = None
    tool_name: Identifier | None = None

    @model_validator(mode="after")
    def validate_relation(self) -> Self:
        if (self.direction is InteractionDirection.TOOL_RESULT) != (
            self.related_interaction_id is not None
        ):
            raise ValueError("tool results require exactly one request relation")
        is_tool_interaction = self.direction in {
            InteractionDirection.TOOL_REQUEST,
            InteractionDirection.TOOL_RESULT,
        }
        if is_tool_interaction != (self.tool_name is not None):
            raise ValueError("tool interactions require exactly one logical tool name")
        return self


class ParticipantToolReservedPayload(StrictModel):
    request_interaction_id: Identifier
    invocation_id: Identifier
    invocation_digest: Digest
    operation_id: Identifier
    operation_digest: Digest
    input_manifest_digest: Digest
    tool_id: Identifier
    capability: Capability
    executor_id: Identifier
    license_binding_id: Identifier | None = None
    budget_digest: Digest
    reserved_compute_milliseconds: JcsPositiveInt
    reserved_license_milliseconds: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_license_reservation(self) -> Self:
        if (self.license_binding_id is None) != (self.reserved_license_milliseconds == 0):
            raise ValueError("licensed tool reservations require positive license capacity")
        if self.reserved_license_milliseconds > self.reserved_compute_milliseconds:
            raise ValueError("license reservation cannot exceed compute reservation")
        return self


class ParticipantToolSettledPayload(StrictModel):
    request_interaction_id: Identifier
    invocation_id: Identifier
    invocation_digest: Digest
    operation_id: Identifier
    operation_digest: Digest
    input_manifest_digest: Digest
    evidence_artifact_id: Identifier
    elapsed_milliseconds: JcsNonNegativeInt
    license_milliseconds: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_usage(self) -> Self:
        if self.license_milliseconds > self.elapsed_milliseconds:
            raise ValueError("license duration cannot exceed tool dispatch duration")
        return self


class ParticipantToolLostPayload(StrictModel):
    request_interaction_id: Identifier
    invocation_id: Identifier
    invocation_digest: Digest


class ProviderUsageFact(StrictModel):
    input_tokens: JcsNonNegativeInt
    output_tokens: JcsNonNegativeInt
    total_tokens: JcsNonNegativeInt
    cached_input_tokens: JcsNonNegativeInt | None = None
    reasoning_tokens: JcsNonNegativeInt | None = None

    @model_validator(mode="after")
    def validate_counters(self) -> Self:
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("total usage must equal input plus output usage")
        if self.cached_input_tokens is not None and self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input usage cannot exceed input usage")
        if self.reasoning_tokens is not None and self.reasoning_tokens > self.output_tokens:
            raise ValueError("reasoning usage cannot exceed output usage")
        return self


class ProviderSecurityBinding(StrictModel):
    canary_receipt_digest: Digest
    runtime_surface_manifest_digest: Digest
    budget_binding_digest: Digest


class ProviderRequestStartedPayload(StrictModel):
    request_id: Identifier
    actor_id: Identifier
    request_artifact_id: Identifier
    security_evidence_artifact_id: Identifier
    provider_profile_digest: Digest
    provider_config_digest: Digest
    requested_model: ModelLabel
    requested_service_tier: ServiceTierLabel | None = None
    observed_input_token_floor: JcsNonNegativeInt = 0
    security_binding: ProviderSecurityBinding
    reserved_input_tokens: JcsPositiveInt
    reserved_output_tokens: JcsPositiveInt

    @model_validator(mode="after")
    def validate_input_reservation(self) -> Self:
        if self.observed_input_token_floor >= self.reserved_input_tokens:
            raise ValueError("input token reservation must exceed the observed route floor")
        return self


class ProviderResponseRecordedPayload(StrictModel):
    request_id: Identifier
    provider_reported_model: ModelLabel
    provider_reported_service_tier: ServiceTierLabel | None = None
    status: ProviderResponseStatus
    usage: ProviderUsageFact | None = None


class ControlTransferredPayload(StrictModel):
    previous_writer: Identifier
    next_writer: Identifier

    @model_validator(mode="after")
    def validate_transfer(self) -> Self:
        if self.previous_writer == self.next_writer:
            raise ValueError("control transfer requires a different writer")
        return self


class CandidateSubmittedPayload(StrictModel):
    candidate_id: Identifier
    candidate_digest: Digest
    parent_candidate_id: Identifier | None = None


class EvaluationStartedPayload(StrictModel):
    stage_id: Identifier
    candidate_id: Identifier
    job_id: Identifier


class EvaluationCompletedPayload(StrictModel):
    candidate_id: Identifier
    job_id: Identifier
    result: StageResult


class ScoringRecordedPayload(StrictModel):
    candidate_id: Identifier
    decision: ScoringDecision


class LicenseLeaseBindingPayload(StrictModel):
    job_id: Identifier
    license_binding_id: Identifier
    provider_id: Identifier
    feature_class: Identifier


class LicenseLeaseAcquiredPayload(LicenseLeaseBindingPayload):
    pass


class LicenseLeaseDeniedPayload(LicenseLeaseBindingPayload):
    reason: LicenseDenialReason


class LicenseLeaseLostPayload(LicenseLeaseBindingPayload):
    pass


class LicenseLeaseReleasedPayload(LicenseLeaseBindingPayload):
    pass


class ArtifactRecordedPayload(StrictModel):
    record: ArtifactRecord


class CheckpointCommittedPayload(StrictModel):
    checkpoint_id: Identifier
    manifest_digest: Digest
    parent_checkpoint_id: Identifier | None = None
    checkpoint_kind: Literal[
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    ] = CheckpointCapability.FILESYSTEM
    driver_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_driver_binding(self) -> Self:
        if (self.checkpoint_kind is CheckpointCapability.APPLICATION) != (
            self.driver_digest is not None
        ):
            raise ValueError("application checkpoint events require a driver identity")
        return self


class JobStateChangedPayload(StrictModel):
    job_id: Identifier
    state: JobStateKind
    reason_code: Identifier | None = None


class PolicyDecisionPayload(StrictModel):
    rule_id: Identifier
    decision: PolicyDecisionKind
    reason_code: Identifier


class RunEndedPayload(StrictModel):
    reason: StopReason
    successful_candidate_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_success_candidate(self) -> Self:
        is_success = self.reason is StopReason.VERIFIER_SUCCESS
        if is_success != (self.successful_candidate_id is not None):
            raise ValueError("verifier success requires exactly one successful candidate")
        return self


class EventBase(StrictModel):
    schema_version: SchemaVersion = 1
    run_id: Digest
    sequence: Annotated[int, Field(strict=True, ge=0)]
    event_id: UUID
    timestamp: datetime
    producer: ProducerKind
    actor: Identifier | None = None
    visibility: Visibility
    artifact_refs: tuple[Identifier, ...] = ()

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("artifact_refs")
    @classmethod
    def normalize_artifacts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("an event may reference an artifact only once")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_actor_attribution(self) -> Self:
        if self.producer is ProducerKind.PARTICIPANT and self.actor is None:
            raise ValueError("participant-produced events require actor attribution")
        if self.producer is not ProducerKind.PARTICIPANT and self.actor is not None:
            raise ValueError("only participant-produced events may carry actor attribution")
        return self


class RunStartedEvent(EventBase):
    kind: Literal[EventKind.RUN_STARTED] = EventKind.RUN_STARTED
    payload: RunStartedPayload


class ParticipantIncarnationEventBase(EventBase):
    producer: Literal[ProducerKind.CONTROLLER] = ProducerKind.CONTROLLER
    visibility: Literal[Visibility.VERIFIER] = Visibility.VERIFIER

    @model_validator(mode="after")
    def reject_artifact_references(self) -> Self:
        if self.artifact_refs:
            raise ValueError("participant incarnation facts cannot reference artifacts")
        return self


class ParticipantIncarnationStartedEvent(ParticipantIncarnationEventBase):
    kind: Literal[EventKind.PARTICIPANT_INCARNATION_STARTED] = (
        EventKind.PARTICIPANT_INCARNATION_STARTED
    )
    payload: ParticipantIncarnationStartedPayload


class ParticipantIncarnationTerminatedEvent(ParticipantIncarnationEventBase):
    kind: Literal[EventKind.PARTICIPANT_INCARNATION_TERMINATED] = (
        EventKind.PARTICIPANT_INCARNATION_TERMINATED
    )
    payload: ParticipantIncarnationTerminatedPayload


class ParticipantIncarnationRestoredEvent(ParticipantIncarnationEventBase):
    kind: Literal[EventKind.PARTICIPANT_INCARNATION_RESTORED] = (
        EventKind.PARTICIPANT_INCARNATION_RESTORED
    )
    payload: ParticipantIncarnationRestoredPayload


class ProviderRequestStartedEvent(EventBase):
    kind: Literal[EventKind.PROVIDER_REQUEST_STARTED] = EventKind.PROVIDER_REQUEST_STARTED
    payload: ProviderRequestStartedPayload

    @model_validator(mode="after")
    def require_request_artifact(self) -> Self:
        required = {
            self.payload.request_artifact_id,
            self.payload.security_evidence_artifact_id,
        }
        if len(required) != 2 or set(self.artifact_refs) != required:
            raise ValueError(
                "provider requests require their raw request and canary evidence artifacts"
            )
        return self


class ProviderResponseRecordedEvent(EventBase):
    kind: Literal[EventKind.PROVIDER_RESPONSE_RECORDED] = EventKind.PROVIDER_RESPONSE_RECORDED
    payload: ProviderResponseRecordedPayload

    @model_validator(mode="after")
    def require_response_artifact(self) -> Self:
        if len(self.artifact_refs) != 1:
            raise ValueError("provider responses require exactly one raw response artifact")
        return self


class InteractionRecordedEvent(EventBase):
    kind: Literal[EventKind.INTERACTION_RECORDED] = EventKind.INTERACTION_RECORDED
    payload: InteractionRecordedPayload


class ParticipantToolReservedEvent(EventBase):
    kind: Literal[EventKind.PARTICIPANT_TOOL_RESERVED] = EventKind.PARTICIPANT_TOOL_RESERVED
    producer: Literal[ProducerKind.CONTROLLER] = ProducerKind.CONTROLLER
    visibility: Literal[Visibility.VERIFIER] = Visibility.VERIFIER
    payload: ParticipantToolReservedPayload

    @model_validator(mode="after")
    def validate_reservation(self) -> Self:
        if self.artifact_refs:
            raise ValueError("participant tool reservations cannot reference artifacts")
        if self.payload.invocation_id != participant_tool_invocation_id(
            self.run_id,
            self.payload.request_interaction_id,
        ):
            raise ValueError("participant tool reservation has the wrong invocation identity")
        return self


class ParticipantToolSettledEvent(EventBase):
    kind: Literal[EventKind.PARTICIPANT_TOOL_SETTLED] = EventKind.PARTICIPANT_TOOL_SETTLED
    producer: Literal[ProducerKind.CONTROLLER] = ProducerKind.CONTROLLER
    visibility: Literal[Visibility.AUTHOR] = Visibility.AUTHOR
    payload: ParticipantToolSettledPayload

    @model_validator(mode="after")
    def require_execution_evidence(self) -> Self:
        if self.artifact_refs != (self.payload.evidence_artifact_id,):
            raise ValueError("participant tool settlement requires its execution evidence")
        return self


class ParticipantToolLostEvent(EventBase):
    kind: Literal[EventKind.PARTICIPANT_TOOL_LOST] = EventKind.PARTICIPANT_TOOL_LOST
    producer: Literal[ProducerKind.CONTROLLER] = ProducerKind.CONTROLLER
    visibility: Literal[Visibility.VERIFIER] = Visibility.VERIFIER
    payload: ParticipantToolLostPayload

    @model_validator(mode="after")
    def reject_artifact_references(self) -> Self:
        if self.artifact_refs:
            raise ValueError("lost participant tool facts cannot reference artifacts")
        return self


class ControlTransferredEvent(EventBase):
    kind: Literal[EventKind.CONTROL_TRANSFERRED] = EventKind.CONTROL_TRANSFERRED
    payload: ControlTransferredPayload


class CandidateSubmittedEvent(EventBase):
    kind: Literal[EventKind.CANDIDATE_SUBMITTED] = EventKind.CANDIDATE_SUBMITTED
    payload: CandidateSubmittedPayload


class EvaluationStartedEvent(EventBase):
    kind: Literal[EventKind.EVALUATION_STARTED] = EventKind.EVALUATION_STARTED
    payload: EvaluationStartedPayload


class EvaluationCompletedEvent(EventBase):
    kind: Literal[EventKind.EVALUATION_COMPLETED] = EventKind.EVALUATION_COMPLETED
    payload: EvaluationCompletedPayload


class ScoringRecordedEvent(EventBase):
    kind: Literal[EventKind.SCORING_RECORDED] = EventKind.SCORING_RECORDED
    payload: ScoringRecordedPayload

    @model_validator(mode="after")
    def reject_artifact_references(self) -> Self:
        if self.artifact_refs:
            raise ValueError("scoring facts cannot reference artifacts")
        return self


class LicenseLeaseEventBase(EventBase):
    producer: Literal[ProducerKind.CONTROLLER] = ProducerKind.CONTROLLER
    visibility: Literal[Visibility.VERIFIER] = Visibility.VERIFIER

    @model_validator(mode="after")
    def reject_artifact_references(self) -> Self:
        if self.artifact_refs:
            raise ValueError("license lease facts cannot reference artifacts")
        return self


class LicenseLeaseAcquiredEvent(LicenseLeaseEventBase):
    kind: Literal[EventKind.LICENSE_LEASE_ACQUIRED] = EventKind.LICENSE_LEASE_ACQUIRED
    payload: LicenseLeaseAcquiredPayload


class LicenseLeaseDeniedEvent(LicenseLeaseEventBase):
    kind: Literal[EventKind.LICENSE_LEASE_DENIED] = EventKind.LICENSE_LEASE_DENIED
    payload: LicenseLeaseDeniedPayload


class LicenseLeaseLostEvent(LicenseLeaseEventBase):
    """Record that restart recovery lost custody of an opaque active lease."""

    kind: Literal[EventKind.LICENSE_LEASE_LOST] = EventKind.LICENSE_LEASE_LOST
    payload: LicenseLeaseLostPayload


class LicenseLeaseReleasedEvent(LicenseLeaseEventBase):
    kind: Literal[EventKind.LICENSE_LEASE_RELEASED] = EventKind.LICENSE_LEASE_RELEASED
    payload: LicenseLeaseReleasedPayload


class ArtifactRecordedEvent(EventBase):
    kind: Literal[EventKind.ARTIFACT_RECORDED] = EventKind.ARTIFACT_RECORDED
    payload: ArtifactRecordedPayload

    @model_validator(mode="after")
    def reject_self_reference(self) -> Self:
        if self.artifact_refs:
            raise ValueError("artifact-recorded events cannot reference unregistered artifacts")
        return self


class CheckpointCommittedEvent(EventBase):
    kind: Literal[EventKind.CHECKPOINT_COMMITTED] = EventKind.CHECKPOINT_COMMITTED
    payload: CheckpointCommittedPayload

    @model_validator(mode="after")
    def require_checkpoint_manifest(self) -> Self:
        if len(self.artifact_refs) != 1:
            raise ValueError("checkpoint commits require exactly one manifest reference")
        return self


class JobStateChangedEvent(EventBase):
    kind: Literal[EventKind.JOB_STATE_CHANGED] = EventKind.JOB_STATE_CHANGED
    payload: JobStateChangedPayload


class PolicyDecisionEvent(EventBase):
    kind: Literal[EventKind.POLICY_DECISION] = EventKind.POLICY_DECISION
    payload: PolicyDecisionPayload


class RunEndedEvent(EventBase):
    kind: Literal[EventKind.RUN_ENDED] = EventKind.RUN_ENDED
    payload: RunEndedPayload


RunEvent = Annotated[
    RunStartedEvent
    | ParticipantIncarnationStartedEvent
    | ParticipantIncarnationTerminatedEvent
    | ParticipantIncarnationRestoredEvent
    | ProviderRequestStartedEvent
    | ProviderResponseRecordedEvent
    | InteractionRecordedEvent
    | ParticipantToolReservedEvent
    | ParticipantToolSettledEvent
    | ParticipantToolLostEvent
    | ControlTransferredEvent
    | CandidateSubmittedEvent
    | EvaluationStartedEvent
    | EvaluationCompletedEvent
    | ScoringRecordedEvent
    | LicenseLeaseAcquiredEvent
    | LicenseLeaseDeniedEvent
    | LicenseLeaseLostEvent
    | LicenseLeaseReleasedEvent
    | ArtifactRecordedEvent
    | CheckpointCommittedEvent
    | JobStateChangedEvent
    | PolicyDecisionEvent
    | RunEndedEvent,
    Field(discriminator="kind"),
]


class ParticipantToolDispatch(StrictModel):
    """One validated participant executor reservation and optional terminal fact."""

    reservation: ParticipantToolReservedEvent
    terminal: ParticipantToolSettledEvent | ParticipantToolLostEvent | None = None


class ParticipantIncarnationTermination(StrictModel):
    incarnation_digest: Digest
    checkpoint_id: Identifier
    checkpoint_manifest_digest: Digest


class ParticipantIncarnationRecovery(StrictModel):
    termination: ParticipantIncarnationTermination
    terminated_sequence: JcsNonNegativeInt
    restored_sequence: JcsNonNegativeInt
    restored_incarnation_digest: Digest
    restored_manifest_digest: Digest

    @model_validator(mode="after")
    def validate_sequence(self) -> Self:
        if self.restored_sequence <= self.terminated_sequence:
            raise ValueError("participant restore must follow its termination")
        if self.restored_manifest_digest != self.termination.checkpoint_manifest_digest:
            raise ValueError("participant recovery manifests must be identical")
        return self


class ParticipantIncarnationLifecycle(StrictModel):
    """Derived participant controller generations for one journal prefix."""

    incarnations: tuple[ParticipantIncarnationBinding, ...] = ()
    initial_started_sequence: JcsNonNegativeInt | None = None
    recoveries: tuple[ParticipantIncarnationRecovery, ...] = ()
    active_incarnation: ParticipantIncarnationBinding | None = None
    pending_termination: ParticipantIncarnationTermination | None = None
    pending_termination_sequence: JcsNonNegativeInt | None = None

    @model_validator(mode="after")
    def validate_projection(self) -> Self:
        if (self.initial_started_sequence is None) != (not self.incarnations):
            raise ValueError("participant lifecycle start sequence differs from its generations")
        if (self.pending_termination is None) != (
            self.pending_termination_sequence is None
        ):
            raise ValueError("pending participant termination requires its event sequence")
        if len(self.recoveries) + 1 != len(self.incarnations) and self.incarnations:
            raise ValueError("participant lifecycle recoveries do not connect every generation")
        return self


def run_journal_anchor(header: RunHeader) -> Digest:
    """Derive the first hash-chain value for a run journal."""

    return canonical_digest(header, domain="run-journal-header-v1")


def run_commit_digest(
    previous_record_digest: Digest,
    events: tuple[RunEvent, ...],
) -> Digest:
    """Derive one crash-atomic journal commit identity."""

    return canonical_digest(
        {
            "events": events,
            "previous_record_digest": previous_record_digest,
        },
        domain="run-journal-record-v1",
    )


class RunCommit(StrictModel):
    """One crash-atomic, hash-chained group in a persisted run record."""

    schema_version: SchemaVersion = 1
    previous_record_digest: Digest
    events: Annotated[tuple[RunEvent, ...], Field(min_length=1)]
    record_digest: Digest

    @classmethod
    def from_events(
        cls,
        *,
        previous_record_digest: Digest,
        events: tuple[RunEvent, ...],
    ) -> RunCommit:
        return cls(
            previous_record_digest=previous_record_digest,
            events=events,
            record_digest=run_commit_digest(previous_record_digest, events),
        )

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.record_digest != run_commit_digest(
            self.previous_record_digest,
            self.events,
        ):
            raise ValueError("run commit digest does not match its content")
        return self


class RunRecord(StrictModel):
    """Portable archive of the immutable header and physical journal commits."""

    schema_version: SchemaVersion = 1
    header: RunHeader
    commits: tuple[RunCommit, ...] = ()

    @model_validator(mode="after")
    def validate_chain(self) -> Self:
        expected_digest = run_journal_anchor(self.header)
        expected_sequence = 0
        event_ids: set[UUID] = set()
        referenced_canary_evidence: set[str] = set()
        for commit in self.commits:
            if commit.previous_record_digest != expected_digest:
                raise ValueError("run record hash chain is discontinuous")
            recorded_artifacts = {
                event.payload.record.logical_id
                for event in commit.events
                if isinstance(event, ArtifactRecordedEvent)
            }
            for event in commit.events:
                if event.run_id != self.header.run_id:
                    raise ValueError("run record event belongs to another run")
                if event.sequence != expected_sequence:
                    raise ValueError("run record event sequence is not contiguous")
                if event.event_id in event_ids:
                    raise ValueError("run record event identifier is duplicated")
                event_ids.add(event.event_id)
                if isinstance(event, ProviderRequestStartedEvent):
                    payload = event.payload
                    if payload.request_artifact_id not in recorded_artifacts:
                        raise ValueError(
                            "provider request bytes must be committed with their request fact"
                        )
                    if (
                        payload.security_evidence_artifact_id
                        not in referenced_canary_evidence
                        and payload.security_evidence_artifact_id
                        not in recorded_artifacts
                    ):
                        raise ValueError(
                            "first provider request must commit its canary evidence"
                        )
                    referenced_canary_evidence.add(
                        payload.security_evidence_artifact_id
                    )
                expected_sequence += 1
            expected_digest = commit.record_digest
        return self

    @property
    def events(self) -> tuple[RunEvent, ...]:
        return tuple(event for commit in self.commits for event in commit.events)

    @property
    def integrity_digest(self) -> Digest:
        if not self.commits:
            return run_journal_anchor(self.header)
        return self.commits[-1].record_digest


class CandidateState(StrictModel):
    candidate_id: Identifier
    digest: Digest
    parent_candidate_id: Identifier | None
    actor: Identifier


class CandidateStageResult(StrictModel):
    candidate_id: Identifier
    result: StageResult


class CandidateScoringState(StrictModel):
    candidate_id: Identifier
    decision: ScoringDecision


class JobStateSnapshot(StrictModel):
    job_id: Identifier
    state: JobStateKind


class ProviderRequestState(StrictModel):
    request_id: Identifier
    actor_id: Identifier
    request_artifact_id: Identifier
    security_evidence_artifact_id: Identifier
    provider_profile_digest: Digest
    provider_config_digest: Digest
    requested_model: ModelLabel
    requested_service_tier: ServiceTierLabel | None = None
    observed_input_token_floor: JcsNonNegativeInt = 0
    security_binding: ProviderSecurityBinding
    reserved_input_tokens: JcsPositiveInt
    reserved_output_tokens: JcsPositiveInt
    provider_reported_model: ModelLabel | None = None
    provider_reported_service_tier: ServiceTierLabel | None = None
    status: ProviderResponseStatus | None = None
    usage: ProviderUsageFact | None = None

    @model_validator(mode="after")
    def validate_input_reservation(self) -> Self:
        if self.observed_input_token_floor >= self.reserved_input_tokens:
            raise ValueError("input token reservation must exceed the observed route floor")
        return self


class ParticipantToolUsage(StrictModel):
    """Conservative journal-derived participant execution usage."""

    eda_compute_milliseconds: JcsNonNegativeInt
    license_milliseconds: JcsNonNegativeInt


class RunState(StrictModel):
    run_id: Digest
    next_sequence: Annotated[int, Field(strict=True, ge=0)]
    current_writer: Identifier
    candidates: tuple[CandidateState, ...] = ()
    stage_results: tuple[CandidateStageResult, ...] = ()
    scoring: tuple[CandidateScoringState, ...] = ()
    artifacts: tuple[ArtifactRecord, ...] = ()
    checkpoint_ids: tuple[Identifier, ...] = ()
    interaction_ids: tuple[Identifier, ...] = ()
    provider_requests: tuple[ProviderRequestState, ...] = ()
    jobs: tuple[JobStateSnapshot, ...] = ()
    terminal_reason: StopReason | None = None
    successful_candidate_id: Identifier | None = None
