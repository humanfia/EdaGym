"""Deterministic scheduling, accounting, and reporting for paid campaigns."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, fields
from dataclasses import field as dataclass_field
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, TypeAdapter, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.evaluation.model import OutcomeKind
from edagym.providers.campaign import (
    CampaignScope,
    ModelCategory,
    ModelReferenceKind,
    RetryCondition,
)
from edagym.providers.campaign_budget import (
    BudgetDimension as BudgetDimension,
)
from edagym.providers.campaign_budget import (
    CampaignAccountingError as CampaignAccountingError,
)
from edagym.providers.campaign_budget import (
    CampaignBudgetExceeded as CampaignBudgetExceeded,
)
from edagym.providers.campaign_budget import (
    CampaignBudgetProjection as CampaignBudgetProjection,
)
from edagym.providers.campaign_budget import (
    CampaignResources as CampaignResources,
)
from edagym.providers.campaign_budget import (
    ProviderBudgetOverrun as ProviderBudgetOverrun,
)
from edagym.providers.campaign_budget import (
    _MutableResources as _MutableResources,
)
from edagym.providers.campaign_schedule import (
    CampaignHeader,
    CampaignSchedule,
    CampaignTaskRole,
    ScheduledTrial,
)
from edagym.providers.model import (
    ProviderProfile,
    ProviderSecurityBinding,
    ProviderUsage,
    RequestTokenClaim,
)
from edagym.run.trial_model import (
    CandidateStageResult,
    ProviderRequestState,
    RunBinding,
    RunState,
    StopReason,
)
from edagym.specs.common import (
    CanonicalDecimal,
    Capability,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    ModelLabel,
    ProviderResponseStatus,
    SchemaVersion,
    ServiceTierLabel,
    StrictModel,
)

_MODEL_LABEL = TypeAdapter(ModelLabel)
_SERVICE_TIER_LABEL = TypeAdapter(ServiceTierLabel)
_SUCCESSFUL_STAGE_OUTCOMES = frozenset({OutcomeKind.PASSED, OutcomeKind.PROVED})


class AttemptDisposition(StrEnum):
    COMPLETED = "completed"
    RETRYABLE_FAILURE = "retryable_failure"
    TERMINAL_FAILURE = "terminal_failure"


class ProviderAttemptRecord(StrictModel):
    request_key: Identifier
    attempt_number: JcsPositiveInt
    reserved_token_claim: RequestTokenClaim
    disposition: AttemptDisposition
    failure_condition: RetryCondition | None = None
    requested_model: ModelLabel
    requested_service_tier: ServiceTierLabel
    security_binding: ProviderSecurityBinding
    provider_reported_model: ModelLabel | None = None
    provider_reported_service_tier: ServiceTierLabel | None = None
    provider_response_status: ProviderResponseStatus | None = None
    provider_usage: ProviderUsage | None = None
    charged_resources: CampaignResources

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        retryable = self.disposition is AttemptDisposition.RETRYABLE_FAILURE
        if retryable != (self.failure_condition is not None):
            raise ValueError("retryable provider failures require exactly one retry condition")
        completed = self.disposition is AttemptDisposition.COMPLETED
        required_response_facts = self.provider_reported_model, self.provider_response_status
        if completed and any(fact is None for fact in required_response_facts):
            raise ValueError("completed provider attempts require response identity and status")
        if not completed and (
            any(fact is not None for fact in required_response_facts)
            or self.provider_reported_service_tier is not None
        ):
            raise ValueError("failed provider attempts cannot carry response facts")
        charged = self.charged_resources
        if (
            charged.requests != 1
            or charged.turns
            or charged.tool_calls
            or charged.wall_seconds
            or charged.eda_compute_seconds
            or charged.license_seconds
            or charged.artifact_bytes
        ):
            raise ValueError("provider attempt resources may contain only one request and tokens")
        if self.provider_usage is not None and (
            charged.input_tokens != self.provider_usage.input_tokens
            or charged.output_tokens != self.provider_usage.output_tokens
        ):
            raise ValueError("known provider usage must equal charged token usage")
        return self


class SpendObservationKind(StrEnum):
    KNOWN = "known"
    UNKNOWN = "unknown"


class KnownSpend(StrictModel):
    kind: Literal[SpendObservationKind.KNOWN] = SpendObservationKind.KNOWN
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")]
    amount: Annotated[CanonicalDecimal, Field(ge=0)]


class UnknownSpendReason(StrEnum):
    PROVIDER_REPORTING_UNAVAILABLE = "provider_reporting_unavailable"
    PROVIDER_REPORTING_INCOMPLETE = "provider_reporting_incomplete"
    TRIAL_NOT_DISPATCHED = "trial_not_dispatched"


class UnknownSpend(StrictModel):
    kind: Literal[SpendObservationKind.UNKNOWN] = SpendObservationKind.UNKNOWN
    reason: UnknownSpendReason


SpendObservation = Annotated[KnownSpend | UnknownSpend, Field(discriminator="kind")]


class TrialDisposition(StrEnum):
    COMPLETED_RUN = "completed_run"
    FAILED_BEFORE_RUN = "failed_before_run"
    NOT_DISPATCHED = "not_dispatched"


class TrialRunOutcome(StrictModel):
    """Typed terminal facts ingested from a real run or an explicit non-run."""

    disposition: TrialDisposition
    terminal_reason: StopReason
    run_id: Digest | None = None
    run_binding: RunBinding | None = None
    stage_results: tuple[CandidateStageResult, ...] = ()
    provider_requests: tuple[ProviderRequestState, ...] = ()
    provider_spend: SpendObservation

    @field_validator("stage_results")
    @classmethod
    def validate_stage_results(
        cls,
        value: tuple[CandidateStageResult, ...],
    ) -> tuple[CandidateStageResult, ...]:
        identities = [(result.candidate_id, result.result.stage_id) for result in value]
        if len(identities) != len(set(identities)):
            raise ValueError("trial stage results require unique candidate and stage pairs")
        return value

    @model_validator(mode="after")
    def validate_terminal_facts(self) -> Self:
        completed = self.disposition is TrialDisposition.COMPLETED_RUN
        if completed and (self.run_id is None or self.run_binding is None):
            raise ValueError("only completed runs carry a run identifier and binding")
        if not completed and (self.run_id is not None or self.run_binding is not None):
            raise ValueError("only completed runs carry a run identifier and binding")
        if self.run_binding is not None and self.run_id != self.run_binding.digest:
            raise ValueError("trial run identifier must equal its run binding digest")
        if not completed and self.stage_results:
            raise ValueError("a trial without a completed run cannot carry stage results")
        if not completed and self.provider_requests:
            raise ValueError("a trial without a completed run cannot carry provider requests")
        request_ids = [request.request_id for request in self.provider_requests]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("trial provider request identifiers must be unique")
        if self.terminal_reason is StopReason.VERIFIER_SUCCESS and not completed:
            raise ValueError("verifier success requires a completed run")
        if self.disposition is TrialDisposition.NOT_DISPATCHED and not isinstance(
            self.provider_spend, UnknownSpend
        ):
            raise ValueError("a trial that was not dispatched cannot have known spend")
        return self

    @classmethod
    def from_run_state(
        cls,
        state: RunState,
        *,
        run_binding: RunBinding,
        provider_spend: SpendObservation,
    ) -> TrialRunOutcome:
        if state.terminal_reason is None:
            raise ValueError("campaign outcomes require a terminal run state")
        return cls(
            disposition=TrialDisposition.COMPLETED_RUN,
            terminal_reason=state.terminal_reason,
            run_id=state.run_id,
            run_binding=run_binding,
            stage_results=state.stage_results,
            provider_requests=state.provider_requests,
            provider_spend=provider_spend,
        )


class CountRatio(StrictModel):
    numerator: JcsNonNegativeInt
    denominator: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_ratio(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("ratio numerator cannot exceed its denominator")
        return self


class ServiceTierCount(StrictModel):
    service_tier: ServiceTierLabel
    count: JcsPositiveInt


class ServiceTierAccounting(StrictModel):
    requested_service_tiers: tuple[ServiceTierCount, ...]
    provider_reported_service_tiers: tuple[ServiceTierCount, ...]
    unknown_attempts: JcsNonNegativeInt
    reported_tier_mismatches: CountRatio

    @field_validator("requested_service_tiers", "provider_reported_service_tiers")
    @classmethod
    def validate_unique_tiers(
        cls,
        value: tuple[ServiceTierCount, ...],
    ) -> tuple[ServiceTierCount, ...]:
        tiers = [item.service_tier for item in value]
        if len(tiers) != len(set(tiers)):
            raise ValueError("provider-reported service tier counts must be unique")
        return tuple(sorted(value, key=lambda item: item.service_tier))


class TokenAccounting(StrictModel):
    request_attempts: JcsNonNegativeInt
    retry_attempts: JcsNonNegativeInt
    charged_input_tokens: JcsNonNegativeInt
    charged_output_tokens: JcsNonNegativeInt
    provider_input_tokens: JcsNonNegativeInt
    provider_output_tokens: JcsNonNegativeInt
    unknown_usage_attempts: JcsNonNegativeInt
    cached_input_tokens: JcsNonNegativeInt
    unknown_cached_usage_attempts: JcsNonNegativeInt
    reasoning_tokens: JcsNonNegativeInt
    unknown_reasoning_usage_attempts: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_attempt_partition(self) -> Self:
        if self.retry_attempts > self.request_attempts:
            raise ValueError("retry attempts cannot exceed provider request attempts")
        if self.unknown_usage_attempts > self.request_attempts:
            raise ValueError("unknown provider usage cannot exceed request attempts")
        if self.unknown_cached_usage_attempts > self.request_attempts:
            raise ValueError("unknown cached usage cannot exceed request attempts")
        if self.unknown_reasoning_usage_attempts > self.request_attempts:
            raise ValueError("unknown reasoning usage cannot exceed request attempts")
        return self


class TrialReport(StrictModel):
    trial: ScheduledTrial
    outcome: TrialRunOutcome
    resources: CampaignResources
    token_accounting: TokenAccounting
    provider_attempts: tuple[ProviderAttemptRecord, ...]
    accounting_violation: bool

    @model_validator(mode="after")
    def validate_attempts(self) -> Self:
        from edagym.providers.campaign_reporting import token_accounting

        by_request: defaultdict[str, list[int]] = defaultdict(list)
        for attempt in self.provider_attempts:
            by_request[attempt.request_key].append(attempt.attempt_number)
        if any(numbers != list(range(1, len(numbers) + 1)) for numbers in by_request.values()):
            raise ValueError("provider attempts must preserve contiguous retry order")
        if self.token_accounting.request_attempts != len(self.provider_attempts):
            raise ValueError("token accounting must count every provider attempt")
        if self.resources.requests != len(self.provider_attempts):
            raise ValueError("trial resources must count every provider attempt")
        if self.token_accounting != token_accounting(self.provider_attempts):
            raise ValueError("trial token accounting must be derived from provider attempts")
        if (
            self.resources.input_tokens != self.token_accounting.charged_input_tokens
            or self.resources.output_tokens != self.token_accounting.charged_output_tokens
        ):
            raise ValueError("trial resource tokens must equal charged provider usage")
        if self.outcome.disposition is TrialDisposition.NOT_DISPATCHED and (
            not self.resources.is_zero or self.provider_attempts
        ):
            raise ValueError("a non-dispatched trial cannot contain resource usage")
        return self

    @property
    def success(self) -> bool:
        return self.outcome.terminal_reason is StopReason.VERIFIER_SUCCESS


class CurrencyTotal(StrictModel):
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")]
    amount: Annotated[CanonicalDecimal, Field(ge=0)]


class SpendSummary(StrictModel):
    known_totals: tuple[CurrencyTotal, ...]
    unknown_trial_count: JcsNonNegativeInt


class TerminalReasonCount(StrictModel):
    reason: StopReason
    count: JcsPositiveInt


class TaskAggregate(StrictModel):
    task_release_digest: Digest
    task_family: Identifier
    task_role: CampaignTaskRole
    success: CountRatio
    resources: CampaignResources
    token_accounting: TokenAccounting
    terminal_reasons: tuple[TerminalReasonCount, ...]
    spend: SpendSummary


class DeviceAggregate(StrictModel):
    device_capability: Capability
    success: CountRatio
    resources: CampaignResources
    token_accounting: TokenAccounting
    terminal_reasons: tuple[TerminalReasonCount, ...]
    spend: SpendSummary


class ReportedModelCount(StrictModel):
    provider_reported_model: ModelLabel
    count: JcsPositiveInt


class ModelAggregate(StrictModel):
    route_id: Identifier
    requested_model: ModelLabel
    qualified_provider_reported_model: ModelLabel
    reference_kind: ModelReferenceKind
    categories: Annotated[tuple[ModelCategory, ...], Field(min_length=1)]
    observed_provider_reported_models: tuple[ReportedModelCount, ...]
    unknown_reported_model_attempts: JcsNonNegativeInt
    reported_label_mismatches: CountRatio
    success: CountRatio
    resources: CampaignResources
    token_accounting: TokenAccounting
    terminal_reasons: tuple[TerminalReasonCount, ...]
    spend: SpendSummary


class CellAggregate(StrictModel):
    cell_id: Identifier
    harness_digest: Digest
    policy_digest: Digest
    route_id: Identifier
    requested_model: ModelLabel
    reasoning_effort: Annotated[str, Field(min_length=1, max_length=32)]
    success: CountRatio
    resources: CampaignResources
    token_accounting: TokenAccounting
    terminal_reasons: tuple[TerminalReasonCount, ...]
    spend: SpendSummary


class ModelCategoryAggregate(StrictModel):
    category: ModelCategory
    route_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    success: CountRatio
    resources: CampaignResources
    token_accounting: TokenAccounting
    terminal_reasons: tuple[TerminalReasonCount, ...]
    spend: SpendSummary


class SuccessAtK(StrictModel):
    cell_id: Identifier
    route_id: Identifier
    requested_model: ModelLabel
    reasoning_effort: Annotated[str, Field(min_length=1, max_length=32)]
    k: JcsPositiveInt
    success: CountRatio


class StageOutcomeCount(StrictModel):
    outcome: OutcomeKind
    evaluation_count: JcsPositiveInt


class EvaluatorFunnel(StrictModel):
    task_release_digest: Digest
    task_family: Identifier
    stage_id: Identifier
    reached: CountRatio
    passed: CountRatio
    outcome_counts: tuple[StageOutcomeCount, ...]


class CampaignReport(StrictModel):
    """Mechanical report over every scheduled trial, including non-runs."""

    schema_version: Literal[2] = 2
    campaign_digest: Digest
    benchmark_spec_digest: Digest
    schedule_digest: Digest
    campaign_record_digest: Digest
    campaign_scope: CampaignScope
    provider_profile: ProviderProfile
    provider_profile_digest: Digest
    provider_config_digest: Digest
    model_set_digest: Digest
    budget_violation: bool
    trials: Annotated[tuple[TrialReport, ...], Field(min_length=1)]
    overall_success: CountRatio
    task_aggregates: tuple[TaskAggregate, ...]
    device_aggregates: tuple[DeviceAggregate, ...]
    model_aggregates: tuple[ModelAggregate, ...]
    cell_aggregates: tuple[CellAggregate, ...]
    model_category_aggregates: tuple[ModelCategoryAggregate, ...]
    success_at_k: tuple[SuccessAtK, ...]
    evaluator_funnel: tuple[EvaluatorFunnel, ...]
    terminal_reasons: tuple[TerminalReasonCount, ...]
    resources: CampaignResources
    token_accounting: TokenAccounting
    service_tier_accounting: ServiceTierAccounting
    spend: SpendSummary

    @model_validator(mode="after")
    def validate_derived_totals(self) -> Self:
        from edagym.providers.campaign_reporting import (
            _cell_aggregate,
            _cell_groups,
            aggregate_resources,
            all_attempts,
            service_tier_accounting,
            spend_summary,
            success_ratio,
            terminal_reason_counts,
            token_accounting,
        )

        if self.provider_profile.digest != self.provider_profile_digest:
            raise ValueError("campaign report provider profile digest is inconsistent")
        if any(
            report.trial.binding.harness.provider_profile_digest != self.provider_profile_digest
            or report.trial.binding.harness.provider_config_digest != self.provider_config_digest
            or report.trial.binding.harness.wire_protocol is not self.provider_profile.wire_protocol
            for report in self.trials
        ):
            raise ValueError("campaign report harness provider identity is inconsistent")
        task_order: dict[int, str] = {}
        for report in self.trials:
            binding = report.trial.binding
            prior = task_order.setdefault(
                binding.task_order_index,
                binding.task_release_digest,
            )
            if prior != binding.task_release_digest:
                raise ValueError("campaign report task order is inconsistent")
        if tuple(sorted(task_order)) != tuple(range(len(task_order))):
            raise ValueError("campaign report task order is not contiguous")
        schedule = CampaignSchedule(
            campaign_digest=self.campaign_digest,
            benchmark_spec_digest=self.benchmark_spec_digest,
            model_set_digest=self.model_set_digest,
            ordered_task_release_digests=tuple(
                task_order[index] for index in range(len(task_order))
            ),
            trials=tuple(report.trial for report in self.trials),
        )
        if schedule.digest != self.schedule_digest:
            raise ValueError("campaign report schedule digest is inconsistent")
        if tuple(report.trial.ordinal for report in self.trials) != tuple(range(len(self.trials))):
            raise ValueError("campaign report trials must preserve the frozen schedule order")
        if any(
            report.trial.binding.campaign_digest != self.campaign_digest for report in self.trials
        ):
            raise ValueError("campaign report trials must match the campaign digest")
        expected_cells = tuple(
            _cell_aggregate(group) for group in _cell_groups(self.trials).values()
        )
        if self.cell_aggregates != expected_cells:
            raise ValueError("cell aggregates must be derived from their scheduled trials")
        if self.overall_success != success_ratio(self.trials):
            raise ValueError("overall success must be derived from every trial")
        if self.resources != aggregate_resources(self.trials):
            raise ValueError("campaign resources must be derived from every trial")
        if self.token_accounting != token_accounting(all_attempts(self.trials)):
            raise ValueError("campaign token accounting must be derived from every trial")
        if self.service_tier_accounting != service_tier_accounting(all_attempts(self.trials)):
            raise ValueError("campaign service tier accounting must be derived from every trial")
        if self.terminal_reasons != terminal_reason_counts(self.trials):
            raise ValueError("campaign terminal reasons must be derived from every trial")
        if self.spend != spend_summary(self.trials):
            raise ValueError("campaign spend must be derived from every trial")
        if self.budget_violation != any(report.accounting_violation for report in self.trials):
            raise ValueError("campaign budget violation must match its trial evidence")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-report-v2")


class CampaignEventKind(StrEnum):
    RESERVATION_CREATED = "reservation_created"
    RESERVATION_DISPATCHED = "reservation_dispatched"
    RESERVATION_CANCELLED = "reservation_cancelled"
    WORK_SETTLED = "work_settled"
    PROVIDER_ATTEMPT_SETTLED = "provider_attempt_settled"
    TRIAL_OUTCOME_RECORDED = "trial_outcome_recorded"
    BUDGET_STOPPED = "budget_stopped"


class ProviderReservationBinding(StrictModel):
    request_key: Identifier
    attempt_number: JcsPositiveInt
    observed_input_token_floor: JcsNonNegativeInt
    security_binding: ProviderSecurityBinding


class ReservationCreatedPayload(StrictModel):
    reservation_id: Identifier
    trial_id: Identifier
    claim: CampaignResources
    provider: ProviderReservationBinding | None = None


class ReservationDispatchedPayload(StrictModel):
    reservation_id: Identifier


class ReservationCancelledPayload(StrictModel):
    reservation_id: Identifier


class WorkSettledPayload(StrictModel):
    reservation_id: Identifier
    actual: CampaignResources


class ProviderAttemptSettledPayload(StrictModel):
    reservation_id: Identifier
    attempt: ProviderAttemptRecord


class TrialOutcomeRecordedPayload(StrictModel):
    trial_id: Identifier
    outcome: TrialRunOutcome


class BudgetStoppedPayload(StrictModel):
    dimension: BudgetDimension
    trial_id: Identifier
    per_trial: bool
    rejected_claim: CampaignResources


class CampaignEventBase(StrictModel):
    event_id: UUID
    sequence: JcsNonNegativeInt


class ReservationCreatedEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.RESERVATION_CREATED] = CampaignEventKind.RESERVATION_CREATED
    payload: ReservationCreatedPayload


class ReservationDispatchedEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.RESERVATION_DISPATCHED] = (
        CampaignEventKind.RESERVATION_DISPATCHED
    )
    payload: ReservationDispatchedPayload


class ReservationCancelledEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.RESERVATION_CANCELLED] = CampaignEventKind.RESERVATION_CANCELLED
    payload: ReservationCancelledPayload


class WorkSettledEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.WORK_SETTLED] = CampaignEventKind.WORK_SETTLED
    payload: WorkSettledPayload


class ProviderAttemptSettledEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.PROVIDER_ATTEMPT_SETTLED] = (
        CampaignEventKind.PROVIDER_ATTEMPT_SETTLED
    )
    payload: ProviderAttemptSettledPayload


class TrialOutcomeRecordedEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.TRIAL_OUTCOME_RECORDED] = (
        CampaignEventKind.TRIAL_OUTCOME_RECORDED
    )
    payload: TrialOutcomeRecordedPayload


class BudgetStoppedEvent(CampaignEventBase):
    kind: Literal[CampaignEventKind.BUDGET_STOPPED] = CampaignEventKind.BUDGET_STOPPED
    payload: BudgetStoppedPayload


CampaignEvent = Annotated[
    ReservationCreatedEvent
    | ReservationDispatchedEvent
    | ReservationCancelledEvent
    | WorkSettledEvent
    | ProviderAttemptSettledEvent
    | TrialOutcomeRecordedEvent
    | BudgetStoppedEvent,
    Field(discriminator="kind"),
]


def campaign_commit_digest(
    previous_record_digest: Digest,
    events: tuple[CampaignEvent, ...],
) -> Digest:
    return canonical_digest(
        {"events": events, "previous_record_digest": previous_record_digest},
        domain="provider-campaign-record-v1",
    )


class CampaignCommit(StrictModel):
    schema_version: SchemaVersion = 1
    previous_record_digest: Digest
    events: Annotated[tuple[CampaignEvent, ...], Field(min_length=1)]
    record_digest: Digest

    @classmethod
    def from_events(
        cls,
        *,
        previous_record_digest: Digest,
        events: tuple[CampaignEvent, ...],
    ) -> CampaignCommit:
        return cls(
            previous_record_digest=previous_record_digest,
            events=events,
            record_digest=campaign_commit_digest(previous_record_digest, events),
        )

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.record_digest != campaign_commit_digest(
            self.previous_record_digest,
            self.events,
        ):
            raise ValueError("campaign commit digest does not match its content")
        return self


class CampaignRecord(StrictModel):
    schema_version: SchemaVersion = 1
    header: CampaignHeader
    commits: tuple[CampaignCommit, ...] = ()

    @model_validator(mode="after")
    def validate_chain(self) -> Self:
        expected_digest = self.header.digest
        expected_sequence = 0
        event_ids: set[UUID] = set()
        for commit in self.commits:
            if commit.previous_record_digest != expected_digest:
                raise ValueError("campaign record hash chain is discontinuous")
            for event in commit.events:
                if event.sequence != expected_sequence:
                    raise ValueError("campaign event sequence is not contiguous")
                if event.event_id in event_ids:
                    raise ValueError("campaign event identifier is duplicated")
                event_ids.add(event.event_id)
                expected_sequence += 1
            expected_digest = commit.record_digest
        return self

    @property
    def events(self) -> tuple[CampaignEvent, ...]:
        return tuple(event for commit in self.commits for event in commit.events)

    @property
    def integrity_digest(self) -> Digest:
        if not self.commits:
            return self.header.digest
        return self.commits[-1].record_digest


@dataclass(slots=True)
class _TrialProjection:
    committed: _MutableResources = dataclass_field(default_factory=_MutableResources)
    reserved: _MutableResources = dataclass_field(default_factory=_MutableResources)
    attempts: list[ProviderAttemptRecord] = dataclass_field(default_factory=list)
    cancelled_provider_requests: set[str] = dataclass_field(default_factory=set)
    outcome: TrialRunOutcome | None = None
    accounting_violation: bool = False


@dataclass(slots=True)
class _ReservationLedger:
    trial_id: str
    claim: CampaignResources
    provider: ProviderReservationBinding | None
    dispatched: bool = False


class CampaignRecovery(StrictModel):
    reservation_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    affected_trial_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]


@dataclass(slots=True)
class _CampaignProjection:
    ledgers: dict[str, _TrialProjection]
    reservations: dict[str, _ReservationLedger]
    committed: _MutableResources
    reserved: _MutableResources
    run_ids: set[str]
    global_stop_dimension: BudgetDimension | None = None
    trial_stop_dimensions: dict[str, BudgetDimension] = dataclass_field(default_factory=dict)
    budget_violation: bool = False


def _replay_campaign_record(record: CampaignRecord) -> _CampaignProjection:
    from edagym.providers.campaign_replay import replay_campaign_record

    return replay_campaign_record(record)


def _ready_campaign_projection(
    state: _CampaignProjection,
    trial_id: str,
) -> _TrialProjection:
    from edagym.providers.campaign_replay import ready_campaign_projection

    return ready_campaign_projection(state, trial_id)


def _reservation_rejection(
    header: CampaignHeader,
    state: _CampaignProjection,
    trial_id: str,
    claim: CampaignResources,
    *,
    provider_request: bool,
) -> CampaignBudgetExceeded | None:
    from edagym.providers.campaign_replay import reservation_rejection

    return reservation_rejection(
        header,
        state,
        trial_id,
        claim,
        provider_request=provider_request,
    )


def _apply_campaign_event(
    header: CampaignHeader,
    state: _CampaignProjection,
    event: CampaignEvent,
) -> None:
    from edagym.providers.campaign_replay import apply_campaign_event

    apply_campaign_event(header, state, event)


class CampaignReservation:
    """Single-use pre-dispatch reservation owned by a campaign runner."""

    __slots__ = (
        "_claim",
        "_dispatched",
        "_lock",
        "_provider",
        "_reservation_id",
        "_runner",
        "_settled",
        "_trial_id",
    )

    def __init__(
        self,
        runner: CampaignRunner,
        trial_id: str,
        reservation_id: str,
        claim: CampaignResources,
        provider: ProviderReservationBinding | None,
        *,
        dispatched: bool = False,
    ) -> None:
        self._runner = runner
        self._trial_id = trial_id
        self._reservation_id = reservation_id
        self._claim = claim
        self._provider = provider
        self._lock = Lock()
        self._dispatched = dispatched
        self._settled = False

    @property
    def claim(self) -> CampaignResources:
        return self._claim

    @property
    def attempt_number(self) -> int | None:
        if self._provider is None:
            return None
        return self._provider.attempt_number

    @property
    def dispatched(self) -> bool:
        return self._dispatched

    def mark_dispatched(self) -> None:
        with self._lock:
            if self._settled or self._dispatched:
                raise CampaignAccountingError("reservation cannot be dispatched in its state")
            self._runner._mark_dispatched(self)
            self._dispatched = True

    def settle_work(self, actual: CampaignResources) -> None:
        if self._provider is not None:
            raise CampaignAccountingError("provider reservations require provider settlement")
        if actual.requests or actual.input_tokens or actual.output_tokens:
            raise ValueError("work settlement cannot report provider request resources")
        with self._lock:
            if self._settled or not self._dispatched:
                raise CampaignAccountingError("reservation cannot be settled in its state")
            exceeded_claim = self._runner._settle_work(self, actual)
            self._settled = True
            if exceeded_claim:
                raise CampaignAccountingError("work usage exceeded its pre-dispatch reservation")

    def finalize_run(
        self,
        *,
        actual: CampaignResources,
        outcome: TrialRunOutcome,
    ) -> None:
        """Atomically settle work and commit the journal-derived run outcome."""

        if self._provider is not None:
            raise CampaignAccountingError("provider reservations cannot finalize a run")
        if actual.requests or actual.input_tokens or actual.output_tokens:
            raise ValueError("run work settlement cannot report provider request resources")
        with self._lock:
            if self._settled or not self._dispatched:
                raise CampaignAccountingError("reservation cannot be finalized in its state")
            exceeded_claim = self._runner._finalize_run(self, actual, outcome)
            self._settled = True
            if exceeded_claim:
                raise CampaignAccountingError("run work exceeded its pre-dispatch reservation")

    def settle_provider(
        self,
        *,
        disposition: AttemptDisposition,
        usage: ProviderUsage | None,
        provider_reported_model: str | None = None,
        provider_reported_service_tier: str | None = None,
        provider_response_status: ProviderResponseStatus | None = None,
        failure_condition: RetryCondition | None = None,
    ) -> None:
        if self._provider is None:
            raise CampaignAccountingError("work reservations cannot report provider outcomes")
        reported_model = (
            None
            if provider_reported_model is None
            else _MODEL_LABEL.validate_python(provider_reported_model)
        )
        reported_service_tier = (
            None
            if provider_reported_service_tier is None
            else _SERVICE_TIER_LABEL.validate_python(provider_reported_service_tier)
        )
        with self._lock:
            if self._settled or not self._dispatched:
                raise CampaignAccountingError("reservation cannot be settled in its state")
            exceeded_claim = self._runner._settle_provider(
                self,
                disposition=disposition,
                usage=usage,
                provider_reported_model=reported_model,
                provider_reported_service_tier=reported_service_tier,
                provider_response_status=provider_response_status,
                failure_condition=failure_condition,
            )
            self._settled = True
            if exceeded_claim:
                raise ProviderBudgetOverrun(
                    "provider usage exceeded its pre-dispatch token reservation"
                )

    def cancel(self) -> None:
        with self._lock:
            if self._settled or self._dispatched:
                raise CampaignAccountingError("a dispatched reservation cannot be cancelled")
            self._runner._cancel(self)
            self._settled = True

    def __repr__(self) -> str:
        return "CampaignReservation(<opaque>)"


class CampaignRunner:
    """Own the complete schedule and atomically account every external dispatch."""

    def __init__(self, *, header: CampaignHeader, state_root: Path) -> None:
        self.header = header
        self.campaign = header.campaign
        self.model_set = header.model_set
        self.tasks = header.tasks
        self.schedule = header.schedule
        self.provider_config = header.provider_config
        from edagym.providers.campaign_journal import CampaignJournal

        self.journal = CampaignJournal.create(state_root, header)
        self._trial_by_id = {trial.trial_id: trial for trial in self.schedule.trials}
        self._route_by_id = {route.route_id: route for route in self.model_set.routes}
        self._task_by_release = {task.task_release_digest: task for task in self.tasks}
        self._active_reservations: set[CampaignReservation] = set()
        self._lock = Lock()
        self._closed = False
        _replay_campaign_record(self.journal.record())

    def pending_trials(self) -> tuple[ScheduledTrial, ...]:
        """Return unresolved trials in their frozen dispatch order."""

        with self._lock:
            state = _replay_campaign_record(self.journal.record())
            return tuple(
                trial
                for trial in self.schedule.trials
                if state.ledgers[trial.trial_id].outcome is None
            )

    def budget_projection(self) -> CampaignBudgetProjection:
        return CampaignBudgetProjection.from_header(self.header)

    def reserve_provider_attempt(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        requested_model: ModelLabel,
        token_claim: RequestTokenClaim,
        security_binding: ProviderSecurityBinding,
    ) -> CampaignReservation:
        claim = CampaignResources(
            requests=1,
            input_tokens=token_claim.input_tokens,
            output_tokens=token_claim.output_tokens,
        )
        with self._lock:
            self._ensure_open()
            reservation_id = f"reservation_{uuid4().hex}"
            selected: dict[str, ProviderReservationBinding | CampaignBudgetExceeded] = {}

            def reserve(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                trial = self._require_trial(trial_id)
                if requested_model != trial.binding.requested_model:
                    raise CampaignAccountingError(
                        "provider request model does not match the frozen trial route"
                    )
                if (
                    token_claim.observed_input_token_floor
                    != trial.binding.observed_input_token_floor
                ):
                    raise CampaignAccountingError(
                        "observed input token floor does not match the frozen trial route"
                    )
                if security_binding.budget_binding_digest != self.budget_projection().digest:
                    raise CampaignAccountingError(
                        "provider security binding has the wrong campaign budget"
                    )
                ledger = _ready_campaign_projection(state, trial_id)
                matching = [
                    attempt for attempt in ledger.attempts if attempt.request_key == request_key
                ]
                attempt_number = len(matching) + 1
                if matching:
                    previous = matching[-1]
                    if previous.disposition is not AttemptDisposition.RETRYABLE_FAILURE:
                        raise CampaignAccountingError(
                            "only retryable failures admit another attempt"
                        )
                    if attempt_number > self.campaign.retry_policy.max_request_attempts:
                        raise CampaignAccountingError("provider retry policy is exhausted")
                    if (
                        previous.failure_condition
                        not in self.campaign.retry_policy.retry_conditions
                    ):
                        raise CampaignAccountingError(
                            "provider failure is not admitted by retry policy"
                        )
                provider = ProviderReservationBinding(
                    request_key=request_key,
                    attempt_number=attempt_number,
                    observed_input_token_floor=(token_claim.observed_input_token_floor),
                    security_binding=security_binding,
                )
                rejection = _reservation_rejection(
                    self.header,
                    state,
                    trial_id,
                    claim,
                    provider_request=True,
                )
                if rejection is not None:
                    selected["result"] = rejection
                    event: CampaignEvent = BudgetStoppedEvent(
                        event_id=uuid4(),
                        sequence=len(record.events),
                        payload=BudgetStoppedPayload(
                            dimension=rejection.dimension,
                            trial_id=trial_id,
                            per_trial=rejection.per_trial,
                            rejected_claim=claim,
                        ),
                    )
                else:
                    selected["result"] = provider
                    event = ReservationCreatedEvent(
                        event_id=uuid4(),
                        sequence=len(record.events),
                        payload=ReservationCreatedPayload(
                            reservation_id=reservation_id,
                            trial_id=trial_id,
                            claim=claim,
                            provider=provider,
                        ),
                    )
                _apply_campaign_event(record.header, state, event)
                return (event,)

            self.journal.transact(reserve)
            result = selected["result"]
            if isinstance(result, CampaignBudgetExceeded):
                raise result
            reservation = CampaignReservation(
                self,
                trial_id,
                reservation_id,
                claim,
                result,
            )
            self._active_reservations.add(reservation)
            return reservation

    def reserve_work(
        self,
        *,
        trial_id: Identifier,
        claim: CampaignResources,
    ) -> CampaignReservation:
        if claim.is_zero:
            raise ValueError("work reservations require a non-zero resource claim")
        if claim.requests or claim.input_tokens or claim.output_tokens:
            raise ValueError("provider request resources require a provider reservation")
        with self._lock:
            self._ensure_open()
            reservation_id = f"reservation_{uuid4().hex}"
            rejected: list[CampaignBudgetExceeded] = []

            def reserve(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                self._require_trial(trial_id)
                _ready_campaign_projection(state, trial_id)
                rejection = _reservation_rejection(
                    self.header,
                    state,
                    trial_id,
                    claim,
                    provider_request=False,
                )
                if rejection is not None:
                    rejected.append(rejection)
                    event: CampaignEvent = BudgetStoppedEvent(
                        event_id=uuid4(),
                        sequence=len(record.events),
                        payload=BudgetStoppedPayload(
                            dimension=rejection.dimension,
                            trial_id=trial_id,
                            per_trial=rejection.per_trial,
                            rejected_claim=claim,
                        ),
                    )
                else:
                    event = ReservationCreatedEvent(
                        event_id=uuid4(),
                        sequence=len(record.events),
                        payload=ReservationCreatedPayload(
                            reservation_id=reservation_id,
                            trial_id=trial_id,
                            claim=claim,
                        ),
                    )
                _apply_campaign_event(record.header, state, event)
                return (event,)

            self.journal.transact(reserve)
            if rejected:
                raise rejected[0]
            reservation = CampaignReservation(self, trial_id, reservation_id, claim, None)
            self._active_reservations.add(reservation)
            return reservation

    def resume_work_reservation(
        self,
        *,
        trial_id: Identifier,
    ) -> CampaignReservation | None:
        """Adopt one durable work reservation after a controller restart."""

        with self._lock:
            self._ensure_open()
            state = _replay_campaign_record(self.journal.record())
            self._require_trial(trial_id)
            reservations = tuple(
                (reservation_id, reservation)
                for reservation_id, reservation in state.reservations.items()
                if reservation.trial_id == trial_id and reservation.provider is None
            )
            if not reservations:
                return None
            if len(reservations) != 1:
                raise CampaignAccountingError(
                    "a trial cannot resume with multiple work reservations"
                )
            reservation_id, ledger = reservations[0]
            if any(
                active._reservation_id == reservation_id for active in self._active_reservations
            ):
                raise CampaignAccountingError("work reservation is already active")
            reservation = CampaignReservation(
                self,
                trial_id,
                reservation_id,
                ledger.claim,
                None,
                dispatched=ledger.dispatched,
            )
            self._active_reservations.add(reservation)
            return reservation

    def record_outcome(self, *, trial_id: Identifier, outcome: TrialRunOutcome) -> None:
        with self._lock:
            self._ensure_open()

            def record_outcome(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                event = TrialOutcomeRecordedEvent(
                    event_id=uuid4(),
                    sequence=len(record.events),
                    payload=TrialOutcomeRecordedPayload(
                        trial_id=trial_id,
                        outcome=outcome,
                    ),
                )
                _apply_campaign_event(record.header, state, event)
                return (event,)

            self.journal.transact(record_outcome)

    def recover_incomplete_provider_dispatches(
        self,
        *,
        trial_id: Identifier,
        provider_requests: tuple[ProviderRequestState, ...],
    ) -> CampaignRecovery | None:
        """Reconcile provider reservations against one resumed run journal."""

        with self._lock:
            self._ensure_open()
            recovered: list[str] = []
            requests = {request.request_id: request for request in provider_requests}
            if len(requests) != len(provider_requests):
                raise CampaignAccountingError("run provider request identities are duplicated")

            def recover(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                self._require_trial(trial_id)
                events: list[CampaignEvent] = []
                for reservation_id, reservation in sorted(state.reservations.items()):
                    if reservation.trial_id != trial_id or reservation.provider is None:
                        continue
                    sequence = len(record.events) + len(events)
                    request = requests.get(reservation.provider.request_key)
                    trial = self._trial_by_id[trial_id]
                    harness = trial.binding.harness
                    if request is not None and (
                        request.provider_profile_digest != harness.provider_profile_digest
                        or request.provider_config_digest != harness.provider_config_digest
                        or request.requested_model != trial.binding.requested_model
                        or request.requested_service_tier != trial.binding.service_tier
                        or request.observed_input_token_floor
                        != reservation.provider.observed_input_token_floor
                        or request.security_binding != reservation.provider.security_binding
                        or request.reserved_input_tokens != reservation.claim.input_tokens
                        or request.reserved_output_tokens != reservation.claim.output_tokens
                    ):
                        raise CampaignAccountingError(
                            "run provider request differs from its campaign reservation"
                        )
                    if not reservation.dispatched:
                        if request is not None and request.status is not None:
                            raise CampaignAccountingError(
                                "an undispatched provider reservation has response evidence"
                            )
                        event: CampaignEvent = ReservationCancelledEvent(
                            event_id=uuid4(),
                            sequence=sequence,
                            payload=ReservationCancelledPayload(reservation_id=reservation_id),
                        )
                    elif request is None:
                        raise CampaignAccountingError(
                            "a dispatched provider reservation lacks run request evidence"
                        )
                    else:
                        completed = request.status is not None
                        if completed and request.provider_reported_model is None:
                            raise CampaignAccountingError(
                                "a completed provider request lacks response identity"
                            )
                        usage = request.usage
                        actual = CampaignResources(
                            requests=1,
                            input_tokens=(
                                reservation.claim.input_tokens
                                if usage is None
                                else usage.input_tokens
                            ),
                            output_tokens=(
                                reservation.claim.output_tokens
                                if usage is None
                                else usage.output_tokens
                            ),
                        )
                        event = ProviderAttemptSettledEvent(
                            event_id=uuid4(),
                            sequence=sequence,
                            payload=ProviderAttemptSettledPayload(
                                reservation_id=reservation_id,
                                attempt=ProviderAttemptRecord(
                                    request_key=reservation.provider.request_key,
                                    attempt_number=reservation.provider.attempt_number,
                                    reserved_token_claim=RequestTokenClaim(
                                        input_tokens=reservation.claim.input_tokens,
                                        output_tokens=reservation.claim.output_tokens,
                                        observed_input_token_floor=(
                                            reservation.provider.observed_input_token_floor
                                        ),
                                    ),
                                    disposition=(
                                        AttemptDisposition.COMPLETED
                                        if completed
                                        else AttemptDisposition.TERMINAL_FAILURE
                                    ),
                                    requested_model=trial.binding.requested_model,
                                    requested_service_tier=trial.binding.service_tier,
                                    security_binding=reservation.provider.security_binding,
                                    provider_reported_model=(
                                        request.provider_reported_model if completed else None
                                    ),
                                    provider_reported_service_tier=(
                                        request.provider_reported_service_tier
                                        if completed
                                        else None
                                    ),
                                    provider_response_status=(
                                        request.status if completed else None
                                    ),
                                    provider_usage=usage,
                                    charged_resources=actual,
                                ),
                            ),
                        )
                    _apply_campaign_event(record.header, state, event)
                    events.append(event)
                    recovered.append(reservation_id)
                if not events:
                    return ()
                return tuple(events)

            record = self.journal.record()
            state = _replay_campaign_record(record)
            has_provider = any(
                reservation.trial_id == trial_id and reservation.provider is not None
                for reservation in state.reservations.values()
            )
            if not has_provider:
                return None
            self.journal.transact(recover)
            return CampaignRecovery(
                reservation_ids=tuple(recovered),
                affected_trial_ids=(trial_id,),
            )

    def stop_unfinished(self, reason: StopReason) -> None:
        """Materialize an explicit terminal record for every unresolved schedule entry."""

        if reason is StopReason.VERIFIER_SUCCESS:
            raise ValueError("unfinished trials cannot be materialized as successful")
        with self._lock:
            self._ensure_open()

            def stop(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                if state.reservations:
                    raise CampaignAccountingError(
                        "active dispatches must settle before campaign stop"
                    )
                events: list[CampaignEvent] = []
                for trial in self.schedule.trials:
                    ledger = state.ledgers[trial.trial_id]
                    if ledger.outcome is not None:
                        continue
                    resources = ledger.committed.snapshot()
                    dispatched = not resources.is_zero or bool(ledger.attempts)
                    event = TrialOutcomeRecordedEvent(
                        event_id=uuid4(),
                        sequence=len(record.events) + len(events),
                        payload=TrialOutcomeRecordedPayload(
                            trial_id=trial.trial_id,
                            outcome=TrialRunOutcome(
                                disposition=(
                                    TrialDisposition.FAILED_BEFORE_RUN
                                    if dispatched
                                    else TrialDisposition.NOT_DISPATCHED
                                ),
                                terminal_reason=reason,
                                provider_spend=UnknownSpend(
                                    reason=(
                                        UnknownSpendReason.PROVIDER_REPORTING_INCOMPLETE
                                        if dispatched
                                        else UnknownSpendReason.TRIAL_NOT_DISPATCHED
                                    )
                                ),
                            ),
                        ),
                    )
                    _apply_campaign_event(record.header, state, event)
                    events.append(event)
                if not events:
                    raise CampaignAccountingError("campaign has no unfinished trials")
                return tuple(events)

            self.journal.transact(stop)

    def build_report(self) -> CampaignReport:
        with self._lock:
            record = self.journal.record()
            from edagym.providers.campaign_reporting import project_campaign_report

            report = project_campaign_report(record)
            self._closed = True
            return report

    def recover_incomplete_dispatches(self) -> CampaignRecovery:
        """Conservatively close reservations left by a controller crash."""

        with self._lock:
            self._ensure_open()
            recovered: list[str] = []
            affected_trials: set[str] = set()

            def recover(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                events: list[CampaignEvent] = []
                for reservation_id, reservation in sorted(state.reservations.items()):
                    sequence = len(record.events) + len(events)
                    if not reservation.dispatched:
                        event: CampaignEvent = ReservationCancelledEvent(
                            event_id=uuid4(),
                            sequence=sequence,
                            payload=ReservationCancelledPayload(reservation_id=reservation_id),
                        )
                    elif reservation.provider is None:
                        event = WorkSettledEvent(
                            event_id=uuid4(),
                            sequence=sequence,
                            payload=WorkSettledPayload(
                                reservation_id=reservation_id,
                                actual=reservation.claim,
                            ),
                        )
                    else:
                        trial = self._trial_by_id[reservation.trial_id]
                        event = ProviderAttemptSettledEvent(
                            event_id=uuid4(),
                            sequence=sequence,
                            payload=ProviderAttemptSettledPayload(
                                reservation_id=reservation_id,
                                attempt=ProviderAttemptRecord(
                                    request_key=reservation.provider.request_key,
                                    attempt_number=reservation.provider.attempt_number,
                                    reserved_token_claim=RequestTokenClaim(
                                        input_tokens=reservation.claim.input_tokens,
                                        output_tokens=reservation.claim.output_tokens,
                                        observed_input_token_floor=(
                                            reservation.provider.observed_input_token_floor
                                        ),
                                    ),
                                    disposition=AttemptDisposition.TERMINAL_FAILURE,
                                    requested_model=trial.binding.requested_model,
                                    requested_service_tier=trial.binding.service_tier,
                                    security_binding=reservation.provider.security_binding,
                                    charged_resources=reservation.claim,
                                ),
                            ),
                        )
                    _apply_campaign_event(record.header, state, event)
                    events.append(event)
                    recovered.append(reservation_id)
                    affected_trials.add(reservation.trial_id)
                if not events:
                    raise CampaignAccountingError(
                        "campaign has no incomplete dispatch reservations"
                    )
                return tuple(events)

            self.journal.transact(recover)
            return CampaignRecovery(
                reservation_ids=tuple(recovered),
                affected_trial_ids=tuple(sorted(affected_trials)),
            )

    def _ensure_open(self) -> None:
        if self._closed:
            raise CampaignAccountingError("campaign runner is closed")

    def _require_trial(self, trial_id: str) -> ScheduledTrial:
        try:
            return self._trial_by_id[trial_id]
        except KeyError:
            raise ValueError("trial is not part of the frozen campaign schedule") from None

    def _mark_dispatched(self, reservation: CampaignReservation) -> None:
        with self._lock:
            self._require_active(reservation)

            def mark(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                event = ReservationDispatchedEvent(
                    event_id=uuid4(),
                    sequence=len(record.events),
                    payload=ReservationDispatchedPayload(
                        reservation_id=reservation._reservation_id
                    ),
                )
                _apply_campaign_event(record.header, state, event)
                return (event,)

            self.journal.transact(mark)

    def _cancel(self, reservation: CampaignReservation) -> None:
        with self._lock:
            self._require_active(reservation)

            def cancel(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                event = ReservationCancelledEvent(
                    event_id=uuid4(),
                    sequence=len(record.events),
                    payload=ReservationCancelledPayload(reservation_id=reservation._reservation_id),
                )
                _apply_campaign_event(record.header, state, event)
                return (event,)

            self.journal.transact(cancel)
            self._active_reservations.remove(reservation)

    def _settle_work(
        self,
        reservation: CampaignReservation,
        actual: CampaignResources,
    ) -> bool:
        with self._lock:
            self._require_active(reservation)
            exceeded_claim = self._exceeds(actual, reservation._claim)

            def settle(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                event = WorkSettledEvent(
                    event_id=uuid4(),
                    sequence=len(record.events),
                    payload=WorkSettledPayload(
                        reservation_id=reservation._reservation_id,
                        actual=actual,
                    ),
                )
                _apply_campaign_event(record.header, state, event)
                return (event,)

            self.journal.transact(settle)
            self._active_reservations.remove(reservation)
            return exceeded_claim

    def _finalize_run(
        self,
        reservation: CampaignReservation,
        actual: CampaignResources,
        outcome: TrialRunOutcome,
    ) -> bool:
        with self._lock:
            self._require_active(reservation)
            exceeded_claim = self._exceeds(actual, reservation._claim)

            def finalize(record: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record)
                settled = WorkSettledEvent(
                    event_id=uuid4(),
                    sequence=len(record.events),
                    payload=WorkSettledPayload(
                        reservation_id=reservation._reservation_id,
                        actual=actual,
                    ),
                )
                _apply_campaign_event(record.header, state, settled)
                terminal = TrialOutcomeRecordedEvent(
                    event_id=uuid4(),
                    sequence=len(record.events) + 1,
                    payload=TrialOutcomeRecordedPayload(
                        trial_id=reservation._trial_id,
                        outcome=outcome,
                    ),
                )
                _apply_campaign_event(record.header, state, terminal)
                return settled, terminal

            self.journal.transact(finalize)
            self._active_reservations.remove(reservation)
            return exceeded_claim

    def _settle_provider(
        self,
        reservation: CampaignReservation,
        *,
        disposition: AttemptDisposition,
        usage: ProviderUsage | None,
        provider_reported_model: str | None,
        provider_reported_service_tier: str | None,
        provider_response_status: ProviderResponseStatus | None,
        failure_condition: RetryCondition | None,
    ) -> bool:
        provider = reservation._provider
        if provider is None:
            raise CampaignAccountingError("provider reservation metadata is missing")
        retryable = disposition is AttemptDisposition.RETRYABLE_FAILURE
        if retryable != (failure_condition is not None):
            raise ValueError("retryable provider failures require exactly one retry condition")
        if failure_condition is not None and (
            failure_condition not in self.campaign.retry_policy.retry_conditions
        ):
            raise ValueError("provider failure condition is not admitted by retry policy")
        completed = disposition is AttemptDisposition.COMPLETED
        if completed and (provider_reported_model is None or provider_response_status is None):
            raise ValueError("completed provider attempts require response identity and status")
        if not completed and (
            provider_reported_model is not None
            or provider_reported_service_tier is not None
            or provider_response_status is not None
            or usage is not None
        ):
            raise ValueError("failed provider attempts cannot carry response facts")
        actual = CampaignResources(
            requests=1,
            input_tokens=(reservation._claim.input_tokens if usage is None else usage.input_tokens),
            output_tokens=(
                reservation._claim.output_tokens if usage is None else usage.output_tokens
            ),
        )
        trial = self._trial_by_id[reservation._trial_id]
        record = ProviderAttemptRecord(
            request_key=provider.request_key,
            attempt_number=provider.attempt_number,
            reserved_token_claim=RequestTokenClaim(
                input_tokens=reservation._claim.input_tokens,
                output_tokens=reservation._claim.output_tokens,
                observed_input_token_floor=(provider.observed_input_token_floor),
            ),
            disposition=disposition,
            failure_condition=failure_condition,
            requested_model=trial.binding.requested_model,
            requested_service_tier=trial.binding.service_tier,
            security_binding=provider.security_binding,
            provider_reported_model=provider_reported_model,
            provider_reported_service_tier=provider_reported_service_tier,
            provider_response_status=provider_response_status,
            provider_usage=usage,
            charged_resources=actual,
        )
        with self._lock:
            self._require_active(reservation)
            exceeded_claim = self._exceeds(actual, reservation._claim)

            def settle(record_state: CampaignRecord) -> tuple[CampaignEvent, ...]:
                state = _replay_campaign_record(record_state)
                event = ProviderAttemptSettledEvent(
                    event_id=uuid4(),
                    sequence=len(record_state.events),
                    payload=ProviderAttemptSettledPayload(
                        reservation_id=reservation._reservation_id,
                        attempt=record,
                    ),
                )
                _apply_campaign_event(record_state.header, state, event)
                return (event,)

            self.journal.transact(settle)
            self._active_reservations.remove(reservation)
            return exceeded_claim

    def _require_active(self, reservation: CampaignReservation) -> None:
        if reservation not in self._active_reservations:
            raise CampaignAccountingError("reservation is not active")

    @staticmethod
    def _exceeds(actual: CampaignResources, claim: CampaignResources) -> bool:
        return any(
            getattr(actual, item.name) > getattr(claim, item.name)
            for item in fields(_MutableResources)
        )
