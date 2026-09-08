"""Immutable model-set and paid campaign envelopes."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.providers.numeric import JcsNonNegativeInt, JcsPositiveInt
from edagym.specs.common import (
    CanonicalDecimal,
    Digest,
    Identifier,
    ModelLabel,
    SchemaVersion,
    Seed128Hex,
    ServiceTierLabel,
    StrictModel,
)

DateStamp = Annotated[str, StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")]


class ModelCategory(StrEnum):
    FRONTIER_REASONING = "frontier_reasoning"
    CODING_AGENT = "coding_agent"
    BALANCED = "balanced"
    HIGH_THROUGHPUT = "high_throughput"
    PREVIOUS_GENERATION = "previous_generation"


REQUIRED_MODEL_CATEGORIES = frozenset(
    {
        ModelCategory.FRONTIER_REASONING,
        ModelCategory.CODING_AGENT,
        ModelCategory.BALANCED,
        ModelCategory.HIGH_THROUGHPUT,
    }
)


class ModelReferenceKind(StrEnum):
    SNAPSHOT = "snapshot"
    ALIAS = "alias"
    UNKNOWN = "unknown"


class FeatureSupport(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class RouteQualification(StrictModel):
    """Capabilities observed by the route's single paid provider canary."""

    authentication: Literal[True] = True
    responses_protocol: Literal[True] = True
    usage_reporting: Literal[True] = True
    structured_output: Literal[True] = True
    typed_tool_call: Literal[True] = True
    reasoning_control: FeatureSupport
    requested_service_tier: ServiceTierLabel | None = None
    provider_reported_service_tier: ServiceTierLabel | None = None
    observed_input_token_floor: JcsNonNegativeInt = 0
    canary_tool_schema_digest: Digest
    canary_evidence_digest: Digest


class ModelRoute(StrictModel):
    route_id: Identifier
    requested_model: ModelLabel
    provider_reported_model: ModelLabel
    reference_kind: ModelReferenceKind
    categories: Annotated[tuple[ModelCategory, ...], Field(min_length=1)]
    qualification: RouteQualification
    provider_attestation_digest: Digest | None = None

    @field_validator("categories")
    @classmethod
    def normalize_categories(
        cls,
        value: tuple[ModelCategory, ...],
    ) -> tuple[ModelCategory, ...]:
        if len(value) != len(set(value)):
            raise ValueError("model route categories must be unique")
        return tuple(sorted(value))


class RouteExclusionReason(StrEnum):
    UNAVAILABLE = "unavailable"
    AUTHENTICATION_REJECTED = "authentication_rejected"
    PROTOCOL_INCOMPATIBLE = "protocol_incompatible"
    TOOL_CALL_UNAVAILABLE = "tool_call_unavailable"
    STRUCTURED_OUTPUT_UNAVAILABLE = "structured_output_unavailable"
    USAGE_UNAVAILABLE = "usage_unavailable"
    ROUTE_REMAPPED = "route_remapped"
    PROBE_BUDGET_EXHAUSTED = "probe_budget_exhausted"


class ExcludedRoute(StrictModel):
    requested_model: ModelLabel
    reason: RouteExclusionReason
    evidence_digest: Digest


class CategoryExclusionReason(StrEnum):
    NO_DISCOVERED_ROUTE = "no_discovered_route"
    NO_QUALIFIED_ROUTE = "no_qualified_route"
    PROBE_BUDGET_EXHAUSTED = "probe_budget_exhausted"


class UncoveredCategory(StrictModel):
    category: ModelCategory
    reason: CategoryExclusionReason
    evidence_digest: Digest


class ModelSetManifest(StrictModel):
    """Frozen, capability-tested routes; model labels do not assert backend identity."""

    schema_version: SchemaVersion = 1
    provider_config_digest: Digest
    discovery_digest: Digest
    resolved_on: DateStamp
    routes: Annotated[tuple[ModelRoute, ...], Field(min_length=1)]
    exclusions: tuple[ExcludedRoute, ...] = ()
    uncovered_categories: tuple[UncoveredCategory, ...] = ()

    @field_validator("routes")
    @classmethod
    def normalize_routes(cls, value: tuple[ModelRoute, ...]) -> tuple[ModelRoute, ...]:
        return tuple(sorted(value, key=lambda route: route.route_id))

    @field_validator("resolved_on")
    @classmethod
    def validate_date(cls, value: str) -> str:
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError("resolved_on must be a valid calendar date") from None
        return value

    @field_validator("exclusions")
    @classmethod
    def normalize_exclusions(
        cls,
        value: tuple[ExcludedRoute, ...],
    ) -> tuple[ExcludedRoute, ...]:
        return tuple(sorted(value, key=lambda route: route.requested_model))

    @field_validator("uncovered_categories")
    @classmethod
    def normalize_uncovered_categories(
        cls,
        value: tuple[UncoveredCategory, ...],
    ) -> tuple[UncoveredCategory, ...]:
        return tuple(sorted(value, key=lambda item: item.category))

    @model_validator(mode="after")
    def validate_route_set(self) -> Self:
        route_ids = [route.route_id for route in self.routes]
        requested = [route.requested_model for route in self.routes]
        excluded = [route.requested_model for route in self.exclusions]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("model route identifiers must be unique")
        if len(requested) != len(set(requested)):
            raise ValueError("requested model labels must be unique")
        if len(excluded) != len(set(excluded)):
            raise ValueError("excluded model labels must be unique")
        if set(requested) & set(excluded):
            raise ValueError("a model label cannot be both qualified and excluded")
        covered = {category for route in self.routes for category in route.categories}
        uncovered = [item.category for item in self.uncovered_categories]
        if len(uncovered) != len(set(uncovered)):
            raise ValueError("each uncovered model category may be recorded once")
        if any(category not in REQUIRED_MODEL_CATEGORIES for category in uncovered):
            raise ValueError("only required model categories need exclusion evidence")
        if covered & set(uncovered):
            raise ValueError("a model category cannot be both covered and excluded")
        if (covered & REQUIRED_MODEL_CATEGORIES) | set(uncovered) != REQUIRED_MODEL_CATEGORIES:
            raise ValueError("every required model category needs a route or exclusion evidence")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-model-set-v1")


class RetryCondition(StrEnum):
    CONNECT_FAILURE = "connect_failure"
    SERVER_UNAVAILABLE = "server_unavailable"
    RATE_LIMITED = "rate_limited"


class RetryPolicy(StrictModel):
    max_request_attempts: JcsPositiveInt
    backoff_milliseconds: JcsNonNegativeInt
    retry_conditions: tuple[RetryCondition, ...] = ()

    @field_validator("retry_conditions")
    @classmethod
    def normalize_conditions(
        cls,
        value: tuple[RetryCondition, ...],
    ) -> tuple[RetryCondition, ...]:
        if len(value) != len(set(value)):
            raise ValueError("retry conditions must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_retries(self) -> Self:
        if self.max_request_attempts > 1 and not self.retry_conditions:
            raise ValueError("multiple request attempts require explicit retry conditions")
        if self.max_request_attempts == 1 and self.retry_conditions:
            raise ValueError("retry conditions require multiple request attempts")
        return self


class CampaignTokenLimits(StrictModel):
    """Directional and combined hard caps at request, trial, and campaign scope."""

    max_requests: JcsPositiveInt
    max_requests_per_trial: JcsPositiveInt
    max_input_tokens_per_request: JcsPositiveInt
    max_output_tokens_per_request: JcsPositiveInt
    max_input_tokens_per_trial: JcsPositiveInt
    max_output_tokens_per_trial: JcsPositiveInt
    max_total_tokens_per_trial: JcsPositiveInt
    max_input_tokens: JcsPositiveInt
    max_output_tokens: JcsPositiveInt
    max_total_tokens: JcsPositiveInt

    @model_validator(mode="after")
    def validate_hard_limits(self) -> Self:
        request_total = self.max_input_tokens_per_request + self.max_output_tokens_per_request
        if self.max_requests_per_trial > self.max_requests:
            raise ValueError("per-trial request limit cannot exceed the campaign limit")
        if self.max_input_tokens_per_request > self.max_input_tokens_per_trial:
            raise ValueError("trial input limit does not admit one maximum request")
        if self.max_output_tokens_per_request > self.max_output_tokens_per_trial:
            raise ValueError("trial output limit does not admit one maximum request")
        if self.max_input_tokens_per_trial > self.max_input_tokens:
            raise ValueError("per-trial input limit cannot exceed the campaign limit")
        if self.max_output_tokens_per_trial > self.max_output_tokens:
            raise ValueError("per-trial output limit cannot exceed the campaign limit")
        if request_total > self.max_total_tokens_per_trial:
            raise ValueError("trial token limit does not admit one maximum request")
        if self.max_total_tokens_per_trial > (
            self.max_input_tokens_per_trial + self.max_output_tokens_per_trial
        ):
            raise ValueError("trial total token limit cannot exceed directional limits")
        if self.max_total_tokens_per_trial > self.max_total_tokens:
            raise ValueError("trial token limit cannot exceed the campaign token limit")
        if self.max_total_tokens > self.max_input_tokens + self.max_output_tokens:
            raise ValueError("total token limit cannot exceed directional limits")
        return self


class CampaignExecutionLimits(StrictModel):
    """Non-token hard caps with independent trial and campaign ceilings."""

    max_turns_per_trial: JcsPositiveInt
    max_tool_calls_per_trial: JcsPositiveInt
    max_wall_seconds_per_trial: JcsPositiveInt
    max_eda_compute_seconds_per_trial: JcsPositiveInt
    max_license_seconds_per_trial: JcsNonNegativeInt
    max_artifact_bytes_per_trial: JcsPositiveInt
    max_turns: JcsPositiveInt
    max_tool_calls: JcsPositiveInt
    max_wall_seconds: JcsPositiveInt
    max_eda_compute_seconds: JcsPositiveInt
    max_license_seconds: JcsNonNegativeInt
    max_artifact_bytes: JcsPositiveInt

    @model_validator(mode="after")
    def validate_scope_limits(self) -> Self:
        pairs = (
            (self.max_turns_per_trial, self.max_turns, "turn"),
            (self.max_tool_calls_per_trial, self.max_tool_calls, "tool-call"),
            (self.max_wall_seconds_per_trial, self.max_wall_seconds, "wall-time"),
            (
                self.max_eda_compute_seconds_per_trial,
                self.max_eda_compute_seconds,
                "EDA-compute",
            ),
            (self.max_license_seconds_per_trial, self.max_license_seconds, "license-time"),
            (self.max_artifact_bytes_per_trial, self.max_artifact_bytes, "artifact"),
        )
        for trial_limit, campaign_limit, label in pairs:
            if trial_limit > campaign_limit:
                raise ValueError(f"per-trial {label} limit cannot exceed the campaign limit")
        return self


class SpendLimitKind(StrEnum):
    UNKNOWN = "unknown"
    CAPPED = "capped"


class UnknownSpendLimit(StrictModel):
    kind: Literal[SpendLimitKind.UNKNOWN] = SpendLimitKind.UNKNOWN


class CappedSpendLimit(StrictModel):
    kind: Literal[SpendLimitKind.CAPPED] = SpendLimitKind.CAPPED
    currency: Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
    amount: Annotated[CanonicalDecimal, Field(gt=0)]


SpendLimit = Annotated[
    UnknownSpendLimit | CappedSpendLimit,
    Field(discriminator="kind"),
]


class CampaignScope(StrEnum):
    END_TO_END_SMOKE = "end_to_end_smoke"
    MODEL_COMPARISON_PILOT = "model_comparison_pilot"
    COMMON_CORE = "common_core"
    REASONING_EFFORT_SENSITIVITY = "reasoning_effort_sensitivity"
    EXPANDED_BREADTH = "expanded_breadth"


class StopPolicy(StrEnum):
    HARD_LIMIT = "hard_limit"


class CampaignSpec(StrictModel):
    """Immutable envelope controlling a comparable, bounded paid evaluation."""

    schema_version: SchemaVersion = 1
    campaign_id: Identifier
    scope: CampaignScope
    model_set_digest: Digest
    route_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    task_release_digests: Annotated[tuple[Digest, ...], Field(min_length=1)]
    environment_digests: Annotated[tuple[Digest, ...], Field(min_length=1)]
    harness_digests: Annotated[tuple[Digest, ...], Field(min_length=1)]
    prompt_digest: Digest
    tool_schema_digest: Digest
    feedback_policy_digest: Digest
    reasoning_efforts: Annotated[
        tuple[Annotated[str, StringConstraints(min_length=1, max_length=32)], ...],
        Field(min_length=1),
    ]
    service_tier: ServiceTierLabel
    paired_trial_seeds: Annotated[tuple[Seed128Hex, ...], Field(min_length=1)]
    task_order_seed: Seed128Hex
    retry_policy: RetryPolicy
    token_limits: CampaignTokenLimits
    execution_limits: CampaignExecutionLimits
    provider_spend_limit: SpendLimit
    stop_policy: Literal[StopPolicy.HARD_LIMIT] = StopPolicy.HARD_LIMIT

    @field_validator(
        "task_release_digests",
        "environment_digests",
        "harness_digests",
        "route_ids",
        "reasoning_efforts",
    )
    @classmethod
    def normalize_unique_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("campaign comparison dimensions must be unique")
        return tuple(sorted(value))

    @field_validator("paired_trial_seeds")
    @classmethod
    def normalize_unique_seeds(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("paired trial seeds must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        repetitions = len(self.paired_trial_seeds)
        if self.scope is CampaignScope.END_TO_END_SMOKE and (
            len(self.task_release_digests) < 1
            or len(self.route_ids) != 1
            or len(self.reasoning_efforts) != 1
            or repetitions != 1
        ):
            raise ValueError(
                "end-to-end smoke campaigns require at least one task, one route, "
                "one reasoning effort, and one repetition"
            )
        if self.scope in {
            CampaignScope.MODEL_COMPARISON_PILOT,
            CampaignScope.COMMON_CORE,
        } and len(self.task_release_digests) < 1:
            raise ValueError("comparison campaigns require at least one task")
        if self.scope is CampaignScope.REASONING_EFFORT_SENSITIVITY and len(
            self.reasoning_efforts
        ) < 2:
            raise ValueError(
                "reasoning effort sensitivity campaigns require at least two reasoning efforts"
            )
        if self.retry_policy.max_request_attempts > self.token_limits.max_requests_per_trial:
            raise ValueError("trial request budget cannot satisfy the retry policy")
        return self

    @property
    def repetitions(self) -> int:
        return len(self.paired_trial_seeds)

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-v1")
