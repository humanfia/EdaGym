"""Resource domains and immutable approval envelope for paid campaigns."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Self

from pydantic import model_validator

from edagym.canonical import canonical_digest
from edagym.providers.campaign_schedule import CampaignHeader
from edagym.run.trial_model import StopReason
from edagym.specs.common import Digest, JcsNonNegativeInt, JcsPositiveInt, StrictModel


class CampaignResources(StrictModel):
    requests: JcsNonNegativeInt = 0
    input_tokens: JcsNonNegativeInt = 0
    output_tokens: JcsNonNegativeInt = 0
    turns: JcsNonNegativeInt = 0
    tool_calls: JcsNonNegativeInt = 0
    wall_seconds: JcsNonNegativeInt = 0
    eda_compute_seconds: JcsNonNegativeInt = 0
    license_seconds: JcsNonNegativeInt = 0
    artifact_bytes: JcsNonNegativeInt = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def is_zero(self) -> bool:
        return all(getattr(self, item.name) == 0 for item in fields(_MutableResources))


@dataclass(slots=True)
class _MutableResources:
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    turns: int = 0
    tool_calls: int = 0
    wall_seconds: int = 0
    eda_compute_seconds: int = 0
    license_seconds: int = 0
    artifact_bytes: int = 0

    def add(self, value: CampaignResources) -> None:
        for item in fields(self):
            setattr(self, item.name, getattr(self, item.name) + getattr(value, item.name))

    def subtract(self, value: CampaignResources) -> None:
        for item in fields(self):
            setattr(self, item.name, getattr(self, item.name) - getattr(value, item.name))

    def snapshot(self) -> CampaignResources:
        return CampaignResources(**{item.name: getattr(self, item.name) for item in fields(self)})


class BudgetDimension(StrEnum):
    REQUESTS = "requests"
    INPUT_TOKENS = "input_tokens"
    OUTPUT_TOKENS = "output_tokens"
    TOTAL_TOKENS = "total_tokens"
    TURNS = "turns"
    TOOL_CALLS = "tool_calls"
    WALL_SECONDS = "wall_seconds"
    EDA_COMPUTE_SECONDS = "eda_compute_seconds"
    LICENSE_SECONDS = "license_seconds"
    ARTIFACT_BYTES = "artifact_bytes"


_DIMENSION_STOP_REASON = {
    BudgetDimension.REQUESTS: StopReason.TOKEN_BUDGET,
    BudgetDimension.INPUT_TOKENS: StopReason.TOKEN_BUDGET,
    BudgetDimension.OUTPUT_TOKENS: StopReason.TOKEN_BUDGET,
    BudgetDimension.TOTAL_TOKENS: StopReason.TOKEN_BUDGET,
    BudgetDimension.TURNS: StopReason.INTERACTION_BUDGET,
    BudgetDimension.TOOL_CALLS: StopReason.TOOL_CALL_BUDGET,
    BudgetDimension.WALL_SECONDS: StopReason.WALL_BUDGET,
    BudgetDimension.EDA_COMPUTE_SECONDS: StopReason.EDA_COMPUTE_BUDGET,
    BudgetDimension.LICENSE_SECONDS: StopReason.LICENSE_BUDGET,
    BudgetDimension.ARTIFACT_BYTES: StopReason.STORAGE_BUDGET,
}


class CampaignBudgetExceeded(RuntimeError):
    """A dispatch was rejected before any external side effect."""

    def __init__(self, dimension: BudgetDimension, *, per_trial: bool) -> None:
        scope = "trial" if per_trial else "campaign"
        super().__init__(f"{scope} {dimension.value} budget reservation rejected")
        self.dimension = dimension
        self.per_trial = per_trial
        self.stop_reason = _DIMENSION_STOP_REASON[dimension]


class CampaignAccountingError(RuntimeError):
    """Raised for inconsistent retry, reservation, or settlement operations."""


class ProviderBudgetOverrun(CampaignAccountingError):
    """Exact provider usage exceeded its durable pre-dispatch reservation."""


class CampaignBudgetProjection(StrictModel):
    """Exact numeric bounds to approve before a campaign can be dispatched."""

    campaign_digest: Digest
    schedule_digest: Digest
    trial_count: JcsPositiveInt
    global_limits: CampaignResources
    global_total_token_limit: JcsPositiveInt
    per_trial_limits: CampaignResources
    per_trial_total_token_limit: JcsPositiveInt
    per_request_input_token_limit: JcsPositiveInt
    per_request_output_token_limit: JcsPositiveInt

    @classmethod
    def from_header(cls, header: CampaignHeader) -> CampaignBudgetProjection:
        global_limits = campaign_limits(header, per_trial=False)
        trial_limits = campaign_limits(header, per_trial=True)
        return cls(
            campaign_digest=header.campaign.digest,
            schedule_digest=header.schedule.digest,
            trial_count=len(header.schedule.trials),
            global_limits=_resource_limits(global_limits),
            global_total_token_limit=global_limits[BudgetDimension.TOTAL_TOKENS],
            per_trial_limits=_resource_limits(trial_limits),
            per_trial_total_token_limit=trial_limits[BudgetDimension.TOTAL_TOKENS],
            per_request_input_token_limit=header.benchmark.episode_budget.max_input_tokens_per_request,
            per_request_output_token_limit=header.benchmark.episode_budget.max_output_tokens_per_request,
        )

    @model_validator(mode="after")
    def validate_token_limits(self) -> Self:
        for item in fields(_MutableResources):
            if getattr(self.per_trial_limits, item.name) > getattr(self.global_limits, item.name):
                raise ValueError(f"per-trial {item.name} limit cannot exceed its campaign limit")
        if self.global_total_token_limit > self.global_limits.total_tokens:
            raise ValueError("global token total cannot exceed its directional limits")
        if self.per_trial_total_token_limit > self.per_trial_limits.total_tokens:
            raise ValueError("trial token total cannot exceed its directional limits")
        if self.per_request_input_token_limit > self.per_trial_limits.input_tokens:
            raise ValueError("trial input limit must admit one maximum provider request")
        if self.per_request_output_token_limit > self.per_trial_limits.output_tokens:
            raise ValueError("trial output limit must admit one maximum provider request")
        if (
            self.per_request_input_token_limit + self.per_request_output_token_limit
            > self.per_trial_total_token_limit
        ):
            raise ValueError("trial token total must admit one maximum provider request")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-budget-projection-v1")


def _resource_limits(limits: dict[BudgetDimension, int]) -> CampaignResources:
    return CampaignResources(
        requests=limits[BudgetDimension.REQUESTS],
        input_tokens=limits[BudgetDimension.INPUT_TOKENS],
        output_tokens=limits[BudgetDimension.OUTPUT_TOKENS],
        turns=limits[BudgetDimension.TURNS],
        tool_calls=limits[BudgetDimension.TOOL_CALLS],
        wall_seconds=limits[BudgetDimension.WALL_SECONDS],
        eda_compute_seconds=limits[BudgetDimension.EDA_COMPUTE_SECONDS],
        license_seconds=limits[BudgetDimension.LICENSE_SECONDS],
        artifact_bytes=limits[BudgetDimension.ARTIFACT_BYTES],
    )


def campaign_limits(
    header: CampaignHeader,
    *,
    per_trial: bool,
) -> dict[BudgetDimension, int]:
    """Derive both budget scopes for projection and reservation replay."""
    token = header.campaign.token_limits
    execution = header.campaign.execution_limits
    if per_trial:
        episode = header.benchmark.episode_budget
        return {
            BudgetDimension.REQUESTS: episode.max_requests,
            BudgetDimension.INPUT_TOKENS: episode.max_input_tokens,
            BudgetDimension.OUTPUT_TOKENS: episode.max_output_tokens,
            BudgetDimension.TOTAL_TOKENS: episode.max_total_tokens,
            BudgetDimension.TURNS: episode.max_turns,
            BudgetDimension.TOOL_CALLS: episode.max_tool_calls,
            BudgetDimension.WALL_SECONDS: episode.max_wall_seconds,
            BudgetDimension.EDA_COMPUTE_SECONDS: episode.max_eda_compute_seconds,
            BudgetDimension.LICENSE_SECONDS: episode.max_license_seconds,
            BudgetDimension.ARTIFACT_BYTES: episode.max_artifact_bytes,
        }
    return {
        BudgetDimension.REQUESTS: token.max_requests,
        BudgetDimension.INPUT_TOKENS: token.max_input_tokens,
        BudgetDimension.OUTPUT_TOKENS: token.max_output_tokens,
        BudgetDimension.TOTAL_TOKENS: token.max_total_tokens,
        BudgetDimension.TURNS: execution.max_turns,
        BudgetDimension.TOOL_CALLS: execution.max_tool_calls,
        BudgetDimension.WALL_SECONDS: execution.max_wall_seconds,
        BudgetDimension.EDA_COMPUTE_SECONDS: execution.max_eda_compute_seconds,
        BudgetDimension.LICENSE_SECONDS: execution.max_license_seconds,
        BudgetDimension.ARTIFACT_BYTES: execution.max_artifact_bytes,
    }
