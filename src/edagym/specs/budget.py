"""Canonical model and execution limits for solving episodes."""

from __future__ import annotations

from typing import Self

from pydantic import model_validator

from edagym.specs.common import JcsNonNegativeInt, JcsPositiveInt, StrictModel


class ResourceBudget(StrictModel):
    max_turns: JcsPositiveInt
    max_tool_calls: JcsPositiveInt
    max_experiments: JcsPositiveInt
    max_wall_seconds: JcsPositiveInt
    max_eda_compute_seconds: JcsPositiveInt
    max_license_seconds: JcsNonNegativeInt
    max_artifact_bytes: JcsPositiveInt


class ModelBudget(StrictModel):
    max_requests: JcsPositiveInt
    max_input_tokens_per_request: JcsPositiveInt
    max_output_tokens_per_request: JcsPositiveInt
    max_input_tokens: JcsPositiveInt
    max_output_tokens: JcsPositiveInt
    max_total_tokens: JcsPositiveInt

    @model_validator(mode="after")
    def validate_request_capacity(self) -> Self:
        if self.max_input_tokens_per_request > self.max_input_tokens:
            raise ValueError("episode input limit does not admit one maximum request")
        if self.max_output_tokens_per_request > self.max_output_tokens:
            raise ValueError("episode output limit does not admit one maximum request")
        if (
            self.max_input_tokens_per_request + self.max_output_tokens_per_request
            > self.max_total_tokens
        ):
            raise ValueError("episode token limit does not admit one maximum request")
        if self.max_total_tokens > self.max_input_tokens + self.max_output_tokens:
            raise ValueError("episode token total cannot exceed its directional limits")
        return self


class EpisodeBudget(ModelBudget, ResourceBudget):
    """A benchmark's complete solving budget, composed from the shared limit domains."""

    @property
    def model_budget(self) -> ModelBudget:
        return ModelBudget.model_validate(self.model_dump(include=set(ModelBudget.model_fields)))

    @property
    def resources(self) -> ResourceBudget:
        return ResourceBudget.model_validate(
            self.model_dump(include=set(ResourceBudget.model_fields))
        )
