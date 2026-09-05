"""Explicit resource grants for trusted backend qualification workloads."""

from __future__ import annotations

from typing import Annotated, Self

from pydantic import Field, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, StrictModel
from edagym.specs.environment import ResourceLimits


class QualificationResourceGrant(StrictModel):
    """Environment-owned limits bound into one qualification evidence case."""

    limits: ResourceLimits
    command_timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=3600)]

    @model_validator(mode="after")
    def validate_timeout_budget(self) -> Self:
        if self.command_timeout_seconds > self.limits.wall_seconds:
            raise ValueError("command timeout exceeds the granted wall-time budget")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="backend-qualification-resource-grant-v1")
