"""Typed benchmark specification and observation records."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import (
    CanonicalDecimal,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    SchemaVersion,
    Seed128Hex,
    StrictModel,
)


class BenchmarkPhase(StrEnum):
    DEVELOPMENT = "development"
    CALIBRATION = "calibration"
    CONFIRMATORY_HOLDOUT = "confirmatory_holdout"


class EvaluationCell(StrictModel):
    cell_id: Identifier
    model_id: Identifier
    harness_id: Identifier
    policy_digest: Digest
    comparison_group: Identifier | None = None
    tier_rank: Annotated[int, Field(strict=True, ge=1)] | None = None

    @model_validator(mode="after")
    def validate_tier(self) -> Self:
        if (self.comparison_group is None) != (self.tier_rank is None):
            raise ValueError("model ordering requires both a comparison group and tier rank")
        return self


class BenchmarkCase(StrictModel):
    task_instance_digest: Digest
    block_id: Identifier


class InformationStatus(StrEnum):
    AVAILABLE = "available"
    INSUFFICIENT = "insufficient_information"


class ContrastKind(StrEnum):
    ADJACENT_MODEL = "adjacent_model"
    STRONG_WEAK_MODEL = "strong_weak_model"
    DIFFICULTY = "difficulty"


class ModelContrast(StrictModel):
    contrast_id: Identifier
    kind: Literal[ContrastKind.ADJACENT_MODEL, ContrastKind.STRONG_WEAK_MODEL]
    left_model_id: Identifier
    right_model_id: Identifier


class DifficultyContrast(StrictModel):
    contrast_id: Identifier
    kind: Literal[ContrastKind.DIFFICULTY] = ContrastKind.DIFFICULTY
    engineering_layer: Identifier
    easier_difficulty_id: Identifier
    harder_difficulty_id: Identifier


Contrast = Annotated[ModelContrast | DifficultyContrast, Field(discriminator="kind")]


class BenchmarkStratum(StrictModel):
    stratum_id: Identifier
    engineering_layer: Identifier
    difficulty_id: Identifier
    weight: Annotated[CanonicalDecimal, Field(gt=0)]
    cases: Annotated[tuple[BenchmarkCase, ...], Field(min_length=1)]

    @field_validator("cases")
    @classmethod
    def normalize_tasks(cls, value: tuple[BenchmarkCase, ...]) -> tuple[BenchmarkCase, ...]:
        ids = [case.task_instance_digest for case in value]
        if len(ids) != len(set(ids)):
            raise ValueError("benchmark strata require unique task instances")
        return tuple(sorted(value, key=lambda case: case.task_instance_digest))

    @property
    def task_instance_digests(self) -> tuple[str, ...]:
        return tuple(case.task_instance_digest for case in self.cases)


class EpisodeBudget(StrictModel):
    """The benchmark owns every solving limit for one scored episode."""

    max_requests: JcsPositiveInt
    max_input_tokens_per_request: JcsPositiveInt
    max_output_tokens_per_request: JcsPositiveInt
    max_input_tokens: JcsPositiveInt
    max_output_tokens: JcsPositiveInt
    max_total_tokens: JcsPositiveInt
    max_turns: JcsPositiveInt
    max_tool_calls: JcsPositiveInt
    max_experiments: JcsPositiveInt
    max_wall_seconds: JcsPositiveInt
    max_eda_compute_seconds: JcsPositiveInt
    max_license_seconds: JcsNonNegativeInt
    max_artifact_bytes: JcsPositiveInt

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


class BenchmarkSpec(StrictModel):
    """Frozen inputs for one finite benchmark series."""

    schema_version: Literal[2] = 2
    benchmark_id: Identifier
    revision: Annotated[int, Field(strict=True, ge=1)]
    parent_benchmark_id: Identifier | None = None
    phase: BenchmarkPhase
    strata: tuple[BenchmarkStratum, ...]
    evaluation_cells: tuple[EvaluationCell, ...]
    repetition_count: Annotated[int, Field(strict=True, ge=1)] = 1
    episode_budget: EpisodeBudget
    schedule_seed: Seed128Hex
    min_valid_blocks_per_stratum: Annotated[int, Field(strict=True, ge=1)] = 40
    max_invalid_rate: Annotated[CanonicalDecimal, Field(ge=0, le=Decimal("0.02"))] = Decimal("0.02")
    target_effect_size: Annotated[CanonicalDecimal, Field(ge=Decimal("0.05"), le=1)] = Decimal(
        "0.05"
    )
    error_budget: Annotated[CanonicalDecimal, Field(gt=0, le=Decimal("0.05"))] = Decimal("0.05")
    max_confirmatory_attempts: Annotated[int, Field(strict=True, ge=1, le=3)] = 3
    bootstrap_resamples: Annotated[int, Field(strict=True, ge=10_000)] = 10_000
    bootstrap_seed: Annotated[int, Field(strict=True, ge=0)] = 0
    contrast_hypotheses: tuple[Contrast, ...] = ()

    @field_validator("strata")
    @classmethod
    def normalize_strata(cls, value: tuple[BenchmarkStratum, ...]) -> tuple[BenchmarkStratum, ...]:
        if not value:
            raise ValueError("benchmark requires at least one stratum")
        ids = [item.stratum_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("benchmark stratum identifiers must be unique")
        total = sum((item.weight for item in value), Decimal(0))
        if total != Decimal(1):
            raise ValueError("benchmark stratum weights must sum to one")
        return tuple(sorted(value, key=lambda item: item.stratum_id))

    @field_validator("evaluation_cells")
    @classmethod
    def normalize_cells(cls, value: tuple[EvaluationCell, ...]) -> tuple[EvaluationCell, ...]:
        if not value:
            raise ValueError("benchmark requires at least one evaluation cell")
        ids = [item.cell_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("evaluation cell identifiers must be unique")
        return tuple(sorted(value, key=lambda item: item.cell_id))

    @model_validator(mode="after")
    def validate_task_coverage(self) -> Self:
        task_ids = [task for stratum in self.strata for task in stratum.task_instance_digests]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("a task instance may belong to one benchmark stratum only")
        if self.parent_benchmark_id == self.benchmark_id:
            raise ValueError("a benchmark cannot be its own parent")
        model_ids = {cell.model_id for cell in self.evaluation_cells}
        for contrast in self.contrast_hypotheses:
            if isinstance(contrast, ModelContrast):
                if contrast.left_model_id == contrast.right_model_id:
                    raise ValueError("a contrast must compare two distinct models")
                if {contrast.left_model_id, contrast.right_model_id} - model_ids:
                    raise ValueError("contrast hypotheses must reference evaluation models")
            else:
                difficulties = {
                    item.difficulty_id
                    for item in self.strata
                    if item.engineering_layer == contrast.engineering_layer
                }
                if (
                    contrast.easier_difficulty_id == contrast.harder_difficulty_id
                    or {contrast.easier_difficulty_id, contrast.harder_difficulty_id} - difficulties
                ):
                    raise ValueError("difficulty contrasts require two declared strata")
        domains = [(item.engineering_layer, item.difficulty_id) for item in self.strata]
        if len(domains) != len(set(domains)):
            raise ValueError("each layer and difficulty pair has one stratum owner")
        block_layers: dict[str, str] = {}
        for stratum in self.strata:
            for case in stratum.cases:
                layer = block_layers.setdefault(case.block_id, stratum.engineering_layer)
                if layer != stratum.engineering_layer:
                    raise ValueError("a lineage block cannot cross engineering layers")
        return self

    @field_validator("contrast_hypotheses")
    @classmethod
    def normalize_contrasts(
        cls,
        value: tuple[ModelContrast | DifficultyContrast, ...],
    ) -> tuple[ModelContrast | DifficultyContrast, ...]:
        ids = [item.contrast_id for item in value]
        if len(ids) != len(set(ids)):
            raise ValueError("contrast hypotheses must be unique")
        return tuple(sorted(value, key=lambda item: item.contrast_id))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="benchmark-spec-v2")

    @property
    def model_ids(self) -> tuple[str, ...]:
        return tuple(sorted({cell.model_id for cell in self.evaluation_cells}))

    @property
    def window_alpha(self) -> Decimal:
        return self.error_budget / (2 * self.max_confirmatory_attempts * (len(self.model_ids) + 1))

    @property
    def contrast_alpha(self) -> Decimal:
        return self.error_budget / (2 * self.max_confirmatory_attempts)

    @property
    def minimum_resamples(self) -> int:
        from math import ceil

        tail = min(self.window_alpha, self.contrast_alpha / max(1, len(self.contrast_hypotheses)))
        return max(10_000, ceil(Decimal(100) / tail))


class TrialObservation(StrictModel):
    """One final-candidate observation; invalid attempts remain in the ledger."""

    schema_version: SchemaVersion = 1
    model_id: Identifier
    cell_id: Identifier
    task_instance_digest: Digest
    block_id: Identifier
    engineering_layer: Identifier
    difficulty_id: Identifier
    outcome: bool
    valid: bool = True
    failure_kind: Identifier | None = None
    repetition_index: Annotated[int, Field(strict=True, ge=0)] = 0


class ContrastResult(StrictModel):
    """A paired effect estimate.  ``left_minus_right`` is the declared sign."""

    contrast_id: Identifier
    left_model_id: Identifier | None = None
    right_model_id: Identifier | None = None
    left_minus_right: CanonicalDecimal
    lower_bound: CanonicalDecimal | None = None
    upper_bound: CanonicalDecimal | None = None
    p_value: CanonicalDecimal | None = None
    adjusted_p_value: CanonicalDecimal | None = None
    significant: bool = False
    information_status: InformationStatus = InformationStatus.AVAILABLE


class BenchmarkQualityReport(StrictModel):
    """Evidence-derived status; it cannot alter the frozen benchmark rules."""

    schema_version: SchemaVersion = 1
    benchmark_digest: Digest
    framework_ready: bool
    station_campaign_complete: bool
    benchmark_quality_qualified: bool
    model_rates: dict[str, Decimal | None]
    model_upper_bounds: dict[str, Decimal | None]
    roster_mean: Decimal | None
    roster_lower_bound: Decimal | None
    invalid_rate: Decimal
    valid_block_counts: dict[str, int]
    failure_counts: dict[str, int]
    reasons: tuple[str, ...]
    bootstrap_resamples: int
    valid_block_counts_by_stratum: dict[str, dict[str, int]] = Field(default_factory=dict)
    block_retention_by_stratum: dict[str, Decimal] = Field(default_factory=dict)
    stratum_rates: dict[str, dict[str, Decimal]] = Field(default_factory=dict)
    contrast_results: tuple[ContrastResult, ...] = ()
    ideal_window_all_models: bool = False
    information_status: InformationStatus = InformationStatus.AVAILABLE

    @field_validator("reasons")
    @classmethod
    def normalize_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="benchmark-quality-report-v1")
