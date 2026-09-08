"""Deterministic benchmark matrix construction.

The benchmark specification owns the matrix dimensions.  This module only
derives an execution order and never stores tool paths or mutable run state.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import Field, model_validator

from edagym.benchmark.model import BenchmarkSpec
from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, Identifier, JcsNonNegativeInt, Seed128Hex, StrictModel
from edagym.specs.release import QualificationStatus, TaskInstance


class ScheduledEvaluation(StrictModel):
    """One immutable task/cell/repetition assignment."""

    ordinal: JcsNonNegativeInt
    evaluation_id: Identifier
    benchmark_digest: Digest
    stratum_id: Identifier
    task_instance_digest: Digest
    block_id: Identifier
    cell_id: Identifier
    model_id: Identifier
    harness_id: Identifier
    policy_digest: Digest
    repetition_index: JcsNonNegativeInt
    paired_seed: Seed128Hex
    task_order_index: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_identity(self) -> ScheduledEvaluation:
        if self.evaluation_id != _evaluation_id(self):
            raise ValueError("scheduled evaluation identifier does not match its binding")
        return self


class BenchmarkSchedule(StrictModel):
    """Frozen, contiguous order for one benchmark specification."""

    schema_version: Literal[2] = 2
    benchmark_digest: Digest
    entries: tuple[ScheduledEvaluation, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_order(self) -> BenchmarkSchedule:
        if tuple(entry.ordinal for entry in self.entries) != tuple(range(len(self.entries))):
            raise ValueError("benchmark schedule ordinals must be contiguous and zero-based")
        identifiers = [entry.evaluation_id for entry in self.entries]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("benchmark schedule evaluation identifiers must be unique")
        if any(entry.benchmark_digest != self.benchmark_digest for entry in self.entries):
            raise ValueError("benchmark schedule entries reference another benchmark")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="benchmark-schedule-v2")

    @property
    def size(self) -> int:
        return len(self.entries)


def require_qualified_cases(spec: BenchmarkSpec, instances: Iterable[TaskInstance]) -> None:
    """Admit the frozen roster only when every exact instance is qualified."""

    qualified = {
        instance.digest
        for instance in instances
        if instance.qualification is not None
        and instance.qualification.status is QualificationStatus.QUALIFIED
    }
    expected = {task for stratum in spec.strata for task in stratum.task_instance_digests}
    if expected - qualified:
        raise ValueError("benchmark schedule contains an unqualified task instance")


def build_benchmark_schedule(spec: BenchmarkSpec) -> BenchmarkSchedule:
    """Derive the sole task, cell, repetition order and lineage pairing."""

    benchmark_digest = spec.digest
    ordered_cases = sorted(
        ((stratum.stratum_id, case) for stratum in spec.strata for case in stratum.cases),
        key=lambda item: (
            canonical_digest(
                {"seed": spec.schedule_seed, "task": item[1].task_instance_digest},
                domain="benchmark-task-order-v2",
            ),
            item[1].task_instance_digest,
        ),
    )
    entries: list[ScheduledEvaluation] = []
    for repetition_index in range(spec.repetition_count):
        for task_order_index, (stratum_id, case) in enumerate(ordered_cases):
            paired_seed = canonical_digest(
                {
                    "seed": spec.schedule_seed,
                    "block": case.block_id,
                    "repetition": repetition_index,
                },
                domain="benchmark-paired-seed-v2",
            )[7:39]
            cells = sorted(
                spec.evaluation_cells,
                key=lambda cell: (
                    canonical_digest(
                        {"seed": paired_seed, "cell": cell.cell_id},
                        domain="benchmark-cell-order-v2",
                    ),
                    cell.cell_id,
                ),
            )
            for cell in cells:
                draft = ScheduledEvaluation.model_construct(
                    ordinal=len(entries),
                    evaluation_id="pending",
                    benchmark_digest=benchmark_digest,
                    stratum_id=stratum_id,
                    task_instance_digest=case.task_instance_digest,
                    block_id=case.block_id,
                    cell_id=cell.cell_id,
                    model_id=cell.model_id,
                    harness_id=cell.harness_id,
                    policy_digest=cell.policy_digest,
                    repetition_index=repetition_index,
                    paired_seed=paired_seed,
                    task_order_index=task_order_index,
                )
                entries.append(
                    ScheduledEvaluation.model_validate(
                        {
                            **draft.model_dump(mode="python"),
                            "evaluation_id": _evaluation_id(draft),
                        }
                    )
                )
    return BenchmarkSchedule(benchmark_digest=benchmark_digest, entries=tuple(entries))


def _evaluation_id(entry: ScheduledEvaluation) -> str:
    digest = canonical_digest(
        {
            "benchmark_digest": entry.benchmark_digest,
            "stratum_id": entry.stratum_id,
            "task_instance_digest": entry.task_instance_digest,
            "block_id": entry.block_id,
            "cell_id": entry.cell_id,
            "repetition_index": entry.repetition_index,
        },
        domain="benchmark-evaluation-v2",
    )
    return f"eval_{digest.removeprefix('sha256:')[:48]}"


__all__ = [
    "BenchmarkSchedule",
    "ScheduledEvaluation",
    "build_benchmark_schedule",
    "require_qualified_cases",
]
