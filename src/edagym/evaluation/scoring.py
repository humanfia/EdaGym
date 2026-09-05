"""Deterministic measurement aggregation and task-bound score derivation."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import ROUND_HALF_EVEN, Context, Decimal, localcontext
from fractions import Fraction

from edagym.canonical import canonical_digest
from edagym.evaluation.model import (
    AggregatedMeasurement,
    CandidateScore,
    ParetoVectorScore,
    ScalarScore,
    ScorerEligibilityKind,
    StageResult,
)
from edagym.evaluation.promotion import scorer_eligibility, validate_stage_results
from edagym.specs.common import Identifier, Seed128Hex
from edagym.specs.task import Aggregation, MeasurementSpec, MetricDirection, TaskSpec


def measurement_sample_seeds(
    task_seed: Seed128Hex,
    measurement_id: Identifier,
    repetitions: int,
) -> tuple[Seed128Hex, ...]:
    """Derive the immutable sample schedule for one measurement vector."""

    if repetitions < 1:
        raise ValueError("measurement sampling requires at least one repetition")
    seeds = tuple(
        canonical_digest(
            {
                "measurement_id": measurement_id,
                "sample_index": sample_index,
                "task_seed": task_seed,
            },
            domain="measurement-sample-seed-v1",
        ).removeprefix("sha256:")[:32]
        for sample_index in range(repetitions)
    )
    if len(seeds) != len(set(seeds)):
        raise RuntimeError("measurement sample seed derivation produced a collision")
    return seeds


def aggregate_samples(
    specification: MeasurementSpec,
    samples: Sequence[Decimal],
) -> Decimal:
    """Apply the aggregation declared by one measurement specification."""

    if len(samples) != specification.repetitions:
        raise ValueError("measurement sample count differs from its specification")
    if not samples:
        raise ValueError("measurement aggregation requires at least one sample")
    ordered = tuple(sorted(samples))
    if specification.aggregation is Aggregation.MINIMUM:
        return ordered[0]
    if specification.aggregation is Aggregation.MAXIMUM:
        return ordered[-1]
    if specification.aggregation is Aggregation.MEAN:
        return _rounded_fraction(
            sum((Fraction(sample) for sample in ordered), Fraction(0)) / len(ordered),
            specification.aggregation_precision_digits,
        )
    if specification.aggregation is Aggregation.MEDIAN:
        midpoint = len(ordered) // 2
        if len(ordered) % 2:
            return ordered[midpoint]
        return _rounded_fraction(
            (Fraction(ordered[midpoint - 1]) + Fraction(ordered[midpoint])) / 2,
            specification.aggregation_precision_digits,
        )
    if specification.aggregation is Aggregation.WORST:
        if specification.direction is MetricDirection.MINIMIZE:
            return ordered[-1]
        if specification.direction is MetricDirection.MAXIMIZE:
            return ordered[0]
        if specification.direction is MetricDirection.TARGET:
            target = specification.target
            if target is None:
                raise ValueError("target measurement has no target value")
            return max(
                ordered,
                key=lambda value: (
                    abs(Fraction(value) - Fraction(target)),
                    Fraction(value),
                ),
            )
        raise ValueError("worst aggregation requires an optimization direction")
    raise TypeError("unsupported measurement aggregation")


def aggregate_measurements(
    task: TaskSpec,
    results: Sequence[StageResult],
) -> tuple[AggregatedMeasurement, ...]:
    """Derive the exact aggregate vector declared by a task."""

    eligibility = scorer_eligibility(task, results)
    if eligibility.state is not ScorerEligibilityKind.READY:
        raise ValueError("measurements can be aggregated only when scoring is ready")
    validated = validate_stage_results(task, results)
    evidence = {
        measurement.measurement_id: measurement
        for result in validated
        for measurement in result.measurements
    }
    return tuple(
        AggregatedMeasurement(
            measurement_id=specification.measurement_id,
            value=aggregate_samples(
                specification,
                evidence[specification.measurement_id].samples,
            ),
        )
        for specification in task.measurements
    )


def build_candidate_score(
    task: TaskSpec,
    results: Sequence[StageResult],
) -> CandidateScore:
    """Build a raw Pareto vector or an explicitly configured scalar score."""

    measurements = aggregate_measurements(task, results)
    return build_score_from_aggregates(
        task,
        measurements,
    )


def build_score_from_aggregates(
    task: TaskSpec,
    measurements: tuple[AggregatedMeasurement, ...],
) -> CandidateScore:
    """Bind one already derived vector to the task's scoring mode."""

    expected_ids = tuple(measurement.measurement_id for measurement in task.measurements)
    actual_ids = tuple(measurement.measurement_id for measurement in measurements)
    if actual_ids != expected_ids or not measurements:
        raise ValueError("aggregate vector differs from the task measurement schema")
    scorer = task.evaluation.scorer
    if scorer is None:
        return ParetoVectorScore(measurements=measurements)
    values = {
        measurement.measurement_id: Fraction(measurement.value)
        for measurement in measurements
    }
    weighted_sum = Fraction(scorer.intercept)
    for term in scorer.terms:
        weighted_sum += Fraction(term.coefficient) * values[term.measurement_id]
    return ScalarScore(
        measurements=measurements,
        value=_rounded_fraction(weighted_sum, scorer.precision_digits),
        direction=scorer.direction,
        scorer_revision_digest=scorer.revision_digest,
    )


def pareto_dominates(
    task: TaskSpec,
    left: ParetoVectorScore,
    right: ParetoVectorScore,
) -> bool:
    """Return whether the left raw vector is no worse and strictly better."""

    specifications = {
        measurement.measurement_id: measurement for measurement in task.measurements
    }
    expected = tuple(sorted(specifications))
    left_values = _score_values(left)
    right_values = _score_values(right)
    if tuple(sorted(left_values)) != expected or tuple(sorted(right_values)) != expected:
        raise ValueError("Pareto vectors do not match the task measurement schema")

    has_objective = False
    strictly_better = False
    for measurement_id in expected:
        specification = specifications[measurement_id]
        if specification.direction is MetricDirection.NONE:
            continue
        has_objective = True
        comparison = _objective_comparison(
            specification,
            left_values[measurement_id],
            right_values[measurement_id],
        )
        if comparison < 0:
            return False
        strictly_better = strictly_better or comparison > 0
    return has_objective and strictly_better


def _score_values(score: ParetoVectorScore) -> dict[str, Decimal]:
    return {
        measurement.measurement_id: measurement.value
        for measurement in score.measurements
    }


def _objective_comparison(
    specification: MeasurementSpec,
    left: Decimal,
    right: Decimal,
) -> int:
    if specification.direction is MetricDirection.MINIMIZE:
        left_objective, right_objective = -Fraction(left), -Fraction(right)
    elif specification.direction is MetricDirection.MAXIMIZE:
        left_objective, right_objective = Fraction(left), Fraction(right)
    elif specification.direction is MetricDirection.TARGET:
        target = specification.target
        if target is None:
            raise ValueError("target measurement has no target value")
        left_objective = -abs(Fraction(left) - Fraction(target))
        right_objective = -abs(Fraction(right) - Fraction(target))
    else:
        raise ValueError("non-objective measurement cannot be compared")
    return (left_objective > right_objective) - (left_objective < right_objective)


def _rounded_fraction(value: Fraction, precision_digits: int) -> Decimal:
    context = Context(prec=precision_digits, rounding=ROUND_HALF_EVEN)
    with localcontext(context):
        return Decimal(value.numerator) / Decimal(value.denominator)
