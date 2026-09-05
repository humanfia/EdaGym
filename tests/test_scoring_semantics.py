"""Evidence for deterministic aggregation and explicit scalar ownership."""

from __future__ import annotations

from decimal import Decimal, localcontext

import pytest
from pydantic import ValidationError

from edagym.evaluation import (
    MeasurementEvidence,
    ParetoVectorScore,
    PassedOutcome,
    ScalarScore,
    StageResult,
    aggregate_samples,
    build_candidate_score,
    measurement_sample_seeds,
    pareto_dominates,
)
from edagym.specs.task import (
    NOT_APPLICABLE_LIBRARY_DIGEST,
    Aggregation,
    MeasurementSpec,
    MeasurementUnit,
    MetricDirection,
    TaskSpec,
)
from tests.factories import scalar_task_spec, task_spec


@pytest.mark.parametrize(
    ("aggregation", "direction", "target", "samples", "expected"),
    (
        (Aggregation.MINIMUM, MetricDirection.MINIMIZE, None, ("5", "1", "3"), "1"),
        (Aggregation.MAXIMUM, MetricDirection.MAXIMIZE, None, ("5", "1", "3"), "5"),
        (Aggregation.MEAN, MetricDirection.MINIMIZE, None, ("2", "3", "7"), "4"),
        (Aggregation.MEDIAN, MetricDirection.MINIMIZE, None, ("2", "8", "4", "6"), "5"),
        (Aggregation.WORST, MetricDirection.MINIMIZE, None, ("2", "8", "4"), "8"),
        (Aggregation.WORST, MetricDirection.MAXIMIZE, None, ("2", "8", "4"), "2"),
        (Aggregation.WORST, MetricDirection.TARGET, "10", ("8", "13", "9"), "13"),
    ),
)
def test_measurement_aggregation_obeys_the_task_contract(
    aggregation: Aggregation,
    direction: MetricDirection,
    target: str | None,
    samples: tuple[str, ...],
    expected: str,
) -> None:
    specification = MeasurementSpec(
        measurement_id="metric",
        producer_stage_id="qor",
        unit=MeasurementUnit.DIMENSIONLESS,
        library_id="not_applicable",
        library_digest=NOT_APPLICABLE_LIBRARY_DIGEST,
        corner="not_applicable",
        mode="analysis",
        direction=direction,
        repetitions=len(samples),
        aggregation=aggregation,
        target=None if target is None else Decimal(target),
    )

    assert aggregate_samples(
        specification,
        tuple(Decimal(sample) for sample in samples),
    ) == Decimal(expected)


def test_scalar_scores_require_an_immutable_task_resource() -> None:
    base = task_spec()
    results = _passing_results(
        (
            MeasurementEvidence(
                measurement_id="cell_count",
                samples=(Decimal(7),),
            ),
        )
    )

    raw = build_candidate_score(base, results)
    assert isinstance(raw, ParetoVectorScore)
    scalar_task = scalar_task_spec()
    scalar = build_candidate_score(scalar_task, results)

    assert isinstance(scalar, ScalarScore)
    assert scalar.value == Decimal(993)
    scorer = scalar_task.evaluation.scorer
    assert scorer is not None
    assert scalar.scorer_revision_digest == scorer.revision_digest
    document = scalar_task.model_dump(mode="python")
    scorer_resource = next(
        resource
        for resource in document["resources"]
        if resource["resource_id"] == scorer.implementation_resource
    )
    scorer_resource["content_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="canonical definition"):
        TaskSpec.model_validate(document)

    unsupported = scalar_task.model_dump(mode="python")
    unsupported["evaluation"]["scorer"]["expression"] = {
        "operator": "arbitrary",
        "source": "cell_count",
    }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TaskSpec.model_validate(unsupported)


def test_measurement_sample_schedule_is_unique_and_bound_to_its_inputs() -> None:
    task_seed = "00000000000000000000000000000007"
    schedule = measurement_sample_seeds(task_seed, "cell_count", 8)

    assert schedule == measurement_sample_seeds(task_seed, "cell_count", 8)
    assert len(schedule) == len(set(schedule)) == 8
    assert schedule != measurement_sample_seeds(task_seed, "throughput", 8)
    assert schedule != measurement_sample_seeds(
        "00000000000000000000000000000008",
        "cell_count",
        8,
    )
    assert schedule[:4] == measurement_sample_seeds(task_seed, "cell_count", 4)


def test_raw_vector_scoring_requires_an_objective() -> None:
    task = task_spec()
    measurement = task.measurements[0].model_copy(
        update={"direction": MetricDirection.NONE}
    )

    with pytest.raises(ValidationError, match="at least one objective"):
        TaskSpec.model_validate(
            {
                **task.model_dump(mode="python"),
                "measurements": (measurement,),
            }
        )


def test_aggregation_is_independent_of_process_decimal_context() -> None:
    base = task_spec()
    measurement = base.measurements[0].model_copy(
        update={
            "aggregation": Aggregation.MEAN,
            "aggregation_precision_digits": 8,
            "repetitions": 3,
        }
    )
    task = TaskSpec.model_validate(
        {**base.model_dump(mode="python"), "measurements": (measurement,)}
    )
    results = _passing_results(
        (
            MeasurementEvidence(
                measurement_id="cell_count",
                samples=(Decimal(1), Decimal(0), Decimal(0)),
            ),
        )
    )

    with localcontext() as context:
        context.prec = 4
        low_context = build_candidate_score(task, results)
    with localcontext() as context:
        context.prec = 50
        high_context = build_candidate_score(task, results)

    assert low_context == high_context
    assert isinstance(low_context, ParetoVectorScore)
    assert low_context.measurements[0].value == Decimal("0.33333333")


def test_pareto_comparison_uses_each_declared_direction() -> None:
    base = task_spec()
    throughput = MeasurementSpec(
        measurement_id="throughput",
        producer_stage_id="qor",
        unit=MeasurementUnit.MEGAHERTZ,
        library_id="not_applicable",
        library_digest=NOT_APPLICABLE_LIBRARY_DIGEST,
        corner="not_applicable",
        mode="analysis",
        direction=MetricDirection.MAXIMIZE,
        repetitions=1,
        aggregation=Aggregation.MEDIAN,
        valid_minimum=Decimal(0),
    )
    task = TaskSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "measurements": (*base.measurements, throughput),
        }
    )
    left = build_candidate_score(
        task,
        _passing_results(
            (
                MeasurementEvidence(
                    measurement_id="cell_count", samples=(Decimal(7),)
                ),
                MeasurementEvidence(
                    measurement_id="throughput", samples=(Decimal(500),)
                ),
            )
        ),
    )
    right = build_candidate_score(
        task,
        _passing_results(
            (
                MeasurementEvidence(
                    measurement_id="cell_count", samples=(Decimal(8),)
                ),
                MeasurementEvidence(
                    measurement_id="throughput", samples=(Decimal(400),)
                ),
            )
        ),
    )
    tradeoff = build_candidate_score(
        task,
        _passing_results(
            (
                MeasurementEvidence(
                    measurement_id="cell_count", samples=(Decimal(6),)
                ),
                MeasurementEvidence(
                    measurement_id="throughput", samples=(Decimal(300),)
                ),
            )
        ),
    )

    assert isinstance(left, ParetoVectorScore)
    assert isinstance(right, ParetoVectorScore)
    assert isinstance(tradeoff, ParetoVectorScore)
    assert pareto_dominates(task, left, right)
    assert not pareto_dominates(task, left, tradeoff)
    assert not pareto_dominates(task, tradeoff, left)


def _passing_results(
    measurements: tuple[MeasurementEvidence, ...],
) -> tuple[StageResult, ...]:
    return (
        StageResult(stage_id="functional", outcome=PassedOutcome()),
        StageResult(
            stage_id="qor",
            outcome=PassedOutcome(),
            measurements=measurements,
        ),
    )
