"""Deterministic evaluation traversal and promotion rules."""

from __future__ import annotations

from collections.abc import Sequence

from edagym.evaluation.model import (
    HardGateState,
    HardGateStatus,
    OutcomeKind,
    ScorerEligibility,
    ScorerEligibilityKind,
    StageEligibility,
    StageEligibilityKind,
    StageOutcome,
    StageResult,
)
from edagym.specs.task import MeasurementSpec, StagePurpose, StageSpec, TaskSpec

_PROMOTING_OUTCOMES = frozenset({OutcomeKind.PASSED, OutcomeKind.PROVED})


def outcome_promotes(outcome: StageOutcome) -> bool:
    """Return whether an outcome permits dependent work to run."""

    return outcome.kind in _PROMOTING_OUTCOMES


def topological_stage_ids(task: TaskSpec) -> tuple[str, ...]:
    """Return the task stages in stable dependency order."""

    stages = _stage_index(task)
    indegree = {stage_id: len(stage.depends_on) for stage_id, stage in stages.items()}
    children: dict[str, list[str]] = {stage_id: [] for stage_id in stages}
    for stage in stages.values():
        for dependency in stage.depends_on:
            children[dependency].append(stage.stage_id)

    ready = sorted(stage_id for stage_id, degree in indegree.items() if degree == 0)
    ordered: list[str] = []
    while ready:
        stage_id = ready.pop(0)
        ordered.append(stage_id)
        for child_id in sorted(children[stage_id]):
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                ready.append(child_id)
                ready.sort()

    if len(ordered) != len(stages):
        raise ValueError("evaluation stages must form an acyclic graph")
    return tuple(ordered)


def validate_stage_results(
    task: TaskSpec, results: Sequence[StageResult]
) -> tuple[StageResult, ...]:
    """Validate a partial result snapshot and return it in topological order."""

    stages = _stage_index(task)
    result_index = _result_index(results)
    unknown_stages = set(result_index) - set(stages)
    if unknown_stages:
        raise ValueError(f"results reference unknown stages: {sorted(unknown_stages)!r}")

    measurements = {
        measurement.measurement_id: measurement for measurement in task.measurements
    }
    expected_by_stage: dict[str, set[str]] = {stage_id: set() for stage_id in stages}
    for measurement in task.measurements:
        expected_by_stage[measurement.producer_stage_id].add(measurement.measurement_id)

    for stage_id in topological_stage_ids(task):
        result = result_index.get(stage_id)
        if result is None:
            continue
        stage = stages[stage_id]
        for dependency in stage.depends_on:
            dependency_result = result_index.get(dependency)
            if dependency_result is None or not outcome_promotes(dependency_result.outcome):
                raise ValueError(
                    f"stage {stage_id!r} completed without a promoting dependency {dependency!r}"
                )
        _validate_measurement_evidence(result, measurements, expected_by_stage[stage_id])

    return tuple(
        result_index[stage_id]
        for stage_id in topological_stage_ids(task)
        if stage_id in result_index
    )


def stage_eligibility(
    task: TaskSpec, results: Sequence[StageResult], stage_id: str
) -> StageEligibility:
    """Derive whether a stage is complete, runnable, waiting, or blocked."""

    stages = _stage_index(task)
    if stage_id not in stages:
        raise ValueError(f"unknown evaluation stage {stage_id!r}")
    validated = validate_stage_results(task, results)
    result_index = _result_index(validated)
    if stage_id in result_index:
        return StageEligibility(stage_id=stage_id, state=StageEligibilityKind.COMPLETED)

    ancestors = _ancestor_ids(stage_id, stages)
    blockers = tuple(
        ancestor
        for ancestor in ancestors
        if ancestor in result_index and not outcome_promotes(result_index[ancestor].outcome)
    )
    if blockers:
        return StageEligibility(
            stage_id=stage_id,
            state=StageEligibilityKind.BLOCKED,
            blocking_stage_ids=blockers,
        )

    waiting = tuple(
        dependency
        for dependency in stages[stage_id].depends_on
        if dependency not in result_index
    )
    if waiting:
        return StageEligibility(
            stage_id=stage_id,
            state=StageEligibilityKind.WAITING,
            waiting_stage_ids=waiting,
        )
    return StageEligibility(stage_id=stage_id, state=StageEligibilityKind.READY)


def hard_gate_status(task: TaskSpec, results: Sequence[StageResult]) -> HardGateStatus:
    """Derive gate success without treating observation success as gate success."""

    validated = validate_stage_results(task, results)
    result_index = _result_index(validated)
    hard_gates = tuple(
        stage
        for stage in task.evaluation.stages
        if stage.purpose is StagePurpose.HARD_GATE
    )
    failed_gates: list[str] = []
    blockers: set[str] = set()
    pending_gates: list[str] = []
    for gate in hard_gates:
        result = result_index.get(gate.stage_id)
        if result is not None:
            if not outcome_promotes(result.outcome):
                failed_gates.append(gate.stage_id)
            continue
        eligibility = stage_eligibility(task, validated, gate.stage_id)
        if eligibility.state is StageEligibilityKind.BLOCKED:
            blockers.update(eligibility.blocking_stage_ids)
        else:
            pending_gates.append(gate.stage_id)

    if failed_gates or blockers:
        return HardGateStatus(
            state=HardGateState.FAILED,
            failed_gate_ids=tuple(failed_gates),
            blocking_stage_ids=tuple(blockers),
            pending_gate_ids=tuple(pending_gates),
        )
    if pending_gates:
        return HardGateStatus(
            state=HardGateState.PENDING,
            pending_gate_ids=tuple(pending_gates),
        )
    return HardGateStatus(state=HardGateState.SUCCEEDED)


def scorer_eligibility(task: TaskSpec, results: Sequence[StageResult]) -> ScorerEligibility:
    """Derive whether task-bound scoring has complete, promoted inputs."""

    validated = validate_stage_results(task, results)
    result_index = _result_index(validated)
    gate_status = hard_gate_status(task, validated)
    if gate_status.state is HardGateState.FAILED:
        return ScorerEligibility(
            state=ScorerEligibilityKind.BLOCKED,
            blocking_stage_ids=tuple(
                {*gate_status.failed_gate_ids, *gate_status.blocking_stage_ids}
            ),
        )
    if gate_status.state is HardGateState.PENDING:
        return ScorerEligibility(
            state=ScorerEligibilityKind.WAITING,
            waiting_stage_ids=gate_status.pending_gate_ids,
        )
    if not task.measurements:
        return ScorerEligibility(state=ScorerEligibilityKind.NOT_CONFIGURED)

    producer_stage_ids = {
        measurement.producer_stage_id for measurement in task.measurements
    }
    nonpromoting = tuple(
        stage_id
        for stage_id in producer_stage_ids
        if stage_id in result_index and not outcome_promotes(result_index[stage_id].outcome)
    )
    if nonpromoting:
        return ScorerEligibility(
            state=ScorerEligibilityKind.BLOCKED,
            blocking_stage_ids=nonpromoting,
        )

    missing = producer_stage_ids - result_index.keys()
    blocked: set[str] = set()
    waiting: set[str] = set()
    for stage_id in missing:
        eligibility = stage_eligibility(task, validated, stage_id)
        if eligibility.state is StageEligibilityKind.BLOCKED:
            blocked.update(eligibility.blocking_stage_ids)
        else:
            waiting.add(stage_id)
    if blocked:
        return ScorerEligibility(
            state=ScorerEligibilityKind.BLOCKED,
            blocking_stage_ids=tuple(blocked),
        )
    if waiting:
        return ScorerEligibility(
            state=ScorerEligibilityKind.WAITING,
            waiting_stage_ids=tuple(waiting),
        )
    return ScorerEligibility(state=ScorerEligibilityKind.READY)


def _stage_index(task: TaskSpec) -> dict[str, StageSpec]:
    return {stage.stage_id: stage for stage in task.evaluation.stages}


def _result_index(results: Sequence[StageResult]) -> dict[str, StageResult]:
    indexed = {result.stage_id: result for result in results}
    if len(indexed) != len(results):
        raise ValueError("a result snapshot can contain only one result per stage")
    return indexed


def _ancestor_ids(stage_id: str, stages: dict[str, StageSpec]) -> tuple[str, ...]:
    ancestors: set[str] = set()
    pending = list(stages[stage_id].depends_on)
    while pending:
        dependency = pending.pop()
        if dependency in ancestors:
            continue
        ancestors.add(dependency)
        pending.extend(stages[dependency].depends_on)
    return tuple(sorted(ancestors))


def _validate_measurement_evidence(
    result: StageResult,
    specifications: dict[str, MeasurementSpec],
    expected: set[str],
) -> None:
    actual = {measurement.measurement_id for measurement in result.measurements}
    unknown = actual - set(specifications)
    if unknown:
        raise ValueError(f"stage result references unknown measurements: {sorted(unknown)!r}")
    misplaced = {
        measurement_id
        for measurement_id in actual
        if specifications[measurement_id].producer_stage_id != result.stage_id
    }
    if misplaced:
        raise ValueError(
            f"stage result contains measurements from another stage: {sorted(misplaced)!r}"
        )
    if outcome_promotes(result.outcome) and actual != expected:
        raise ValueError("a promoting result must contain every measurement produced by its stage")

    for evidence in result.measurements:
        specification = specifications[evidence.measurement_id]
        if len(evidence.samples) != specification.repetitions:
            raise ValueError(
                f"measurement {evidence.measurement_id!r} has an invalid sample count"
            )
        for sample in evidence.samples:
            if specification.valid_minimum is not None and sample < specification.valid_minimum:
                raise ValueError(
                    f"measurement {evidence.measurement_id!r} is below its valid minimum"
                )
            if specification.valid_maximum is not None and sample > specification.valid_maximum:
                raise ValueError(
                    f"measurement {evidence.measurement_id!r} is above its valid maximum"
                )
