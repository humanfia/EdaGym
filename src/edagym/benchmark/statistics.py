"""Frozen denominators, paired lineage resampling, and multiplicity control."""

from __future__ import annotations

import hashlib
import itertools
import math
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import TypedDict

from edagym.benchmark.model import (
    BenchmarkSpec,
    ContrastResult,
    DifficultyContrast,
    InformationStatus,
    ModelContrast,
    TrialObservation,
)

Vector = tuple[float, ...]
BlockGroup = tuple[Vector, ...]


@dataclass(frozen=True)
class PairedData:
    """Validated final cells, with incomplete lineage blocks excluded jointly."""

    blocks: dict[str, dict[str, Vector]]
    retention: dict[str, Decimal]
    invalid_rate: Decimal
    valid_rows: int
    failures: dict[str, int]


class QualityGate(TypedDict):
    rates: dict[str, Decimal | None]
    uppers: dict[str, Decimal | None]
    roster_mean: Decimal | None
    roster_lower: Decimal | None
    invalid_rate: Decimal
    block_counts: dict[str, int]
    block_counts_by_stratum: dict[str, dict[str, int]]
    block_retention_by_stratum: dict[str, Decimal]
    stratum_rates: dict[str, dict[str, Decimal]]
    failure_counts: dict[str, int]
    valid_rows: int
    information_status: InformationStatus


def paired_data(spec: BenchmarkSpec, observations: Iterable[TrialObservation]) -> PairedData:
    """Reject contradictory records and retain missing cells in the planned denominator."""

    cases = {
        case.task_instance_digest: (stratum, case)
        for stratum in spec.strata for case in stratum.cases
    }
    cells = {cell.cell_id: cell for cell in spec.evaluation_cells}
    observed: dict[tuple[str, str, int], TrialObservation] = {}
    failures: Counter[str] = Counter()
    bad_blocks: set[str] = set()
    valid_rows = 0
    for row in observations:
        if row.task_instance_digest not in cases or row.cell_id not in cells:
            raise ValueError("observation is outside the frozen benchmark matrix")
        stratum, case = cases[row.task_instance_digest]
        if (
            row.model_id != cells[row.cell_id].model_id
            or row.block_id != case.block_id
            or row.engineering_layer != stratum.engineering_layer
            or row.difficulty_id != stratum.difficulty_id
            or row.repetition_index >= spec.repetition_count
        ):
            raise ValueError("observation disagrees with its frozen matrix binding")
        key = (row.task_instance_digest, row.cell_id, row.repetition_index)
        if key in observed:
            raise ValueError("final observations must contain each matrix cell only once")
        observed[key] = row
        valid_rows += int(row.valid)
        if row.failure_kind is not None:
            failures[row.failure_kind] += 1
        elif not row.valid:
            failures["invalid_trial"] += 1
        if not row.valid:
            bad_blocks.add(case.block_id)

    expected = len(cases) * len(cells) * spec.repetition_count
    missing = expected - len(observed)
    if missing:
        failures["missing_trial"] = missing
    for task, (_stratum, case) in cases.items():
        if any(
            (task, cell, repeat) not in observed
            for cell in cells for repeat in range(spec.repetition_count)
        ):
            bad_blocks.add(case.block_id)

    cells_by_model: dict[str, tuple[str, ...]] = {
        model: tuple(cell.cell_id for cell in cells.values() if cell.model_id == model)
        for model in {cell.model_id for cell in cells.values()}
    }
    blocks: dict[str, dict[str, Vector]] = {}
    retention: dict[str, Decimal] = {}
    for stratum in spec.strata:
        block_cases: dict[str, list[str]] = defaultdict(list)
        for case in stratum.cases:
            block_cases[case.block_id].append(case.task_instance_digest)
        valid_blocks: dict[str, Vector] = {}
        for block, tasks in sorted(block_cases.items()):
            if block in bad_blocks:
                continue
            valid_blocks[block] = tuple(
                sum(
                    sum(
                        sum(
                            int(observed[(task, cell_id, repeat)].outcome)
                            for cell_id in cells_by_model[model]
                        ) / len(cells_by_model[model])
                        for repeat in range(spec.repetition_count)
                    ) / spec.repetition_count
                    for task in tasks
                ) / len(tasks)
                for model in spec.model_ids
            )
        blocks[stratum.stratum_id] = valid_blocks
        retention[stratum.stratum_id] = Decimal(len(valid_blocks)) / len(block_cases)
    return PairedData(
        blocks=blocks,
        retention=retention,
        invalid_rate=Decimal(expected - valid_rows) / expected,
        valid_rows=valid_rows,
        failures=dict(sorted(failures.items())),
    )


def compute_quality_gate(
    spec: BenchmarkSpec, observations: Iterable[TrialObservation]
) -> QualityGate:
    data = paired_data(spec, observations)
    models = spec.model_ids
    rates: dict[str, Decimal | None] = {model: None for model in models}
    uppers: dict[str, Decimal | None] = dict(rates)
    stratum_rates: dict[str, dict[str, Decimal]] = {}
    counts = {sid: len(blocks) for sid, blocks in data.blocks.items()}
    for sid, blocks in data.blocks.items():
        stratum_rates[sid] = {
            model: _decimal(sum(vector[index] for vector in blocks.values()) / len(blocks))
            for index, model in enumerate(models)
        } if blocks else {}
    roster_mean = None
    roster_lower = None
    information = InformationStatus.INSUFFICIENT
    if all(counts.values()):
        groups = _weighted_groups(spec, data)
        points = _group_mean(groups, len(models))
        rates = {model: _decimal(points[index]) for index, model in enumerate(models)}
        roster_mean = _decimal(sum(points) / len(points))
        if min(counts.values()) >= 2:
            samples = _bootstrap_groups(groups, spec.bootstrap_seed, spec.bootstrap_resamples)
            alpha = float(spec.window_alpha)
            for index, model in enumerate(models):
                values = [sample[index] for sample in samples]
                if min(values) < max(values):
                    uppers[model] = _decimal(_quantile(values, 1 - alpha))
            means = [sum(sample) / len(sample) for sample in samples]
            if min(means) < max(means):
                roster_lower = _decimal(_quantile(means, alpha))
            if (
                all(value is not None for value in uppers.values())
                and roster_lower is not None
                and spec.bootstrap_resamples >= spec.minimum_resamples
            ):
                information = InformationStatus.AVAILABLE
    return {
        "rates": rates,
        "uppers": uppers,
        "roster_mean": roster_mean,
        "roster_lower": roster_lower,
        "invalid_rate": data.invalid_rate,
        "block_counts": {model: sum(counts.values()) for model in models},
        "block_counts_by_stratum": {
            sid: {model: count for model in models} for sid, count in counts.items()
        },
        "block_retention_by_stratum": data.retention,
        "stratum_rates": stratum_rates,
        "failure_counts": data.failures,
        "valid_rows": data.valid_rows,
        "information_status": information,
    }


def compute_paired_contrasts(
    spec: BenchmarkSpec, observations: Iterable[TrialObservation]
) -> tuple[ContrastResult, ...]:
    data = paired_data(spec, observations)
    models = spec.model_ids
    results: list[ContrastResult] = []
    for contrast in spec.contrast_hypotheses:
        groups: tuple[BlockGroup, ...] = ()
        if isinstance(contrast, ModelContrast) and all(data.blocks.values()):
            left = models.index(contrast.left_model_id)
            right = models.index(contrast.right_model_id)
            groups = tuple(
                tuple(
                    (vector[left] - vector[right],)
                    for vector in group
                )
                for group in _weighted_groups(spec, data)
            )
        elif isinstance(contrast, DifficultyContrast):
            strata = {
                item.difficulty_id: item.stratum_id for item in spec.strata
                if item.engineering_layer == contrast.engineering_layer
            }
            easier = data.blocks[strata[contrast.easier_difficulty_id]]
            harder = data.blocks[strata[contrast.harder_difficulty_id]]
            if easier and easier.keys() == harder.keys():
                groups = (tuple(
                    ((sum(easier[block]) - sum(harder[block])) / len(models),)
                    for block in sorted(easier)
                ),)
        if not groups or any(len(group) < 2 for group in groups):
            results.append(ContrastResult(
                contrast_id=contrast.contrast_id,
                left_model_id=(
                    contrast.left_model_id if isinstance(contrast, ModelContrast) else None
                ),
                right_model_id=(
                    contrast.right_model_id if isinstance(contrast, ModelContrast) else None
                ),
                left_minus_right=Decimal(0),
                information_status=InformationStatus.INSUFFICIENT,
            ))
            continue
        effect = _group_mean(groups, 1)[0]
        seed = spec.bootstrap_seed ^ _stable_seed(contrast.contrast_id)
        samples = [item[0] for item in _bootstrap_groups(groups, seed, spec.bootstrap_resamples)]
        available = min(samples) < max(samples)
        p_value = _permutation_p_value(groups, seed, spec.bootstrap_resamples)
        results.append(ContrastResult(
            contrast_id=contrast.contrast_id,
            left_model_id=(
                contrast.left_model_id if isinstance(contrast, ModelContrast) else None
            ),
            right_model_id=(
                contrast.right_model_id if isinstance(contrast, ModelContrast) else None
            ),
            left_minus_right=_decimal(effect),
            lower_bound=_decimal(_quantile(samples, 0.025)) if available else None,
            upper_bound=_decimal(_quantile(samples, 0.975)) if available else None,
            p_value=_decimal(p_value) if available else None,
            information_status=(
                InformationStatus.AVAILABLE if available else InformationStatus.INSUFFICIENT
            ),
        ))
    ordered = sorted(enumerate(results), key=lambda pair: pair[1].p_value or Decimal(1))
    adjusted = Decimal(0)
    for rank, (index, result) in enumerate(ordered):
        if result.p_value is None:
            continue
        adjusted = max(adjusted, min(Decimal(1), result.p_value * (len(results) - rank)))
        results[index] = result.model_copy(update={
            "adjusted_p_value": adjusted,
            "significant": adjusted <= spec.contrast_alpha and result.left_minus_right > 0,
        })
    return tuple(results)


def bootstrap_interval(
    values: Sequence[float], *, seed: int, resamples: int, confidence: float = 0.95
) -> tuple[float, float] | None:
    if len(values) < 2 or not 0 < confidence < 1 or resamples < 100:
        return None
    groups = (tuple((float(value),) for value in values),)
    samples = [item[0] for item in _bootstrap_groups(groups, seed, resamples)]
    if min(samples) == max(samples):
        return None
    alpha = (1 - confidence) / 2
    return _quantile(samples, alpha), _quantile(samples, 1 - alpha)


def wilson_interval(
    successes: int, trials: int, z: float = 1.959963984540054
) -> tuple[float, float] | None:
    """Binomial diagnostic only; this does not replace the paired estimator."""

    if trials <= 0 or successes < 0 or successes > trials:
        return None
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return max(0.0, centre - radius), min(1.0, centre + radius)


def _weighted_groups(spec: BenchmarkSpec, data: PairedData) -> tuple[BlockGroup, ...]:
    # Resample complete blocks independently within each frozen stratum. The
    # model vector for a block is multiplied by its stratum weight; bootstrap
    # then preserves both pairing and the declared denominator.
    weights = {item.stratum_id: float(item.weight) for item in spec.strata}
    return tuple(
        tuple(
            tuple(weights[sid] * value for value in data.blocks[sid][block])
            for block in sorted(data.blocks[sid])
        )
        for sid in sorted(data.blocks)
    )


def _group_mean(groups: tuple[BlockGroup, ...], width: int) -> Vector:
    return tuple(
        sum(sum(vector[index] for vector in group) / len(group) for group in groups)
        for index in range(width)
    )


def _bootstrap_groups(groups: tuple[BlockGroup, ...], seed: int, resamples: int) -> list[Vector]:
    rng = random.Random(seed)
    width = len(groups[0][0])
    samples: list[Vector] = []
    for _ in range(resamples):
        totals = [0.0] * width
        for group in groups:
            for _ in group:
                vector = group[rng.randrange(len(group))]
                for index in range(width):
                    totals[index] += vector[index] / len(group)
        samples.append(tuple(totals))
    return samples


def _permutation_p_value(groups: tuple[BlockGroup, ...], seed: int, resamples: int) -> float:
    values = tuple(vector[0] / len(group) for group in groups for vector in group)
    observed = sum(values)
    if len(values) <= 16:
        permutations = itertools.product((-1, 1), repeat=len(values))
        count = int(sum(
            sum(value * sign for value, sign in zip(values, signs, strict=True))
            >= observed - 1e-12
            for signs in permutations
        ))
        return float(count) / float(2 ** len(values))
    rng = random.Random(seed)
    random_count = int(sum(
        sum(value if rng.getrandbits(1) else -value for value in values) >= observed - 1e-12
        for _ in range(resamples)
    ))
    return (random_count + 1) / (resamples + 1)


def _quantile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    position = fraction * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    ratio = position - low
    return float(ordered[low] * (1 - ratio) + ordered[high] * ratio)


def _decimal(value: float) -> Decimal:
    return Decimal(str(value))


def _stable_seed(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big")
