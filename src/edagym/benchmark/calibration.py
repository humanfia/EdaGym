"""Calibration reports derived from valid paired observations."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable
from decimal import Decimal

from edagym.benchmark.model import BenchmarkSpec, TrialObservation
from edagym.benchmark.statistics import compute_quality_gate
from edagym.specs.common import Digest, StrictModel


class CalibrationReport(StrictModel):
    benchmark_digest: Digest
    rates_by_difficulty: dict[str, Decimal]
    rates_by_layer: dict[str, Decimal]
    valid_block_counts: dict[str, int]
    failure_mechanisms: dict[str, int]
    qualified_observation_count: int
    invalid_observation_count: int

    @property
    def digest(self) -> Digest:
        from edagym.canonical import canonical_digest

        return canonical_digest(self, domain="benchmark-calibration-report-v1")


def derive_calibration_report(
    spec: BenchmarkSpec,
    observations: tuple[TrialObservation, ...],
) -> CalibrationReport:
    gate = compute_quality_gate(spec, observations)
    valid = tuple(row for row in observations if row.valid)
    difficulty = _rate_map(valid, lambda row: row.difficulty_id)
    layers = _rate_map(valid, lambda row: row.engineering_layer)
    failures = Counter(row.failure_kind for row in observations if row.failure_kind is not None)
    return CalibrationReport(
        benchmark_digest=spec.digest,
        rates_by_difficulty=difficulty,
        rates_by_layer=layers,
        valid_block_counts={str(key): int(value) for key, value in gate["block_counts"].items()},
        failure_mechanisms=dict(sorted(failures.items())),
        qualified_observation_count=len(valid),
        invalid_observation_count=len(observations) - len(valid),
    )


def _rate_map(
    rows: tuple[TrialObservation, ...],
    key: Callable[[TrialObservation], str],
) -> dict[str, Decimal]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        grouped[str(key(row))].append(int(row.outcome))
    return {
        name: Decimal(str(sum(values) / len(values)))
        for name, values in sorted(grouped.items())
        if values
    }
