"""Versioned benchmark contracts and evidence-derived quality reports."""

from edagym.benchmark.calibration import CalibrationReport, derive_calibration_report
from edagym.benchmark.model import (
    BenchmarkCase,
    BenchmarkPhase,
    BenchmarkQualityReport,
    BenchmarkSpec,
    BenchmarkStratum,
    ContrastResult,
    EvaluationCell,
    TrialObservation,
)
from edagym.benchmark.reporting import build_quality_report
from edagym.benchmark.schedule import (
    BenchmarkSchedule,
    ScheduledEvaluation,
    build_benchmark_schedule,
)
from edagym.benchmark.statistics import bootstrap_interval, compute_quality_gate
from edagym.benchmark.store import (
    BenchmarkStoreError,
    load_instances,
    load_prepared,
    prepare_benchmark,
)

__all__ = [
    "BenchmarkCase",
    "BenchmarkPhase",
    "BenchmarkQualityReport",
    "BenchmarkSchedule",
    "BenchmarkSpec",
    "BenchmarkStoreError",
    "BenchmarkStratum",
    "CalibrationReport",
    "ContrastResult",
    "EvaluationCell",
    "ScheduledEvaluation",
    "TrialObservation",
    "bootstrap_interval",
    "build_benchmark_schedule",
    "build_quality_report",
    "compute_quality_gate",
    "derive_calibration_report",
    "load_instances",
    "load_prepared",
    "prepare_benchmark",
]
