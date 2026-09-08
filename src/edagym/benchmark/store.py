"""Private persistence for frozen benchmark specifications and schedules."""

from __future__ import annotations

from pathlib import Path

from edagym.authoring.factory import TaskFactory
from edagym.benchmark.model import BenchmarkSpec
from edagym.benchmark.schedule import BenchmarkSchedule, build_benchmark_schedule
from edagym.canonical import canonical_bytes
from edagym.policy.runtime_storage import private_directory, read_private, write_private
from edagym.specs.release import TaskInstance


class BenchmarkStoreError(ValueError):
    """A benchmark bundle is missing, stale, or crosses a private root boundary."""


def prepare_benchmark(
    spec: BenchmarkSpec,
    instances: tuple[TaskInstance, ...],
    root: Path,
) -> BenchmarkSchedule:
    """Freeze and atomically publish one qualified benchmark matrix."""

    schedule = build_benchmark_schedule(spec, instances=instances)
    directory = private_directory(root / "benchmarks" / spec.benchmark_id, create=True)
    write_private(directory / "spec.json", canonical_bytes(spec) + b"\n")
    write_private(directory / "schedule.json", canonical_bytes(schedule) + b"\n")
    return schedule


def load_prepared(root: Path, benchmark_id: str) -> tuple[BenchmarkSpec, BenchmarkSchedule]:
    directory = private_directory(root / "benchmarks" / benchmark_id)
    try:
        spec = BenchmarkSpec.model_validate_json(read_private(directory / "spec.json"))
        schedule = BenchmarkSchedule.model_validate_json(read_private(directory / "schedule.json"))
    except (OSError, ValueError) as error:
        raise BenchmarkStoreError("benchmark bundle is unreadable") from error
    if schedule.benchmark_digest != spec.digest:
        raise BenchmarkStoreError("benchmark schedule does not match its specification")
    return spec, schedule


def load_instances(root: Path, instance_ids: tuple[str, ...]) -> tuple[TaskInstance, ...]:
    factory = TaskFactory()
    try:
        return tuple(factory.load(root, item).instance for item in instance_ids)
    except (OSError, ValueError) as error:
        raise BenchmarkStoreError("benchmark task instance is unavailable") from error


__all__ = ["BenchmarkStoreError", "load_instances", "load_prepared", "prepare_benchmark"]
