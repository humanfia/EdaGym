"""Mechanically derived JSON Schema documents for persisted specifications."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from pydantic import BaseModel

from edagym.benchmark.model import BenchmarkQualityReport, BenchmarkSpec, TrialObservation
from edagym.benchmark.schedule import BenchmarkSchedule
from edagym.config.model import EdaGymConfig
from edagym.drivers.qualification import BackendQualification
from edagym.providers.campaign import CampaignSpec
from edagym.providers.campaign_runner import CampaignRecord, CampaignReport
from edagym.release_commands import ReleaseCommandReceipt
from edagym.release_reporting import ReleaseReport
from edagym.run.manifest import RunManifest
from edagym.run.model import RunRecord
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import SessionSpec
from edagym.specs.task import TaskSpec

SchemaName = Literal[
    "backend_qualification",
    "benchmark",
    "benchmark_quality_report",
    "benchmark_schedule",
    "trial_observation",
    "config",
    "campaign",
    "campaign_record",
    "campaign_report",
    "release_command",
    "release_report",
    "task",
    "environment",
    "session",
    "task_instance",
    "release_manifest",
    "run_record",
    "run_manifest",
]

SCHEMA_MODELS: Mapping[SchemaName, type[BaseModel]] = MappingProxyType(
    {
        "backend_qualification": BackendQualification,
        "benchmark": BenchmarkSpec,
        "benchmark_quality_report": BenchmarkQualityReport,
        "benchmark_schedule": BenchmarkSchedule,
        "config": EdaGymConfig,
        "campaign": CampaignSpec,
        "campaign_record": CampaignRecord,
        "campaign_report": CampaignReport,
        "release_command": ReleaseCommandReceipt,
        "release_report": ReleaseReport,
        "task": TaskSpec,
        "environment": EnvironmentSpec,
        "session": SessionSpec,
        "task_instance": TaskInstance,
        "release_manifest": ReleaseManifest,
        "run_record": RunRecord,
        "run_manifest": RunManifest,
        "trial_observation": TrialObservation,
    }
)


def schema_document(name: SchemaName) -> dict[str, object]:
    """Derive one deterministic schema from its Pydantic semantic owner."""

    model = SCHEMA_MODELS[name]
    generated = model.model_json_schema(mode="validation")
    generated["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    generated["$id"] = f"https://edagym.local/schemas/v1/{name}.schema.json"
    return generated


def schema_index() -> dict[str, object]:
    """Return the digest-bound inventory of every generated schema."""

    entries = []
    for name in sorted(SCHEMA_MODELS):
        document = schema_document(name)
        entries.append(
            {
                "name": name,
                "path": f"{name}.schema.json",
                "digest": _schema_digest(document),
            }
        )
    return {"schema_version": 1, "schemas": entries}


def export_schemas(directory: Path) -> None:
    """Write canonical generated schemas and their digest index."""

    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name in sorted(SCHEMA_MODELS):
        (directory / f"{name}.schema.json").write_bytes(
            _schema_bytes(schema_document(name)) + b"\n"
        )
    (directory / "index.json").write_bytes(_schema_bytes(schema_index()) + b"\n")


def schema_exports_are_current(directory: Path) -> bool:
    """Compare committed schema bytes with their complete canonical derivation."""

    if directory.is_symlink() or not directory.is_dir():
        return False
    expected = {
        f"{name}.schema.json": _schema_bytes(schema_document(name)) + b"\n"
        for name in SCHEMA_MODELS
    }
    expected["index.json"] = _schema_bytes(schema_index()) + b"\n"
    try:
        actual_paths = tuple(directory.iterdir())
        if {path.name for path in actual_paths} != set(expected):
            return False
        return all(
            not path.is_symlink()
            and path.is_file()
            and path.read_bytes() == expected[path.name]
            for path in actual_paths
        )
    except OSError:
        return False


def _schema_bytes(value: object) -> bytes:
    """Encode JSON Schema, whose numeric bounds may exceed the RFC 8785 domain."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _schema_digest(value: object) -> str:
    payload = b"edagym\0json-schema-v1\0" + _schema_bytes(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
