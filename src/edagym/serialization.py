"""Strict YAML loading and canonical document dispatch."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from io import TextIOBase
from pathlib import Path
from typing import Any, Literal, TypeVar

import yaml
from pydantic import BaseModel
from yaml.nodes import MappingNode

from edagym.drivers.qualification import BackendQualification
from edagym.release_commands import ReleaseCommandReceipt
from edagym.release_reporting import ReleaseReport
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import SessionSpec
from edagym.specs.task import TaskSpec


class DuplicateKeyError(ValueError):
    """Raised when a YAML mapping contains the same key more than once."""


class UnsupportedSchemaVersion(ValueError):
    """Raised when no exact schema owner exists for an input document."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise DuplicateKeyError(f"duplicate YAML mapping key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


DocumentKind = Literal[
    "backend_qualification",
    "task",
    "environment",
    "session",
    "task_instance",
    "release_manifest",
    "release_command",
    "release_report",
]

PersistedDocument = (
    BackendQualification
    | TaskSpec
    | EnvironmentSpec
    | SessionSpec
    | TaskInstance
    | ReleaseManifest
    | ReleaseCommandReceipt
    | ReleaseReport
)

_MODEL_BY_KIND_AND_VERSION: Mapping[tuple[DocumentKind, int], type[PersistedDocument]] = {
    ("backend_qualification", 1): BackendQualification,
    ("task", 1): TaskSpec,
    ("environment", 1): EnvironmentSpec,
    ("session", 1): SessionSpec,
    ("task_instance", 1): TaskInstance,
    ("release_manifest", 1): ReleaseManifest,
    ("release_command", 1): ReleaseCommandReceipt,
    ("release_report", 1): ReleaseReport,
}


def load_yaml(source: str | bytes | TextIOBase) -> object:
    """Load one YAML document with duplicate keys rejected."""

    value = yaml.load(source, Loader=UniqueKeyLoader)
    if value is None:
        raise ValueError("a persisted document cannot be empty")
    return value


def load_document(data: object, *, kind: DocumentKind) -> PersistedDocument:
    """Validate a persisted document against its exact versioned owner."""

    if not isinstance(data, dict):
        raise ValueError("a persisted document must be a mapping")
    version = data.get("schema_version")
    if type(version) is not int:
        raise UnsupportedSchemaVersion("schema_version must be an integer")
    model = _MODEL_BY_KIND_AND_VERSION.get((kind, version))
    if model is None:
        raise UnsupportedSchemaVersion(f"unsupported {kind} schema version: {version}")
    return model.model_validate(data)


TDocument = TypeVar("TDocument", bound=BaseModel)


def load_yaml_document(path: Path, *, kind: DocumentKind) -> PersistedDocument:
    """Load and validate a YAML document from a regular file."""

    with path.open("r", encoding="utf-8") as stream:
        return load_document(load_yaml(stream), kind=kind)


def dump_for_schema(document: BaseModel) -> dict[str, Any]:
    """Return the complete JSON-compatible representation used for persistence."""

    return document.model_dump(
        mode="json",
        exclude_defaults=False,
        exclude_none=False,
        exclude_unset=False,
    )


def register_migration(
    _kind: DocumentKind,
    _source_version: int,
    _target_version: int,
    _migration: Callable[[Mapping[str, object]], Mapping[str, object]],
) -> None:
    """Reject speculative migrations until a real second schema has an owner."""

    raise UnsupportedSchemaVersion("no schema migrations are defined")
