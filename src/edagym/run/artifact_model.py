"""Content identities, disclosure metadata, and immutable file manifests."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
    validate_relative_path,
)
from edagym.specs.environment import ArtifactDisclosure


class BlobRef(StrictModel):
    digest: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0)]


class ArtifactRecord(ArtifactDisclosure):
    logical_id: Identifier
    blob: BlobRef
    media_type: Annotated[str, Field(min_length=1, max_length=127)]
    artifact_class: ArtifactClass


class ManifestEntry(StrictModel):
    path: str
    blob: BlobRef
    mode: Literal[0o644, 0o755]

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return validate_relative_path(value)


class ArtifactManifest(ArtifactDisclosure):
    schema_version: SchemaVersion = 1
    artifact_class: ArtifactClass
    entries: tuple[ManifestEntry, ...]

    @field_validator("entries")
    @classmethod
    def normalize_entries(cls, value: tuple[ManifestEntry, ...]) -> tuple[ManifestEntry, ...]:
        return tuple(sorted(value, key=lambda item: item.path))

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        paths = [entry.path for entry in self.entries]
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("artifact manifest paths must be unique and non-empty")
        path_objects = [PurePosixPath(path) for path in paths]
        for position, path in enumerate(path_objects):
            if any(
                path in other.parents or other in path.parents
                for other in path_objects[position + 1 :]
            ):
                raise ValueError("artifact manifest paths cannot be file-prefix conflicts")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="artifact-manifest-v1")


class CommittedManifest(StrictModel):
    semantic_digest: Digest
    blob: BlobRef
