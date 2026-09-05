"""Portable identity of one settled credential-free runtime surface set."""

from __future__ import annotations

from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    IsolationSurface,
)
from edagym.runtime_surface_protocol import (
    RuntimeSurfaceBinding as RuntimeSurfaceBinding,
)
from edagym.specs.common import Digest, SchemaVersion, StrictModel
from edagym.specs.environment import EnvironmentSpec


def runtime_surface_export_policy_digest(environment: EnvironmentSpec) -> Digest:
    """Bind the artifact policy and canonical participant disclosure boundary."""

    from edagym.participants.model import PARTICIPANT_EVENT_VISIBILITY

    if type(environment) is not EnvironmentSpec:
        raise TypeError("runtime surface export policy requires an environment specification")
    participant_visibility = tuple(
        sorted(visibility.value for visibility in PARTICIPANT_EVENT_VISIBILITY)
    )
    return canonical_digest(
        {
            "artifact_policy": environment.artifact_policy,
            "participant_artifact_visibility": participant_visibility,
            "participant_event_visibility": participant_visibility,
        },
        domain="runtime-surface-export-policy-v1",
    )


class RuntimeSurfaceIdentity(StrictModel):
    """Path-free identity of one descriptor-bound preflight surface."""

    surface: IsolationSurface
    identity_digest: Digest


class RuntimeSurfaceManifest(StrictModel):
    """Public, path-free receipt for all isolation surfaces of one preflight."""

    schema_version: SchemaVersion = 1
    preflight_run_id: Digest
    preflight_record_digest: Digest
    run_binding_digest: Digest
    binding: RuntimeSurfaceBinding
    executor_receipt_digest: Digest
    launcher_receipt_digest: Digest
    artifact_closure_receipt_digest: Digest
    artifact_store_identity_digest: Digest
    surfaces: Annotated[tuple[RuntimeSurfaceIdentity, ...], Field(min_length=8, max_length=8)]

    @field_validator("surfaces")
    @classmethod
    def normalize_surfaces(
        cls,
        surfaces: tuple[RuntimeSurfaceIdentity, ...],
    ) -> tuple[RuntimeSurfaceIdentity, ...]:
        identities = {item.surface: item for item in surfaces}
        if len(identities) != len(surfaces) or set(identities) != set(REQUIRED_ISOLATION_SURFACES):
            raise ValueError("runtime surface manifest must cover every role exactly once")
        return tuple(identities[surface] for surface in REQUIRED_ISOLATION_SURFACES)

    @model_validator(mode="after")
    def validate_run_identity(self) -> Self:
        if self.preflight_run_id != self.run_binding_digest:
            raise ValueError("preflight run identity must equal its run binding digest")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="runtime-surface-manifest-v1")
