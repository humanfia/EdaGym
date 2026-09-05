"""Deterministic task instances and immutable release manifests."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import (
    Digest,
    Identifier,
    Redistribution,
    SchemaVersion,
    Seed128Hex,
    Sensitivity,
    StrictModel,
    Visibility,
    validate_relative_path,
)


class ParameterValueKind(StrEnum):
    INTEGER = "integer"
    BOOLEAN = "boolean"
    CHOICE = "choice"


class IntegerParameterValue(StrictModel):
    kind: Literal[ParameterValueKind.INTEGER] = ParameterValueKind.INTEGER
    parameter_id: Identifier
    value: int


class BooleanParameterValue(StrictModel):
    kind: Literal[ParameterValueKind.BOOLEAN] = ParameterValueKind.BOOLEAN
    parameter_id: Identifier
    value: bool


class ChoiceParameterValue(StrictModel):
    kind: Literal[ParameterValueKind.CHOICE] = ParameterValueKind.CHOICE
    parameter_id: Identifier
    value: Annotated[str, Field(min_length=1, max_length=160)]


ParameterValue = Annotated[
    IntegerParameterValue | BooleanParameterValue | ChoiceParameterValue,
    Field(discriminator="kind"),
]


class TaskInstanceIdentity(StrictModel):
    task_family: Identifier
    authoring_revision: Annotated[int, Field(ge=1)]
    task_spec_digest: Digest
    generator_digest: Digest
    seed: Seed128Hex
    parameters: tuple[ParameterValue, ...] = ()

    @field_validator("parameters")
    @classmethod
    def normalize_parameters(cls, value: tuple[ParameterValue, ...]) -> tuple[ParameterValue, ...]:
        return tuple(sorted(value, key=lambda item: item.parameter_id))

    @model_validator(mode="after")
    def validate_parameter_ownership(self) -> Self:
        identifiers = [item.parameter_id for item in self.parameters]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("an instance may bind each parameter only once")
        return self


class GeneratedFile(StrictModel):
    path: str
    content_digest: Digest
    media_type: Annotated[str, Field(min_length=1, max_length=120)]
    source_resource_ids: tuple[Identifier, ...] = ()
    visibility: Visibility
    sensitivity: Sensitivity
    redistribution: Redistribution

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @field_validator("source_resource_ids")
    @classmethod
    def normalize_sources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("generated-file source resources must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_publication_policy(self) -> Self:
        if self.visibility is Visibility.PUBLIC and (
            self.sensitivity is not Sensitivity.PUBLIC
            or self.redistribution is not Redistribution.ALLOWED
        ):
            raise ValueError("public generated files require public, redistributable data")
        if self.sensitivity is Sensitivity.SECRET:
            raise ValueError("secret data cannot be persisted as a generated task file")
        return self


class TaskInstance(StrictModel):
    schema_version: SchemaVersion = 1
    identity: TaskInstanceIdentity
    generated_files: tuple[GeneratedFile, ...]

    @field_validator("generated_files")
    @classmethod
    def normalize_files(cls, value: tuple[GeneratedFile, ...]) -> tuple[GeneratedFile, ...]:
        return tuple(sorted(value, key=lambda item: item.path))

    @model_validator(mode="after")
    def validate_files(self) -> Self:
        paths = [item.path for item in self.generated_files]
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("generated-file paths must be unique and non-empty")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="task-instance-v1")


class MutantQualification(StrictModel):
    mutant_resource_id: Identifier
    evidence_digest: Digest
    rejected: Literal[True] = True


class ReleaseQualificationKind(StrEnum):
    SAIL_RTL = "sail_rtl"
    EDA_FLOW_CANDIDATE = "eda_flow_candidate"
    EDA_FLOW = "eda_flow"


class ReleaseQualification(StrictModel):
    kind: Literal[ReleaseQualificationKind.SAIL_RTL] = ReleaseQualificationKind.SAIL_RTL
    reference_evidence_digest: Digest
    known_answer_evidence_digests: tuple[Digest, ...]
    mutant_results: tuple[MutantQualification, ...]
    simulator_evidence_digests: tuple[Digest, ...]
    synthesis_evidence_digest: Digest
    formal_evidence_digest: Digest | None = None
    temporal_evidence_digest: Digest
    structural_evidence_digest: Digest
    reference_passed: Literal[True] = True

    @field_validator(
        "known_answer_evidence_digests",
        "simulator_evidence_digests",
    )
    @classmethod
    def normalize_evidence(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("qualification evidence digests must be unique")
        return tuple(sorted(value))

    @field_validator("mutant_results")
    @classmethod
    def normalize_mutants(
        cls, value: tuple[MutantQualification, ...]
    ) -> tuple[MutantQualification, ...]:
        return tuple(sorted(value, key=lambda item: item.mutant_resource_id))

    @model_validator(mode="after")
    def validate_qualification(self) -> Self:
        if not self.known_answer_evidence_digests:
            raise ValueError("release qualification requires known-answer evidence")
        if len(self.simulator_evidence_digests) < 2:
            raise ValueError("release qualification requires two independent simulators")
        mutants = [item.mutant_resource_id for item in self.mutant_results]
        if len(mutants) < 3 or len(mutants) != len(set(mutants)):
            raise ValueError("release qualification requires three unique rejected mutants")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="release-qualification-v1")


class NegativeCandidateQualification(StrictModel):
    candidate_resource_id: Identifier
    evidence_digest: Digest
    rejected: Literal[True] = True


class FlowReleaseCandidateQualification(StrictModel):
    kind: Literal[ReleaseQualificationKind.EDA_FLOW_CANDIDATE] = (
        ReleaseQualificationKind.EDA_FLOW_CANDIDATE
    )
    authoring_source_digest: Digest
    release_eligible: Literal[False] = False


class FlowReleaseQualification(StrictModel):
    kind: Literal[ReleaseQualificationKind.EDA_FLOW] = ReleaseQualificationKind.EDA_FLOW
    witness_resource_id: Identifier
    witness_evidence_digest: Digest
    negative_results: tuple[NegativeCandidateQualification, ...]
    release_eligible: Literal[True] = True

    @field_validator("negative_results")
    @classmethod
    def normalize_negative_results(
        cls, value: tuple[NegativeCandidateQualification, ...]
    ) -> tuple[NegativeCandidateQualification, ...]:
        identifiers = [item.candidate_resource_id for item in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("flow releases require unique rejected negative candidates")
        return tuple(sorted(value, key=lambda item: item.candidate_resource_id))

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="flow-release-qualification-v1")


TaskReleaseQualification = Annotated[
    ReleaseQualification | FlowReleaseCandidateQualification | FlowReleaseQualification,
    Field(discriminator="kind"),
]


class ReleaseManifest(StrictModel):
    schema_version: SchemaVersion = 1
    task_spec_digest: Digest
    task_instance_digest: Digest
    participant_bundle_digest: Digest
    verifier_bundle_digest: Digest
    environment_digests: tuple[Digest, ...]
    files: tuple[GeneratedFile, ...]
    qualification: TaskReleaseQualification

    @field_validator("environment_digests")
    @classmethod
    def normalize_environments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("release environments must be unique and non-empty")
        return tuple(sorted(value))

    @field_validator("files")
    @classmethod
    def normalize_files(cls, value: tuple[GeneratedFile, ...]) -> tuple[GeneratedFile, ...]:
        return tuple(sorted(value, key=lambda item: item.path))

    @model_validator(mode="after")
    def validate_projection_separation(self) -> Self:
        if self.participant_bundle_digest == self.verifier_bundle_digest:
            raise ValueError("participant and verifier bundles must be distinct")
        paths = [item.path for item in self.files]
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("release file paths must be unique and non-empty")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="release-manifest-v1")
