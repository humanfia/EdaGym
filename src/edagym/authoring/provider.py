"""Path-free protocol for restricted task-authoring providers."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Final, Literal, Self

from pydantic import Field, StringConstraints, TypeAdapter, field_validator, model_validator

from edagym.authoring.clean_room import (
    CleanRoomCatalogAttestation,
    CleanRoomFamilyProjection,
)
from edagym.authoring.content import content_digest
from edagym.authoring.provider_process import (
    RestrictedProviderProcessError,
    invoke_trusted_executable,
    open_trusted_executable,
    provider_environment,
)
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.evaluation.model import StageResult
from edagym.evaluation.promotion import hard_gate_status
from edagym.policy.private_roots import (
    PrivateRootRegistration,
    PrivateRootRole,
    _bind_private_root_from_descriptor,
)
from edagym.specs.common import (
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    SchemaVersion,
    StrictModel,
    validate_relative_path,
)
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import (
    FlowReleaseCandidateQualification,
    IntegerParameterValue,
    ReleaseManifest,
    TaskInstance,
)
from edagym.specs.task import TaskSpec
from edagym.task_families.catalog import (
    PUBLIC_TASK_CATALOG_DIGEST,
    TaskFamilyDefinition,
    TaskRoot,
    families_for_root,
)

AUTHORING_PROVIDER_PROTOCOL_REVISION: Final[Literal[1]] = 1
_MAXIMUM_PROVIDER_RESPONSE_BYTES = 256 * 1024 * 1024
_MAXIMUM_PROVIDER_REQUEST_BYTES = 192 * 1024 * 1024
_MAXIMUM_MEMBER_BYTES = 32 * 1024 * 1024
_MAXIMUM_EXPORTED_BYTES = 128 * 1024 * 1024
_DIGEST_ADAPTER = TypeAdapter(Digest)


class AuthoringProviderError(RuntimeError):
    """A restricted provider violated the public authoring protocol."""


class PrivateAuthoringCapability(StrEnum):
    SAIL_RTL_CATALOG = "sail_rtl_catalog"
    EDA_FLOW_CATALOG = "eda_flow_catalog"


class PrivateEvaluatorIsolation(StrEnum):
    ROOTLESS_CONTAINER = "rootless_container"
    VIRTUAL_MACHINE = "virtual_machine"
    MICROVM = "microvm"


class PrivateProviderSecurityQualification(StrictModel):
    """Digest-only evidence that the provider confines untrusted candidates."""

    schema_version: SchemaVersion = 1
    provider_implementation_digest: Digest
    evaluator_isolation: PrivateEvaluatorIsolation
    candidate_execution_isolated: Literal[True] = True
    server_enforced_one_shot_leases: Literal[True] = True
    candidate_escape_evidence_digest: Digest
    lease_replay_rejection_evidence_digest: Digest
    network_confinement_evidence_digest: Digest
    verifier_confidentiality_evidence_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="private-provider-security-qualification-v1")


EvaluatorLeaseToken = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9_-]{43,128}$"),
]


class AuthoringProviderOperation(StrEnum):
    DESCRIBE = "describe"
    EXPORT = "export"
    DERIVE = "derive"
    QUALIFY = "qualify"
    OPEN_EVALUATOR = "open_evaluator"
    EVALUATE = "evaluate"


class ExportMemberRole(StrEnum):
    PUBLIC_FILE = "public_file"
    PARTICIPANT_FILE = "participant_file"
    VERIFIER_FILE = "verifier_file"
    TASK_SPEC_DOCUMENT = "task_spec_document"
    TASK_INSTANCE_DOCUMENT = "task_instance_document"
    AUTHOR_EVIDENCE = "author_evidence"
    FLOW_TASK_PACK = "flow_task_pack"


_PARTICIPANT_BUNDLE_ROLES = frozenset(
    {ExportMemberRole.PUBLIC_FILE, ExportMemberRole.PARTICIPANT_FILE}
)
_VERIFIER_BUNDLE_ROLES = frozenset({ExportMemberRole.VERIFIER_FILE})
_DERIVED_DOCUMENT_ROLES = frozenset(
    {
        ExportMemberRole.TASK_SPEC_DOCUMENT,
        ExportMemberRole.TASK_INSTANCE_DOCUMENT,
    }
)
_INSTANCE_BOUND_MEMBER_ROLES = (
    _PARTICIPANT_BUNDLE_ROLES | _VERIFIER_BUNDLE_ROLES | _DERIVED_DOCUMENT_ROLES
)


class FlowCandidateRole(StrEnum):
    FEASIBILITY_WITNESS = "feasibility_witness"
    SEMANTIC_NEGATIVE = "semantic_negative"


def flow_candidate_resource_id_for_role(
    candidate_id: str,
    role: FlowCandidateRole,
) -> str:
    prefix = (
        "witness" if role is FlowCandidateRole.FEASIBILITY_WITNESS else "negative"
    )
    return f"{prefix}.{candidate_id}"


def _root_for_capability(capability: PrivateAuthoringCapability) -> TaskRoot:
    if capability is PrivateAuthoringCapability.SAIL_RTL_CATALOG:
        return TaskRoot.SAIL_RTL
    return TaskRoot.EDA_FLOW


def _validate_family_capability(
    capability: PrivateAuthoringCapability | None,
    family: str,
) -> None:
    if capability is None:
        raise ValueError("task family requests require a capability")
    known = {item.family for item in families_for_root(_root_for_capability(capability))}
    if family not in known:
        raise ValueError("task family does not belong to the requested capability")


def validate_member_path_set(paths: tuple[str, ...]) -> None:
    """Reject duplicate paths and file/directory ancestor collisions."""

    ordered = sorted((PurePosixPath(path).parts, path) for path in paths)
    if len(ordered) != len({parts for parts, _path in ordered}):
        raise ValueError("provider member paths must be unique")
    for index, (parts, _path) in enumerate(ordered):
        for other_parts, _other_path in ordered[index + 1 :]:
            if len(other_parts) <= len(parts):
                continue
            if other_parts[: len(parts)] == parts:
                raise ValueError("provider member paths cannot be ancestors of other members")


def _validate_derivation_scope(
    capability: PrivateAuthoringCapability,
    derivation: PrivateDerivationScope,
) -> None:
    metadata = next(
        item
        for item in families_for_root(_root_for_capability(capability))
        if item.family == derivation.family
    )
    if derivation.instance_name not in metadata.instance_names:
        raise ValueError("derivation instance name is not declared by public metadata")
    expected = {
        item.parameter_id: item.value
        for item in _difficulty_for_instance(metadata, derivation.instance_name)
    }
    actual = {item.parameter_id: item.value for item in derivation.difficulty}
    if actual != expected:
        raise ValueError("derivation difficulty does not match its named public instance")


class PrivateAuthoringProviderDescriptor(StrictModel):
    """Non-secret identity advertised by a restricted authoring implementation."""

    schema_version: SchemaVersion = 1
    protocol_revision: Literal[1] = AUTHORING_PROVIDER_PROTOCOL_REVISION
    provider_id: Identifier
    implementation_digest: Digest
    security_qualification: PrivateProviderSecurityQualification
    evaluator_isolation: PrivateEvaluatorIsolation
    public_catalog_digest: Digest
    capabilities: tuple[PrivateAuthoringCapability, ...]
    clean_room_auditor_descriptor_digest: Digest | None = None
    clean_room_auditor_implementation_digest: Digest | None = None

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(
        cls,
        value: tuple[PrivateAuthoringCapability, ...],
    ) -> tuple[PrivateAuthoringCapability, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("provider capabilities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def bind_public_catalog(self) -> Self:
        if self.public_catalog_digest != PUBLIC_TASK_CATALOG_DIGEST:
            raise ValueError("provider targets a different public task catalog")
        if (
            self.security_qualification.provider_implementation_digest
            != self.implementation_digest
            or self.security_qualification.evaluator_isolation is not self.evaluator_isolation
        ):
            raise ValueError("provider security qualification does not bind its implementation")
        clean_room_fields_present = (
            self.clean_room_auditor_descriptor_digest is not None
            and self.clean_room_auditor_implementation_digest is not None
        )
        if (
            PrivateAuthoringCapability.SAIL_RTL_CATALOG in self.capabilities
        ) != clean_room_fields_present:
            raise ValueError(
                "Sail authoring capability requires one trusted clean-room auditor identity"
            )
        return self

    @property
    def security_qualification_digest(self) -> Digest:
        return self.security_qualification.digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="private-authoring-provider-v1")


class OpaqueCatalogReference(StrictModel):
    """Stable private-catalog reference containing no locator or credential material."""

    provider_id: Identifier
    capability: PrivateAuthoringCapability
    catalog_id: Identifier
    revision: JcsPositiveInt
    member_manifest_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="opaque-private-catalog-reference-v1")


class DifficultyBinding(StrictModel):
    parameter_id: Identifier
    value: JcsNonNegativeInt


def _difficulty_for_instance(
    metadata: TaskFamilyDefinition,
    instance_name: str,
) -> tuple[DifficultyBinding, ...]:
    if instance_name not in metadata.instance_names:
        raise ValueError("task instance name is not declared by public metadata")
    return tuple(
        DifficultyBinding(
            parameter_id=axis.axis_id,
            value=axis.base_value if instance_name == "base" else axis.advanced_value,
        )
        for axis in metadata.difficulty_axes
    )


def _public_derivation_scope_digest(
    family: str,
    instance_name: str,
    difficulty: tuple[DifficultyBinding, ...],
) -> Digest:
    return canonical_digest(
        {
            "difficulty": difficulty,
            "family": family,
            "instance_name": instance_name,
        },
        domain="private-derivation-public-scope-v1",
    )


class PrivateDerivationScope(StrictModel):
    """Public parameters plus a provider-owned handle to undisclosed seed material."""

    family: Identifier
    instance_name: Identifier
    difficulty: tuple[DifficultyBinding, ...]
    seed_handle: Annotated[Identifier, Field(repr=False)]

    @field_validator("difficulty")
    @classmethod
    def normalize_difficulty(
        cls,
        value: tuple[DifficultyBinding, ...],
    ) -> tuple[DifficultyBinding, ...]:
        identifiers = [item.parameter_id for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("difficulty parameters must have unique owners")
        return tuple(sorted(value, key=lambda item: item.parameter_id))

    @property
    def public_digest(self) -> Digest:
        return _public_derivation_scope_digest(
            self.family,
            self.instance_name,
            self.difficulty,
        )


class OpaqueTaskInstanceReference(StrictModel):
    """Digest-only private instance identity with no seed, locator, or access token."""

    provider_id: Identifier
    capability: PrivateAuthoringCapability
    family: Identifier
    instance_name: Identifier
    public_metadata_digest: Digest
    public_derivation_scope_digest: Digest
    task_spec_digest: Digest
    task_instance_digest: Digest
    participant_bundle_digest: Digest
    verifier_bundle_digest: Digest
    reference_id: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="opaque-private-task-instance-reference-v1")


class DerivedTaskDocument(StrictModel):
    """Controller-only typed task inputs bound to one opaque provider reference."""

    instance_reference: OpaqueTaskInstanceReference
    task: TaskSpec
    instance: Annotated[TaskInstance, Field(repr=False)]

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        reference = self.instance_reference
        identity = self.instance.identity
        if (
            self.task.identity.family != reference.family
            or self.task.digest != reference.task_spec_digest
            or identity.task_family != reference.family
            or identity.task_spec_digest != self.task.digest
            or self.instance.digest != reference.task_instance_digest
            or identity.authoring_revision != self.task.identity.authoring_revision
        ):
            raise ValueError("derived task documents do not match their opaque reference")
        metadata = next(
            (
                item
                for item in families_for_root(_root_for_capability(reference.capability))
                if item.family == reference.family
            ),
            None,
        )
        if (
            metadata is None
            or reference.instance_name not in metadata.instance_names
            or reference.public_metadata_digest != metadata.digest
        ):
            raise ValueError("derived task reference does not bind public family metadata")
        expected_difficulty = _difficulty_for_instance(metadata, reference.instance_name)
        expected_values = {
            item.parameter_id: item.value for item in expected_difficulty
        }
        actual_values = {
            item.parameter_id: item.value
            for item in identity.parameters
            if isinstance(item, IntegerParameterValue)
        }
        if len(actual_values) != len(identity.parameters) or actual_values != expected_values:
            raise ValueError("derived task instance does not bind its public difficulty")
        expected_scope_digest = _public_derivation_scope_digest(
            reference.family,
            reference.instance_name,
            expected_difficulty,
        )
        if reference.public_derivation_scope_digest != expected_scope_digest:
            raise ValueError("derived task reference does not bind its public derivation scope")
        return self


class OpaqueEvaluatorDescriptor(StrictModel):
    """Journal-safe evaluator identity; authority remains in its in-process lease."""

    evaluator_id: Identifier
    capability: PrivateAuthoringCapability
    family: Identifier
    task_spec_digest: Digest
    provider_descriptor_digest: Digest
    provider_implementation_digest: Digest
    instance_reference_digest: Digest
    evaluator_implementation_digest: Digest
    scope_attestation_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="opaque-private-evaluator-descriptor-v1")


class FlowCandidateInventory(StrictModel):
    """Environment-independent private candidate identity exported with a flow pack."""

    candidate_id: Identifier
    candidate_resource_id: Identifier
    role: FlowCandidateRole
    content_manifest_digest: Digest

    @model_validator(mode="after")
    def bind_resource_identity(self) -> Self:
        if self.candidate_resource_id != flow_candidate_resource_id_for_role(
            self.candidate_id,
            self.role,
        ):
            raise ValueError("flow candidate resource identity does not match its role")
        return self


class FlowCandidateAttestation(FlowCandidateInventory):
    """Qualification evidence for one candidate in one exact environment."""

    environment_spec_digest: Digest
    expected_candidate_manifest_digest: Digest
    qualification_evidence_digest: Digest


class CandidateMember(StrictModel):
    """One bounded candidate file transported directly to a private evaluator."""

    relative_path: str
    media_type: Annotated[str, Field(min_length=1, max_length=120)]
    content_digest: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0, le=_MAXIMUM_MEMBER_BYTES)]
    content_base64: Annotated[
        str,
        Field(min_length=0, max_length=(_MAXIMUM_MEMBER_BYTES * 4 // 3) + 4, repr=False),
    ]

    @field_validator("relative_path")
    @classmethod
    def normalize_relative_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @field_validator("content_base64")
    @classmethod
    def require_canonical_base64(cls, value: str) -> str:
        _decode_canonical_base64(value)
        return value

    @model_validator(mode="after")
    def bind_content(self) -> Self:
        content = self.content
        if len(content) != self.size_bytes or content_digest(content) != self.content_digest:
            raise ValueError("candidate member content does not match its descriptor")
        return self

    @property
    def content(self) -> bytes:
        return _decode_canonical_base64(self.content_base64)

    @property
    def descriptor(self) -> dict[str, str | int]:
        return {
            "content_digest": self.content_digest,
            "media_type": self.media_type,
            "relative_path": self.relative_path,
            "size_bytes": self.size_bytes,
        }


class CandidateSubmission(StrictModel):
    members: tuple[CandidateMember, ...]

    @field_validator("members")
    @classmethod
    def normalize_members(cls, value: tuple[CandidateMember, ...]) -> tuple[CandidateMember, ...]:
        paths = [item.relative_path for item in value]
        if not value:
            raise ValueError("candidate submission paths must be non-empty")
        validate_member_path_set(tuple(paths))
        if sum(item.size_bytes for item in value) > _MAXIMUM_EXPORTED_BYTES:
            raise ValueError("candidate submission exceeds the transport size bound")
        return tuple(sorted(value, key=lambda item: item.relative_path))

    @property
    def manifest_digest(self) -> Digest:
        return canonical_digest(
            tuple(item.descriptor for item in self.members),
            domain="private-evaluator-candidate-manifest-v1",
        )


class AuthoringProviderRequest(StrictModel):
    """Canonical request sent over stdin without filesystem or credential fields."""

    schema_version: SchemaVersion = 1
    protocol_revision: Literal[1] = AUTHORING_PROVIDER_PROTOCOL_REVISION
    operation: AuthoringProviderOperation
    public_catalog_digest: Digest = PUBLIC_TASK_CATALOG_DIGEST
    capability: PrivateAuthoringCapability | None = None
    expected_provider_digest: Digest | None = None
    derivation: PrivateDerivationScope | None = None
    instance_reference: OpaqueTaskInstanceReference | None = None
    qualification_environment: EnvironmentSpec | None = None
    evaluator_descriptor: OpaqueEvaluatorDescriptor | None = None
    evaluator_lease_token: Annotated[EvaluatorLeaseToken | None, Field(repr=False)] = None
    candidate: CandidateSubmission | None = None

    @model_validator(mode="after")
    def validate_operation(self) -> Self:
        present = {
            "capability": self.capability is not None,
            "expected": self.expected_provider_digest is not None,
            "derivation": self.derivation is not None,
            "instance": self.instance_reference is not None,
            "qualification_environment": self.qualification_environment is not None,
            "evaluator": self.evaluator_descriptor is not None,
            "lease": self.evaluator_lease_token is not None,
            "candidate": self.candidate is not None,
        }
        required = {
            AuthoringProviderOperation.DESCRIBE: set(),
            AuthoringProviderOperation.EXPORT: {"capability", "expected"},
            AuthoringProviderOperation.DERIVE: {"capability", "expected", "derivation"},
            AuthoringProviderOperation.QUALIFY: (
                {"capability", "expected", "instance", "qualification_environment"}
                if self.capability is PrivateAuthoringCapability.EDA_FLOW_CATALOG
                else {"capability", "expected", "instance"}
            ),
            AuthoringProviderOperation.OPEN_EVALUATOR: {
                "capability",
                "expected",
                "instance",
            },
            AuthoringProviderOperation.EVALUATE: {
                "capability",
                "expected",
                "evaluator",
                "lease",
                "candidate",
            },
        }[self.operation]
        if {name for name, is_present in present.items() if is_present} != required:
            raise ValueError("provider operation has an invalid field set")
        if self.derivation is not None:
            if self.capability is None:
                raise ValueError("derivation request requires a capability")
            _validate_family_capability(self.capability, self.derivation.family)
            _validate_derivation_scope(self.capability, self.derivation)
        if self.instance_reference is not None:
            if self.instance_reference.capability is not self.capability:
                raise ValueError("instance reference capability does not match the request")
            _validate_family_capability(self.capability, self.instance_reference.family)
        if self.evaluator_descriptor is not None:
            if self.evaluator_descriptor.capability is not self.capability:
                raise ValueError("evaluator capability does not match the request")
            _validate_family_capability(self.capability, self.evaluator_descriptor.family)
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="private-authoring-request-v1")


class SealedInstanceQualification(StrictModel):
    """Qualification evidence for exactly one opaque private task instance."""

    instance_reference_digest: Digest
    instance_reference_id: Digest
    family: Identifier
    instance_name: Identifier
    public_derivation_scope_digest: Digest
    difficulty: tuple[DifficultyBinding, ...]
    task_spec_digest: Digest
    task_instance_digest: Digest
    release_digest: Digest
    participant_bundle_digest: Digest
    verifier_bundle_digest: Digest
    release_qualification_digest: Digest
    reference_evidence_digests: tuple[Digest, ...]
    known_answer_evidence_digests: tuple[Digest, ...] = ()
    negative_evidence_digests: tuple[Digest, ...]
    tool_evidence_digests: tuple[Digest, ...]

    @field_validator(
        "reference_evidence_digests",
        "known_answer_evidence_digests",
        "negative_evidence_digests",
        "tool_evidence_digests",
    )
    @classmethod
    def normalize_digest_sets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("instance qualification digest sets must be unique")
        return tuple(sorted(value))

    @field_validator("difficulty")
    @classmethod
    def normalize_difficulty(
        cls,
        value: tuple[DifficultyBinding, ...],
    ) -> tuple[DifficultyBinding, ...]:
        identifiers = [item.parameter_id for item in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("instance qualification difficulty must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.parameter_id))

    @model_validator(mode="after")
    def validate_common_evidence(self) -> Self:
        if (
            not self.reference_evidence_digests
            or not self.negative_evidence_digests
            or not self.tool_evidence_digests
        ):
            raise ValueError(
                "instance qualification requires positive, negative, and tool evidence"
            )
        if self.participant_bundle_digest == self.verifier_bundle_digest:
            raise ValueError("participant and verifier bundle identities must differ")
        if self.public_derivation_scope_digest != _public_derivation_scope_digest(
            self.family,
            self.instance_name,
            self.difficulty,
        ):
            raise ValueError("instance qualification public scope digest is invalid")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="sealed-instance-qualification-v1")


class SealedFamilyAttestation(StrictModel):
    """Mechanical aggregation of private instance qualifications for one family."""

    family: Identifier
    public_metadata_digest: Digest
    task_spec_digest: Digest
    qualification_digest: Digest
    instances: tuple[SealedInstanceQualification, ...]
    flow_candidate_inventory: tuple[FlowCandidateInventory, ...] = ()

    @field_validator("instances")
    @classmethod
    def normalize_instances(
        cls,
        value: tuple[SealedInstanceQualification, ...],
    ) -> tuple[SealedInstanceQualification, ...]:
        identities = [item.instance_reference_digest for item in value]
        if not value or len(identities) != len(set(identities)):
            raise ValueError("family instance qualifications must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.instance_reference_digest))

    @field_validator("flow_candidate_inventory")
    @classmethod
    def normalize_flow_candidate_inventory(
        cls,
        value: tuple[FlowCandidateInventory, ...],
    ) -> tuple[FlowCandidateInventory, ...]:
        resource_ids = [item.candidate_resource_id for item in value]
        candidate_ids = [item.candidate_id for item in value]
        if len(resource_ids) != len(set(resource_ids)) or len(candidate_ids) != len(
            set(candidate_ids)
        ):
            raise ValueError("flow candidate inventory identities must be unique")
        return tuple(sorted(value, key=lambda item: item.candidate_resource_id))

    @model_validator(mode="after")
    def bind_instances(self) -> Self:
        if any(
            item.family != self.family or item.task_spec_digest != self.task_spec_digest
            for item in self.instances
        ):
            raise ValueError("family attestation contains an unrelated instance")
        names = [item.instance_name for item in self.instances]
        if len(names) != len(set(names)):
            raise ValueError("family attestation contains duplicate named instances")
        expected = canonical_digest(
            tuple(item.digest for item in self.instances),
            domain="sealed-family-qualification-aggregate-v1",
        )
        if self.qualification_digest != expected:
            raise ValueError("family qualification digest must be derived from its instances")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="sealed-family-attestation-v1")


class ExportMemberDescriptor(StrictModel):
    relative_path: str
    role: ExportMemberRole
    family: Identifier | None = None
    instance_reference_id: Digest | None = None
    media_type: Annotated[str, Field(min_length=1, max_length=120)]
    content_digest: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0, le=_MAXIMUM_MEMBER_BYTES)]

    @field_validator("relative_path")
    @classmethod
    def normalize_relative_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @model_validator(mode="after")
    def validate_role(self) -> Self:
        instance_member = self.role in _INSTANCE_BOUND_MEMBER_ROLES
        if instance_member != (
            self.instance_reference_id is not None and self.family is not None
        ):
            raise ValueError("instance-visible members require exactly one opaque instance binding")
        if not instance_member and self.instance_reference_id is not None:
            raise ValueError("author-only members cannot claim a visible instance binding")
        if self.role is ExportMemberRole.FLOW_TASK_PACK and self.family is None:
            raise ValueError("flow task-pack members identify their public family")
        return self


class ExportedMember(ExportMemberDescriptor):
    content_base64: Annotated[
        str,
        Field(min_length=0, max_length=(_MAXIMUM_MEMBER_BYTES * 4 // 3) + 4, repr=False),
    ]

    @field_validator("content_base64")
    @classmethod
    def require_canonical_base64(cls, value: str) -> str:
        _decode_canonical_base64(value)
        return value

    @model_validator(mode="after")
    def bind_content(self) -> Self:
        content = self.content
        if len(content) != self.size_bytes or content_digest(content) != self.content_digest:
            raise ValueError("provider member content does not match its descriptor")
        return self

    @property
    def content(self) -> bytes:
        return _decode_canonical_base64(self.content_base64)

    @property
    def descriptor(self) -> ExportMemberDescriptor:
        return ExportMemberDescriptor.model_validate(
            self.model_dump(mode="python", exclude={"content_base64"})
        )


def exported_member_manifest_digest(
    members: tuple[ExportMemberDescriptor, ...] | tuple[ExportedMember, ...],
) -> Digest:
    descriptors = tuple(
        item.descriptor if isinstance(item, ExportedMember) else item for item in members
    )
    return canonical_digest(descriptors, domain="private-authoring-member-manifest-v1")


def exported_role_manifest_digest(
    members: tuple[ExportMemberDescriptor, ...] | tuple[ExportedMember, ...],
    roles: frozenset[ExportMemberRole],
) -> Digest:
    descriptors = tuple(
        item.descriptor if isinstance(item, ExportedMember) else item
        for item in members
        if item.role in roles
    )
    if not descriptors:
        raise ValueError("role manifest cannot be empty")
    return canonical_digest(descriptors, domain="private-authoring-role-manifest-v1")


def _validate_derived_task_members(
    document: DerivedTaskDocument,
    members: tuple[ExportedMember, ...],
) -> None:
    reference = document.instance_reference
    scoped = tuple(
        item
        for item in members
        if item.instance_reference_id == reference.reference_id
        and item.role in _DERIVED_DOCUMENT_ROLES
    )
    by_role = {item.role: item for item in scoped}
    if len(scoped) != 2 or by_role.keys() != _DERIVED_DOCUMENT_ROLES:
        raise ValueError("derived task requires exactly one typed task and instance document")
    expected = {
        ExportMemberRole.TASK_SPEC_DOCUMENT: canonical_bytes(document.task),
        ExportMemberRole.TASK_INSTANCE_DOCUMENT: canonical_bytes(document.instance),
    }
    if any(
        member.family != reference.family
        or member.media_type != "application/json"
        or member.content != expected[role]
        for role, member in by_role.items()
    ):
        raise ValueError("derived task document members do not match their typed values")


def validate_export_member_roles(
    attestation: SealedCatalogAttestation,
    members: tuple[ExportMemberDescriptor, ...] | tuple[ExportedMember, ...],
) -> None:
    """Recompute participant and verifier bundle closures from typed member roles."""

    instance_count = sum(len(family.instances) for family in attestation.families)
    qualifications = {
        instance.instance_reference_id: instance
        for family in attestation.families
        for instance in family.instances
    }
    if len(qualifications) != instance_count:
        raise ValueError("catalog instance reference identifiers must be unique")
    visible_reference_ids = {
        item.instance_reference_id
        for item in members
        if item.role in _INSTANCE_BOUND_MEMBER_ROLES
    }
    if visible_reference_ids != qualifications.keys():
        raise ValueError("catalog members do not exactly cover qualified instances")
    for reference_id, qualification in qualifications.items():
        scoped = tuple(item for item in members if item.instance_reference_id == reference_id)
        if any(item.family != qualification.family for item in scoped):
            raise ValueError("catalog member family does not match its opaque instance")
        participant_digest = exported_role_manifest_digest(
            scoped,
            _PARTICIPANT_BUNDLE_ROLES,
        )
        verifier_digest = exported_role_manifest_digest(
            scoped,
            _VERIFIER_BUNDLE_ROLES,
        )
        if (
            participant_digest != qualification.participant_bundle_digest
            or verifier_digest != qualification.verifier_bundle_digest
        ):
            raise ValueError("catalog member roles do not match qualified bundles")


class SealedCatalogAttestation(StrictModel):
    """Digest-bound qualification closure for a private catalog."""

    schema_version: SchemaVersion = 1
    provider_descriptor_digest: Digest
    provider_implementation_digest: Digest
    provider_security_qualification_digest: Digest
    capability: PrivateAuthoringCapability
    public_catalog_digest: Digest
    catalog_reference: OpaqueCatalogReference
    member_manifest_digest: Digest
    families: tuple[SealedFamilyAttestation, ...]
    clean_room_attestation: CleanRoomCatalogAttestation | None = None

    @field_validator("families")
    @classmethod
    def normalize_families(
        cls,
        value: tuple[SealedFamilyAttestation, ...],
    ) -> tuple[SealedFamilyAttestation, ...]:
        identifiers = [item.family for item in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("catalog attestations require unique task families")
        return tuple(sorted(value, key=lambda item: item.family))

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.public_catalog_digest != PUBLIC_TASK_CATALOG_DIGEST:
            raise ValueError("attestation targets a different public task catalog")
        if self.catalog_reference.capability is not self.capability:
            raise ValueError("catalog reference capability does not match its attestation")
        if self.catalog_reference.member_manifest_digest != self.member_manifest_digest:
            raise ValueError("catalog reference does not bind the exported member manifest")
        sail_catalog = self.capability is PrivateAuthoringCapability.SAIL_RTL_CATALOG
        if sail_catalog != (self.clean_room_attestation is not None):
            raise ValueError("only Sail catalogs require a clean-room attestation")
        if self.clean_room_attestation is not None:
            family_metadata = {
                item.family: item.public_metadata_digest for item in self.families
            }
            clean_room_metadata = {
                item.family: item.public_metadata_digest
                for item in self.clean_room_attestation.families
            }
            if family_metadata != clean_room_metadata:
                raise ValueError(
                    "clean-room evidence does not bind every sealed Sail family"
                )
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="sealed-private-catalog-attestation-v1")


class DescribeProviderResponse(StrictModel):
    kind: Literal["describe"] = "describe"
    request_digest: Digest
    descriptor: PrivateAuthoringProviderDescriptor


class ExportCatalogResponse(StrictModel):
    kind: Literal["export"] = "export"
    request_digest: Digest
    descriptor: PrivateAuthoringProviderDescriptor
    attestation: SealedCatalogAttestation
    derived_tasks: tuple[DerivedTaskDocument, ...] = ()
    members: tuple[ExportedMember, ...]

    @field_validator("derived_tasks")
    @classmethod
    def normalize_derived_tasks(
        cls,
        value: tuple[DerivedTaskDocument, ...],
    ) -> tuple[DerivedTaskDocument, ...]:
        identities = [item.instance_reference.reference_id for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("exported derived tasks must have unique opaque references")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.instance_reference.family,
                    item.instance_reference.instance_name,
                ),
            )
        )

    @field_validator("members")
    @classmethod
    def normalize_members(cls, value: tuple[ExportedMember, ...]) -> tuple[ExportedMember, ...]:
        paths = [item.relative_path for item in value]
        if not value:
            raise ValueError("provider export members require non-empty paths")
        validate_member_path_set(tuple(paths))
        if sum(item.size_bytes for item in value) > _MAXIMUM_EXPORTED_BYTES:
            raise ValueError("provider export exceeds the catalog size bound")
        return tuple(sorted(value, key=lambda item: item.relative_path))

    @model_validator(mode="after")
    def bind_export(self) -> Self:
        if exported_member_manifest_digest(self.members) != self.attestation.member_manifest_digest:
            raise ValueError("provider export does not match its attested member manifest")
        validate_export_member_roles(self.attestation, self.members)
        qualified = {
            instance.instance_reference_id: instance
            for family in self.attestation.families
            for instance in family.instances
        }
        derived_reference_ids = {
            item.instance_reference.reference_id for item in self.derived_tasks
        }
        document_member_reference_ids = {
            item.instance_reference_id
            for item in self.members
            if item.role in _DERIVED_DOCUMENT_ROLES
        }
        if document_member_reference_ids != derived_reference_ids:
            raise ValueError("typed task members do not exactly cover exported derived tasks")
        for document in self.derived_tasks:
            reference = document.instance_reference
            qualification = qualified.get(reference.reference_id)
            if qualification is None or (
                qualification.instance_reference_digest != reference.digest
                or qualification.task_spec_digest != document.task.digest
                or qualification.task_instance_digest != document.instance.digest
            ):
                raise ValueError("exported derived task lacks its exact qualification")
            _validate_derived_task_members(document, self.members)
        return self


class DerivedTaskResponse(StrictModel):
    kind: Literal["derive"] = "derive"
    request_digest: Digest
    descriptor: PrivateAuthoringProviderDescriptor
    derived_task: DerivedTaskDocument
    member_manifest_digest: Digest
    members: tuple[ExportedMember, ...]

    @field_validator("members")
    @classmethod
    def normalize_members(cls, value: tuple[ExportedMember, ...]) -> tuple[ExportedMember, ...]:
        paths = [item.relative_path for item in value]
        if not value:
            raise ValueError("derived task members require non-empty paths")
        validate_member_path_set(tuple(paths))
        if sum(item.size_bytes for item in value) > _MAXIMUM_EXPORTED_BYTES:
            raise ValueError("derived task exceeds the transport size bound")
        return tuple(sorted(value, key=lambda item: item.relative_path))

    @model_validator(mode="after")
    def bind_members(self) -> Self:
        instance_reference = self.derived_task.instance_reference
        if exported_member_manifest_digest(self.members) != self.member_manifest_digest:
            raise ValueError("derived task members do not match their manifest")
        if any(
            item.instance_reference_id != instance_reference.reference_id
            for item in self.members
            if item.role in _INSTANCE_BOUND_MEMBER_ROLES
        ):
            raise ValueError("derived task member belongs to another opaque instance")
        _validate_derived_task_members(self.derived_task, self.members)
        participant_digest = exported_role_manifest_digest(
            self.members,
            _PARTICIPANT_BUNDLE_ROLES,
        )
        verifier_digest = exported_role_manifest_digest(
            self.members,
            _VERIFIER_BUNDLE_ROLES,
        )
        if (
            participant_digest != instance_reference.participant_bundle_digest
            or verifier_digest != instance_reference.verifier_bundle_digest
        ):
            raise ValueError("derived task role manifests do not match the instance reference")
        return self


class QualificationProviderResponse(StrictModel):
    kind: Literal["qualify"] = "qualify"
    request_digest: Digest
    descriptor: PrivateAuthoringProviderDescriptor
    instance_reference_digest: Digest
    qualification: SealedInstanceQualification
    release: ReleaseManifest

    @model_validator(mode="after")
    def bind_release(self) -> Self:
        qualification = self.qualification
        release = self.release
        if isinstance(release.qualification, FlowReleaseCandidateQualification):
            raise ValueError("instance qualification cannot return a release candidate")
        if (
            release.digest != qualification.release_digest
            or release.qualification.digest != qualification.release_qualification_digest
            or release.task_spec_digest != qualification.task_spec_digest
            or release.task_instance_digest != qualification.task_instance_digest
            or release.participant_bundle_digest != qualification.participant_bundle_digest
            or release.verifier_bundle_digest != qualification.verifier_bundle_digest
        ):
            raise ValueError("qualified release does not match its instance evidence")
        return self


class OpenEvaluatorProviderResponse(StrictModel):
    kind: Literal["open_evaluator"] = "open_evaluator"
    request_digest: Digest
    descriptor: PrivateAuthoringProviderDescriptor
    evaluator: OpaqueEvaluatorDescriptor
    evaluator_lease_token: Annotated[EvaluatorLeaseToken, Field(repr=False)]


class PrivateEvaluationAttestation(StrictModel):
    evaluator_descriptor_digest: Digest
    candidate_manifest_digest: Digest
    stage_results: tuple[StageResult, ...]
    hidden_evidence_digest: Digest
    public_feedback_digest: Digest | None = None

    @field_validator("stage_results")
    @classmethod
    def normalize_stage_results(cls, value: tuple[StageResult, ...]) -> tuple[StageResult, ...]:
        identifiers = [item.stage_id for item in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("private evaluation requires unique public stage results")
        return tuple(sorted(value, key=lambda item: item.stage_id))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="private-evaluation-attestation-v1")


class EvaluateProviderResponse(StrictModel):
    kind: Literal["evaluate"] = "evaluate"
    request_digest: Digest
    descriptor: PrivateAuthoringProviderDescriptor
    evaluation: PrivateEvaluationAttestation


AuthoringProviderResponse = Annotated[
    DescribeProviderResponse
    | ExportCatalogResponse
    | DerivedTaskResponse
    | QualificationProviderResponse
    | OpenEvaluatorProviderResponse
    | EvaluateProviderResponse,
    Field(discriminator="kind"),
]
_RESPONSE_ADAPTER: TypeAdapter[AuthoringProviderResponse] = TypeAdapter(
    AuthoringProviderResponse
)


def authoring_provider_schema_digest() -> Digest:
    """Return the canonical identity of both public wire schemas."""

    return canonical_digest(
        {
            "request": AuthoringProviderRequest.model_json_schema(),
            "response": _RESPONSE_ADAPTER.json_schema(),
        },
        domain="private-authoring-provider-wire-schema-v1",
    )


def validate_catalog_attestation(
    descriptor: PrivateAuthoringProviderDescriptor,
    attestation: SealedCatalogAttestation,
) -> None:
    """Validate a digest-only private qualification claim against public metadata."""

    if attestation.provider_descriptor_digest != descriptor.digest:
        raise AuthoringProviderError("attestation provider descriptor mismatch")
    if attestation.provider_implementation_digest != descriptor.implementation_digest:
        raise AuthoringProviderError("attestation implementation mismatch")
    if (
        attestation.provider_security_qualification_digest
        != descriptor.security_qualification_digest
    ):
        raise AuthoringProviderError("attestation provider security qualification mismatch")
    if attestation.catalog_reference.provider_id != descriptor.provider_id:
        raise AuthoringProviderError("attestation provider identifier mismatch")
    if attestation.capability not in descriptor.capabilities:
        raise AuthoringProviderError("provider did not declare the attested capability")
    clean_room = attestation.clean_room_attestation
    if attestation.capability is PrivateAuthoringCapability.SAIL_RTL_CATALOG:
        if (
            clean_room is None
            or clean_room.auditor_descriptor_digest
            != descriptor.clean_room_auditor_descriptor_digest
            or clean_room.auditor_implementation_digest
            != descriptor.clean_room_auditor_implementation_digest
        ):
            raise AuthoringProviderError(
                "Sail clean-room evidence is not controller-authorized"
            )
    elif clean_room is not None:
        raise AuthoringProviderError("flow catalog cannot contain Sail clean-room evidence")

    public_families = families_for_root(_root_for_capability(attestation.capability))
    expected = {item.family: item for item in public_families}
    actual = {item.family: item for item in attestation.families}
    if actual.keys() != expected.keys():
        raise AuthoringProviderError("attestation does not exactly cover the public family catalog")
    for family, evidence in actual.items():
        _validate_family_attestation(attestation.capability, evidence, expected[family].digest)


def _validate_family_attestation(
    capability: PrivateAuthoringCapability,
    evidence: SealedFamilyAttestation,
    expected_public_metadata_digest: Digest,
) -> None:
    if evidence.public_metadata_digest != expected_public_metadata_digest:
        raise AuthoringProviderError("attestation family metadata mismatch")
    for instance in evidence.instances:
        _validate_instance_qualification(capability, instance)
    metadata = next(
        item
        for item in families_for_root(_root_for_capability(capability))
        if item.family == evidence.family
    )
    instance_names = {item.instance_name for item in evidence.instances}
    if not instance_names.issubset(set(metadata.instance_names)):
        raise AuthoringProviderError("family attestation names an undeclared instance")
    for instance in evidence.instances:
        _validate_public_instance_difficulty(instance, metadata)
    if capability is PrivateAuthoringCapability.SAIL_RTL_CATALOG:
        if (
            len(evidence.instances) != 2
            or instance_names != set(metadata.instance_names)
            or any(
                not item.known_answer_evidence_digests
                or len(item.negative_evidence_digests) < 3
                for item in evidence.instances
            )
            or evidence.flow_candidate_inventory
        ):
            raise AuthoringProviderError("Sail family qualification evidence is incomplete")
        return
    if (
        len(evidence.instances) < 1
        or any(len(item.negative_evidence_digests) < 1 for item in evidence.instances)
        or not evidence.flow_candidate_inventory
    ):
        raise AuthoringProviderError("flow family qualification evidence is incomplete")
    roles = [item.role for item in evidence.flow_candidate_inventory]
    if (
        roles.count(FlowCandidateRole.FEASIBILITY_WITNESS) != 1
        or roles.count(FlowCandidateRole.SEMANTIC_NEGATIVE) < 1
    ):
        raise AuthoringProviderError("flow family candidate inventory is incomplete")


def _validate_instance_qualification(
    capability: PrivateAuthoringCapability,
    evidence: SealedInstanceQualification,
) -> None:
    if capability is PrivateAuthoringCapability.SAIL_RTL_CATALOG:
        if not evidence.known_answer_evidence_digests or len(
            evidence.negative_evidence_digests
        ) < 3:
            raise AuthoringProviderError("Sail instance qualification evidence is incomplete")
    elif len(evidence.negative_evidence_digests) < 1:
        raise AuthoringProviderError("flow instance qualification evidence is incomplete")


def _validate_public_instance_difficulty(
    evidence: SealedInstanceQualification,
    metadata: TaskFamilyDefinition,
) -> None:
    expected_difficulty = _difficulty_for_instance(metadata, evidence.instance_name)
    if (
        evidence.difficulty != expected_difficulty
        or evidence.public_derivation_scope_digest
        != _public_derivation_scope_digest(
            evidence.family,
            evidence.instance_name,
            expected_difficulty,
        )
    ):
        raise AuthoringProviderError(
            "instance qualification does not bind its public difficulty"
        )


class ExternalAuthoringProvider:
    """Invoke one trusted executable without persisting its local locator."""

    def __init__(
        self,
        executable: Path,
        *,
        expected_executable_digest: str,
        expected_implementation_digest: str,
        expected_descriptor_digest: str,
        environment: Mapping[str, str] | None = None,
        executable_search_path: str = "/usr/local/bin:/usr/bin:/bin",
        timeout_seconds: int = 3600,
    ) -> None:
        self._executable = executable.absolute()
        self._expected_executable_digest = _DIGEST_ADAPTER.validate_python(
            expected_executable_digest
        )
        self._expected_implementation_digest = _DIGEST_ADAPTER.validate_python(
            expected_implementation_digest
        )
        self._expected_descriptor_digest = _DIGEST_ADAPTER.validate_python(
            expected_descriptor_digest
        )
        if not executable_search_path or any(
            boundary in executable_search_path for boundary in ("\x00", "\r", "\n")
        ):
            raise ValueError("provider executable search path is invalid")
        self._environment = provider_environment(environment, executable_search_path)
        if timeout_seconds < 1:
            raise ValueError("provider timeout must be positive")
        self._timeout_seconds = timeout_seconds

    def __repr__(self) -> str:
        return "ExternalAuthoringProvider(executable=<restricted>)"

    def describe(self) -> PrivateAuthoringProviderDescriptor:
        request = AuthoringProviderRequest(operation=AuthoringProviderOperation.DESCRIBE)
        response = self._invoke(request)
        if not isinstance(response, DescribeProviderResponse):
            raise AuthoringProviderError("provider returned the wrong response kind")
        if response.descriptor.implementation_digest != self._expected_implementation_digest:
            raise AuthoringProviderError("provider implementation is not controller-authorized")
        if response.descriptor.digest != self._expected_descriptor_digest:
            raise AuthoringProviderError("provider descriptor is not controller-authorized")
        return response.descriptor

    def open_catalog(self, capability: PrivateAuthoringCapability) -> PrivateCatalogLease:
        descriptor = self.describe()
        if capability not in descriptor.capabilities:
            raise AuthoringProviderError("provider does not implement the requested capability")
        return PrivateCatalogLease(self, descriptor, capability)

    def source_registration(self) -> PrivateRootRegistration:
        """Register the live authorized executable without exposing its path or digest."""

        descriptor = self.describe()
        try:
            executable_fd, _snapshot = open_trusted_executable(
                self._executable,
                self._expected_executable_digest,
            )
        except RestrictedProviderProcessError as error:
            raise AuthoringProviderError("private authoring provider is unavailable") from error
        try:
            source_identity = canonical_digest(
                {
                    "descriptor_digest": descriptor.digest,
                    "executable_digest": self._expected_executable_digest,
                    "implementation_digest": descriptor.implementation_digest,
                },
                domain="private-authoring-provider-source-v1",
            )
            return _bind_private_root_from_descriptor(
                PrivateRootRole.AUTHORING_PROVIDER_SOURCE,
                executable_fd,
                source_identity,
            )
        finally:
            os.close(executable_fd)

    def derive(
        self,
        capability: PrivateAuthoringCapability,
        derivation: PrivateDerivationScope,
    ) -> DerivedTaskResponse:
        descriptor = self.describe()
        self._require_capability(descriptor, capability)
        request = AuthoringProviderRequest(
            operation=AuthoringProviderOperation.DERIVE,
            capability=capability,
            expected_provider_digest=descriptor.digest,
            derivation=derivation,
        )
        response = self._invoke(request)
        if not isinstance(response, DerivedTaskResponse) or response.descriptor != descriptor:
            raise AuthoringProviderError("provider returned the wrong derivation response")
        reference = response.derived_task.instance_reference
        expected_family = next(
            item
            for item in families_for_root(_root_for_capability(capability))
            if item.family == derivation.family
        )
        if (
            reference.provider_id != descriptor.provider_id
            or reference.capability is not capability
            or reference.family != derivation.family
            or reference.instance_name != derivation.instance_name
            or reference.public_metadata_digest != expected_family.digest
            or reference.public_derivation_scope_digest != derivation.public_digest
        ):
            raise AuthoringProviderError("provider derivation escaped its requested scope")
        return response

    def qualify(
        self,
        capability: PrivateAuthoringCapability,
        instance_reference: OpaqueTaskInstanceReference,
        *,
        environment: EnvironmentSpec | None = None,
    ) -> QualificationProviderResponse:
        descriptor = self.describe()
        self._require_capability(descriptor, capability)
        request = AuthoringProviderRequest(
            operation=AuthoringProviderOperation.QUALIFY,
            capability=capability,
            expected_provider_digest=descriptor.digest,
            instance_reference=instance_reference,
            qualification_environment=environment,
        )
        response = self._invoke(request)
        if not isinstance(response, QualificationProviderResponse) or (
            response.descriptor != descriptor
            or response.instance_reference_digest != instance_reference.digest
            or response.qualification.family != instance_reference.family
        ):
            raise AuthoringProviderError("provider returned the wrong qualification response")
        qualification = response.qualification
        if (
            qualification.instance_reference_id != instance_reference.reference_id
            or qualification.instance_reference_digest != instance_reference.digest
            or qualification.family != instance_reference.family
            or qualification.instance_name != instance_reference.instance_name
            or qualification.public_derivation_scope_digest
            != instance_reference.public_derivation_scope_digest
            or qualification.task_spec_digest != instance_reference.task_spec_digest
            or qualification.task_instance_digest != instance_reference.task_instance_digest
            or qualification.participant_bundle_digest
            != instance_reference.participant_bundle_digest
            or qualification.verifier_bundle_digest != instance_reference.verifier_bundle_digest
        ):
            raise AuthoringProviderError("instance qualification escaped its derivation identity")
        _validate_instance_qualification(capability, qualification)
        metadata = next(
            item
            for item in families_for_root(_root_for_capability(capability))
            if item.family == qualification.family
        )
        _validate_public_instance_difficulty(qualification, metadata)
        if capability is PrivateAuthoringCapability.EDA_FLOW_CATALOG:
            if environment is None or response.release.environment_digests != (
                environment.digest,
            ):
                raise AuthoringProviderError(
                    "flow qualification escaped its requested environment"
                )
        elif environment is not None:
            raise AuthoringProviderError("Sail qualification cannot bind a flow environment")
        return response

    def open_evaluator(
        self,
        capability: PrivateAuthoringCapability,
        instance_reference: OpaqueTaskInstanceReference,
    ) -> PrivateEvaluatorLease:
        descriptor = self.describe()
        self._require_capability(descriptor, capability)
        request = AuthoringProviderRequest(
            operation=AuthoringProviderOperation.OPEN_EVALUATOR,
            capability=capability,
            expected_provider_digest=descriptor.digest,
            instance_reference=instance_reference,
        )
        response = self._invoke(request)
        if not isinstance(response, OpenEvaluatorProviderResponse) or (
            response.descriptor != descriptor
            or response.evaluator.provider_descriptor_digest != descriptor.digest
            or response.evaluator.provider_implementation_digest
            != descriptor.implementation_digest
            or response.evaluator.instance_reference_digest != instance_reference.digest
            or response.evaluator.capability is not capability
            or response.evaluator.family != instance_reference.family
            or response.evaluator.task_spec_digest != instance_reference.task_spec_digest
        ):
            raise AuthoringProviderError("provider returned an invalid evaluator scope")
        return PrivateEvaluatorLease(
            self,
            descriptor,
            capability,
            response.evaluator,
            response.evaluator_lease_token,
        )

    @staticmethod
    def _require_capability(
        descriptor: PrivateAuthoringProviderDescriptor,
        capability: PrivateAuthoringCapability,
    ) -> None:
        if capability not in descriptor.capabilities:
            raise AuthoringProviderError("provider does not implement the requested capability")

    def _export(
        self,
        descriptor: PrivateAuthoringProviderDescriptor,
        capability: PrivateAuthoringCapability,
    ) -> ExportCatalogResponse:
        request = AuthoringProviderRequest(
            operation=AuthoringProviderOperation.EXPORT,
            capability=capability,
            expected_provider_digest=descriptor.digest,
        )
        response = self._invoke(request)
        if not isinstance(response, ExportCatalogResponse):
            raise AuthoringProviderError("provider returned the wrong response kind")
        if response.descriptor != descriptor:
            raise AuthoringProviderError("provider identity changed during one export")
        if response.attestation.capability is not capability:
            raise AuthoringProviderError("provider returned the wrong catalog capability")
        validate_catalog_attestation(descriptor, response.attestation)
        return response

    def _evaluate(
        self,
        descriptor: PrivateAuthoringProviderDescriptor,
        capability: PrivateAuthoringCapability,
        evaluator: OpaqueEvaluatorDescriptor,
        evaluator_lease_token: str,
        candidate: CandidateSubmission,
        task: TaskSpec,
    ) -> EvaluateProviderResponse:
        if task.digest != evaluator.task_spec_digest:
            raise AuthoringProviderError("evaluator lease does not belong to the supplied task")
        request = AuthoringProviderRequest(
            operation=AuthoringProviderOperation.EVALUATE,
            capability=capability,
            expected_provider_digest=descriptor.digest,
            evaluator_descriptor=evaluator,
            evaluator_lease_token=evaluator_lease_token,
            candidate=candidate,
        )
        response = self._invoke(request)
        if not isinstance(response, EvaluateProviderResponse) or (
            response.descriptor != descriptor
            or response.evaluation.evaluator_descriptor_digest != evaluator.digest
            or response.evaluation.candidate_manifest_digest != candidate.manifest_digest
        ):
            raise AuthoringProviderError("provider returned an invalid evaluation attestation")
        try:
            hard_gate_status(task, response.evaluation.stage_results)
        except ValueError as error:
            raise AuthoringProviderError(
                "provider returned invalid public stage results"
            ) from error
        return response

    def _invoke(self, request: AuthoringProviderRequest) -> AuthoringProviderResponse:
        payload = canonical_bytes(request) + b"\n"
        if len(payload) > _MAXIMUM_PROVIDER_REQUEST_BYTES:
            raise AuthoringProviderError("private authoring provider request is too large")
        try:
            executable_fd, before = open_trusted_executable(
                self._executable,
                self._expected_executable_digest,
            )
        except RestrictedProviderProcessError as error:
            raise AuthoringProviderError("private authoring provider is unavailable") from error
        try:
            response_bytes = invoke_trusted_executable(
                executable_fd,
                before,
                payload,
                environment=self._environment,
                maximum_output_bytes=_MAXIMUM_PROVIDER_RESPONSE_BYTES,
                timeout_seconds=self._timeout_seconds,
            )
        except RestrictedProviderProcessError as error:
            raise AuthoringProviderError("private authoring provider invocation failed") from error
        finally:
            os.close(executable_fd)
        if not response_bytes.endswith(b"\n") or response_bytes.endswith(b"\n\n"):
            raise AuthoringProviderError("provider response must have one final newline")
        try:
            document = json.loads(response_bytes, object_pairs_hook=_unique_object)
            response = _RESPONSE_ADAPTER.validate_python(document)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise AuthoringProviderError(
                "provider response is not canonical protocol data"
            ) from error
        if response_bytes != canonical_bytes(response) + b"\n":
            raise AuthoringProviderError("provider response is not canonically encoded")
        if response.request_digest != request.digest:
            raise AuthoringProviderError("provider response belongs to a different request")
        if request.expected_provider_digest is not None and (
            response.descriptor.digest != request.expected_provider_digest
        ):
            raise AuthoringProviderError("provider response has an unexpected identity")
        if (
            response.descriptor.digest != self._expected_descriptor_digest
            or response.descriptor.implementation_digest != self._expected_implementation_digest
        ):
            raise AuthoringProviderError("provider response is not controller-authorized")
        return response

class PrivateCatalogLease:
    """One-shot in-process authority to read one restricted catalog export."""

    __slots__ = ("_capability", "_consumed", "_descriptor", "_provider")

    def __init__(
        self,
        provider: ExternalAuthoringProvider,
        descriptor: PrivateAuthoringProviderDescriptor,
        capability: PrivateAuthoringCapability,
    ) -> None:
        self._provider = provider
        self._descriptor = descriptor
        self._capability = capability
        self._consumed = False

    def __repr__(self) -> str:
        return (
            "PrivateCatalogLease("
            f"provider_descriptor_digest={self._descriptor.digest!r}, "
            f"capability={self._capability.value!r}, consumed={self._consumed!r})"
        )

    def __copy__(self) -> Self:
        raise TypeError("private catalog leases cannot be copied")

    def __deepcopy__(self, _memo: object) -> Self:
        raise TypeError("private catalog leases cannot be copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("private catalog leases cannot be serialized")

    def consume(self) -> ExportCatalogResponse:
        if self._consumed:
            raise AuthoringProviderError("private catalog lease was already consumed")
        self._consumed = True
        return self._provider._export(self._descriptor, self._capability)


class PrivateEvaluatorLease:
    """Single-use evaluator authority that cannot cross a persistence boundary."""

    __slots__ = (
        "_capability",
        "_consumed",
        "_descriptor",
        "_evaluator",
        "_lease_token",
        "_provider",
    )

    def __init__(
        self,
        provider: ExternalAuthoringProvider,
        descriptor: PrivateAuthoringProviderDescriptor,
        capability: PrivateAuthoringCapability,
        evaluator: OpaqueEvaluatorDescriptor,
        lease_token: str,
    ) -> None:
        self._provider = provider
        self._descriptor = descriptor
        self._capability = capability
        self._evaluator = evaluator
        self._lease_token = lease_token
        self._consumed = False

    @property
    def evaluator_identity(self) -> OpaqueEvaluatorDescriptor:
        return self._evaluator

    def __repr__(self) -> str:
        return (
            "PrivateEvaluatorLease("
            f"evaluator_descriptor_digest={self._evaluator.digest!r}, "
            f"consumed={self._consumed!r})"
        )

    def __copy__(self) -> Self:
        raise TypeError("private evaluator leases cannot be copied")

    def __deepcopy__(self, _memo: object) -> Self:
        raise TypeError("private evaluator leases cannot be copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("private evaluator leases cannot be serialized")

    def evaluate(
        self,
        candidate: CandidateSubmission,
        task: TaskSpec,
    ) -> EvaluateProviderResponse:
        if self._consumed:
            raise AuthoringProviderError("private evaluator lease was already consumed")
        self._consumed = True
        return self._provider._evaluate(
            self._descriptor,
            self._capability,
            self._evaluator,
            self._lease_token,
            candidate,
            task,
        )


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("provider response contains a duplicate key")
        result[key] = value
    return result


def _decode_canonical_base64(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("provider member content is not valid base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("provider member content must use canonical base64")
    return decoded


__all__ = [
    "AUTHORING_PROVIDER_PROTOCOL_REVISION",
    "AuthoringProviderError",
    "AuthoringProviderOperation",
    "AuthoringProviderRequest",
    "CandidateMember",
    "CandidateSubmission",
    "CleanRoomCatalogAttestation",
    "CleanRoomFamilyProjection",
    "DerivedTaskDocument",
    "DerivedTaskResponse",
    "DescribeProviderResponse",
    "DifficultyBinding",
    "EvaluateProviderResponse",
    "ExportCatalogResponse",
    "ExportMemberDescriptor",
    "ExportMemberRole",
    "ExportedMember",
    "ExternalAuthoringProvider",
    "FlowCandidateAttestation",
    "FlowCandidateInventory",
    "FlowCandidateRole",
    "OpaqueCatalogReference",
    "OpaqueEvaluatorDescriptor",
    "OpaqueTaskInstanceReference",
    "OpenEvaluatorProviderResponse",
    "PrivateAuthoringCapability",
    "PrivateAuthoringProviderDescriptor",
    "PrivateCatalogLease",
    "PrivateDerivationScope",
    "PrivateEvaluationAttestation",
    "PrivateEvaluatorIsolation",
    "PrivateEvaluatorLease",
    "PrivateProviderSecurityQualification",
    "QualificationProviderResponse",
    "SealedCatalogAttestation",
    "SealedFamilyAttestation",
    "SealedInstanceQualification",
    "authoring_provider_schema_digest",
    "exported_member_manifest_digest",
    "exported_role_manifest_digest",
    "flow_candidate_resource_id_for_role",
    "validate_catalog_attestation",
]
