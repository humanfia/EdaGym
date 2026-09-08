"""Public-safe backend qualification and release coverage projection."""

from __future__ import annotations

from typing import Annotated, Self

from pydantic import Field, ValidationInfo, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.drivers.fixtures.model import FixtureRole
from edagym.drivers.model import BackendDefinition, Vendor
from edagym.drivers.qualification import (
    QualificationDisposition,
    QualificationFailure,
    QualificationGapReason,
    QualificationOutcome,
    aggregate_backend_qualifications,
)
from edagym.drivers.qualification_verification import (
    QualificationSourceKind,
    VerifiedBackendQualificationSource,
)
from edagym.drivers.semantic_claims import (
    SemanticJoint,
    joint_capability,
    semantic_contract,
)
from edagym.release_commands import ReleaseEvidenceStatus
from edagym.release_evidence import EvidenceCounts, evidence_counts, evidence_status
from edagym.specs.common import Capability, Digest, Identifier, StrictModel

_DISPOSITION_STATUS = {
    QualificationDisposition.CONFORMANT: ReleaseEvidenceStatus.PASSED,
    QualificationDisposition.NONCONFORMANT: ReleaseEvidenceStatus.FAILED,
    QualificationDisposition.UNAVAILABLE: ReleaseEvidenceStatus.UNAVAILABLE,
    QualificationDisposition.PROBE_ONLY: ReleaseEvidenceStatus.UNAVAILABLE,
    QualificationDisposition.INCOMPLETE: ReleaseEvidenceStatus.UNAVAILABLE,
}


def _normalize_joints(
    capability: Capability,
    value: tuple[SemanticJoint, ...],
) -> tuple[SemanticJoint, ...]:
    if len(value) != len(set(value)) or any(
        joint_capability(item) is not capability for item in value
    ):
        raise ValueError("backend semantic joints must be unique and owned by the capability")
    return tuple(sorted(value, key=lambda item: item.value))


class BackendRoleFailure(StrictModel):
    role: FixtureRole
    failure: QualificationFailure


class BackendCapabilityEvidence(StrictModel):
    """One tool-capability pair: its verified source, exact claim scope, and status."""

    capability: Capability
    status: ReleaseEvidenceStatus
    source_kind: QualificationSourceKind
    verified_source_digest: Digest
    artifact_closure_digest: Digest | None = None
    evidence_digest: Digest | None = None
    semantic_claim_id: Identifier | None = None
    semantic_joints: tuple[SemanticJoint, ...] = ()
    implementation_family: Identifier | None = None
    failures: tuple[BackendRoleFailure, ...] = ()
    unavailable: QualificationGapReason | None = None

    @field_validator("semantic_joints")
    @classmethod
    def normalize_semantic_joints(
        cls,
        value: tuple[SemanticJoint, ...],
        info: ValidationInfo,
    ) -> tuple[SemanticJoint, ...]:
        return _normalize_joints(info.data["capability"], value)

    @field_validator("failures")
    @classmethod
    def normalize_failures(
        cls, value: tuple[BackendRoleFailure, ...]
    ) -> tuple[BackendRoleFailure, ...]:
        roles = [item.role for item in value]
        if len(roles) != len(set(roles)):
            raise ValueError("backend role failures must be unique")
        return tuple(sorted(value, key=lambda item: item.role.value))

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        has_semantic_evidence = self.evidence_digest is not None
        if has_semantic_evidence != (
            self.semantic_claim_id is not None
            and self.implementation_family is not None
            and bool(self.semantic_joints)
        ):
            raise ValueError("backend semantic evidence requires one exact implementation claim")
        if self.source_kind is QualificationSourceKind.EVIDENCE_PAIR:
            if not has_semantic_evidence or self.artifact_closure_digest is None:
                raise ValueError("evidence-pair sources require a live artifact closure")
        elif has_semantic_evidence or self.artifact_closure_digest is not None:
            raise ValueError("live-probe gap sources cannot claim retained evidence")
        if self.status is ReleaseEvidenceStatus.PASSED:
            if not has_semantic_evidence or self.failures or self.unavailable is not None:
                raise ValueError("passing backend capabilities require both passing roles")
        elif self.status is ReleaseEvidenceStatus.FAILED:
            if not has_semantic_evidence or not self.failures or self.unavailable is not None:
                raise ValueError("failed backend capabilities require typed evidence")
        elif has_semantic_evidence or self.failures or self.unavailable is None:
            raise ValueError("unavailable backend capabilities require a typed reason")
        return self


class BackendQualificationEvidence(StrictModel):
    tool_id: Identifier
    vendor: Vendor
    driver_digest: Digest
    tool_version: str | None
    deployment_attestation_digest: Digest | None
    qualification_digest: Digest
    disposition: QualificationDisposition
    capabilities: Annotated[tuple[BackendCapabilityEvidence, ...], Field(min_length=1)]
    counts: EvidenceCounts
    status: ReleaseEvidenceStatus

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(
        cls, value: tuple[BackendCapabilityEvidence, ...]
    ) -> tuple[BackendCapabilityEvidence, ...]:
        capabilities = [item.capability for item in value]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("backend capability results must be unique")
        return tuple(sorted(value, key=lambda item: item.capability.value))

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if not self.counts.total:
            raise ValueError("backend evidence must cover at least one capability")
        if self.counts != evidence_counts(item.status for item in self.capabilities):
            raise ValueError("backend counts must be derived from capability results")
        if self.status is not _DISPOSITION_STATUS[self.disposition]:
            raise ValueError("backend status must be derived from its disposition")
        if self.status is not evidence_status(self.counts):
            raise ValueError("backend status must agree with its capability counts")
        if self.disposition is QualificationDisposition.CONFORMANT and (
            self.tool_version is None or self.deployment_attestation_digest is None
        ):
            raise ValueError("conformant backend evidence requires a versioned deployment identity")
        if self.disposition is not QualificationDisposition.CONFORMANT and (
            self.tool_version is not None and self.deployment_attestation_digest is None
        ):
            raise ValueError("backend versions require an opaque deployment identity")
        return self


class BackendCapabilityClaim(StrictModel):
    """The exact semantic scope one conformant tool has proven for a capability."""

    tool_id: Identifier
    vendor: Vendor
    implementation_family: Identifier
    semantic_joints: Annotated[tuple[SemanticJoint, ...], Field(min_length=1)]


class BackendCapabilityCoverage(StrictModel):
    """Derived release coverage for one logical evaluator capability.

    The contract in ``semantic_claims`` is the only owner of the required joints and
    independence rule; every field here is derived from it and from the conformant claims.
    """

    capability: Capability
    required_joints: tuple[SemanticJoint, ...]
    required_implementations: Annotated[int, Field(strict=True, ge=1, le=3)]
    claims: tuple[BackendCapabilityClaim, ...]
    independent_implementations: tuple[BackendCapabilityClaim, ...] = ()
    uncovered_joints: tuple[SemanticJoint, ...]
    failed_tool_ids: tuple[Identifier, ...]
    unavailable_tool_ids: tuple[Identifier, ...]
    status: ReleaseEvidenceStatus

    @field_validator("required_joints", "uncovered_joints")
    @classmethod
    def normalize_joint_sets(
        cls,
        value: tuple[SemanticJoint, ...],
        info: ValidationInfo,
    ) -> tuple[SemanticJoint, ...]:
        return _normalize_joints(info.data["capability"], value)

    @field_validator("failed_tool_ids", "unavailable_tool_ids")
    @classmethod
    def normalize_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("backend coverage tool identities must be unique")
        return tuple(sorted(value))

    @field_validator("claims")
    @classmethod
    def normalize_claims(
        cls,
        value: tuple[BackendCapabilityClaim, ...],
    ) -> tuple[BackendCapabilityClaim, ...]:
        tool_ids = [item.tool_id for item in value]
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("backend coverage claims require unique tools")
        return tuple(sorted(value, key=lambda item: item.tool_id))

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        contract = semantic_contract(self.capability)
        if any(
            _normalize_joints(self.capability, claim.semantic_joints) != claim.semantic_joints
            for claim in self.claims
        ):
            raise ValueError("backend coverage claims must carry canonical capability joints")
        if (
            self.required_joints != contract.required_joints
            or self.required_implementations != contract.effective_required_implementations
        ):
            raise ValueError("backend coverage requirement must be policy-derived")
        conformant = {item.tool_id for item in self.claims}
        if self.independent_implementations != self.claims:
            raise ValueError("independent implementations must be derived from qualifications")
        if (
            conformant & set(self.failed_tool_ids)
            or conformant & set(self.unavailable_tool_ids)
            or set(self.failed_tool_ids) & set(self.unavailable_tool_ids)
        ):
            raise ValueError("backend coverage tool partitions must be disjoint")
        claimed = {joint for item in self.claims for joint in item.semantic_joints}
        if set(self.uncovered_joints) != set(self.required_joints) - claimed:
            raise ValueError("uncovered joints must be derived from the conformant claims")
        expected_status = (
            ReleaseEvidenceStatus.PASSED
            if self.covered
            else ReleaseEvidenceStatus.FAILED
            if self.failed_tool_ids
            else ReleaseEvidenceStatus.UNAVAILABLE
        )
        if self.status is not expected_status:
            raise ValueError("backend coverage status must be derived from qualification pairs")
        return self

    @property
    def conformant_tool_ids(self) -> tuple[Identifier, ...]:
        return tuple(item.tool_id for item in self.claims)

    @property
    def covered(self) -> bool:
        contract = semantic_contract(self.capability)
        return (
            not self.uncovered_joints
            and len({item.implementation_family for item in self.independent_implementations})
            >= self.required_implementations
            and set(contract.required_tool_ids).issubset(self.conformant_tool_ids)
            and set(contract.required_vendors).issubset(item.vendor for item in self.claims)
        )


def project_backend_qualification(
    sources: tuple[VerifiedBackendQualificationSource, ...],
    definition: BackendDefinition,
) -> BackendQualificationEvidence:
    """Project one catalog backend from its exact live capability sources."""

    if not sources or any(
        type(source) is not VerifiedBackendQualificationSource for source in sources
    ):
        raise TypeError("backend projection requires live verified qualification sources")
    ordered_sources = tuple(
        sorted(
            sources,
            key=lambda source: source.qualification.requested_capabilities[0].value,
        )
    )
    qualifications = tuple(source.qualification for source in ordered_sources)
    qualification = aggregate_backend_qualifications(definition, qualifications)
    source_by_capability = {
        source.qualification.requested_capabilities[0]: source for source in ordered_sources
    }
    if len(source_by_capability) != len(ordered_sources) or (
        qualification.probe.tool_id != definition.tool_id
        or qualification.probe.vendor is not definition.vendor
        or qualification.probe.driver_digest != definition.driver_digest
        or set(qualification.requested_capabilities) != set(definition.capabilities)
    ):
        raise ValueError("backend qualification diverges from its public catalog definition")
    evidence_by_capability = {
        capability: tuple(item for item in qualification.evidence if item.capability is capability)
        for capability in qualification.requested_capabilities
    }
    implementation_families = {
        item.capability: item.implementation_family for item in definition.fixtures
    }
    gaps = {item.capability: item.reason for item in qualification.gaps}
    capability_summaries: list[BackendCapabilityEvidence] = []
    for capability in qualification.requested_capabilities:
        source = source_by_capability[capability]
        paired = evidence_by_capability[capability]
        if not paired:
            if source.source_kind is not QualificationSourceKind.LIVE_PROBE_GAP:
                raise ValueError("evidence source lacks its verified qualification pair")
            capability_summaries.append(
                BackendCapabilityEvidence(
                    capability=capability,
                    status=ReleaseEvidenceStatus.UNAVAILABLE,
                    source_kind=source.source_kind,
                    verified_source_digest=source.source_digest,
                    unavailable=gaps[capability],
                )
            )
            continue
        if (
            source.source_kind is not QualificationSourceKind.EVIDENCE_PAIR
            or source.artifact_closure_digest is None
        ):
            raise ValueError("qualification evidence lacks its verified live artifact closure")
        failures = tuple(
            BackendRoleFailure(role=item.role, failure=item.failure)
            for item in paired
            if item.failure is not None
        )
        pair_digest = canonical_digest(
            {
                "verified_source_digest": source.source_digest,
                "capability": capability,
                "role_evidence": tuple(
                    {"role": item.role, "evidence_digest": item.digest} for item in paired
                ),
            },
            domain="release-backend-capability-evidence-v2",
        )
        claim_identities = {
            (item.fixture.semantic_claim_id, item.fixture.semantic_joints) for item in paired
        }
        if len(claim_identities) != 1 or capability not in implementation_families:
            raise ValueError("backend evidence lacks one catalog-bound semantic implementation")
        semantic_claim_id, semantic_joints = next(iter(claim_identities))
        passed = all(item.outcome is QualificationOutcome.PASSED for item in paired)
        capability_summaries.append(
            BackendCapabilityEvidence(
                capability=capability,
                status=ReleaseEvidenceStatus.PASSED if passed else ReleaseEvidenceStatus.FAILED,
                source_kind=source.source_kind,
                verified_source_digest=source.source_digest,
                artifact_closure_digest=source.artifact_closure_digest,
                evidence_digest=pair_digest,
                semantic_claim_id=semantic_claim_id,
                semantic_joints=semantic_joints,
                implementation_family=implementation_families[capability],
                failures=failures,
            )
        )
    capabilities = tuple(capability_summaries)
    counts = evidence_counts(item.status for item in capabilities)
    return BackendQualificationEvidence(
        tool_id=qualification.probe.tool_id,
        vendor=qualification.probe.vendor,
        driver_digest=qualification.probe.driver_digest,
        tool_version=qualification.probe.tool_version,
        deployment_attestation_digest=qualification.probe.deployment_attestation_digest,
        qualification_digest=qualification.digest,
        disposition=qualification.disposition,
        capabilities=capabilities,
        counts=counts,
        status=_DISPOSITION_STATUS[qualification.disposition],
    )


def project_backend_coverage(
    backends: tuple[BackendQualificationEvidence, ...],
) -> tuple[BackendCapabilityCoverage, ...]:
    """Derive the full capability coverage matrix from public-safe qualifications."""

    summaries: list[BackendCapabilityCoverage] = []
    for capability in Capability:
        contract = semantic_contract(capability)
        matching = tuple(
            (backend, result)
            for backend in backends
            for result in backend.capabilities
            if result.capability is capability
        )
        claims = tuple(
            BackendCapabilityClaim(
                tool_id=backend.tool_id,
                vendor=backend.vendor,
                implementation_family=result.implementation_family,
                semantic_joints=result.semantic_joints,
            )
            for backend, result in matching
            if result.status is ReleaseEvidenceStatus.PASSED
            and result.implementation_family is not None
        )
        claimed = {joint for item in claims for joint in item.semantic_joints}
        uncovered = tuple(joint for joint in contract.required_joints if joint not in claimed)
        failed = tuple(
            backend.tool_id
            for backend, result in matching
            if result.status is ReleaseEvidenceStatus.FAILED
        )
        unavailable = tuple(
            backend.tool_id
            for backend, result in matching
            if result.status is ReleaseEvidenceStatus.UNAVAILABLE
        )
        families = {item.implementation_family for item in claims}
        covered = (
            not uncovered
            and len(families) >= contract.effective_required_implementations
            and set(contract.required_tool_ids).issubset(item.tool_id for item in claims)
            and set(contract.required_vendors).issubset(item.vendor for item in claims)
        )
        summaries.append(
            BackendCapabilityCoverage(
                capability=capability,
                required_joints=contract.required_joints,
                required_implementations=contract.effective_required_implementations,
                claims=claims,
                independent_implementations=claims,
                uncovered_joints=uncovered,
                failed_tool_ids=failed,
                unavailable_tool_ids=unavailable,
                status=(
                    ReleaseEvidenceStatus.PASSED
                    if covered
                    else ReleaseEvidenceStatus.FAILED
                    if failed
                    else ReleaseEvidenceStatus.UNAVAILABLE
                ),
            )
        )
    return tuple(sorted(summaries, key=lambda item: item.capability.value))
