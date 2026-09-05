"""Public-safe backend qualification and release coverage projection."""

from __future__ import annotations

from itertools import combinations
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

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
    is_comprehensive_claim,
    semantic_contract,
)
from edagym.release_commands import ReleaseEvidenceStatus
from edagym.release_evidence import EvidenceCounts, evidence_counts, evidence_status
from edagym.specs.common import Capability, Digest, Identifier, StrictModel


class BackendRoleFailure(StrictModel):
    role: FixtureRole
    failure: QualificationFailure


class BackendCapabilityEvidence(StrictModel):
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
    ) -> tuple[SemanticJoint, ...]:
        if len(value) != len(set(value)):
            raise ValueError("backend semantic joints must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

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
        ):
            raise ValueError("backend semantic evidence requires one exact implementation claim")
        comprehensive = (
            has_semantic_evidence
            and self.semantic_claim_id is not None
            and is_comprehensive_claim(
                self.capability,
                self.semantic_claim_id,
                self.semantic_joints,
            )
        )
        if self.source_kind is QualificationSourceKind.EVIDENCE_PAIR:
            if not has_semantic_evidence or self.artifact_closure_digest is None:
                raise ValueError("evidence-pair sources require a live artifact closure")
        elif has_semantic_evidence or self.artifact_closure_digest is not None:
            raise ValueError("live-probe gap sources cannot claim retained evidence")
        if self.status is ReleaseEvidenceStatus.PASSED:
            if not comprehensive or self.failures or self.unavailable is not None:
                raise ValueError("passing backend capabilities require comprehensive evidence")
        elif self.status is ReleaseEvidenceStatus.FAILED:
            if not has_semantic_evidence or not self.failures or self.unavailable is not None:
                raise ValueError("failed backend capabilities require typed evidence")
        elif self.failures or self.unavailable is None:
            raise ValueError("unavailable backend capabilities require a typed reason")
        elif has_semantic_evidence != (
            self.unavailable is QualificationGapReason.SEMANTIC_COVERAGE_INCOMPLETE
        ):
            raise ValueError(
                "only incomplete semantic evidence may accompany an unavailable capability"
            )
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
        expected_status = {
            QualificationDisposition.CONFORMANT: ReleaseEvidenceStatus.PASSED,
            QualificationDisposition.NONCONFORMANT: ReleaseEvidenceStatus.FAILED,
            QualificationDisposition.UNAVAILABLE: ReleaseEvidenceStatus.UNAVAILABLE,
            QualificationDisposition.PROBE_ONLY: ReleaseEvidenceStatus.UNAVAILABLE,
            QualificationDisposition.INCOMPLETE: ReleaseEvidenceStatus.UNAVAILABLE,
        }[self.disposition]
        if self.status is not expected_status:
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


class IndependentBackendImplementation(StrictModel):
    tool_id: Identifier
    vendor: Vendor
    implementation_family: Identifier
    deployment_attestation_digest: Digest


class BackendCapabilityCoverage(StrictModel):
    """Derived release coverage for one logical evaluator capability."""

    capability: Capability
    required_tool_count: Annotated[int, Field(strict=True, ge=1, le=3)]
    conformant_tool_ids: tuple[Identifier, ...]
    independent_implementations: tuple[IndependentBackendImplementation, ...]
    failed_tool_ids: tuple[Identifier, ...]
    unavailable_tool_ids: tuple[Identifier, ...]
    status: ReleaseEvidenceStatus

    @field_validator(
        "conformant_tool_ids",
        "failed_tool_ids",
        "unavailable_tool_ids",
    )
    @classmethod
    def normalize_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("backend coverage tool identities must be unique")
        return tuple(sorted(value))

    @field_validator("independent_implementations")
    @classmethod
    def normalize_implementations(
        cls,
        value: tuple[IndependentBackendImplementation, ...],
    ) -> tuple[IndependentBackendImplementation, ...]:
        tool_ids = [item.tool_id for item in value]
        families = [item.implementation_family for item in value]
        deployments = [item.deployment_attestation_digest for item in value]
        if (
            len(tool_ids) != len(set(tool_ids))
            or len(families) != len(set(families))
            or len(deployments) != len(set(deployments))
        ):
            raise ValueError(
                "independent backend implementations require unique tools, families, "
                "and deployments"
            )
        return tuple(sorted(value, key=lambda item: item.tool_id))

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        groups = (
            set(self.conformant_tool_ids),
            set(self.failed_tool_ids),
            set(self.unavailable_tool_ids),
        )
        if groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2]:
            raise ValueError("backend coverage tool partitions must be disjoint")
        independent_tool_ids = {
            item.tool_id for item in self.independent_implementations
        }
        if not independent_tool_ids.issubset(groups[0]):
            raise ValueError("independent backend tools must be conformant")
        contract = semantic_contract(self.capability)
        if self.required_tool_count != contract.effective_required_implementations:
            raise ValueError("backend coverage requirement must be policy-derived")
        covered = (
            len(self.independent_implementations)
            >= contract.effective_required_implementations
            and set(contract.required_tool_ids).issubset(independent_tool_ids)
            and set(contract.required_vendors).issubset(
                {item.vendor for item in self.independent_implementations}
            )
        )
        if covered:
            expected_status = ReleaseEvidenceStatus.PASSED
        elif self.failed_tool_ids:
            expected_status = ReleaseEvidenceStatus.FAILED
        else:
            expected_status = ReleaseEvidenceStatus.UNAVAILABLE
        if self.status is not expected_status:
            raise ValueError("backend coverage status must be derived from qualification pairs")
        return self

    @property
    def independent_tool_ids(self) -> tuple[Identifier, ...]:
        return tuple(item.tool_id for item in self.independent_implementations)


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
        source.qualification.requested_capabilities[0]: source
        for source in ordered_sources
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
        comprehensive = is_comprehensive_claim(
            capability,
            semantic_claim_id,
            semantic_joints,
        )
        passed = all(item.outcome is QualificationOutcome.PASSED for item in paired)
        capability_summaries.append(
            BackendCapabilityEvidence(
                capability=capability,
                status=(
                    ReleaseEvidenceStatus.PASSED
                    if passed and comprehensive
                    else ReleaseEvidenceStatus.UNAVAILABLE
                    if passed
                    else ReleaseEvidenceStatus.FAILED
                ),
                source_kind=source.source_kind,
                verified_source_digest=source.source_digest,
                artifact_closure_digest=source.artifact_closure_digest,
                evidence_digest=pair_digest,
                semantic_claim_id=semantic_claim_id,
                semantic_joints=semantic_joints,
                implementation_family=implementation_families[capability],
                failures=failures,
                unavailable=(
                    QualificationGapReason.SEMANTIC_COVERAGE_INCOMPLETE
                    if passed and not comprehensive
                    else None
                ),
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
        status={
            QualificationDisposition.CONFORMANT: ReleaseEvidenceStatus.PASSED,
            QualificationDisposition.NONCONFORMANT: ReleaseEvidenceStatus.FAILED,
            QualificationDisposition.UNAVAILABLE: ReleaseEvidenceStatus.UNAVAILABLE,
            QualificationDisposition.PROBE_ONLY: ReleaseEvidenceStatus.UNAVAILABLE,
            QualificationDisposition.INCOMPLETE: ReleaseEvidenceStatus.UNAVAILABLE,
        }[qualification.disposition],
    )


def required_backend_count(capability: Capability) -> int:
    return semantic_contract(capability).effective_required_implementations


def project_backend_coverage(
    backends: tuple[BackendQualificationEvidence, ...],
) -> tuple[BackendCapabilityCoverage, ...]:
    """Derive the full capability coverage matrix from public-safe qualifications."""

    summaries: list[BackendCapabilityCoverage] = []
    for capability in Capability:
        matching = tuple(
            (backend, result)
            for backend in backends
            for result in backend.capabilities
            if result.capability is capability
        )
        conformant = tuple(
            (backend, result)
            for backend, result in matching
            if result.status is ReleaseEvidenceStatus.PASSED
        )
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
        candidates = tuple(
            IndependentBackendImplementation(
                tool_id=backend.tool_id,
                vendor=backend.vendor,
                implementation_family=result.implementation_family,
                deployment_attestation_digest=backend.deployment_attestation_digest,
            )
            for backend, result in conformant
            if result.implementation_family is not None
            and backend.deployment_attestation_digest is not None
        )
        contract = semantic_contract(capability)
        independent = _select_independent_implementations(candidates, capability)
        required = required_backend_count(capability)
        independent_tool_ids = {item.tool_id for item in independent}
        covered = (
            len(independent) >= required
            and set(contract.required_tool_ids).issubset(independent_tool_ids)
            and set(contract.required_vendors).issubset(
                {item.vendor for item in independent}
            )
        )
        status = (
            ReleaseEvidenceStatus.PASSED
            if covered
            else ReleaseEvidenceStatus.FAILED
            if failed
            else ReleaseEvidenceStatus.UNAVAILABLE
        )
        summaries.append(
            BackendCapabilityCoverage(
                capability=capability,
                required_tool_count=required,
                conformant_tool_ids=tuple(item.tool_id for item, _ in conformant),
                independent_implementations=independent,
                failed_tool_ids=failed,
                unavailable_tool_ids=unavailable,
                status=status,
            )
        )
    return tuple(sorted(summaries, key=lambda item: item.capability.value))


def _select_independent_implementations(
    candidates: tuple[IndependentBackendImplementation, ...],
    capability: Capability,
) -> tuple[IndependentBackendImplementation, ...]:
    """Choose the strongest deterministic set with independent lineage and deployment."""

    contract = semantic_contract(capability)
    valid: list[tuple[IndependentBackendImplementation, ...]] = []
    ordered = tuple(sorted(candidates, key=lambda item: item.tool_id))
    for size in range(1, len(ordered) + 1):
        for selection in combinations(ordered, size):
            if len({item.implementation_family for item in selection}) != size or len(
                {item.deployment_attestation_digest for item in selection}
            ) != size:
                continue
            valid.append(selection)
    if not valid:
        return ()

    required_tools = set(contract.required_tool_ids)
    required_vendors = set(contract.required_vendors)

    def score(
        selection: tuple[IndependentBackendImplementation, ...],
    ) -> tuple[int, int, int, int, tuple[str, ...]]:
        tools = {item.tool_id for item in selection}
        vendors = {item.vendor for item in selection}
        covered = (
            len(selection) >= contract.effective_required_implementations
            and required_tools.issubset(tools)
            and required_vendors.issubset(vendors)
        )
        return (
            int(covered),
            len(required_tools & tools),
            len(required_vendors & vendors),
            len(selection),
            tuple(item.tool_id for item in selection),
        )

    return max(valid, key=score)
