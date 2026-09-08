"""Release projection for the sealed Sail authoring catalog."""

from __future__ import annotations

from typing import Self

from pydantic import field_validator, model_validator

from edagym.authoring.provider import (
    DerivedTaskDocument,
    PrivateAuthoringCapability,
    QualificationProviderResponse,
    SealedCatalogAttestation,
    validate_catalog_attestation,
)
from edagym.release_commands import ReleaseEvidenceStatus
from edagym.release_evidence import EvidenceCounts
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.release import ReleaseQualification
from edagym.task_families.catalog import PublicTaskCatalog, TaskRoot


class AuthoringCatalogEvidence(StrictModel):
    public_catalog_digest: Digest
    catalog_attestation_digest: Digest
    catalog_reference_digest: Digest
    member_manifest_digest: Digest
    provider_descriptor_digest: Digest
    provider_implementation_digest: Digest
    provider_security_qualification_digest: Digest
    clean_room_attestation_digest: Digest
    clean_room_auditor_descriptor_digest: Digest
    clean_room_auditor_implementation_digest: Digest
    reference_tree_snapshot_digest: Digest
    reference_inventory_digest: Digest
    human_review_aggregate_digest: Digest
    clean_room_family_projection_digests: tuple[Digest, ...]
    families: tuple[Identifier, ...]
    task_spec_digests: tuple[Digest, ...]
    instance_digests: tuple[Digest, ...]
    release_digests: tuple[Digest, ...]
    release_environment_digests: tuple[Digest, ...]
    qualification_digests: tuple[Digest, ...]
    qualification_request_digests: tuple[Digest, ...]
    counts: EvidenceCounts
    status: ReleaseEvidenceStatus

    @field_validator(
        "clean_room_family_projection_digests",
        "families",
        "task_spec_digests",
        "instance_digests",
        "release_digests",
        "release_environment_digests",
        "qualification_digests",
        "qualification_request_digests",
    )
    @classmethod
    def normalize_sets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("authoring release identities must be unique and non-empty")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_complete_catalog(self) -> Self:
        if len(self.families) != len(self.clean_room_family_projection_digests):
            raise ValueError("authoring evidence must cover every registered family")
        release_counts = (
            len(self.instance_digests),
            len(self.release_digests),
            len(self.qualification_digests),
            len(self.qualification_request_digests),
        )
        if len(set(release_counts)) != 1:
            raise ValueError("authoring evidence references must cover the same instances")
        expected_counts = EvidenceCounts(
            passed=release_counts[0], failed=0, unavailable=0, total=release_counts[0]
        )
        if self.counts != expected_counts or self.status is not ReleaseEvidenceStatus.PASSED:
            raise ValueError("complete sealed authoring evidence must derive a passing status")
        return self


def project_authoring_catalog(
    public_catalog: PublicTaskCatalog,
    attestation: SealedCatalogAttestation,
    task_documents: tuple[DerivedTaskDocument, ...],
    qualification_responses: tuple[QualificationProviderResponse, ...],
) -> AuthoringCatalogEvidence:
    """Join the exact sealed catalog, clean-room proof, and forty live responses."""

    sail_families = {
        item.family: item
        for item in public_catalog.families
        if item.root is TaskRoot.SAIL_RTL
    }
    if (
        not sail_families
        or attestation.capability is not PrivateAuthoringCapability.SAIL_RTL_CATALOG
        or attestation.public_catalog_digest != public_catalog.digest
    ):
        raise ValueError("Sail authoring does not bind the complete public task catalog")
    if not qualification_responses:
        raise ValueError("Sail authoring requires live qualification responses")
    descriptor = qualification_responses[0].descriptor
    validate_catalog_attestation(descriptor, attestation)
    if any(item.descriptor != descriptor for item in qualification_responses):
        raise ValueError("Sail qualifications must share one exact provider descriptor")

    families = {item.family: item for item in attestation.families}
    if len(families) != len(attestation.families) or set(families) != set(sail_families):
        raise ValueError("sealed Sail families must exactly cover public metadata")
    documents = {
        (item.instance_reference.family, item.instance_reference.instance_name): item
        for item in task_documents
    }
    expected_instances = {
        (family.family, instance_name)
        for family in sail_families.values()
        for instance_name in family.instance_names
    }
    if len(documents) != len(task_documents) or set(documents) != expected_instances:
        raise ValueError("Sail documents must contain the declared instances")
    responses = {
        item.instance_reference_digest: item for item in qualification_responses
    }
    expected_references = {
        item.instance_reference.digest for item in task_documents
    }
    if len(responses) != len(qualification_responses) or set(responses) != expected_references:
        raise ValueError("Sail qualifications must exactly cover every derived instance")

    releases = []
    qualifications = []
    request_digests = []
    for identity, document in documents.items():
        family, instance_name = identity
        reference = document.instance_reference
        family_evidence = families[family]
        matches = tuple(
            item
            for item in family_evidence.instances
            if item.instance_reference_digest == reference.digest
            and item.instance_reference_id == reference.reference_id
        )
        if len(matches) != 1:
            raise ValueError("Sail document lacks one exact sealed qualification")
        instance_evidence = matches[0]
        response = responses[reference.digest]
        release = response.release
        if (
            family_evidence.public_metadata_digest != sail_families[family].digest
            or family_evidence.task_spec_digest != document.task.digest
            or reference.capability is not PrivateAuthoringCapability.SAIL_RTL_CATALOG
            or reference.provider_id != attestation.catalog_reference.provider_id
            or reference.family != family
            or reference.instance_name != instance_name
            or response.instance_reference_digest != reference.digest
            or response.qualification != instance_evidence
            or release.task_spec_digest != document.task.digest
            or release.task_instance_digest != document.instance.digest
            or release.files != document.instance.generated_files
            or release.participant_bundle_digest != reference.participant_bundle_digest
            or release.verifier_bundle_digest != reference.verifier_bundle_digest
            or not isinstance(release.qualification, ReleaseQualification)
        ):
            raise ValueError("Sail release diverges from its sealed authoring sources")
        releases.append(release)
        qualifications.append(release.qualification.digest)
        request_digests.append(response.request_digest)

    task_digests = {item.task.digest for item in task_documents}
    if len(task_digests) != len(sail_families):
        raise ValueError("Sail instances must share one TaskSpec per generated family")
    clean_room = attestation.clean_room_attestation
    if clean_room is None or not clean_room.passed:
        raise ValueError("Sail catalog lacks its complete clean-room attestation")
    return AuthoringCatalogEvidence(
        public_catalog_digest=public_catalog.digest,
        catalog_attestation_digest=attestation.digest,
        catalog_reference_digest=attestation.catalog_reference.digest,
        member_manifest_digest=attestation.member_manifest_digest,
        provider_descriptor_digest=descriptor.digest,
        provider_implementation_digest=descriptor.implementation_digest,
        provider_security_qualification_digest=descriptor.security_qualification_digest,
        clean_room_attestation_digest=clean_room.digest,
        clean_room_auditor_descriptor_digest=clean_room.auditor_descriptor_digest,
        clean_room_auditor_implementation_digest=clean_room.auditor_implementation_digest,
        reference_tree_snapshot_digest=clean_room.reference_tree_snapshot_digest,
        reference_inventory_digest=clean_room.reference_inventory_digest,
        human_review_aggregate_digest=clean_room.human_review_aggregate_digest,
        clean_room_family_projection_digests=tuple(
            item.digest for item in clean_room.families
        ),
        families=tuple(sail_families),
        task_spec_digests=tuple(task_digests),
        instance_digests=tuple(item.instance.digest for item in task_documents),
        release_digests=tuple(item.digest for item in releases),
        release_environment_digests=tuple(
            {digest for item in releases for digest in item.environment_digests}
        ),
        qualification_digests=tuple(qualifications),
        qualification_request_digests=tuple(request_digests),
        counts=EvidenceCounts(
            passed=len(task_documents), failed=0, unavailable=0, total=len(task_documents)
        ),
        status=ReleaseEvidenceStatus.PASSED,
    )
