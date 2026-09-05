"""Digest-only clean-room evidence produced by a restricted catalog auditor."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, Identifier, JcsPositiveInt, SchemaVersion, StrictModel
from edagym.task_families.catalog import TaskRoot, families_for_root


class CleanRoomFamilyProjection(StrictModel):
    """Result of comparing one complete public/reference family pair."""

    family: Identifier
    public_metadata_digest: Digest
    public_member_inventory_digest: Digest
    public_member_count: JcsPositiveInt
    reference_family_snapshot_digest: Digest
    reference_member_inventory_digest: Digest
    reference_member_count: JcsPositiveInt
    normalized_public_abi_graph_digest: Digest
    normalized_reference_abi_graph_digest: Digest
    abi_mapping_evidence_digest: Digest
    content_overlap_evidence_digest: Digest
    content_overlap_count: Literal[0] = 0
    human_semantic_review_receipt_digest: Digest
    semantic_overlap_found: Literal[False] = False
    passed: Literal[True] = True

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="clean-room-family-projection-v1")


class CleanRoomCatalogAttestation(StrictModel):
    """Complete restricted comparison projected without paths or source bytes."""

    schema_version: SchemaVersion = 1
    auditor_descriptor_digest: Digest
    auditor_implementation_digest: Digest
    reference_tree_snapshot_digest: Digest
    reference_inventory_digest: Digest
    human_review_aggregate_digest: Digest
    families: tuple[CleanRoomFamilyProjection, ...]
    passed: Literal[True] = True

    @field_validator("families")
    @classmethod
    def normalize_families(
        cls,
        value: tuple[CleanRoomFamilyProjection, ...],
    ) -> tuple[CleanRoomFamilyProjection, ...]:
        identifiers = [item.family for item in value]
        if len(identifiers) != 20 or len(identifiers) != len(set(identifiers)):
            raise ValueError("clean-room attestation requires exactly 20 unique families")
        return tuple(sorted(value, key=lambda item: item.family))

    @staticmethod
    def derive_reference_inventory_digest(
        families: tuple[CleanRoomFamilyProjection, ...],
    ) -> Digest:
        ordered = tuple(sorted(families, key=lambda item: item.family))
        return canonical_digest(
            tuple(
                {
                    "family": item.family,
                    "reference_family_snapshot_digest": item.reference_family_snapshot_digest,
                    "reference_member_count": item.reference_member_count,
                    "reference_member_inventory_digest": (
                        item.reference_member_inventory_digest
                    ),
                }
                for item in ordered
            ),
            domain="clean-room-reference-inventory-v1",
        )

    @staticmethod
    def derive_human_review_aggregate_digest(
        families: tuple[CleanRoomFamilyProjection, ...],
    ) -> Digest:
        ordered = tuple(sorted(families, key=lambda item: item.family))
        return canonical_digest(
            tuple(
                {
                    "family": item.family,
                    "receipt_digest": item.human_semantic_review_receipt_digest,
                }
                for item in ordered
            ),
            domain="clean-room-human-review-aggregate-v1",
        )

    @model_validator(mode="after")
    def bind_complete_inventory(self) -> Self:
        expected_metadata = {
            item.family: item.digest for item in families_for_root(TaskRoot.SAIL_RTL)
        }
        actual_metadata = {
            item.family: item.public_metadata_digest for item in self.families
        }
        if actual_metadata != expected_metadata:
            raise ValueError("clean-room attestation does not cover exact Sail metadata")
        if (
            self.reference_inventory_digest
            != self.derive_reference_inventory_digest(self.families)
            or self.human_review_aggregate_digest
            != self.derive_human_review_aggregate_digest(self.families)
        ):
            raise ValueError("clean-room aggregate digests are not derived from all families")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="clean-room-catalog-attestation-v1")


__all__ = ["CleanRoomCatalogAttestation", "CleanRoomFamilyProjection"]
