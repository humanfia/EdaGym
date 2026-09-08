"""Explicit private flow catalog loaded through the authoring boundary."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from edagym.authoring.provider import (
    AuthoringProviderError,
    ExportCatalogResponse,
    ExportMemberRole,
    ExternalAuthoringProvider,
    FlowCandidateAttestation,
    FlowCandidateInventory,
    FlowCandidateRole,
    PrivateAuthoringCapability,
    SealedCatalogAttestation,
    SealedFamilyAttestation,
    validate_catalog_attestation,
)
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers.catalog import backend_by_id
from edagym.flow_tasks.canonical import (
    CanonicalFlowTask,
    derive_flow_release,
    flow_candidate_manifest_digest,
    flow_candidate_resource_id,
    validate_canonical_flow_task,
)
from edagym.flow_tasks.model import (
    CandidateExpectation,
    CandidateVariant,
    FlowTaskPack,
    ToolCommand,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.trial_model import RunRecord
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest
from edagym.task_families.catalog import PublicTaskCatalog, TaskFamilyDefinition, TaskRoot


@dataclass(frozen=True, repr=False)
class FlowTaskCatalog:
    """Trusted in-memory view of private packs and their digest-only attestation."""

    public_catalog_digest: str
    provider_descriptor_digest: str
    attestation: SealedCatalogAttestation
    _packs: MappingProxyType[str, FlowTaskPack]
    _canonical: MappingProxyType[tuple[str, str], CanonicalFlowTask]

    def __repr__(self) -> str:
        return (
            "FlowTaskCatalog("
            f"public_catalog_digest={self.public_catalog_digest!r}, "
            f"provider_descriptor_digest={self.provider_descriptor_digest!r}, "
            f"attestation_digest={self.attestation.digest!r}, packs=<restricted>)"
        )

    @property
    def families(self) -> tuple[str, ...]:
        return tuple(sorted(self._packs))

    def task_pack(self, family: str) -> FlowTaskPack:
        try:
            return self._packs[family]
        except KeyError:
            raise KeyError(family) from None

    def canonical_task(
        self,
        family: str,
        instance_name: str = "base",
    ) -> CanonicalFlowTask:
        try:
            return self._canonical[(family, instance_name)]
        except KeyError:
            raise KeyError((family, instance_name)) from None

    def family_attestation(self, family: str) -> SealedFamilyAttestation:
        matches = [item for item in self.attestation.families if item.family == family]
        if len(matches) != 1:
            raise KeyError(family)
        return matches[0]

    def candidate_inventory(
        self,
        family: str,
        candidate_resource_id: str,
    ) -> FlowCandidateInventory:
        matches = [
            item
            for item in self.family_attestation(family).flow_candidate_inventory
            if item.candidate_resource_id == candidate_resource_id
        ]
        if len(matches) != 1:
            raise KeyError((family, candidate_resource_id))
        return matches[0]


def load_private_flow_catalog(
    provider: ExternalAuthoringProvider,
    public_catalog: PublicTaskCatalog,
) -> FlowTaskCatalog:
    """Consume one provider lease and validate every private flow pack."""

    exported = provider.open_catalog(PrivateAuthoringCapability.EDA_FLOW_CATALOG).consume()
    return flow_catalog_from_export(exported, public_catalog)


def flow_catalog_from_export(
    exported: ExportCatalogResponse,
    public_catalog: PublicTaskCatalog,
) -> FlowTaskCatalog:
    """Build a private catalog only from an exact digest-bound provider export."""

    descriptor = exported.descriptor
    attestation = exported.attestation
    if public_catalog.digest != descriptor.public_catalog_digest:
        raise AuthoringProviderError("flow provider targets a different public catalog")
    if attestation.capability is not PrivateAuthoringCapability.EDA_FLOW_CATALOG:
        raise AuthoringProviderError("provider export is not an EDA flow catalog")
    validate_catalog_attestation(descriptor, attestation)

    flow_metadata = {
        item.family: item
        for item in public_catalog.families
        if item.root is TaskRoot.EDA_FLOW
    }
    pack_members = [
        item for item in exported.members if item.role is ExportMemberRole.FLOW_TASK_PACK
    ]
    packs: dict[str, FlowTaskPack] = {}
    canonical_tasks: dict[tuple[str, str], CanonicalFlowTask] = {}
    for member in pack_members:
        if member.family is None:
            raise AuthoringProviderError("flow task-pack member has no family")
        pack = _load_canonical_pack(member.content)
        if pack.family != member.family or pack.family in packs:
            raise AuthoringProviderError("flow task-pack member identity is ambiguous")
        try:
            metadata = flow_metadata[pack.family]
        except KeyError:
            raise AuthoringProviderError("flow task pack is not in the public catalog") from None
        _validate_flow_task_pack(pack, metadata)
        family_attestation = next(
            item for item in attestation.families if item.family == pack.family
        )
        _validate_candidate_inventory(pack, family_attestation.flow_candidate_inventory)
        packs[pack.family] = pack
    if packs.keys() != flow_metadata.keys():
        raise AuthoringProviderError("private flow packs do not exactly cover public metadata")
    for document in exported.derived_tasks:
        reference = document.instance_reference
        if (
            reference.capability is not PrivateAuthoringCapability.EDA_FLOW_CATALOG
            or reference.family not in packs
        ):
            raise AuthoringProviderError("flow catalog contains an unrelated derived task")
        identity = (reference.family, reference.instance_name)
        if identity in canonical_tasks:
            raise AuthoringProviderError("flow catalog contains a duplicate derived task")
        canonical = CanonicalFlowTask(
            task=document.task,
            instance=document.instance,
            instance_reference=reference,
        )
        try:
            validate_canonical_flow_task(packs[reference.family], canonical)
        except ValueError as error:
            raise AuthoringProviderError(
                "flow catalog contains an invalid provider-derived task"
            ) from error
        canonical_tasks[identity] = canonical
    required = {(family, "base") for family in flow_metadata}
    if not required.issubset(canonical_tasks):
        raise AuthoringProviderError("flow catalog lacks one qualified base task per family")
    return FlowTaskCatalog(
        public_catalog_digest=public_catalog.digest,
        provider_descriptor_digest=descriptor.digest,
        attestation=attestation,
        _packs=MappingProxyType(packs),
        _canonical=MappingProxyType(canonical_tasks),
    )


def flow_candidate_content_manifest_digest(candidate: CandidateVariant) -> str:
    """Return the environment-independent content identity attested for one candidate."""

    members = tuple(
        sorted(
            (
                asset.path,
                canonical_digest(asset.content, domain="flow-candidate-asset-content-v1"),
            )
            for asset in candidate.assets
        )
    )
    return canonical_digest(members, domain="flow-candidate-content-manifest-v1")


def join_flow_candidate_attestations(
    catalog: FlowTaskCatalog,
    family: str,
    environment: EnvironmentSpec,
    release: ReleaseManifest,
    records: Mapping[str, RunRecord],
    artifact_store: ContentAddressedStore,
) -> tuple[FlowCandidateAttestation, ...]:
    """Join signed candidate identities with CAS-verified live qualification runs."""

    pack = catalog.task_pack(family)
    canonical = catalog.canonical_task(family)
    verified_release = derive_flow_release(
        pack,
        canonical,
        environment,
        records,
        artifact_store,
    )
    if verified_release != release:
        raise AuthoringProviderError("flow release differs from its CAS-verified run records")
    inventory = {
        item.candidate_id: item
        for item in catalog.family_attestation(family).flow_candidate_inventory
    }
    candidates = {item.candidate_id: item for item in pack.candidates}
    if set(inventory) != set(candidates):
        raise AuthoringProviderError("flow candidate inventory does not cover the private pack")
    return tuple(
        FlowCandidateAttestation(
            candidate_id=candidate_id,
            candidate_resource_id=inventory[candidate_id].candidate_resource_id,
            role=inventory[candidate_id].role,
            content_manifest_digest=inventory[candidate_id].content_manifest_digest,
            environment_spec_digest=environment.digest,
            expected_candidate_manifest_digest=flow_candidate_manifest_digest(
                candidates[candidate_id],
                environment,
            ),
            qualification_evidence_digest=records[candidate_id].integrity_digest,
        )
        for candidate_id in sorted(candidates)
    )


def _validate_candidate_inventory(
    pack: FlowTaskPack,
    inventory: tuple[FlowCandidateInventory, ...],
) -> None:
    expected = {
        flow_candidate_resource_id(candidate): (
            flow_candidate_content_manifest_digest(candidate),
            (
                FlowCandidateRole.FEASIBILITY_WITNESS
                if candidate.expectation is CandidateExpectation.ACCEPTED
                else FlowCandidateRole.SEMANTIC_NEGATIVE
            ),
        )
        for candidate in pack.candidates
    }
    actual = {
        item.candidate_resource_id: (item.content_manifest_digest, item.role)
        for item in inventory
    }
    if actual != expected:
        raise AuthoringProviderError("flow candidate inventory does not bind exact pack content")


def _validate_flow_task_pack(
    pack: FlowTaskPack,
    metadata: TaskFamilyDefinition,
) -> None:
    if pack.semantic_definition_digest != metadata.digest:
        raise AuthoringProviderError("flow pack does not bind its public family metadata")
    semantic_capabilities = set(metadata.required_capabilities)
    stage_capabilities = {stage.capability for stage in pack.stages}
    if not semantic_capabilities.issubset(stage_capabilities):
        raise AuthoringProviderError("flow pack does not implement its public capability")
    for stage in pack.stages:
        commands = [command for command in stage.commands if isinstance(command, ToolCommand)]
        if not commands or not any(command.capability is stage.capability for command in commands):
            raise AuthoringProviderError("flow stage lacks its declared tool capability")
        for command in commands:
            if command.capability not in backend_by_id(command.tool_id).capabilities:
                raise AuthoringProviderError("flow command capability is not owned by its backend")
    if not any(item.expectation is CandidateExpectation.REJECTED for item in pack.candidates):
        raise AuthoringProviderError("flow pack lacks executable negative evidence")


def _load_canonical_pack(content: bytes) -> FlowTaskPack:
    try:
        document = json.loads(content, object_pairs_hook=_unique_object)
        pack = FlowTaskPack.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AuthoringProviderError("flow task pack is not valid canonical data") from error
    if content != canonical_bytes(pack):
        raise AuthoringProviderError("flow task pack is not canonically encoded")
    return pack


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("flow task pack contains duplicate keys")
        result[key] = value
    return result


__all__ = [
    "FlowTaskCatalog",
    "flow_candidate_content_manifest_digest",
    "flow_catalog_from_export",
    "join_flow_candidate_attestations",
    "load_private_flow_catalog",
]
