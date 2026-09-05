"""Security evidence for the external private-authoring boundary."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from edagym.authoring.content import content_digest
from edagym.authoring.contracts import (
    AuthoringContractReceipt,
    parse_authoring_contract_output,
)
from edagym.authoring.materialization import (
    materialize_private_catalog,
    verify_materialized_catalog,
)
from edagym.authoring.provider import (
    AuthoringProviderError,
    AuthoringProviderOperation,
    AuthoringProviderRequest,
    CandidateMember,
    CandidateSubmission,
    CleanRoomCatalogAttestation,
    CleanRoomFamilyProjection,
    DifficultyBinding,
    ExportCatalogResponse,
    ExportedMember,
    ExportMemberRole,
    ExternalAuthoringProvider,
    OpaqueCatalogReference,
    OpaqueTaskInstanceReference,
    PrivateAuthoringCapability,
    PrivateAuthoringProviderDescriptor,
    PrivateDerivationScope,
    PrivateEvaluatorIsolation,
    PrivateProviderSecurityQualification,
    SealedCatalogAttestation,
    SealedFamilyAttestation,
    SealedInstanceQualification,
    exported_member_manifest_digest,
    exported_role_manifest_digest,
)
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.task_families.catalog import (
    PUBLIC_TASK_CATALOG,
    SAIL_RTL_FAMILIES,
)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _descriptor() -> PrivateAuthoringProviderDescriptor:
    implementation_digest = _digest("implementation-closure")
    security_qualification = PrivateProviderSecurityQualification(
        provider_implementation_digest=implementation_digest,
        evaluator_isolation=PrivateEvaluatorIsolation.ROOTLESS_CONTAINER,
        candidate_escape_evidence_digest=_digest("candidate-escape"),
        lease_replay_rejection_evidence_digest=_digest("lease-replay"),
        network_confinement_evidence_digest=_digest("network-confinement"),
        verifier_confidentiality_evidence_digest=_digest("verifier-confidentiality"),
    )
    return PrivateAuthoringProviderDescriptor(
        provider_id="restricted_authoring_test",
        implementation_digest=implementation_digest,
        security_qualification=security_qualification,
        evaluator_isolation=PrivateEvaluatorIsolation.ROOTLESS_CONTAINER,
        public_catalog_digest=PUBLIC_TASK_CATALOG.digest,
        capabilities=(PrivateAuthoringCapability.SAIL_RTL_CATALOG,),
        clean_room_auditor_descriptor_digest=_digest("clean-room-auditor-descriptor"),
        clean_room_auditor_implementation_digest=_digest(
            "clean-room-auditor-implementation"
        ),
    )


def _write_describe_provider(
    root: Path,
    descriptor: PrivateAuthoringProviderDescriptor,
) -> tuple[Path, str]:
    descriptor_json = json.dumps(
        descriptor.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    source = f'''#!/usr/bin/python3
import hashlib
import json
import os
import sys

if "EDAGYM_AMBIENT_SECRET" in os.environ:
    raise SystemExit(10)
if os.environ.get("HOME") != "/nonexistent":
    raise SystemExit(11)
raw = sys.stdin.buffer.read()
if not raw.endswith(b"\\n"):
    raise SystemExit(12)
request = json.loads(raw)
if request.get("operation") != "describe":
    raise SystemExit(13)
request_digest = "sha256:" + hashlib.sha256(
    b"edagym\\x00private-authoring-request-v1\\x00" + raw[:-1]
).hexdigest()
descriptor = json.loads({descriptor_json!r})
response = {{
    "descriptor": descriptor,
    "kind": "describe",
    "request_digest": request_digest,
}}
sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\\n")
'''
    executable = root / "provider"
    executable.write_text(source, encoding="ascii")
    executable.chmod(0o700)
    return executable, content_digest(source.encode("ascii"))


def test_provider_handshake_is_controller_rooted_and_drops_ambient_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = _descriptor()
    executable, executable_digest = _write_describe_provider(tmp_path, descriptor)
    monkeypatch.setenv("EDAGYM_AMBIENT_SECRET", "must-not-cross-boundary")
    provider = ExternalAuthoringProvider(
        executable,
        expected_executable_digest=executable_digest,
        expected_implementation_digest=descriptor.implementation_digest,
        expected_descriptor_digest=descriptor.digest,
        timeout_seconds=10,
    )

    assert provider.describe() == descriptor
    with pytest.raises(AuthoringProviderError):
        ExternalAuthoringProvider(
            executable,
            expected_executable_digest=executable_digest,
            expected_implementation_digest=_digest("unauthorized-implementation"),
            expected_descriptor_digest=descriptor.digest,
            timeout_seconds=10,
        ).describe()


def test_provider_requests_enforce_public_derivation_and_path_antichains() -> None:
    family = SAIL_RTL_FAMILIES[0]
    base = PrivateDerivationScope(
        family=family.family,
        instance_name="base",
        difficulty=tuple(
            DifficultyBinding(parameter_id=axis.axis_id, value=axis.base_value)
            for axis in family.difficulty_axes
        ),
        seed_handle="opaque_seed_handle",
    )
    descriptor = _descriptor()
    request = AuthoringProviderRequest(
        operation=AuthoringProviderOperation.DERIVE,
        capability=PrivateAuthoringCapability.SAIL_RTL_CATALOG,
        expected_provider_digest=descriptor.digest,
        derivation=base,
    )
    assert request.derivation is not None
    assert request.derivation.public_digest == base.public_digest

    invalid = base.model_copy(
        update={
            "difficulty": (
                DifficultyBinding(
                    parameter_id=family.difficulty_axes[0].axis_id,
                    value=family.difficulty_axes[0].advanced_value,
                ),
            )
        }
    )
    with pytest.raises(ValidationError):
        AuthoringProviderRequest(
            operation=AuthoringProviderOperation.DERIVE,
            capability=PrivateAuthoringCapability.SAIL_RTL_CATALOG,
            expected_provider_digest=descriptor.digest,
            derivation=invalid,
        )

    def member(path: str) -> CandidateMember:
        content = b"module candidate; endmodule\n"
        return CandidateMember(
            relative_path=path,
            media_type="text/x-systemverilog",
            content_digest=content_digest(content),
            size_bytes=len(content),
            content_base64=base64.b64encode(content).decode("ascii"),
        )

    with pytest.raises(ValidationError):
        CandidateSubmission(members=(member("rtl"), member("rtl/candidate.sv")))


def test_public_catalog_and_contract_receipt_contain_no_private_qualification_recipe() -> None:
    document = PUBLIC_TASK_CATALOG.model_dump(mode="json")
    encoded = json.dumps(document, sort_keys=True)
    for private_field in ("mutant_classes", "oracle_kind", "known_answer_kind"):
        assert private_field not in encoded
    assert len(PUBLIC_TASK_CATALOG.families) == 32

    receipt = AuthoringContractReceipt()
    parsed = parse_authoring_contract_output(canonical_bytes(receipt) + b"\n")
    assert parsed == receipt
    assert parsed.public_catalog_digest == PUBLIC_TASK_CATALOG.digest


class _CatalogLease:
    def __init__(self, exported: ExportCatalogResponse) -> None:
        self._exported = exported

    def consume(self) -> ExportCatalogResponse:
        return self._exported


class _CatalogProvider:
    def __init__(self, exported: ExportCatalogResponse) -> None:
        self._exported = exported

    def open_catalog(self, _capability: PrivateAuthoringCapability) -> _CatalogLease:
        return _CatalogLease(self._exported)


def _member(
    path: str,
    role: ExportMemberRole,
    family: str,
    reference_id: str,
) -> ExportedMember:
    content = f"{role.value}:{family}:{reference_id}\n".encode()
    return ExportedMember(
        relative_path=path,
        role=role,
        family=family,
        instance_reference_id=reference_id,
        media_type="text/plain",
        content_digest=content_digest(content),
        size_bytes=len(content),
        content_base64=base64.b64encode(content).decode("ascii"),
    )


def _sail_export() -> ExportCatalogResponse:
    descriptor = _descriptor()
    members: list[ExportedMember] = []
    family_attestations: list[SealedFamilyAttestation] = []
    for family in SAIL_RTL_FAMILIES:
        instance_qualifications: list[SealedInstanceQualification] = []
        task_spec_digest = _digest(f"{family.family}:task")
        for instance_name in family.instance_names:
            difficulty = tuple(
                DifficultyBinding(
                    parameter_id=axis.axis_id,
                    value=(
                        axis.base_value
                        if instance_name == "base"
                        else axis.advanced_value
                    ),
                )
                for axis in family.difficulty_axes
            )
            public_scope_digest = canonical_digest(
                {
                    "difficulty": difficulty,
                    "family": family.family,
                    "instance_name": instance_name,
                },
                domain="private-derivation-public-scope-v1",
            )
            reference_id = _digest(f"{family.family}:{instance_name}:reference")
            scoped_members = (
                _member(
                    f"{family.family}/{instance_name}/behavior.txt",
                    ExportMemberRole.PUBLIC_FILE,
                    family.family,
                    reference_id,
                ),
                _member(
                    f"{family.family}/{instance_name}/starter.sv",
                    ExportMemberRole.PARTICIPANT_FILE,
                    family.family,
                    reference_id,
                ),
                _member(
                    f"{family.family}/{instance_name}/verifier.bin",
                    ExportMemberRole.VERIFIER_FILE,
                    family.family,
                    reference_id,
                ),
            )
            members.extend(scoped_members)
            participant_digest = exported_role_manifest_digest(
                scoped_members,
                frozenset(
                    {
                        ExportMemberRole.PUBLIC_FILE,
                        ExportMemberRole.PARTICIPANT_FILE,
                    }
                ),
            )
            verifier_digest = exported_role_manifest_digest(
                scoped_members,
                frozenset({ExportMemberRole.VERIFIER_FILE}),
            )
            reference = OpaqueTaskInstanceReference(
                provider_id=descriptor.provider_id,
                capability=PrivateAuthoringCapability.SAIL_RTL_CATALOG,
                family=family.family,
                instance_name=instance_name,
                public_metadata_digest=family.digest,
                public_derivation_scope_digest=public_scope_digest,
                task_spec_digest=task_spec_digest,
                task_instance_digest=_digest(f"{family.family}:{instance_name}:instance"),
                participant_bundle_digest=participant_digest,
                verifier_bundle_digest=verifier_digest,
                reference_id=reference_id,
            )
            instance_qualifications.append(
                SealedInstanceQualification(
                    instance_reference_digest=reference.digest,
                    instance_reference_id=reference_id,
                    family=family.family,
                    instance_name=instance_name,
                    public_derivation_scope_digest=public_scope_digest,
                    difficulty=difficulty,
                    task_spec_digest=task_spec_digest,
                    task_instance_digest=reference.task_instance_digest,
                    release_digest=_digest(f"{family.family}:{instance_name}:release"),
                    participant_bundle_digest=participant_digest,
                    verifier_bundle_digest=verifier_digest,
                    release_qualification_digest=_digest(
                        f"{family.family}:{instance_name}:qualification"
                    ),
                    reference_evidence_digests=(
                        _digest(f"{family.family}:{instance_name}:reference-evidence"),
                    ),
                    known_answer_evidence_digests=(
                        _digest(f"{family.family}:{instance_name}:known-answer"),
                    ),
                    negative_evidence_digests=tuple(
                        _digest(f"{family.family}:{instance_name}:negative:{index}")
                        for index in range(3)
                    ),
                    tool_evidence_digests=(
                        _digest(f"{family.family}:{instance_name}:tool"),
                    ),
                )
            )
        ordered = tuple(
            sorted(
                instance_qualifications,
                key=lambda item: item.instance_reference_digest,
            )
        )
        family_attestations.append(
            SealedFamilyAttestation(
                family=family.family,
                public_metadata_digest=family.digest,
                task_spec_digest=task_spec_digest,
                qualification_digest=canonical_digest(
                    tuple(item.digest for item in ordered),
                    domain="sealed-family-qualification-aggregate-v1",
                ),
                instances=ordered,
            )
        )
    ordered_members = tuple(sorted(members, key=lambda item: item.relative_path))
    member_manifest_digest = exported_member_manifest_digest(ordered_members)
    catalog_reference = OpaqueCatalogReference(
        provider_id=descriptor.provider_id,
        capability=PrivateAuthoringCapability.SAIL_RTL_CATALOG,
        catalog_id="sealed_sail_test",
        revision=1,
        member_manifest_digest=member_manifest_digest,
    )
    clean_room_families = tuple(
        CleanRoomFamilyProjection(
            family=family.family,
            public_metadata_digest=family.digest,
            public_member_inventory_digest=_digest(
                f"{family.family}:public-member-inventory"
            ),
            public_member_count=4,
            reference_family_snapshot_digest=_digest(
                f"{family.family}:reference-family-snapshot"
            ),
            reference_member_inventory_digest=_digest(
                f"{family.family}:reference-member-inventory"
            ),
            reference_member_count=7,
            normalized_public_abi_graph_digest=_digest(
                f"{family.family}:public-abi-graph"
            ),
            normalized_reference_abi_graph_digest=_digest(
                f"{family.family}:reference-abi-graph"
            ),
            abi_mapping_evidence_digest=_digest(f"{family.family}:abi-mapping"),
            content_overlap_evidence_digest=_digest(
                f"{family.family}:content-overlap"
            ),
            human_semantic_review_receipt_digest=_digest(
                f"{family.family}:human-semantic-review"
            ),
        )
        for family in SAIL_RTL_FAMILIES
    )
    assert descriptor.clean_room_auditor_descriptor_digest is not None
    assert descriptor.clean_room_auditor_implementation_digest is not None
    clean_room = CleanRoomCatalogAttestation(
        auditor_descriptor_digest=descriptor.clean_room_auditor_descriptor_digest,
        auditor_implementation_digest=descriptor.clean_room_auditor_implementation_digest,
        reference_tree_snapshot_digest=_digest("reference-tree-snapshot"),
        reference_inventory_digest=(
            CleanRoomCatalogAttestation.derive_reference_inventory_digest(
                clean_room_families
            )
        ),
        human_review_aggregate_digest=(
            CleanRoomCatalogAttestation.derive_human_review_aggregate_digest(
                clean_room_families
            )
        ),
        families=clean_room_families,
    )
    attestation = SealedCatalogAttestation(
        provider_descriptor_digest=descriptor.digest,
        provider_implementation_digest=descriptor.implementation_digest,
        provider_security_qualification_digest=descriptor.security_qualification_digest,
        capability=PrivateAuthoringCapability.SAIL_RTL_CATALOG,
        public_catalog_digest=PUBLIC_TASK_CATALOG.digest,
        catalog_reference=catalog_reference,
        member_manifest_digest=member_manifest_digest,
        families=tuple(family_attestations),
        clean_room_attestation=clean_room,
    )
    return ExportCatalogResponse(
        request_digest=_digest("export-request"),
        descriptor=descriptor,
        attestation=attestation,
        members=ordered_members,
    )


def test_materialized_catalog_is_owner_only_exact_and_role_separated() -> None:
    exported = _sail_export()
    by_family = {item.family: item for item in exported.attestation.families}
    for metadata in SAIL_RTL_FAMILIES:
        qualifications = by_family[metadata.family].instances
        assert {item.instance_name for item in qualifications} == set(
            metadata.instance_names
        )
        for qualification in qualifications:
            expected = {
                axis.axis_id: (
                    axis.base_value
                    if qualification.instance_name == "base"
                    else axis.advanced_value
                )
                for axis in metadata.difficulty_axes
            }
            assert {
                item.parameter_id: item.value for item in qualification.difficulty
            } == expected
    with tempfile.TemporaryDirectory(
        prefix=".edagym-private-catalog-test-",
        dir=Path.cwd().parent,
    ) as external_directory:
        external_root = Path(external_directory)
        external_root.chmod(0o700)
        root = external_root / "catalog"
        receipt = materialize_private_catalog(
            _CatalogProvider(exported),
            PrivateAuthoringCapability.SAIL_RTL_CATALOG,
            PUBLIC_TASK_CATALOG,
            root,
        )
        assert verify_materialized_catalog(root, PUBLIC_TASK_CATALOG) == receipt
        assert (root / "participant").is_dir()
        assert (root / "verifier").is_dir()
        assert not (root / "participant" / "verifier").exists()

        unexpected = root / "unexpected"
        unexpected.mkdir(mode=0o700)
        with pytest.raises(AuthoringProviderError):
            verify_materialized_catalog(root, PUBLIC_TASK_CATALOG)
        unexpected.rmdir()

        public_member = (
            root / "public" / SAIL_RTL_FAMILIES[0].family / "base" / "behavior.txt"
        )
        public_member.chmod(0o640)
        with pytest.raises(AuthoringProviderError):
            verify_materialized_catalog(root, PUBLIC_TASK_CATALOG)


def test_private_catalog_materialization_rejects_git_worktrees(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "edagym.authoring.materialization.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args,
            returncode=128,
            stdout=b"",
            stderr=b"fatal: simulated Git audit failure\n",
        ),
    )
    with pytest.raises(AuthoringProviderError):
        materialize_private_catalog(
            _CatalogProvider(_sail_export()),
            PrivateAuthoringCapability.SAIL_RTL_CATALOG,
            PUBLIC_TASK_CATALOG,
            Path.cwd() / "temp" / "must-not-materialize-in-worktree",
        )
