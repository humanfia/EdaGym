"""Capability qualification with content-bound, secret-safe evidence."""

from __future__ import annotations

import hashlib
import os
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.drivers.closure import ROOTLESS_IMAGE_FILE_SIZE_LIMIT_BYTES
from edagym.drivers.deployment import (
    BackendDeploymentConfiguration,
    SiteContainerConfiguration,
)
from edagym.drivers.fixtures import QUALIFICATION_FIXTURES, QualificationFixture, fixture_for
from edagym.drivers.fixtures.model import (
    FixtureObservation,
    FixtureRole,
    MarkerLogProjection,
    ObservedFile,
    QualificationFixtureSnapshot,
    SemanticRejectionReason,
    ToolInvocation,
    WorkspaceInvocation,
    qualification_artifact_id,
    qualification_case_id,
)
from edagym.drivers.licensing import (
    CommercialQualificationAuthorization,
    CommercialQualificationAuthorizationError,
    CommercialQualificationReceipt,
)
from edagym.drivers.model import (
    BackendDefinition,
    BackendProbe,
    ExecutableInvocationMode,
    QualificationState,
    Vendor,
)
from edagym.drivers.probe import (
    AuthorizedBackendResolutionError,
    AuthorizedBackendResolutionReason,
    ResolvedInstallation,
    _trusted_immutable_executable,
    deployment_attestation_digest,
    probe_backend,
    resolve_authorized_commercial_backend,
)
from edagym.drivers.qualification_assets import (
    materialize_qualification_assets,
    revalidate_materialized_qualification_assets,
)
from edagym.drivers.qualification_resources import QualificationResourceGrant
from edagym.drivers.rootless_image import RootlessImageConfiguration
from edagym.drivers.semantic_claims import is_comprehensive_claim
from edagym.drivers.site_container import site_container_license_environment
from edagym.executors.assets import AssetSnapshot
from edagym.run.artifacts import ContentAddressedStore, RetainedArtifact
from edagym.run.model import ArtifactRecord, BlobRef
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
    validate_relative_path,
)
from edagym.specs.environment import PROTECTED_RAW_DISCLOSURE, ArtifactDisclosure

_PARSER_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_QUALIFICATION_FILE_BYTES = ROOTLESS_IMAGE_FILE_SIZE_LIMIT_BYTES
_ROOTLESS_PACKAGE_MANIFEST_ID = "rootless_image_package_manifest"


class QualificationOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class QualificationFailure(StrEnum):
    TOOL_EXITED = "tool_exited"
    TIMED_OUT = "timed_out"
    PROGRAM_UNAVAILABLE = "program_unavailable"
    OUTPUT_MISSING = "output_missing"
    PARSER_REJECTED = "parser_rejected"
    PARSER_CRASHED = "parser_crashed"
    EXECUTION_CLOSURE_CHANGED = "execution_closure_changed"
    RESTRICTED_ASSET_CHANGED = "restricted_asset_changed"


class QualificationGapReason(StrEnum):
    PROBE_NOT_INVOCABLE = "probe_not_invocable"
    LICENSE_AUTHORIZATION_REQUIRED = "license_authorization_required"
    AUTHORIZED_BINDING_MISMATCH = "authorized_binding_mismatch"
    AUTHORIZED_LICENSE_UNAVAILABLE = "authorized_license_unavailable"
    AUTHORIZED_IDENTITY_CHANGED = "authorized_identity_changed"
    AUTHORIZED_EXECUTABLE_UNAVAILABLE = "authorized_executable_unavailable"
    HOST_RUNTIME_DEPENDENCY_UNAVAILABLE = "host_runtime_dependency_unavailable"
    AUTHORIZED_VERSION_PROBE_FAILED = "authorized_version_probe_failed"
    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    EULA_ACCEPTANCE_REQUIRED = "eula_acceptance_required"
    SEMANTIC_COVERAGE_INCOMPLETE = "semantic_coverage_incomplete"


class QualificationDisposition(StrEnum):
    UNAVAILABLE = "unavailable"
    PROBE_ONLY = "probe_only"
    INCOMPLETE = "incomplete"
    NONCONFORMANT = "nonconformant"
    CONFORMANT = "conformant"


class QualificationAssetEvidence(StrictModel):
    logical_id: Identifier
    asset_id: Identifier
    path: str
    restricted_digest: Digest
    media_type: Annotated[str, Field(min_length=3, max_length=127)]

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return validate_relative_path(value)


class QualificationEvidence(StrictModel):
    """Restricted replay evidence; public reports expose only its opaque attestation."""

    schema_version: SchemaVersion = 1
    tool_id: Identifier
    vendor: Vendor
    capability: Capability
    role: FixtureRole
    fixture: QualificationFixtureSnapshot
    fixture_pair_digest: Digest
    driver_digest: Digest
    backend_probe_digest: Digest
    tool_version: Annotated[str, Field(min_length=1, max_length=160)]
    executable_digest: Digest
    execution_closure_digest: Digest
    version_output_digest: Digest
    executable_invocation_mode: ExecutableInvocationMode
    deployment_attestation_digest: Digest
    deployment_record_digest: Digest | None = None
    package_manifest_digest: Digest | None = None
    modulefile_digest: Digest | None = None
    license_authorization: CommercialQualificationReceipt | None = None
    artifact_policy_digest: Digest
    resource_grant: QualificationResourceGrant
    input_artifacts: tuple[ArtifactRecord, ...]
    deployment_artifacts: tuple[ArtifactRecord, ...] = Field(
        default=(),
        exclude_if=lambda value: not value,
    )
    restricted_assets: tuple[QualificationAssetEvidence, ...] = Field(
        default=(),
        exclude_if=lambda value: not value,
    )
    output_artifacts: tuple[ArtifactRecord, ...]
    diagnostic_artifacts: tuple[ArtifactRecord, ...] = Field(
        default=(),
        exclude_if=lambda value: not value,
    )
    exit_codes: tuple[int, ...]
    outcome: QualificationOutcome
    failure: QualificationFailure | None = None
    semantic_rejection_reason: SemanticRejectionReason | None = None
    recorded_at: datetime

    @field_validator(
        "input_artifacts",
        "deployment_artifacts",
        "output_artifacts",
        "diagnostic_artifacts",
    )
    @classmethod
    def normalize_artifacts(cls, value: tuple[ArtifactRecord, ...]) -> tuple[ArtifactRecord, ...]:
        identities = [item.logical_id for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("qualification artifact identities must be unique")
        return tuple(sorted(value, key=lambda item: item.logical_id))

    @field_validator("restricted_assets")
    @classmethod
    def normalize_restricted_assets(
        cls,
        value: tuple[QualificationAssetEvidence, ...],
    ) -> tuple[QualificationAssetEvidence, ...]:
        identities = [(item.logical_id, item.asset_id, item.path) for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("qualification restricted assets must be unique")
        return tuple(sorted(value, key=lambda item: item.logical_id))

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if not self.input_artifacts or not self.output_artifacts:
            raise ValueError("qualification evidence requires input and output artifacts")
        all_identities = [
            item.logical_id
            for item in (
                *self.input_artifacts,
                *self.deployment_artifacts,
                *self.output_artifacts,
                *self.diagnostic_artifacts,
            )
        ] + [item.logical_id for item in self.restricted_assets]
        if len(all_identities) != len(set(all_identities)):
            raise ValueError("qualification input and output identities cannot overlap")
        if (
            self.fixture.tool_id != self.tool_id
            or self.fixture.capability is not self.capability
            or self.fixture.role is not self.role
            or self.fixture.fixture_id
            != qualification_case_id(self.tool_id, self.capability, self.role)
        ):
            raise ValueError("qualification fixture snapshot does not bind its backend capability")
        if any(
            record.artifact_class is not ArtifactClass.EVIDENCE
            for record in (
                *self.input_artifacts,
                *self.deployment_artifacts,
                *self.output_artifacts,
            )
        ) or any(
            record.artifact_class is not ArtifactClass.DIAGNOSTIC
            for record in self.diagnostic_artifacts
        ):
            raise ValueError(
                "qualification outputs must be evidence and raw logs must be diagnostics"
            )
        has_commercial_authorization = self.license_authorization is not None
        if has_commercial_authorization != (self.vendor is not Vendor.OPEN_SOURCE):
            raise ValueError(
                "commercial evidence requires exactly one explicit authorization identity"
            )
        if self.deployment_attestation_digest != deployment_attestation_digest(
            tool_id=self.tool_id,
            driver_digest=self.driver_digest,
            deployment_record_digest=self.deployment_record_digest,
            tool_version=self.tool_version,
            executable_digest=self.executable_digest,
            execution_closure_digest_value=self.execution_closure_digest,
            version_output_digest=self.version_output_digest,
            modulefile_digest=self.modulefile_digest,
            invocation_mode=self.executable_invocation_mode,
            package_manifest_digest=self.package_manifest_digest,
        ):
            raise ValueError("qualification evidence has a noncanonical deployment attestation")
        if self.package_manifest_digest is None:
            if self.deployment_artifacts:
                raise ValueError("deployment artifacts require a package manifest identity")
        elif (
            len(self.deployment_artifacts) != 1
            or self.deployment_artifacts[0].logical_id != _ROOTLESS_PACKAGE_MANIFEST_ID
            or self.deployment_artifacts[0].blob.digest != self.package_manifest_digest
            or self.deployment_artifacts[0].media_type != "text/tab-separated-values"
        ):
            raise ValueError("rootless image evidence requires its exact package manifest")
        if self.vendor is not Vendor.OPEN_SOURCE and any(
            (
                record.sensitivity,
                record.visibility,
                record.redistribution,
            )
            != (
                PROTECTED_RAW_DISCLOSURE.sensitivity,
                PROTECTED_RAW_DISCLOSURE.visibility,
                PROTECTED_RAW_DISCLOSURE.redistribution,
            )
            for record in (
                *self.input_artifacts,
                *self.deployment_artifacts,
                *self.output_artifacts,
                *self.diagnostic_artifacts,
            )
        ):
            raise ValueError("commercial qualification artifacts require protected disclosure")
        if self.license_authorization is not None and (
            self.license_authorization.tool_id != self.tool_id
            or self.license_authorization.vendor is not self.vendor
            or self.license_authorization.capability is not self.capability
            or self.license_authorization.driver_digest != self.driver_digest
            or self.license_authorization.fixture_digest != self.fixture_pair_digest
        ):
            raise ValueError("commercial evidence does not bind its authorization receipt")
        expected_inputs = {
            (item.logical_id, item.digest, item.size_bytes, item.media_type)
            for item in self.fixture.inputs
        }
        observed_inputs = {
            (
                item.logical_id,
                item.blob.digest,
                item.blob.size_bytes,
                item.media_type,
            )
            for item in self.input_artifacts
        }
        if observed_inputs != expected_inputs:
            raise ValueError("qualification evidence must contain every canonical fixture input")
        expected_assets = {
            (item.logical_id, item.asset_id, item.path, item.media_type)
            for item in self.fixture.restricted_assets
        }
        observed_assets = {
            (item.logical_id, item.asset_id, item.path, item.media_type)
            for item in self.restricted_assets
        }
        if observed_assets != expected_assets:
            raise ValueError("qualification evidence must bind every restricted fixture asset")
        if len(self.exit_codes) > len(self.fixture.invocations):
            raise ValueError("qualification evidence has excess invocation results")
        expected_exit_codes = self.fixture.expected_exit_codes
        output_ids = {item.logical_id for item in self.output_artifacts}
        log_ids = {
            qualification_artifact_id(
                self.fixture.fixture_id,
                f"command_{index}_{stream}",
            )
            for index in range(len(self.fixture.invocations))
            for stream in ("stdout", "stderr")
        }
        raw_log_ids = {f"{logical_id}_raw" for logical_id in log_ids}
        observed_log_ids = output_ids & log_ids
        expected_raw_log_ids = {f"{logical_id}_raw" for logical_id in observed_log_ids}
        diagnostic_ids = {item.logical_id for item in self.diagnostic_artifacts}
        raw_diagnostics_required = (
            self.fixture.log_retention == "marker_projection"
            and self.outcome is QualificationOutcome.FAILED
        )
        if raw_diagnostics_required and diagnostic_ids != expected_raw_log_ids:
            raise ValueError("failed marker-projected logs require exact raw diagnostics")
        if not raw_diagnostics_required and diagnostic_ids:
            raise ValueError("raw diagnostics are retained only for projected failures")
        if not diagnostic_ids.issubset(raw_log_ids) or any(
            item.media_type != "text/plain"
            or (
                item.sensitivity,
                item.visibility,
                item.redistribution,
            )
            != (
                PROTECTED_RAW_DISCLOSURE.sensitivity,
                PROTECTED_RAW_DISCLOSURE.visibility,
                PROTECTED_RAW_DISCLOSURE.redistribution,
            )
            for item in self.diagnostic_artifacts
        ):
            raise ValueError("qualification diagnostics must be protected raw command logs")
        required_ids = {item.logical_id for item in self.fixture.outputs if item.required}
        optional_ids = {item.logical_id for item in self.fixture.outputs if not item.required}
        if not output_ids.issubset(log_ids | required_ids | optional_ids):
            raise ValueError("qualification evidence contains an undeclared output")
        declared_media = {item.logical_id: item.media_type for item in self.fixture.outputs}
        if any(
            record.media_type
            != ("text/plain" if record.logical_id in log_ids else declared_media[record.logical_id])
            for record in self.output_artifacts
        ):
            raise ValueError("qualification output media type differs from its fixture contract")
        if self.outcome is QualificationOutcome.PASSED:
            if (
                self.failure is not None
                or len(self.exit_codes) != len(self.fixture.invocations)
                or self.exit_codes != expected_exit_codes
                or not (log_ids | required_ids).issubset(output_ids)
            ):
                raise ValueError("passing evidence requires successful tool invocations")
            if self.role is FixtureRole.ACCEPTANCE:
                if self.semantic_rejection_reason is not None:
                    raise ValueError("acceptance evidence cannot carry a semantic rejection")
            elif self.semantic_rejection_reason is not self.fixture.rejection_reason:
                raise ValueError("rejection evidence must carry its exact expected semantic reason")
        else:
            if self.failure is None:
                raise ValueError("failed evidence requires a typed failure")
            if self.semantic_rejection_reason is not None:
                raise ValueError("failed evidence cannot claim a semantic rejection")
            complete_expected_invocations = self.exit_codes == expected_exit_codes
            completed_expected_prefix = (
                self.exit_codes == expected_exit_codes[: len(self.exit_codes)]
            )
            completed_log_ids = {
                qualification_artifact_id(
                    self.fixture.fixture_id,
                    f"command_{index}_{stream}",
                )
                for index in range(len(self.exit_codes))
                for stream in ("stdout", "stderr")
            }
            has_completed_logs = completed_log_ids.issubset(output_ids)
            missing_required = not required_ids.issubset(output_ids)
            if self.failure is QualificationFailure.TOOL_EXITED and (
                not self.exit_codes or completed_expected_prefix or not has_completed_logs
            ):
                raise ValueError("tool-exited evidence requires an unexpected exit status")
            if self.failure is QualificationFailure.TIMED_OUT and (
                not self.exit_codes or completed_expected_prefix or not has_completed_logs
            ):
                raise ValueError("timeout evidence requires a terminated invocation")
            if self.failure is QualificationFailure.PROGRAM_UNAVAILABLE and len(
                self.exit_codes
            ) >= len(self.fixture.invocations):
                raise ValueError("program-unavailable evidence requires an incomplete invocation")
            if self.failure is QualificationFailure.OUTPUT_MISSING and not (
                complete_expected_invocations and log_ids.issubset(output_ids) and missing_required
            ):
                raise ValueError("output-missing evidence requires successful tools and a gap")
            if self.failure is QualificationFailure.PARSER_REJECTED and not (
                complete_expected_invocations
                and log_ids.issubset(output_ids)
                and not missing_required
            ):
                raise ValueError("parser-rejected evidence requires complete workload outputs")
            if self.failure is QualificationFailure.PARSER_CRASHED and not (
                complete_expected_invocations
                and log_ids.issubset(output_ids)
                and not missing_required
            ):
                raise ValueError("parser-crashed evidence requires complete workload outputs")
            if self.failure is QualificationFailure.EXECUTION_CLOSURE_CHANGED and not (
                completed_expected_prefix and has_completed_logs
            ):
                raise ValueError(
                    "closure-changed evidence requires an exact completed invocation prefix"
                )
            if self.failure is QualificationFailure.RESTRICTED_ASSET_CHANGED and not (
                completed_expected_prefix and has_completed_logs and bool(self.restricted_assets)
            ):
                raise ValueError(
                    "asset-changed evidence requires a bound restricted asset and exact prefix"
                )
        return self

    @field_validator("recorded_at")
    @classmethod
    def normalize_recorded_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("qualification evidence time must be timezone-aware")
        return value.astimezone(UTC)

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="backend-qualification-evidence-v1")


class CapabilityGap(StrictModel):
    capability: Capability
    reason: QualificationGapReason


class BackendQualification(StrictModel):
    schema_version: SchemaVersion = 1
    probe: BackendProbe
    requested_capabilities: tuple[Capability, ...]
    evidence: tuple[QualificationEvidence, ...] = ()
    gaps: tuple[CapabilityGap, ...] = ()
    disposition: QualificationDisposition

    @field_validator("requested_capabilities")
    @classmethod
    def normalize_capabilities(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("qualification capabilities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.value))

    @field_validator("evidence")
    @classmethod
    def normalize_evidence(
        cls, value: tuple[QualificationEvidence, ...]
    ) -> tuple[QualificationEvidence, ...]:
        identities = [(item.capability, item.role) for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("qualification evidence roles must be unique per capability")
        return tuple(sorted(value, key=lambda item: (item.capability.value, item.role.value)))

    @field_validator("gaps")
    @classmethod
    def normalize_gaps(cls, value: tuple[CapabilityGap, ...]) -> tuple[CapabilityGap, ...]:
        capabilities = [item.capability for item in value]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("a qualification result may contain one gap per capability")
        return tuple(sorted(value, key=lambda item: item.capability.value))

    @model_validator(mode="after")
    def validate_partition_and_disposition(self) -> Self:
        requested = set(self.requested_capabilities)
        if not requested.issubset(self.probe.capabilities):
            raise ValueError("qualification requests a capability absent from its probe")
        if any(item.capability not in requested for item in self.evidence):
            raise ValueError("qualification evidence contains an unrequested capability")
        evidence_roles = {
            capability: {item.role for item in self.evidence if item.capability is capability}
            for capability in requested
        }
        covered = {
            capability for capability, roles in evidence_roles.items() if roles == set(FixtureRole)
        }
        partial = {
            capability
            for capability, roles in evidence_roles.items()
            if roles and roles != set(FixtureRole)
        }
        if partial:
            raise ValueError("qualification evidence requires both roles per capability")
        missing = {item.capability for item in self.gaps}
        if covered & missing or covered | missing != requested:
            raise ValueError(
                "qualification evidence and gaps must partition requested capabilities"
            )
        if any(
            item.tool_id != self.probe.tool_id
            or item.vendor is not self.probe.vendor
            or item.driver_digest != self.probe.driver_digest
            or item.backend_probe_digest != canonical_digest(self.probe, domain="backend-probe-v1")
            or item.tool_version != self.probe.tool_version
            or item.deployment_attestation_digest
            != self.probe.deployment_attestation_digest
            for item in self.evidence
        ):
            raise ValueError("qualification evidence must bind the assessed probe")
        resolution_identities = {
            (
                item.executable_digest,
                item.execution_closure_digest,
                item.version_output_digest,
                item.executable_invocation_mode,
                item.deployment_record_digest,
                item.modulefile_digest,
            )
            for item in self.evidence
        }
        if len(resolution_identities) > 1:
            raise ValueError("one qualification must use one exact resolved installation")
        for item in self.evidence:
            canonical_fixture = fixture_for(item.tool_id, item.capability)
            if (
                canonical_fixture is None
                or item.fixture != canonical_fixture.snapshot_for(item.role)
                or item.fixture_pair_digest != canonical_fixture.digest
                or item.fixture.tool_id != item.tool_id
                or item.fixture.capability is not item.capability
            ):
                raise ValueError("qualification evidence differs from its canonical fixture")
        for capability in covered:
            paired = {item.role: item for item in self.evidence if item.capability is capability}
            acceptance = paired[FixtureRole.ACCEPTANCE]
            rejection = paired[FixtureRole.REJECTION]
            if (
                acceptance.fixture.pair_id != rejection.fixture.pair_id
                or acceptance.fixture.parser_digest != rejection.fixture.parser_digest
                or acceptance.fixture.invocations != rejection.fixture.invocations
                or tuple(
                    (item.path, item.required, item.media_type)
                    for item in acceptance.fixture.outputs
                )
                != tuple(
                    (item.path, item.required, item.media_type)
                    for item in rejection.fixture.outputs
                )
                or tuple((item.path, item.media_type) for item in acceptance.fixture.inputs)
                != tuple((item.path, item.media_type) for item in rejection.fixture.inputs)
                or tuple(
                    (
                        item.asset_id,
                        item.path,
                        item.restricted_digest,
                        item.media_type,
                    )
                    for item in acceptance.restricted_assets
                )
                != tuple(
                    (
                        item.asset_id,
                        item.path,
                        item.restricted_digest,
                        item.media_type,
                    )
                    for item in rejection.restricted_assets
                )
                or acceptance.resource_grant != rejection.resource_grant
            ):
                raise ValueError("qualification evidence roles must share one semantic joint")
            pair_digest = canonical_digest(
                {
                    "acceptance": acceptance.fixture,
                    "rejection": rejection.fixture,
                },
                domain="backend-qualification-pair-v1",
            )
            if (
                acceptance.fixture_pair_digest != pair_digest
                or rejection.fixture_pair_digest != pair_digest
            ):
                raise ValueError("qualification evidence does not bind its immutable pair")
        if len({item.artifact_policy_digest for item in self.evidence}) > 1:
            raise ValueError("one qualification assessment must use one artifact policy")
        expected = _derive_disposition(self.probe, self.evidence, self.gaps)
        if self.disposition is not expected:
            raise ValueError("qualification disposition is inconsistent with its evidence")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="backend-qualification-v1")

    def retained_artifacts(self) -> tuple[RetainedArtifact, ...]:
        """Derive CAS retention roots for every supporting evidence blob."""

        retained = [
            RetainedArtifact(record=record, recorded_at=evidence.recorded_at)
            for evidence in self.evidence
            for record in (
                *evidence.input_artifacts,
                *evidence.deployment_artifacts,
                *evidence.output_artifacts,
                *evidence.diagnostic_artifacts,
            )
        ]
        return tuple(retained)


def aggregate_backend_qualifications(
    definition: BackendDefinition,
    qualifications: tuple[BackendQualification, ...],
) -> BackendQualification:
    """Derive the single release source from disjoint capability assessments."""

    if not qualifications:
        raise ValueError("backend qualification aggregation requires source assessments")
    requested = _requested_capabilities(definition, None)
    expected_probe_digest = canonical_digest(
        qualifications[0].probe,
        domain="backend-probe-v1",
    )
    covered: set[Capability] = set()
    evidence: list[QualificationEvidence] = []
    gaps: list[CapabilityGap] = []
    for qualification in qualifications:
        probe = qualification.probe
        if (
            probe.tool_id != definition.tool_id
            or probe.vendor is not definition.vendor
            or probe.capabilities != definition.capabilities
            or probe.driver_digest != definition.driver_digest
            or canonical_digest(probe, domain="backend-probe-v1") != expected_probe_digest
        ):
            raise ValueError("aggregated qualifications must bind one exact backend probe")
        partition = set(qualification.requested_capabilities)
        if covered & partition:
            raise ValueError("aggregated qualification capability partitions must be disjoint")
        covered.update(partition)
        evidence.extend(qualification.evidence)
        gaps.extend(qualification.gaps)
    if covered != set(requested):
        raise ValueError("aggregated qualifications must cover every backend capability")
    return _assessment(
        qualifications[0].probe,
        requested,
        tuple(evidence),
        tuple(gaps),
    )


def qualify_backend(
    definition: BackendDefinition,
    probe: BackendProbe,
    installation: ResolvedInstallation | None,
    *,
    scratch_root: Path,
    capabilities: tuple[Capability, ...] | None = None,
    artifact_store: ContentAddressedStore | None = None,
    artifact_disclosure: ArtifactDisclosure | None = None,
    restricted_assets: Mapping[str, AssetSnapshot] | None = None,
    deployment_configuration: BackendDeploymentConfiguration | None = None,
    rootless_image_configuration: RootlessImageConfiguration | None = None,
    resource_grant: QualificationResourceGrant | None = None,
) -> BackendQualification:
    """Run canonical trusted-tool fixtures; commercial tools remain probe-only."""

    _validate_probe_binding(definition, probe, installation)
    requested = _requested_capabilities(definition, capabilities)
    if probe.state is not QualificationState.INVOCABLE:
        gap_reason = (
            QualificationGapReason.EULA_ACCEPTANCE_REQUIRED
            if probe.state is QualificationState.DETECTED
            and definition.workload_use_requires_eula_acceptance
            else QualificationGapReason.LICENSE_AUTHORIZATION_REQUIRED
            if probe.state is QualificationState.DETECTED
            and definition.vendor is not Vendor.OPEN_SOURCE
            else QualificationGapReason.PROBE_NOT_INVOCABLE
        )
        unavailable_gaps = tuple(
            CapabilityGap(capability=item, reason=gap_reason) for item in requested
        )
        return _assessment(probe, requested, (), unavailable_gaps)
    if installation is None:
        raise ValueError("invocable probes require a resolved installation")

    authorized = frozenset(requested) if definition.vendor is Vendor.OPEN_SOURCE else frozenset()
    gaps: list[CapabilityGap] = []
    scheduled: list[tuple[Capability, QualificationFixture]] = []
    for capability in requested:
        if capability not in authorized:
            gaps.append(
                CapabilityGap(
                    capability=capability,
                    reason=(
                        QualificationGapReason.EULA_ACCEPTANCE_REQUIRED
                        if definition.workload_use_requires_eula_acceptance
                        else QualificationGapReason.LICENSE_AUTHORIZATION_REQUIRED
                    ),
                )
            )
            continue
        fixture = _fixture_for(QUALIFICATION_FIXTURES, definition.tool_id, capability)
        if fixture is None or not fixture.rejection_inputs:
            gaps.append(
                CapabilityGap(
                    capability=capability,
                    reason=QualificationGapReason.FIXTURE_UNAVAILABLE,
                )
            )
            continue
        scheduled.append((capability, fixture))

    if not scheduled:
        if restricted_assets:
            raise ValueError("qualification assets cannot be supplied without a workload")
        return _assessment(probe, requested, (), tuple(gaps))
    if artifact_store is None or artifact_disclosure is None:
        raise ValueError("qualification workloads require policy-bound artifact persistence")
    if resource_grant is None:
        raise ValueError("qualification workloads require an explicit resource grant")
    refreshed_probe, refreshed_installation = probe_backend(
        definition,
        deployment_configuration=deployment_configuration,
        rootless_image_configuration=rootless_image_configuration,
    )
    if refreshed_installation is None or canonical_digest(
        refreshed_probe, domain="backend-probe-v1"
    ) != canonical_digest(probe, domain="backend-probe-v1"):
        raise ValueError("backend resolution changed before qualification execution")

    evidence: list[QualificationEvidence] = []
    provided_assets = {} if restricted_assets is None else restricted_assets
    required_asset_ids = {
        asset.asset_id for _, fixture in scheduled for asset in fixture.restricted_assets
    }
    if set(provided_assets) != required_asset_ids:
        raise ValueError("qualification asset grant differs from scheduled fixtures")
    for _, fixture in scheduled:
        fixture_assets = {
            asset.asset_id: provided_assets[asset.asset_id]
            for asset in fixture.restricted_assets
        }
        for role in FixtureRole:
            evidence.append(
                _execute_fixture(
                    fixture,
                    role=role,
                    definition=definition,
                    probe=probe,
                    installation=refreshed_installation,
                    scratch_root=scratch_root,
                    artifact_store=artifact_store,
                    artifact_disclosure=artifact_disclosure,
                    resource_grant=resource_grant,
                    license_authorization=None,
                    restricted_assets=fixture_assets,
                    runtime_license_environment={},
                    deployment_configuration=deployment_configuration,
                )
            )
    return _assessment(probe, requested, tuple(evidence), tuple(gaps))


def qualify_commercial_backend(
    definition: BackendDefinition,
    metadata_probe: BackendProbe,
    authorization: CommercialQualificationAuthorization,
    *,
    scratch_root: Path,
    artifact_store: ContentAddressedStore,
    artifact_disclosure: ArtifactDisclosure,
    resource_grant: QualificationResourceGrant,
    deployment_configuration: BackendDeploymentConfiguration,
    restricted_assets: Mapping[str, AssetSnapshot] | None = None,
) -> BackendQualification:
    """Consume one explicit license grant for one canonical commercial fixture."""

    try:
        _validate_probe_binding(definition, metadata_probe, None)
        if definition.vendor is Vendor.OPEN_SOURCE:
            raise ValueError("commercial qualification requires a commercial backend")
        if metadata_probe.state is not QualificationState.DETECTED:
            raise ValueError("commercial qualification requires a metadata-only detected probe")
        receipt = authorization.receipt
        fixture = fixture_for(definition.tool_id, receipt.capability)
        if fixture is None:
            raise CommercialQualificationAuthorizationError(
                "commercial qualification fixture is unavailable"
            )
        if fixture.log_projection is None or not fixture.rejection_inputs:
            raise CommercialQualificationAuthorizationError(
                "commercial fixture does not enforce secret-safe artifact projection"
            )
        if artifact_disclosure != PROTECTED_RAW_DISCLOSURE or not artifact_store.encrypted:
            raise CommercialQualificationAuthorizationError(
                "commercial qualification requires encrypted protected artifact retention"
            )
        provided_assets = {} if restricted_assets is None else restricted_assets
        if set(provided_assets) != {item.asset_id for item in fixture.restricted_assets}:
            raise CommercialQualificationAuthorizationError(
                "commercial qualification asset grant differs from its fixture"
            )
        receipt, lease = authorization._consume(
            definition=definition,
            metadata_probe=metadata_probe,
            fixture=fixture,
            timeout_seconds=resource_grant.command_timeout_seconds,
        )
        requested = (fixture.capability,)
        try:
            probe, installation = resolve_authorized_commercial_backend(
                definition,
                metadata_probe,
                lease,
                deployment_configuration=deployment_configuration,
            )
        except AuthorizedBackendResolutionError as error:
            return _assessment(
                metadata_probe,
                requested,
                (),
                (
                    CapabilityGap(
                        capability=fixture.capability,
                        reason=_authorized_resolution_gap(error.reason),
                    ),
                ),
            )
        evidence = tuple(
            _execute_fixture(
                fixture,
                role=role,
                definition=definition,
                probe=probe,
                installation=installation,
                scratch_root=scratch_root,
                artifact_store=artifact_store,
                artifact_disclosure=artifact_disclosure,
                resource_grant=resource_grant,
                license_authorization=receipt,
                restricted_assets=provided_assets,
                runtime_license_environment=site_container_license_environment(
                    lease._process_environment()
                ),
                deployment_configuration=deployment_configuration,
            )
            for role in FixtureRole
        )
        return _assessment(probe, requested, evidence, ())
    finally:
        authorization.close()


def _authorized_resolution_gap(
    reason: AuthorizedBackendResolutionReason,
) -> QualificationGapReason:
    return {
        AuthorizedBackendResolutionReason.BINDING_MISMATCH: (
            QualificationGapReason.AUTHORIZED_BINDING_MISMATCH
        ),
        AuthorizedBackendResolutionReason.LICENSE_LEASE_UNAVAILABLE: (
            QualificationGapReason.AUTHORIZED_LICENSE_UNAVAILABLE
        ),
        AuthorizedBackendResolutionReason.MODULE_METADATA_UNAVAILABLE: (
            QualificationGapReason.AUTHORIZED_IDENTITY_CHANGED
        ),
        AuthorizedBackendResolutionReason.MODULE_METADATA_CHANGED: (
            QualificationGapReason.AUTHORIZED_IDENTITY_CHANGED
        ),
        AuthorizedBackendResolutionReason.EXECUTABLE_IDENTITY_CHANGED: (
            QualificationGapReason.AUTHORIZED_IDENTITY_CHANGED
        ),
        AuthorizedBackendResolutionReason.EXECUTABLE_UNAVAILABLE: (
            QualificationGapReason.AUTHORIZED_EXECUTABLE_UNAVAILABLE
        ),
        AuthorizedBackendResolutionReason.HOST_RUNTIME_DEPENDENCY_UNAVAILABLE: (
            QualificationGapReason.HOST_RUNTIME_DEPENDENCY_UNAVAILABLE
        ),
        AuthorizedBackendResolutionReason.VERSION_PROBE_FAILED: (
            QualificationGapReason.AUTHORIZED_VERSION_PROBE_FAILED
        ),
        AuthorizedBackendResolutionReason.EULA_ACCEPTANCE_REQUIRED: (
            QualificationGapReason.EULA_ACCEPTANCE_REQUIRED
        ),
    }[reason]


def _requested_capabilities(
    definition: BackendDefinition,
    capabilities: tuple[Capability, ...] | None,
) -> tuple[Capability, ...]:
    selected = definition.capabilities if capabilities is None else capabilities
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("requested capabilities must be unique and non-empty")
    if any(item not in definition.capabilities for item in selected):
        raise ValueError("requested capability is not declared by the backend")
    return tuple(sorted(selected, key=lambda item: item.value))


def _validate_probe_binding(
    definition: BackendDefinition,
    probe: BackendProbe,
    installation: ResolvedInstallation | None,
) -> None:
    if (
        probe.tool_id != definition.tool_id
        or probe.vendor is not definition.vendor
        or probe.capabilities != definition.capabilities
        or probe.host_support_mode is not definition.host_support_mode
        or probe.driver_digest != definition.driver_digest
    ):
        raise ValueError("backend probe does not bind the supplied definition")
    resolved = probe.state is QualificationState.INVOCABLE
    if not resolved:
        if installation is not None:
            raise ValueError("non-invocable probes cannot carry an installation")
        return
    if installation is None:
        raise ValueError("invocable probes require an installation")
    if (
        installation.definition.driver_digest != definition.driver_digest
        or installation.version_label != probe.tool_version
        or installation.deployment_attestation_digest
        != probe.deployment_attestation_digest
    ):
        raise ValueError("resolved installation does not bind the supplied probe")


def _fixture_for(
    fixtures: tuple[QualificationFixture, ...],
    tool_id: str,
    capability: Capability,
) -> QualificationFixture | None:
    matches = [
        item for item in fixtures if item.tool_id == tool_id and item.capability is capability
    ]
    if len(matches) > 1:
        raise ValueError("qualification fixtures contain duplicate backend capability ownership")
    return matches[0] if matches else None


def _execute_fixture(
    fixture: QualificationFixture,
    *,
    role: FixtureRole,
    definition: BackendDefinition,
    probe: BackendProbe,
    installation: ResolvedInstallation,
    scratch_root: Path,
    artifact_store: ContentAddressedStore,
    artifact_disclosure: ArtifactDisclosure,
    resource_grant: QualificationResourceGrant,
    license_authorization: CommercialQualificationReceipt | None,
    restricted_assets: Mapping[str, AssetSnapshot],
    runtime_license_environment: Mapping[str, str],
    deployment_configuration: BackendDeploymentConfiguration | None,
) -> QualificationEvidence:
    root = _validated_scratch_root(scratch_root)
    if (
        resource_grant.command_timeout_seconds * len(fixture.invocations)
        > resource_grant.limits.wall_seconds
    ):
        raise ValueError("fixture execution exceeds the granted wall-time budget")
    if fixture.log_projection is not None and (
        not artifact_store.encrypted
        or artifact_store.policy.persistent_disclosure(ArtifactClass.DIAGNOSTIC)
        != PROTECTED_RAW_DISCLOSURE
    ):
        raise ValueError(
            "marker-projected qualification requires protected encrypted diagnostics"
        )
    workspace = Path(tempfile.mkdtemp(prefix="edagym-qualification-", dir=root))
    workspace_descriptor = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    try:
        materialized_assets = materialize_qualification_assets(
            workspace,
            fixture.restricted_assets,
            restricted_assets,
        )
        fixture_snapshot = fixture.snapshot_for(role)
        asset_evidence = tuple(
            QualificationAssetEvidence(
                logical_id=item.logical_id,
                asset_id=item.asset_id,
                path=item.path,
                restricted_digest=restricted_assets[item.asset_id].restricted_digest,
                media_type=item.media_type,
            )
            for item in fixture_snapshot.restricted_assets
        )
        input_artifacts = _materialize_inputs(
            workspace,
            workspace_descriptor,
            fixture,
            role,
            artifact_store,
            artifact_disclosure,
        )
        environment = _fixture_environment(installation.environment, workspace)
        site_runtime = installation.execution_closure.site_container_runtime
        rootless_runtime = installation.execution_closure.rootless_image_runtime
        deployment_artifacts = _persist_rootless_package_manifest(
            rootless_runtime.package_manifest if rootless_runtime is not None else None,
            artifact_store,
            artifact_disclosure,
        )
        site_environment_file: Path | None = None
        site_container_configuration: SiteContainerConfiguration | None = None
        if installation.executable_invocation_mode is ExecutableInvocationMode.SITE_CONTAINER:
            site_container_configuration = (
                deployment_configuration
                if isinstance(deployment_configuration, SiteContainerConfiguration)
                else None
            )
            if site_runtime is None or site_container_configuration is None:
                raise ValueError("site-container installations require private runtime state")
            site_environment_file = workspace / ".site-container-environment.sh"
            _write_private_file(
                site_environment_file,
                site_runtime.environment_file_bytes(runtime_license_environment),
            )
        exit_codes: list[int] = []
        stdout_files: list[Path] = []
        stderr_files: list[Path] = []
        timed_out = False
        program_unavailable = False
        execution_closure_changed = False
        restricted_asset_changed = False
        expected_exit_codes = fixture.exit_codes_for(role)

        for index, invocation in enumerate(fixture.invocations):
            stdout_path = workspace / f".command-{index:03d}.stdout"
            stderr_path = workspace / f".command-{index:03d}.stderr"
            stdout_files.append(stdout_path)
            stderr_files.append(stderr_path)
            closure_valid = installation.execution_closure.revalidate()
            deployment_valid = (
                deployment_configuration is None
                or deployment_configuration.revalidate()
            )
            assets_valid = revalidate_materialized_qualification_assets(
                materialized_assets,
                restricted_assets,
                workspace,
            )
            if isinstance(invocation, ToolInvocation) and not (
                closure_valid and deployment_valid and assets_valid
            ):
                stdout_path.touch(mode=0o600)
                stderr_path.touch(mode=0o600)
                execution_closure_changed = not (closure_valid and deployment_valid)
                restricted_asset_changed = not assets_valid
                break
            executable_descriptor = _invocation_executable(
                invocation,
                installation,
                workspace_descriptor,
            )
            if executable_descriptor is None:
                stdout_path.touch(mode=0o600)
                stderr_path.touch(mode=0o600)
                program_unavailable = True
                break
            arguments = invocation.arguments
            site_container_execution = (
                isinstance(invocation, ToolInvocation)
                and installation.executable_invocation_mode
                is ExecutableInvocationMode.SITE_CONTAINER
            )
            rootless_image_execution = (
                isinstance(invocation, ToolInvocation)
                and installation.executable_invocation_mode
                is ExecutableInvocationMode.ROOTLESS_IMAGE
            )
            child_environment: Mapping[str, str] = environment
            if site_container_execution:
                if site_runtime is None or site_environment_file is None:
                    raise ValueError("site-container runtime state disappeared")
                arguments = site_runtime.invocation_arguments(
                    workspace,
                    site_environment_file,
                    invocation.arguments,
                )
                child_environment = site_runtime.host_environment
            elif rootless_image_execution:
                if rootless_runtime is None:
                    raise ValueError("rootless-image runtime state disappeared")
                arguments = rootless_runtime.invocation_arguments(
                    workspace,
                    invocation.arguments,
                )
                child_environment = rootless_runtime.host_environment
            trusted_path_execution = (
                isinstance(invocation, ToolInvocation)
                and installation.executable_invocation_mode
                in {
                    ExecutableInvocationMode.TRUSTED_PATH,
                    ExecutableInvocationMode.SITE_CONTAINER,
                    ExecutableInvocationMode.ROOTLESS_IMAGE,
                }
            )
            if (
                trusted_path_execution
                and _trusted_immutable_executable(installation.executable_path)
                != installation.executable_path
            ):
                stdout_path.touch(mode=0o600)
                stderr_path.touch(mode=0o600)
                program_unavailable = True
                os.close(executable_descriptor)
                break
            executable_reference = (
                os.fspath(installation.executable_path)
                if trusted_path_execution
                else f"/proc/self/fd/{executable_descriptor}"
            )
            argument_zero = (
                os.fspath(installation.executable_path)
                if isinstance(invocation, ToolInvocation)
                else invocation.executable
            )
            with (
                _held_deployment_mounts(site_container_configuration),
                stdout_path.open("xb") as stdout_stream,
                stderr_path.open("xb") as stderr_stream,
            ):
                os.fchmod(stdout_stream.fileno(), 0o600)
                os.fchmod(stderr_stream.fileno(), 0o600)
                try:
                    process = subprocess.Popen(
                        (argument_zero, *arguments),
                        executable=executable_reference,
                        cwd=workspace,
                        env=child_environment,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_stream,
                        stderr=stderr_stream,
                        pass_fds=(() if trusted_path_execution else (executable_descriptor,)),
                        start_new_session=True,
                        preexec_fn=lambda: _apply_process_limits(resource_grant),
                    )
                except (OSError, subprocess.SubprocessError):
                    program_unavailable = True
                    os.close(executable_descriptor)
                    break
                except BaseException:
                    os.close(executable_descriptor)
                    raise
                os.close(executable_descriptor)
                try:
                    try:
                        exit_code = process.wait(
                            timeout=resource_grant.command_timeout_seconds
                        )
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        _kill_process_group(process.pid)
                        exit_code = process.wait()
                finally:
                    _kill_process_group(process.pid)
                    if process.poll() is None:
                        process.wait()
                exit_codes.append(exit_code)
            if (
                isinstance(invocation, ToolInvocation)
                and not (
                    installation.execution_closure.revalidate()
                    and (
                        deployment_configuration is None
                        or deployment_configuration.revalidate()
                    )
                )
            ):
                execution_closure_changed = True
            if not revalidate_materialized_qualification_assets(
                materialized_assets,
                restricted_assets,
                workspace,
            ):
                restricted_asset_changed = True
            if (
                timed_out
                or execution_closure_changed
                or restricted_asset_changed
                or exit_codes[-1] != expected_exit_codes[index]
            ):
                break

        _privatize_workspace_tree(workspace_descriptor)
        (
            output_artifacts,
            observation_files,
            stdout_samples,
            stderr_samples,
            missing_output,
        ) = _collect_outputs(
            workspace_descriptor,
            fixture,
            role,
            stdout_files,
            stderr_files,
            artifact_store,
            artifact_disclosure,
            fixture.log_projection,
        )
        observation = FixtureObservation(
            exit_codes=tuple(exit_codes),
            stdout=stdout_samples,
            stderr=stderr_samples,
            files=observation_files,
        )
        failure: QualificationFailure | None
        if timed_out:
            failure = QualificationFailure.TIMED_OUT
        elif execution_closure_changed:
            failure = QualificationFailure.EXECUTION_CLOSURE_CHANGED
        elif restricted_asset_changed:
            failure = QualificationFailure.RESTRICTED_ASSET_CHANGED
        elif program_unavailable:
            failure = QualificationFailure.PROGRAM_UNAVAILABLE
        elif tuple(exit_codes) != expected_exit_codes:
            failure = QualificationFailure.TOOL_EXITED
        elif missing_output:
            failure = QualificationFailure.OUTPUT_MISSING
        else:
            try:
                semantic_rejection = fixture.parser.rejection(observation)
                accepted = fixture.parser.accepts(observation)
            except Exception:
                semantic_rejection = None
                accepted = False
                failure = QualificationFailure.PARSER_CRASHED
            else:
                expected = (
                    accepted and semantic_rejection is None
                    if role is FixtureRole.ACCEPTANCE
                    else not accepted and semantic_rejection is fixture.rejection_reason
                )
                failure = None if expected else QualificationFailure.PARSER_REJECTED
        if failure is not None:
            semantic_rejection = None
        diagnostic_artifacts = (
            _collect_raw_diagnostics(
                workspace_descriptor,
                fixture,
                role,
                stdout_files,
                stderr_files,
                artifact_store,
            )
            if failure is not None and fixture.log_projection is not None
            else ()
        )
        return QualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capability=fixture.capability,
            role=role,
            fixture=fixture_snapshot,
            fixture_pair_digest=fixture.digest,
            driver_digest=definition.driver_digest,
            backend_probe_digest=canonical_digest(probe, domain="backend-probe-v1"),
            tool_version=probe.tool_version or installation.version_label,
            executable_digest=installation.executable_digest,
            execution_closure_digest=installation.execution_closure_digest,
            version_output_digest=installation.version_output_digest,
            executable_invocation_mode=installation.executable_invocation_mode,
            deployment_attestation_digest=installation.deployment_attestation_digest,
            deployment_record_digest=installation.deployment_record_digest,
            package_manifest_digest=installation.package_manifest_digest,
            modulefile_digest=installation.modulefile_digest,
            license_authorization=license_authorization,
            artifact_policy_digest=artifact_store.policy_digest,
            resource_grant=resource_grant,
            input_artifacts=input_artifacts,
            deployment_artifacts=deployment_artifacts,
            restricted_assets=asset_evidence,
            output_artifacts=output_artifacts,
            diagnostic_artifacts=diagnostic_artifacts,
            exit_codes=tuple(exit_codes),
            outcome=(
                QualificationOutcome.PASSED if failure is None else QualificationOutcome.FAILED
            ),
            failure=failure,
            semantic_rejection_reason=(
                semantic_rejection if failure is None and role is FixtureRole.REJECTION else None
            ),
            recorded_at=datetime.now(UTC),
        )
    finally:
        os.close(workspace_descriptor)
        shutil.rmtree(workspace)


@contextmanager
def _held_deployment_mounts(
    configuration: SiteContainerConfiguration | None,
) -> Iterator[None]:
    descriptors = () if configuration is None else configuration.open_mount_descriptors()
    try:
        yield
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _validated_scratch_root(root: Path) -> Path:
    if root.is_symlink():
        raise ValueError("qualification scratch root cannot be a symbolic link")
    resolved = root.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("qualification scratch root must be a real directory")
    if metadata.st_uid != os.getuid():
        raise ValueError("qualification scratch root must be owned by the current user")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("qualification scratch root cannot be group or world writable")
    return resolved


def _materialize_inputs(
    workspace: Path,
    workspace_descriptor: int,
    fixture: QualificationFixture,
    role: FixtureRole,
    artifact_store: ContentAddressedStore,
    disclosure: ArtifactDisclosure,
) -> tuple[ArtifactRecord, ...]:
    artifacts: list[ArtifactRecord] = []
    case_id = qualification_case_id(fixture.tool_id, fixture.capability, role)
    for source in fixture.inputs_for(role):
        target = workspace / source.path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_private_file(target, source.content)
        artifact, _, _ = _persist_relative_file(
            workspace_descriptor,
            source.path,
            qualification_artifact_id(case_id, source.logical_id),
            artifact_store,
            disclosure,
            media_type=source.media_type,
        )
        artifacts.append(artifact)
    return tuple(artifacts)


def _write_private_file(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _persist_rootless_package_manifest(
    manifest: bytes | None,
    artifact_store: ContentAddressedStore,
    disclosure: ArtifactDisclosure,
) -> tuple[ArtifactRecord, ...]:
    if manifest is None:
        return ()
    reference = artifact_store.put_bytes(
        manifest,
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )
    return (
        ArtifactRecord(
            logical_id=_ROOTLESS_PACKAGE_MANIFEST_ID,
            blob=BlobRef(digest=reference.digest, size_bytes=reference.size_bytes),
            media_type="text/tab-separated-values",
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        ),
    )


def _fixture_environment(source: dict[str, str], workspace: Path) -> dict[str, str]:
    home = workspace / "home"
    temporary = workspace / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    environment = dict(source)
    environment.update(
        {
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
        }
    )
    for name in ("BASH_ENV", "CDPATH", "ENV", "GIT_CONFIG_GLOBAL", "PYTHONSTARTUP"):
        environment.pop(name, None)
    return environment


def _invocation_executable(
    invocation: ToolInvocation | WorkspaceInvocation,
    installation: ResolvedInstallation,
    workspace_descriptor: int,
) -> int | None:
    if isinstance(invocation, ToolInvocation):
        try:
            descriptor = os.open(
                installation.executable_path,
                os.O_RDONLY | os.O_CLOEXEC,
            )
        except OSError:
            return None
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            return None
        if _digest_descriptor(descriptor) != installation.execution_closure.host_entrypoint_digest:
            os.close(descriptor)
            return None
        return descriptor
    return _open_relative_file(workspace_descriptor, invocation.executable)


def _collect_outputs(
    workspace_descriptor: int,
    fixture: QualificationFixture,
    role: FixtureRole,
    stdout_files: list[Path],
    stderr_files: list[Path],
    artifact_store: ContentAddressedStore,
    disclosure: ArtifactDisclosure,
    log_projection: MarkerLogProjection | None,
) -> tuple[
    tuple[ArtifactRecord, ...],
    tuple[ObservedFile, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
    bool,
]:
    artifacts: list[ArtifactRecord] = []
    observations: list[ObservedFile] = []
    stdout_samples: list[bytes] = []
    stderr_samples: list[bytes] = []
    case_id = qualification_case_id(fixture.tool_id, fixture.capability, role)
    for index, path in enumerate(stdout_files):
        artifact, sample, _ = _persist_relative_file(
            workspace_descriptor,
            path.name,
            qualification_artifact_id(case_id, f"command_{index}_stdout"),
            artifact_store,
            disclosure,
            media_type="text/plain",
            projection=log_projection,
        )
        artifacts.append(artifact)
        stdout_samples.append(sample)
    for index, path in enumerate(stderr_files):
        artifact, sample, _ = _persist_relative_file(
            workspace_descriptor,
            path.name,
            qualification_artifact_id(case_id, f"command_{index}_stderr"),
            artifact_store,
            disclosure,
            media_type="text/plain",
            projection=log_projection,
        )
        artifacts.append(artifact)
        stderr_samples.append(sample)
    missing = False
    for declaration in fixture.outputs:
        try:
            artifact, sample, size = _persist_relative_file(
                workspace_descriptor,
                declaration.path,
                qualification_artifact_id(case_id, declaration.logical_id),
                artifact_store,
                disclosure,
                media_type=declaration.media_type,
            )
        except FileNotFoundError:
            missing |= declaration.required
            continue
        artifacts.append(artifact)
        observations.append(
            ObservedFile(
                path=declaration.path,
                content=sample,
                size_bytes=size,
                truncated=size > len(sample),
            )
        )
    return (
        tuple(artifacts),
        tuple(observations),
        tuple(stdout_samples),
        tuple(stderr_samples),
        missing,
    )


def _collect_raw_diagnostics(
    workspace_descriptor: int,
    fixture: QualificationFixture,
    role: FixtureRole,
    stdout_files: list[Path],
    stderr_files: list[Path],
    artifact_store: ContentAddressedStore,
) -> tuple[ArtifactRecord, ...]:
    """Seal native failed-command logs without exposing them to semantic parsers."""

    artifacts: list[ArtifactRecord] = []
    case_id = qualification_case_id(fixture.tool_id, fixture.capability, role)
    for index, path in enumerate(stdout_files):
        artifacts.append(
            _persist_raw_diagnostic(
                workspace_descriptor,
                path.name,
                f"{qualification_artifact_id(case_id, f'command_{index}_stdout')}_raw",
                artifact_store,
            )
        )
    for index, path in enumerate(stderr_files):
        artifacts.append(
            _persist_raw_diagnostic(
                workspace_descriptor,
                path.name,
                f"{qualification_artifact_id(case_id, f'command_{index}_stderr')}_raw",
                artifact_store,
            )
        )
    return tuple(artifacts)


def _persist_raw_diagnostic(
    workspace_descriptor: int,
    relative_path: str,
    logical_id: str,
    artifact_store: ContentAddressedStore,
) -> ArtifactRecord:
    descriptor = _open_relative_file(workspace_descriptor, relative_path)
    if descriptor is None:
        raise FileNotFoundError(relative_path)
    try:
        os.fchmod(descriptor, 0o600)
        reference = artifact_store.put_file_descriptor(
            descriptor,
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=PROTECTED_RAW_DISCLOSURE.sensitivity,
            visibility=PROTECTED_RAW_DISCLOSURE.visibility,
            redistribution=PROTECTED_RAW_DISCLOSURE.redistribution,
        )
        return ArtifactRecord(
            logical_id=logical_id,
            blob=BlobRef(digest=reference.digest, size_bytes=reference.size_bytes),
            media_type="text/plain",
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=PROTECTED_RAW_DISCLOSURE.sensitivity,
            visibility=PROTECTED_RAW_DISCLOSURE.visibility,
            redistribution=PROTECTED_RAW_DISCLOSURE.redistribution,
        )
    finally:
        os.close(descriptor)


def _persist_relative_file(
    workspace_descriptor: int,
    relative_path: str,
    logical_id: str,
    artifact_store: ContentAddressedStore,
    disclosure: ArtifactDisclosure,
    *,
    media_type: str,
    projection: MarkerLogProjection | None = None,
) -> tuple[ArtifactRecord, bytes, int]:
    descriptor = _open_relative_file(workspace_descriptor, relative_path)
    if descriptor is None:
        raise FileNotFoundError(relative_path)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        size = metadata.st_size

        def chunks() -> Iterator[bytes]:
            while chunk := os.read(descriptor, 1024 * 1024):
                yield chunk

        if projection is None:
            reference = artifact_store.put_chunks(
                chunks(),
                artifact_class=ArtifactClass.EVIDENCE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            sample = os.read(descriptor, _PARSER_CAPTURE_BYTES)
            retained_size = size
        else:
            projected = projection.project(chunks())
            reference = artifact_store.put_bytes(
                projected,
                artifact_class=ArtifactClass.EVIDENCE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
            sample = projected
            retained_size = len(projected)
        return (
            ArtifactRecord(
                logical_id=logical_id,
                blob=BlobRef(digest=reference.digest, size_bytes=reference.size_bytes),
                media_type=media_type,
                artifact_class=ArtifactClass.EVIDENCE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            ),
            sample,
            retained_size,
        )
    finally:
        os.close(descriptor)


def _open_relative_file(workspace_descriptor: int, relative_path: str) -> int | None:
    parts = Path(relative_path).parts
    directory = os.dup(workspace_descriptor)
    try:
        for part in parts[:-1]:
            next_directory = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    except OSError:
        return None
    finally:
        os.close(directory)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        return None
    return descriptor


def _privatize_workspace_tree(workspace_descriptor: int) -> None:
    """Normalize settled vendor output through owned, non-symlink descriptors."""

    root = os.fstat(workspace_descriptor)
    if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.getuid():
        raise ValueError("qualification workspace ownership changed")
    os.fchmod(workspace_descriptor, 0o700)
    if stat.S_IMODE(os.fstat(workspace_descriptor).st_mode) != 0o700:
        raise ValueError("qualification workspace could not be made private")

    with os.scandir(workspace_descriptor) as iterator:
        names = tuple(sorted(entry.name for entry in iterator))
    for name in names:
        metadata = os.stat(name, dir_fd=workspace_descriptor, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            continue
        if metadata.st_uid != os.getuid():
            raise ValueError("qualification output is not owned by the current user")
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=workspace_descriptor,
            )
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise ValueError("qualification output changed during privatization")
                _privatize_workspace_tree(child)
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("qualification output has an unsupported file type")
        child = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=workspace_descriptor,
        )
        try:
            opened = os.fstat(child)
            if (
                (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or opened.st_uid != os.getuid()
                or opened.st_nlink != 1
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise ValueError("qualification output changed during privatization")
            private_mode = 0o700 if opened.st_mode & stat.S_IXUSR else 0o600
            os.fchmod(child, private_mode)
            after = os.fstat(child)
            if (
                (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or stat.S_IMODE(after.st_mode) != private_mode
            ):
                raise ValueError("qualification output could not be made private")
        finally:
            os.close(child)


def _digest_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return f"sha256:{digest.hexdigest()}"


def _apply_process_limits(resource_grant: QualificationResourceGrant) -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    file_size_limit = min(
        resource_grant.limits.disk_bytes,
        _MAX_QUALIFICATION_FILE_BYTES,
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (file_size_limit, file_size_limit),
    )
    resource.setrlimit(
        resource.RLIMIT_AS,
        (resource_grant.limits.memory_bytes, resource_grant.limits.memory_bytes),
    )
    timeout_seconds = resource_grant.command_timeout_seconds
    resource.setrlimit(
        resource.RLIMIT_CPU,
        (timeout_seconds, timeout_seconds + 1),
    )


def _kill_process_group(process_group: int) -> None:
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return


def _assessment(
    probe: BackendProbe,
    requested: tuple[Capability, ...],
    evidence: tuple[QualificationEvidence, ...],
    gaps: tuple[CapabilityGap, ...],
) -> BackendQualification:
    disposition = _derive_disposition(probe, evidence, gaps)
    return BackendQualification(
        probe=probe,
        requested_capabilities=requested,
        evidence=evidence,
        gaps=gaps,
        disposition=disposition,
    )


def _derive_disposition(
    probe: BackendProbe,
    evidence: tuple[QualificationEvidence, ...],
    gaps: tuple[CapabilityGap, ...],
) -> QualificationDisposition:
    if probe.state is QualificationState.UNAVAILABLE:
        return QualificationDisposition.UNAVAILABLE
    if (
        not evidence
        and gaps
        and all(item.reason is QualificationGapReason.EULA_ACCEPTANCE_REQUIRED for item in gaps)
    ):
        return QualificationDisposition.UNAVAILABLE
    if any(item.outcome is QualificationOutcome.FAILED for item in evidence):
        return QualificationDisposition.NONCONFORMANT
    if (
        not evidence
        and gaps
        and all(
            item.reason is QualificationGapReason.LICENSE_AUTHORIZATION_REQUIRED for item in gaps
        )
    ):
        return QualificationDisposition.PROBE_ONLY
    if gaps:
        return QualificationDisposition.INCOMPLETE
    if any(
        not is_comprehensive_claim(
            item.capability,
            item.fixture.semantic_claim_id,
            item.fixture.semantic_joints,
        )
        for item in evidence
    ):
        return QualificationDisposition.INCOMPLETE
    return QualificationDisposition.CONFORMANT
