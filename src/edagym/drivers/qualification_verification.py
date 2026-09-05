"""Live source verification for backend qualification evidence."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import IO, Never, SupportsIndex

from edagym.canonical import canonical_digest
from edagym.drivers.catalog import backend_by_id
from edagym.drivers.deployment import BackendDeploymentConfiguration
from edagym.drivers.fixtures import QualificationFixture, fixture_for
from edagym.drivers.fixtures.model import (
    FixtureObservation,
    FixtureRole,
    MarkerLogProjection,
    ObservedFile,
    qualification_artifact_id,
)
from edagym.drivers.model import BackendDefinition, QualificationState, Vendor
from edagym.drivers.probe import probe_backend
from edagym.drivers.qualification import (
    _PARSER_CAPTURE_BYTES,
    BackendQualification,
    QualificationEvidence,
    QualificationFailure,
    QualificationGapReason,
    QualificationOutcome,
)
from edagym.drivers.rootless_image import RootlessImageConfiguration
from edagym.run.artifacts import ContentAddressedStore, artifact_policy_digest
from edagym.run.model import ArtifactRecord
from edagym.specs.common import ArtifactClass
from edagym.specs.environment import EnvironmentSpec, FilesystemScope, ImageToolLocator

_VERIFIED_SOURCE_ISSUER = object()


class QualificationSourceKind(StrEnum):
    """The independently verified source behind one qualification partition."""

    EVIDENCE_PAIR = "evidence_pair"
    LIVE_PROBE_GAP = "live_probe_gap"


class QualificationSourceVerificationError(RuntimeError):
    """Live qualification artifacts or their bound context are inconsistent."""


class VerifiedBackendQualificationSource:
    """Immutable process-local proof of one live qualification source."""

    _qualification: BackendQualification
    _source_kind: QualificationSourceKind
    _artifact_closure_digest: str | None
    _artifact_store: ContentAddressedStore | None
    _source_digest: str

    __slots__ = (
        "_artifact_closure_digest",
        "_artifact_store",
        "_qualification",
        "_source_digest",
        "_source_kind",
    )

    def __init__(
        self,
        qualification: BackendQualification,
        *,
        source_kind: QualificationSourceKind,
        artifact_closure_digest: str | None,
        artifact_store: ContentAddressedStore | None,
        source_digest: str,
        _issuer: object,
    ) -> None:
        if _issuer is not _VERIFIED_SOURCE_ISSUER:
            raise TypeError("verified qualification sources are issued only by live verification")
        carries_artifacts = (
            artifact_closure_digest is not None and artifact_store is not None
        )
        if carries_artifacts != (source_kind is QualificationSourceKind.EVIDENCE_PAIR):
            raise TypeError("verified source kind differs from its live artifact closure")
        object.__setattr__(self, "_qualification", qualification)
        object.__setattr__(self, "_source_kind", source_kind)
        object.__setattr__(self, "_artifact_closure_digest", artifact_closure_digest)
        object.__setattr__(self, "_artifact_store", artifact_store)
        object.__setattr__(self, "_source_digest", source_digest)

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise TypeError("verified qualification sources are immutable")

    @property
    def qualification(self) -> BackendQualification:
        return self._qualification

    @property
    def source_kind(self) -> QualificationSourceKind:
        return self._source_kind

    @property
    def artifact_closure_digest(self) -> str | None:
        return self._artifact_closure_digest

    @property
    def artifact_store(self) -> ContentAddressedStore | None:
        """Return the verified live store only for an evidence-pair source."""

        return self._artifact_store

    @property
    def source_digest(self) -> str:
        return self._source_digest

    def __repr__(self) -> str:
        return (
            "VerifiedBackendQualificationSource("
            f"tool_id={self._qualification.probe.tool_id!r}, "
            f"source_kind={self._source_kind.value!r}, source=<verified>)"
        )

    def __reduce__(self) -> Never:
        raise TypeError("verified qualification sources cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified qualification sources cannot be serialized")


@dataclass(frozen=True, slots=True)
class _QualificationRecordBinding:
    role: FixtureRole
    collection: str
    record: ArtifactRecord


def verify_backend_qualification_source(
    qualification: BackendQualification,
    *,
    definition: BackendDefinition,
    environment: EnvironmentSpec | None = None,
    artifact_store: ContentAddressedStore | None = None,
    deployment_configuration: BackendDeploymentConfiguration | None = None,
    rootless_image_configuration: RootlessImageConfiguration | None = None,
) -> VerifiedBackendQualificationSource:
    """Re-probe one gap or replay one evidence pair from its exclusive live CAS."""

    _verify_canonical_partition(qualification, definition)
    _verify_runtime_configuration_shape(
        definition,
        deployment_configuration,
        rootless_image_configuration,
    )
    if qualification.evidence:
        if environment is None or artifact_store is None:
            raise QualificationSourceVerificationError(
                "evidence verification requires its exact environment and live store"
            )
        return _verify_evidence_pair_source(
            qualification,
            definition=definition,
            environment=environment,
            artifact_store=artifact_store,
            deployment_configuration=deployment_configuration,
            rootless_image_configuration=rootless_image_configuration,
        )
    if environment is not None or artifact_store is not None:
        raise QualificationSourceVerificationError(
            "gap verification does not accept an unbound environment or artifact store"
        )
    return _verify_live_probe_gap_source(
        qualification,
        definition=definition,
        deployment_configuration=deployment_configuration,
        rootless_image_configuration=rootless_image_configuration,
    )


def _verify_canonical_partition(
    qualification: BackendQualification,
    definition: BackendDefinition,
) -> None:
    if type(qualification) is not BackendQualification or type(definition) is not BackendDefinition:
        raise QualificationSourceVerificationError(
            "qualification verification requires concrete canonical models"
        )
    try:
        canonical_definition = backend_by_id(definition.tool_id)
    except KeyError as error:
        raise QualificationSourceVerificationError(
            "qualification backend is absent from the canonical catalog"
        ) from error
    if definition != canonical_definition:
        raise QualificationSourceVerificationError(
            "qualification definition differs from the canonical backend"
        )
    if (
        qualification.probe.tool_id != definition.tool_id
        or qualification.probe.vendor is not definition.vendor
        or qualification.probe.capabilities != definition.capabilities
        or qualification.probe.host_support_mode is not definition.host_support_mode
        or qualification.probe.driver_digest != definition.driver_digest
        or len(qualification.requested_capabilities) != 1
    ):
        raise QualificationSourceVerificationError(
            "qualification does not bind one canonical backend capability"
        )


def _verify_runtime_configuration_shape(
    definition: BackendDefinition,
    deployment_configuration: BackendDeploymentConfiguration | None,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> None:
    if deployment_configuration is not None and rootless_image_configuration is not None:
        raise QualificationSourceVerificationError(
            "qualification cannot bind two deployment configurations"
        )
    if (
        deployment_configuration is not None
        and deployment_configuration.tool_id != definition.tool_id
    ):
        raise QualificationSourceVerificationError(
            "qualification deployment names a different backend"
        )
    if definition.vendor is not Vendor.OPEN_SOURCE and rootless_image_configuration is not None:
        raise QualificationSourceVerificationError(
            "commercial qualification cannot use an open-image deployment binding"
        )


def _verify_evidence_pair_source(
    qualification: BackendQualification,
    *,
    definition: BackendDefinition,
    environment: EnvironmentSpec,
    artifact_store: ContentAddressedStore,
    deployment_configuration: BackendDeploymentConfiguration | None,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> VerifiedBackendQualificationSource:
    capability = qualification.requested_capabilities[0]
    fixture = fixture_for(definition.tool_id, capability)
    if fixture is None:
        raise QualificationSourceVerificationError(
            "qualification has no canonical semantic fixture"
        )
    if len(qualification.evidence) != len(FixtureRole) or qualification.gaps:
        raise QualificationSourceVerificationError(
            "live evidence verification requires one complete semantic pair"
        )
    if (
        type(environment) is not EnvironmentSpec
        or type(artifact_store) is not ContentAddressedStore
    ):
        raise QualificationSourceVerificationError(
            "evidence verification requires concrete environment and store implementations"
        )
    if artifact_policy_digest(environment.artifact_policy) != artifact_store.policy_digest:
        raise QualificationSourceVerificationError(
            "artifact store policy differs from the bound environment"
        )

    _verify_evidence_deployment_binding(
        qualification,
        definition,
        deployment_configuration,
        rootless_image_configuration,
    )
    _verify_environment_binding(
        qualification,
        definition,
        environment,
        rootless_image_configuration,
    )
    bindings = _qualification_record_bindings(qualification)
    content, raw_projections, artifact_closure_digest = _reopen_exact_artifact_closure(
        bindings,
        fixture,
        artifact_store,
    )
    for evidence in qualification.evidence:
        _verify_evidence_source(evidence, fixture, content, raw_projections)
    _revalidate_runtime_configuration(
        deployment_configuration,
        rootless_image_configuration,
    )

    live_probe_digest = canonical_digest(
        qualification.probe,
        domain="backend-probe-v1",
    )
    source_digest = canonical_digest(
        {
            "source_kind": QualificationSourceKind.EVIDENCE_PAIR,
            "qualification_digest": qualification.digest,
            "driver_digest": definition.driver_digest,
            "live_probe_digest": live_probe_digest,
            "environment_digest": environment.digest,
            "deployment_record_digest": _runtime_configuration_digest(
                deployment_configuration,
                rootless_image_configuration,
            ),
            "artifact_closure_digest": artifact_closure_digest,
        },
        domain="verified-backend-qualification-source-v2",
    )
    return VerifiedBackendQualificationSource(
        qualification,
        source_kind=QualificationSourceKind.EVIDENCE_PAIR,
        artifact_closure_digest=artifact_closure_digest,
        artifact_store=artifact_store,
        source_digest=source_digest,
        _issuer=_VERIFIED_SOURCE_ISSUER,
    )


def _verify_live_probe_gap_source(
    qualification: BackendQualification,
    *,
    definition: BackendDefinition,
    deployment_configuration: BackendDeploymentConfiguration | None,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> VerifiedBackendQualificationSource:
    if qualification.evidence or len(qualification.gaps) != 1:
        raise QualificationSourceVerificationError(
            "gap verification requires one exact capability gap and no evidence"
        )
    live_probe, _installation = probe_backend(
        definition,
        deployment_configuration=deployment_configuration,
        rootless_image_configuration=rootless_image_configuration,
    )
    if live_probe != qualification.probe:
        raise QualificationSourceVerificationError(
            "qualification gap differs from its current live probe"
        )
    _verify_gap_reason(qualification, definition)
    _revalidate_runtime_configuration(
        deployment_configuration,
        rootless_image_configuration,
    )
    live_probe_digest = canonical_digest(live_probe, domain="backend-probe-v1")
    source_digest = canonical_digest(
        {
            "source_kind": QualificationSourceKind.LIVE_PROBE_GAP,
            "qualification_digest": qualification.digest,
            "driver_digest": definition.driver_digest,
            "live_probe_digest": live_probe_digest,
            "deployment_record_digest": _runtime_configuration_digest(
                deployment_configuration,
                rootless_image_configuration,
            ),
            "artifact_closure_digest": None,
        },
        domain="verified-backend-qualification-source-v2",
    )
    return VerifiedBackendQualificationSource(
        qualification,
        source_kind=QualificationSourceKind.LIVE_PROBE_GAP,
        artifact_closure_digest=None,
        artifact_store=None,
        source_digest=source_digest,
        _issuer=_VERIFIED_SOURCE_ISSUER,
    )


def _verify_gap_reason(
    qualification: BackendQualification,
    definition: BackendDefinition,
) -> None:
    reason = qualification.gaps[0].reason
    state = qualification.probe.state
    if state is QualificationState.UNAVAILABLE:
        valid = reason is QualificationGapReason.PROBE_NOT_INVOCABLE
    elif state is QualificationState.INVOCABLE:
        capability = qualification.requested_capabilities[0]
        valid = (
            fixture_for(definition.tool_id, capability) is None
            and reason is QualificationGapReason.FIXTURE_UNAVAILABLE
        )
    elif definition.workload_use_requires_eula_acceptance:
        valid = reason is QualificationGapReason.EULA_ACCEPTANCE_REQUIRED
    else:
        valid = reason in {
            QualificationGapReason.LICENSE_AUTHORIZATION_REQUIRED,
            QualificationGapReason.AUTHORIZED_BINDING_MISMATCH,
            QualificationGapReason.AUTHORIZED_LICENSE_UNAVAILABLE,
            QualificationGapReason.AUTHORIZED_IDENTITY_CHANGED,
            QualificationGapReason.AUTHORIZED_EXECUTABLE_UNAVAILABLE,
            QualificationGapReason.HOST_RUNTIME_DEPENDENCY_UNAVAILABLE,
            QualificationGapReason.AUTHORIZED_VERSION_PROBE_FAILED,
        }
    if not valid:
        raise QualificationSourceVerificationError(
            "qualification gap reason differs from its live probe state"
        )


def _verify_evidence_deployment_binding(
    qualification: BackendQualification,
    definition: BackendDefinition,
    deployment_configuration: BackendDeploymentConfiguration | None,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> None:
    expected_digest = _runtime_configuration_digest(
        deployment_configuration,
        rootless_image_configuration,
    )
    if any(
        evidence.deployment_record_digest != expected_digest
        for evidence in qualification.evidence
    ):
        raise QualificationSourceVerificationError(
            "qualification differs from its live deployment binding"
        )
    if definition.vendor is not Vendor.OPEN_SOURCE and expected_digest is None:
        raise QualificationSourceVerificationError(
            "commercial qualification lacks its live deployment binding"
        )
    _revalidate_runtime_configuration(
        deployment_configuration,
        rootless_image_configuration,
    )


def _runtime_configuration_digest(
    deployment_configuration: BackendDeploymentConfiguration | None,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> str | None:
    if deployment_configuration is not None:
        return deployment_configuration.deployment_digest
    if rootless_image_configuration is not None:
        return rootless_image_configuration.recipe.requirement_digest
    return None


def _revalidate_runtime_configuration(
    deployment_configuration: BackendDeploymentConfiguration | None,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> None:
    configuration = (
        deployment_configuration
        if deployment_configuration is not None
        else rootless_image_configuration
    )
    if configuration is not None and not configuration.revalidate():
        raise QualificationSourceVerificationError(
            "deployment changed during live qualification verification"
        )


def _verify_environment_binding(
    qualification: BackendQualification,
    definition: BackendDefinition,
    environment: EnvironmentSpec,
    rootless_image_configuration: RootlessImageConfiguration | None,
) -> None:
    capability = qualification.requested_capabilities[0]
    if len(environment.tool_bindings) != 1:
        raise QualificationSourceVerificationError(
            "qualification environment requires one exact tool binding"
        )
    binding = environment.tool_bindings[0]
    if (
        binding.tool_id != definition.tool_id
        or binding.capability is not capability
        or binding.driver_digest != definition.driver_digest
        or binding.tool_version != qualification.probe.tool_version
        or binding.locator.executable not in definition.executable_candidates
        or binding.locator.deployment_attestation_digest
        != qualification.probe.deployment_attestation_digest
    ):
        raise QualificationSourceVerificationError(
            "qualification probe differs from its environment tool binding"
        )
    if rootless_image_configuration is not None and (
        not isinstance(binding.locator, ImageToolLocator)
        or binding.locator.image_digest
        != rootless_image_configuration.recipe.image_digest
    ):
        raise QualificationSourceVerificationError(
            "rootless qualification differs from its exact image binding"
        )
    if any(
        evidence.resource_grant.limits != environment.resources
        or evidence.artifact_policy_digest
        != artifact_policy_digest(environment.artifact_policy)
        for evidence in qualification.evidence
    ):
        raise QualificationSourceVerificationError(
            "qualification resource or artifact grant differs from its environment"
        )

    required_assets: dict[str, str] = {}
    for evidence in qualification.evidence:
        for asset in evidence.restricted_assets:
            previous = required_assets.setdefault(asset.asset_id, asset.restricted_digest)
            if previous != asset.restricted_digest:
                raise QualificationSourceVerificationError(
                    "qualification roles bind different restricted assets"
                )
    environment_assets = {asset.asset_id: asset for asset in environment.assets}
    if set(environment_assets) != set(required_assets) or any(
        environment_assets[asset_id].restricted_digest != digest
        or FilesystemScope.EVALUATOR not in environment_assets[asset_id].allowed_scopes
        for asset_id, digest in required_assets.items()
    ):
        raise QualificationSourceVerificationError(
            "qualification assets differ from the exact environment"
        )
    evaluator_mounts = {
        mount.asset_id
        for mount in environment.filesystem.readonly_assets
        if mount.scope is FilesystemScope.EVALUATOR
    }
    if evaluator_mounts != set(required_assets):
        raise QualificationSourceVerificationError(
            "qualification asset mounts differ from the exact environment"
        )

    receipts = {
        evidence.license_authorization.digest: evidence.license_authorization
        for evidence in qualification.evidence
        if evidence.license_authorization is not None
    }
    if definition.vendor is Vendor.OPEN_SOURCE:
        if receipts or environment.licenses or binding.license_binding_id is not None:
            raise QualificationSourceVerificationError(
                "open-source qualification carries a commercial license binding"
            )
        return
    if len(receipts) != 1 or len(environment.licenses) != 1:
        raise QualificationSourceVerificationError(
            "commercial qualification requires one exact license receipt"
        )
    receipt = next(iter(receipts.values()))
    license_binding = environment.licenses[0]
    if (
        binding.license_binding_id != license_binding.license_binding_id
        or receipt.license_binding_id != license_binding.license_binding_id
        or receipt.license_binding_digest
        != canonical_digest(license_binding, domain="license-binding-v1")
        or receipt.provider_id != license_binding.provider_id
        or receipt.provider_digest != license_binding.provider_digest
        or receipt.feature_class != license_binding.feature_class
    ):
        raise QualificationSourceVerificationError(
            "commercial qualification differs from its environment license binding"
        )


def _qualification_record_bindings(
    qualification: BackendQualification,
) -> tuple[_QualificationRecordBinding, ...]:
    bindings = tuple(
        _QualificationRecordBinding(role=evidence.role, collection=collection, record=record)
        for evidence in qualification.evidence
        for collection, records in (
            ("input", evidence.input_artifacts),
            ("deployment", evidence.deployment_artifacts),
            ("output", evidence.output_artifacts),
            ("diagnostic", evidence.diagnostic_artifacts),
        )
        for record in records
    )
    identities = [(item.role, item.collection, item.record.logical_id) for item in bindings]
    if not bindings or len(identities) != len(set(identities)):
        raise QualificationSourceVerificationError(
            "qualification artifact closure is empty or ambiguous"
        )
    return tuple(
        sorted(
            bindings,
            key=lambda item: (item.role.value, item.collection, item.record.logical_id),
        )
    )


def _reopen_exact_artifact_closure(
    bindings: tuple[_QualificationRecordBinding, ...],
    fixture: QualificationFixture,
    store: ContentAddressedStore,
) -> tuple[Mapping[tuple[str, int], bytes], Mapping[tuple[str, int], bytes], str]:
    records = tuple(binding.record for binding in bindings)
    for record in records:
        disclosure = store.policy.persistent_disclosure(record.artifact_class)
        if disclosure is None or (
            record.sensitivity is not disclosure.sensitivity
            or record.visibility is not disclosure.visibility
            or record.redistribution is not disclosure.redistribution
        ):
            raise QualificationSourceVerificationError(
                "qualification artifact differs from its environment disclosure"
            )
        store.verify_disclosure(
            record.blob,
            artifact_class=record.artifact_class,
            sensitivity=record.sensitivity,
            visibility=record.visibility,
            redistribution=record.redistribution,
        )

    expected = {(record.blob.digest, record.blob.size_bytes) for record in records}
    classes_by_blob: dict[tuple[str, int], set[ArtifactClass]] = {}
    for record in records:
        classes_by_blob.setdefault((record.blob.digest, record.blob.size_bytes), set()).add(
            record.artifact_class
        )
    observed: set[tuple[str, int]] = set()
    evidence_content: dict[tuple[str, int], bytes] = {}
    raw_projections: dict[tuple[str, int], bytes] = {}
    with store.stable_plaintext_blobs() as blobs:
        for reference, stream in blobs:
            identity = (reference.digest, reference.size_bytes)
            observed.add(identity)
            classes = classes_by_blob.get(identity, set())
            if ArtifactClass.EVIDENCE in classes:
                evidence_content[identity] = stream.read(
                    min(reference.size_bytes, _PARSER_CAPTURE_BYTES)
                )
            if ArtifactClass.DIAGNOSTIC in classes:
                if fixture.log_projection is None:
                    raise QualificationSourceVerificationError(
                        "raw qualification diagnostic lacks a canonical projection"
                    )
                stream.seek(0)
                raw_projections[identity] = fixture.log_projection.project(_stream_chunks(stream))
    if observed != expected:
        raise QualificationSourceVerificationError(
            "live artifact store is missing, extra, or cross-wired"
        )
    closure_digest = canonical_digest(
        {
            "store_metadata": store.metadata,
            "records": tuple(
                {
                    "role": binding.role,
                    "collection": binding.collection,
                    "logical_id": binding.record.logical_id,
                    "digest": binding.record.blob.digest,
                    "size_bytes": binding.record.blob.size_bytes,
                    "media_type": binding.record.media_type,
                    "artifact_class": binding.record.artifact_class,
                    "sensitivity": binding.record.sensitivity,
                    "visibility": binding.record.visibility,
                    "redistribution": binding.record.redistribution,
                }
                for binding in bindings
            ),
        },
        domain="backend-qualification-artifact-closure-v2",
    )
    return evidence_content, raw_projections, closure_digest


def _stream_chunks(stream: IO[bytes]) -> Iterator[bytes]:
    while chunk := stream.read(1024 * 1024):
        yield chunk


def _verify_evidence_source(
    evidence: QualificationEvidence,
    fixture: QualificationFixture,
    content: Mapping[tuple[str, int], bytes],
    raw_projections: Mapping[tuple[str, int], bytes],
) -> None:
    records = {
        record.logical_id: record
        for record in (
            *evidence.input_artifacts,
            *evidence.deployment_artifacts,
            *evidence.output_artifacts,
        )
    }
    diagnostics = {record.logical_id: record for record in evidence.diagnostic_artifacts}

    def artifact_bytes(record: ArtifactRecord) -> bytes:
        try:
            return content[(record.blob.digest, record.blob.size_bytes)]
        except KeyError as error:
            raise QualificationSourceVerificationError(
                "qualification parser input is absent from the evidence closure"
            ) from error

    expected_inputs = fixture.inputs_for(evidence.role)
    for input_declaration, snapshot in zip(
        expected_inputs,
        evidence.fixture.inputs,
        strict=True,
    ):
        input_record = records[snapshot.logical_id]
        if (
            input_record.blob.size_bytes <= _PARSER_CAPTURE_BYTES
            and artifact_bytes(input_record) != input_declaration.content
        ):
            raise QualificationSourceVerificationError(
                "live fixture input differs from its canonical bytes"
            )

    stdout: list[bytes] = []
    stderr: list[bytes] = []
    for index in range(len(fixture.invocations)):
        stdout_id = qualification_artifact_id(
            evidence.fixture.fixture_id,
            f"command_{index}_stdout",
        )
        stderr_id = qualification_artifact_id(
            evidence.fixture.fixture_id,
            f"command_{index}_stderr",
        )
        if stdout_id not in records or stderr_id not in records:
            if evidence.outcome is QualificationOutcome.PASSED:
                raise QualificationSourceVerificationError(
                    "passing qualification lacks its live command logs"
                )
            break
        stdout_sample = artifact_bytes(records[stdout_id])
        stderr_sample = artifact_bytes(records[stderr_id])
        stdout.append(stdout_sample)
        stderr.append(stderr_sample)
        if isinstance(fixture.log_projection, MarkerLogProjection):
            _verify_projected_log(
                fixture.log_projection,
                stdout_id,
                stdout_sample,
                diagnostics,
                raw_projections,
            )
            _verify_projected_log(
                fixture.log_projection,
                stderr_id,
                stderr_sample,
                diagnostics,
                raw_projections,
            )

    observed_files: list[ObservedFile] = []
    for output_declaration in evidence.fixture.outputs:
        output_record = records.get(output_declaration.logical_id)
        if output_record is None:
            continue
        sample = artifact_bytes(output_record)
        observed_files.append(
            ObservedFile(
                path=output_declaration.path,
                content=sample,
                size_bytes=output_record.blob.size_bytes,
                truncated=output_record.blob.size_bytes > len(sample),
            )
        )
    observation = FixtureObservation(
        exit_codes=evidence.exit_codes,
        stdout=tuple(stdout),
        stderr=tuple(stderr),
        files=tuple(observed_files),
    )
    if evidence.outcome is QualificationOutcome.PASSED:
        _replay_passing_semantics(evidence, fixture, observation)
    elif evidence.failure in {
        QualificationFailure.PARSER_REJECTED,
        QualificationFailure.PARSER_CRASHED,
    }:
        _replay_parser_failure(evidence, fixture, observation)


def _verify_projected_log(
    projection: MarkerLogProjection,
    projected_id: str,
    projected_content: bytes,
    diagnostics: Mapping[str, ArtifactRecord],
    raw_projections: Mapping[tuple[str, int], bytes],
) -> None:
    raw_record = diagnostics.get(f"{projected_id}_raw")
    if raw_record is None:
        expected = projection.project((projected_content,))
    else:
        try:
            expected = raw_projections[(raw_record.blob.digest, raw_record.blob.size_bytes)]
        except KeyError as error:
            raise QualificationSourceVerificationError(
                "raw qualification log is absent from its diagnostic closure"
            ) from error
    if expected != projected_content:
        raise QualificationSourceVerificationError(
            "qualification log differs from its canonical raw projection"
        )


def _replay_passing_semantics(
    evidence: QualificationEvidence,
    fixture: QualificationFixture,
    observation: FixtureObservation,
) -> None:
    try:
        accepted = fixture.parser.accepts(observation)
        rejection = fixture.parser.rejection(observation)
    except Exception as error:
        raise QualificationSourceVerificationError(
            "canonical qualification parser failed during live replay"
        ) from error
    if evidence.role is FixtureRole.ACCEPTANCE:
        valid = accepted and rejection is None
    else:
        valid = not accepted and rejection is fixture.rejection_reason
    if not valid or rejection is not evidence.semantic_rejection_reason:
        raise QualificationSourceVerificationError(
            "live artifacts do not reproduce their semantic qualification outcome"
        )


def _replay_parser_failure(
    evidence: QualificationEvidence,
    fixture: QualificationFixture,
    observation: FixtureObservation,
) -> None:
    try:
        accepted = fixture.parser.accepts(observation)
        rejection = fixture.parser.rejection(observation)
    except Exception:
        if evidence.failure is not QualificationFailure.PARSER_CRASHED:
            raise QualificationSourceVerificationError(
                "live parser outcome differs from its qualification failure"
            ) from None
        return
    if evidence.failure is QualificationFailure.PARSER_CRASHED:
        raise QualificationSourceVerificationError(
            "live parser no longer reproduces its recorded crash"
        )
    expected = (
        accepted and rejection is None
        if evidence.role is FixtureRole.ACCEPTANCE
        else not accepted and rejection is fixture.rejection_reason
    )
    if expected:
        raise QualificationSourceVerificationError(
            "live parser accepts evidence recorded as parser-rejected"
        )
