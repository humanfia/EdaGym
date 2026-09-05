"""Live qualification source closure and parser replay evidence."""

from __future__ import annotations

import pickle
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from edagym.canonical import canonical_digest
from edagym.drivers.catalog import backend_by_id
from edagym.drivers.fixtures import QualificationFixture, fixture_for
from edagym.drivers.fixtures.model import (
    FixtureRole,
    MarkerLogProjection,
    qualification_artifact_id,
)
from edagym.drivers.fixtures.open_simulation import _VECTOR_SCHEDULE, RtlTraceWaveformParser
from edagym.drivers.model import (
    BackendDefinition,
    BackendProbe,
    ExecutableInvocationMode,
    QualificationState,
)
from edagym.drivers.probe import deployment_attestation_digest, probe_backend
from edagym.drivers.qualification import (
    BackendQualification,
    CapabilityGap,
    QualificationDisposition,
    QualificationEvidence,
    QualificationGapReason,
    QualificationOutcome,
)
from edagym.drivers.qualification_resources import QualificationResourceGrant
from edagym.drivers.qualification_verification import (
    QualificationSourceKind,
    QualificationSourceVerificationError,
    VerifiedBackendQualificationSource,
    _QualificationRecordBinding,
    _reopen_exact_artifact_closure,
    _verify_projected_log,
    verify_backend_qualification_source,
)
from edagym.run.artifacts import (
    ContentAddressedStore,
    EncryptionKey,
)
from edagym.run.model import ArtifactRecord
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    PROTECTED_RAW_DISCLOSURE,
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    AttestedHostToolLocator,
    BrokeredHostToolExecutor,
    CheckpointCapability,
    EnvironmentIdentity,
    EnvironmentSpec,
    FilesystemPolicy,
    ManagedEncryption,
    NoEncryption,
    NoNetwork,
    ResourceLimits,
    ToolBinding,
)


def _digest(name: str) -> str:
    return canonical_digest(name, domain="qualification-verification-test-v1")


_DISCLOSURE = ArtifactDisclosure(
    sensitivity=Sensitivity.INTERNAL,
    visibility=Visibility.AUTHOR,
    redistribution=Redistribution.RESTRICTED,
)
_LIMITS = ResourceLimits(
    cpu_millicores=1000,
    memory_bytes=1024 * 1024 * 1024,
    pids=128,
    disk_bytes=1024 * 1024 * 1024,
    wall_seconds=120,
)
_RESOURCE_GRANT = QualificationResourceGrant(
    limits=_LIMITS,
    command_timeout_seconds=30,
)
_SIMULATION_PROGRAM = b"compiled simulation"
# Testbench signals in dump order with the identifier codes the simulator assigns them.
_WAVEFORM_SIGNALS = (("a", "reg", 4, "!"), ("b", "reg", 4, '"'), ("y", "wire", 5, "#"))


@dataclass(frozen=True, slots=True)
class _QualificationCase:
    definition: BackendDefinition
    qualification: BackendQualification
    environment: EnvironmentSpec
    store: ContentAddressedStore


def _artifact_policy(
    disclosure: ArtifactDisclosure = _DISCLOSURE,
    *,
    managed: bool = False,
) -> ArtifactPolicy:
    return ArtifactPolicy(
        quota_bytes=64 * 1024 * 1024,
        encryption=(
            ManagedEncryption(
                provider_id="test_encryption_provider",
                policy_digest=_digest("test-encryption-policy"),
            )
            if managed
            else NoEncryption()
        ),
        rules=tuple(
            ArtifactRetentionRule(
                artifact_class=artifact_class,
                retention_seconds=600,
                allowed_disclosures=(disclosure,),
            )
            for artifact_class in ArtifactClass
        ),
    )


def _record(
    store: ContentAddressedStore,
    disclosure: ArtifactDisclosure,
    logical_id: str,
    content: bytes,
    media_type: str,
    *,
    artifact_class: ArtifactClass = ArtifactClass.EVIDENCE,
) -> ArtifactRecord:
    blob = store.put_bytes(
        content,
        artifact_class=artifact_class,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )
    return ArtifactRecord(
        logical_id=logical_id,
        blob=blob,
        media_type=media_type,
        artifact_class=artifact_class,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )


def _qualification_case(
    root: Path,
    *,
    rejection_marker: bytes = b"EDAGYM_RTL_SIMULATION_REJECTED\n",
) -> _QualificationCase:
    definition = backend_by_id("iverilog")
    capability = Capability.RTL_SIMULATION
    fixture = fixture_for(definition.tool_id, capability)
    assert fixture is not None
    policy = _artifact_policy()
    store = ContentAddressedStore(root / "cas", policy=policy)
    executable_digest = _digest("iverilog-executable")
    closure_digest = _digest("iverilog-closure")
    version_digest = _digest("iverilog-version")
    attestation = deployment_attestation_digest(
        tool_id=definition.tool_id,
        driver_digest=definition.driver_digest,
        deployment_record_digest=None,
        tool_version="1.0",
        executable_digest=executable_digest,
        execution_closure_digest_value=closure_digest,
        version_output_digest=version_digest,
        modulefile_digest=None,
        invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
    )
    probe = BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.INVOCABLE,
        tool_version="1.0",
        deployment_attestation_digest=attestation,
        host_support_mode=definition.host_support_mode,
        driver_digest=definition.driver_digest,
    )
    evidence = tuple(
        _qualification_evidence(
            definition,
            fixture,
            probe,
            store,
            role,
            marker=(
                b"EDAGYM_RTL_SIMULATION_ACCEPTED\n"
                if role is FixtureRole.ACCEPTANCE
                else rejection_marker
            ),
            executable_digest=executable_digest,
            closure_digest=closure_digest,
            version_digest=version_digest,
            attestation=attestation,
        )
        for role in FixtureRole
    )
    qualification = BackendQualification(
        probe=probe,
        requested_capabilities=(capability,),
        evidence=evidence,
        disposition=QualificationDisposition.CONFORMANT,
    )
    environment = EnvironmentSpec(
        identity=EnvironmentIdentity(
            environment_id="qualification_verification",
            authoring_revision=1,
        ),
        executor=BrokeredHostToolExecutor(
            executor_id="qualification_broker",
            implementation_digest=_digest("executor"),
            broker_id="qualification_broker",
            broker_digest=_digest("broker"),
            participant_image_digest=_digest("participant-image"),
        ),
        tool_bindings=(
            ToolBinding(
                capability=capability,
                tool_id=definition.tool_id,
                tool_version="1.0",
                driver_id="iverilog_driver",
                driver_digest=definition.driver_digest,
                locator=AttestedHostToolLocator(
                    executable="iverilog",
                    deployment_attestation_digest=attestation,
                ),
            ),
        ),
        filesystem=FilesystemPolicy(
            workspace_target="/workspace",
            artifact_target="/artifacts",
        ),
        network=NoNetwork(),
        resources=_LIMITS,
        checkpoint=CheckpointCapability.NONE,
        artifact_policy=policy,
    )
    return _QualificationCase(definition, qualification, environment, store)


def _dut_output(role: FixtureRole, left: int, right: int) -> int:
    """Model the role's device under test: the adder or its subtractor mutant."""

    if role is FixtureRole.ACCEPTANCE:
        return left + right
    return (left - right) & 0x1F


def _simulation_files(fixture: QualificationFixture, role: FixtureRole) -> dict[str, bytes]:
    """Reproduce the event trace and waveform the testbench writes for one role."""

    parser = fixture.parser
    assert isinstance(parser, RtlTraceWaveformParser)
    rows = tuple(
        (index, left, right, _dut_output(role, left, right), left + right)
        for index, (left, right) in enumerate(_VECTOR_SCHEDULE)
    )
    trace = "".join(" ".join(str(field) for field in row) + "\n" for row in rows)
    waveform = ["$timescale 1s $end", "$scope module tb $end"]
    waveform.extend(
        f"$var {kind} {width} {code} {name} [{width - 1}:0] $end"
        for name, kind, width, code in _WAVEFORM_SIGNALS
    )
    waveform.extend(("$upscope $end", "$enddefinitions $end"))
    previous: dict[str, int] = {}
    for index, left, right, output, _expected in rows:
        waveform.append(f"#{index}")
        if index == 0:
            waveform.append("$dumpvars")
        for (_name, _kind, _width, code), value in zip(
            _WAVEFORM_SIGNALS,
            (left, right, output),
            strict=True,
        ):
            if previous.get(code) != value:
                waveform.append(f"b{value:b} {code}")
                previous[code] = value
        if index == 0:
            waveform.append("$end")
    # The testbench finishes one time unit after applying the last vector.
    waveform.append(f"#{len(rows)}")
    return {
        parser.trace_path: trace.encode("ascii"),
        parser.waveform_path: "".join(f"{line}\n" for line in waveform).encode("ascii"),
    }


def _qualification_evidence(
    definition: BackendDefinition,
    fixture: QualificationFixture,
    probe: BackendProbe,
    store: ContentAddressedStore,
    role: FixtureRole,
    *,
    marker: bytes,
    executable_digest: str,
    closure_digest: str,
    version_digest: str,
    attestation: str,
) -> QualificationEvidence:
    snapshot = fixture.snapshot_for(role)
    inputs = tuple(
        _record(store, _DISCLOSURE, item.logical_id, declaration.content, item.media_type)
        for item, declaration in zip(
            snapshot.inputs,
            fixture.inputs_for(role),
            strict=True,
        )
    )
    simulation_run = len(fixture.invocations) - 1
    outputs = [
        _record(
            store,
            _DISCLOSURE,
            qualification_artifact_id(
                snapshot.fixture_id,
                f"command_{index}_{stream}",
            ),
            marker if (index, stream) == (simulation_run, "stdout") else b"",
            "text/plain",
        )
        for index in range(len(fixture.invocations))
        for stream in ("stdout", "stderr")
    ]
    files = _simulation_files(fixture, role)
    outputs.extend(
        _record(
            store,
            _DISCLOSURE,
            output.logical_id,
            files.get(output.path, _SIMULATION_PROGRAM),
            output.media_type,
        )
        for output in snapshot.outputs
    )
    return QualificationEvidence(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capability=fixture.capability,
        role=role,
        fixture=snapshot,
        fixture_pair_digest=fixture.digest,
        driver_digest=definition.driver_digest,
        backend_probe_digest=canonical_digest(probe, domain="backend-probe-v1"),
        tool_version="1.0",
        executable_digest=executable_digest,
        execution_closure_digest=closure_digest,
        version_output_digest=version_digest,
        executable_invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
        deployment_attestation_digest=attestation,
        artifact_policy_digest=store.policy_digest,
        resource_grant=_RESOURCE_GRANT,
        input_artifacts=inputs,
        output_artifacts=tuple(outputs),
        exit_codes=snapshot.expected_exit_codes,
        outcome=QualificationOutcome.PASSED,
        semantic_rejection_reason=(
            fixture.rejection_reason if role is FixtureRole.REJECTION else None
        ),
        recorded_at=datetime(2026, 9, 4, tzinfo=UTC),
    )


def test_live_evidence_source_reopens_exact_store_and_replays_both_roles(
    tmp_path: Path,
) -> None:
    case = _qualification_case(tmp_path)

    verified = verify_backend_qualification_source(
        case.qualification,
        definition=case.definition,
        environment=case.environment,
        artifact_store=case.store,
    )

    assert verified.qualification is case.qualification
    assert verified.source_kind is QualificationSourceKind.EVIDENCE_PAIR
    assert verified.artifact_closure_digest is not None
    assert verified.artifact_store is case.store
    with pytest.raises(TypeError, match="immutable"):
        verified._source_digest = _digest("forged")
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(verified)
    with pytest.raises(TypeError, match="issued only"):
        VerifiedBackendQualificationSource(
            case.qualification,
            source_kind=QualificationSourceKind.EVIDENCE_PAIR,
            artifact_closure_digest=_digest("closure"),
            artifact_store=case.store,
            source_digest=_digest("source"),
            _issuer=object(),
        )


def test_live_evidence_source_rejects_extra_blobs_and_semantic_cross_wiring(
    tmp_path: Path,
) -> None:
    extra_case = _qualification_case(tmp_path / "extra")
    extra_case.store.put_bytes(
        b"unbound",
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=_DISCLOSURE.sensitivity,
        visibility=_DISCLOSURE.visibility,
        redistribution=_DISCLOSURE.redistribution,
    )
    with pytest.raises(QualificationSourceVerificationError, match="missing, extra"):
        verify_backend_qualification_source(
            extra_case.qualification,
            definition=extra_case.definition,
            environment=extra_case.environment,
            artifact_store=extra_case.store,
        )

    cross_wired = _qualification_case(
        tmp_path / "cross-wired",
        rejection_marker=b"EDAGYM_RTL_SIMULATION_ACCEPTED\n",
    )
    with pytest.raises(QualificationSourceVerificationError, match="do not reproduce"):
        verify_backend_qualification_source(
            cross_wired.qualification,
            definition=cross_wired.definition,
            environment=cross_wired.environment,
            artifact_store=cross_wired.store,
        )


def test_live_evidence_source_rejects_environment_resource_drift(tmp_path: Path) -> None:
    case = _qualification_case(tmp_path)
    drifted_limits = _LIMITS.model_copy(
        update={"memory_bytes": _LIMITS.memory_bytes * 2}
    )
    drifted_environment = case.environment.model_copy(
        update={"resources": drifted_limits}
    )

    with pytest.raises(QualificationSourceVerificationError, match="resource or artifact"):
        verify_backend_qualification_source(
            case.qualification,
            definition=case.definition,
            environment=drifted_environment,
            artifact_store=case.store,
        )


def test_gap_source_requires_a_matching_live_probe_without_cas() -> None:
    definition = backend_by_id("achronix_ace")
    probe, installation = probe_backend(definition)
    assert installation is None
    qualification = BackendQualification(
        probe=probe,
        requested_capabilities=(Capability.FPGA_IMPLEMENTATION,),
        gaps=(
            CapabilityGap(
                capability=Capability.FPGA_IMPLEMENTATION,
                reason=QualificationGapReason.PROBE_NOT_INVOCABLE,
            ),
        ),
        disposition=QualificationDisposition.UNAVAILABLE,
    )

    verified = verify_backend_qualification_source(
        qualification,
        definition=definition,
    )

    assert verified.source_kind is QualificationSourceKind.LIVE_PROBE_GAP
    assert verified.artifact_closure_digest is None
    assert verified.artifact_store is None


def test_failed_projected_log_is_rederived_from_encrypted_raw_diagnostic(
    tmp_path: Path,
) -> None:
    fixture = fixture_for("iverilog", Capability.RTL_SIMULATION)
    assert fixture is not None
    projection = MarkerLogProjection(
        (
            b"EDAGYM_RTL_SIMULATION_ACCEPTED",
            b"EDAGYM_RTL_SIMULATION_REJECTED",
        )
    )
    projected_fixture = replace(fixture, log_projection=projection)
    policy = _artifact_policy(PROTECTED_RAW_DISCLOSURE, managed=True)
    store = ContentAddressedStore(
        tmp_path / "cas",
        policy=policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"v" * 32),
    )
    projected_id = qualification_artifact_id(
        projected_fixture.snapshot.fixture_id,
        "command_0_stdout",
    )
    projected = _record(
        store,
        PROTECTED_RAW_DISCLOSURE,
        projected_id,
        b"EDAGYM_RTL_SIMULATION_ACCEPTED\n",
        "text/plain",
    )
    raw = _record(
        store,
        PROTECTED_RAW_DISCLOSURE,
        f"{projected_id}_raw",
        b"private vendor prefix\nEDAGYM_RTL_SIMULATION_ACCEPTED\nprivate suffix\n",
        "text/plain",
        artifact_class=ArtifactClass.DIAGNOSTIC,
    )
    content, raw_projections, _closure = _reopen_exact_artifact_closure(
        (
            _QualificationRecordBinding(FixtureRole.ACCEPTANCE, "output", projected),
            _QualificationRecordBinding(FixtureRole.ACCEPTANCE, "diagnostic", raw),
        ),
        projected_fixture,
        store,
    )

    _verify_projected_log(
        projection,
        projected_id,
        content[(projected.blob.digest, projected.blob.size_bytes)],
        {raw.logical_id: raw},
        raw_projections,
    )
    with pytest.raises(QualificationSourceVerificationError, match="canonical raw projection"):
        _verify_projected_log(
            projection,
            projected_id,
            b"EDAGYM_RTL_SIMULATION_REJECTED\n",
            {raw.logical_id: raw},
            raw_projections,
        )
