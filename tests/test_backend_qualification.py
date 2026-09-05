"""Evidence for semantic parsing, identity binding, and commercial fail-closed behavior."""

from __future__ import annotations

import os
import pickle
import stat
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers import rootless_image, site_container
from edagym.drivers.catalog import backend_by_id
from edagym.drivers.closure import (
    DescriptorExecutionClosure,
    SiteContainerLauncherKind,
    SiteContainerOperatingSystem,
    execution_closure_digest,
    site_container_arguments,
)
from edagym.drivers.deployment import (
    BackendDeploymentConfiguration,
    HostModuleConfiguration,
    load_backend_deployment_configuration,
    load_backend_deployment_registry,
)
from edagym.drivers.fixtures.analog_physical import (
    HspiceMeasureParser,
    IcvDrcParser,
    PegasusDrcParser,
)
from edagym.drivers.fixtures.catalog import QUALIFICATION_FIXTURES, fixture_for
from edagym.drivers.fixtures.model import (
    AbcEquivalenceParser,
    AbcSynthesisParser,
    FixtureAssetInput,
    FixtureObservation,
    FixtureRole,
    JasperCdcStatusParser,
    JasperPropertyStatusParser,
    KlayoutDrcParser,
    MarkerLogProjection,
    MarkerParser,
    MarkerSetParser,
    ObservedFile,
    SemanticRejectionReason,
    SpyglassStatusParser,
    YosysNetlistParser,
    qualification_artifact_id,
)
from edagym.drivers.licensing import (
    CommercialQualificationAuthorizationError,
    CommercialQualificationLicenseBroker,
    HostModuleLicenseProvider,
)
from edagym.drivers.model import (
    BackendDefinition,
    BackendProbe,
    ExecutableInvocationMode,
    HostSupportMode,
    QualificationState,
    UnavailableReason,
    Vendor,
)
from edagym.drivers.probe import (
    AuthorizedBackendResolutionError,
    AuthorizedBackendResolutionReason,
    _inspect_executable,
    _normalize_version_output,
    _trusted_immutable_executable,
    _version_identity,
    _version_label,
    _version_probe_digest,
    deployment_attestation_digest,
    probe_backend,
    resolve_authorized_commercial_backend,
)
from edagym.drivers.qualification import (
    BackendQualification,
    QualificationAssetEvidence,
    QualificationDisposition,
    QualificationEvidence,
    QualificationGapReason,
    QualificationOutcome,
    _privatize_workspace_tree,
    aggregate_backend_qualifications,
    qualify_backend,
    qualify_commercial_backend,
)
from edagym.drivers.qualification_assets import (
    materialize_qualification_assets,
    revalidate_materialized_qualification_assets,
)
from edagym.drivers.qualification_resources import QualificationResourceGrant
from edagym.executors.asset_identity import capture_asset_identity
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.assets import AssetSnapshot
from edagym.executors.licenses import LeaseState, LicenseLease
from edagym.run.artifacts import ContentAddressedStore, EncryptionKey
from edagym.run.model import ArtifactRecord, BlobRef
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    PROTECTED_RAW_DISCLOSURE,
    ArtifactPolicy,
    ArtifactRetentionRule,
    LicenseBinding,
    ManagedEncryption,
    ResourceLimits,
)
from tests.factories import digest

_RECORDED_AT = datetime(2026, 9, 4, tzinfo=UTC)
_RESOURCE_GRANT = QualificationResourceGrant(
    limits=ResourceLimits(
        cpu_millicores=4000,
        memory_bytes=16 * 1024**3,
        pids=512,
        disk_bytes=16 * 1024**3,
        wall_seconds=300,
    ),
    command_timeout_seconds=60,
)


def test_settled_vendor_outputs_are_privatized_without_following_links(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    nested = workspace / "nested"
    nested.mkdir(mode=0o755)
    report = nested / "report.bin"
    report.write_bytes(b"native report")
    report.chmod(0o666)
    executable = workspace / "generated-tool"
    executable.write_bytes(b"binary")
    executable.chmod(0o777)
    external = tmp_path / "external"
    external.write_bytes(b"outside")
    external.chmod(0o644)
    (workspace / "external-link").symlink_to(external)
    descriptor = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        _privatize_workspace_tree(descriptor)
    finally:
        os.close(descriptor)

    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested.stat().st_mode) == 0o700
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert stat.S_IMODE(executable.stat().st_mode) == 0o700
    assert stat.S_IMODE(external.stat().st_mode) == 0o644


def test_vendor_output_privatization_rejects_hard_links(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.write_bytes(b"outside")
    external.chmod(0o644)
    os.link(external, workspace / "linked-output")
    descriptor = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        with pytest.raises(ValueError, match="unsupported file type"):
            _privatize_workspace_tree(descriptor)
    finally:
        os.close(descriptor)

    assert stat.S_IMODE(external.stat().st_mode) == 0o644


def _descriptor_closure(label: str) -> DescriptorExecutionClosure:
    return DescriptorExecutionClosure(entrypoint_digest=digest(label))


class _StubCommercialLicenseProvider:
    def __init__(self, configuration: BackendDeploymentConfiguration) -> None:
        self.provider_id = "test_license_provider"
        self.provider_digest = digest("test-license-provider")
        self.feature_class = "xcelium_simulation"
        self.tool_id = configuration.tool_id
        self.deployment_digest = configuration.deployment_digest
        self.max_checkouts = 1
        self.released = False

    def acquire(self, *, feature_class: str, run_id: str, ttl_seconds: int) -> LicenseLease:
        assert feature_class == self.feature_class
        assert run_id == "commercial_qualification"
        return LicenseLease(
            lease_id="test-lease",
            provider_id=self.provider_id,
            feature_class=self.feature_class,
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            environment={"PATH": "/usr/bin:/bin"},
        )

    def renew(self, lease: LicenseLease, *, ttl_seconds: int) -> LeaseState:
        del ttl_seconds
        return lease.state

    def release(self, lease: LicenseLease) -> LeaseState:
        lease._release()
        self.released = True
        return lease.state


def _host_deployment(
    root: Path,
    tool_id: str,
    module_name: str = "vendor/tool/1",
) -> HostModuleConfiguration:
    deployment = root / f"{tool_id}-deployment.json"
    deployment.write_bytes(
        canonical_bytes(
            {
                "schema_version": 2,
                "deployment_id": "private_test_deployment",
                "bindings": (
                    {
                        "kind": "host_module",
                        "tool_id": tool_id,
                        "module_name": module_name,
                    },
                ),
            }
        )
    )
    deployment.chmod(0o600)
    configuration = load_backend_deployment_configuration(deployment, tool_id)
    assert isinstance(configuration, HostModuleConfiguration)
    return configuration


def _invocable_probe(
    definition: BackendDefinition,
    *,
    tool_version: str,
    executable_digest: str,
    execution_closure_digest_value: str,
    version_output_digest: str,
    modulefile_digest: str | None = None,
    deployment_record_digest: str | None = None,
) -> BackendProbe:
    attestation = deployment_attestation_digest(
        tool_id=definition.tool_id,
        driver_digest=definition.driver_digest,
        deployment_record_digest=deployment_record_digest,
        tool_version=tool_version,
        executable_digest=executable_digest,
        execution_closure_digest_value=execution_closure_digest_value,
        version_output_digest=version_output_digest,
        modulefile_digest=modulefile_digest,
        invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
    )
    return BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.INVOCABLE,
        tool_version=tool_version,
        deployment_attestation_digest=attestation,
        host_support_mode=definition.host_support_mode,
        driver_digest=definition.driver_digest,
    )


def test_host_module_provider_accepts_canonical_run_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "edagym.drivers.licensing._module_environment",
        lambda _module_name: {"PATH": "/usr/bin:/bin"},
    )
    configuration = _host_deployment(tmp_path, "licensed_tool")
    provider = HostModuleLicenseProvider(
        provider_id="host_module_provider",
        feature_class="licensed_feature",
        deployment_configuration=configuration,
        max_checkouts=1,
    )

    lease = provider.acquire(
        feature_class=provider.feature_class,
        run_id=digest("canonical-runtime-run"),
        ttl_seconds=60,
    )

    assert lease.state is LeaseState.ACTIVE
    assert provider.release(lease) is LeaseState.RELEASED


def _evidence_record(
    logical_id: str,
    artifact_digest: str,
    size: int,
    media_type: str,
) -> ArtifactRecord:
    return ArtifactRecord(
        logical_id=logical_id,
        blob=BlobRef(digest=artifact_digest, size_bytes=size),
        media_type=media_type,
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )


def test_firtool_capability_and_fixture_share_one_catalog_identity() -> None:
    definition = backend_by_id("firtool")
    assert definition.capabilities == (Capability.HW_IR_LOWERING,)
    assert len(definition.fixtures) == 1
    fixture = fixture_for("firtool", Capability.HW_IR_LOWERING)
    assert fixture is not None
    assert definition.fixtures[0].fixture_id == fixture.fixture_id


def test_every_fixture_binds_two_roles_to_one_parser_and_invocation() -> None:
    assert QUALIFICATION_FIXTURES
    for fixture in QUALIFICATION_FIXTURES:
        acceptance = fixture.snapshot_for(FixtureRole.ACCEPTANCE)
        rejection = fixture.snapshot_for(FixtureRole.REJECTION)
        assert acceptance.pair_id == rejection.pair_id == fixture.fixture_id
        assert acceptance.parser_digest == rejection.parser_digest
        assert acceptance.invocations == rejection.invocations
        assert tuple((item.path, item.media_type) for item in acceptance.inputs) == tuple(
            (item.path, item.media_type) for item in rejection.inputs
        )
        assert acceptance.role is FixtureRole.ACCEPTANCE
        assert acceptance.rejection_reason is None
        assert rejection.role is FixtureRole.REJECTION
        assert rejection.rejection_reason is fixture.rejection_reason
        assert acceptance.digest != rejection.digest


def test_only_role_bound_nonzero_exit_can_be_a_semantic_rejection() -> None:
    parser = MarkerParser(
        b"ACCEPTED",
        rejection_marker=b"SEMANTIC_REJECTION",
        rejection_reason=SemanticRejectionReason.FUNCTIONAL_MISMATCH,
    )
    failed_process = FixtureObservation(
        exit_codes=(1,),
        stdout=(b"SEMANTIC_REJECTION\n",),
        stderr=(b"",),
        files=(),
    )
    assert parser.rejection(failed_process) is None

    semantic_parser = replace(parser, rejection_exit_code=16)
    semantic_process = replace(failed_process, exit_codes=(16,))
    assert (
        semantic_parser.rejection(semantic_process) is SemanticRejectionReason.FUNCTIONAL_MISMATCH
    )
    assert semantic_parser.rejection(failed_process) is None

    fixture = fixture_for("xcelium", Capability.RTL_SIMULATION)
    assert fixture is not None
    semantic_fixture = replace(
        fixture,
        parser=semantic_parser,
        rejection_exit_code=16,
    )
    assert semantic_fixture.snapshot_for(FixtureRole.ACCEPTANCE).expected_exit_codes == (0,)
    assert semantic_fixture.snapshot_for(FixtureRole.REJECTION).expected_exit_codes == (16,)
    assert semantic_fixture.digest != fixture.digest


def test_vendor_unsupported_host_modes_are_explicit() -> None:
    jasper = backend_by_id("jaspergold")
    vcs = backend_by_id("vcs")
    assert jasper.host_support_mode is HostSupportMode.VENDOR_UNSUPPORTED_OVERRIDE
    assert jasper.version_arguments == ("-allow_unsupported_OS", "-version")
    assert vcs.host_support_mode is HostSupportMode.VENDOR_UNSUPPORTED
    assert vcs.version_arguments == ("-full64", "-ID")


def test_commercial_backend_remains_probe_only_without_workload_support(
    tmp_path: Path,
) -> None:
    definition = backend_by_id("xcelium")
    probe = BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.DETECTED,
        deployment_attestation_digest=digest("xcelium-deployment-metadata"),
        driver_digest=definition.driver_digest,
    )

    result = qualify_backend(
        definition,
        probe,
        None,
        scratch_root=tmp_path,
    )
    assert result.disposition is QualificationDisposition.PROBE_ONLY
    assert not result.evidence
    assert result.gaps[0].reason is QualificationGapReason.LICENSE_AUTHORIZATION_REQUIRED


def test_eula_restricted_backend_never_uses_generic_commercial_authorization(
    tmp_path: Path,
) -> None:
    definition = backend_by_id("achronix_ace")
    configuration = _host_deployment(tmp_path, definition.tool_id)
    probe = BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.DETECTED,
        deployment_attestation_digest=digest("achronix-deployment-metadata"),
        driver_digest=definition.driver_digest,
    )
    result = qualify_backend(definition, probe, None, scratch_root=tmp_path)
    assert result.disposition is QualificationDisposition.UNAVAILABLE
    assert result.gaps[0].reason is QualificationGapReason.EULA_ACCEPTANCE_REQUIRED

    lease = LicenseLease(
        lease_id="eula-restricted-lease",
        provider_id="site_provider",
        feature_class="fpga_implementation",
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        environment={"PATH": "/usr/bin:/bin"},
    )
    with pytest.raises(AuthorizedBackendResolutionError) as error:
        resolve_authorized_commercial_backend(
            definition,
            probe,
            lease,
            deployment_configuration=configuration,
        )
    assert error.value.reason is AuthorizedBackendResolutionReason.EULA_ACCEPTANCE_REQUIRED


def test_site_closure_requirement_is_opaque_and_tool_arguments_stay_out_of_shell() -> None:
    definition = backend_by_id("modus")
    serialized = definition.model_dump_json()
    assert "cadence_modus" not in serialized
    assert "deployment" not in serialized
    assert "MODUS_HOME" not in serialized
    assert "tools/bin" not in serialized
    malicious = '$(touch participant-controlled)\n"; exit 0'
    arguments = site_container_arguments(
        SiteContainerLauncherKind.SITE_WRAPPER,
        SiteContainerOperatingSystem.ALMA_LINUX_8,
        Path("/private/workspace"),
        Path("/private/environment"),
        ("/private/tool", malicious),
    )
    shell_index = arguments.index("-c") + 1
    assert arguments[shell_index] == 'cd "$HOME/work" && exec "$@"'
    assert malicious not in arguments[shell_index]
    assert arguments[-1] == malicious


def test_private_deployment_loader_and_restricted_asset_materialization(
    tmp_path: Path,
) -> None:
    deployment = tmp_path / "deployment.json"
    deployment_payload = canonical_bytes(
        {
            "schema_version": 2,
            "deployment_id": "private_test_deployment",
            "bindings": [
                {
                    "kind": "host_module",
                    "tool_id": "synthetic_site_tool",
                    "module_name": "vendor/tool/1",
                }
            ],
        }
    )
    deployment.write_bytes(deployment_payload)
    deployment.chmod(0o600)
    registry = load_backend_deployment_registry(deployment)
    assert registry.tool_ids == ("synthetic_site_tool",)
    assert registry.configuration_for("unconfigured_tool") is None
    assert "vendor/tool/1" not in repr(registry)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(registry)
    configuration = registry.configuration_for("synthetic_site_tool")
    assert isinstance(configuration, HostModuleConfiguration)
    assert "vendor/tool/1" not in repr(configuration)
    assert configuration.revalidate()
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(configuration)
    deployment.write_bytes(deployment_payload + b"\n")
    assert not configuration.revalidate()
    deployment.chmod(0o640)
    assert not configuration.revalidate()
    with pytest.raises(ValueError, match="owner-only"):
        load_backend_deployment_configuration(deployment, "synthetic_site_tool")

    source = tmp_path / "restricted.lib"
    source.write_bytes(b"restricted library bytes\n")
    source.chmod(0o600)
    captured = capture_asset_identity(source)
    snapshot = AssetSnapshot(
        path=captured.path,
        restricted_digest=captured.restricted_digest,
        root_identity=captured.root_identity,
        source_policy=load_system_asset_source_policy(),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    declaration = FixtureAssetInput(
        logical_id="cell_library",
        path="inputs/cells.lib",
        asset_id="synthetic_cell_library",
    )
    snapshots = {declaration.asset_id: snapshot}
    materialized = materialize_qualification_assets(
        workspace,
        (declaration,),
        snapshots,
    )
    assert revalidate_materialized_qualification_assets(materialized, snapshots, workspace)
    materialized[0].target.write_bytes(b"changed\n")
    assert not revalidate_materialized_qualification_assets(materialized, snapshots, workspace)


def test_private_deployment_rejects_a_broad_site_mount(tmp_path: Path) -> None:
    image_digest = digest("synthetic-image")
    trusted_owner_uid = 1 if os.getuid() != 1 else 2
    deployment = tmp_path / "deployment.json"
    deployment.write_bytes(
        canonical_bytes(
            {
                "schema_version": 2,
                "deployment_id": "private_test_deployment",
                "bindings": [
                    {
                        "kind": "site_container",
                        "tool_id": "synthetic_site_tool",
                        "module_name": "vendor/tool/1",
                        "requirement_id": "synthetic_site_tool_closure",
                        "operating_system": "almalinux8",
                        "launcher_kind": "podman",
                        "launcher": "/usr/bin/true",
                        "image_inspector": "/usr/bin/true",
                        "image_reference": f"test.invalid/image@{image_digest}",
                        "image_digest": image_digest,
                        "container_user": "tester",
                        "trusted_owner_uid": trusted_owner_uid,
                        "readonly_mounts": [{"source": "/usr", "target": "/usr"}],
                        "root_environment_variable": "SYNTHETIC_TOOL_ROOT",
                        "entrypoint_relative_path": "bin/tool",
                        "components": [
                            {
                                "role": "support_file",
                                "relative_path": "share/support.dat",
                            }
                        ],
                        "tool_environment_names": [],
                        "environment_bindings": [],
                    }
                ],
            }
        )
    )
    deployment.chmod(0o600)
    with pytest.raises(ValueError, match="deployment mounts require absolute path pairs"):
        load_backend_deployment_configuration(deployment, "synthetic_site_tool")


def test_release_qualification_aggregation_requires_one_exact_probe_and_partition(
    tmp_path: Path,
) -> None:
    definition = backend_by_id("openroad")
    probe = BackendProbe(
        tool_id=definition.tool_id,
        vendor=definition.vendor,
        capabilities=definition.capabilities,
        state=QualificationState.UNAVAILABLE,
        host_support_mode=definition.host_support_mode,
        driver_digest=definition.driver_digest,
        reason=UnavailableReason.EXECUTABLE_UNAVAILABLE,
    )
    midpoint = len(definition.capabilities) // 2
    first = qualify_backend(
        definition,
        probe,
        None,
        scratch_root=tmp_path,
        capabilities=definition.capabilities[:midpoint],
    )
    second = qualify_backend(
        definition,
        probe,
        None,
        scratch_root=tmp_path,
        capabilities=definition.capabilities[midpoint:],
    )

    aggregate = aggregate_backend_qualifications(definition, (first, second))
    assert aggregate.requested_capabilities == definition.capabilities
    assert {gap.capability for gap in aggregate.gaps} == set(definition.capabilities)
    with pytest.raises(ValueError, match="partitions must be disjoint"):
        aggregate_backend_qualifications(definition, (first, first, second))


def test_commercial_probe_never_runs_the_tool_version_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    definition = BackendDefinition(
        tool_id="commercial_metadata_probe",
        vendor=Vendor.CADENCE,
        capabilities=(Capability.RTL_SIMULATION,),
        executable_candidates=("false",),
        version_arguments=("--this-command-must-not-run",),
    )
    configuration = _host_deployment(tmp_path, definition.tool_id)
    monkeypatch.setattr("edagym.drivers.probe._module_available", lambda _name: True)
    monkeypatch.setattr(
        "edagym.drivers.probe._module_show",
        lambda _name: b"private module metadata",
    )
    probe, installation = probe_backend(
        definition,
        deployment_configuration=configuration,
    )
    assert probe.state is QualificationState.DETECTED
    assert probe.tool_version is None
    assert probe.deployment_attestation_digest is not None
    assert installation is None


def test_probe_identity_does_not_inherit_ambient_account_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = BackendDefinition(
        tool_id="account_independent_probe",
        vendor=Vendor.OPEN_SOURCE,
        capabilities=(Capability.FORMAL_PROPERTY,),
        executable_candidates=("python3",),
        version_arguments=("--version",),
    )
    monkeypatch.setenv("USER", "ambient_account_a")
    first, _ = probe_backend(definition)
    monkeypatch.setenv("USER", "ambient_account_b")
    second, _ = probe_backend(definition)
    assert first.state is QualificationState.INVOCABLE
    assert second == first


def test_commercial_authorization_is_exact_opaque_and_single_use(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    definition = backend_by_id("xcelium")
    fixture = fixture_for("xcelium", Capability.RTL_SIMULATION)
    assert fixture is not None
    configuration = _host_deployment(tmp_path, definition.tool_id)
    monkeypatch.setattr("edagym.drivers.probe._module_available", lambda _name: True)
    monkeypatch.setattr(
        "edagym.drivers.probe._module_show",
        lambda _name: b"metadata-only-module",
    )
    metadata_probe, installation = probe_backend(
        definition,
        deployment_configuration=configuration,
    )
    assert metadata_probe.state is QualificationState.DETECTED
    assert installation is None
    provider = _StubCommercialLicenseProvider(configuration)
    binding = LicenseBinding(
        license_binding_id="xcelium_qualification_license",
        provider_id=provider.provider_id,
        provider_digest=provider.provider_digest,
        feature_class=provider.feature_class,
        max_checkouts=provider.max_checkouts,
        lease_ttl_seconds=300,
    )
    broker = CommercialQualificationLicenseBroker(
        binding=binding,
        provider=provider,
        deployment_configuration=configuration,
    )
    altered_fixture = replace(
        fixture,
        inputs=(
            replace(fixture.inputs[0], content=b"module dut; endmodule\n"),
            *fixture.inputs[1:],
        ),
    )
    with pytest.raises(
        CommercialQualificationAuthorizationError,
        match="canonical backend fixture",
    ):
        broker.authorize(
            definition=definition,
            metadata_probe=metadata_probe,
            fixture=altered_fixture,
            run_id="commercial_qualification",
            max_execution_seconds=120,
        )

    authorization = broker.authorize(
        definition=definition,
        metadata_probe=metadata_probe,
        fixture=fixture,
        run_id="commercial_qualification",
        max_execution_seconds=120,
    )
    assert repr(authorization) == "CommercialQualificationAuthorization(<opaque>)"
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(authorization)

    disclosure = PROTECTED_RAW_DISCLOSURE
    artifact_policy = ArtifactPolicy(
        quota_bytes=64 * 1024**2,
        encryption=ManagedEncryption(
            provider_id="test_encryption_provider",
            policy_digest=digest("test-encryption-policy"),
        ),
        rules=tuple(
            ArtifactRetentionRule(
                artifact_class=artifact_class,
                retention_seconds=60,
                allowed_disclosures=(disclosure,),
            )
            for artifact_class in ArtifactClass
        ),
    )
    store = ContentAddressedStore(
        tmp_path / "cas",
        policy=artifact_policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"q" * 32),
    )
    result = qualify_commercial_backend(
        definition,
        metadata_probe,
        authorization,
        scratch_root=tmp_path,
        artifact_store=store,
        artifact_disclosure=disclosure,
        resource_grant=_RESOURCE_GRANT,
        deployment_configuration=configuration,
    )
    assert result.disposition is QualificationDisposition.INCOMPLETE
    assert result.gaps[0].reason is QualificationGapReason.AUTHORIZED_EXECUTABLE_UNAVAILABLE
    assert provider.released
    with pytest.raises(CommercialQualificationAuthorizationError, match="closed"):
        qualify_commercial_backend(
            definition,
            metadata_probe,
            authorization,
            scratch_root=tmp_path,
            artifact_store=store,
            artifact_disclosure=disclosure,
            resource_grant=_RESOURCE_GRANT,
            deployment_configuration=configuration,
        )

    invalid_authorization = broker.authorize(
        definition=definition,
        metadata_probe=metadata_probe,
        fixture=fixture,
        run_id="commercial_qualification",
        max_execution_seconds=120,
    )
    provider.released = False
    with pytest.raises(
        CommercialQualificationAuthorizationError,
        match="exceeds its authorized execution time",
    ):
        qualify_commercial_backend(
            definition,
            metadata_probe,
            invalid_authorization,
            scratch_root=tmp_path,
            artifact_store=store,
            artifact_disclosure=disclosure,
            resource_grant=_RESOURCE_GRANT.model_copy(
                update={"command_timeout_seconds": 61}
            ),
            deployment_configuration=configuration,
        )
    assert provider.released


def test_marker_log_projection_never_retains_surrounding_diagnostics() -> None:
    marker = b"EDAGYM_XCELIUM_RTL_SIMULATION_PASS"
    projection = MarkerLogProjection((marker,))
    retained = projection.project(
        (
            b"license-path-before\nEDAGYM_XCELIUM_",
            b"RTL_SIMULATION_PASS hostid-after\n",
        )
    )
    assert retained == marker + b"\n"
    assert b"license-path-before" not in retained
    assert b"hostid-after" not in retained


def test_trusted_path_fallback_rejects_user_owned_executables(tmp_path: Path) -> None:
    executable = tmp_path / "self-locating-tool"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o555)
    assert _trusted_immutable_executable(executable) is None


def test_trusted_path_preserves_an_immutable_dispatch_name() -> None:
    dispatch_path = Path("/bin/sh")
    if not dispatch_path.exists():
        pytest.skip("host has no immutable shell dispatch path")
    assert _trusted_immutable_executable(dispatch_path) == dispatch_path


def test_version_label_discards_banner_decoration() -> None:
    assert (
        _version_label(b"******\n** ngspice-47 : Circuit level simulation program\n")
        == "ngspice-47 : Circuit level simulation program"
    )


def test_version_exit_status_is_enforced_across_execution_transports(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    arguments = ("-c", "print('Version: 1.2'); raise SystemExit(1)")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    for accepted, expected in (((0,), None), ((0, 1), b"Version: 1.2\n")):
        inspected = _inspect_executable(
            executable,
            arguments,
            environment,
            None,
            accepted_exit_codes=accepted,
        )
        assert (None if inspected is None else inspected[0]) == expected
        for transport in (rootless_image, site_container):
            assert transport._run_bounded(
                executable,
                arguments,
                environment,
                tmp_path,
                accepted_exit_codes=accepted,
            ) == expected


def test_version_probe_normalizes_only_its_standalone_process_identity() -> None:
    assert _normalize_version_output(b"pid=1234 build=12345 child 1234\n", 1234) == (
        b"pid=PROCESS_ID build=12345 child PROCESS_ID\n"
    )


def test_projected_version_probe_excludes_runtime_banner_fields() -> None:
    definition = backend_by_id("pegasus")
    first = (
        b"Pegasus 25.13-s012 stable/BUILD 2026-09-04 09:23:00 1234 host-a\nruntime diagnostics a\n"
    )
    second = (
        b"Pegasus 25.13-s012 stable/BUILD 2026-09-05 10:24:01 5678 host-b\nruntime diagnostics b\n"
    )
    first_identity = _version_identity(first, definition.version_identity_pattern)
    second_identity = _version_identity(second, definition.version_identity_pattern)
    assert first_identity == second_identity == b"Pegasus 25.13-s012 stable/BUILD"
    assert first_identity is not None

    arguments = {
        "executable_name": "pegasus",
        "executable_digest": digest("pegasus-executable"),
        "module_name": "cadence/PEGASUS/251",
        "modulefile_digest": digest("pegasus-modulefile"),
        "version_label": "251",
        "execution_closure_digest": digest("pegasus-closure"),
    }
    assert _version_probe_digest(
        definition,
        version_identity=first_identity,
        **arguments,
    ) == _version_probe_digest(
        definition,
        version_identity=second_identity,
        **arguments,
    )
    changed_identity = _version_identity(
        second.replace(b"25.13-s012", b"25.13-s013"),
        definition.version_identity_pattern,
    )
    assert changed_identity is not None
    assert _version_probe_digest(
        definition,
        version_identity=first_identity,
        **arguments,
    ) != _version_probe_digest(
        definition,
        version_identity=changed_identity,
        **arguments,
    )


def test_vitis_version_probe_binds_only_the_stable_product_version() -> None:
    definition = backend_by_id("vitis_hls")
    first = (
        b"**** Start of session at: Fri Sep 04 12:00:01 2026\n"
        b"****** vitis-run v2026.1 (64-bit)\n"
    )
    second = first.replace(b"12:00:01", b"12:00:59")
    changed = first.replace(b"v2026.1", b"v2026.2")
    first_identity = _version_identity(first, definition.version_identity_pattern)
    second_identity = _version_identity(second, definition.version_identity_pattern)
    changed_identity = _version_identity(changed, definition.version_identity_pattern)
    assert first_identity == second_identity == b"****** vitis-run v2026.1 (64-bit)"
    assert changed_identity == b"****** vitis-run v2026.2 (64-bit)"


def test_commercial_evidence_cannot_exist_without_an_authorization_receipt() -> None:
    definition = backend_by_id("xcelium")
    fixture = fixture_for("xcelium", Capability.RTL_SIMULATION)
    assert fixture is not None
    snapshot = fixture.snapshot
    inputs = tuple(
        _evidence_record(item.logical_id, item.digest, item.size_bytes, item.media_type)
        for item in snapshot.inputs
    )
    outputs = tuple(
        _evidence_record(
            qualification_artifact_id(snapshot.fixture_id, f"command_0_{stream}"),
            digest(stream),
            0,
            "text/plain",
        )
        for stream in ("stdout", "stderr")
    )
    evidence_attestation = deployment_attestation_digest(
        tool_id=definition.tool_id,
        driver_digest=definition.driver_digest,
        deployment_record_digest=digest("xcelium-deployment"),
        tool_version="2603",
        executable_digest=digest("xrun"),
        execution_closure_digest_value=digest("xcelium-closure"),
        version_output_digest=digest("xcelium-version"),
        modulefile_digest=digest("xcelium-module"),
        invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
    )
    with pytest.raises(ValidationError, match="explicit authorization identity"):
        QualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capability=Capability.RTL_SIMULATION,
            role=FixtureRole.ACCEPTANCE,
            fixture=snapshot,
            fixture_pair_digest=fixture.digest,
            driver_digest=definition.driver_digest,
            backend_probe_digest=digest("xcelium-probe"),
            tool_version="2603",
            executable_digest=digest("xrun"),
            execution_closure_digest=digest("xcelium-closure"),
            executable_invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
            deployment_attestation_digest=evidence_attestation,
            deployment_record_digest=digest("xcelium-deployment"),
            modulefile_digest=digest("xcelium-module"),
            version_output_digest=digest("xcelium-version"),
            artifact_policy_digest=digest("artifact-policy"),
            resource_grant=_RESOURCE_GRANT,
            input_artifacts=inputs,
            output_artifacts=outputs,
            exit_codes=(0,),
            outcome=QualificationOutcome.PASSED,
            recorded_at=_RECORDED_AT,
        )


def test_yosys_parser_requires_semantic_netlist_content() -> None:
    parser = YosysNetlistParser(
        marker=b"QUALIFICATION_PASS",
        output_path="synth.json",
        module_name="dut",
    )
    marker_only = FixtureObservation(
        exit_codes=(0,),
        stdout=(b"QUALIFICATION_PASS\n",),
        stderr=(b"",),
        files=(
            ObservedFile(
                path="synth.json",
                content=b'{"modules":{"dut":{"cells":{}}}}',
                size_bytes=32,
                truncated=False,
            ),
        ),
    )
    semantic_netlist = FixtureObservation(
        exit_codes=(0,),
        stdout=(b"QUALIFICATION_PASS\n",),
        stderr=(b"",),
        files=(
            ObservedFile(
                path="synth.json",
                content=b'{"modules":{"dut":{"cells":{"adder":{"type":"$add"}}}}}',
                size_bytes=58,
                truncated=False,
            ),
        ),
    )
    assert not parser.accepts(marker_only)
    assert parser.rejection(marker_only) is SemanticRejectionReason.DEGENERATE_IMPLEMENTATION
    assert parser.accepts(semantic_netlist)
    assert parser.rejection(semantic_netlist) is None


def test_abc_parsers_require_a_network_and_an_equivalence_result() -> None:
    synthesis = AbcSynthesisParser(
        marker=b"ABC_SYNTHESIS_PASS",
        output_path="synthesized.blif",
        model_name="dut",
    )
    empty_network = FixtureObservation(
        exit_codes=(0,),
        stdout=(b"ABC_SYNTHESIS_PASS\n",),
        stderr=(b"",),
        files=(
            ObservedFile(
                path="synthesized.blif",
                content=b".model dut\n.inputs a\n.outputs y\n.end\n",
                size_bytes=40,
                truncated=False,
            ),
        ),
    )
    semantic_network = replace(
        empty_network,
        files=(
            replace(
                empty_network.files[0],
                content=b".model dut\n.inputs a\n.outputs y\n.names a y\n1 1\n.end\n",
                size_bytes=55,
            ),
        ),
    )
    equivalence = AbcEquivalenceParser(
        marker=b"ABC_EQUIVALENCE_PASS",
        equivalence_token=b"Networks are equivalent.",
    )
    mismatch = FixtureObservation(
        exit_codes=(0,),
        stdout=(b"Networks are NOT EQUIVALENT.\nABC_EQUIVALENCE_PASS\n",),
        stderr=(b"",),
        files=(),
    )
    equivalent = replace(
        mismatch,
        stdout=(b"Networks are equivalent.\nABC_EQUIVALENCE_PASS\n",),
    )
    assert not synthesis.accepts(empty_network)
    assert synthesis.accepts(semantic_network)
    assert not equivalence.accepts(mismatch)
    assert equivalence.rejection(mismatch) is SemanticRejectionReason.EQUIVALENCE_MISMATCH
    assert equivalence.accepts(equivalent)


def test_vendor_status_parsers_require_semantic_success_markers() -> None:
    jasper_property = JasperPropertyStatusParser(
        property_name="formal_probe.ap_check",
        expected_status=b"proven",
    )
    jasper_cdc = JasperCdcStatusParser(
        expected_violation_count=0,
        pass_marker=b"EDAGYM_CDC_PASS",
    )
    spyglass = SpyglassStatusParser(
        status_marker=(b"SpyGlass Exit Code 0 (Rule-checking completed without errors or warnings)")
    )
    spectre = MarkerSetParser((b"EDAGYM_SPECTRE_DIVIDER_PASS", b"spectre completes with 0 errors"))

    def observation(*lines: bytes, exit_code: int = 0) -> FixtureObservation:
        return FixtureObservation(
            exit_codes=(exit_code,),
            stdout=(b"\n".join(lines),),
            stderr=(b"",),
            files=(),
        )

    assert jasper_property.accepts(
        observation(b"EDAGYM_JASPER_PROPERTY_STATUS formal_probe.ap_check proven")
    )
    assert not jasper_property.accepts(
        observation(b"EDAGYM_JASPER_PROPERTY_STATUS formal_probe.ap_check cex")
    )
    assert (
        jasper_property.rejection(
            observation(b"EDAGYM_JASPER_PROPERTY_STATUS formal_probe.ap_check cex")
        )
        is SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE
    )
    assert jasper_cdc.accepts(observation(b"EDAGYM_CDC_VIOLATION_COUNT 0", b"EDAGYM_CDC_PASS"))
    cdc_violation = observation(
        b"EDAGYM_CDC_VIOLATION_COUNT 1",
        b"EDAGYM_CDC_PASS",
    )
    assert not jasper_cdc.accepts(cdc_violation)
    assert jasper_cdc.rejection(cdc_violation) is SemanticRejectionReason.RULE_VIOLATION
    assert spyglass.accepts(
        observation(b"SpyGlass Exit Code 0 (Rule-checking completed without errors or warnings)")
    )
    assert not spyglass.accepts(
        observation(b"SpyGlass Exit Code 0 (Rule-checking completed with errors)")
    )
    assert spectre.accepts(
        observation(
            b"EDAGYM_SPECTRE_DIVIDER_PASS",
            b"spectre completes with 0 errors",
        )
    )
    assert not spectre.accepts(observation(b"EDAGYM_SPECTRE_DIVIDER_PASS"))


def test_klayout_parser_requires_a_typed_rule_result() -> None:
    parser = KlayoutDrcParser(output_path="drc-report.json", rule_id="minimum_spacing")

    def observation(violation_count: int) -> FixtureObservation:
        content = (
            b'{"engine":"klayout.db","engine_version":"0.30.12",'
            b'"minimum_spacing_nm":100,"rule_id":"minimum_spacing",'
            b'"violation_count":' + str(violation_count).encode("ascii") + b"}"
        )
        return FixtureObservation(
            exit_codes=(0,),
            stdout=(b"",),
            stderr=(b"",),
            files=(
                ObservedFile(
                    path="drc-report.json",
                    content=content,
                    size_bytes=len(content),
                    truncated=False,
                ),
            ),
        )

    assert parser.accepts(observation(0))
    violation = observation(1)
    assert not parser.accepts(violation)
    assert parser.rejection(violation) is SemanticRejectionReason.RULE_VIOLATION


def test_hspice_parser_classifies_a_native_numeric_measurement() -> None:
    parser = HspiceMeasureParser(
        output_path="divider.ms0",
        measure_name="divider_voltage",
        expected_microvolts=500_000,
        tolerance_microvolts=1_000,
    )

    def observation(value: bytes, *, exit_code: int = 0) -> FixtureObservation:
        content = (
            b"$DATA1 SOURCE='PrimeSim HSPICE' VERSION='Y-2026.03-SP1 linux64' "
            b"PARAM_COUNT=0\n"
            b".TITLE '* edagym hspice divider qualification'\n"
            b" divider_voltage  temper  alter#\n    " + value + b"  25.0000  1\n"
        )
        return FixtureObservation(
            exit_codes=(exit_code,),
            stdout=(b"hspice job concluded\n",),
            stderr=(b"",),
            files=(
                ObservedFile(
                    path="divider.ms0",
                    content=content,
                    size_bytes=len(content),
                    truncated=False,
                ),
            ),
        )

    assert parser.accepts(observation(b"0.5000"))
    mismatch = observation(b"0.3333")
    assert not parser.accepts(mismatch)
    assert parser.rejection(mismatch) is SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE
    assert parser.rejection(observation(b"0.3333", exit_code=1)) is None


def test_icv_parser_requires_one_completed_rule_and_typed_violations() -> None:
    parser = IcvDrcParser(output_path="TOP.RESULTS", expected_rule_count=1)

    def observation(violations: int, *, exit_code: int = 0) -> FixtureObservation:
        clean = violations == 0
        report = (
            (b"RESULTS: CLEAN\n" if clean else b"RESULTS: NOT CLEAN\n")
            + b"1 total rule was run.\n"
            + b"0 rules NOT EXECUTED.\n"
            + (b"0 rules have violations.\n" if clean else b"1 rule has violations.\n")
            + (
                b"There are 0 total violations.\n"
                if clean
                else f"There is {violations} total violation.\n".encode("ascii")
            )
            + b"IC Validator is done.\n"
        )
        return FixtureObservation(
            exit_codes=(exit_code,),
            stdout=(b"",),
            stderr=(b"IC Validator is done.\n",),
            files=(
                ObservedFile(
                    path="TOP.RESULTS",
                    content=report,
                    size_bytes=len(report),
                    truncated=False,
                ),
            ),
        )

    assert parser.accepts(observation(0))
    violation = observation(1)
    assert not parser.accepts(violation)
    assert parser.rejection(violation) is SemanticRejectionReason.RULE_VIOLATION
    assert parser.rejection(observation(1, exit_code=1)) is None


def test_pegasus_parser_requires_consistent_native_drc_counts() -> None:
    parser = PegasusDrcParser(
        output_path="run/DRC.rep",
        rule_name="M1_SPACING",
        expected_geometry_count=2,
        expected_rule_count=1,
    )

    def observation(rule_results: int, total_results: int) -> FixtureObservation:
        report = (
            b"RULECHECK M1_SPACING ............... Total Result          "
            + str(rule_results).encode("ascii")
            + b" (         "
            + str(rule_results).encode("ascii")
            + b")\nTotal Original Geometry           : 2 (2)\n"
            + b"Total DRC RuleChecks              : 1\nTotal DRC Results                 : "
            + str(total_results).encode("ascii")
            + b" ("
            + str(total_results).encode("ascii")
            + b")\n"
        )
        return FixtureObservation(
            exit_codes=(0,),
            stdout=(b"Pegasus finished normally.\n",),
            stderr=(b"",),
            files=(
                ObservedFile(
                    path="run/DRC.rep",
                    content=report,
                    size_bytes=len(report),
                    truncated=False,
                ),
            ),
        )

    assert parser.accepts(observation(0, 0))
    violation = observation(1, 1)
    assert not parser.accepts(violation)
    assert parser.rejection(violation) is SemanticRejectionReason.RULE_VIOLATION
    assert parser.rejection(observation(1, 0)) is None


def test_passing_evidence_cannot_omit_fixture_inputs_or_invocations() -> None:
    definition = backend_by_id("iverilog")
    fixture = fixture_for("iverilog", Capability.RTL_SIMULATION)
    assert fixture is not None
    snapshot = fixture.snapshot
    first_input = snapshot.inputs[0]
    partial_inputs = (
        _evidence_record(
            first_input.logical_id,
            first_input.digest,
            first_input.size_bytes,
            first_input.media_type,
        ),
    )
    outputs_list = [
        _evidence_record(
            qualification_artifact_id(
                snapshot.fixture_id,
                f"command_{index}_{stream}",
            ),
            digest(f"command-{index}-{stream}"),
            0,
            "text/plain",
        )
        for index in range(2)
        for stream in ("stdout", "stderr")
    ]
    outputs_list.append(
        _evidence_record(
            snapshot.outputs[0].logical_id,
            digest("simulation-binary"),
            1,
            "application/octet-stream",
        )
    )
    outputs = tuple(outputs_list)
    evidence_attestation = deployment_attestation_digest(
        tool_id=definition.tool_id,
        driver_digest=definition.driver_digest,
        deployment_record_digest=None,
        tool_version="13.0",
        executable_digest=digest("executable"),
        execution_closure_digest_value=digest("iverilog-closure"),
        version_output_digest=digest("version"),
        modulefile_digest=digest("module"),
        invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
    )
    with pytest.raises(ValidationError, match="every canonical fixture input"):
        QualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capability=Capability.RTL_SIMULATION,
            role=FixtureRole.ACCEPTANCE,
            fixture=snapshot,
            fixture_pair_digest=fixture.digest,
            driver_digest=definition.driver_digest,
            backend_probe_digest=digest("probe"),
            tool_version="13.0",
            executable_digest=digest("executable"),
            execution_closure_digest=digest("iverilog-closure"),
            executable_invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
            version_output_digest=digest("version"),
            deployment_attestation_digest=evidence_attestation,
            modulefile_digest=digest("module"),
            artifact_policy_digest=digest("artifact-policy"),
            resource_grant=_RESOURCE_GRANT,
            input_artifacts=partial_inputs,
            output_artifacts=outputs,
            exit_codes=(0,),
            outcome=QualificationOutcome.PASSED,
            recorded_at=_RECORDED_AT,
        )


def test_imported_qualification_must_bind_the_exact_probe() -> None:
    definition = backend_by_id("firtool")
    fixture = fixture_for("firtool", Capability.HW_IR_LOWERING)
    assert fixture is not None
    closure = _descriptor_closure("firtool-executable")
    executable_digest = digest("firtool-executable")
    version_output_digest = digest("firtool-version")
    modulefile_digest = digest("firtool-modulefile")
    closure_digest = execution_closure_digest(closure)
    probe = _invocable_probe(
        definition,
        tool_version="1.157.0",
        executable_digest=executable_digest,
        execution_closure_digest_value=closure_digest,
        version_output_digest=version_output_digest,
        modulefile_digest=modulefile_digest,
    )
    deployment_attestation = probe.deployment_attestation_digest
    assert deployment_attestation is not None

    def forged_evidence(role: FixtureRole) -> QualificationEvidence:
        snapshot = fixture.snapshot_for(role)
        input_records = tuple(
            _evidence_record(item.logical_id, item.digest, item.size_bytes, item.media_type)
            for item in snapshot.inputs
        )
        output_records = (
            _evidence_record(
                qualification_artifact_id(snapshot.fixture_id, "command_0_stdout"),
                digest(f"{role.value}-stdout"),
                1,
                "text/plain",
            ),
            _evidence_record(
                qualification_artifact_id(snapshot.fixture_id, "command_0_stderr"),
                digest(f"{role.value}-stderr"),
                0,
                "text/plain",
            ),
            _evidence_record(
                snapshot.outputs[0].logical_id,
                digest(f"{role.value}-lowered-rtl"),
                1,
                "text/x-systemverilog",
            ),
        )
        return QualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capability=Capability.HW_IR_LOWERING,
            role=role,
            fixture=snapshot,
            fixture_pair_digest=fixture.digest,
            driver_digest=definition.driver_digest,
            backend_probe_digest=digest("wrong-probe"),
            tool_version="1.157.0",
            executable_digest=executable_digest,
            execution_closure_digest=closure_digest,
            executable_invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
            version_output_digest=version_output_digest,
            deployment_attestation_digest=deployment_attestation,
            modulefile_digest=modulefile_digest,
            artifact_policy_digest=digest("artifact-policy"),
            resource_grant=_RESOURCE_GRANT,
            input_artifacts=input_records,
            output_artifacts=output_records,
            exit_codes=(0,),
            outcome=QualificationOutcome.PASSED,
            semantic_rejection_reason=(
                SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE
                if role is FixtureRole.REJECTION
                else None
            ),
            recorded_at=_RECORDED_AT,
        )

    acceptance = forged_evidence(FixtureRole.ACCEPTANCE)
    with pytest.raises(ValidationError, match="both roles"):
        BackendQualification(
            probe=probe,
            requested_capabilities=(Capability.HW_IR_LOWERING,),
            evidence=(acceptance,),
            disposition=QualificationDisposition.CONFORMANT,
        )
    with pytest.raises(ValidationError, match="bind the assessed probe"):
        BackendQualification(
            probe=probe,
            requested_capabilities=(Capability.HW_IR_LOWERING,),
            evidence=tuple(forged_evidence(role) for role in FixtureRole),
            disposition=QualificationDisposition.CONFORMANT,
        )
    probe_digest = canonical_digest(probe, domain="backend-probe-v1")
    exact_pair = tuple(
        forged_evidence(role).model_copy(update={"backend_probe_digest": probe_digest})
        for role in FixtureRole
    )
    weakened_acceptance = exact_pair[0].model_copy(
        update={
            "fixture": exact_pair[0].fixture.model_copy(
                update={"parser_digest": digest("weakened-parser")}
            )
        }
    )
    with pytest.raises(ValidationError, match="canonical fixture"):
        BackendQualification(
            probe=probe,
            requested_capabilities=(Capability.HW_IR_LOWERING,),
            evidence=(weakened_acceptance, exact_pair[1]),
            disposition=QualificationDisposition.CONFORMANT,
        )


def test_asset_backed_roles_share_topology_but_bind_one_restricted_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = backend_by_id("firtool")
    canonical_fixture = fixture_for("firtool", Capability.HW_IR_LOWERING)
    assert canonical_fixture is not None
    fixture = replace(
        canonical_fixture,
        restricted_assets=(
            FixtureAssetInput(
                logical_id="technology_library",
                path="inputs/technology.lib",
                asset_id="synthetic_technology_library",
            ),
        ),
    )
    monkeypatch.setattr(
        "edagym.drivers.qualification.fixture_for",
        lambda tool_id, capability: (
            fixture
            if tool_id == definition.tool_id and capability is fixture.capability
            else None
        ),
    )
    closure = _descriptor_closure("firtool-asset-executable")
    closure_digest = execution_closure_digest(closure)
    version_output_digest = digest("firtool-asset-version")
    probe = _invocable_probe(
        definition,
        tool_version="1.157.0",
        executable_digest=closure.entrypoint_digest,
        execution_closure_digest_value=closure_digest,
        version_output_digest=version_output_digest,
    )
    deployment_attestation = probe.deployment_attestation_digest
    assert deployment_attestation is not None
    probe_digest = canonical_digest(probe, domain="backend-probe-v1")

    def role_evidence(role: FixtureRole) -> QualificationEvidence:
        snapshot = fixture.snapshot_for(role)
        inputs = tuple(
            _evidence_record(item.logical_id, item.digest, item.size_bytes, item.media_type)
            for item in snapshot.inputs
        )
        logs = tuple(
            _evidence_record(
                qualification_artifact_id(
                    snapshot.fixture_id,
                    f"command_{index}_{stream}",
                ),
                digest(f"asset-{role.value}-{index}-{stream}"),
                0,
                "text/plain",
            )
            for index in range(len(snapshot.invocations))
            for stream in ("stdout", "stderr")
        )
        outputs = tuple(
            _evidence_record(
                item.logical_id,
                digest(f"asset-{role.value}-{item.logical_id}"),
                1,
                item.media_type,
            )
            for item in snapshot.outputs
            if item.required
        )
        asset = snapshot.restricted_assets[0]
        return QualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capability=fixture.capability,
            role=role,
            fixture=snapshot,
            fixture_pair_digest=fixture.digest,
            driver_digest=definition.driver_digest,
            backend_probe_digest=probe_digest,
            tool_version="1.157.0",
            executable_digest=closure.entrypoint_digest,
            execution_closure_digest=closure_digest,
            version_output_digest=version_output_digest,
            executable_invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
            deployment_attestation_digest=deployment_attestation,
            artifact_policy_digest=digest("asset-artifact-policy"),
            resource_grant=_RESOURCE_GRANT,
            input_artifacts=inputs,
            restricted_assets=(
                QualificationAssetEvidence(
                    logical_id=asset.logical_id,
                    asset_id=asset.asset_id,
                    path=asset.path,
                    restricted_digest=digest("technology-library-content"),
                    media_type=asset.media_type,
                ),
            ),
            output_artifacts=logs + outputs,
            exit_codes=snapshot.expected_exit_codes,
            outcome=QualificationOutcome.PASSED,
            semantic_rejection_reason=(
                fixture.rejection_reason if role is FixtureRole.REJECTION else None
            ),
            recorded_at=_RECORDED_AT,
        )

    acceptance, rejection = tuple(role_evidence(role) for role in FixtureRole)
    assert acceptance.restricted_assets[0].logical_id != rejection.restricted_assets[0].logical_id
    qualification = BackendQualification(
        probe=probe,
        requested_capabilities=(fixture.capability,),
        evidence=(acceptance, rejection),
        disposition=QualificationDisposition.CONFORMANT,
    )
    assert qualification.disposition is QualificationDisposition.CONFORMANT

    changed_asset = rejection.restricted_assets[0].model_copy(
        update={"restricted_digest": digest("different-technology-library-content")}
    )
    changed_rejection = rejection.model_copy(update={"restricted_assets": (changed_asset,)})
    with pytest.raises(ValidationError, match="semantic joint"):
        BackendQualification(
            probe=probe,
            requested_capabilities=(fixture.capability,),
            evidence=(acceptance, changed_rejection),
            disposition=QualificationDisposition.CONFORMANT,
        )


def test_qualification_rejects_evidence_outside_its_requested_capabilities() -> None:
    definition = backend_by_id("verilator")
    closure = _descriptor_closure("verilator-executable")
    executable_digest = digest("verilator-executable")
    version_output_digest = digest("verilator-version")
    modulefile_digest = digest("verilator-modulefile")
    closure_digest = execution_closure_digest(closure)
    probe = _invocable_probe(
        definition,
        tool_version="5.050",
        executable_digest=executable_digest,
        execution_closure_digest_value=closure_digest,
        version_output_digest=version_output_digest,
        modulefile_digest=modulefile_digest,
    )
    probe_digest = canonical_digest(probe, domain="backend-probe-v1")
    tool_version = probe.tool_version
    deployment_attestation = probe.deployment_attestation_digest
    assert tool_version is not None
    assert deployment_attestation is not None

    def passing_evidence(
        capability: Capability,
        role: FixtureRole,
    ) -> QualificationEvidence:
        fixture = fixture_for(definition.tool_id, capability)
        assert fixture is not None
        snapshot = fixture.snapshot_for(role)
        inputs = tuple(
            _evidence_record(item.logical_id, item.digest, item.size_bytes, item.media_type)
            for item in snapshot.inputs
        )
        logs = tuple(
            _evidence_record(
                qualification_artifact_id(
                    snapshot.fixture_id,
                    f"command_{index}_{stream}",
                ),
                digest(f"{capability.value}-{role.value}-{index}-{stream}"),
                0,
                "text/plain",
            )
            for index in range(len(snapshot.invocations))
            for stream in ("stdout", "stderr")
        )
        outputs = tuple(
            _evidence_record(
                item.logical_id,
                digest(f"{capability.value}-{role.value}-{item.logical_id}"),
                1,
                item.media_type,
            )
            for item in snapshot.outputs
            if item.required
        )
        return QualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capability=capability,
            role=role,
            fixture=snapshot,
            fixture_pair_digest=fixture.digest,
            driver_digest=definition.driver_digest,
            backend_probe_digest=probe_digest,
            tool_version=tool_version,
            executable_digest=executable_digest,
            execution_closure_digest=closure_digest,
            executable_invocation_mode=ExecutableInvocationMode.DESCRIPTOR_BOUND,
            version_output_digest=version_output_digest,
            deployment_attestation_digest=deployment_attestation,
            modulefile_digest=modulefile_digest,
            artifact_policy_digest=digest("artifact-policy"),
            resource_grant=_RESOURCE_GRANT,
            input_artifacts=inputs,
            output_artifacts=logs + outputs,
            exit_codes=(0,) * len(snapshot.invocations),
            outcome=QualificationOutcome.PASSED,
            semantic_rejection_reason=(
                fixture.rejection_reason if role is FixtureRole.REJECTION else None
            ),
            recorded_at=_RECORDED_AT,
        )

    evidence = (
        *(passing_evidence(Capability.RTL_SIMULATION, role) for role in FixtureRole),
        passing_evidence(Capability.RTL_LINT, FixtureRole.ACCEPTANCE),
    )
    with pytest.raises(ValidationError, match="unrequested capability"):
        BackendQualification(
            probe=probe,
            requested_capabilities=(Capability.RTL_SIMULATION,),
            evidence=evidence,
            disposition=QualificationDisposition.CONFORMANT,
        )
