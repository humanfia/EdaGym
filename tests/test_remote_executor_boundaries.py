"""Security evidence for VM and remote execution-provider boundaries."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.capabilities import (
    ExecutorCapability,
    ExecutorProviderKind,
    LocalContainmentCapability,
    MicrovmAttestation,
    ProviderAvailability,
    ProviderFeature,
    ProviderTrustBoundary,
    ProviderUnavailableReason,
    RuntimeEvidence,
    SignedMicrovmAttestation,
    probe_libvirt_kvm,
    probe_local_containment,
    probe_slurm_apptainer,
    verify_microvm_attestation,
)
from edagym.executors.licenses import LicenseLease
from edagym.executors.local import ExecutorUnavailable, UnknownJob
from edagym.executors.model import (
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
)
from edagym.executors.vm import (
    HostResourceGrant,
    LibvirtVmExecutor,
    VmIsolationCleanup,
    VmResourceKind,
)
from edagym.specs.common import Capability
from edagym.specs.environment import (
    CheckpointCapability,
    EnvironmentIdentity,
    EnvironmentSpec,
    FilesystemPolicy,
    FilesystemScope,
    VmPerRunExecutor,
)
from tests.factories import digest, environment_spec


def _libvirt_capability(*, snapshot: bool = False) -> ExecutorCapability:
    features = (
        ProviderFeature.GUEST_CONTROL_CHANNEL,
        ProviderFeature.HARDWARE_VIRTUALIZATION,
        ProviderFeature.IMMUTABLE_BASE_IMAGE,
        ProviderFeature.PER_RUN_MACHINE,
    )
    return ExecutorCapability(
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        kind=ExecutorProviderKind.LIBVIRT_KVM,
        availability=ProviderAvailability.AVAILABLE,
        trust_boundary=ProviderTrustBoundary.HARDWARE_VM,
        features=((*features, ProviderFeature.VM_SNAPSHOT) if snapshot else features),
        runtimes=(
            RuntimeEvidence(
                command="virsh",
                version="11.10.0",
                executable_digest=digest("virsh-executable"),
                version_output_digest=digest("virsh-version"),
            ),
        ),
        control_plane_probe_digest=digest("libvirt-control-plane"),
        snapshot_policy_digest=(digest("vm-snapshot-policy") if snapshot else None),
    )


def _vm_environment(
    checkpoint: CheckpointCapability = CheckpointCapability.NONE,
) -> EnvironmentSpec:
    baseline = environment_spec()
    image_digest = digest("sealed-vm-image")
    return EnvironmentSpec(
        identity=EnvironmentIdentity(environment_id="vm_test", authoring_revision=1),
        executor=VmPerRunExecutor(
            executor_id="libvirt_vm",
            implementation_digest=digest("libvirt-executor"),
            provider_id="local_libvirt",
            provider_digest=digest("local-libvirt-provider"),
            image_digest=image_digest,
        ),
        tool_bindings=tuple(
            binding.model_copy(
                update={
                    "locator": binding.locator.model_copy(
                        update={"image_digest": image_digest}
                    )
                }
            )
            for binding in baseline.tool_bindings
        ),
        filesystem=FilesystemPolicy(
            workspace_target="/workspace",
            artifact_target="/artifacts",
        ),
        resources=baseline.resources,
        checkpoint=checkpoint,
        artifact_policy=baseline.artifact_policy,
    )


def _invocation() -> InvocationPlan:
    baseline = environment_spec()
    tool = next(
        binding
        for binding in baseline.tool_bindings
        if binding.capability is Capability.RTL_SIMULATION
    )
    return InvocationPlan(
        invocation_id="vm_probe",
        run_id=digest("vm-probe-run"),
        capability=tool.capability,
        tool_id=tool.tool_id,
        driver_digest=tool.driver_digest,
        view=InvocationView.PARTICIPANT,
        executable=tool.locator.executable,
        input_manifest_digest=digest("vm-input"),
    )


def _vm_directories(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    workspace_root = tmp_path / "vm-workspaces"
    artifact_root = tmp_path / "vm-artifacts"
    workspace_root.mkdir(mode=0o700, exist_ok=True)
    artifact_root.mkdir(mode=0o700, exist_ok=True)
    workspace = workspace_root / _invocation().invocation_id
    artifacts = artifact_root / _invocation().invocation_id
    workspace.mkdir(mode=0o700, exist_ok=True)
    artifacts.mkdir(mode=0o700, exist_ok=True)
    return workspace_root, artifact_root, workspace, artifacts


class _GrantInspectingBroker:
    def __init__(self, capability_digest: str, forbidden_path: Path) -> None:
        self._capability_digest = capability_digest
        self._forbidden_path = os.fspath(forbidden_path)
        self.seen_descriptors: tuple[int, int] | None = None

    @property
    def capability_digest(self) -> str:
        return self._capability_digest

    def launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        scope: FilesystemScope,
        workspace: HostResourceGrant,
        artifact_directory: HostResourceGrant,
        assets: Mapping[str, HostResourceGrant],
        license_lease: LicenseLease | None,
    ) -> JobHandle:
        assert scope is FilesystemScope.PARTICIPANT
        assert workspace.guest_target == environment.filesystem.workspace_target
        assert artifact_directory.guest_target == environment.filesystem.artifact_target
        assert self._forbidden_path not in repr(workspace)
        assert self._forbidden_path not in repr(artifact_directory)
        assert not assets
        assert license_lease is None
        descriptors = (workspace.fileno(), artifact_directory.fileno())
        os.fstat(descriptors[0])
        os.fstat(descriptors[1])
        self.seen_descriptors = descriptors
        return JobHandle(
            job_id=plan.invocation_id,
            invocation_digest=plan.digest,
            executor_id="libvirt_vm",
        )

    def inspect(self, handle: JobHandle) -> JobState:
        raise AssertionError(handle)

    def cancel(self, handle: JobHandle) -> JobState:
        raise AssertionError(handle)

    def collect(self, handle: JobHandle) -> ExecutionResult:
        raise AssertionError(handle)

    def abandon(self, invocation_id: str) -> VmIsolationCleanup:
        return VmIsolationCleanup(
            invocation_id=invocation_id,
            lifecycle_fence_digest=digest(f"cleanup-fence-{invocation_id}"),
        )


class _DurableCleanupBroker(_GrantInspectingBroker):
    def __init__(
        self,
        capability_digest: str,
        forbidden_path: Path,
        state_path: Path,
    ) -> None:
        super().__init__(capability_digest, forbidden_path)
        self._state_path = state_path

    def launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        scope: FilesystemScope,
        workspace: HostResourceGrant,
        artifact_directory: HostResourceGrant,
        assets: Mapping[str, HostResourceGrant],
        license_lease: LicenseLease | None,
    ) -> JobHandle:
        if self._state_path.exists():
            phase, owner, _ = self._state_path.read_text().strip().split(":", 2)
            if phase == "fenced" and owner == plan.invocation_id:
                raise ExecutorUnavailable("VM invocation is durably fenced")
        handle = super().launch(
            plan,
            environment=environment,
            scope=scope,
            workspace=workspace,
            artifact_directory=artifact_directory,
            assets=assets,
            license_lease=license_lease,
        )
        self._state_path.write_text(
            f"active:{plan.invocation_id}:machine,writable_layer,guest_control_channel\n"
        )
        self._state_path.chmod(0o600)
        return handle

    def abandon(self, invocation_id: str) -> VmIsolationCleanup:
        resources: tuple[VmResourceKind, ...] = ()
        if self._state_path.exists():
            phase, owner, encoded = self._state_path.read_text().strip().split(":", 2)
            if phase == "active" and owner == invocation_id and encoded:
                resources = tuple(VmResourceKind(item) for item in encoded.split(","))
        self._state_path.write_text(f"fenced:{invocation_id}:\n")
        self._state_path.chmod(0o600)
        assert not resources or set(resources) == set(VmResourceKind)
        return VmIsolationCleanup(
            invocation_id=invocation_id,
            lifecycle_fence_digest=digest(f"cleanup-fence-{invocation_id}"),
        )

    def delayed_commit(self, invocation_id: str) -> bool:
        phase, owner, _ = self._state_path.read_text().strip().split(":", 2)
        if phase == "fenced" and owner == invocation_id:
            return False
        self._state_path.write_text(
            f"active:{invocation_id}:machine,writable_layer,guest_control_channel\n"
        )
        self._state_path.chmod(0o600)
        return True


class _IncompleteCleanupBroker(_GrantInspectingBroker):
    def abandon(self, invocation_id: str) -> VmIsolationCleanup:
        return VmIsolationCleanup(
            invocation_id=invocation_id,
            lifecycle_fence_digest=digest(f"incomplete-fence-{invocation_id}"),
            remaining_resources=(VmResourceKind.MACHINE,),
        )


def test_libvirt_boundary_uses_opaque_scoped_descriptors(tmp_path: Path) -> None:
    capability = _libvirt_capability()
    broker = _GrantInspectingBroker(capability.digest, tmp_path)
    workspace_root, artifact_root, workspace, artifacts = _vm_directories(tmp_path)
    executor = LibvirtVmExecutor(
        executor_id="libvirt_vm",
        implementation_digest=digest("libvirt-executor"),
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        capability=capability,
        broker=broker,
        asset_source_policy=load_system_asset_source_policy(),
        workspace_root=workspace_root,
        artifact_root=artifact_root,
    )
    handle = executor.launch(
        _invocation(),
        environment=_vm_environment(),
        workspace=workspace,
        artifact_directory=artifacts,
        asset_paths={},
        scope=FilesystemScope.PARTICIPANT,
    )
    assert handle.job_id == _invocation().invocation_id
    assert broker.seen_descriptors is not None
    for descriptor in broker.seen_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_libvirt_snapshot_claim_fails_without_a_snapshot_lifecycle(tmp_path: Path) -> None:
    capability = _libvirt_capability(snapshot=True)
    workspace_root, artifact_root, workspace, artifacts = _vm_directories(tmp_path)
    executor = LibvirtVmExecutor(
        executor_id="libvirt_vm",
        implementation_digest=digest("libvirt-executor"),
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        capability=capability,
        broker=_GrantInspectingBroker(capability.digest, tmp_path),
        asset_source_policy=load_system_asset_source_policy(),
        workspace_root=workspace_root,
        artifact_root=artifact_root,
    )

    with pytest.raises(ExecutorUnavailable, match="lifecycle is not implemented"):
        executor.launch(
            _invocation(),
            environment=_vm_environment(CheckpointCapability.VIRTUAL_MACHINE),
            workspace=workspace,
            artifact_directory=artifacts,
            asset_paths={},
            scope=FilesystemScope.PARTICIPANT,
        )


def test_libvirt_cleanup_survives_controller_reconstruction(tmp_path: Path) -> None:
    capability = _libvirt_capability()
    state_path = tmp_path / "durable-control-plane-state"
    workspace_root, artifact_root, workspace, artifacts = _vm_directories(tmp_path)
    broker = _DurableCleanupBroker(capability.digest, tmp_path, state_path)
    executor = LibvirtVmExecutor(
        executor_id="libvirt_vm",
        implementation_digest=digest("libvirt-executor"),
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        capability=capability,
        broker=broker,
        asset_source_policy=load_system_asset_source_policy(),
        workspace_root=workspace_root,
        artifact_root=artifact_root,
    )
    handle = executor.launch(
        _invocation(),
        environment=_vm_environment(),
        workspace=workspace,
        artifact_directory=artifacts,
        asset_paths={},
        scope=FilesystemScope.PARTICIPANT,
    )

    reconstructed = LibvirtVmExecutor(
        executor_id="libvirt_vm",
        implementation_digest=digest("libvirt-executor"),
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        capability=capability,
        broker=_DurableCleanupBroker(capability.digest, tmp_path, state_path),
        asset_source_policy=load_system_asset_source_policy(),
        workspace_root=workspace_root,
        artifact_root=artifact_root,
    )
    reconstructed.abandon(_invocation().invocation_id)
    reconstructed.abandon(_invocation().invocation_id)
    assert state_path.read_text() == f"fenced:{_invocation().invocation_id}:\n"
    assert broker.delayed_commit(_invocation().invocation_id) is False
    executor.abandon(_invocation().invocation_id)
    with pytest.raises(UnknownJob, match="fenced VM invocation"):
        executor.inspect(handle)
    newly_reconstructed = LibvirtVmExecutor(
        executor_id="libvirt_vm",
        implementation_digest=digest("libvirt-executor"),
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        capability=capability,
        broker=_DurableCleanupBroker(capability.digest, tmp_path, state_path),
        asset_source_policy=load_system_asset_source_policy(),
        workspace_root=workspace_root,
        artifact_root=artifact_root,
    )
    with pytest.raises(ExecutorUnavailable, match="launch failed after fenced cleanup"):
        newly_reconstructed.launch(
            _invocation(),
            environment=_vm_environment(),
            workspace=workspace,
            artifact_directory=artifacts,
            asset_paths={},
            scope=FilesystemScope.PARTICIPANT,
        )


def test_libvirt_cleanup_fails_closed_when_a_resource_remains(tmp_path: Path) -> None:
    capability = _libvirt_capability()
    workspace_root, artifact_root, _, _ = _vm_directories(tmp_path)
    executor = LibvirtVmExecutor(
        executor_id="libvirt_vm",
        implementation_digest=digest("libvirt-executor"),
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        capability=capability,
        broker=_IncompleteCleanupBroker(capability.digest, tmp_path),
        asset_source_policy=load_system_asset_source_policy(),
        workspace_root=workspace_root,
        artifact_root=artifact_root,
    )
    with pytest.raises(ExecutorUnavailable, match="complete isolation cleanup"):
        executor.abandon(_invocation().invocation_id)


def test_remote_provider_probes_fail_closed_without_private_path_disclosure(
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private-control-plane" / "missing"
    libvirt = probe_libvirt_kvm(
        provider_id="local_libvirt",
        provider_digest=digest("local-libvirt-provider"),
        guest_control_digest=digest("guest-control"),
        immutable_image_digest=digest("image-policy"),
        virsh_path=private_path,
    )
    slurm = probe_slurm_apptainer(
        provider_id="batch_cluster",
        provider_digest=digest("batch-provider"),
        site_policy_digest=digest("batch-policy"),
        sbatch_path=private_path,
    )
    assert libvirt.reason is ProviderUnavailableReason.EXECUTABLE_UNAVAILABLE
    assert slurm.reason is ProviderUnavailableReason.EXECUTABLE_UNAVAILABLE
    assert os.fspath(private_path) not in libvirt.model_dump_json()
    assert os.fspath(private_path) not in slurm.model_dump_json()
    workspace_root, artifact_root, _, _ = _vm_directories(tmp_path)
    with pytest.raises(ExecutorUnavailable):
        LibvirtVmExecutor(
            executor_id="libvirt_vm",
            implementation_digest=digest("libvirt-executor"),
            provider_id="local_libvirt",
            provider_digest=digest("local-libvirt-provider"),
            capability=libvirt,
            broker=_GrantInspectingBroker(libvirt.digest, tmp_path),
            asset_source_policy=load_system_asset_source_policy(),
            workspace_root=workspace_root,
            artifact_root=artifact_root,
        )


def test_local_containment_probe_rejects_untrusted_supervisors(tmp_path: Path) -> None:
    untrusted = tmp_path / "systemctl"
    untrusted.write_text("#!/bin/sh\nexit 0\n")
    untrusted.chmod(0o700)
    capability = probe_local_containment(systemctl_path=untrusted)
    assert capability.reason is ProviderUnavailableReason.EXECUTABLE_UNTRUSTED
    assert os.fspath(untrusted) not in capability.model_dump_json()


def test_local_containment_capability_requires_complete_runtime_evidence() -> None:
    with pytest.raises(ValueError, match="all trusted supervisors"):
        LocalContainmentCapability(
            availability=ProviderAvailability.AVAILABLE,
            runtimes=(),
            control_plane_probe_digest=digest("local-user-manager"),
        )


def test_microvm_attestation_requires_valid_signature_and_lifetime() -> None:
    private_key = Ed25519PrivateKey.generate()
    statement = MicrovmAttestation(
        provider_id="remote_microvm",
        provider_digest=digest("remote-microvm-provider"),
        issued_at_epoch_seconds=1_000,
        expires_at_epoch_seconds=2_000,
        features=(
            ProviderFeature.GUEST_CONTROL_CHANNEL,
            ProviderFeature.HARDWARE_VIRTUALIZATION,
            ProviderFeature.HOST_NETWORK_ALLOWLIST,
            ProviderFeature.IMMUTABLE_BASE_IMAGE,
            ProviderFeature.PER_RUN_MACHINE,
        ),
        control_plane_revision_digest=digest("microvm-control-plane"),
        network_enforcer_digest=digest("microvm-network-policy"),
    )
    signature = private_key.sign(statement.signing_bytes).hex()
    signed = SignedMicrovmAttestation(
        statement=statement,
        key_id="microvm_attestation_key",
        signature_hex=signature,
    )
    trusted_keys = {
        "microvm_attestation_key": private_key.public_key().public_bytes_raw(),
    }
    valid = verify_microvm_attestation(
        signed,
        trusted_public_keys=trusted_keys,
        now_epoch_seconds=1_500,
    )
    expired = verify_microvm_attestation(
        signed,
        trusted_public_keys=trusted_keys,
        now_epoch_seconds=2_000,
    )
    invalid = verify_microvm_attestation(
        signed.model_copy(
            update={"signature_hex": ("0" if signature[0] != "0" else "1") + signature[1:]}
        ),
        trusted_public_keys=trusted_keys,
        now_epoch_seconds=1_500,
    )
    assert valid.availability is ProviderAvailability.AVAILABLE
    assert expired.reason is ProviderUnavailableReason.ATTESTATION_EXPIRED
    assert invalid.reason is ProviderUnavailableReason.ATTESTATION_INVALID
