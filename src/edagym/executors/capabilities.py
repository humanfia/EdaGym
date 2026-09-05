"""Fail-closed capability evidence for non-local execution providers."""

from __future__ import annotations

import fcntl
import hashlib
import os
import pwd
import stat
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    Field,
    StrictInt,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel

_PROBE_OUTPUT_LIMIT = 1024 * 1024
_PROBE_TIMEOUT_SECONDS = 20
_CLEAN_PATH = "/usr/local/bin:/usr/bin:/bin"
_DIGEST_ADAPTER = TypeAdapter(Digest)
LOCAL_SYSTEMCTL_PATH = Path("/usr/bin/systemctl")
LOCAL_SYSTEMD_RUN_PATH = Path("/usr/bin/systemd-run")
LOCAL_ENV_PATH = Path("/usr/bin/env")
DEFAULT_PYTHON_PATH = Path(sys.executable).resolve()
_KVM_GET_API_VERSION = 0xAE00
_KVM_API_VERSION = 12


class ExecutorProviderKind(StrEnum):
    LIBVIRT_KVM = "libvirt_kvm"
    SLURM_APPTAINER = "slurm_apptainer"
    MICROVM = "microvm"


class ProviderAvailability(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class ProviderTrustBoundary(StrEnum):
    HARDWARE_VM = "hardware_vm"
    ROOTLESS_USER_NAMESPACE = "rootless_user_namespace"
    TRUSTED_CLUSTER = "trusted_cluster"


class ProviderFeature(StrEnum):
    AGGREGATE_STORAGE_QUOTA = "aggregate_storage_quota"
    HARDWARE_VIRTUALIZATION = "hardware_virtualization"
    DURABLE_PROCESS_CONTAINMENT = "durable_process_containment"
    PER_RUN_MACHINE = "per_run_machine"
    IMMUTABLE_BASE_IMAGE = "immutable_base_image"
    GUEST_CONTROL_CHANNEL = "guest_control_channel"
    HOST_NETWORK_ALLOWLIST = "host_network_allowlist"
    VM_SNAPSHOT = "vm_snapshot"
    BATCH_ACCOUNTING = "batch_accounting"
    CONTAINER_ENCAPSULATION = "container_encapsulation"


class ProviderUnavailableReason(StrEnum):
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    EXECUTABLE_UNTRUSTED = "executable_untrusted"
    VERSION_PROBE_FAILED = "version_probe_failed"
    ACCELERATION_UNAVAILABLE = "acceleration_unavailable"
    CONTROL_PLANE_UNAVAILABLE = "control_plane_unavailable"
    POLICY_UNATTESTED = "policy_unattested"
    ATTESTATION_INVALID = "attestation_invalid"
    ATTESTATION_EXPIRED = "attestation_expired"


class LibvirtConnection(StrEnum):
    SESSION = "qemu:///session"
    SYSTEM = "qemu:///system"


class RuntimeEvidence(StrictModel):
    command: Identifier
    version: Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[ -~]+$")]
    executable_digest: Digest
    version_output_digest: Digest


class LocalContainmentCapability(StrictModel):
    """Path-free evidence for the durable user-systemd process boundary."""

    schema_version: SchemaVersion = 1
    availability: ProviderAvailability
    runtimes: tuple[RuntimeEvidence, ...] = ()
    control_plane_probe_digest: Digest | None = None
    reason: ProviderUnavailableReason | None = None

    @field_validator("runtimes")
    @classmethod
    def normalize_runtimes(
        cls,
        value: tuple[RuntimeEvidence, ...],
    ) -> tuple[RuntimeEvidence, ...]:
        commands = [runtime.command for runtime in value]
        if len(commands) != len(set(commands)):
            raise ValueError("local containment runtime owners must be unique")
        return tuple(sorted(value, key=lambda runtime: runtime.command))

    @model_validator(mode="after")
    def validate_capability(self) -> Self:
        available = self.availability is ProviderAvailability.AVAILABLE
        if available != (self.reason is None):
            raise ValueError("local containment availability and reason disagree")
        if available != (self.control_plane_probe_digest is not None):
            raise ValueError("available local containment requires user-manager evidence")
        commands = {runtime.command for runtime in self.runtimes}
        expected = {"env", "systemctl", "systemd-run"}
        if available and commands != expected:
            raise ValueError("available local containment requires all trusted supervisors")
        if not commands <= expected:
            raise ValueError("local containment evidence contains an unknown supervisor")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="local-containment-capability-v1")


class RootlessContainerCapability(StrictModel):
    """Path-free proof of one rootless runtime and its local immutable images."""

    schema_version: SchemaVersion = 1
    availability: ProviderAvailability
    containment: LocalContainmentCapability
    runtime: RuntimeEvidence | None = None
    image_digests: tuple[Digest, ...] = ()
    control_plane_probe_digest: Digest | None = None
    reason: ProviderUnavailableReason | None = None

    @field_validator("image_digests")
    @classmethod
    def normalize_image_digests(cls, value: tuple[Digest, ...]) -> tuple[Digest, ...]:
        if len(value) != len(set(value)):
            raise ValueError("rootless image identities must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_capability(self) -> Self:
        available = self.availability is ProviderAvailability.AVAILABLE
        if available != (self.reason is None):
            raise ValueError("rootless availability and reason disagree")
        if available and (
            self.containment.availability is not ProviderAvailability.AVAILABLE
            or self.runtime is None
            or self.runtime.command != "podman"
            or not self.image_digests
            or self.control_plane_probe_digest is None
        ):
            raise ValueError("available rootless execution requires its complete closure")
        if not available and self.control_plane_probe_digest is not None:
            raise ValueError("unavailable rootless execution cannot carry control evidence")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="rootless-container-capability-v1")


_VM_FEATURES = frozenset(
    {
        ProviderFeature.HARDWARE_VIRTUALIZATION,
        ProviderFeature.PER_RUN_MACHINE,
        ProviderFeature.IMMUTABLE_BASE_IMAGE,
        ProviderFeature.GUEST_CONTROL_CHANNEL,
    }
)
_SLURM_FEATURES = frozenset(
    {
        ProviderFeature.BATCH_ACCOUNTING,
        ProviderFeature.CONTAINER_ENCAPSULATION,
    }
)
_MICROVM_FEATURES = _VM_FEATURES | {ProviderFeature.HOST_NETWORK_ALLOWLIST}


class ExecutorCapability(StrictModel):
    """Public, path-free evidence that a provider can enforce its stated profile."""

    schema_version: SchemaVersion = 1
    provider_id: Identifier
    provider_digest: Digest
    kind: ExecutorProviderKind
    availability: ProviderAvailability
    trust_boundary: ProviderTrustBoundary
    features: tuple[ProviderFeature, ...] = ()
    runtimes: tuple[RuntimeEvidence, ...] = ()
    control_plane_probe_digest: Digest | None = None
    network_enforcer_digest: Digest | None = None
    snapshot_policy_digest: Digest | None = None
    reason: ProviderUnavailableReason | None = None

    @field_validator("features")
    @classmethod
    def normalize_features(cls, value: tuple[ProviderFeature, ...]) -> tuple[ProviderFeature, ...]:
        if len(value) != len(set(value)):
            raise ValueError("provider features must be unique")
        return tuple(sorted(value, key=lambda feature: feature.value))

    @field_validator("runtimes")
    @classmethod
    def normalize_runtimes(cls, value: tuple[RuntimeEvidence, ...]) -> tuple[RuntimeEvidence, ...]:
        commands = [runtime.command for runtime in value]
        if len(commands) != len(set(commands)):
            raise ValueError("runtime evidence must have one owner per command")
        return tuple(sorted(value, key=lambda runtime: runtime.command))

    @model_validator(mode="after")
    def validate_capability(self) -> Self:
        available = self.availability is ProviderAvailability.AVAILABLE
        if available != (self.reason is None):
            raise ValueError("provider availability and unavailable reason disagree")
        if available and self.control_plane_probe_digest is None:
            raise ValueError("available providers require control-plane evidence")

        features = frozenset(self.features)
        if (ProviderFeature.HOST_NETWORK_ALLOWLIST in features) != (
            self.network_enforcer_digest is not None
        ):
            raise ValueError("network allowlist support requires its exact policy identity")
        if (ProviderFeature.VM_SNAPSHOT in features) != (self.snapshot_policy_digest is not None):
            raise ValueError("VM snapshot support requires its exact policy identity")
        if self.kind is ExecutorProviderKind.LIBVIRT_KVM:
            if self.trust_boundary is not ProviderTrustBoundary.HARDWARE_VM:
                raise ValueError("libvirt providers require a hardware-VM trust boundary")
            if available and (not features >= _VM_FEATURES or len(self.runtimes) != 1):
                raise ValueError("available libvirt providers require the complete VM profile")
        elif self.kind is ExecutorProviderKind.SLURM_APPTAINER:
            if self.trust_boundary is not ProviderTrustBoundary.TRUSTED_CLUSTER:
                raise ValueError("Slurm providers are trusted-cluster boundaries")
            if available and (not features >= _SLURM_FEATURES or len(self.runtimes) != 7):
                raise ValueError("available Slurm providers require scheduler and runtime evidence")
            if features & _VM_FEATURES:
                raise ValueError("Slurm and Apptainer cannot be represented as a VM boundary")
        else:
            if self.trust_boundary is not ProviderTrustBoundary.HARDWARE_VM:
                raise ValueError("microVM providers require a hardware-VM trust boundary")
            if available and (not features >= _MICROVM_FEATURES or self.runtimes):
                raise ValueError("available microVM providers require a complete attestation")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="executor-capability-v1")


class MicrovmAttestation(StrictModel):
    """Signed, secret-free statement returned by an external microVM control plane."""

    schema_version: SchemaVersion = 1
    provider_id: Identifier
    provider_digest: Digest
    issued_at_epoch_seconds: Annotated[StrictInt, Field(ge=0)]
    expires_at_epoch_seconds: Annotated[StrictInt, Field(gt=0)]
    features: tuple[ProviderFeature, ...]
    control_plane_revision_digest: Digest
    network_enforcer_digest: Digest
    snapshot_policy_digest: Digest | None = None

    @field_validator("features")
    @classmethod
    def normalize_features(cls, value: tuple[ProviderFeature, ...]) -> tuple[ProviderFeature, ...]:
        if len(value) != len(set(value)):
            raise ValueError("attested provider features must be unique")
        return tuple(sorted(value, key=lambda feature: feature.value))

    @model_validator(mode="after")
    def validate_lifetime(self) -> Self:
        if self.expires_at_epoch_seconds <= self.issued_at_epoch_seconds:
            raise ValueError("microVM attestation expiration must follow issuance")
        return self

    @property
    def signing_bytes(self) -> bytes:
        return b"edagym\x00microvm-attestation-v1\x00" + canonical_bytes(self)


class SignedMicrovmAttestation(StrictModel):
    statement: MicrovmAttestation
    key_id: Identifier
    signature_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def probe_local_containment(
    *,
    systemctl_path: Path = LOCAL_SYSTEMCTL_PATH,
    systemd_run_path: Path = LOCAL_SYSTEMD_RUN_PATH,
    env_path: Path = LOCAL_ENV_PATH,
) -> LocalContainmentCapability:
    """Inspect the trusted supervisors and user manager without creating a scope."""

    definitions = (
        (systemctl_path, "systemctl", ("--version",)),
        (systemd_run_path, "systemd-run", ("--version",)),
        (env_path, "env", ("--version",)),
    )
    runtimes: list[RuntimeEvidence] = []
    for path, command, arguments in definitions:
        runtime, failure = _root_runtime_evidence(path, command, arguments)
        if failure is not None:
            return LocalContainmentCapability(
                availability=ProviderAvailability.UNAVAILABLE,
                runtimes=tuple(runtimes),
                reason=failure,
            )
        assert runtime is not None
        runtimes.append(runtime)
    manager_output = _run_user_manager_probe(systemctl_path)
    if manager_output is None or _version_line(manager_output) is None:
        return LocalContainmentCapability(
            availability=ProviderAvailability.UNAVAILABLE,
            runtimes=tuple(runtimes),
            reason=ProviderUnavailableReason.CONTROL_PLANE_UNAVAILABLE,
        )
    return LocalContainmentCapability(
        availability=ProviderAvailability.AVAILABLE,
        runtimes=tuple(runtimes),
        control_plane_probe_digest=canonical_digest(
            {"manager_version_output_digest": _digest_bytes(manager_output)},
            domain="local-user-manager-probe-v1",
        ),
    )


def probe_rootless_container(
    *,
    image_references: Mapping[str, str],
    podman_path: Path = Path("/usr/bin/podman"),
    systemctl_path: Path = LOCAL_SYSTEMCTL_PATH,
    systemd_run_path: Path = LOCAL_SYSTEMD_RUN_PATH,
    env_path: Path = LOCAL_ENV_PATH,
) -> RootlessContainerCapability:
    """Probe exact local OCI identities without pulling or starting a container."""

    containment = probe_local_containment(
        systemctl_path=systemctl_path,
        systemd_run_path=systemd_run_path,
        env_path=env_path,
    )
    if containment.availability is not ProviderAvailability.AVAILABLE:
        return RootlessContainerCapability(
            availability=ProviderAvailability.UNAVAILABLE,
            containment=containment,
            reason=containment.reason,
        )
    runtime, failure = _root_runtime_evidence(
        podman_path,
        "podman",
        ("version", "--format", "{{.Client.Version}}"),
        environment=_rootless_control_environment(),
    )
    if failure is not None:
        return RootlessContainerCapability(
            availability=ProviderAvailability.UNAVAILABLE,
            containment=containment,
            reason=failure,
        )
    assert runtime is not None
    try:
        normalized = {
            _DIGEST_ADAPTER.validate_python(image_digest): reference
            for image_digest, reference in image_references.items()
        }
    except ValidationError:
        normalized = {}
    if (
        not normalized
        or len(normalized) != len(image_references)
        or any(
            not reference.endswith(f"@{image_digest}")
            or any(character in reference for character in "\x00\r\n")
            for image_digest, reference in normalized.items()
        )
    ):
        return RootlessContainerCapability(
            availability=ProviderAvailability.UNAVAILABLE,
            containment=containment,
            runtime=runtime,
            reason=ProviderUnavailableReason.POLICY_UNATTESTED,
        )
    inspections: dict[str, str] = {}
    for image_digest, reference in sorted(normalized.items()):
        output = _run_probe(
            podman_path,
            ("image", "inspect", "--format", "{{.Digest}}", reference),
            environment=_rootless_control_environment(),
        )
        if output is None or output.strip() != image_digest.encode("ascii"):
            return RootlessContainerCapability(
                availability=ProviderAvailability.UNAVAILABLE,
                containment=containment,
                runtime=runtime,
                reason=ProviderUnavailableReason.CONTROL_PLANE_UNAVAILABLE,
            )
        inspections[image_digest] = _digest_bytes(output)
    return RootlessContainerCapability(
        availability=ProviderAvailability.AVAILABLE,
        containment=containment,
        runtime=runtime,
        image_digests=tuple(normalized),
        control_plane_probe_digest=canonical_digest(
            {
                "containment_digest": containment.digest,
                "image_inspection_digests": inspections,
            },
            domain="rootless-container-control-plane-v1",
        ),
    )


def probe_libvirt_kvm(
    *,
    provider_id: str,
    provider_digest: str,
    guest_control_digest: str | None,
    immutable_image_digest: str | None,
    snapshot_policy_digest: str | None = None,
    network_enforcer_digest: str | None = None,
    connection: LibvirtConnection = LibvirtConnection.SESSION,
    virsh_path: Path = Path("/usr/bin/virsh"),
    kvm_path: Path = Path("/dev/kvm"),
) -> ExecutorCapability:
    """Probe a local libvirt/KVM control plane without creating or changing a VM."""

    runtime, failure = _runtime_evidence(virsh_path, "virsh", ("--version",))
    runtimes = () if runtime is None else (runtime,)
    if failure is not None:
        return _unavailable_libvirt(provider_id, provider_digest, runtimes, failure)
    if not _kvm_accessible(kvm_path):
        return _unavailable_libvirt(
            provider_id,
            provider_digest,
            runtimes,
            ProviderUnavailableReason.ACCELERATION_UNAVAILABLE,
        )
    required_policy = (guest_control_digest, immutable_image_digest)
    optional_policy = (snapshot_policy_digest, network_enforcer_digest)
    if any(value is None or not _is_digest(value) for value in required_policy) or any(
        value is not None and not _is_digest(value) for value in optional_policy
    ):
        return _unavailable_libvirt(
            provider_id,
            provider_digest,
            runtimes,
            ProviderUnavailableReason.POLICY_UNATTESTED,
        )
    control_output = _run_probe(
        virsh_path,
        ("-c", connection.value, "domcapabilities"),
        environment=libvirt_control_environment(connection),
    )
    if control_output is None or not _supports_kvm(control_output):
        return _unavailable_libvirt(
            provider_id,
            provider_digest,
            runtimes,
            ProviderUnavailableReason.CONTROL_PLANE_UNAVAILABLE,
        )
    features = set(_VM_FEATURES)
    if snapshot_policy_digest is not None:
        features.add(ProviderFeature.VM_SNAPSHOT)
    if network_enforcer_digest is not None:
        features.add(ProviderFeature.HOST_NETWORK_ALLOWLIST)
    control_digest = canonical_digest(
        {
            "domcapabilities_digest": _digest_bytes(control_output),
            "guest_control_digest": guest_control_digest,
            "immutable_image_digest": immutable_image_digest,
            "snapshot_policy_digest": snapshot_policy_digest,
            "network_enforcer_digest": network_enforcer_digest,
        },
        domain="libvirt-control-plane-probe-v1",
    )
    return ExecutorCapability(
        provider_id=provider_id,
        provider_digest=provider_digest,
        kind=ExecutorProviderKind.LIBVIRT_KVM,
        availability=ProviderAvailability.AVAILABLE,
        trust_boundary=ProviderTrustBoundary.HARDWARE_VM,
        features=tuple(features),
        runtimes=runtimes,
        control_plane_probe_digest=control_digest,
        network_enforcer_digest=network_enforcer_digest,
        snapshot_policy_digest=snapshot_policy_digest,
    )


def probe_slurm_apptainer(
    *,
    provider_id: str,
    provider_digest: str,
    site_policy_digest: str | None,
    sbatch_path: Path = Path("/usr/bin/sbatch"),
    sacct_path: Path = Path("/usr/bin/sacct"),
    scancel_path: Path = Path("/usr/bin/scancel"),
    scontrol_path: Path = Path("/usr/bin/scontrol"),
    squeue_path: Path = Path("/usr/bin/squeue"),
    apptainer_path: Path = Path("/usr/bin/apptainer"),
    python_path: Path = DEFAULT_PYTHON_PATH,
) -> ExecutorCapability:
    """Probe scheduler accounting and Apptainer without submitting a job."""

    definitions = (
        (sbatch_path, "sbatch", ("--version",), False),
        (sacct_path, "sacct", ("--version",), False),
        (scancel_path, "scancel", ("--version",), False),
        (scontrol_path, "scontrol", ("--version",), False),
        (squeue_path, "squeue", ("--version",), False),
        (apptainer_path, "apptainer", ("--version",), False),
        (python_path, "python", ("--version",), True),
    )
    runtimes: list[RuntimeEvidence] = []
    for path, command, arguments, require_root in definitions:
        evidence = _root_runtime_evidence if require_root else _runtime_evidence
        runtime, failure = evidence(path, command, arguments)
        if failure is not None:
            return _unavailable_slurm(provider_id, provider_digest, tuple(runtimes), failure)
        assert runtime is not None
        runtimes.append(runtime)
    if site_policy_digest is None or not _is_digest(site_policy_digest):
        return _unavailable_slurm(
            provider_id,
            provider_digest,
            tuple(runtimes),
            ProviderUnavailableReason.POLICY_UNATTESTED,
        )
    scheduler_output = _run_probe(scontrol_path, ("ping",))
    accounting_output = _run_status_probe(
        sacct_path,
        (
            "--noheader",
            "--parsable2",
            "--allocations",
            "--starttime=now",
            "--format=JobIDRaw",
        ),
    )
    container_output = _run_probe(apptainer_path, ("exec", "--help"))
    required_container_options = (
        b"--cleanenv",
        b"--containall",
        b"--network",
        b"--no-eval",
        b"--no-mount",
        b"--pids-limit",
        b"--writable-tmpfs",
    )
    if (
        scheduler_output is None
        or accounting_output is None
        or container_output is None
        or any(option not in container_output for option in required_container_options)
    ):
        return _unavailable_slurm(
            provider_id,
            provider_digest,
            tuple(runtimes),
            ProviderUnavailableReason.CONTROL_PLANE_UNAVAILABLE,
        )
    return ExecutorCapability(
        provider_id=provider_id,
        provider_digest=provider_digest,
        kind=ExecutorProviderKind.SLURM_APPTAINER,
        availability=ProviderAvailability.AVAILABLE,
        trust_boundary=ProviderTrustBoundary.TRUSTED_CLUSTER,
        features=tuple(_SLURM_FEATURES),
        runtimes=tuple(runtimes),
        control_plane_probe_digest=canonical_digest(
            {
                "scheduler_probe_digest": _digest_bytes(scheduler_output),
                "accounting_probe_digest": _digest_bytes(accounting_output),
                "container_interface_digest": _digest_bytes(container_output),
                "site_policy_digest": site_policy_digest,
            },
            domain="slurm-apptainer-control-plane-probe-v1",
        ),
    )


def verify_microvm_attestation(
    signed: SignedMicrovmAttestation,
    *,
    trusted_public_keys: Mapping[str, bytes],
    now_epoch_seconds: int,
) -> ExecutorCapability:
    """Verify one bounded provider statement against an explicit trust store."""

    statement = signed.statement
    key = trusted_public_keys.get(signed.key_id)
    if key is None or len(key) != 32:
        return _unavailable_microvm(
            statement,
            ProviderUnavailableReason.ATTESTATION_INVALID,
        )
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(signed.signature_hex),
            statement.signing_bytes,
        )
    except (InvalidSignature, ValueError):
        return _unavailable_microvm(
            statement,
            ProviderUnavailableReason.ATTESTATION_INVALID,
        )
    if not (
        statement.issued_at_epoch_seconds <= now_epoch_seconds < statement.expires_at_epoch_seconds
    ):
        return _unavailable_microvm(
            statement,
            ProviderUnavailableReason.ATTESTATION_EXPIRED,
        )
    features = frozenset(statement.features)
    snapshot_consistent = (ProviderFeature.VM_SNAPSHOT in features) == (
        statement.snapshot_policy_digest is not None
    )
    if not features >= _MICROVM_FEATURES or not snapshot_consistent:
        return _unavailable_microvm(
            statement,
            ProviderUnavailableReason.POLICY_UNATTESTED,
        )
    return ExecutorCapability(
        provider_id=statement.provider_id,
        provider_digest=statement.provider_digest,
        kind=ExecutorProviderKind.MICROVM,
        availability=ProviderAvailability.AVAILABLE,
        trust_boundary=ProviderTrustBoundary.HARDWARE_VM,
        features=statement.features,
        control_plane_probe_digest=canonical_digest(
            statement,
            domain="microvm-control-plane-probe-v1",
        ),
        network_enforcer_digest=statement.network_enforcer_digest,
        snapshot_policy_digest=statement.snapshot_policy_digest,
    )


def _unavailable_microvm(
    statement: MicrovmAttestation,
    reason: ProviderUnavailableReason,
) -> ExecutorCapability:
    return ExecutorCapability(
        provider_id=statement.provider_id,
        provider_digest=statement.provider_digest,
        kind=ExecutorProviderKind.MICROVM,
        availability=ProviderAvailability.UNAVAILABLE,
        trust_boundary=ProviderTrustBoundary.HARDWARE_VM,
        reason=reason,
    )


def _unavailable_libvirt(
    provider_id: str,
    provider_digest: str,
    runtimes: tuple[RuntimeEvidence, ...],
    reason: ProviderUnavailableReason,
) -> ExecutorCapability:
    return ExecutorCapability(
        provider_id=provider_id,
        provider_digest=provider_digest,
        kind=ExecutorProviderKind.LIBVIRT_KVM,
        availability=ProviderAvailability.UNAVAILABLE,
        trust_boundary=ProviderTrustBoundary.HARDWARE_VM,
        runtimes=runtimes,
        reason=reason,
    )


def _unavailable_slurm(
    provider_id: str,
    provider_digest: str,
    runtimes: tuple[RuntimeEvidence, ...],
    reason: ProviderUnavailableReason,
) -> ExecutorCapability:
    return ExecutorCapability(
        provider_id=provider_id,
        provider_digest=provider_digest,
        kind=ExecutorProviderKind.SLURM_APPTAINER,
        availability=ProviderAvailability.UNAVAILABLE,
        trust_boundary=ProviderTrustBoundary.TRUSTED_CLUSTER,
        runtimes=runtimes,
        reason=reason,
    )


def _runtime_evidence(
    path: Path,
    command: str,
    arguments: tuple[str, ...],
) -> tuple[RuntimeEvidence | None, ProviderUnavailableReason | None]:
    executable_digest = _executable_digest(path)
    if executable_digest is None:
        return None, ProviderUnavailableReason.EXECUTABLE_UNAVAILABLE
    output = _run_probe(path, arguments)
    if output is None:
        return None, ProviderUnavailableReason.VERSION_PROBE_FAILED
    version = _version_line(output)
    if version is None:
        return None, ProviderUnavailableReason.VERSION_PROBE_FAILED
    return (
        RuntimeEvidence(
            command=command,
            version=version,
            executable_digest=executable_digest,
            version_output_digest=_digest_bytes(output),
        ),
        None,
    )


def _root_runtime_evidence(
    path: Path,
    command: str,
    arguments: tuple[str, ...],
    *,
    environment: Mapping[str, str] | None = None,
) -> tuple[RuntimeEvidence | None, ProviderUnavailableReason | None]:
    executable_digest, failure = _root_executable_digest(path)
    if failure is not None:
        return None, failure
    assert executable_digest is not None
    output = _run_probe(path, arguments, environment=environment)
    if output is None:
        return None, ProviderUnavailableReason.VERSION_PROBE_FAILED
    version = _version_line(output)
    if version is None:
        return None, ProviderUnavailableReason.VERSION_PROBE_FAILED
    return (
        RuntimeEvidence(
            command=command,
            version=version,
            executable_digest=executable_digest,
            version_output_digest=_digest_bytes(output),
        ),
        None,
    )


def _root_executable_digest(
    path: Path,
) -> tuple[str | None, ProviderUnavailableReason | None]:
    if not path.is_absolute():
        return None, ProviderUnavailableReason.EXECUTABLE_UNAVAILABLE
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None, ProviderUnavailableReason.EXECUTABLE_UNAVAILABLE
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & stat.S_IXUSR
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            return None, ProviderUnavailableReason.EXECUTABLE_UNTRUSTED
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        return f"sha256:{digest.hexdigest()}", None
    finally:
        os.close(descriptor)


def _executable_digest(path: Path) -> str | None:
    if not path.is_absolute():
        return None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & stat.S_IXUSR
            or metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            return None
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def libvirt_control_environment(connection: LibvirtConnection) -> dict[str, str]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": _CLEAN_PATH,
    }
    if connection is LibvirtConnection.SESSION:
        environment["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    return environment


def _rootless_control_environment() -> dict[str, str]:
    try:
        account = pwd.getpwuid(os.getuid())
    except KeyError:
        return {}
    home = Path(account.pw_dir)
    environment = {
        "HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": account.pw_name,
        "PATH": _CLEAN_PATH,
        "USER": account.pw_name,
    }
    runtime = Path("/run/user") / str(os.getuid())
    try:
        home_metadata = home.stat()
        runtime_metadata = runtime.stat()
    except OSError:
        return {}
    if (
        not home.is_absolute()
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
        or not stat.S_ISDIR(runtime_metadata.st_mode)
        or runtime_metadata.st_uid != os.getuid()
        or stat.S_IMODE(runtime_metadata.st_mode) & 0o022
    ):
        return {}
    environment["XDG_RUNTIME_DIR"] = os.fspath(runtime)
    return environment


def _run_probe(
    path: Path,
    arguments: tuple[str, ...],
    *,
    environment: Mapping[str, str] | None = None,
) -> bytes | None:
    try:
        completed = subprocess.run(
            (path, *arguments),
            env=(
                {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": _CLEAN_PATH}
                if environment is None
                else environment
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout:
        return None
    return completed.stdout[:_PROBE_OUTPUT_LIMIT]


def _run_status_probe(path: Path, arguments: tuple[str, ...]) -> bytes | None:
    try:
        completed = subprocess.run(
            (path, *arguments),
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": _CLEAN_PATH},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout) > _PROBE_OUTPUT_LIMIT:
        return None
    return completed.stdout


def _run_user_manager_probe(systemctl_path: Path) -> bytes | None:
    try:
        completed = subprocess.run(
            (
                systemctl_path,
                "--user",
                "show",
                "--property=Version",
                "--value",
            ),
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": _CLEAN_PATH,
                "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > _PROBE_OUTPUT_LIMIT
    ):
        return None
    return completed.stdout


def _version_line(output: bytes) -> str | None:
    for raw_line in output.decode("ascii", errors="replace").splitlines():
        line = " ".join(raw_line.split())[:120]
        if line and all(" " <= character <= "~" for character in line):
            return line
    return None


def _kvm_accessible(path: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return stat.S_ISCHR(os.fstat(descriptor).st_mode) and (
            fcntl.ioctl(descriptor, _KVM_GET_API_VERSION) == _KVM_API_VERSION
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _supports_kvm(output: bytes) -> bool:
    try:
        root = ElementTree.fromstring(output)
    except ElementTree.ParseError:
        return False
    domain = root.findtext("domain")
    return root.tag == "domainCapabilities" and domain == "kvm"


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _is_digest(value: str) -> bool:
    try:
        _DIGEST_ADAPTER.validate_python(value)
    except ValidationError:
        return False
    return True
