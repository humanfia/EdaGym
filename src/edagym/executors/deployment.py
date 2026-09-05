"""Owner-only deployment registry for concrete executor substrates."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self, SupportsIndex

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.capabilities import (
    ExecutorCapability,
    LibvirtConnection,
    ProviderAvailability,
    ProviderFeature,
    ProviderTrustBoundary,
    ProviderUnavailableReason,
    RootlessContainerCapability,
    SignedMicrovmAttestation,
    probe_libvirt_kvm,
    probe_rootless_container,
    probe_slurm_apptainer,
    verify_microvm_attestation,
)
from edagym.executors.local import ExecutorUnavailable
from edagym.executors.rootless_storage import RootlessStorageProvider
from edagym.policy.private_roots import (
    PrivateRootRegistration,
    PrivateRootRole,
    _bind_private_root_from_descriptor,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.environment import (
    EnvironmentSpec,
    RootlessLocalExecutor,
    VmPerRunExecutor,
)
from edagym.specs.environment import (
    SlurmApptainerExecutor as SlurmExecutorSpec,
)

if TYPE_CHECKING:
    from edagym.drivers.probe import ResolvedInstallation
    from edagym.executors.libvirt_broker import LibvirtKernelImage
    from edagym.executors.rootless import RootlessContainerExecutor
    from edagym.executors.slurm import SlurmApptainerExecutor
    from edagym.executors.vm import LibvirtVmExecutor

_MAXIMUM_REGISTRY_BYTES = 1024 * 1024
_MINIMUM_ROOTLESS_STORAGE_BYTES = 32 * 1024 * 1024
_PRIVATE_FILE_MODE = 0o600


class ExecutorDeploymentKind(StrEnum):
    ROOTLESS_LOCAL = "rootless_local"
    LIBVIRT_KVM = "libvirt_kvm"
    SLURM_APPTAINER = "slurm_apptainer"
    MICROVM = "microvm"


class ExecutorDeploymentStatus(StrictModel):
    """Path-free live projection of one registry-selected executor substrate."""

    kind: ExecutorDeploymentKind
    registry_source_digest: Digest | None
    availability: ProviderAvailability
    trust_boundary: ProviderTrustBoundary
    features: tuple[ProviderFeature, ...] = ()
    deployment_binding_digest: Digest | None = None
    capability_digest: Digest | None = None
    reason: ProviderUnavailableReason | None = None

    @field_validator("features")
    @classmethod
    def normalize_features(
        cls,
        value: tuple[ProviderFeature, ...],
    ) -> tuple[ProviderFeature, ...]:
        if len(value) != len(set(value)):
            raise ValueError("executor deployment features must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        available = self.availability is ProviderAvailability.AVAILABLE
        configured = self.deployment_binding_digest is not None
        if available != (self.reason is None):
            raise ValueError("executor deployment availability and reason disagree")
        if configured and self.registry_source_digest is None:
            raise ValueError("configured executor deployments require their registry source")
        if available and (not configured or self.capability_digest is None):
            raise ValueError("available executor deployments require live capability evidence")
        if not configured and (
            self.reason is not ProviderUnavailableReason.POLICY_UNATTESTED
            or self.capability_digest is not None
            or self.features
        ):
            raise ValueError("unconfigured executor deployments have no capability claims")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-deployment-status-v1")


class _RootlessImage(StrictModel):
    image_digest: Digest
    image_reference: Annotated[str, Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if (
            not self.image_reference.endswith(f"@{self.image_digest}")
            or any(character in self.image_reference for character in "\x00\r\n")
        ):
            raise ValueError("rootless image references must be digest-pinned")
        return self


class _RootlessDeployment(StrictModel):
    podman_path: str
    mkfs_path: str
    fuse2fs_path: str
    fusermount_path: str
    maximum_storage_bytes: Annotated[
        int,
        Field(strict=True, ge=_MINIMUM_ROOTLESS_STORAGE_BYTES),
    ]
    images: tuple[_RootlessImage, ...]

    @field_validator("podman_path", "mkfs_path", "fuse2fs_path", "fusermount_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _absolute_path_text(value)

    @field_validator("images")
    @classmethod
    def validate_images(cls, value: tuple[_RootlessImage, ...]) -> tuple[_RootlessImage, ...]:
        identities = [item.image_digest for item in value]
        if not value or len(identities) != len(set(identities)):
            raise ValueError("rootless deployment images must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.image_digest))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-rootless-deployment-v1")


class _LibvirtDeployment(StrictModel):
    provider_id: Identifier
    virsh_path: str
    kernel_path: str
    initrd_path: str
    kernel_arguments: Annotated[str, Field(min_length=1, max_length=4096)]
    guest_control_digest: Digest
    state_root: str
    control_root: str
    workspace_root: str
    artifact_root: str
    boot_timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=600)]
    snapshot_policy_digest: Digest | None
    network_enforcer_digest: Digest | None

    @field_validator(
        "virsh_path",
        "kernel_path",
        "initrd_path",
        "state_root",
        "control_root",
        "workspace_root",
        "artifact_root",
    )
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _absolute_path_text(value)

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        roots = tuple(
            Path(value)
            for value in (
                self.state_root,
                self.control_root,
                self.workspace_root,
                self.artifact_root,
            )
        )
        if (
            len(roots) != len(set(roots))
            or any(
                _paths_overlap(left, right)
                for index, left in enumerate(roots)
                for right in roots[index + 1 :]
            )
            or any(character in self.kernel_arguments for character in "\x00\r\n")
        ):
            raise ValueError("libvirt deployment roots and kernel arguments are not bounded")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-libvirt-deployment-v1")


class _SlurmImage(StrictModel):
    image_digest: Digest
    image_path: str

    @field_validator("image_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _absolute_path_text(value)


class _SlurmDeployment(StrictModel):
    provider_id: Identifier
    site_policy_digest: Digest
    sbatch_path: str
    sacct_path: str
    scancel_path: str
    scontrol_path: str
    squeue_path: str
    apptainer_path: str
    python_path: str
    job_state_root: str
    images: tuple[_SlurmImage, ...]

    @field_validator(
        "sbatch_path",
        "sacct_path",
        "scancel_path",
        "scontrol_path",
        "squeue_path",
        "apptainer_path",
        "python_path",
        "job_state_root",
    )
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _absolute_path_text(value)

    @field_validator("images")
    @classmethod
    def validate_images(cls, value: tuple[_SlurmImage, ...]) -> tuple[_SlurmImage, ...]:
        identities = [item.image_digest for item in value]
        if not value or len(identities) != len(set(identities)):
            raise ValueError("Slurm deployment images must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.image_digest))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-slurm-deployment-v1")


class _MicrovmDeployment(StrictModel):
    signed_attestation: SignedMicrovmAttestation
    trusted_key_id: Identifier
    trusted_public_key_hex: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-microvm-deployment-v1")


class _ExecutorDeploymentDocument(StrictModel):
    schema_version: Literal[1]
    deployment_id: Identifier
    rootless: _RootlessDeployment | None = None
    libvirt: _LibvirtDeployment | None = None
    slurm: _SlurmDeployment | None = None
    microvm: _MicrovmDeployment | None = None

    @model_validator(mode="after")
    def require_one_deployment(self) -> Self:
        if all(
            value is None
            for value in (self.rootless, self.libvirt, self.slurm, self.microvm)
        ):
            raise ValueError("executor deployment registry cannot be empty")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-deployment-registry-v1")


class _DeploymentSource:
    __slots__ = ("content_digest", "descriptor", "identity")

    def __init__(
        self,
        *,
        descriptor: int,
        identity: tuple[int, ...],
        content_digest: Digest,
    ) -> None:
        self.descriptor = descriptor
        self.identity = identity
        self.content_digest = content_digest

    def read(self) -> bytes:
        if self.descriptor < 0:
            raise ValueError("executor deployment registry is closed")
        metadata = os.fstat(self.descriptor)
        if _source_identity(metadata) != self.identity:
            raise ValueError("executor deployment registry source changed")
        content = _pread_exact(self.descriptor, metadata.st_size)
        after = os.fstat(self.descriptor)
        if (
            _source_identity(after) != self.identity
            or _content_digest(content) != self.content_digest
        ):
            raise ValueError("executor deployment registry source changed")
        return content

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class ExecutorDeploymentRegistry:
    """Descriptor-bound private source for every site executor deployment."""

    __slots__ = ("_document", "_source")

    def __init__(
        self,
        document: _ExecutorDeploymentDocument,
        source: _DeploymentSource,
    ) -> None:
        self._document = document
        self._source = source

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            {
                "document_digest": self._document.digest,
                "source_content_digest": self._source.content_digest,
            },
            domain="executor-deployment-registry-source-v1",
        )

    def revalidate(self) -> bool:
        try:
            content = self._source.read()
            current = _ExecutorDeploymentDocument.model_validate_json(content)
        except (OSError, ValueError, TypeError):
            return False
        return canonical_bytes(current) + b"\n" == content and current == self._document

    def source_registration(self) -> PrivateRootRegistration:
        """Register the retained exact source descriptor for release audit."""

        if not self.revalidate():
            raise ValueError("executor deployment registry changed before registration")
        return _bind_private_root_from_descriptor(
            PrivateRootRole.EXECUTOR_DEPLOYMENT_REGISTRY,
            self._source.descriptor,
            self.digest,
        )

    def statuses(self, *, now_epoch_seconds: int) -> tuple[ExecutorDeploymentStatus, ...]:
        return tuple(
            self.status(kind, now_epoch_seconds=now_epoch_seconds)
            for kind in ExecutorDeploymentKind
        )

    def status(
        self,
        kind: ExecutorDeploymentKind,
        *,
        now_epoch_seconds: int,
    ) -> ExecutorDeploymentStatus:
        if not self.revalidate():
            return _unavailable_status(
                kind,
                self.digest,
                ProviderUnavailableReason.POLICY_UNATTESTED,
                configured=True,
            )
        if kind is ExecutorDeploymentKind.ROOTLESS_LOCAL:
            return self._rootless_status()
        if kind is ExecutorDeploymentKind.LIBVIRT_KVM:
            return self._libvirt_status()
        if kind is ExecutorDeploymentKind.SLURM_APPTAINER:
            return self._slurm_status()
        return self._microvm_status(now_epoch_seconds)

    def rootless_configuration(self) -> RootlessExecutorDeployment:
        binding = self._document.rootless
        if binding is None or not self.revalidate():
            raise ExecutorUnavailable("rootless executor deployment is not registered")
        capability, storage = _probe_rootless(binding)
        if capability.availability is not ProviderAvailability.AVAILABLE or storage is None:
            raise ExecutorUnavailable("rootless executor deployment is unavailable")
        return RootlessExecutorDeployment(self, binding, capability, storage)

    def libvirt_configuration(self) -> LibvirtExecutorDeployment:
        binding = self._document.libvirt
        if binding is None or not self.revalidate():
            raise ExecutorUnavailable("libvirt executor deployment is not registered")
        configuration = _probe_libvirt(self, binding)
        if configuration.capability.availability is not ProviderAvailability.AVAILABLE:
            raise ExecutorUnavailable("libvirt executor deployment is unavailable")
        return configuration

    def slurm_configuration(self) -> SlurmExecutorDeployment:
        binding = self._document.slurm
        if binding is None or not self.revalidate():
            raise ExecutorUnavailable("Slurm executor deployment is not registered")
        capability = _probe_slurm(self, binding)
        if capability.availability is not ProviderAvailability.AVAILABLE:
            raise ExecutorUnavailable("Slurm executor deployment is unavailable")
        return SlurmExecutorDeployment(self, binding, capability)

    def _rootless_status(self) -> ExecutorDeploymentStatus:
        binding = self._document.rootless
        if binding is None:
            return _unavailable_status(
                ExecutorDeploymentKind.ROOTLESS_LOCAL,
                self.digest,
                ProviderUnavailableReason.POLICY_UNATTESTED,
            )
        capability, storage = _probe_rootless(binding)
        reason = capability.reason
        capability_digest = canonical_digest(
            {
                "container_capability_digest": capability.digest,
                "storage_capability_digest": (
                    None if storage is None else storage.capability_digest
                ),
            },
            domain="executor-rootless-deployment-capability-v1",
        )
        available = (
            capability.availability is ProviderAvailability.AVAILABLE and storage is not None
        )
        if not available and reason is None:
            reason = ProviderUnavailableReason.EXECUTABLE_UNAVAILABLE
        return ExecutorDeploymentStatus(
            kind=ExecutorDeploymentKind.ROOTLESS_LOCAL,
            registry_source_digest=self.digest,
            availability=(
                ProviderAvailability.AVAILABLE
                if available
                else ProviderAvailability.UNAVAILABLE
            ),
            trust_boundary=ProviderTrustBoundary.ROOTLESS_USER_NAMESPACE,
            features=(
                ProviderFeature.AGGREGATE_STORAGE_QUOTA,
                ProviderFeature.CONTAINER_ENCAPSULATION,
                ProviderFeature.DURABLE_PROCESS_CONTAINMENT,
                ProviderFeature.IMMUTABLE_BASE_IMAGE,
            ),
            deployment_binding_digest=binding.digest,
            capability_digest=capability_digest,
            reason=None if available else reason,
        )

    def _libvirt_status(self) -> ExecutorDeploymentStatus:
        binding = self._document.libvirt
        if binding is None:
            return _unavailable_status(
                ExecutorDeploymentKind.LIBVIRT_KVM,
                self.digest,
                ProviderUnavailableReason.POLICY_UNATTESTED,
            )
        configuration = _probe_libvirt(self, binding)
        capability = configuration.capability
        return _status_from_capability(
            ExecutorDeploymentKind.LIBVIRT_KVM,
            self.digest,
            binding.digest,
            capability,
        )

    def _slurm_status(self) -> ExecutorDeploymentStatus:
        binding = self._document.slurm
        if binding is None:
            return _unavailable_status(
                ExecutorDeploymentKind.SLURM_APPTAINER,
                self.digest,
                ProviderUnavailableReason.POLICY_UNATTESTED,
            )
        capability = _probe_slurm(self, binding)
        return _status_from_capability(
            ExecutorDeploymentKind.SLURM_APPTAINER,
            self.digest,
            binding.digest,
            capability,
        )

    def _microvm_status(self, now_epoch_seconds: int) -> ExecutorDeploymentStatus:
        binding = self._document.microvm
        if binding is None:
            return _unavailable_status(
                ExecutorDeploymentKind.MICROVM,
                self.digest,
                ProviderUnavailableReason.POLICY_UNATTESTED,
            )
        capability = _probe_microvm(binding, now_epoch_seconds)
        return _status_from_capability(
            ExecutorDeploymentKind.MICROVM,
            self.digest,
            binding.digest,
            capability,
        )

    def close(self) -> None:
        self._source.close()

    def __enter__(self) -> ExecutorDeploymentRegistry:
        if not self.revalidate():
            raise ValueError("executor deployment registry is unavailable")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        return "ExecutorDeploymentRegistry(<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("executor deployment registries cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class RootlessExecutorDeployment:
    _registry: ExecutorDeploymentRegistry
    _binding: _RootlessDeployment
    capability: RootlessContainerCapability
    storage_provider: RootlessStorageProvider

    @property
    def image_references(self) -> Mapping[Digest, str]:
        return MappingProxyType(
            {item.image_digest: item.image_reference for item in self._binding.images}
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            {
                "registry_source_digest": self._registry.digest,
                "binding_digest": self._binding.digest,
                "container_capability_digest": self.capability.digest,
                "storage_capability_digest": self.storage_provider.capability_digest,
            },
            domain="rootless-executor-deployment-binding-v1",
        )

    def revalidate(self) -> bool:
        if not self._registry.revalidate():
            return False
        capability, storage = _probe_rootless(self._binding)
        return (
            storage is not None
            and capability == self.capability
            and storage.capability_digest == self.storage_provider.capability_digest
        )

    def create_executor(
        self,
        *,
        environment: EnvironmentSpec,
        tool_installations: Mapping[str, ResolvedInstallation],
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
        job_state_root: Path,
    ) -> RootlessContainerExecutor:
        from edagym.executors.rootless import RootlessContainerExecutor

        executor = environment.executor
        if (
            not self.revalidate()
            or not isinstance(executor, RootlessLocalExecutor)
            or executor.image_digest not in self.image_references
        ):
            raise ExecutorUnavailable("environment differs from rootless deployment")
        return RootlessContainerExecutor(
            executor_id=executor.executor_id,
            implementation_digest=executor.implementation_digest,
            capability=self.capability,
            tool_installations=tool_installations,
            storage_provider=self.storage_provider,
            asset_source_policy=asset_source_policy,
            artifact_store=artifact_store,
            job_state_root=job_state_root,
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("rootless executor deployments cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class LibvirtExecutorDeployment:
    _registry: ExecutorDeploymentRegistry
    _binding: _LibvirtDeployment
    capability: ExecutorCapability
    image: LibvirtKernelImage | None

    @property
    def provider_digest(self) -> Digest:
        return _provider_digest(self._registry, self._binding.digest)

    def revalidate(self) -> bool:
        if not self._registry.revalidate():
            return False
        current = _probe_libvirt(self._registry, self._binding)
        return (
            current.capability == self.capability
            and current.image is not None
            and self.image is not None
            and current.image.image_digest == self.image.image_digest
        )

    def create_executor(
        self,
        *,
        environment: EnvironmentSpec,
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
    ) -> LibvirtVmExecutor:
        from edagym.executors.libvirt_broker import SessionLibvirtVmBroker
        from edagym.executors.vm import LibvirtVmExecutor

        executor = environment.executor
        if (
            not self.revalidate()
            or not isinstance(executor, VmPerRunExecutor)
            or executor.provider_id != self._binding.provider_id
            or executor.provider_digest != self.provider_digest
            or self.image is None
        ):
            raise ExecutorUnavailable("environment differs from libvirt deployment")
        image = self.image
        broker = SessionLibvirtVmBroker(
            executor_id=executor.executor_id,
            implementation_digest=executor.implementation_digest,
            provider_id=self._binding.provider_id,
            provider_digest=self.provider_digest,
            capability=self.capability,
            virsh_path=Path(self._binding.virsh_path),
            images={image.image_digest: image},
            artifact_store=artifact_store,
            state_root=Path(self._binding.state_root),
            control_root=Path(self._binding.control_root),
            connection=LibvirtConnection.SESSION,
            boot_timeout_seconds=self._binding.boot_timeout_seconds,
        )
        return LibvirtVmExecutor(
            executor_id=executor.executor_id,
            implementation_digest=executor.implementation_digest,
            provider_id=self._binding.provider_id,
            provider_digest=self.provider_digest,
            capability=self.capability,
            broker=broker,
            asset_source_policy=asset_source_policy,
            workspace_root=Path(self._binding.workspace_root),
            artifact_root=Path(self._binding.artifact_root),
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("libvirt executor deployments cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class SlurmExecutorDeployment:
    _registry: ExecutorDeploymentRegistry
    _binding: _SlurmDeployment
    capability: ExecutorCapability

    @property
    def provider_digest(self) -> Digest:
        return _provider_digest(self._registry, self._binding.digest)

    def revalidate(self) -> bool:
        return self._registry.revalidate() and _probe_slurm(
            self._registry,
            self._binding,
        ) == self.capability

    def create_executor(
        self,
        *,
        environment: EnvironmentSpec,
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
    ) -> SlurmApptainerExecutor:
        from edagym.executors.slurm import SlurmApptainerExecutor

        executor = environment.executor
        if (
            not self.revalidate()
            or not isinstance(executor, SlurmExecutorSpec)
            or executor.provider_id != self._binding.provider_id
            or executor.provider_digest != self.provider_digest
        ):
            raise ExecutorUnavailable("environment differs from Slurm deployment")
        return SlurmApptainerExecutor(
            executor_id=executor.executor_id,
            implementation_digest=executor.implementation_digest,
            provider_id=self._binding.provider_id,
            provider_digest=self.provider_digest,
            site_policy_digest=self._binding.site_policy_digest,
            capability=self.capability,
            sbatch_path=Path(self._binding.sbatch_path),
            sacct_path=Path(self._binding.sacct_path),
            scancel_path=Path(self._binding.scancel_path),
            scontrol_path=Path(self._binding.scontrol_path),
            squeue_path=Path(self._binding.squeue_path),
            apptainer_path=Path(self._binding.apptainer_path),
            python_path=Path(self._binding.python_path),
            image_paths={item.image_digest: Path(item.image_path) for item in self._binding.images},
            asset_source_policy=asset_source_policy,
            artifact_store=artifact_store,
            job_state_root=Path(self._binding.job_state_root),
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("Slurm executor deployments cannot be serialized")


def load_executor_deployment_registry(path: Path) -> ExecutorDeploymentRegistry:
    """Load and retain one exact owner-only executor deployment source."""

    descriptor = _open_registry(path)
    try:
        metadata = os.fstat(descriptor)
        content = _pread_exact(descriptor, metadata.st_size)
        after = os.fstat(descriptor)
        if _source_identity(metadata) != _source_identity(after):
            raise ValueError("executor deployment registry changed while loading")
        document = _ExecutorDeploymentDocument.model_validate_json(content)
        if canonical_bytes(document) + b"\n" != content:
            raise ValueError("executor deployment registry must use canonical JSON")
        source = _DeploymentSource(
            descriptor=descriptor,
            identity=_source_identity(metadata),
            content_digest=_content_digest(content),
        )
        descriptor = -1
        return ExecutorDeploymentRegistry(document, source)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("executor deployment registry is invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _probe_rootless(
    binding: _RootlessDeployment,
) -> tuple[RootlessContainerCapability, RootlessStorageProvider | None]:
    capability = probe_rootless_container(
        image_references={item.image_digest: item.image_reference for item in binding.images},
        podman_path=Path(binding.podman_path),
    )
    try:
        storage = RootlessStorageProvider(
            maximum_quota_bytes=binding.maximum_storage_bytes,
            mkfs_path=Path(binding.mkfs_path),
            fuse2fs_path=Path(binding.fuse2fs_path),
            fusermount_path=Path(binding.fusermount_path),
        )
    except ExecutorUnavailable:
        storage = None
    return capability, storage


def _probe_libvirt(
    registry: ExecutorDeploymentRegistry,
    binding: _LibvirtDeployment,
) -> LibvirtExecutorDeployment:
    from edagym.executors.libvirt_broker import LibvirtKernelImage

    provider_digest = _provider_digest(registry, binding.digest)
    image: LibvirtKernelImage | None
    try:
        image = LibvirtKernelImage(
            kernel_path=Path(binding.kernel_path),
            initrd_path=Path(binding.initrd_path),
            kernel_arguments=binding.kernel_arguments,
        )
        image_digest: Digest | None = image.image_digest
    except ExecutorUnavailable:
        image = None
        image_digest = None
    capability = probe_libvirt_kvm(
        provider_id=binding.provider_id,
        provider_digest=provider_digest,
        guest_control_digest=binding.guest_control_digest,
        immutable_image_digest=image_digest,
        snapshot_policy_digest=binding.snapshot_policy_digest,
        network_enforcer_digest=binding.network_enforcer_digest,
        connection=LibvirtConnection.SESSION,
        virsh_path=Path(binding.virsh_path),
    )
    return LibvirtExecutorDeployment(registry, binding, capability, image)


def _probe_slurm(
    registry: ExecutorDeploymentRegistry,
    binding: _SlurmDeployment,
) -> ExecutorCapability:
    return probe_slurm_apptainer(
        provider_id=binding.provider_id,
        provider_digest=_provider_digest(registry, binding.digest),
        site_policy_digest=binding.site_policy_digest,
        sbatch_path=Path(binding.sbatch_path),
        sacct_path=Path(binding.sacct_path),
        scancel_path=Path(binding.scancel_path),
        scontrol_path=Path(binding.scontrol_path),
        squeue_path=Path(binding.squeue_path),
        apptainer_path=Path(binding.apptainer_path),
        python_path=Path(binding.python_path),
    )


def _probe_microvm(
    binding: _MicrovmDeployment,
    now_epoch_seconds: int,
) -> ExecutorCapability:
    return verify_microvm_attestation(
        binding.signed_attestation,
        trusted_public_keys={
            binding.trusted_key_id: bytes.fromhex(binding.trusted_public_key_hex)
        },
        now_epoch_seconds=now_epoch_seconds,
    )


def _provider_digest(
    registry: ExecutorDeploymentRegistry,
    binding_digest: Digest,
) -> Digest:
    return canonical_digest(
        {
            "registry_source_digest": registry.digest,
            "binding_digest": binding_digest,
        },
        domain="executor-provider-deployment-v1",
    )


def _status_from_capability(
    kind: ExecutorDeploymentKind,
    registry_digest: Digest,
    binding_digest: Digest,
    capability: ExecutorCapability,
) -> ExecutorDeploymentStatus:
    return ExecutorDeploymentStatus(
        kind=kind,
        registry_source_digest=registry_digest,
        availability=capability.availability,
        trust_boundary=capability.trust_boundary,
        features=capability.features,
        deployment_binding_digest=binding_digest,
        capability_digest=capability.digest,
        reason=capability.reason,
    )


def _unavailable_status(
    kind: ExecutorDeploymentKind,
    registry_digest: Digest | None,
    reason: ProviderUnavailableReason,
    *,
    configured: bool = False,
) -> ExecutorDeploymentStatus:
    trust = (
        ProviderTrustBoundary.ROOTLESS_USER_NAMESPACE
        if kind is ExecutorDeploymentKind.ROOTLESS_LOCAL
        else ProviderTrustBoundary.TRUSTED_CLUSTER
        if kind is ExecutorDeploymentKind.SLURM_APPTAINER
        else ProviderTrustBoundary.HARDWARE_VM
    )
    return ExecutorDeploymentStatus(
        kind=kind,
        registry_source_digest=registry_digest,
        availability=ProviderAvailability.UNAVAILABLE,
        trust_boundary=trust,
        deployment_binding_digest=(registry_digest if configured else None),
        reason=reason,
    )


def _open_registry(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("executor deployment registry path must be absolute")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError:
        raise ValueError("executor deployment registry is unavailable") from None
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > _MAXIMUM_REGISTRY_BYTES
    ):
        os.close(descriptor)
        raise ValueError("executor deployment registry must be an owner-only regular file")
    return descriptor


def _pread_exact(descriptor: int, size: int) -> bytes:
    content = bytearray()
    while len(content) < size:
        block = os.pread(descriptor, min(1024 * 1024, size - len(content)), len(content))
        if not block:
            break
        content.extend(block)
    if len(content) != size:
        raise ValueError("executor deployment registry could not be read completely")
    return bytes(content)


def _source_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _content_digest(content: bytes) -> Digest:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _absolute_path_text(value: str) -> str:
    path = Path(value)
    if (
        not path.is_absolute()
        or os.path.normpath(value) != value
        or any(character in value for character in "\x00\r\n")
    ):
        raise ValueError("executor deployment paths must be absolute")
    return value


def unconfigured_executor_statuses() -> tuple[ExecutorDeploymentStatus, ...]:
    """Describe the absence of site authority without probing arbitrary defaults."""

    return tuple(
        _unavailable_status(kind, None, ProviderUnavailableReason.POLICY_UNATTESTED)
        for kind in ExecutorDeploymentKind
    )


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents
