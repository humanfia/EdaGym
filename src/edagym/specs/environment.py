"""Canonical resolved execution, tool-access, and artifact policy."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, StrictInt, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Digest,
    Identifier,
    Redistribution,
    SchemaVersion,
    Sensitivity,
    StrictModel,
    Visibility,
    validate_relative_path,
)
from edagym.specs.operation import (
    ParticipantOperationBinding,
    executable_is_shell,
)

PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonNegativeInt = Annotated[StrictInt, Field(ge=0)]


class ExecutorKind(StrEnum):
    ROOTLESS_LOCAL = "rootless_local"
    BROKERED_HOST_TOOL = "brokered_host_tool"
    VM_PER_RUN = "vm_per_run"
    SLURM_APPTAINER = "slurm_apptainer"
    MICROVM_CLOUD = "microvm_cloud"


class ContainerRuntime(StrEnum):
    PODMAN = "podman"


class ToolLocatorKind(StrEnum):
    ATTESTED_HOST = "attested_host"
    IMAGE = "image"


class NetworkKind(StrEnum):
    NONE = "none"
    HOST_ALLOWLIST = "host_allowlist"


class NetworkProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class FilesystemScope(StrEnum):
    PARTICIPANT = "participant"
    EVALUATOR = "evaluator"
    TOOL = "tool"


class EncryptionKind(StrEnum):
    NONE = "none"
    MANAGED = "managed"


class CheckpointCapability(StrEnum):
    NONE = "none"
    APPLICATION = "app"
    FILESYSTEM = "fs"
    VIRTUAL_MACHINE = "vm"


class ApplicationCheckpointBinding(StrictModel):
    """A tool-owned durable database captured at declared evaluator boundaries."""

    driver_id: Identifier
    driver_digest: Digest
    capture_paths: tuple[str, ...]
    after_stage_ids: tuple[Identifier, ...]

    @field_validator("capture_paths")
    @classmethod
    def normalize_capture_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        paths = tuple(sorted(validate_relative_path(path) for path in value))
        path_objects = tuple(PurePosixPath(path) for path in paths)
        if (
            not paths
            or len(paths) != len(set(paths))
            or any(
                left in right.parents or right in left.parents
                for position, left in enumerate(path_objects)
                for right in path_objects[position + 1 :]
            )
        ):
            raise ValueError("application checkpoint paths must be unique and non-overlapping")
        return paths

    @field_validator("after_stage_ids")
    @classmethod
    def normalize_stage_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("application checkpoint boundaries must be unique and non-empty")
        return tuple(sorted(value))


class EnvironmentIdentity(StrictModel):
    environment_id: Identifier
    authoring_revision: PositiveInt
    provenance: tuple[str, ...] = ()

    @field_validator("provenance")
    @classmethod
    def normalize_provenance(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("environment provenance entries must be unique")
        return tuple(sorted(value))


class ExecutorBase(StrictModel):
    executor_id: Identifier
    implementation_digest: Digest


class RootlessLocalExecutor(ExecutorBase):
    kind: Literal[ExecutorKind.ROOTLESS_LOCAL] = ExecutorKind.ROOTLESS_LOCAL
    runtime: ContainerRuntime
    runtime_version: Annotated[str, Field(min_length=1, max_length=120)]
    runtime_probe_digest: Digest
    image_digest: Digest

    @field_validator("runtime_version")
    @classmethod
    def validate_runtime_version(cls, value: str) -> str:
        return _validate_exact_version(value)


class BrokeredHostToolExecutor(ExecutorBase):
    kind: Literal[ExecutorKind.BROKERED_HOST_TOOL] = ExecutorKind.BROKERED_HOST_TOOL
    broker_id: Identifier
    broker_digest: Digest
    participant_image_digest: Digest


class VmPerRunExecutor(ExecutorBase):
    kind: Literal[ExecutorKind.VM_PER_RUN] = ExecutorKind.VM_PER_RUN
    provider_id: Identifier
    provider_digest: Digest
    image_digest: Digest


class SlurmApptainerExecutor(ExecutorBase):
    kind: Literal[ExecutorKind.SLURM_APPTAINER] = ExecutorKind.SLURM_APPTAINER
    provider_id: Identifier
    provider_digest: Digest
    apptainer_version: Annotated[str, Field(min_length=1, max_length=120)]
    apptainer_probe_digest: Digest
    image_digest: Digest

    @field_validator("apptainer_version")
    @classmethod
    def validate_apptainer_version(cls, value: str) -> str:
        return _validate_exact_version(value)


class MicrovmCloudExecutor(ExecutorBase):
    kind: Literal[ExecutorKind.MICROVM_CLOUD] = ExecutorKind.MICROVM_CLOUD
    provider_id: Identifier
    provider_digest: Digest
    image_digest: Digest


ExecutorSpec = Annotated[
    RootlessLocalExecutor
    | BrokeredHostToolExecutor
    | VmPerRunExecutor
    | SlurmApptainerExecutor
    | MicrovmCloudExecutor,
    Field(discriminator="kind"),
]


def executor_is_participant_isolation(executor: ExecutorSpec) -> bool:
    """Return whether the executor isolates arbitrary participant-controlled bytes."""

    return isinstance(
        executor,
        (RootlessLocalExecutor, VmPerRunExecutor, MicrovmCloudExecutor),
    )


_EXECUTABLE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_NON_EXACT_VERSION_MARKERS = frozenset({"*", "<", ">", "~=", "^="})
_NON_EXACT_VERSION_NAMES = frozenset({"any", "current", "latest", "stable"})


def _validate_exact_version(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("version labels must be normalized and contain no control characters")
    if any(marker in value for marker in _NON_EXACT_VERSION_MARKERS):
        raise ValueError("version constraints and wildcards are not exact tool identities")
    if value.casefold() in _NON_EXACT_VERSION_NAMES:
        raise ValueError("version aliases are not exact tool identities")
    return value


def _validate_executable_name(value: str) -> str:
    if not _EXECUTABLE_PATTERN.fullmatch(value):
        raise ValueError("executable must be an opaque command name, not a host path")
    return value


ExecutableName = Annotated[str, AfterValidator(_validate_executable_name)]


class AttestedHostToolLocator(StrictModel):
    """Path-free identity for a deployment-attested host tool."""

    kind: Literal[ToolLocatorKind.ATTESTED_HOST] = ToolLocatorKind.ATTESTED_HOST
    executable: ExecutableName
    deployment_attestation_digest: Digest


class ImageToolLocator(StrictModel):
    kind: Literal[ToolLocatorKind.IMAGE] = ToolLocatorKind.IMAGE
    image_digest: Digest
    executable: ExecutableName
    deployment_attestation_digest: Digest


ToolLocator = Annotated[
    AttestedHostToolLocator | ImageToolLocator,
    Field(discriminator="kind"),
]


class ToolBinding(StrictModel):
    capability: Capability
    tool_id: Identifier
    tool_version: Annotated[str, Field(min_length=1, max_length=120)]
    driver_id: Identifier
    driver_digest: Digest
    locator: ToolLocator
    license_binding_id: Identifier | None = None

    @field_validator("tool_version")
    @classmethod
    def validate_tool_version(cls, value: str) -> str:
        return _validate_exact_version(value)


class AssetBinding(StrictModel):
    asset_id: Identifier
    restricted_digest: Digest
    allowed_scopes: tuple[FilesystemScope, ...]

    @field_validator("allowed_scopes")
    @classmethod
    def normalize_allowed_scopes(
        cls, value: tuple[FilesystemScope, ...]
    ) -> tuple[FilesystemScope, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("asset scopes must be unique and non-empty")
        return tuple(sorted(value, key=lambda scope: scope.value))


_RESERVED_GUEST_TARGETS = tuple(
    PurePosixPath(path)
    for path in (
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/mnt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
        "/var/lib/containers",
        "/var/lib/docker",
        "/var/run",
    )
)


def _normalize_guest_target(value: str) -> str:
    if "\\" in value or "\x00" in value:
        raise ValueError("guest target must be a POSIX path")
    raw_parts = value.split("/")
    if (
        not value.startswith("/")
        or value.startswith("//")
        or any(part in {".", ".."} for part in raw_parts)
    ):
        raise ValueError("guest target must be an absolute path without traversal")
    path = PurePosixPath(value)
    if path == PurePosixPath("/"):
        raise ValueError("guest target cannot be the filesystem root")
    if any(path == reserved or reserved in path.parents for reserved in _RESERVED_GUEST_TARGETS):
        raise ValueError("guest target is inside a reserved host-control namespace")
    return path.as_posix()


GuestTarget = Annotated[
    str,
    Field(min_length=2, max_length=240),
    AfterValidator(_normalize_guest_target),
]


class ReadonlyAssetMount(StrictModel):
    asset_id: Identifier
    scope: FilesystemScope
    target: GuestTarget


class FilesystemPolicy(StrictModel):
    readonly_assets: tuple[ReadonlyAssetMount, ...] = ()
    workspace_target: GuestTarget
    artifact_target: GuestTarget

    @field_validator("readonly_assets")
    @classmethod
    def normalize_readonly_assets(
        cls, value: tuple[ReadonlyAssetMount, ...]
    ) -> tuple[ReadonlyAssetMount, ...]:
        return tuple(
            sorted(value, key=lambda mount: (mount.scope.value, mount.target, mount.asset_id))
        )

    @model_validator(mode="after")
    def validate_disjoint_targets(self) -> Self:
        mount_keys = [(mount.asset_id, mount.scope, mount.target) for mount in self.readonly_assets]
        if len(mount_keys) != len(set(mount_keys)):
            raise ValueError("readonly asset mounts must be unique")
        if _paths_overlap(self.workspace_target, self.artifact_target):
            raise ValueError("workspace and artifact targets must be disjoint")
        for scope in FilesystemScope:
            targets = [mount.target for mount in self.readonly_assets if mount.scope is scope]
            targets.extend((self.workspace_target, self.artifact_target))
            for position, target in enumerate(targets):
                if any(_paths_overlap(target, other) for other in targets[position + 1 :]):
                    raise ValueError("mount targets within one view must be disjoint")
        return self


def _paths_overlap(left: str, right: str) -> bool:
    left_path = PurePosixPath(left)
    right_path = PurePosixPath(right)
    return (
        left_path == right_path
        or left_path in right_path.parents
        or right_path in left_path.parents
    )


class NetworkRule(StrictModel):
    endpoint_id: Identifier
    protocol: NetworkProtocol
    port: Annotated[StrictInt, Field(ge=1, le=65535)]


class NoNetwork(StrictModel):
    kind: Literal[NetworkKind.NONE] = NetworkKind.NONE


class HostAllowlistNetwork(StrictModel):
    kind: Literal[NetworkKind.HOST_ALLOWLIST] = NetworkKind.HOST_ALLOWLIST
    enforcer_id: Identifier
    enforcer_digest: Digest
    resolution_policy_digest: Digest
    rules: tuple[NetworkRule, ...]

    @field_validator("rules")
    @classmethod
    def normalize_rules(cls, value: tuple[NetworkRule, ...]) -> tuple[NetworkRule, ...]:
        if not value:
            raise ValueError("host allowlist networking requires at least one rule")
        keys = [(rule.endpoint_id, rule.protocol, rule.port) for rule in value]
        if len(keys) != len(set(keys)):
            raise ValueError("host allowlist rules must be unique")
        return tuple(sorted(value, key=lambda rule: (rule.endpoint_id, rule.protocol, rule.port)))


NetworkPolicy = Annotated[NoNetwork | HostAllowlistNetwork, Field(discriminator="kind")]


class ResourceLimits(StrictModel):
    cpu_millicores: PositiveInt
    memory_bytes: PositiveInt
    pids: PositiveInt
    disk_bytes: PositiveInt
    wall_seconds: PositiveInt
    max_concurrency: PositiveInt = 1
    io_read_bytes_per_second: PositiveInt | None = None
    io_write_bytes_per_second: PositiveInt | None = None


class LicenseBinding(StrictModel):
    license_binding_id: Identifier
    provider_id: Identifier
    provider_digest: Digest
    feature_class: Identifier
    max_checkouts: PositiveInt = 1
    acquire_timeout_seconds: NonNegativeInt = 0
    lease_ttl_seconds: PositiveInt


class ArtifactDisclosure(StrictModel):
    sensitivity: Sensitivity
    visibility: Visibility
    redistribution: Redistribution

    @model_validator(mode="after")
    def validate_disclosure(self) -> Self:
        if self.sensitivity is Sensitivity.SECRET:
            raise ValueError("secret data cannot be retained as an artifact")
        if self.visibility is Visibility.PUBLIC and (
            self.sensitivity is not Sensitivity.PUBLIC
            or self.redistribution is not Redistribution.ALLOWED
        ):
            raise ValueError("public artifacts require public, redistributable content")
        return self


RAW_EDA_ARTIFACT_CLASSES = (ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE)
PROTECTED_RAW_DISCLOSURE = ArtifactDisclosure(
    sensitivity=Sensitivity.CONFIDENTIAL,
    visibility=Visibility.AUTHOR,
    redistribution=Redistribution.FORBIDDEN,
)


class NoEncryption(StrictModel):
    kind: Literal[EncryptionKind.NONE] = EncryptionKind.NONE


class ManagedEncryption(StrictModel):
    kind: Literal[EncryptionKind.MANAGED] = EncryptionKind.MANAGED
    provider_id: Identifier
    policy_digest: Digest


EncryptionPolicy = Annotated[NoEncryption | ManagedEncryption, Field(discriminator="kind")]


class ArtifactRetentionRule(StrictModel):
    artifact_class: ArtifactClass
    retention_seconds: NonNegativeInt
    allowed_disclosures: tuple[ArtifactDisclosure, ...]

    @field_validator("allowed_disclosures")
    @classmethod
    def normalize_disclosures(
        cls, value: tuple[ArtifactDisclosure, ...]
    ) -> tuple[ArtifactDisclosure, ...]:
        keys = [(item.sensitivity, item.visibility, item.redistribution) for item in value]
        if not value or len(keys) != len(set(keys)):
            raise ValueError("artifact disclosure choices must be unique and non-empty")
        return tuple(
            sorted(
                value,
                key=lambda item: (
                    item.sensitivity.value,
                    item.visibility.value,
                    item.redistribution.value,
                ),
            )
        )


class ArtifactPolicy(StrictModel):
    quota_bytes: PositiveInt
    encryption: EncryptionPolicy = NoEncryption()
    rules: tuple[ArtifactRetentionRule, ...]

    @field_validator("rules")
    @classmethod
    def normalize_rules(
        cls, value: tuple[ArtifactRetentionRule, ...]
    ) -> tuple[ArtifactRetentionRule, ...]:
        classes = [rule.artifact_class for rule in value]
        if len(classes) != len(set(classes)):
            raise ValueError("artifact classes must have exactly one retention rule")
        if set(classes) != set(ArtifactClass):
            raise ValueError("artifact policy must cover every artifact class")
        return tuple(sorted(value, key=lambda rule: rule.artifact_class.value))

    @model_validator(mode="after")
    def validate_encryption_requirement(self) -> Self:
        needs_encryption = any(
            disclosure.sensitivity is Sensitivity.CONFIDENTIAL
            for rule in self.rules
            for disclosure in rule.allowed_disclosures
        )
        if needs_encryption and isinstance(self.encryption, NoEncryption):
            raise ValueError("confidential or secret artifacts require managed encryption")
        return self

    def persistent_disclosure(
        self,
        artifact_class: ArtifactClass,
    ) -> ArtifactDisclosure | None:
        """Return the sole unambiguous retained disclosure for an artifact class."""

        rule = next(item for item in self.rules if item.artifact_class is artifact_class)
        if rule.retention_seconds == 0 or len(rule.allowed_disclosures) != 1:
            return None
        return rule.allowed_disclosures[0]


class EnvironmentSpec(StrictModel):
    schema_version: SchemaVersion = 1
    identity: EnvironmentIdentity
    executor: ExecutorSpec
    tool_bindings: tuple[ToolBinding, ...] = ()
    participant_operations: tuple[ParticipantOperationBinding, ...] = ()
    assets: tuple[AssetBinding, ...] = ()
    filesystem: FilesystemPolicy
    network: NetworkPolicy = NoNetwork()
    resources: ResourceLimits
    licenses: tuple[LicenseBinding, ...] = ()
    checkpoint: CheckpointCapability = CheckpointCapability.NONE
    application_checkpoint: ApplicationCheckpointBinding | None = None
    artifact_policy: ArtifactPolicy

    @field_validator("tool_bindings")
    @classmethod
    def normalize_tool_bindings(cls, value: tuple[ToolBinding, ...]) -> tuple[ToolBinding, ...]:
        return tuple(sorted(value, key=lambda binding: binding.capability.value))

    @field_validator("participant_operations")
    @classmethod
    def normalize_participant_operations(
        cls,
        value: tuple[ParticipantOperationBinding, ...],
    ) -> tuple[ParticipantOperationBinding, ...]:
        identifiers = [operation.operation_id for operation in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("participant operation identifiers must be unique")
        return tuple(sorted(value, key=lambda operation: operation.operation_id))

    @field_validator("assets")
    @classmethod
    def normalize_assets(cls, value: tuple[AssetBinding, ...]) -> tuple[AssetBinding, ...]:
        return tuple(sorted(value, key=lambda asset: asset.asset_id))

    @field_validator("licenses")
    @classmethod
    def normalize_licenses(cls, value: tuple[LicenseBinding, ...]) -> tuple[LicenseBinding, ...]:
        return tuple(sorted(value, key=lambda binding: binding.license_binding_id))

    @model_validator(mode="after")
    def validate_environment(self) -> Self:
        capabilities = [binding.capability for binding in self.tool_bindings]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("each logical capability may have at most one tool binding")
        if isinstance(self.executor, BrokeredHostToolExecutor):
            if any(
                not isinstance(binding.locator, AttestedHostToolLocator)
                for binding in self.tool_bindings
            ):
                raise ValueError("brokered host tools require attested host locators")
        else:
            image_digest = self.executor.image_digest
            if any(
                not isinstance(binding.locator, ImageToolLocator)
                or binding.locator.image_digest != image_digest
                for binding in self.tool_bindings
            ):
                raise ValueError(
                    "image-backed executors require locators in their exact image"
                )
        tools = {(binding.capability, binding.tool_id): binding for binding in self.tool_bindings}
        for operation in self.participant_operations:
            tool = tools.get((operation.capability, operation.tool_id))
            if tool is None:
                raise ValueError("participant operation does not name an exact tool binding")
            if isinstance(self.executor, BrokeredHostToolExecutor):
                raise ValueError("brokered executors cannot expose participant operations")
            if executable_is_shell(tool.locator.executable):
                raise ValueError("participant operations cannot execute a command interpreter")
            if any(
                self.artifact_policy.persistent_disclosure(output.artifact_class) is None
                for output in operation.outputs
            ):
                raise ValueError("participant operation outputs must be retainable artifacts")

        assets = {asset.asset_id: asset for asset in self.assets}
        if len(assets) != len(self.assets):
            raise ValueError("asset identifiers must be unique")
        for mount in self.filesystem.readonly_assets:
            asset = assets.get(mount.asset_id)
            if asset is None:
                raise ValueError("filesystem policy references an unknown asset")
            if mount.scope not in asset.allowed_scopes:
                raise ValueError("filesystem policy exceeds an asset's authorized scopes")

        licenses = {binding.license_binding_id: binding for binding in self.licenses}
        if len(licenses) != len(self.licenses):
            raise ValueError("license binding identifiers must be unique")
        feature_owners = [(binding.provider_id, binding.feature_class) for binding in self.licenses]
        if len(feature_owners) != len(set(feature_owners)):
            raise ValueError("provider feature classes must have one budget owner")
        referenced_licenses = {
            binding.license_binding_id
            for binding in self.tool_bindings
            if binding.license_binding_id is not None
        }
        if referenced_licenses - licenses.keys():
            raise ValueError("tool binding references an unknown license binding")
        if referenced_licenses != set(licenses):
            raise ValueError("every license binding must be owned by at least one tool")

        if licenses:
            if not isinstance(self.artifact_policy.encryption, ManagedEncryption):
                raise ValueError("licensed environments require managed artifact encryption")
            for artifact_class in RAW_EDA_ARTIFACT_CLASSES:
                rule = next(
                    item
                    for item in self.artifact_policy.rules
                    if item.artifact_class is artifact_class
                )
                if rule.retention_seconds == 0 or rule.allowed_disclosures != (
                    PROTECTED_RAW_DISCLOSURE,
                ):
                    raise ValueError(
                        "licensed tool diagnostics and evidence must be retained only as "
                        "confidential author artifacts"
                    )

        if self.checkpoint is CheckpointCapability.VIRTUAL_MACHINE and not isinstance(
            self.executor, (VmPerRunExecutor, MicrovmCloudExecutor)
        ):
            raise ValueError("virtual-machine checkpoints require a VM-backed executor")
        if (self.checkpoint is CheckpointCapability.APPLICATION) != (
            self.application_checkpoint is not None
        ):
            raise ValueError(
                "application checkpoint capability requires exactly one driver binding"
            )
        checkpoint_rule = next(
            rule
            for rule in self.artifact_policy.rules
            if rule.artifact_class is ArtifactClass.CHECKPOINT
        )
        if (
            self.checkpoint is not CheckpointCapability.NONE
            and checkpoint_rule.retention_seconds == 0
        ):
            raise ValueError("recoverable checkpoints require non-zero artifact retention")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="environment-spec-v1")
