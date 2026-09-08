"""Execution projections derived from frozen profiles and observed installations.

Projection does not qualify tool visibility or task behavior. Callers must retain
the probe receipts and complete view qualification before admitting a task run.
"""

from __future__ import annotations

from enum import StrEnum

from edagym.canonical import canonical_digest
from edagym.config.model import ConfigView, UserImageToolSource, VerifierTrust
from edagym.config.qualification import ConfiguredToolResolution
from edagym.config.resolve import ResolvedEnvironmentPair
from edagym.executors.capabilities import ProviderAvailability
from edagym.run.artifacts import PRIVATE_ARTIFACT_KEY_PROVIDER_ID
from edagym.specs.common import ArtifactClass, Redistribution, Sensitivity, Visibility
from edagym.specs.environment import (
    PROTECTED_RAW_DISCLOSURE,
    RAW_EDA_ARTIFACT_CLASSES,
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    AssetBinding,
    EnvironmentIdentity,
    EnvironmentSpec,
    ExecutorKind,
    FilesystemPolicy,
    FilesystemScope,
    ImageToolLocator,
    ManagedEncryption,
    NetworkKind,
    ReadonlyAssetMount,
    ResourceLimits,
    RootlessLocalExecutor,
    ToolBinding,
)


class ExecutionPolicyGap(StrEnum):
    VIEW_UNAVAILABLE = "configured_view_unavailable"
    EXECUTOR_UNSUPPORTED = "configured_executor_unsupported"
    NETWORK_UNSUPPORTED = "configured_network_unsupported"
    VERIFIER_TRUST_UNSUPPORTED = "configured_verifier_trust_unsupported"
    LIMITS_REQUIRED = "configured_resource_limits_required"
    CPU_TIME_UNSUPPORTED = "configured_cpu_time_limit_unsupported"
    INODE_LIMIT_UNSUPPORTED = "configured_inode_limit_unsupported"
    ENVIRONMENT_UNSUPPORTED = "configured_tool_environment_unsupported"
    TOOL_EVIDENCE_MISMATCH = "configured_tool_evidence_mismatch"


class ExecutionPolicyError(ValueError):
    """A configured policy cannot be represented by the selected executor."""

    def __init__(self, gap: ExecutionPolicyGap) -> None:
        self.gap = gap
        super().__init__(gap.value)


def project_environment(
    pair: ResolvedEnvironmentPair,
    view: ConfigView,
    resolutions: tuple[ConfiguredToolResolution, ...],
    executor: RootlessLocalExecutor,
) -> EnvironmentSpec:
    """Bind profile grants and limits to the installations that actually probed.

    The executor's implementation identity comes from its deployment owner.
    Library paths and storage roots remain in the private resolved profile;
    neither is serialized into the path-free execution projection.
    """

    selected = pair.participant if view is ConfigView.PARTICIPANT else pair.evaluator
    profile = pair.snapshot.configuration.profiles[0]
    if not pair.site.available or not selected.available or selected.runtime is None:
        raise ExecutionPolicyError(ExecutionPolicyGap.VIEW_UNAVAILABLE)
    if pair.site.executor_kind is not ExecutorKind.ROOTLESS_LOCAL:
        raise ExecutionPolicyError(ExecutionPolicyGap.EXECUTOR_UNSUPPORTED)
    if selected.network is not NetworkKind.NONE:
        raise ExecutionPolicyError(ExecutionPolicyGap.NETWORK_UNSUPPORTED)
    if profile.verifier_trust is not VerifierTrust.SAME_ACCOUNT:
        raise ExecutionPolicyError(ExecutionPolicyGap.VERIFIER_TRUST_UNSUPPORTED)
    limits, storage = selected.resources, selected.storage
    if limits.cpu_seconds:
        raise ExecutionPolicyError(ExecutionPolicyGap.CPU_TIME_UNSUPPORTED)
    if storage.max_inodes:
        raise ExecutionPolicyError(ExecutionPolicyGap.INODE_LIMIT_UNSUPPORTED)
    if not all(
        (
            limits.cpu_millicores,
            limits.memory_bytes,
            limits.process_count,
            limits.wall_seconds,
            storage.max_bytes,
            storage.output_max_bytes,
        )
    ):
        raise ExecutionPolicyError(ExecutionPolicyGap.LIMITS_REQUIRED)
    observed = tuple(item for item in resolutions if item.receipt.view is view)
    by_tool = {item.receipt.tool_id: item for item in observed}
    if (
        not observed
        or len(by_tool) != len(observed)
        or set(by_tool) != {item.tool.tool_id for item in selected.tools}
    ):
        raise ExecutionPolicyError(ExecutionPolicyGap.TOOL_EVIDENCE_MISMATCH)
    if executor.image_digest != selected.runtime.image_digest:
        raise ExecutionPolicyError(ExecutionPolicyGap.TOOL_EVIDENCE_MISMATCH)
    bindings = []
    for tool in (item.tool for item in selected.tools):
        if tool.environment_reference_ids:
            raise ExecutionPolicyError(ExecutionPolicyGap.ENVIRONMENT_UNSUPPORTED)
        result = by_tool[tool.tool_id]
        receipt, installation, capability = result.receipt, result.installation, result.capability
        if (
            receipt.snapshot_digest != pair.snapshot.digest
            or receipt.failure is not None
            or installation is None
            or capability is None
            or capability.availability is not ProviderAvailability.AVAILABLE
            or capability.runtime is None
            or receipt.runtime_capability_digest != capability.digest
            or receipt.execution_closure_digest != installation.execution_closure_digest
            or installation.tool_id != tool.tool_id
            or installation.definition.tool_id != tool.adapter_id
            or installation.version_label != tool.version_label
            or not isinstance(tool.source, UserImageToolSource)
            or installation.executable_name != tool.source.executable
            or executor.runtime_version != capability.runtime.version
            or executor.runtime_probe_digest != capability.runtime.version_output_digest
            or executor.image_digest not in capability.image_digests
        ):
            raise ExecutionPolicyError(ExecutionPolicyGap.TOOL_EVIDENCE_MISMATCH)
        for granted in tool.capabilities:
            bindings.append(
                ToolBinding(
                    capability=granted,
                    tool_id=installation.tool_id,
                    tool_version=installation.version_label,
                    driver_id=installation.definition.tool_id,
                    driver_digest=installation.definition.driver_digest,
                    locator=ImageToolLocator(
                        image_digest=selected.runtime.image_digest,
                        executable=installation.executable_name,
                        deployment_attestation_digest=installation.deployment_attestation_digest,
                    ),
                )
            )
    scope = (
        FilesystemScope.PARTICIPANT if view is ConfigView.PARTICIPANT else FilesystemScope.EVALUATOR
    )
    disclosure = ArtifactDisclosure(
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.PARTICIPANT
        if view is ConfigView.PARTICIPANT
        else Visibility.VERIFIER,
        redistribution=Redistribution.FORBIDDEN,
    )
    libraries = {item.library_id: item for item in pair.snapshot.configuration.libraries}
    return EnvironmentSpec(
        identity=EnvironmentIdentity(
            environment_id=f"{view.value}_view",
            authoring_revision=1,
            provenance=(pair.snapshot.digest,),
        ),
        executor=executor,
        tool_bindings=tuple(bindings),
        assets=tuple(
            AssetBinding(
                asset_id=library_id,
                restricted_digest=libraries[library_id].content_digest,
                allowed_scopes=(scope,),
            )
            for library_id in selected.library_ids
        ),
        filesystem=FilesystemPolicy(
            workspace_target="/workspace",
            artifact_target="/artifacts",
            readonly_assets=tuple(
                ReadonlyAssetMount(
                    asset_id=library_id,
                    scope=scope,
                    target=f"/edagym-libraries/{library_id}",
                )
                for library_id in selected.library_ids
            ),
        ),
        resources=ResourceLimits(
            cpu_millicores=limits.cpu_millicores,
            memory_bytes=limits.memory_bytes,
            pids=limits.process_count,
            disk_bytes=storage.max_bytes,
            wall_seconds=limits.wall_seconds,
            max_concurrency=pair.site.max_concurrency,
        ),
        artifact_policy=ArtifactPolicy(
            quota_bytes=storage.output_max_bytes,
            encryption=ManagedEncryption(
                provider_id=PRIVATE_ARTIFACT_KEY_PROVIDER_ID,
                policy_digest=canonical_digest(
                    {"snapshot": pair.snapshot.digest, "view": view},
                    domain="private-artifact-key-policy-v1",
                ),
            ),
            rules=tuple(
                ArtifactRetentionRule(
                    artifact_class=kind,
                    retention_seconds=storage.retention_seconds,
                    allowed_disclosures=(
                        PROTECTED_RAW_DISCLOSURE
                        if kind in RAW_EDA_ARTIFACT_CLASSES
                        else disclosure,
                    ),
                )
                for kind in ArtifactClass
            ),
        ),
    )
