"""Private, configuration-bound tool probes preceding execution qualification."""

from __future__ import annotations

import base64
import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.model import ConfigView, ToolConfig, UserImageToolSource
from edagym.config.resolve import ResolvedEnvironmentPair, ResolvedEnvironmentView
from edagym.drivers.catalog import backend_by_id
from edagym.drivers.closure import (
    ExecutionClosureRequirementRef,
    execution_closure_digest,
    rootless_image_execution_closure,
)
from edagym.drivers.deployment import private_container_host_environment
from edagym.drivers.model import Vendor
from edagym.drivers.probe import (
    ResolvedInstallation,
    _version_identity,
    _version_label,
    _version_probe_digest,
)
from edagym.drivers.qualification import QualificationDisposition
from edagym.drivers.rootless_image import probe_rootless_image_tool
from edagym.executors.capabilities import (
    ProviderAvailability,
    RootlessContainerCapability,
    probe_rootless_container,
)
from edagym.policy.runtime_storage import private_directory, write_private
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.environment import ExecutorKind, NetworkKind


class ToolProbeGap(StrEnum):
    VIEW_UNAVAILABLE = "configured_view_unavailable"
    EXECUTOR_UNSUPPORTED = "executor_qualification_unavailable"
    SOURCE_UNSUPPORTED = "installed_tree_closure_required"
    ADAPTER_UNSUPPORTED = "adapter_qualification_unavailable"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    VERSION_MISMATCH = "configured_version_not_verified"
    ARCHITECTURE_MISMATCH = "configured_architecture_not_verified"
    LAUNCHER_UNAVAILABLE = "configured_launcher_probe_failed"
    ENTRYPOINT_UNAVAILABLE = "configured_entrypoint_unavailable"
    CLOSURE_UNAVAILABLE = "configured_execution_closure_unavailable"


class ToolQualificationReceipt(StrictModel):
    """A version probe is evidence, never complete view qualification."""

    snapshot_digest: Digest
    view: ConfigView
    tool_id: Identifier
    observed_at: datetime
    runtime_capability_digest: Digest | None = None
    version_output_digest: Digest | None = None
    execution_closure_digest: Digest | None = None
    failure: ToolProbeGap | None = None

    @property
    def disposition(self) -> QualificationDisposition:
        if (
            self.failure is not None
            or self.version_output_digest is None
            or self.execution_closure_digest is None
        ):
            return QualificationDisposition.UNAVAILABLE
        return QualificationDisposition.PROBE_ONLY

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="configured-tool-probe-v1")


@dataclass(frozen=True, slots=True, repr=False)
class ConfiguredToolResolution:
    """One probe's private evidence and the same installation used by execution."""

    receipt: ToolQualificationReceipt
    installation: ResolvedInstallation | None
    capability: RootlessContainerCapability | None


def resolve_profile_tools(pair: ResolvedEnvironmentPair) -> tuple[ConfiguredToolResolution, ...]:
    """Resolve configured tools once for both qualification and executor construction."""

    root = private_directory(pair.site.state_root / "qualifications", create=True)
    write_private(
        root / "snapshots" / f"{pair.snapshot.digest[7:]}.json",
        canonical_bytes(pair.snapshot) + b"\n",
    )
    resolutions = tuple(
        _probe_tool(pair, view, resolved_tool.tool, root)
        for view in (pair.participant, pair.evaluator)
        for resolved_tool in view.tools
    )
    for result in resolutions:
        receipt = result.receipt
        write_private(root / f"{receipt.digest[7:]}.json", canonical_bytes(receipt) + b"\n")
    return resolutions


def _probe_tool(
    pair: ResolvedEnvironmentPair,
    view: ResolvedEnvironmentView,
    tool: ToolConfig,
    root: Path,
) -> ConfiguredToolResolution:
    source = tool.source
    receipt = ToolQualificationReceipt(
        snapshot_digest=pair.snapshot.digest,
        view=view.view,
        tool_id=tool.tool_id,
        observed_at=datetime.now(UTC),
    )
    failure: ToolProbeGap | None = ToolProbeGap.RUNTIME_UNAVAILABLE
    version_digest = None
    runtime_capability_digest = None
    capability = None
    installation = None
    if not pair.site.available or not view.available:
        failure = ToolProbeGap.VIEW_UNAVAILABLE
    elif (
        pair.site.executor_kind != ExecutorKind.ROOTLESS_LOCAL
        or view.network is not NetworkKind.NONE
    ):
        failure = ToolProbeGap.EXECUTOR_UNSUPPORTED
    elif not isinstance(source, UserImageToolSource):
        failure = ToolProbeGap.SOURCE_UNSUPPORTED
    elif view.runtime is not None:
        try:
            adapter = backend_by_id(tool.adapter_id)
        except KeyError:
            adapter = None
        if (
            adapter is None
            or adapter.vendor is not Vendor.OPEN_SOURCE
            or source.executable not in adapter.executable_candidates
            or not set(tool.capabilities) <= set(adapter.capabilities)
        ):
            failure = ToolProbeGap.ADAPTER_UNSUPPORTED
        elif view.runtime.image_reference.endswith(f"@{source.image_digest}"):
            capability = probe_rootless_container(
                image_references={source.image_digest: view.runtime.image_reference}
            )
            if capability.availability is ProviderAvailability.AVAILABLE:
                runtime_capability_digest = capability.digest
                write_private(
                    root / "runtimes" / f"{capability.digest[7:]}.json",
                    canonical_bytes(capability) + b"\n",
                )
                installation, version_digest, failure = _resolve_installation(
                    pair, view, tool, root
                )
    receipt = receipt.model_copy(
        update={
            "version_output_digest": version_digest,
            "runtime_capability_digest": runtime_capability_digest,
            "execution_closure_digest": (
                None if installation is None else installation.execution_closure_digest
            ),
            "failure": failure,
        }
    )
    return ConfiguredToolResolution(receipt, installation, capability)


def _resolve_installation(
    pair: ResolvedEnvironmentPair,
    view: ResolvedEnvironmentView,
    tool: ToolConfig,
    root: Path,
) -> tuple[ResolvedInstallation | None, Digest | None, ToolProbeGap | None]:
    runtime = view.runtime
    source = tool.source
    assert runtime is not None and isinstance(source, UserImageToolSource)
    adapter = backend_by_id(tool.adapter_id)
    engine = Path("/usr/bin/podman")
    host_environment = private_container_host_environment()
    try:
        inspection = subprocess.run(
            (engine, "image", "inspect", "--format", "{{.Architecture}}", runtime.image_reference),
            env=host_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
        if inspection.returncode != 0 or inspection.stdout.strip().decode() != runtime.architecture:
            return None, None, ToolProbeGap.ARCHITECTURE_MISMATCH
        with tempfile.TemporaryDirectory(prefix="probe-", dir=root) as directory:
            probed = probe_rootless_image_tool(
                engine=engine,
                image_reference=runtime.image_reference,
                host_environment=host_environment,
                workspace=Path(directory),
                launcher_executable=runtime.launcher_executable,
                executable=source.executable,
                version_arguments=adapter.version_arguments,
                supporting_executables=adapter.supporting_executables,
            )
        if probed is None:
            return None, None, ToolProbeGap.LAUNCHER_UNAVAILABLE
        observation, probe_source = probed
        output = base64.b64decode(observation.version_output_base64, validate=True)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None, None, ToolProbeGap.LAUNCHER_UNAVAILABLE

    version_digest = f"sha256:{hashlib.sha256(output).hexdigest()}"
    write_private(root / "outputs" / version_digest[7:], output)
    observation_digest = canonical_digest(observation, domain="image-tool-observation-v1")
    write_private(
        root / "observations" / f"{observation_digest[7:]}.json",
        canonical_bytes(observation) + b"\n",
    )
    if (
        observation.entrypoint is None
        or observation.entrypoint_digest is None
        or tuple(item.executable for item in observation.supporting_entrypoints)
        != adapter.supporting_executables
    ):
        return None, version_digest, ToolProbeGap.ENTRYPOINT_UNAVAILABLE
    identity = _version_identity(output, adapter.version_identity_pattern)
    if (
        observation.exit_code not in adapter.accepted_version_exit_codes
        or identity is None
        or not identity.strip()
        or _version_label(identity) != tool.version_label
    ):
        return None, version_digest, ToolProbeGap.VERSION_MISMATCH
    probe_source_digest = f"sha256:{hashlib.sha256(probe_source).hexdigest()}"
    requirement_document = {
        "snapshot_digest": pair.snapshot.digest,
        "view": view.view,
        "tool_id": tool.tool_id,
        "observation_digest": observation_digest,
        "probe_source_digest": probe_source_digest,
    }
    requirement = ExecutionClosureRequirementRef(
        requirement_id=tool.tool_id,
        requirement_digest=canonical_digest(
            requirement_document, domain="configured-image-tool-closure-v1"
        ),
    )
    write_private(root / "sources" / probe_source_digest[7:], probe_source)
    write_private(
        root / "requirements" / f"{requirement.requirement_digest[7:]}.json",
        canonical_bytes(requirement_document) + b"\n",
    )
    try:
        closure = rootless_image_execution_closure(
            requirement,
            engine=engine,
            host_environment=host_environment,
            image_reference=runtime.image_reference,
            image_digest=runtime.image_digest,
            tool_entrypoint=observation.entrypoint,
            tool_entrypoint_digest=observation.entrypoint_digest,
            supervisor_entrypoint=observation.launcher_entrypoint,
            supporting_entrypoints=observation.supporting_entrypoints,
        )
    except (OSError, ValueError):
        return None, version_digest, ToolProbeGap.CLOSURE_UNAVAILABLE
    if closure is None or not closure.revalidate():
        return None, version_digest, ToolProbeGap.CLOSURE_UNAVAILABLE
    installation = ResolvedInstallation(
        definition=adapter,
        tool_id=tool.tool_id,
        module_name=None,
        executable_name=source.executable,
        environment=host_environment,
        version_label=tool.version_label,
        modulefile_digest=None,
        version_output_digest=_version_probe_digest(
            adapter,
            executable_name=source.executable,
            executable_digest=observation.entrypoint_digest,
            module_name=None,
            modulefile_digest=None,
            version_label=tool.version_label,
            version_identity=identity,
            execution_closure_digest=execution_closure_digest(closure.evidence),
        ),
        execution_closure=closure,
        deployment_record_digest=requirement.requirement_digest,
    )
    write_private(
        root / "closures" / f"{installation.execution_closure_digest[7:]}.json",
        canonical_bytes(closure.evidence) + b"\n",
    )
    return installation, version_digest, None
