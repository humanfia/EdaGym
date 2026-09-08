"""Qualification of complete configured filesystem views through their executor."""

from __future__ import annotations

import secrets
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import Field, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.execution import ExecutionPolicyError, ExecutionPolicyGap, project_environment
from edagym.config.model import ConfigView, ToolVisibility
from edagym.config.qualification import (
    ConfiguredToolResolution,
    ToolQualificationReceipt,
    resolve_profile_tools,
)
from edagym.config.resolve import ResolvedEnvironmentPair
from edagym.drivers.qualification import QualificationDisposition
from edagym.executors import view_probe
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.local import CollectionError, ExecutorUnavailable
from edagym.executors.model import (
    COMPOSITE_REPORT_LOGICAL_ID,
    COMPOSITE_REPORT_PATH,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobStateKind,
    OutputDeclaration,
    ToolRecipeCommand,
    WorkspaceRecipeCommand,
)
from edagym.executors.podman import (
    ROOTLESS_CONTROL_TARGETS,
    ROOTLESS_EMPTY_SECRET_TARGET,
    ROOTLESS_RUNTIME_FILE_TARGETS,
    ROOTLESS_TEMP_TARGETS,
    RootlessControlFile,
)
from edagym.executors.rootless import RootlessContainerExecutor
from edagym.executors.rootless_storage import RootlessStorageProvider
from edagym.implementation import FRAMEWORK_PACKAGE_ROOT
from edagym.policy.runtime_storage import private_directory, write_private
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass, Digest, Identifier, StrictModel
from edagym.specs.environment import EnvironmentSpec, FilesystemScope

VIEW_OBSERVATION_ID = "view_observation"
_OBSERVATION_PATH = "view-observation.json"
_REQUEST_PATH = "view-request.json"
_PROBE_PATH = "view-probe.py"
_MAX_OBSERVATION_BYTES = 32 * 1024 * 1024
_POLL_SECONDS = 0.05


class ViewQualificationGap(StrEnum):
    PROBE_FAILED = "view_probe_failed"
    ROOTFS_WRITABLE = "view_rootfs_writable"
    ENTRYPOINT_MISMATCH = "view_entrypoint_mismatch"
    FRAMEWORK_VISIBLE = "view_private_framework_visible"
    PRIVATE_SOURCE_VISIBLE = "view_private_source_visible"
    LIBRARY_MOUNT_MISMATCH = "view_library_mount_mismatch"
    UNDECLARED_MOUNT = "view_undeclared_mount"
    DEFAULT_SECRETS_VISIBLE = "view_default_secrets_visible"
    EXACT_TOOLSET_UNPROVEN = "exact_toolset_filesystem_evidence_required"
    RECOVERY_REQUIRED = "view_operation_recovery_required"


class _ViewRecoveryRequired(RuntimeError):
    """A durable invocation must be reconciled before its storage can be released."""


class ViewObservation(StrictModel):
    """Private complete image file inventory plus kernel mount observations.

    Program paths are an informative subset. Scripts without the executable bit,
    package files, symlinks, and dedicated libraries remain in rootfs_paths.
    A bundle grants the whole recorded image; tool grants do not hide its files.
    """

    rootfs_readonly: bool
    entrypoints_match: bool
    framework_absent: bool
    private_sources_absent: bool
    readonly_library_ids: tuple[Identifier, ...]
    rootfs_paths: tuple[str, ...] = Field(min_length=1, max_length=250_000)
    program_paths: tuple[str, ...]
    symlinks: dict[str, str]
    search_denied_directories: tuple[str, ...]
    unexpected_mounts: tuple[str, ...]
    default_secrets_empty: bool


class ViewQualificationReceipt(StrictModel):
    snapshot_digest: Digest
    view: ConfigView
    tool_visibility: ToolVisibility
    observed_at: datetime
    environment_digest: Digest | None = None
    evidence_id: Identifier | None = None
    tool_probes: tuple[ToolQualificationReceipt, ...] = ()
    observation_digest: Digest | None = None
    execution: ExecutionResult | None = None
    plan: InvocationPlan | None = None
    failure: ViewQualificationGap | ExecutionPolicyGap | None = None

    @property
    def disposition(self) -> QualificationDisposition:
        if (
            self.failure is not None or self.environment_digest is None
            or self.observation_digest is None or self.execution is None
            or self.evidence_id is None or self.plan is None
            or self.execution.state.state is not JobStateKind.COMPLETED
        ):
            return QualificationDisposition.UNAVAILABLE
        return QualificationDisposition.CONFORMANT

    @model_validator(mode="after")
    def validate_execution_binding(self) -> Self:
        if self.execution is not None and (
            self.plan is None
            or self.execution.state.handle.invocation_digest != self.plan.digest
            or self.execution.state.handle.job_id != self.plan.invocation_id
            or self.plan.view.value != self.view.value
        ):
            raise ValueError("view qualification result differs from its invocation")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="configured-view-qualification-v1")


def qualify_profile(pair: ResolvedEnvironmentPair) -> tuple[ViewQualificationReceipt, ...]:
    """Qualify both views with the same closure used for tool probes and launch."""

    resolutions = resolve_profile_tools(pair)
    return tuple(qualify_view(pair, view, resolutions) for view in ConfigView)


def qualify_view(
    pair: ResolvedEnvironmentPair,
    view: ConfigView,
    resolutions: tuple[ConfiguredToolResolution, ...],
) -> ViewQualificationReceipt:
    selected = pair.participant if view is ConfigView.PARTICIPANT else pair.evaluator
    root = private_directory(pair.site.state_root / "qualifications" / "views", create=True)
    receipt = ViewQualificationReceipt(
        snapshot_digest=pair.snapshot.digest,
        view=view,
        tool_visibility=selected.tool_visibility,
        observed_at=datetime.now(UTC),
        tool_probes=tuple(
            item.receipt for item in resolutions if item.receipt.view is view
        ),
    )
    try:
        environment = project_environment(pair, view, resolutions)
    except ExecutionPolicyError as error:
        receipt = receipt.model_copy(update={
            "failure": error.gap,
        })
    else:
        receipt = receipt.model_copy(update={"environment_digest": environment.digest})
        evidence_root = private_directory(root / f"probe_{secrets.token_hex(16)}", create=True)
        receipt = receipt.model_copy(update={"evidence_id": evidence_root.name})
        write_private(evidence_root / "snapshot.json", canonical_bytes(pair.snapshot))
        write_private(evidence_root / "environment.json", canonical_bytes(environment))
        try:
            plan, result, observation = _observe_view(
                pair, view, environment, resolutions, evidence_root,
            )
        except (
            _ViewRecoveryRequired, ExecutorUnavailable, CollectionError, OSError, ValueError,
        ) as error:
            write_private(evidence_root / "failure.json", canonical_bytes({
                "error_type": type(error).__name__, "message": str(error)[:8192],
            }))
            receipt = receipt.model_copy(update={
                "failure": (
                    ViewQualificationGap.RECOVERY_REQUIRED
                    if isinstance(error, _ViewRecoveryRequired)
                    else ViewQualificationGap.PROBE_FAILED
                ),
            })
        else:
            receipt = receipt.model_copy(update={
                "execution": result,
                "plan": plan,
                "observation_digest": canonical_digest(observation, domain="view-observation-v1"),
                "failure": _observation_failure(observation, selected.tool_visibility, environment),
            })
        write_private(evidence_root / "qualification.json", canonical_bytes(receipt))
    write_private(root / f"{receipt.digest[7:]}.json", canonical_bytes(receipt))
    return receipt


def _observation_failure(
    observation: ViewObservation,
    visibility: ToolVisibility,
    environment: EnvironmentSpec,
) -> ViewQualificationGap | None:
    for verified, failure in (
        (observation.rootfs_readonly, ViewQualificationGap.ROOTFS_WRITABLE),
        (observation.entrypoints_match, ViewQualificationGap.ENTRYPOINT_MISMATCH),
        (observation.framework_absent, ViewQualificationGap.FRAMEWORK_VISIBLE),
        (observation.private_sources_absent, ViewQualificationGap.PRIVATE_SOURCE_VISIBLE),
        (not observation.unexpected_mounts, ViewQualificationGap.UNDECLARED_MOUNT),
        (observation.default_secrets_empty, ViewQualificationGap.DEFAULT_SECRETS_VISIBLE),
        (
            observation.readonly_library_ids == tuple(item.asset_id for item in environment.assets),
            ViewQualificationGap.LIBRARY_MOUNT_MISMATCH,
        ),
    ):
        if not verified:
            return failure
    if visibility is ToolVisibility.EXACT_TOOLSET:
        # Enumerating a complete image proves the bundle contents, not that all
        # non-granted EDA programs and dedicated libraries have been excluded.
        return ViewQualificationGap.EXACT_TOOLSET_UNPROVEN
    return None


def _observe_view(
    pair: ResolvedEnvironmentPair,
    view: ConfigView,
    environment: EnvironmentSpec,
    resolutions: tuple[ConfiguredToolResolution, ...],
    root: Path,
) -> tuple[InvocationPlan, ExecutionResult, ViewObservation]:
    selected = pair.participant if view is ConfigView.PARTICIPANT else pair.evaluator
    observed = tuple(item for item in resolutions if item.receipt.view is view)
    capability = observed[0].capability
    assert capability is not None
    installations = {
        item.receipt.tool_id: item.installation
        for item in observed if item.installation is not None
    }
    store = ContentAddressedStore.open_private(root / "cas", policy=environment.artifact_policy)
    executor = RootlessContainerExecutor(
        executor_id=environment.executor.executor_id,
        implementation_digest=environment.executor.implementation_digest,
        capability=capability,
        tool_installations=installations,
        storage_provider=RootlessStorageProvider(maximum_quota_bytes=environment.resources.disk_bytes),
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=root / "jobs",
    )
    run_id = canonical_digest(
        {"snapshot": pair.snapshot.digest, "view": view, "probe_id": root.name},
        domain="view-qualification-run-v1",
    )
    operation_id = "view_inventory"
    storage_root = private_directory(
        (root if selected.storage.root is None else selected.storage.root / root.name) / "storage",
        create=True,
    )
    scope = (
        FilesystemScope.PARTICIPANT if view is ConfigView.PARTICIPANT else FilesystemScope.EVALUATOR
    )
    entrypoints = {}
    launcher = None
    for installation in installations.values():
        runtime = installation.execution_closure.rootless_image_runtime
        assert runtime is not None
        launcher = runtime.supervisor_entrypoint
        entrypoints[runtime.tool_entrypoint] = runtime.tool_entrypoint_digest
        for item in runtime.supporting_entrypoints:
            entrypoints[item.path] = item.content_digest
    assert launcher is not None
    canary = root / "private-controller-canary"
    write_private(canary, secrets.token_bytes(32))
    request = {
        "workspace": environment.filesystem.workspace_target,
        "artifacts": environment.filesystem.artifact_target,
        "entrypoints": entrypoints,
        "private_paths": (str(canary), str(FRAMEWORK_PACKAGE_ROOT)),
        "temporary_targets": ROOTLESS_TEMP_TARGETS,
        "runtime_files": ROOTLESS_RUNTIME_FILE_TARGETS,
        "empty_secret_target": ROOTLESS_EMPTY_SECRET_TARGET,
        "control_root": str(Path(
            ROOTLESS_CONTROL_TARGETS[RootlessControlFile.COMPOSITE_SUPERVISOR]
        ).parent),
        "control_files": (
            ROOTLESS_CONTROL_TARGETS[RootlessControlFile.COMPOSITE_SUPERVISOR],
            ROOTLESS_CONTROL_TARGETS[RootlessControlFile.COMPOSITE_RECIPE],
        ),
        "libraries": tuple(
            {"asset_id": item.asset_id, "target": item.target}
            for item in environment.filesystem.readonly_assets if item.scope is scope
        ),
    }
    source = f"#!{launcher}\n".encode() + Path(view_probe.__file__).read_bytes()
    input_document = {"source": source.hex(), "request": request}
    write_private(root / "input.json", canonical_bytes(input_document))
    binding = environment.tool_bindings[0]
    plan = InvocationPlan(
        invocation_id=operation_id, run_id=run_id,
        capability=binding.capability, tool_id=binding.tool_id, driver_digest=binding.driver_digest,
        view=(
            InvocationView.PARTICIPANT
            if view is ConfigView.PARTICIPANT else InvocationView.EVALUATOR
        ),
        executable=binding.locator.executable,
        input_manifest_digest=canonical_digest(
            input_document, domain="view-probe-input-v1",
        ),
        recipe=(
            ToolRecipeCommand(
                tool_id=binding.tool_id, capability=binding.capability,
                driver_digest=binding.driver_digest, executable=binding.locator.executable,
                arguments=installations[binding.tool_id].definition.version_arguments,
            ),
            WorkspaceRecipeCommand(
                executable=_PROBE_PATH, arguments=(_REQUEST_PATH, _OBSERVATION_PATH),
            ),
        ),
        outputs=(
            OutputDeclaration(
                logical_id=VIEW_OBSERVATION_ID, path=_OBSERVATION_PATH,
                media_type="application/json", artifact_class=ArtifactClass.EVIDENCE,
                required=False,
            ),
            OutputDeclaration(
                logical_id=COMPOSITE_REPORT_LOGICAL_ID, path=COMPOSITE_REPORT_PATH,
                media_type="application/json", artifact_class=ArtifactClass.EVIDENCE,
            ),
        ),
    )
    write_private(root / "plan.json", canonical_bytes(plan))
    lease = executor.create_storage(
        environment=environment, runtime_root=storage_root,
        run_id=run_id, invocation_id=operation_id,
    )
    result_committed = False
    handle = None
    try:
        (lease.workspace / _PROBE_PATH).write_bytes(source)
        (lease.workspace / _PROBE_PATH).chmod(0o700)
        (lease.workspace / _REQUEST_PATH).write_bytes(canonical_bytes(request))
        handle = executor.launch(
            plan, environment=environment, workspace=lease.workspace,
            artifact_directory=lease.artifact_directory,
            asset_paths=dict(selected.library_paths), scope=scope,
        )
        while executor.inspect(handle).state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
            time.sleep(_POLL_SECONDS)
        result = executor.collect(handle)
        write_private(root / "result.json", canonical_bytes(result))
        result_committed = True
        if result.state.state is not JobStateKind.COMPLETED:
            raise ExecutorUnavailable("view probe did not complete")
        output = next(
            (item for item in result.outputs if item.logical_id == VIEW_OBSERVATION_ID), None,
        )
        if output is None:
            raise ExecutorUnavailable("view probe produced no observation")
        observation = ViewObservation.model_validate_json(
            store.read_bytes(output.blob, maximum_bytes=_MAX_OBSERVATION_BYTES),
        )
        return plan, result, observation
    finally:
        try:
            if (root / "jobs" / operation_id).exists():
                # The executor persists this namespace before Podman creation.
                # Retain incomplete collection and its bounded storage so that
                # reconciliation can recover raw diagnostics and the outcome.
                if not result_committed:
                    if handle is not None:
                        executor.cancel(handle)
                    raise _ViewRecoveryRequired("view invocation has no committed result")
                executor.abandon(operation_id)
            lease.close()
        except (ExecutorUnavailable, OSError, ValueError) as error:
            raise _ViewRecoveryRequired("view invocation cleanup is incomplete") from error
