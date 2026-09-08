"""Digest-bound rootless container execution for participant-controlled work."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import IO, TYPE_CHECKING, Literal

from pydantic import TypeAdapter, field_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers.model import ExecutableInvocationMode
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.capabilities import (
    LOCAL_ENV_PATH,
    ProviderAvailability,
    RootlessContainerCapability,
)
from edagym.executors.isolation_launch import (
    SyntheticIsolationPreflightExecution,
    SyntheticPreflightLaunchCapability,
    SyntheticPreflightParentReceipt,
    SyntheticPreflightProbeLaunchReceipt,
    _issue_synthetic_isolation_preflight_execution,
    _SyntheticPreflightLaunchClaim,
)
from edagym.executors.isolation_preflight import (
    ISOLATION_PROBE_IMPLEMENTATION_DIGEST,
    ISOLATION_PROBE_SURFACE,
    IsolationPreflightExecution,
    IsolationPreflightReceipt,
    IsolationProbeReceipt,
    IsolationProbeRole,
    _issue_isolation_preflight_execution,
    isolation_probe_plan,
    validate_isolation_probe_execution,
)
from edagym.executors.licenses import LicenseLease
from edagym.executors.local import (
    CollectionError,
    ExecutorUnavailable,
    UnknownJob,
    _bind_asset_closure,
    _collect_execution_result,
    _disclosure_for,
    _forget_isolation,
    _open_owned_directory,
    _remove_invocation_transient_files,
    _revalidate_bound_assets,
    _sealed_environment_file,
    _systemd_launch_environment,
    _systemd_scope_command,
    _systemd_unit_is_quiescent,
    _systemd_unit_result,
    _systemd_unit_state,
    _terminate_isolation,
    _validate_plan_binding,
    _validate_scope,
    _write_private_transient_file,
)
from edagym.executors.model import (
    COMPOSITE_REPORT_PATH,
    EnvironmentEntry,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    JobHandle,
    JobState,
    JobStateKind,
    ToolRecipeCommand,
    WorkspaceRecipeCommand,
)
from edagym.executors.podman import (
    ROOTLESS_CONTROL_TARGETS,
    PodmanCommand,
    PodmanContainment,
    RootlessControlFile,
    rootless_podman_command,
    rootless_resources_supported,
)
from edagym.executors.protocol import InvocationStorageReceipt
from edagym.executors.rootless_storage import (
    RootlessStorageLease,
    RootlessStorageProvider,
)
from edagym.policy.runtime_storage import private_directory, read_private, write_private
from edagym.run.artifacts import ContentAddressedStore
from edagym.runtime_surface_protocol import IsolationSurface
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
)
from edagym.specs.environment import (
    ContainerRuntime,
    EnvironmentSpec,
    FilesystemScope,
    ImageToolLocator,
    NoNetwork,
    RootlessLocalExecutor,
)

if TYPE_CHECKING:
    from edagym.drivers.probe import ResolvedInstallation

_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)
_DIGEST_ADAPTER = TypeAdapter(Digest)
_COMPOSITE_SUPERVISOR_PATH = Path(__file__).with_name("composite_driver.py")
_ROOTLESS_CONTROL_PROTOCOL = "scoped-podman-v2"
_CONTAINER_OWNER_LABEL = "io.edagym.execution"
_CONTAINER_RUN_LABEL = "io.edagym.run"
_CONTAINER_OPERATION_LABEL = "io.edagym.operation"
_CONTAINER_ENVIRONMENT_LABEL = "io.edagym.environment"
_CONTROL_PLANE_TIMEOUT_SECONDS = 10
_QUIESCENCE_TIMEOUT_SECONDS = 5.0
_QUIESCENCE_POLL_SECONDS = 0.05
_PRIVATE_DIRECTORY_MODE = 0o700


class RootlessResourceKind(StrEnum):
    CONTAINER = "container"
    CONTAINMENT_SCOPE = "containment_scope"


class _ContainerStatus(StrEnum):
    CONFIGURED = "configured"
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    EXITED = "exited"
    STOPPED = "stopped"
    STOPPING = "stopping"
    REMOVING = "removing"


class _ContainerObservation(StrictModel):
    container_id: str
    status: _ContainerStatus
    running: bool
    exit_code: int
    error: str
    oom_killed: bool
    started_at: datetime
    finished_at: datetime
    process_cgroup: str | None

    @property
    def active(self) -> bool:
        return self.running or self.status in {
            _ContainerStatus.RUNNING, _ContainerStatus.PAUSED,
            _ContainerStatus.STOPPING, _ContainerStatus.REMOVING,
        }


class _InvocationBinding(StrictModel):
    """Execution identity derivable from the durable prepared operation."""

    plan: InvocationPlan
    environment: EnvironmentSpec

    @property
    def handle(self) -> JobHandle:
        return JobHandle(
            job_id=self.plan.invocation_id,
            invocation_digest=self.plan.digest,
            executor_id=self.environment.executor.executor_id,
        )

    @property
    def owner(self) -> Digest:
        return canonical_digest(
            {"environment_digest": self.environment.digest, "handle": self.handle},
            domain="rootless-container-owner-v2",
        )

    @property
    def container_name(self) -> str:
        return f"edagym-{self.owner.removeprefix('sha256:')}"

    @property
    def scope_unit(self) -> str:
        return f"{self.container_name}.scope"

    @property
    def labels(self) -> dict[str, str]:
        return {
            _CONTAINER_OWNER_LABEL: self.owner,
            _CONTAINER_RUN_LABEL: self.plan.run_id,
            _CONTAINER_OPERATION_LABEL: self.plan.invocation_id,
            _CONTAINER_ENVIRONMENT_LABEL: self.environment.digest,
        }


class _InvocationReceipt(_InvocationBinding):
    """Private launch inputs persisted before creating an owned container."""

    schema_version: Literal[1] = 1
    workspace: Path
    artifact_directory: Path
    storage: InvocationStorageReceipt | None


class _ScopeAttachment(StrictModel):
    """A kernel observation binding the container payload to its delegated scope."""

    container_id: str
    cgroup_path: str


class RootlessIsolationCleanup(StrictModel):
    """Authoritative local control-plane observation after rootless cleanup."""

    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    observation_digest: Digest
    remaining_resources: tuple[RootlessResourceKind, ...] = ()

    @field_validator("remaining_resources")
    @classmethod
    def normalize_resources(
        cls,
        value: tuple[RootlessResourceKind, ...],
    ) -> tuple[RootlessResourceKind, ...]:
        if len(value) != len(set(value)):
            raise ValueError("rootless cleanup resources must be unique")
        return tuple(sorted(value, key=lambda resource: resource.value))


class RootlessContainerExecutor:
    """Execute only exact installations inside an immutable rootless image."""

    def __init__(
        self,
        *,
        executor_id: str,
        implementation_digest: str,
        capability: RootlessContainerCapability,
        tool_installations: Mapping[str, ResolvedInstallation],
        storage_provider: RootlessStorageProvider,
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
        job_state_root: Path,
    ) -> None:
        if (
            capability.availability is not ProviderAvailability.AVAILABLE
            or capability.runtime is None
            or not tool_installations
        ):
            raise ExecutorUnavailable("rootless container capability is unavailable")
        self.executor_id = _IDENTIFIER_ADAPTER.validate_python(executor_id)
        self._implementation_digest = _DIGEST_ADAPTER.validate_python(implementation_digest)
        self._capability = capability
        self._installations = MappingProxyType(dict(tool_installations))
        self._storage_provider = storage_provider
        self._storage_leases: dict[str, RootlessStorageLease] = {}
        self._storage_lock = threading.Lock()
        self._artifact_store = artifact_store
        self._supervisor_bytes = _read_supervisor_bytes(_COMPOSITE_SUPERVISOR_PATH)
        self._supervisor_digest = _content_digest(self._supervisor_bytes)
        runtimes = []
        for tool_id, installation in self._installations.items():
            runtime = installation.execution_closure.rootless_image_runtime
            if (
                tool_id != installation.tool_id
                or installation.executable_invocation_mode
                is not ExecutableInvocationMode.ROOTLESS_IMAGE
                or runtime is None
                or runtime.image_digest not in capability.image_digests
                or installation.execution_closure.host_entrypoint_digest
                != capability.runtime.executable_digest
                or not installation.execution_closure.revalidate()
            ):
                raise ExecutorUnavailable("rootless installation closure is invalid")
            runtimes.append(runtime)
        first = runtimes[0]
        if any(
            runtime.engine_path != first.engine_path
            or runtime.host_environment != first.host_environment
            for runtime in runtimes[1:]
        ):
            raise ExecutorUnavailable("rootless installations require one runtime owner")
        self._runtime = first
        if type(asset_source_policy) is not AssetSourcePolicy:
            raise ExecutorUnavailable("executor requires trusted asset source authority")
        self._asset_source_policy = asset_source_policy
        self._job_state_root = private_directory(job_state_root, create=True)
        self._lock = threading.RLock()
        write_private(self._job_state_root / ".provider.lock", b"")

    @property
    def isolation_capability_digest(self) -> Digest:
        return canonical_digest(
            {
                "executor_implementation_digest": self._implementation_digest,
                "runtime_capability_digest": self._capability.digest,
                "supervisor_digest": self._supervisor_digest,
                "control_protocol": _ROOTLESS_CONTROL_PROTOCOL,
            },
            domain="rootless-isolation-capability-v1",
        )

    @property
    def storage_capability_digest(self) -> Digest:
        return self._storage_provider.capability_digest

    def create_storage(
        self,
        *,
        environment: EnvironmentSpec,
        runtime_root: Path,
        run_id: Digest,
        invocation_id: str,
    ) -> RootlessStorageLease:
        """Issue the only writable substrate accepted by participant launch."""

        self._validate_environment(environment)
        normalized = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        with self._storage_lock:
            existing = self._storage_leases.get(normalized)
            if existing is not None and existing.active:
                raise ExecutorUnavailable("rootless invocation already owns writable storage")
            lease = self._storage_provider.create(
                runtime_root=runtime_root,
                invocation_id=normalized,
                run_id=run_id,
                environment_spec_digest=environment.digest,
                executor_id=self.executor_id,
                executor_implementation_digest=self._implementation_digest,
                maximum_bytes=environment.resources.disk_bytes,
            )
            self._storage_leases[normalized] = lease
            return lease

    def recover_storage(
        self,
        *,
        environment: EnvironmentSpec,
        runtime_root: Path,
        run_id: Digest,
        invocation_id: str,
    ) -> RootlessStorageLease | None:
        """Reopen an existing durable writable substrate after controller loss."""

        self._validate_environment(environment)
        normalized = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        with self._storage_lock:
            existing = self._storage_leases.get(normalized)
            if existing is not None and existing.active:
                return existing
            lease = self._storage_provider.recover(
                runtime_root=runtime_root,
                invocation_id=normalized,
                run_id=run_id,
                environment_spec_digest=environment.digest,
                executor_id=self.executor_id,
                executor_implementation_digest=self._implementation_digest,
                maximum_bytes=environment.resources.disk_bytes,
            )
            if lease is not None:
                self._storage_leases[normalized] = lease
            return lease

    def launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: dict[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None = None,
    ) -> JobHandle:
        handle, parent_launch_digest = self._launch(
            plan,
            environment=environment,
            workspace=workspace,
            artifact_directory=artifact_directory,
            asset_paths=asset_paths,
            scope=scope,
            license_lease=license_lease,
            fixed_probe=False,
            synthetic_claim=None,
        )
        if parent_launch_digest is not None:
            raise ExecutorUnavailable("ordinary launch returned synthetic parent evidence")
        return handle

    def _launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: Mapping[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None,
        fixed_probe: bool,
        synthetic_claim: _SyntheticPreflightLaunchClaim | None,
    ) -> tuple[JobHandle, Digest | None]:
        with self._guard():
            return self._launch_locked(
                plan,
                environment=environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                asset_paths=asset_paths,
                scope=scope,
                license_lease=license_lease,
                fixed_probe=fixed_probe,
                synthetic_claim=synthetic_claim,
            )

    def _launch_locked(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: Mapping[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None,
        fixed_probe: bool,
        synthetic_claim: _SyntheticPreflightLaunchClaim | None,
    ) -> tuple[JobHandle, Digest | None]:
        self._validate_environment(environment)
        if fixed_probe is not (synthetic_claim is not None):
            raise ExecutorUnavailable("synthetic launch authority differs from probe mode")
        if license_lease is not None:
            raise ExecutorUnavailable("license leases cannot enter participant containers")
        if fixed_probe:
            if plan.driver_digest != ISOLATION_PROBE_IMPLEMENTATION_DIGEST:
                raise ExecutorUnavailable("rootless isolation probe closure is invalid")
        else:
            _validate_plan_binding(plan, environment)
        _validate_scope(plan, scope)
        storage_lease = None if fixed_probe else self._require_storage_lease(
            plan,
            environment=environment,
            workspace=workspace,
            artifact_directory=artifact_directory,
        )
        if fixed_probe:
            _require_private_directory(workspace)
            _require_private_directory(artifact_directory)
        asset_snapshots = _bind_asset_closure(
            source_policy=self._asset_source_policy,
            protected_paths=(self._artifact_store.root, self._job_state_root),
            environment=environment,
            asset_paths=asset_paths,
            scope=scope,
            writable_paths=(workspace, artifact_directory),
        )
        bound_assets = MappingProxyType(
            {asset_id: snapshot.path for asset_id, snapshot in asset_snapshots.items()}
        )
        selected = self._installations_for_environment(environment)
        image_runtime = next(iter(selected.values())).execution_closure.rootless_image_runtime
        assert image_runtime is not None
        receipt = _InvocationReceipt(
            plan=plan,
            environment=environment,
            workspace=workspace,
            artifact_directory=artifact_directory,
            storage=None if storage_lease is None else storage_lease.receipt,
        )
        directory = self._job_directory(plan.invocation_id)
        if directory.exists():
            existing = self._load_invocation(plan.invocation_id)
            if (
                existing.plan != plan or existing.environment != environment
                or existing.workspace != workspace
                or existing.artifact_directory != artifact_directory
                or existing.storage is None or receipt.storage is None
                or existing.storage.run_id != receipt.storage.run_id
                or existing.storage.storage_instance_digest
                != receipt.storage.storage_instance_digest
            ):
                raise ExecutorUnavailable("invocation already owns another execution binding")
            _revalidate_bound_assets(
                asset_snapshots,
                protected_paths=(self._artifact_store.root, self._job_state_root),
                writable_paths=(workspace, artifact_directory),
            )
            state = self._state(existing)
            if state.state is JobStateKind.QUEUED:
                self._start_container(existing)
            return existing.handle, None
        self._require_concurrency_slot(environment)
        private_directory(directory, create=True)
        write_private(directory / "invocation.json", canonical_bytes(receipt))
        environment_fd: int | None = None
        runtime_descriptor: int | None = None
        try:
            control_files: Mapping[RootlessControlFile, Path] | None = None
            arguments: tuple[str, ...]
            if plan.recipe:
                recipe = self._resolved_recipe(plan, environment, selected)
                supervisor = _write_private_transient_file(
                    self._job_state_root,
                    plan.invocation_id,
                    "rootless-supervisor",
                    self._supervisor_bytes,
                )
                recipe_file = _write_private_transient_file(
                    self._job_state_root,
                    plan.invocation_id,
                    "rootless-recipe",
                    canonical_bytes(recipe),
                )
                control_files = MappingProxyType(
                    {
                        RootlessControlFile.COMPOSITE_SUPERVISOR: supervisor.path,
                        RootlessControlFile.COMPOSITE_RECIPE: recipe_file.path,
                    }
                )
                executable = image_runtime.supervisor_entrypoint
                arguments = (
                    ROOTLESS_CONTROL_TARGETS[RootlessControlFile.COMPOSITE_SUPERVISOR],
                    ROOTLESS_CONTROL_TARGETS[RootlessControlFile.COMPOSITE_RECIPE],
                    COMPOSITE_REPORT_PATH,
                )
            elif fixed_probe:
                executable = "/bin/sh"
                arguments = plan.arguments
            else:
                installation = self._require_plan_installation(plan, environment)
                runtime = installation.execution_closure.rootless_image_runtime
                assert runtime is not None
                executable = runtime.tool_entrypoint
                arguments = plan.arguments
                environment_fd = _sealed_environment_file(plan.environment)
            runtime_evidence = self._capability.runtime
            if runtime_evidence is None:
                raise ExecutorUnavailable("rootless runtime evidence disappeared")
            runtime_descriptor = _open_runtime_descriptor(
                self._runtime.engine_path,
                runtime_evidence.executable_digest,
            )
            runtime_path = Path(f"/proc/self/fd/{runtime_descriptor}")
            podman_command = rootless_podman_command(
                podman_path=runtime_path,
                resources=environment.resources,
                filesystem=environment.filesystem,
                workspace=workspace,
                artifact_directory=artifact_directory,
                temporary_directory=(
                    None if storage_lease is None else storage_lease.temporary_directory
                ),
                asset_paths=bound_assets,
                scope=scope,
                image=image_runtime.image_reference,
                environment_fd=environment_fd,
                executable=executable,
                arguments=arguments,
                working_directory=plan.working_directory,
                exact_entrypoint=True,
                hermetic_process_environment=True,
                container_name=receipt.container_name,
                container_labels=receipt.labels,
                control_files=control_files,
                command_kind=PodmanCommand.CREATE,
                cidfile=self._container_receipt_path(plan.invocation_id),
                log_max_bytes=environment.artifact_policy.quota_bytes,
                containment=PodmanContainment.DELEGATED_SCOPE,
            )
            create_command = (
                os.fspath(LOCAL_ENV_PATH),
                "--argv0=/usr/bin/podman",
                *podman_command,
            )
            _revalidate_bound_assets(
                asset_snapshots,
                protected_paths=(self._artifact_store.root, self._job_state_root),
                writable_paths=(workspace, artifact_directory),
            )
            if not all(
                installation.execution_closure.revalidate() for installation in selected.values()
            ):
                raise ExecutorUnavailable("rootless installation changed before launch")
            pass_fds: tuple[int, ...] = (runtime_descriptor,)
            if environment_fd is not None:
                pass_fds += (environment_fd,)
            process_environment = self._runtime.host_environment
            parent_launch_digest: Digest | None = None
            parent_launch_digest = self._create_container(
                command=create_command,
                process_environment=process_environment,
                workspace=workspace,
                pass_fds=pass_fds,
                invocation_id=plan.invocation_id,
                synthetic_claim=synthetic_claim,
            )
            self._start_container(receipt)
            if synthetic_claim is not None and parent_launch_digest is None:
                raise ExecutorUnavailable("synthetic parent launch was not observed")
            return receipt.handle, parent_launch_digest
        finally:
            if environment_fd is not None:
                os.close(environment_fd)
            if runtime_descriptor is not None:
                os.close(runtime_descriptor)

    def inspect(self, handle: JobHandle) -> JobState:
        with self._guard():
            return self._state(self._invocation_for(handle))

    def cancel(
        self, handle: JobHandle, *, reason: ExecutionFailureKind = ExecutionFailureKind.CANCELLED
    ) -> JobState:
        if reason not in {ExecutionFailureKind.CANCELLED, ExecutionFailureKind.TIMEOUT}:
            raise ValueError("rootless stop requires cancellation or timeout")
        with self._guard():
            receipt = self._invocation_for(handle)
            state = self._state(receipt)
            if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                write_private(
                    self._job_directory(handle.job_id) / "stop.json",
                    canonical_bytes(reason),
                )
                self._stop_container(receipt)
                return self._state(receipt)
            return state

    def collect(self, handle: JobHandle) -> ExecutionResult:
        with self._guard():
            receipt = self._invocation_for(handle)
            result_path = self._job_directory(handle.job_id) / "result.json"
            if result_path.exists():
                content = read_private(result_path)
                result = ExecutionResult.model_validate_json(content)
                if (
                    canonical_bytes(result) != content
                    or result.state != self._state(receipt)
                ):
                    raise CollectionError("durable result belongs to another invocation")
                for blob in (result.stdout, result.stderr, *(item.blob for item in result.outputs)):
                    self._artifact_store.verify(blob)
                return result
            state = self._state(receipt)
            if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                raise CollectionError("job output cannot be collected before termination")
            if state.state is JobStateKind.LOST:
                raise CollectionError("container outcome is unknown; no result can be collected")
            self._validate_collection_storage(receipt)
            installations = self._installations_for_environment(receipt.environment)
            if not all(item.execution_closure.revalidate() for item in installations.values()):
                raise CollectionError("tool execution closure changed during execution")
            stdout_path, stderr_path = self._capture_logs(receipt)
            workspace = _open_owned_directory(receipt.workspace)
            try:
                artifacts = _open_owned_directory(receipt.artifact_directory)
                try:
                    result = _collect_execution_result(
                        plan=receipt.plan,
                        environment=receipt.environment,
                        artifact_store=self._artifact_store,
                        workspace_descriptor=workspace,
                        artifact_directory_descriptor=artifacts,
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                        state=state,
                    )
                finally:
                    os.close(artifacts)
            finally:
                os.close(workspace)
            write_private(result_path, canonical_bytes(result))
            return result

    def abandon(self, invocation_id: str) -> None:
        self.cleanup(invocation_id)

    def recover_result(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        storage_available: bool,
        required: bool = True,
    ) -> ExecutionResult | None:
        """Recover retained results or fence an operation whose outcome is unknown.

        Only a newly prepared operation may omit its invocation namespace. A
        replayed preparation with lost launch evidence cannot authorize launch.
        LOST diagnostics contain only bytes retained or recovered during fencing;
        an empty stream means no bytes were retained, not that execution was quiet.
        """
        with self._guard():
            directory = self._job_directory(plan.invocation_id)
            if not directory.exists() and not required:
                return None
            binding = self._recovery_binding(plan, environment)
            result_path = directory / "result.json"
            if result_path.exists():
                content = read_private(result_path)
                result = ExecutionResult.model_validate_json(content)
                if (
                    canonical_bytes(result) != content or result.state.handle != binding.handle
                    or result.state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}
                ):
                    raise CollectionError("retained result differs from its prepared operation")
                for blob in (result.stdout, result.stderr, *(item.blob for item in result.outputs)):
                    self._artifact_store.verify(blob)
                if result.state.state is not JobStateKind.LOST:
                    observation = self._observe(binding)
                    if not _systemd_unit_is_quiescent(binding.scope_unit) or (
                        observation is not None and observation.active
                        and not self._scope_terminated(binding, observation)
                    ):
                        raise CollectionError("retained result has active runtime resources")
                    if (
                        isinstance(binding, _InvocationReceipt)
                        and self._state(binding) != result.state
                    ):
                        raise CollectionError(
                            "retained result differs from its runtime observation"
                        )
                if result.state.state is JobStateKind.LOST:
                    self._fence(binding)
                return result
            state = None
            terminal_path = directory / "terminal.json"
            if terminal_path.exists():
                content = read_private(terminal_path)
                state = JobState.model_validate_json(content)
                if canonical_bytes(state) != content or state.handle != binding.handle:
                    raise ExecutorUnavailable("terminal observation differs from its operation")
            if isinstance(binding, _InvocationReceipt) and (
                state is None or state.state is not JobStateKind.LOST
            ):
                state = self._state(binding)
            if (
                storage_available and state is not None and state.state is not JobStateKind.LOST
                and isinstance(binding, _InvocationReceipt)
            ):
                return None
            # Verify the container identity before touching its delegated scope.
            observation = self._observe(binding)
            self._stop_container(binding)
            if observation is not None:
                self._capture_logs(binding)
            diagnostics = []
            disclosure = _disclosure_for(environment, ArtifactClass.DIAGNOSTIC)
            for name in ("stdout.bin", "stderr.bin"):
                path = directory / name
                content = (
                    read_private(path, max_bytes=environment.artifact_policy.quota_bytes)
                    if path.exists() else b""
                )
                diagnostics.append(self._artifact_store.put_bytes(
                    content,
                    artifact_class=ArtifactClass.DIAGNOSTIC,
                    sensitivity=disclosure.sensitivity,
                    visibility=disclosure.visibility,
                    redistribution=disclosure.redistribution,
                ))
            self._fence(binding)
            result = ExecutionResult(
                state=JobState(
                    handle=binding.handle,
                    state=JobStateKind.LOST,
                    exit_code=None if state is None else state.exit_code,
                    failure=ExecutionFailureKind.INFRASTRUCTURE,
                ),
                stdout=diagnostics[0], stderr=diagnostics[1],
            )
            write_private(result_path, canonical_bytes(result))
            return result

    def fence(
        self, plan: InvocationPlan, *, environment: EnvironmentSpec
    ) -> RootlessIsolationCleanup:
        """Release only resources owned by this frozen operation, without relaunch."""
        with self._guard():
            binding = self._recovery_binding(plan, environment)
            cleanup = self._fence(binding)
            _remove_invocation_transient_files(self._job_state_root, plan.invocation_id)
            self._remove_raw_logs(plan.invocation_id)
            return cleanup

    def _recovery_binding(
        self, plan: InvocationPlan, environment: EnvironmentSpec
    ) -> _InvocationBinding:
        self._validate_environment(environment)
        _validate_plan_binding(plan, environment)
        directory = private_directory(self._job_directory(plan.invocation_id), create=True)
        if (directory / "invocation.json").exists():
            receipt = self._load_invocation(plan.invocation_id)
            if receipt.plan != plan or receipt.environment != environment:
                raise ExecutorUnavailable("recovery differs from the frozen invocation")
            return receipt
        return _InvocationBinding(plan=plan, environment=environment)

    def cleanup(self, invocation_id: str) -> RootlessIsolationCleanup:
        with self._guard():
            receipt = self._load_invocation(invocation_id)
            cleanup = self._fence(receipt)
            _remove_invocation_transient_files(self._job_state_root, invocation_id)
            self._remove_raw_logs(invocation_id)
            return cleanup

    def _fence(self, binding: _InvocationBinding) -> RootlessIsolationCleanup:
        self._owned_container(binding)
        _terminate_isolation(binding.scope_unit)
        self._remove_container(binding)
        _forget_isolation(binding.scope_unit)
        observation = self._owned_container(binding)
        remaining = []
        if observation is not None:
            remaining.append(RootlessResourceKind.CONTAINER)
        if not _systemd_unit_is_quiescent(binding.scope_unit):
            remaining.append(RootlessResourceKind.CONTAINMENT_SCOPE)
        cleanup = RootlessIsolationCleanup(
            invocation_id=binding.plan.invocation_id,
            observation_digest=canonical_digest(
                {"owner": binding.owner, "remaining": remaining},
                domain="rootless-cleanup-observation-v2",
            ),
            remaining_resources=tuple(remaining),
        )
        if remaining:
            raise ExecutorUnavailable("operation fencing did not prove resource absence")
        return cleanup

    def execute_isolation_preflight(
        self,
        *,
        environment: EnvironmentSpec,
        runtime_root: Path,
        asset_paths: Mapping[str, Path],
        artifact_store: ContentAddressedStore,
        launch_capability: SyntheticPreflightLaunchCapability,
    ) -> SyntheticIsolationPreflightExecution:
        if artifact_store is not self._artifact_store:
            raise ExecutorUnavailable("rootless preflight artifact store differs")
        if type(launch_capability) is not SyntheticPreflightLaunchCapability:
            raise ExecutorUnavailable("rootless preflight requires controller authority")
        self._validate_environment(environment)
        expected_assets = {mount.asset_id for mount in environment.filesystem.readonly_assets}
        if set(asset_paths) != expected_assets:
            raise ExecutorUnavailable("rootless preflight assets are incomplete")
        _require_private_directory(runtime_root)
        nonce = secrets.token_hex(12)
        receipts: list[IsolationProbeReceipt] = []
        parent_receipts: list[SyntheticPreflightProbeLaunchReceipt] = []
        surfaces: list[tuple[IsolationSurface, int]] = []
        invocation_ids: list[str] = []
        claim = launch_capability._claim()
        execution: IsolationPreflightExecution | None = None
        synthetic_execution: SyntheticIsolationPreflightExecution | None = None
        try:
            for role in IsolationProbeRole:
                invocation_id = f"isolation_probe_{role.value}_{nonce}"
                invocation_ids.append(invocation_id)
                role_root = runtime_root / invocation_id
                role_root.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
                workspace = role_root / "workspace"
                artifacts = role_root / "artifacts"
                workspace.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
                artifacts.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
                plan = isolation_probe_plan(
                    role=role,
                    invocation_id=invocation_id,
                    environment_spec_digest=environment.digest,
                )
                scope = _isolation_probe_scope(role)
                scoped_assets = {
                    mount.asset_id: asset_paths[mount.asset_id]
                    for mount in environment.filesystem.readonly_assets
                    if mount.scope is scope
                }
                handle, parent_launch_digest = self._launch(
                    plan,
                    environment=environment,
                    workspace=workspace,
                    artifact_directory=artifacts,
                    asset_paths=scoped_assets,
                    scope=scope,
                    license_lease=None,
                    fixed_probe=True,
                    synthetic_claim=claim,
                )
                if parent_launch_digest is None:
                    raise ExecutorUnavailable("rootless probe has no parent launch evidence")
                parent_receipts.append(
                    SyntheticPreflightProbeLaunchReceipt(
                        role=role,
                        parent_launch_digest=parent_launch_digest,
                    )
                )
                probe_result = self._wait_and_collect(handle, environment)
                receipts.append(
                    validate_isolation_probe_execution(
                        role=role,
                        plan=plan,
                        execution=probe_result,
                        artifact_store=artifact_store,
                    )
                )
                self.abandon(invocation_id)
                descriptor = os.open(
                    workspace,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                surfaces.append((ISOLATION_PROBE_SURFACE[role], descriptor))
            receipt = IsolationPreflightReceipt(
                environment_spec_digest=environment.digest,
                executor_id=self.executor_id,
                executor_implementation_digest=self._implementation_digest,
                isolation_capability_digest=self.isolation_capability_digest,
                probe_implementation_digest=ISOLATION_PROBE_IMPLEMENTATION_DIGEST,
                artifact_store_policy_digest=artifact_store.policy_digest,
                probes=tuple(receipts),
            )
            execution = _issue_isolation_preflight_execution(
                receipt=receipt,
                surfaces=tuple(surfaces),
                artifact_store=artifact_store,
            )
            surfaces.clear()
            synthetic_execution = _issue_synthetic_isolation_preflight_execution(
                execution=execution,
                parent_receipt=SyntheticPreflightParentReceipt(
                    canary_launch_binding_digest=claim.canary_launch_binding_digest,
                    controller_boundary_digest=claim.controller_boundary_digest,
                    probes=tuple(parent_receipts),
                ),
            )
            execution = None
            claim.close()
            completed_execution = synthetic_execution
            synthetic_execution = None
            return completed_execution
        except BaseException:
            if synthetic_execution is not None:
                synthetic_execution.close()
            if execution is not None:
                execution.close()
            for _, descriptor in surfaces:
                with suppress(OSError):
                    os.close(descriptor)
            cleanup_error: Exception | None = None
            for invocation_id in invocation_ids:
                if not self._job_directory(invocation_id).exists():
                    continue
                try:
                    self.abandon(invocation_id)
                except Exception as error:
                    cleanup_error = error
            if cleanup_error is not None:
                raise ExecutorUnavailable(
                    "rootless preflight cleanup could not be proven"
                ) from cleanup_error
            raise
        finally:
            claim.close()

    def _wait_and_collect(
        self,
        handle: JobHandle,
        environment: EnvironmentSpec,
    ) -> ExecutionResult:
        deadline = time.monotonic() + environment.resources.wall_seconds + 20
        while time.monotonic() < deadline:
            state = self.inspect(handle)
            if state.state not in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                return self.collect(handle)
            time.sleep(0.05)
        self.cancel(handle)
        raise ExecutorUnavailable("rootless preflight did not settle")

    @contextmanager
    def _guard(self) -> Iterator[None]:
        with self._lock:
            descriptor = os.open(
                self._job_state_root / ".provider.lock",
                os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                ):
                    raise ExecutorUnavailable("rootless provider lock is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                os.close(descriptor)

    def _job_directory(self, invocation_id: str) -> Path:
        return self._job_state_root / _IDENTIFIER_ADAPTER.validate_python(invocation_id)

    def _load_invocation(self, invocation_id: str) -> _InvocationReceipt:
        content = read_private(self._job_directory(invocation_id) / "invocation.json")
        receipt = _InvocationReceipt.model_validate_json(content)
        if receipt.plan.invocation_id != invocation_id or canonical_bytes(receipt) != content:
            raise ExecutorUnavailable("durable invocation identity is corrupt")
        self._validate_environment(receipt.environment)
        if receipt.storage is None:
            if receipt.plan.driver_digest != ISOLATION_PROBE_IMPLEMENTATION_DIGEST:
                raise ExecutorUnavailable("ordinary invocation has no bounded storage receipt")
        elif (
            receipt.storage.run_id != receipt.plan.run_id
            or receipt.storage.environment_spec_digest != receipt.environment.digest
            or receipt.storage.executor_id != self.executor_id
            or receipt.storage.invocation_id != invocation_id
        ):
            raise ExecutorUnavailable("durable invocation storage binding is corrupt")
        return receipt

    def _invocation_for(self, handle: JobHandle) -> _InvocationReceipt:
        receipt = self._load_invocation(handle.job_id)
        if receipt.handle != handle:
            raise UnknownJob("job handle is not owned by this executor")
        return receipt

    def _require_concurrency_slot(self, environment: EnvironmentSpec) -> None:
        count = 0
        for path in self._job_state_root.iterdir():
            if path.name.startswith(".") or not path.is_dir():
                continue
            receipt = self._load_invocation(path.name)
            if receipt.environment.digest != environment.digest:
                continue
            if self._state(receipt).state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                count += 1
        if count >= environment.resources.max_concurrency:
            raise ExecutorUnavailable("executor environment concurrency limit is exhausted")

    def _observe(self, receipt: _InvocationBinding) -> _ContainerObservation | None:
        observation = self._owned_container(receipt)
        if observation is not None and observation.process_cgroup is not None:
            if receipt.scope_unit not in PurePosixPath(observation.process_cgroup).parts:
                raise ExecutorUnavailable("container process is outside its invocation scope")
            write_private(
                self._job_directory(receipt.plan.invocation_id) / "scope.json",
                canonical_bytes(_ScopeAttachment(
                    container_id=observation.container_id,
                    cgroup_path=observation.process_cgroup,
                )),
            )
        return observation

    def _owned_container(self, receipt: _InvocationBinding) -> _ContainerObservation | None:
        """Verify resource ownership independently of its current containment health."""
        existing = self._run_podman("container", "exists", receipt.container_name)
        if existing.returncode == 1:
            return None
        if existing.returncode != 0:
            raise ExecutorUnavailable("container state is unavailable")
        inspected = self._run_podman("container", "inspect", receipt.container_name)
        if inspected.returncode != 0:
            raise ExecutorUnavailable("container state changed during inspection")
        try:
            value, = json.loads(inspected.stdout)
            labels = value["Config"]["Labels"]
            if any(labels.get(key) != expected for key, expected in receipt.labels.items()):
                raise ValueError("container labels do not match this run and invocation")
            container_id = value["Id"]
            if (
                not isinstance(container_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
            ):
                raise ValueError("container has no complete identity")
            captured_id = self._read_container_receipt(receipt.plan.invocation_id)
            if captured_id is not None and captured_id != container_id:
                raise ValueError("container identity differs from its creation receipt")
            identity_path = self._job_directory(receipt.plan.invocation_id) / "container.id"
            if identity_path.exists():
                if read_private(identity_path) != container_id.encode("ascii"):
                    raise ValueError("container differs from its durable identity")
            else:
                write_private(identity_path, container_id.encode("ascii"))
            state = value["State"]
            return _ContainerObservation(
                container_id=container_id,
                status=_ContainerStatus(state["Status"]),
                running=state["Running"],
                exit_code=state["ExitCode"],
                error=state["Error"],
                oom_killed=state["OOMKilled"],
                started_at=datetime.fromisoformat(state["StartedAt"]),
                finished_at=datetime.fromisoformat(state["FinishedAt"]),
                process_cgroup=_process_cgroup(state["Pid"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ExecutorUnavailable(
                "container observation does not prove invocation ownership"
            ) from error

    def _state(self, receipt: _InvocationReceipt) -> JobState:
        directory = self._job_directory(receipt.plan.invocation_id)
        terminal_path = directory / "terminal.json"
        if terminal_path.exists():
            content = read_private(terminal_path)
            state = JobState.model_validate_json(content)
            if (
                state.handle != receipt.handle or canonical_bytes(state) != content
                or state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}
            ):
                raise ExecutorUnavailable("durable terminal observation is corrupt")
            observed = self._observe(receipt)
            if not _systemd_unit_is_quiescent(receipt.scope_unit) or (
                observed is not None and observed.active
                and not self._scope_terminated(receipt, observed)
            ):
                raise ExecutorUnavailable("terminal invocation has active container state")
            return state
        observation = self._observe(receipt)
        stop_path = directory / "stop.json"
        stop = (
            ExecutionFailureKind(json.loads(read_private(stop_path)))
            if stop_path.exists() else None
        )
        if stop not in {None, ExecutionFailureKind.TIMEOUT, ExecutionFailureKind.CANCELLED}:
            raise ExecutorUnavailable("durable stop request is invalid")
        scope_quiescent = _systemd_unit_is_quiescent(receipt.scope_unit)
        scope_state, _ = _systemd_unit_state(receipt.scope_unit)
        if stop is None and scope_state == "failed" and (
            _systemd_unit_result(receipt.scope_unit) == "timeout"
        ):
            stop = ExecutionFailureKind.TIMEOUT
            write_private(stop_path, canonical_bytes(stop))
        if observation is not None and observation.status in {
            _ContainerStatus.CONFIGURED, _ContainerStatus.CREATED,
        }:
            if stop is None:
                return JobState(
                    handle=receipt.handle,
                    state=(JobStateKind.QUEUED if scope_quiescent
                           else JobStateKind.RUNNING),
                )
            state = JobState(
                handle=receipt.handle,
                state=(JobStateKind.TIMED_OUT if stop is ExecutionFailureKind.TIMEOUT
                       else JobStateKind.CANCELLED),
                failure=stop,
            )
        elif observation is not None and observation.active:
            if scope_quiescent:
                if stop is not None and self._scope_terminated(receipt, observation):
                    # The scope kills conmon with the payload. Its deadline and
                    # empty kernel cgroup prove termination even when Podman's
                    # cached state has no final exit receipt. Keep that code absent.
                    state = JobState(
                        handle=receipt.handle,
                        state=(JobStateKind.TIMED_OUT if stop is ExecutionFailureKind.TIMEOUT
                               else JobStateKind.CANCELLED),
                        failure=stop,
                    )
                else:
                    state = JobState(
                        handle=receipt.handle, state=JobStateKind.LOST,
                        failure=ExecutionFailureKind.INFRASTRUCTURE,
                    )
                write_private(terminal_path, canonical_bytes(state))
                return state
            if stop is not None:
                self._stop_container(receipt)
                return self._state(receipt)
            return JobState(handle=receipt.handle, state=JobStateKind.RUNNING)
        elif not scope_quiescent:
            return JobState(handle=receipt.handle, state=JobStateKind.RUNNING)
        elif observation is None or observation.status not in {
            _ContainerStatus.EXITED, _ContainerStatus.STOPPED,
        } or (observation.exit_code < 0 and stop is None) or observation.finished_at.year < 1970:
            state = JobState(
                handle=receipt.handle, state=JobStateKind.LOST,
                failure=ExecutionFailureKind.INFRASTRUCTURE,
            )
        elif stop is not None:
            state = JobState(
                handle=receipt.handle,
                state=(JobStateKind.TIMED_OUT if stop is ExecutionFailureKind.TIMEOUT
                       else JobStateKind.CANCELLED),
                exit_code=observation.exit_code,
                failure=stop,
            )
        elif observation.error or observation.oom_killed:
            state = JobState(
                handle=receipt.handle, state=JobStateKind.FAILED,
                exit_code=observation.exit_code, failure=ExecutionFailureKind.INFRASTRUCTURE,
            )
        else:
            state = JobState(
                handle=receipt.handle,
                state=JobStateKind.COMPLETED if observation.exit_code == 0 else JobStateKind.FAILED,
                exit_code=observation.exit_code,
                failure=None if observation.exit_code == 0 else ExecutionFailureKind.CANDIDATE,
            )
        write_private(terminal_path, canonical_bytes(state))
        return state

    def _start_container(self, receipt: _InvocationReceipt) -> None:
        """The scope retains deadline evidence; Podman owns the actual job state."""

        if not _systemd_unit_is_quiescent(receipt.scope_unit):
            return
        wall_seconds: float = receipt.environment.resources.wall_seconds
        if receipt.plan.deadline is not None:
            remaining = (receipt.plan.deadline - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                write_private(
                    self._job_directory(receipt.plan.invocation_id) / "stop.json",
                    canonical_bytes(ExecutionFailureKind.TIMEOUT),
                )
                return
            wall_seconds = min(wall_seconds, remaining)
        _forget_isolation(receipt.scope_unit)
        runtime = self._capability.runtime
        assert runtime is not None
        descriptor = _open_runtime_descriptor(self._runtime.engine_path, runtime.executable_digest)
        try:
            command = _systemd_scope_command(
                receipt.scope_unit,
                (
                    os.fspath(LOCAL_ENV_PATH), "--argv0=/usr/bin/podman",
                    f"/proc/self/fd/{descriptor}", "start", "--attach", receipt.container_name,
                ),
                wall_seconds=wall_seconds,
                delegate=True,
            )
            process = subprocess.Popen(
                command,
                env=_systemd_launch_environment(self._runtime.host_environment),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(descriptor,), close_fds=True, start_new_session=True, umask=0o077,
            )
        except OSError:
            raise ExecutorUnavailable("container start control is unavailable") from None
        finally:
            os.close(descriptor)
        # Reaping is process-local housekeeping, never a job-state authority.
        threading.Thread(target=process.wait, daemon=True).start()
        deadline = time.monotonic() + _CONTROL_PLANE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            observation = self._observe(receipt)
            if observation is not None and observation.started_at.year >= 1970:
                return
            if process.poll() is not None:
                raise ExecutorUnavailable("container start requires recovery")
            time.sleep(_QUIESCENCE_POLL_SECONDS)
        raise ExecutorUnavailable("container start acknowledgement is unavailable")

    def _stop_container(self, receipt: _InvocationBinding) -> None:
        self._owned_container(receipt)
        _terminate_isolation(receipt.scope_unit)
        observation = self._owned_container(receipt)
        if (
            observation is None or not observation.active
            or self._scope_terminated(receipt, observation)
        ):
            return
        if observation.status in {_ContainerStatus.RUNNING, _ContainerStatus.PAUSED}:
            stopped = self._run_podman("kill", "--signal=KILL", observation.container_id)
            if stopped.returncode != 0:
                current = self._owned_container(receipt)
                if current is not None and current.active:
                    raise ExecutorUnavailable("container cancellation requires recovery")
        deadline = time.monotonic() + _QUIESCENCE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            observation = self._owned_container(receipt)
            if (
                observation is None or not observation.active
                or self._scope_terminated(receipt, observation)
            ):
                return
            time.sleep(_QUIESCENCE_POLL_SECONDS)
        raise ExecutorUnavailable("container cancellation did not become quiescent")

    def _validate_collection_storage(self, receipt: _InvocationReceipt) -> None:
        if receipt.storage is None:
            _require_private_directory(receipt.workspace)
            _require_private_directory(receipt.artifact_directory)
            return
        lease = self._require_storage_lease(
            receipt.plan, environment=receipt.environment,
            workspace=receipt.workspace, artifact_directory=receipt.artifact_directory,
        )
        if (
            lease.receipt.run_id != receipt.plan.run_id
            or lease.receipt.storage_instance_digest != receipt.storage.storage_instance_digest
        ):
            raise CollectionError("recovered workspace differs from its original storage")

    def _capture_logs(self, receipt: _InvocationBinding) -> tuple[Path, Path]:
        directory = self._job_directory(receipt.plan.invocation_id)
        paths = (directory / "stdout.bin", directory / "stderr.bin")
        streams: list[IO[bytes]] = []
        try:
            for path in paths:
                descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                )
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    os.close(descriptor)
                    raise CollectionError("container log destination is unsafe")
                os.ftruncate(descriptor, 0)
                streams.append(os.fdopen(descriptor, "wb"))
            observation = self._observe(receipt)
            if observation is None or (
                observation.active and not self._scope_terminated(receipt, observation)
            ):
                raise CollectionError("container logs have no quiescent runtime source")
            result = self._run_podman(
                "logs", observation.container_id, output_files=(streams[0], streams[1]),
            )
            if result.returncode != 0:
                raise CollectionError("container logs are unavailable")
            for stream in streams:
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            for stream in streams:
                stream.close()
        return paths

    def _scope_terminated(
        self, receipt: _InvocationBinding, observation: _ContainerObservation,
    ) -> bool:
        if observation.process_cgroup is not None and (
            receipt.scope_unit not in PurePosixPath(observation.process_cgroup).parts
        ):
            return False
        path = self._job_directory(receipt.plan.invocation_id) / "scope.json"
        if not path.exists() or not _systemd_unit_is_quiescent(receipt.scope_unit):
            return False
        attachment = _ScopeAttachment.model_validate_json(read_private(path))
        cgroup = PurePosixPath(attachment.cgroup_path)
        if (
            attachment.container_id != observation.container_id or not cgroup.is_absolute()
            or ".." in cgroup.parts or receipt.scope_unit not in cgroup.parts
        ):
            raise ExecutorUnavailable("container scope attachment is invalid")
        scope_parts = cgroup.parts[1:cgroup.parts.index(receipt.scope_unit) + 1]
        scope_root = Path("/sys/fs/cgroup").joinpath(*scope_parts)
        try:
            content = (scope_root / "cgroup.events").read_text(encoding="ascii")
            events = dict(line.split() for line in content.splitlines())
        except FileNotFoundError:
            return True
        return events.get("populated") == "0"

    def _remove_raw_logs(self, invocation_id: str) -> None:
        directory = _open_owned_directory(self._job_directory(invocation_id))
        try:
            for name in ("stdout.bin", "stderr.bin"):
                try:
                    descriptor = os.open(
                        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        dir_fd=directory,
                    )
                except FileNotFoundError:
                    continue
                try:
                    metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
                    ):
                        raise ExecutorUnavailable("rootless raw log cannot be removed safely")
                    os.unlink(name, dir_fd=directory)
                finally:
                    os.close(descriptor)
            os.fsync(directory)
        finally:
            os.close(directory)

    def _validate_environment(self, environment: EnvironmentSpec) -> RootlessLocalExecutor:
        executor = environment.executor
        runtime = self._capability.runtime
        if (
            not isinstance(executor, RootlessLocalExecutor)
            or executor.executor_id != self.executor_id
            or executor.implementation_digest != self._implementation_digest
            or executor.runtime is not ContainerRuntime.PODMAN
            or runtime is None
            or executor.runtime_version != runtime.version
            or executor.runtime_probe_digest != runtime.version_output_digest
            or executor.image_digest not in self._capability.image_digests
            or not isinstance(environment.network, NoNetwork)
            or not rootless_resources_supported(environment.resources)
            or environment.artifact_policy != self._artifact_store.policy
        ):
            raise ExecutorUnavailable("environment does not bind this rootless executor")
        return executor

    def _require_storage_lease(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
    ) -> RootlessStorageLease:
        with self._storage_lock:
            lease = self._storage_leases.get(plan.invocation_id)
        if (
            lease is None
            or lease.receipt.run_id != plan.run_id
            or lease.receipt.environment_spec_digest != environment.digest
            or lease.receipt.executor_id != self.executor_id
            or lease.receipt.executor_implementation_digest != self._implementation_digest
            or lease.receipt.provider_capability_digest != self.storage_capability_digest
            or not lease._matches(
            workspace,
            artifact_directory,
            maximum_bytes=environment.resources.disk_bytes,
            )
        ):
            raise ExecutorUnavailable(
                "rootless writable mounts require an executor-issued bounded filesystem"
            )
        return lease

    def _installations_for_environment(
        self,
        environment: EnvironmentSpec,
    ) -> Mapping[str, ResolvedInstallation]:
        executor = environment.executor
        assert isinstance(executor, RootlessLocalExecutor)
        selected: dict[str, ResolvedInstallation] = {}
        for binding in environment.tool_bindings:
            installation = self._installations.get(binding.tool_id)
            if not isinstance(binding.locator, ImageToolLocator) or not _installation_matches(
                installation,
                binding=binding,
                image_digest=executor.image_digest,
            ):
                raise ExecutorUnavailable("environment rootless tool attestation is stale")
            assert installation is not None
            selected[binding.tool_id] = installation
        if not selected:
            raise ExecutorUnavailable("rootless environment has no resolved tools")
        references = {
            (
                installation.execution_closure.rootless_image_runtime.image_reference,
                installation.execution_closure.rootless_image_runtime.supervisor_entrypoint,
            )
            for installation in selected.values()
            if installation.execution_closure.rootless_image_runtime is not None
        }
        if len(references) != 1:
            raise ExecutorUnavailable(
                "rootless environment has inconsistent image or supervisor bindings"
            )
        return MappingProxyType(selected)

    def _require_plan_installation(
        self,
        plan: InvocationPlan,
        environment: EnvironmentSpec,
    ) -> ResolvedInstallation:
        selected = self._installations_for_environment(environment)
        installation = selected.get(plan.tool_id)
        if installation is None:
            raise ExecutorUnavailable("rootless plan tool is not resolved")
        return installation

    def _resolved_recipe(
        self,
        plan: InvocationPlan,
        environment: EnvironmentSpec,
        installations: Mapping[str, ResolvedInstallation],
    ) -> dict[str, object]:
        executor = environment.executor
        if not isinstance(executor, RootlessLocalExecutor):
            raise ExecutorUnavailable("rootless composite environment changed")
        command_environment = _container_command_environment(plan.environment)
        commands: list[dict[str, object]] = []
        for command in plan.recipe:
            if isinstance(command, ToolRecipeCommand):
                installation = installations.get(command.tool_id)
                binding = next(
                    (
                        item
                        for item in environment.tool_bindings
                        if item.tool_id == command.tool_id and item.capability is command.capability
                    ),
                    None,
                )
                if (
                    binding is None
                    or binding.driver_digest != command.driver_digest
                    or not _installation_matches(
                        installation,
                        binding=binding,
                        image_digest=executor.image_digest,
                    )
                ):
                    raise ExecutorUnavailable(
                        "rootless composite command has a stale tool attestation"
                    )
                assert installation is not None
                runtime = installation.execution_closure.rootless_image_runtime
                assert runtime is not None
                if command.executable not in (
                    installation.executable_name, *installation.definition.supporting_executables
                ):
                    raise ExecutorUnavailable("composite command is not declared by its driver")
                executable = runtime.executable_path(command.executable)
            elif isinstance(command, WorkspaceRecipeCommand):
                executable = command.executable
            else:
                raise TypeError("unsupported rootless composite command")
            commands.append(
                {
                    "kind": command.kind,
                    "identity_digest": canonical_digest(
                        command,
                        domain="composite-recipe-command-v1",
                    ),
                    "executable": executable,
                    "arguments": command.arguments,
                    "environment": command_environment,
                }
            )
        return {
            "schema_version": 1,
            "commands": commands,
        }

    def _remove_container(self, receipt: _InvocationBinding) -> None:
        observation = self._owned_container(receipt)
        if observation is None:
            return
        removed = self._run_podman("rm", "--force", "--time=0", observation.container_id)
        if removed.returncode != 0:
            raise ExecutorUnavailable("container recovery could not remove the invocation")
        deadline = time.monotonic() + _QUIESCENCE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            exists = self._run_podman("container", "exists", receipt.container_name)
            if exists.returncode == 1:
                return
            if exists.returncode != 0:
                raise ExecutorUnavailable("container recovery state is unavailable")
            time.sleep(_QUIESCENCE_POLL_SECONDS)
        raise ExecutorUnavailable("container recovery did not become quiescent")

    def _container_receipt_path(self, invocation_id: str) -> Path:
        return self._job_directory(invocation_id) / "container.cid"

    def _create_container(
        self,
        *,
        command: tuple[str, ...],
        process_environment: Mapping[str, str],
        workspace: Path,
        pass_fds: tuple[int, ...],
        invocation_id: str,
        synthetic_claim: _SyntheticPreflightLaunchClaim | None,
    ) -> Digest | None:
        receipt = self._container_receipt_path(invocation_id)
        if receipt.exists() or receipt.is_symlink():
            raise ExecutorUnavailable("container receipt already exists and requires recovery")
        parent_launch_digest = None
        if synthetic_claim is not None:
            process_environment = synthetic_claim._parent_environment(process_environment)
            parent_launch_digest = synthetic_claim._validate_parent_launch(
                process_environment=process_environment,
                parent_argv=command,
                container_argv=command,
                pass_fds=pass_fds,
            )
        try:
            completed = subprocess.run(
                command,
                cwd=workspace,
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=pass_fds,
                timeout=_CONTROL_PLANE_TIMEOUT_SECONDS,
                check=False,
                umask=0o077,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ExecutorUnavailable("container creation control is unavailable") from None
        if completed.returncode != 0:
            raise ExecutorUnavailable("container creation was rejected")
        if self._observe(self._load_invocation(invocation_id)) is None:
            raise ExecutorUnavailable("created container has no durable observation")
        return parent_launch_digest

    def _read_container_receipt(self, invocation_id: str) -> str | None:
        receipt = self._container_receipt_path(invocation_id)
        _require_private_directory(receipt.parent)
        try:
            descriptor = os.open(
                receipt, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise ExecutorUnavailable("container creation produced no receipt") from None
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_nlink != 1
                or metadata.st_size != 64
            ):
                raise ExecutorUnavailable("container receipt is unsafe or malformed")
            content = os.read(descriptor, 65)
            if re.fullmatch(rb"[0-9a-f]{64}", content) is None:
                raise ExecutorUnavailable("container receipt has no complete container ID")
            container_id = content.decode("ascii")
            # Podman chooses its own receipt mode. The enclosing controller
            # directory is already private; seal the verified file before use.
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return container_id

    def _run_podman(
        self, *arguments: str, output_files: tuple[IO[bytes], IO[bytes]] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        descriptor: int | None = None
        try:
            runtime = self._capability.runtime
            assert runtime is not None
            descriptor = _open_runtime_descriptor(
                self._runtime.engine_path,
                runtime.executable_digest,
            )
            executable = f"/proc/self/fd/{descriptor}"
            return subprocess.run(
                (
                    os.fspath(LOCAL_ENV_PATH),
                    "--argv0=/usr/bin/podman",
                    executable,
                    *arguments,
                ),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if output_files is None else output_files[0],
                stderr=subprocess.DEVNULL if output_files is None else output_files[1],
                text=True,
                env=self._runtime.host_environment,
                pass_fds=(descriptor,),
                timeout=_CONTROL_PLANE_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ExecutorUnavailable("container recovery control is unavailable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _process_cgroup(process_id: int) -> str | None:
    """Observe a live process only; PIDs are never persisted as operation identity."""

    if type(process_id) is not int or process_id < 0:
        raise ValueError("container process identity is invalid")
    if process_id == 0:
        return None
    try:
        content = Path(f"/proc/{process_id}/cgroup").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    return next((line[3:] for line in content.splitlines() if line.startswith("0::")), None)


def _installation_matches(
    installation: ResolvedInstallation | None,
    *,
    binding: object,
    image_digest: str,
) -> bool:
    if installation is None:
        return False
    from edagym.specs.environment import ToolBinding

    if not isinstance(binding, ToolBinding):
        return False
    runtime = installation.execution_closure.rootless_image_runtime
    return (
        runtime is not None
        and installation.tool_id == binding.tool_id
        and binding.capability in installation.definition.capabilities
        and installation.definition.driver_digest == binding.driver_digest
        and installation.version_label == binding.tool_version
        and installation.executable_name == binding.locator.executable
        and installation.deployment_attestation_digest
        == binding.locator.deployment_attestation_digest
        and runtime.image_digest == image_digest
        and Path(runtime.tool_entrypoint).name == binding.locator.executable
        and tuple(item.executable for item in runtime.supporting_entrypoints)
        == installation.definition.supporting_executables
        and binding.license_binding_id is None
        and installation.execution_closure.revalidate()
    )


def _container_command_environment(
    entries: tuple[EnvironmentEntry, ...],
) -> dict[str, str]:
    environment = {entry.name: entry.value for entry in entries}
    environment.update(
        {
            "BASH_ENV": "",
            "ENV": "",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_PRELOAD": "",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONHOME": "",
            "PYTHONPATH": "",
        }
    )
    return environment


def _read_supervisor_bytes(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("rootless supervisor is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > 1024 * 1024
        ):
            raise ExecutorUnavailable("rootless supervisor identity is untrusted")
        content = bytearray()
        while len(content) <= metadata.st_size:
            block = os.read(
                descriptor,
                min(1024 * 1024, metadata.st_size + 1 - len(content)),
            )
            if not block:
                break
            content.extend(block)
        current = os.fstat(descriptor)
        if len(content) != metadata.st_size or _stable_file_identity(
            current
        ) != _stable_file_identity(metadata):
            raise ExecutorUnavailable("rootless supervisor changed while being captured")
        return bytes(content)
    finally:
        os.close(descriptor)


def _open_runtime_descriptor(path: Path, expected_digest: str) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("rootless runtime is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not metadata.st_mode & stat.S_IXUSR
            or f"sha256:{digest.hexdigest()}" != expected_digest
        ):
            raise ExecutorUnavailable("rootless runtime identity differs from capability")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_private_directory(path: Path) -> None:
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ExecutorUnavailable("rootless runtime directory is unavailable") from None
    if (
        not path.is_absolute()
        or canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ExecutorUnavailable("rootless runtime directories must be private and canonical")


def _content_digest(content: bytes) -> Digest:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _isolation_probe_scope(role: IsolationProbeRole) -> FilesystemScope:
    if role is IsolationProbeRole.PARTICIPANT:
        return FilesystemScope.PARTICIPANT
    if role is IsolationProbeRole.TOOL:
        return FilesystemScope.TOOL
    return FilesystemScope.EVALUATOR
