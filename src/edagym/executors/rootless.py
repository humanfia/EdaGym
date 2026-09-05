"""Digest-bound rootless container execution for participant-controlled work."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING

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
    ExecutorUnavailable,
    _bind_asset_closure,
    _isolation_unit,
    _PrivateTransientFile,
    _ProcessManager,
    _remove_private_transient_files,
    _revalidate_bound_assets,
    _sealed_environment_file,
    _systemd_unit_is_quiescent,
    _systemd_unit_state,
    _validate_plan_binding,
    _validate_scope,
    _write_private_transient_file,
)
from edagym.executors.model import (
    COMPOSITE_REPORT_PATH,
    EnvironmentEntry,
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
    RootlessControlFile,
    rootless_podman_command,
)
from edagym.executors.rootless_storage import (
    RootlessStorageLease,
    RootlessStorageProvider,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.runtime_surface_protocol import IsolationSurface
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel
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
_ROOTLESS_CONTROL_PROTOCOL = "sealed-composite-v1"
_CONTAINER_OWNER_LABEL = "io.edagym.execution"
_CONTROL_PLANE_TIMEOUT_SECONDS = 10
_QUIESCENCE_TIMEOUT_SECONDS = 5.0
_QUIESCENCE_POLL_SECONDS = 0.05
_PRIVATE_DIRECTORY_MODE = 0o700


class RootlessResourceKind(StrEnum):
    CONTAINER = "container"
    CONTAINMENT_SCOPE = "containment_scope"


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
                tool_id != installation.definition.tool_id
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
        self._manager = _ProcessManager(
            executor_id=self.executor_id,
            asset_source_policy=asset_source_policy,
            artifact_store=artifact_store,
            job_state_root=job_state_root,
        )

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
            self._manager,
            environment=environment,
            asset_paths=asset_paths,
            scope=scope,
            writable_paths=(workspace, artifact_directory),
        )
        bound_assets = MappingProxyType(
            {asset_id: snapshot.path for asset_id, snapshot in asset_snapshots.items()}
        )
        selected = self._installations_for_environment(environment)
        transients: tuple[_PrivateTransientFile, ...] = ()
        environment_fd: int | None = None
        runtime_descriptor: int | None = None
        try:
            control_files: Mapping[RootlessControlFile, Path] | None = None
            arguments: tuple[str, ...]
            if plan.recipe:
                recipe = self._resolved_recipe(plan, environment, selected)
                supervisor = _write_private_transient_file(
                    self._manager.job_state_root,
                    plan.invocation_id,
                    "rootless-supervisor",
                    self._supervisor_bytes,
                )
                recipe_file = _write_private_transient_file(
                    self._manager.job_state_root,
                    plan.invocation_id,
                    "rootless-recipe",
                    canonical_bytes(recipe),
                )
                transients = (supervisor, recipe_file)
                control_files = MappingProxyType(
                    {
                        RootlessControlFile.COMPOSITE_SUPERVISOR: supervisor.path,
                        RootlessControlFile.COMPOSITE_RECIPE: recipe_file.path,
                    }
                )
                executable = "/usr/bin/python3"
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
            image_runtime = next(iter(selected.values())).execution_closure.rootless_image_runtime
            if image_runtime is None:
                raise ExecutorUnavailable("rootless image runtime disappeared")
            runtime_path = Path(f"/proc/self/fd/{runtime_descriptor}")
            podman_command = rootless_podman_command(
                podman_path=runtime_path,
                environment=environment,
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
                container_name=_container_name(self.executor_id, plan.invocation_id),
                container_labels={
                    _CONTAINER_OWNER_LABEL: _container_owner(
                        self.executor_id,
                        plan.invocation_id,
                    )
                },
                control_files=control_files,
            )
            command = (
                os.fspath(LOCAL_ENV_PATH),
                "--argv0=/usr/bin/podman",
                *podman_command,
            )
            _revalidate_bound_assets(
                asset_snapshots,
                self._manager,
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
            pre_spawn_validator: Callable[
                [tuple[str, ...], Mapping[str, str], tuple[int, ...]],
                None,
            ] | None = None
            if synthetic_claim is not None:
                process_environment = synthetic_claim._parent_environment(
                    process_environment
                )

                def validate_parent_launch(
                    parent_argv: tuple[str, ...],
                    launched_environment: Mapping[str, str],
                    inherited_descriptors: tuple[int, ...],
                ) -> None:
                    nonlocal parent_launch_digest
                    if parent_launch_digest is not None:
                        raise ExecutorUnavailable(
                            "synthetic parent launch was validated more than once"
                        )
                    parent_launch_digest = synthetic_claim._validate_parent_launch(
                        process_environment=launched_environment,
                        parent_argv=parent_argv,
                        container_argv=command,
                        pass_fds=inherited_descriptors,
                    )

                pre_spawn_validator = validate_parent_launch
            handle = self._manager.launch_command(
                plan=plan,
                environment=environment,
                command=command,
                process_environment=process_environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                apply_host_limits=False,
                pass_fds=pass_fds,
                transient_files=transients,
                post_execution_validators=tuple(
                    installation.execution_closure.revalidate for installation in selected.values()
                ),
                pre_spawn_validator=pre_spawn_validator,
            )
            if synthetic_claim is not None and parent_launch_digest is None:
                raise ExecutorUnavailable("synthetic parent launch was not observed")
            return handle, parent_launch_digest
        except BaseException:
            _remove_private_transient_files(
                transients,
                self._manager.job_state_root,
            )
            raise
        finally:
            if environment_fd is not None:
                os.close(environment_fd)
            if runtime_descriptor is not None:
                os.close(runtime_descriptor)

    def inspect(self, handle: JobHandle) -> JobState:
        return self._manager.inspect(handle)

    def cancel(self, handle: JobHandle) -> JobState:
        return self._manager.cancel(handle)

    def collect(self, handle: JobHandle) -> ExecutionResult:
        return self._manager.collect(handle)

    def abandon(self, invocation_id: str) -> None:
        cleanup = self.cleanup(invocation_id)
        if cleanup.remaining_resources:
            raise ExecutorUnavailable("rootless cleanup did not prove resource absence")

    def cleanup(self, invocation_id: str) -> RootlessIsolationCleanup:
        normalized = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        self._manager.abandon(normalized)
        self._remove_container(normalized)
        unit = _isolation_unit(self.executor_id, normalized)
        active_state, control_group = _systemd_unit_state(unit)
        container_state = self._run_podman(
            "container", "exists", _container_name(self.executor_id, normalized)
        )
        remaining: list[RootlessResourceKind] = []
        if not _systemd_unit_is_quiescent(unit):
            remaining.append(RootlessResourceKind.CONTAINMENT_SCOPE)
        if container_state.returncode != 1:
            remaining.append(RootlessResourceKind.CONTAINER)
        return RootlessIsolationCleanup(
            invocation_id=normalized,
            observation_digest=canonical_digest(
                {
                    "executor_id": self.executor_id,
                    "invocation_id": normalized,
                    "active_state": active_state,
                    "control_group_present": bool(control_group),
                    "container_absence_status": container_state.returncode,
                },
                domain="rootless-cleanup-observation-v1",
            ),
            remaining_resources=tuple(remaining),
        )

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
            or environment.resources.io_read_bytes_per_second is not None
            or environment.resources.io_write_bytes_per_second is not None
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
            installation.execution_closure.rootless_image_runtime.image_reference
            for installation in selected.values()
            if installation.execution_closure.rootless_image_runtime is not None
        }
        if len(references) != 1:
            raise ExecutorUnavailable("rootless environment has multiple image owners")
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
                    or binding.locator.executable != command.executable
                    or not _installation_matches(
                        installation,
                        binding=binding,
                        image_digest=executor.image_digest,
                    )
                ):
                    raise ExecutorUnavailable(
                        "rootless composite command has a stale tool attestation"
                    )
                executable = command.executable
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
            "tool_resolution": "fixed_image_path",
            "commands": commands,
        }

    def _remove_container(self, invocation_id: str) -> None:
        name = _container_name(self.executor_id, invocation_id)
        expected_owner = _container_owner(self.executor_id, invocation_id)
        exists = self._run_podman("container", "exists", name)
        if exists.returncode == 1:
            return
        if exists.returncode != 0:
            raise ExecutorUnavailable("container recovery state is unavailable")
        inspected = self._run_podman(
            "container",
            "inspect",
            "--format",
            f'{{{{ index .Config.Labels "{_CONTAINER_OWNER_LABEL}" }}}}',
            name,
        )
        if inspected.returncode != 0 or inspected.stdout.strip() != expected_owner:
            raise ExecutorUnavailable("container recovery ownership does not match")
        removed = self._run_podman("rm", "--force", "--time=0", name)
        if removed.returncode != 0:
            raise ExecutorUnavailable("container recovery could not remove the invocation")
        deadline = time.monotonic() + _QUIESCENCE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            exists = self._run_podman("container", "exists", name)
            if exists.returncode == 1:
                return
            if exists.returncode != 0:
                raise ExecutorUnavailable("container recovery state is unavailable")
            time.sleep(_QUIESCENCE_POLL_SECONDS)
        raise ExecutorUnavailable("container recovery did not become quiescent")

    def _run_podman(self, *arguments: str) -> subprocess.CompletedProcess[str]:
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
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
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
        and installation.definition.tool_id == binding.tool_id
        and binding.capability in installation.definition.capabilities
        and installation.definition.driver_digest == binding.driver_digest
        and installation.version_label == binding.tool_version
        and installation.executable_name == binding.locator.executable
        and installation.deployment_attestation_digest
        == binding.locator.deployment_attestation_digest
        and runtime.image_digest == image_digest
        and Path(runtime.tool_entrypoint).name == binding.locator.executable
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


def _container_name(executor_id: str, invocation_id: str) -> str:
    identity = canonical_digest(
        {"executor_id": executor_id, "invocation_id": invocation_id},
        domain="executor-container-name-v1",
    ).removeprefix("sha256:")
    return f"edagym-{identity}"


def _container_owner(executor_id: str, invocation_id: str) -> str:
    return canonical_digest(
        {"executor_id": executor_id, "invocation_id": invocation_id},
        domain="executor-container-owner-v1",
    )


def _isolation_probe_scope(role: IsolationProbeRole) -> FilesystemScope:
    if role is IsolationProbeRole.PARTICIPANT:
        return FilesystemScope.PARTICIPANT
    if role is IsolationProbeRole.TOOL:
        return FilesystemScope.TOOL
    return FilesystemScope.EVALUATOR
