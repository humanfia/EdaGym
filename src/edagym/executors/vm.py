"""Libvirt VM-per-run execution boundary backed by an attested host broker."""

from __future__ import annotations

import os
import secrets
import stat
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Never, Protocol, runtime_checkable

from pydantic import TypeAdapter, ValidationError, field_validator

from edagym.canonical import canonical_digest
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.assets import (
    AssetSnapshot,
    AssetValidationError,
    revalidate_asset_closure,
    validate_asset_closure,
)
from edagym.executors.capabilities import (
    ExecutorCapability,
    ExecutorProviderKind,
    ProviderAvailability,
    ProviderFeature,
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
from edagym.executors.licenses import LeaseState, LicenseLease
from edagym.executors.local import (
    ExecutorUnavailable,
    UnknownJob,
    _validate_plan_binding,
    _validate_scope,
)
from edagym.executors.model import (
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
    JobStateKind,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.runtime_surface_protocol import IsolationSurface
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.environment import (
    CheckpointCapability,
    EnvironmentSpec,
    FilesystemScope,
    HostAllowlistNetwork,
    VmPerRunExecutor,
)

_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)


class GrantAccess(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


class VmResourceKind(StrEnum):
    MACHINE = "machine"
    WRITABLE_LAYER = "writable_layer"
    GUEST_CONTROL_CHANNEL = "guest_control_channel"


class VmIsolationCleanup(StrictModel):
    """Authoritative fenced broker observation after isolation cleanup."""

    invocation_id: Identifier
    lifecycle_fence_digest: Digest
    remaining_resources: tuple[VmResourceKind, ...] = ()

    @field_validator("remaining_resources")
    @classmethod
    def normalize_resources(
        cls,
        value: tuple[VmResourceKind, ...],
    ) -> tuple[VmResourceKind, ...]:
        if len(value) != len(set(value)):
            raise ValueError("VM cleanup resources must be unique")
        return tuple(sorted(value, key=lambda resource: resource.value))


class HostResourceGrant:
    """Non-serializable open descriptor handed only to the trusted VM broker."""

    __slots__ = ("_access", "_descriptor", "_guest_target", "_restricted_digest")

    def __init__(
        self,
        *,
        descriptor: int,
        guest_target: str,
        access: GrantAccess,
        restricted_digest: str | None = None,
    ) -> None:
        self._descriptor = descriptor
        self._guest_target = guest_target
        self._access = access
        self._restricted_digest = restricted_digest

    def __repr__(self) -> str:
        return (
            "HostResourceGrant(<opaque>, "
            f"guest_target={self._guest_target!r}, access={self._access.value!r})"
        )

    def __reduce__(self) -> Never:
        raise TypeError("host resource grants cannot be serialized")

    @property
    def access(self) -> GrantAccess:
        return self._access

    @property
    def guest_target(self) -> str:
        return self._guest_target

    @property
    def restricted_digest(self) -> str | None:
        return self._restricted_digest

    def fileno(self) -> int:
        if self._descriptor < 0:
            raise ValueError("host resource grant is closed")
        return self._descriptor

    def close(self) -> None:
        if self._descriptor >= 0:
            descriptor = self._descriptor
            self._descriptor = -1
            os.close(descriptor)


class LibvirtVmBroker(Protocol):
    """Trusted host controller with atomic per-invocation lifecycle ownership.

    ``abandon`` must durably and permanently tombstone the invocation before it
    observes resource absence. No preceding or subsequent launch may commit for
    that identity. Launch must duplicate any resource grant retained after the
    call returns.
    """

    @property
    def capability_digest(self) -> str: ...

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
    ) -> JobHandle: ...

    def inspect(self, handle: JobHandle) -> JobState: ...

    def cancel(self, handle: JobHandle) -> JobState: ...

    def collect(self, handle: JobHandle) -> ExecutionResult: ...

    def abandon(self, invocation_id: str) -> VmIsolationCleanup:
        """Fence creation and destroy or prove absent every per-run resource."""

        ...


@runtime_checkable
class _PreflightArtifactBroker(Protocol):
    @property
    def artifact_store(self) -> ContentAddressedStore: ...


_ACTIVE_STATES = frozenset({JobStateKind.QUEUED, JobStateKind.RUNNING})


class LibvirtVmExecutor:
    """Validate policy locally and delegate VM lifecycle through opaque grants."""

    def __init__(
        self,
        *,
        executor_id: str,
        implementation_digest: str,
        provider_id: str,
        provider_digest: str,
        capability: ExecutorCapability,
        broker: LibvirtVmBroker,
        asset_source_policy: AssetSourcePolicy,
        workspace_root: Path,
        artifact_root: Path,
    ) -> None:
        if (
            capability.kind is not ExecutorProviderKind.LIBVIRT_KVM
            or capability.availability is not ProviderAvailability.AVAILABLE
            or capability.provider_id != provider_id
            or capability.provider_digest != provider_digest
            or broker.capability_digest != capability.digest
        ):
            raise ExecutorUnavailable("libvirt provider capability is unavailable or stale")
        self.executor_id = executor_id
        self._implementation_digest = implementation_digest
        self._provider_id = provider_id
        self._provider_digest = provider_digest
        self._capability = capability
        self._broker = broker
        if type(asset_source_policy) is not AssetSourcePolicy:
            raise ExecutorUnavailable("VM executor requires trusted asset source authority")
        self._asset_source_policy = asset_source_policy
        self._workspace_root = _require_executor_root(workspace_root)
        self._artifact_root = _require_executor_root(artifact_root)
        if _paths_overlap(self._workspace_root, self._artifact_root):
            raise ExecutorUnavailable("VM executor roots must be disjoint")
        self._jobs: dict[str, tuple[JobHandle, InvocationPlan, JobState | None]] = {}
        self._cleanup_fences: dict[str, str] = {}
        self._launch_lock = threading.RLock()
        self._lock = threading.RLock()

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
        with self._launch_lock:
            return self._launch_serialized(
                plan,
                environment=environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                asset_paths=asset_paths,
                scope=scope,
                license_lease=license_lease,
            )

    def _launch_serialized(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: dict[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None,
        fixed_probe: bool = False,
        workspace_owner_root: Path | None = None,
    ) -> JobHandle:
        with self._lock:
            if plan.invocation_id in self._jobs or plan.invocation_id in self._cleanup_fences:
                raise ExecutorUnavailable("VM invocation identity cannot be relaunched")
        executor = environment.executor
        if (
            not isinstance(executor, VmPerRunExecutor)
            or executor.executor_id != self.executor_id
            or executor.implementation_digest != self._implementation_digest
            or executor.provider_id != self._provider_id
            or executor.provider_digest != self._provider_digest
        ):
            raise ExecutorUnavailable("environment does not bind this libvirt executor")
        self._validate_environment_policy(environment)
        if fixed_probe:
            if (
                plan.driver_digest != ISOLATION_PROBE_IMPLEMENTATION_DIGEST
                or license_lease is not None
            ):
                raise ExecutorUnavailable("VM isolation probe closure is invalid")
        else:
            _validate_plan_binding(plan, environment)
        _validate_scope(plan, scope)
        _require_invocation_directory(
            workspace,
            root=(self._workspace_root if workspace_owner_root is None else workspace_owner_root),
            invocation_id=plan.invocation_id,
        )
        _require_invocation_directory(
            artifact_directory,
            root=self._artifact_root,
            invocation_id=plan.invocation_id,
        )
        try:
            asset_snapshots = validate_asset_closure(
                environment,
                asset_paths,
                scope,
                source_policy=self._asset_source_policy,
                writable_paths=(workspace, artifact_directory),
            )
            revalidate_asset_closure(
                asset_snapshots,
                writable_paths=(workspace, artifact_directory),
            )
        except AssetValidationError:
            raise ExecutorUnavailable("VM asset closure is invalid") from None
        if not fixed_probe:
            self._validate_license(plan, environment, license_lease)

        grants = self._open_grants(
            environment=environment,
            workspace=workspace,
            artifact_directory=artifact_directory,
            asset_snapshots=asset_snapshots,
            scope=scope,
        )
        try:
            try:
                self._validate_asset_grants(asset_snapshots, grants[2])
                handle = self._broker.launch(
                    plan,
                    environment=environment,
                    scope=scope,
                    workspace=grants[0],
                    artifact_directory=grants[1],
                    assets=MappingProxyType(grants[2]),
                    license_lease=license_lease,
                )
                if (
                    not isinstance(handle, JobHandle)
                    or handle.job_id != plan.invocation_id
                    or handle.executor_id != self.executor_id
                    or handle.invocation_digest != plan.digest
                ):
                    raise ExecutorUnavailable("VM broker returned an invalid job identity")
            except Exception as launch_error:
                try:
                    self._require_cleanup(plan.invocation_id)
                except Exception as cleanup_error:
                    raise ExecutorUnavailable(
                        "VM launch failed and fenced cleanup was not proven"
                    ) from cleanup_error
                raise ExecutorUnavailable(
                    "VM broker launch failed after fenced cleanup"
                ) from launch_error
        finally:
            grants[0].close()
            grants[1].close()
            for grant in grants[2].values():
                grant.close()
        with self._lock:
            self._jobs[handle.job_id] = (handle, plan, None)
        return handle

    @property
    def isolation_capability_digest(self) -> Digest:
        return canonical_digest(
            {
                "executor_implementation_digest": self._implementation_digest,
                "provider_capability_digest": self._capability.digest,
                "probe_implementation_digest": ISOLATION_PROBE_IMPLEMENTATION_DIGEST,
            },
            domain="libvirt-vm-isolation-capability-v1",
        )

    def execute_isolation_preflight(
        self,
        *,
        environment: EnvironmentSpec,
        runtime_root: Path,
        asset_paths: Mapping[str, Path],
        artifact_store: ContentAddressedStore,
    ) -> IsolationPreflightExecution:
        """Run fixed credential-absence probes in four disposable guests."""

        if (
            type(artifact_store) is not ContentAddressedStore
            or not isinstance(self._broker, _PreflightArtifactBroker)
            or self._broker.artifact_store is not artifact_store
            or not _is_private_descendant(runtime_root, self._workspace_root)
            or environment.executor.executor_id != self.executor_id
        ):
            raise ExecutorUnavailable("VM isolation preflight closure is unavailable")
        expected_assets = {mount.asset_id for mount in environment.filesystem.readonly_assets}
        if set(asset_paths) != expected_assets:
            raise ExecutorUnavailable("VM isolation preflight assets are incomplete")
        nonce = secrets.token_hex(12)
        receipts: list[IsolationProbeReceipt] = []
        surfaces: list[tuple[IsolationSurface, int]] = []
        invocation_ids: list[str] = []
        try:
            for role in IsolationProbeRole:
                invocation_id = f"isolation_probe_{role.value}_{nonce}"
                invocation_ids.append(invocation_id)
                workspace = runtime_root / invocation_id
                artifacts = self._artifact_root / invocation_id
                workspace.mkdir(mode=0o700)
                artifacts.mkdir(mode=0o700)
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
                with self._launch_lock:
                    handle = self._launch_serialized(
                        plan,
                        environment=environment,
                        workspace=workspace,
                        artifact_directory=artifacts,
                        asset_paths=scoped_assets,
                        scope=scope,
                        license_lease=None,
                        fixed_probe=True,
                        workspace_owner_root=runtime_root,
                    )
                result = self._collect_preflight_result(handle, environment)
                receipts.append(
                    validate_isolation_probe_execution(
                        role=role,
                        plan=plan,
                        execution=result,
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
            return _issue_isolation_preflight_execution(
                receipt=receipt,
                surfaces=tuple(surfaces),
                artifact_store=artifact_store,
            )
        except BaseException:
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
                    "VM isolation preflight cleanup could not be proven"
                ) from cleanup_error
            raise

    def _collect_preflight_result(
        self,
        handle: JobHandle,
        environment: EnvironmentSpec,
    ) -> ExecutionResult:
        deadline = time.monotonic() + environment.resources.wall_seconds + 60
        while time.monotonic() < deadline:
            state = self.inspect(handle)
            if state.state not in _ACTIVE_STATES:
                return self.collect(handle)
            time.sleep(0.05)
        self.cancel(handle)
        raise ExecutorUnavailable("VM isolation preflight did not settle")

    @staticmethod
    def _validate_asset_grants(
        snapshots: Mapping[str, AssetSnapshot],
        grants: Mapping[str, HostResourceGrant],
    ) -> None:
        if set(snapshots) != set(grants) or any(
            not snapshots[asset_id].matches_descriptor(grant._descriptor)
            for asset_id, grant in grants.items()
        ):
            raise ExecutorUnavailable("VM asset grant changed after validation")

    def inspect(self, handle: JobHandle) -> JobState:
        with self._launch_lock:
            state = self._broker.inspect(self._owned_handle(handle)[0])
            return self._accept_state(handle, state)

    def cancel(self, handle: JobHandle) -> JobState:
        with self._launch_lock:
            state = self._broker.cancel(self._owned_handle(handle)[0])
            return self._accept_state(handle, state)

    def collect(self, handle: JobHandle) -> ExecutionResult:
        with self._launch_lock:
            owned, plan, _ = self._owned_handle(handle)
            result = self._broker.collect(owned)
            self._accept_state(handle, result.state)
            if result.state.state in _ACTIVE_STATES:
                raise ExecutorUnavailable("VM output cannot be collected before termination")
            declarations = {declaration.logical_id: declaration for declaration in plan.outputs}
            logical_ids = [output.logical_id for output in result.outputs]
            if len(logical_ids) != len(set(logical_ids)) or set(logical_ids) - declarations.keys():
                raise ExecutorUnavailable(
                    "VM broker returned outputs outside the invocation contract"
                )
            for output in result.outputs:
                declaration = declarations[output.logical_id]
                if (
                    output.media_type != declaration.media_type
                    or output.artifact_class is not declaration.artifact_class
                ):
                    raise ExecutorUnavailable(
                        "VM broker returned output metadata outside the contract"
                    )
            if result.state.state is JobStateKind.COMPLETED:
                required = {
                    declaration.logical_id for declaration in plan.outputs if declaration.required
                }
                if not required <= set(logical_ids):
                    raise ExecutorUnavailable("VM broker omitted a required invocation output")
            return result

    def abandon(self, invocation_id: str) -> None:
        with self._launch_lock:
            self._require_cleanup(invocation_id)

    def _require_cleanup(self, invocation_id: str) -> None:
        try:
            normalized_id = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        except ValidationError:
            raise ExecutorUnavailable("invalid VM invocation identity") from None
        cleanup = self._broker.abandon(normalized_id)
        if cleanup.invocation_id != normalized_id or cleanup.remaining_resources:
            raise ExecutorUnavailable("VM broker did not prove complete isolation cleanup")
        with self._lock:
            previous_fence = self._cleanup_fences.get(normalized_id)
            if previous_fence is not None and previous_fence != cleanup.lifecycle_fence_digest:
                raise ExecutorUnavailable("VM broker changed a durable isolation fence")
            self._cleanup_fences[normalized_id] = cleanup.lifecycle_fence_digest
            self._jobs.pop(normalized_id, None)

    def _owned_handle(self, handle: JobHandle) -> tuple[JobHandle, InvocationPlan, JobState | None]:
        with self._lock:
            if handle.job_id in self._cleanup_fences:
                raise UnknownJob("job handle belongs to a fenced VM invocation")
            owned = self._jobs.get(handle.job_id)
            if owned is None or owned[0] != handle:
                raise UnknownJob("job handle is not owned by this executor")
            return owned

    def _accept_state(self, handle: JobHandle, state: JobState) -> JobState:
        if state.handle != handle:
            raise ExecutorUnavailable("VM broker returned state for a different job")
        with self._lock:
            owned, plan, previous = self._owned_handle(handle)
            if previous is not None:
                if previous.state not in _ACTIVE_STATES and state != previous:
                    raise ExecutorUnavailable("VM broker changed a terminal job state")
                if previous.state is JobStateKind.RUNNING and state.state is JobStateKind.QUEUED:
                    raise ExecutorUnavailable("VM broker regressed a running job to queued")
            self._jobs[handle.job_id] = (owned, plan, state)
        return state

    def _validate_environment_policy(self, environment: EnvironmentSpec) -> None:
        features = frozenset(self._capability.features)
        if isinstance(environment.network, HostAllowlistNetwork) and (
            ProviderFeature.HOST_NETWORK_ALLOWLIST not in features
            or self._capability.network_enforcer_digest != environment.network.enforcer_digest
        ):
            raise ExecutorUnavailable("VM provider cannot enforce the selected network policy")
        if environment.checkpoint is CheckpointCapability.VIRTUAL_MACHINE:
            if ProviderFeature.VM_SNAPSHOT not in features:
                raise ExecutorUnavailable("VM provider cannot enforce virtual-machine checkpoints")
            raise ExecutorUnavailable("VM snapshot lifecycle is not implemented by this executor")

    @staticmethod
    def _validate_license(
        plan: InvocationPlan,
        environment: EnvironmentSpec,
        license_lease: LicenseLease | None,
    ) -> None:
        tool = next(
            binding
            for binding in environment.tool_bindings
            if binding.capability is plan.capability and binding.tool_id == plan.tool_id
        )
        if tool.license_binding_id is None:
            if license_lease is not None:
                raise ExecutorUnavailable("unlicensed tools cannot receive a license lease")
            return
        if plan.view is InvocationView.PARTICIPANT:
            raise ExecutorUnavailable("license leases cannot enter participant processes")
        binding = next(
            binding
            for binding in environment.licenses
            if binding.license_binding_id == tool.license_binding_id
        )
        if (
            license_lease is None
            or license_lease.state is not LeaseState.ACTIVE
            or license_lease.provider_id != binding.provider_id
            or license_lease.feature_class != binding.feature_class
        ):
            raise ExecutorUnavailable("invocation lacks the exact active license lease")

    @staticmethod
    def _open_grants(
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_snapshots: Mapping[str, AssetSnapshot],
        scope: FilesystemScope,
    ) -> tuple[HostResourceGrant, HostResourceGrant, dict[str, HostResourceGrant]]:
        opened: list[HostResourceGrant] = []
        try:
            workspace_grant = _open_resource_grant(
                workspace,
                guest_target=environment.filesystem.workspace_target,
                access=GrantAccess.READ_WRITE,
            )
            opened.append(workspace_grant)
            artifact_grant = _open_resource_grant(
                artifact_directory,
                guest_target=environment.filesystem.artifact_target,
                access=GrantAccess.READ_WRITE,
            )
            opened.append(artifact_grant)
            assets: dict[str, HostResourceGrant] = {}
            for mount in environment.filesystem.readonly_assets:
                if mount.scope is not scope:
                    continue
                snapshot = asset_snapshots[mount.asset_id]
                grant = _open_resource_grant(
                    snapshot.path,
                    guest_target=mount.target,
                    access=GrantAccess.READ_ONLY,
                    restricted_digest=snapshot.restricted_digest,
                )
                opened.append(grant)
                assets[mount.asset_id] = grant
            identities = [_resource_identity(grant) for grant in opened]
            if len(identities) != len(set(identities)):
                raise ExecutorUnavailable("VM resource grants must not alias")
            return workspace_grant, artifact_grant, assets
        except BaseException:
            for grant in opened:
                grant.close()
            raise


def _open_resource_grant(
    path: Path,
    *,
    guest_target: str,
    access: GrantAccess,
    restricted_digest: str | None = None,
) -> HostResourceGrant:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    if access is GrantAccess.READ_WRITE:
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ExecutorUnavailable("VM resource grant cannot be opened safely") from None
    metadata = os.fstat(descriptor)
    accepted_type = stat.S_ISDIR(metadata.st_mode) or (
        access is GrantAccess.READ_ONLY and stat.S_ISREG(metadata.st_mode)
    )
    writable_is_private = access is GrantAccess.READ_ONLY or (
        metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o022
    )
    if not accepted_type or not writable_is_private:
        os.close(descriptor)
        raise ExecutorUnavailable("VM resource grant violates its ownership or type policy")
    return HostResourceGrant(
        descriptor=descriptor,
        guest_target=guest_target,
        access=access,
        restricted_digest=restricted_digest,
    )


def _require_executor_root(path: Path) -> Path:
    if not path.is_absolute():
        raise ExecutorUnavailable("VM executor roots must be absolute")
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ExecutorUnavailable("VM executor root is unavailable") from None
    if (
        canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ExecutorUnavailable("VM executor root is not private and canonical")
    return canonical


def _require_invocation_directory(
    path: Path,
    *,
    root: Path,
    invocation_id: str,
) -> None:
    expected = root / invocation_id
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ExecutorUnavailable("VM invocation directory is unavailable") from None
    if (
        path != expected
        or canonical != expected
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ExecutorUnavailable("VM writable grants must be private per-invocation directories")


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _is_private_descendant(path: Path, root: Path) -> bool:
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        canonical == path
        and (path == root or root in path.parents)
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _isolation_probe_scope(role: IsolationProbeRole) -> FilesystemScope:
    if role is IsolationProbeRole.PARTICIPANT:
        return FilesystemScope.PARTICIPANT
    if role is IsolationProbeRole.TOOL:
        return FilesystemScope.TOOL
    return FilesystemScope.EVALUATOR


def _resource_identity(grant: HostResourceGrant) -> tuple[int, int]:
    metadata = os.fstat(grant.fileno())
    return metadata.st_dev, metadata.st_ino
