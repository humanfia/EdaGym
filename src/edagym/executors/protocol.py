"""The execution protocol shared by local, brokered, and VM providers."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Protocol, runtime_checkable

from edagym.canonical import canonical_digest
from edagym.executors.licenses import LicenseLease
from edagym.executors.model import ExecutionResult, InvocationPlan, JobHandle, JobState
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.environment import EnvironmentSpec, FilesystemScope, PositiveInt


class InvocationStorageReceipt(StrictModel):
    """Path-free identity of one executor-issued bounded writable substrate."""

    schema_version: SchemaVersion = 1
    run_id: Digest
    invocation_id: Identifier
    environment_spec_digest: Digest
    executor_id: Identifier
    executor_implementation_digest: Digest
    provider_capability_digest: Digest
    storage_instance_digest: Digest
    filesystem_identity_digest: Digest
    workspace_identity_digest: Digest
    artifact_directory_identity_digest: Digest
    temporary_directory_identity_digest: Digest
    quota_bytes: PositiveInt
    provider_maximum_bytes: PositiveInt
    reported_capacity_bytes: PositiveInt
    predecessor_receipt_digest: Digest | None = None

    def model_post_init(self, _context: object) -> None:
        if self.predecessor_receipt_digest == self.digest:
            raise ValueError("executor storage receipt cannot reference itself")

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-invocation-storage-v1")


class InvocationStorageLease(Protocol):
    """Opaque live lease consumed only by the generic invocation owner."""

    @property
    def receipt(self) -> InvocationStorageReceipt: ...

    @property
    def workspace(self) -> Path: ...

    @property
    def artifact_directory(self) -> Path: ...

    def close(self) -> None: ...


@runtime_checkable
class ExecutorStorageProvider(Protocol):
    """Capability implemented only when writable paths must be executor-issued."""

    def create_storage(
        self,
        *,
        environment: EnvironmentSpec,
        runtime_root: Path,
        run_id: Digest,
        invocation_id: str,
    ) -> InvocationStorageLease: ...

    def recover_storage(
        self,
        *,
        environment: EnvironmentSpec,
        runtime_root: Path,
        run_id: Digest,
        invocation_id: str,
    ) -> InvocationStorageLease | None: ...


class Executor(Protocol):
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
    ) -> JobHandle: ...

    def inspect(self, handle: JobHandle) -> JobState: ...

    def cancel(self, handle: JobHandle) -> JobState: ...

    def collect(self, handle: JobHandle) -> ExecutionResult: ...

    def abandon(self, invocation_id: str) -> None:
        """Prove that a prior invocation's complete isolation domain is empty."""

        ...


def acquire_executor_storage(
    provider: ExecutorStorageProvider,
    *,
    environment: EnvironmentSpec,
    runtime_root: Path,
    run_id: Digest,
    invocation_id: str,
) -> InvocationStorageLease:
    """Acquire and independently validate one executor-issued live lease."""

    runtime_root.mkdir(mode=0o700, exist_ok=True)
    _require_private_directory(runtime_root)
    lease = provider.create_storage(
        environment=environment,
        runtime_root=runtime_root,
        run_id=run_id,
        invocation_id=invocation_id,
    )
    return _validate_storage_lease(
        lease,
        environment=environment,
        runtime_root=runtime_root,
        run_id=run_id,
        invocation_id=invocation_id,
    )


def recover_executor_storage(
    provider: ExecutorStorageProvider,
    *,
    environment: EnvironmentSpec,
    runtime_root: Path,
    run_id: Digest,
    invocation_id: str,
) -> InvocationStorageLease | None:
    """Reopen only an existing durable lease under its authoritative owner root."""

    _require_private_directory(runtime_root)
    lease = provider.recover_storage(
        environment=environment,
        runtime_root=runtime_root,
        run_id=run_id,
        invocation_id=invocation_id,
    )
    if lease is None:
        return None
    return _validate_storage_lease(
        lease,
        environment=environment,
        runtime_root=runtime_root,
        run_id=run_id,
        invocation_id=invocation_id,
    )


def close_recovered_executor_invocation(
    executor: Executor,
    *,
    environment: EnvironmentSpec,
    runtime_root: Path,
    run_id: Digest,
    invocation_id: str,
) -> InvocationStorageReceipt | None:
    """Fence one interrupted invocation, then release any durable writable substrate."""

    executor.abandon(invocation_id)
    if not isinstance(executor, ExecutorStorageProvider):
        return None
    lease = recover_executor_storage(
        executor,
        environment=environment,
        runtime_root=runtime_root,
        run_id=run_id,
        invocation_id=invocation_id,
    )
    if lease is None:
        return None
    receipt = lease.receipt
    lease.close()
    return receipt


def _validate_storage_lease(
    lease: InvocationStorageLease,
    *,
    environment: EnvironmentSpec,
    runtime_root: Path,
    run_id: Digest,
    invocation_id: str,
) -> InvocationStorageLease:
    try:
        receipt = lease.receipt
        workspace = lease.workspace
        artifact_directory = lease.artifact_directory
        executor = environment.executor
        normalized_root = runtime_root.resolve(strict=True)
        if (
            type(receipt) is not InvocationStorageReceipt
            or not isinstance(workspace, Path)
            or not isinstance(artifact_directory, Path)
            or receipt.run_id != run_id
            or receipt.invocation_id != invocation_id
            or receipt.environment_spec_digest != environment.digest
            or receipt.executor_id != executor.executor_id
            or receipt.executor_implementation_digest != executor.implementation_digest
            or receipt.quota_bytes != environment.resources.disk_bytes
            or receipt.quota_bytes > receipt.provider_maximum_bytes
            or receipt.reported_capacity_bytes > receipt.quota_bytes
            or normalized_root not in workspace.resolve(strict=True).parents
            or normalized_root not in artifact_directory.resolve(strict=True).parents
        ):
            raise ValueError("executor storage receipt differs from the invocation")
        _require_private_directory(workspace)
        _require_private_directory(artifact_directory)
        if _paths_overlap(workspace, artifact_directory):
            raise ValueError("executor storage writable directories overlap")
        return lease
    except BaseException:
        lease.close()
        raise


def release_executor_storage(
    executor: Executor,
    lease: InvocationStorageLease,
    invocation_id: str,
) -> None:
    """Fence an invocation before releasing its writable filesystem."""

    executor.abandon(invocation_id)
    lease.close()


def _require_private_directory(path: Path) -> None:
    try:
        canonical = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ValueError("executor storage directory is unavailable") from None
    if (
        not path.is_absolute()
        or canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("executor storage directory is not private")


def _paths_overlap(left: Path, right: Path) -> bool:
    normalized_left = left.resolve(strict=True)
    normalized_right = right.resolve(strict=True)
    return (
        normalized_left == normalized_right
        or normalized_left in normalized_right.parents
        or normalized_right in normalized_left.parents
    )
