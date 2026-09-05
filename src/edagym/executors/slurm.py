"""Durable Slurm scheduling with an explicitly contained Apptainer payload."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import shlex
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated

from pydantic import Field, TypeAdapter, ValidationError

from edagym.canonical import canonical_bytes
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.assets import (
    AssetSnapshot,
    AssetValidationError,
    asset_content_digest,
    revalidate_asset_closure,
    validate_asset_closure,
)
from edagym.executors.capabilities import (
    ExecutorCapability,
    ExecutorProviderKind,
    ProviderAvailability,
    probe_slurm_apptainer,
)
from edagym.executors.licenses import LicenseLease
from edagym.executors.local import (
    CollectionError,
    ExecutorUnavailable,
    UnknownJob,
    _disclosure_for,
    _open_owned_directory,
    _open_relative_file,
    _validate_plan_binding,
    _validate_scope,
)
from edagym.executors.model import (
    CollectedOutput,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
    JobStateKind,
)
from edagym.executors.slurm_protocol import (
    HostDirectoryBinding,
    SlurmInputBinding,
    SlurmJobRecord,
    SlurmLaunchManifest,
    SlurmRecordPhase,
    SlurmSharedDirectory,
    validate_slurm_absolute_path,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import (
    ArtifactClass,
    Identifier,
    JcsNonNegativeInt,
    StrictModel,
)
from edagym.specs.environment import (
    EnvironmentSpec,
    FilesystemScope,
    ImageToolLocator,
    NoNetwork,
)
from edagym.specs.environment import SlurmApptainerExecutor as SlurmExecutorSpec

_COMMAND_TIMEOUT_SECONDS = 20
_CLEAN_HOST_ENVIRONMENT = MappingProxyType(
    {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
)
_WORKER_BOOTSTRAP = """\
import hashlib, os, sys, types
def load(path, expected):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        content = b''
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            content += block
    finally:
        os.close(descriptor)
    observed = 'sha256:' + hashlib.sha256(content).hexdigest()
    if observed != expected:
        raise SystemExit(70)
    return content
try:
    (
        worker_path,
        worker_digest,
        identity_path,
        identity_digest,
        manifest_path,
        manifest_digest,
    ) = sys.argv[1:]
    worker = load(worker_path, worker_digest)
    identity = load(identity_path, identity_digest)
    manifest = load(manifest_path, manifest_digest)
    module = types.ModuleType('_edagym_asset_identity')
    module.__file__ = identity_path
    sys.modules[module.__name__] = module
    exec(compile(identity, identity_path, 'exec'), module.__dict__)
    namespace = {
        '__name__': '__main__',
        '__file__': worker_path,
        'MANIFEST_BYTES': manifest,
        'CAPTURE_ASSET_IDENTITY': module.capture_asset_identity,
        'FILE_IDENTITY': module.file_identity,
    }
    exec(compile(worker, worker_path, 'exec'), namespace)
except BaseException:
    raise SystemExit(70) from None
"""
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_PAYLOAD_MARKER = "edagym-payload-started"
_PAYLOAD_CONTROL_TARGET = "/run/edagym-control"
_PAYLOAD_RESERVED_ENVIRONMENT = frozenset(
    {
        "APPTAINER_BIND",
        "APPTAINER_BINDPATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PWD",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    }
)
_SCHEDULER_ID = re.compile(r"^[1-9][0-9]*$")
_SCHEDULER_CLUSTER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
_SCHEDULER_SUBMIT_TIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$"
)
_USER_ID = re.compile(r"^.*\(([0-9]+)\)$")
_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)
_ACTIVE_SLURM_STATES = frozenset(
    {
        "COMPLETING",
        "CONFIGURING",
        "RUNNING",
        "SIGNALING",
        "STAGE_OUT",
        "STOPPED",
        "SUSPENDED",
    }
)
_TERMINAL_SLURM_STATES = frozenset(
    {
        "BOOT_FAIL",
        "CANCELLED",
        "COMPLETED",
        "DEADLINE",
        "FAILED",
        "NODE_FAIL",
        "OUT_OF_MEMORY",
        "PREEMPTED",
        "REVOKED",
        "SPECIAL_EXIT",
        "TIMEOUT",
    }
)
_QUEUED_SLURM_STATES = frozenset(
    {
        "PENDING",
        "REQUEUED",
        "REQUEUE_FED",
        "REQUEUE_HOLD",
        "RESIZING",
    }
)
_INFRASTRUCTURE_SLURM_STATES = frozenset(
    {
        "BOOT_FAIL",
        "NODE_FAIL",
        "PREEMPTED",
        "REVOKED",
        "SPECIAL_EXIT",
    }
)


class _SlurmObservation(StrictModel):
    scheduler_job_id: Annotated[str, Field(pattern=r"^[1-9][0-9]*$")]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    exit_status: Annotated[int, Field(strict=True, ge=0, le=255)] | None = None
    signal: Annotated[int, Field(strict=True, ge=0, le=255)] | None = None


class _AccountingSlurmJob(_SlurmObservation):
    submit_time: Annotated[
        str,
        Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$"),
    ]
    job_name: Identifier
    user_id: JcsNonNegativeInt
    cluster: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")]
    restarts: JcsNonNegativeInt


class _ActiveSlurmJob(StrictModel):
    scheduler_job_id: Annotated[str, Field(pattern=r"^[1-9][0-9]*$")]
    job_name: Identifier
    scheduler_comment: Annotated[str, Field(pattern=r"^edagym-v1:[0-9a-f]{64}$")]
    state: Annotated[str, Field(min_length=1, max_length=64)]
    submit_time: Annotated[
        str,
        Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$"),
    ]
    reason: Annotated[str, Field(min_length=1, max_length=128)]
    user_id: JcsNonNegativeInt
    exit_status: Annotated[int, Field(strict=True, ge=0, le=255)]
    signal: Annotated[int, Field(strict=True, ge=0, le=255)]
    restarts: JcsNonNegativeInt


class SlurmApptainerExecutor:
    """Submit contained single-node jobs while retaining exact invocation ownership."""

    def __init__(
        self,
        *,
        executor_id: str,
        implementation_digest: str,
        provider_id: str,
        provider_digest: str,
        site_policy_digest: str,
        capability: ExecutorCapability,
        sbatch_path: Path,
        sacct_path: Path,
        scancel_path: Path,
        scontrol_path: Path,
        squeue_path: Path,
        apptainer_path: Path,
        python_path: Path,
        image_paths: Mapping[str, Path],
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
        job_state_root: Path,
    ) -> None:
        observed = probe_slurm_apptainer(
            provider_id=provider_id,
            provider_digest=provider_digest,
            site_policy_digest=site_policy_digest,
            sbatch_path=sbatch_path,
            sacct_path=sacct_path,
            scancel_path=scancel_path,
            scontrol_path=scontrol_path,
            squeue_path=squeue_path,
            apptainer_path=apptainer_path,
            python_path=python_path,
        )
        if (
            capability.kind is not ExecutorProviderKind.SLURM_APPTAINER
            or capability.availability is not ProviderAvailability.AVAILABLE
            or capability != observed
        ):
            raise ExecutorUnavailable("Slurm provider capability is unavailable or stale")
        self.executor_id = executor_id
        self._implementation_digest = implementation_digest
        self._provider_id = provider_id
        self._provider_digest = provider_digest
        self._site_policy_digest = site_policy_digest
        self._capability = capability
        self._sbatch_path = sbatch_path
        self._sacct_path = sacct_path
        self._scancel_path = scancel_path
        self._scontrol_path = scontrol_path
        self._squeue_path = squeue_path
        self._apptainer_path = apptainer_path
        self._python_path = python_path
        runtime_paths = {
            "sbatch": sbatch_path,
            "sacct": sacct_path,
            "scancel": scancel_path,
            "scontrol": scontrol_path,
            "squeue": squeue_path,
            "apptainer": apptainer_path,
            "python": python_path,
        }
        self._runtime_digests = MappingProxyType(
            {
                runtime_paths[runtime.command]: runtime.executable_digest
                for runtime in capability.runtimes
            }
        )
        self._image_paths = MappingProxyType(dict(image_paths))
        if type(asset_source_policy) is not AssetSourcePolicy:
            raise ExecutorUnavailable("Slurm executor requires trusted asset source authority")
        self._asset_source_policy = asset_source_policy
        self._artifact_store = artifact_store
        self._job_state_root = job_state_root
        _require_cli_safe_path(self._job_state_root, grammar="Slurm filename")
        self._job_state_root.mkdir(
            mode=_PRIVATE_DIRECTORY_MODE,
            parents=True,
            exist_ok=True,
        )
        descriptor = _open_owned_directory(self._job_state_root)
        os.close(descriptor)
        self._lock_root = self._job_state_root / ".locks"
        self._lock_root.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
        descriptor = _open_owned_directory(self._lock_root)
        os.close(descriptor)
        self._invocation_locks: dict[str, threading.Lock] = {}
        self._lock_index = threading.Lock()

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
        with (
            self._provider_guard() as provider_lock,
            self._invocation_guard(plan.invocation_id) as invocation_lock,
        ):
            return self._launch_locked(
                plan,
                environment=environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                asset_paths=asset_paths,
                scope=scope,
                license_lease=license_lease,
                submission_locks=(provider_lock, invocation_lock),
            )

    def _launch_locked(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: dict[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None,
        submission_locks: tuple[int, int],
    ) -> JobHandle:
        executor = environment.executor
        if (
            not isinstance(executor, SlurmExecutorSpec)
            or executor.executor_id != self.executor_id
            or executor.implementation_digest != self._implementation_digest
            or executor.provider_id != self._provider_id
            or executor.provider_digest != self._provider_digest
        ):
            raise ExecutorUnavailable("environment does not bind this Slurm executor")
        if not isinstance(environment.network, NoNetwork):
            raise ExecutorUnavailable("Slurm execution currently requires network none")
        if plan.view is InvocationView.PARTICIPANT:
            raise ExecutorUnavailable(
                "Slurm and Apptainer are not a participant isolation boundary"
            )
        if plan.recipe:
            raise ExecutorUnavailable(
                "composite recipes require a trusted Slurm recipe supervisor"
            )
        _validate_plan_binding(plan, environment)
        _validate_scope(plan, scope)
        binding = next(
            item
            for item in environment.tool_bindings
            if item.capability is plan.capability and item.tool_id == plan.tool_id
        )
        if (
            not isinstance(binding.locator, ImageToolLocator)
            or binding.locator.image_digest != executor.image_digest
        ):
            raise ExecutorUnavailable("Slurm tools must belong to the bound immutable image")
        if binding.license_binding_id is not None or license_lease is not None:
            raise ExecutorUnavailable(
                "licensed Slurm jobs require a trusted scheduler credential bridge"
            )
        _validate_scheduler_resources(environment)
        _require_apptainer_bind_path(environment.filesystem.workspace_target)
        _require_apptainer_bind_path(environment.filesystem.artifact_target)
        for mount in environment.filesystem.readonly_assets:
            if mount.scope is _scope_for_plan(plan):
                _require_apptainer_bind_path(mount.target)
        _validate_payload_environment(plan)
        apptainer_runtime = next(
            runtime for runtime in self._capability.runtimes if runtime.command == "apptainer"
        )
        if (
            executor.apptainer_version != apptainer_runtime.version
            or executor.apptainer_probe_digest != apptainer_runtime.version_output_digest
        ):
            raise ExecutorUnavailable("environment binds stale Apptainer evidence")

        workspace_binding = _capture_private_directory(workspace)
        artifact_binding = _capture_private_directory(artifact_directory)
        _prepare_workspace_runtime_directories(workspace)
        try:
            snapshots = validate_asset_closure(
                environment,
                asset_paths,
                scope,
                source_policy=self._asset_source_policy,
                protected_paths=(self._artifact_store.root, self._job_state_root),
                writable_paths=(workspace, artifact_directory),
            )
        except AssetValidationError:
            raise ExecutorUnavailable("Slurm asset closure is invalid") from None
        _require_apptainer_bind_path(workspace)
        _require_apptainer_bind_path(artifact_directory)
        for snapshot in snapshots.values():
            _require_apptainer_bind_path(snapshot.path)
        image_path = self._verified_image(executor.image_digest)
        _require_image_separation(
            image_path,
            workspace=workspace,
            artifact_directory=artifact_directory,
            protected_paths=(self._artifact_store.root, self._job_state_root),
            asset_paths=tuple(snapshot.path for snapshot in snapshots.values()),
        )
        record_path = self._record_path(plan.invocation_id)
        if record_path.exists():
            record = self._load_record(plan.invocation_id)
            if (
                record.plan != plan
                or record.environment != environment
                or record.workspace != workspace_binding
                or record.artifact_directory != artifact_binding
            ):
                raise ExecutorUnavailable(
                    "invocation identity already owns another Slurm execution"
                )
            if record.phase is not SlurmRecordPhase.SUBMITTED:
                raise ExecutorUnavailable("Slurm invocation requires explicit recovery")
            return self._recover_submission(record).handle

        self._require_concurrency_slot(environment)
        job_directory = record_path.parent
        try:
            job_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            raise ExecutorUnavailable("Slurm invocation has incomplete durable state") from None
        control_directory = job_directory / "control"
        control_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        control_binding = _capture_private_directory(control_directory)
        job_name, scheduler_comment = _scheduler_identity(
            self.executor_id,
            plan.invocation_id,
        )
        record = SlurmJobRecord(
            capability_digest=self._capability.digest,
            phase=SlurmRecordPhase.PREPARED,
            plan=plan,
            environment=environment,
            workspace=workspace_binding,
            artifact_directory=artifact_binding,
            control_directory=control_binding,
            job_name=job_name,
            scheduler_comment=scheduler_comment,
            control_nonce=secrets.token_hex(16),
        )
        self._write_record(record, create=True)
        script_path = job_directory / "submit.sh"
        mounts = {
            mount.asset_id: mount
            for mount in environment.filesystem.readonly_assets
            if mount.scope is _scope_for_plan(plan)
        }
        manifest = SlurmLaunchManifest(
            invocation_id=plan.invocation_id,
            invocation_digest=plan.digest,
            site_policy_digest=self._site_policy_digest,
            control_nonce=record.control_nonce,
            workspace=_shared_directory(workspace_binding),
            artifact_directory=_shared_directory(artifact_binding),
            control_directory=_shared_directory(control_binding),
            image_path=os.fspath(image_path),
            image_digest=executor.image_digest,
            assets=tuple(
                SlurmInputBinding(
                    asset_id=asset_id,
                    path=os.fspath(snapshot.path),
                    restricted_digest=snapshot.restricted_digest,
                    target=mounts[asset_id].target,
                )
                for asset_id, snapshot in snapshots.items()
            ),
            apptainer_path=os.fspath(self._apptainer_path),
            apptainer_digest=apptainer_runtime.executable_digest,
            workspace_target=environment.filesystem.workspace_target,
            artifact_target=environment.filesystem.artifact_target,
            working_directory=_guest_working_directory(environment, plan),
            pids=environment.resources.pids,
            file_size_bytes=environment.resources.disk_bytes,
            payload_environment=plan.environment,
            payload_executable=plan.executable,
            payload_arguments=plan.arguments,
            control_target=_PAYLOAD_CONTROL_TARGET,
        )
        manifest_path = job_directory / "preflight.json"
        manifest_bytes = canonical_bytes(manifest) + b"\n"
        _write_exclusive(
            manifest_path,
            manifest_bytes,
            mode=_PRIVATE_FILE_MODE,
        )
        worker_path, worker_digest = _stage_worker_artifact(
            Path(__file__).with_name("slurm_worker.py"),
            job_directory / "worker.py",
        )
        identity_path, identity_digest = _stage_worker_artifact(
            Path(__file__).with_name("asset_identity.py"),
            job_directory / "asset_identity.py",
        )
        worker_command = (
            os.fspath(self._python_path),
            "-I",
            "-c",
            _WORKER_BOOTSTRAP,
            os.fspath(worker_path),
            worker_digest,
            os.fspath(identity_path),
            identity_digest,
            os.fspath(manifest_path),
            _digest_bytes(manifest_bytes),
        )
        script = "#!/bin/sh\nset -eu\numask 077\nexec " + shlex.join(worker_command) + "\n"
        _write_exclusive(script_path, script.encode("utf-8"), mode=0o700)
        self._revalidate_launch_inputs(
            record,
            snapshots=snapshots,
            image_path=image_path,
            image_digest=executor.image_digest,
        )
        submitted = self._run_scheduler(
            self._sbatch_path,
            "--parsable",
            f"--job-name={job_name}",
            f"--comment={scheduler_comment}",
            "--hold",
            "--export=NIL",
            "--open-mode=truncate",
            f"--output={job_directory / 'stdout.bin'}",
            f"--error={job_directory / 'stderr.bin'}",
            f"--chdir={workspace}",
            "--nodes=1",
            "--ntasks=1",
            f"--cpus-per-task={environment.resources.cpu_millicores // 1000}",
            f"--mem={environment.resources.memory_bytes // 1024**2}M",
            f"--tmp={environment.resources.disk_bytes // 1024**2}M",
            f"--time={environment.resources.wall_seconds // 60}",
            "--no-requeue",
            os.fspath(script_path),
            inherited_descriptors=submission_locks,
        )
        scheduler_job_id, scheduler_cluster = _parse_submission(submitted)
        accepted_record = _transition_record(
            record,
            {
                "phase": SlurmRecordPhase.ACCEPTED,
                "scheduler_job_id": scheduler_job_id,
                "scheduler_cluster": scheduler_cluster,
            },
        )
        self._write_record(accepted_record)
        submitted_record = self._bind_accepted_job(accepted_record)
        self._release_if_held(submitted_record)
        return submitted_record.handle

    def inspect(self, handle: JobHandle) -> JobState:
        with self._invocation_guard(handle.job_id):
            return self._inspect_locked(handle)

    def _inspect_locked(self, handle: JobHandle) -> JobState:
        record = self._owned_record(handle)
        record = self._recover_submission(record)
        if record.phase is SlurmRecordPhase.ABANDONED:
            return JobState(
                handle=record.handle,
                state=JobStateKind.CANCELLED,
                exit_code=0,
                failure=ExecutionFailureKind.CANCELLED,
            )
        assert record.scheduler_job_id is not None
        return self._job_state(record)

    def cancel(self, handle: JobHandle) -> JobState:
        with self._invocation_guard(handle.job_id):
            record = self._owned_record(handle)
            record = self._recover_submission(record)
            if record.phase is SlurmRecordPhase.ABANDONED:
                return JobState(
                    handle=record.handle,
                    state=JobStateKind.CANCELLED,
                    exit_code=0,
                    failure=ExecutionFailureKind.CANCELLED,
                )
            state = self._job_state(record)
            if state.state not in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                return state
            assert record.scheduler_job_id is not None
            self._run_scheduler(
                self._scancel_path,
                *self._cluster_arguments(record.scheduler_cluster),
                "--quiet",
                record.scheduler_job_id,
            )
            deadline = time.monotonic() + _COMMAND_TIMEOUT_SECONDS
            delay = 0.5
            while time.monotonic() < deadline:
                state = self._job_state(record)
                if state.state not in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                    return state
                time.sleep(delay)
                delay = min(delay * 2, 4.0)
            raise ExecutorUnavailable("Slurm cancellation did not become terminal")

    def collect(self, handle: JobHandle) -> ExecutionResult:
        with self._invocation_guard(handle.job_id):
            record = self._owned_record(handle)
            if record.result is not None:
                return record.result
            state = self._inspect_locked(handle)
            record = self._owned_record(handle)
            if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                raise CollectionError("Slurm output cannot be collected before termination")
            job_directory = self._record_path(handle.job_id).parent
            diagnostic = _disclosure_for(
                record.environment,
                artifact_class=ArtifactClass.DIAGNOSTIC,
            )
            job_descriptor = _open_owned_directory(job_directory)
            try:
                stdout_descriptor = _open_relative_file(job_descriptor, "stdout.bin")
                stderr_descriptor = _open_relative_file(job_descriptor, "stderr.bin")
            except OSError as error:
                os.close(job_descriptor)
                raise CollectionError("Slurm diagnostic output is missing or unsafe") from error
            try:
                stdout = self._artifact_store.put_file_descriptor(
                    stdout_descriptor,
                    artifact_class=ArtifactClass.DIAGNOSTIC,
                    sensitivity=diagnostic.sensitivity,
                    visibility=diagnostic.visibility,
                    redistribution=diagnostic.redistribution,
                )
                stderr = self._artifact_store.put_file_descriptor(
                    stderr_descriptor,
                    artifact_class=ArtifactClass.DIAGNOSTIC,
                    sensitivity=diagnostic.sensitivity,
                    visibility=diagnostic.visibility,
                    redistribution=diagnostic.redistribution,
                )
            finally:
                os.close(stdout_descriptor)
                os.close(stderr_descriptor)
                os.close(job_descriptor)

            workspace_descriptor = _open_bound_directory(record.workspace)
            outputs: list[CollectedOutput] = []
            try:
                for declaration in record.plan.outputs:
                    try:
                        descriptor = _open_relative_file(
                            workspace_descriptor,
                            declaration.path,
                        )
                    except FileNotFoundError:
                        if declaration.required:
                            raise CollectionError(
                                f"required output {declaration.logical_id!r} is missing"
                            ) from None
                        continue
                    except OSError as error:
                        raise CollectionError(
                            f"output {declaration.logical_id!r} cannot be opened safely"
                        ) from error
                    try:
                        disclosure = _disclosure_for(
                            record.environment,
                            declaration.artifact_class,
                        )
                        blob = self._artifact_store.put_file_descriptor(
                            descriptor,
                            artifact_class=declaration.artifact_class,
                            sensitivity=disclosure.sensitivity,
                            visibility=disclosure.visibility,
                            redistribution=disclosure.redistribution,
                        )
                    finally:
                        os.close(descriptor)
                    outputs.append(
                        CollectedOutput(
                            logical_id=declaration.logical_id,
                            blob=blob,
                            media_type=declaration.media_type,
                            artifact_class=declaration.artifact_class,
                        )
                    )
            finally:
                os.close(workspace_descriptor)
            result = ExecutionResult(
                state=state,
                stdout=stdout,
                stderr=stderr,
                outputs=tuple(outputs),
            )
            updated = _transition_record(record, {"result": result})
            self._write_record(updated)
            return result

    def abandon(self, invocation_id: str) -> None:
        try:
            normalized_id = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        except ValidationError:
            raise ExecutorUnavailable("invalid Slurm invocation identity") from None
        with self._invocation_guard(normalized_id):
            self._abandon_locked(normalized_id)

    def _abandon_locked(self, normalized_id: str) -> None:
        job_name, scheduler_comment = _scheduler_identity(self.executor_id, normalized_id)
        record: SlurmJobRecord | None = None
        if self._record_path(normalized_id).exists():
            record = self._load_record(normalized_id)
            if record.phase is SlurmRecordPhase.ABANDONED:
                return
            job_name = record.job_name
            scheduler_comment = record.scheduler_comment
        cluster = None if record is None else record.scheduler_cluster
        scheduler_job_id = None if record is None else record.scheduler_job_id
        submit_time = None if record is None else record.scheduler_submit_time
        scheduler_uid = os.getuid() if record is None else record.scheduler_uid
        deadline = time.monotonic() + _COMMAND_TIMEOUT_SECONDS
        delay = 0.5
        while True:
            active = self._matching_live_jobs(
                job_name,
                scheduler_comment,
                cluster,
                scheduler_job_id=scheduler_job_id,
                submit_time=submit_time,
                scheduler_uid=scheduler_uid,
            )
            for job in active:
                self._run_scheduler(
                    self._scancel_path,
                    *self._cluster_arguments(cluster),
                    "--quiet",
                    job.scheduler_job_id,
                )
            if not active:
                break
            if time.monotonic() >= deadline:
                raise ExecutorUnavailable("Slurm recovery could not quiesce the invocation")
            time.sleep(delay)
            delay = min(delay * 2, 4.0)
        if record is not None and record.phase is not SlurmRecordPhase.ABANDONED:
            abandoned = _transition_record(
                record,
                {
                    "phase": SlurmRecordPhase.ABANDONED,
                    "scheduler_job_id": None,
                    "scheduler_cluster": None,
                    "scheduler_submit_time": None,
                    "scheduler_uid": None,
                    "result": None,
                },
            )
            self._write_record(abandoned)
        elif record is None:
            self._remove_incomplete_job_directory(normalized_id)

    def _recover_submission(self, record: SlurmJobRecord) -> SlurmJobRecord:
        if record.phase is SlurmRecordPhase.PREPARED:
            jobs = self._matching_scheduler_jobs(
                record.job_name,
                record.scheduler_comment,
                record.scheduler_cluster,
            )
            if len(jobs) != 1:
                raise ExecutorUnavailable(
                    "prepared Slurm invocation has no unique durable scheduler owner"
                )
            record = _transition_record(
                record,
                {
                    "phase": SlurmRecordPhase.ACCEPTED,
                    "scheduler_job_id": jobs[0].scheduler_job_id,
                },
            )
            self._write_record(record)
        if record.phase is SlurmRecordPhase.ACCEPTED:
            record = self._bind_accepted_job(record)
        if record.phase is SlurmRecordPhase.SUBMITTED:
            self._release_if_held(record)
        return record

    def _bind_accepted_job(self, record: SlurmJobRecord) -> SlurmJobRecord:
        assert record.scheduler_job_id is not None
        jobs = self._matching_scheduler_jobs(
            record.job_name,
            record.scheduler_comment,
            record.scheduler_cluster,
            scheduler_job_id=record.scheduler_job_id,
        )
        if len(jobs) != 1:
            raise ExecutorUnavailable("accepted Slurm job has no unique scheduler identity")
        job = jobs[0]
        if job.state != "PENDING" or job.reason != "JobHeldUser":
            raise ExecutorUnavailable(
                "accepted Slurm job crossed the durable hold boundary"
            )
        submitted = _transition_record(
            record,
            {
                "phase": SlurmRecordPhase.SUBMITTED,
                "scheduler_submit_time": job.submit_time,
                "scheduler_uid": job.user_id,
            },
        )
        self._write_record(submitted)
        return submitted

    def _release_if_held(self, record: SlurmJobRecord) -> None:
        jobs = self._matching_scheduler_jobs(
            record.job_name,
            record.scheduler_comment,
            record.scheduler_cluster,
            scheduler_job_id=record.scheduler_job_id,
            submit_time=record.scheduler_submit_time,
            scheduler_uid=record.scheduler_uid,
        )
        if len(jobs) > 1:
            raise ExecutorUnavailable("Slurm scheduler returned duplicate job ownership")
        if jobs and jobs[0].state in _QUEUED_SLURM_STATES and jobs[0].reason == "JobHeldUser":
            assert record.scheduler_job_id is not None
            self._run_scheduler(
                self._scontrol_path,
                *self._cluster_arguments(record.scheduler_cluster),
                "release",
                record.scheduler_job_id,
            )

    def _job_state(self, record: SlurmJobRecord) -> JobState:
        assert record.scheduler_job_id is not None
        active = self._matching_scheduler_jobs(
            record.job_name,
            record.scheduler_comment,
            record.scheduler_cluster,
            scheduler_job_id=record.scheduler_job_id,
            submit_time=record.scheduler_submit_time,
            scheduler_uid=record.scheduler_uid,
        )
        if len(active) > 1:
            raise ExecutorUnavailable("Slurm scheduler returned duplicate job ownership")
        observation: _SlurmObservation | None
        if active and active[0].state in _QUEUED_SLURM_STATES | _ACTIVE_SLURM_STATES:
            observation = _SlurmObservation(
                scheduler_job_id=active[0].scheduler_job_id,
                state=active[0].state,
            )
        else:
            if active and active[0].state not in _TERMINAL_SLURM_STATES:
                raise ExecutorUnavailable("Slurm returned an unknown owned job state")
            if active:
                observation = _SlurmObservation(
                    scheduler_job_id=active[0].scheduler_job_id,
                    state=active[0].state,
                    exit_status=active[0].exit_status,
                    signal=active[0].signal,
                )
            else:
                observation = self._accounting_observation(record)
                if observation is None:
                    raise ExecutorUnavailable(
                        "Slurm accounting is not yet authoritative for this job"
                    )
        return _state_from_observation(
            record.handle,
            observation,
            payload_started=_payload_started(
                record.control_directory,
                record.control_nonce,
            ),
        )

    def _accounting_observation(
        self,
        record: SlurmJobRecord,
    ) -> _SlurmObservation | None:
        assert record.scheduler_job_id is not None
        output = self._run_scheduler(
            self._sacct_path,
            *self._cluster_arguments(record.scheduler_cluster),
            *("--local",) if record.scheduler_cluster is None else (),
            "--noheader",
            "--parsable2",
            "--allocations",
            "--duplicates",
            f"--jobs={record.scheduler_job_id}",
            (
                "--format=JobIDRaw%64,State%64,ExitCode%16,Submit%32,"
                "JobName%64,UID%20,Cluster%96,Restarts%20"
            ),
        )
        rows: list[_AccountingSlurmJob] = []
        for line in output.decode("ascii", errors="replace").splitlines():
            fields = tuple(field.strip() for field in line.split("|"))
            if len(fields) != 8:
                raise ExecutorUnavailable("Slurm accounting returned a malformed row")
            if fields[0] != record.scheduler_job_id:
                continue
            try:
                scheduler_uid = int(fields[5])
                restarts = int(fields[7])
            except ValueError:
                raise ExecutorUnavailable("Slurm accounting returned an invalid owner") from None
            exit_status, signal = _parse_exit_code(fields[2])
            try:
                row = _AccountingSlurmJob(
                    scheduler_job_id=fields[0],
                    state=_normalize_slurm_state(fields[1]),
                    exit_status=exit_status,
                    signal=signal,
                    submit_time=fields[3],
                    job_name=fields[4],
                    user_id=scheduler_uid,
                    cluster=fields[6],
                    restarts=restarts,
                )
            except ValidationError:
                raise ExecutorUnavailable("Slurm accounting identity is invalid") from None
            if (
                row.job_name == record.job_name
                and row.user_id == record.scheduler_uid
                and (
                    record.scheduler_cluster is None
                    or row.cluster == record.scheduler_cluster
                )
            ):
                if row.submit_time != record.scheduler_submit_time or row.restarts != 0:
                    raise ExecutorUnavailable("Slurm job was requeued or its id was reused")
                rows.append(row)
        if len(rows) > 1:
            raise ExecutorUnavailable("Slurm accounting returned duplicate allocation rows")
        if not rows:
            return None
        row = rows[0]
        return _SlurmObservation(
            scheduler_job_id=row.scheduler_job_id,
            state=row.state,
            exit_status=row.exit_status,
            signal=row.signal,
        )

    def _matching_scheduler_jobs(
        self,
        job_name: str,
        scheduler_comment: str,
        cluster: str | None,
        *,
        scheduler_job_id: str | None = None,
        submit_time: str | None = None,
        scheduler_uid: int | None = None,
    ) -> tuple[_ActiveSlurmJob, ...]:
        scheduler_ids = self._queued_job_ids(
            job_name,
            cluster,
            scheduler_job_id=scheduler_job_id,
        )
        jobs: list[_ActiveSlurmJob] = []
        for identifier in scheduler_ids:
            job = self._scheduler_job(
                identifier,
                cluster,
                expected_job_name=job_name,
                expected_comment=scheduler_comment,
                exact_identity=scheduler_job_id is not None,
            )
            if job is None:
                continue
            if submit_time is not None and job.submit_time != submit_time:
                raise ExecutorUnavailable("Slurm job was requeued or its id was reused")
            if scheduler_uid is not None and job.user_id != scheduler_uid:
                raise ExecutorUnavailable("Slurm job ownership changed")
            jobs.append(job)
        return tuple(jobs)

    def _matching_live_jobs(
        self,
        job_name: str,
        scheduler_comment: str,
        cluster: str | None,
        *,
        scheduler_job_id: str | None,
        submit_time: str | None,
        scheduler_uid: int | None,
    ) -> tuple[_ActiveSlurmJob, ...]:
        jobs = self._matching_scheduler_jobs(
            job_name,
            scheduler_comment,
            cluster,
            scheduler_job_id=scheduler_job_id,
            submit_time=submit_time,
            scheduler_uid=scheduler_uid,
        )
        live: list[_ActiveSlurmJob] = []
        for job in jobs:
            if job.state in _QUEUED_SLURM_STATES | _ACTIVE_SLURM_STATES:
                live.append(job)
            elif job.state not in _TERMINAL_SLURM_STATES:
                raise ExecutorUnavailable("Slurm returned an unknown owned job state")
        return tuple(live)

    def _queued_job_ids(
        self,
        job_name: str,
        cluster: str | None,
        *,
        scheduler_job_id: str | None,
    ) -> tuple[str, ...]:
        output = self._run_scheduler(
            self._squeue_path,
            *self._cluster_arguments(cluster),
            *("--local",) if cluster is None else (),
            "--noheader",
            "--all",
            "--states=all",
            f"--user={os.getuid()}",
            f"--name={job_name}",
            "--format=%i",
        )
        identifiers = tuple(line.strip() for line in output.decode("ascii").splitlines())
        if len(identifiers) > 64 or any(
            not _SCHEDULER_ID.fullmatch(identifier) for identifier in identifiers
        ):
            raise ExecutorUnavailable("Slurm queue returned invalid job identities")
        if len(identifiers) != len(set(identifiers)):
            raise ExecutorUnavailable("Slurm queue returned duplicate job identities")
        if scheduler_job_id is None:
            return identifiers
        return tuple(identifier for identifier in identifiers if identifier == scheduler_job_id)

    def _scheduler_job(
        self,
        requested_job_id: str,
        cluster: str | None,
        *,
        expected_job_name: str,
        expected_comment: str,
        exact_identity: bool,
    ) -> _ActiveSlurmJob | None:
        output = self._run_scheduler(
            self._scontrol_path,
            *self._cluster_arguments(cluster),
            "show",
            "job",
            requested_job_id,
            "--oneliner",
        )
        jobs: list[_ActiveSlurmJob] = []
        for line in output.decode("ascii", errors="replace").splitlines():
            fields = dict(token.split("=", 1) for token in line.split() if "=" in token)
            observed_job_id = fields.get("JobId")
            job_name = fields.get("JobName")
            comment = fields.get("Comment")
            state = fields.get("JobState")
            user_id = fields.get("UserId")
            submit_time = fields.get("SubmitTime")
            reason = fields.get("Reason")
            exit_code = fields.get("ExitCode")
            restarts = fields.get("Restarts")
            if job_name != expected_job_name or comment != expected_comment:
                if exact_identity:
                    raise ExecutorUnavailable("Slurm scheduler job identity changed")
                continue
            user_match = None if user_id is None else _USER_ID.fullmatch(user_id)
            if (
                observed_job_id is None
                or observed_job_id != requested_job_id
                or not _SCHEDULER_ID.fullmatch(observed_job_id)
                or job_name is None
                or comment is None
                or state is None
                or submit_time is None
                or not _SCHEDULER_SUBMIT_TIME.fullmatch(submit_time)
                or reason is None
                or exit_code is None
                or restarts is None
                or user_match is None
            ):
                raise ExecutorUnavailable("Slurm returned incomplete owned job identity")
            try:
                exit_status, signal = _parse_exit_code(exit_code)
                restart_count = int(restarts)
                if restart_count != 0:
                    raise ExecutorUnavailable("Slurm job was requeued or its id was reused")
                jobs.append(
                    _ActiveSlurmJob(
                        scheduler_job_id=observed_job_id,
                        job_name=job_name,
                        scheduler_comment=comment,
                        state=_normalize_slurm_state(state),
                        submit_time=submit_time,
                        reason=reason,
                        user_id=int(user_match.group(1)),
                        exit_status=exit_status,
                        signal=signal,
                        restarts=restart_count,
                    )
                )
            except (ValidationError, ValueError):
                raise ExecutorUnavailable("Slurm returned invalid owned job identity") from None
        if len(jobs) > 1:
            raise ExecutorUnavailable("Slurm returned duplicate scheduler job identities")
        return jobs[0] if jobs else None

    def _revalidate_launch_inputs(
        self,
        record: SlurmJobRecord,
        *,
        snapshots: Mapping[str, AssetSnapshot],
        image_path: Path,
        image_digest: str,
    ) -> None:
        if (
            _capture_private_directory(Path(record.workspace.path)) != record.workspace
            or _capture_private_directory(Path(record.artifact_directory.path))
            != record.artifact_directory
            or _capture_private_directory(Path(record.control_directory.path))
            != record.control_directory
            or asset_content_digest(image_path) != image_digest
        ):
            raise ExecutorUnavailable("Slurm launch inputs changed before submission")
        try:
            revalidate_asset_closure(
                snapshots,
                protected_paths=(self._artifact_store.root, self._job_state_root),
                writable_paths=(
                    Path(record.workspace.path),
                    Path(record.artifact_directory.path),
                ),
            )
        except AssetValidationError:
            raise ExecutorUnavailable("Slurm asset closure changed before submission") from None

    def _verified_image(self, image_digest: str) -> Path:
        path = self._image_paths.get(image_digest)
        if path is None:
            raise ExecutorUnavailable("Slurm image is not registered")
        try:
            observed = asset_content_digest(path)
        except AssetValidationError:
            raise ExecutorUnavailable("Slurm image cannot be verified safely") from None
        if observed != image_digest:
            raise ExecutorUnavailable("Slurm image content does not match its identity")
        return path

    def _owned_record(self, handle: JobHandle) -> SlurmJobRecord:
        if handle.executor_id != self.executor_id:
            raise UnknownJob("job handle is not owned by this executor")
        record = self._load_record(handle.job_id)
        if record.handle != handle:
            raise UnknownJob("job handle is not owned by this executor")
        return record

    def _load_record(self, invocation_id: str) -> SlurmJobRecord:
        path = self._record_path(invocation_id)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise UnknownJob("Slurm invocation record is unavailable") from None
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                or metadata.st_size > 64 * 1024 * 1024
            ):
                raise ExecutorUnavailable("Slurm invocation record is unsafe")
            content = b""
            while block := os.read(descriptor, 1024 * 1024):
                content += block
        finally:
            os.close(descriptor)
        try:
            record = SlurmJobRecord.model_validate_json(content)
        except ValidationError:
            raise ExecutorUnavailable("Slurm invocation record is invalid") from None
        if canonical_bytes(record) + b"\n" != content:
            raise ExecutorUnavailable("Slurm invocation record is not canonical")
        executor = record.environment.executor
        if (
            record.capability_digest != self._capability.digest
            or not isinstance(executor, SlurmExecutorSpec)
            or executor.executor_id != self.executor_id
            or executor.implementation_digest != self._implementation_digest
            or executor.provider_id != self._provider_id
            or executor.provider_digest != self._provider_digest
        ):
            raise ExecutorUnavailable("Slurm invocation record belongs to another provider")
        return record

    def _write_record(self, record: SlurmJobRecord, *, create: bool = False) -> None:
        path = self._record_path(record.plan.invocation_id)
        encoded = canonical_bytes(record) + b"\n"
        if create:
            _write_exclusive(path, encoded, mode=_PRIVATE_FILE_MODE)
            _fsync_directory(path.parent)
            return
        descriptor, temporary = tempfile.mkstemp(
            prefix="record.",
            suffix=".tmp",
            dir=path.parent,
        )
        try:
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(OSError):
                os.unlink(temporary)
            raise

    def _record_path(self, invocation_id: str) -> Path:
        return self._job_state_root / invocation_id / "record.json"

    def _remove_incomplete_job_directory(self, invocation_id: str) -> None:
        job_directory = self._record_path(invocation_id).parent
        if not job_directory.exists():
            return
        descriptor = _open_owned_directory(job_directory)
        try:
            entries = set(os.listdir(descriptor))
            if entries - {"control"}:
                raise ExecutorUnavailable(
                    "incomplete Slurm invocation contains unowned state"
                )
            if "control" in entries:
                control = os.open(
                    "control",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                try:
                    metadata = os.fstat(control)
                    if (
                        metadata.st_uid != os.getuid()
                        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
                        or os.listdir(control)
                    ):
                        raise ExecutorUnavailable(
                            "incomplete Slurm control directory is unsafe"
                        )
                finally:
                    os.close(control)
                os.rmdir("control", dir_fd=descriptor)
        finally:
            os.close(descriptor)
        os.rmdir(job_directory)
        _fsync_directory(self._job_state_root)

    def _require_concurrency_slot(self, environment: EnvironmentSpec) -> None:
        active = 0
        for candidate in self._job_state_root.iterdir():
            if not candidate.is_dir() or candidate.name == ".locks":
                continue
            try:
                invocation_id = _IDENTIFIER_ADAPTER.validate_python(candidate.name)
            except ValidationError:
                raise ExecutorUnavailable("Slurm state contains an invalid owner") from None
            record_path = self._record_path(invocation_id)
            if not record_path.exists():
                continue
            record = self._load_record(invocation_id)
            if (
                record.environment.digest != environment.digest
                or record.phase is SlurmRecordPhase.ABANDONED
                or record.result is not None
            ):
                continue
            if record.phase is not SlurmRecordPhase.SUBMITTED:
                active += 1
                continue
            record = self._recover_submission(record)
            state = self._job_state(record)
            if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                active += 1
        if active >= environment.resources.max_concurrency:
            raise ExecutorUnavailable("Slurm environment concurrency limit is exhausted")

    @contextmanager
    def _provider_guard(self) -> Iterator[int]:
        path = self._job_state_root / ".provider.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            _PRIVATE_FILE_MODE,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            ):
                raise ExecutorUnavailable("Slurm provider lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield descriptor
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @contextmanager
    def _invocation_guard(self, invocation_id: str) -> Iterator[int]:
        try:
            normalized_id = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        except ValidationError:
            raise ExecutorUnavailable("invalid Slurm invocation identity") from None
        with self._lock_index:
            process_lock = self._invocation_locks.setdefault(
                normalized_id,
                threading.Lock(),
            )
        with process_lock:
            path = self._lock_root / f"{normalized_id}.lock"
            try:
                descriptor = os.open(
                    path,
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                    _PRIVATE_FILE_MODE,
                )
            except OSError:
                raise ExecutorUnavailable("Slurm invocation lock is unavailable") from None
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                ):
                    raise ExecutorUnavailable("Slurm invocation lock is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                try:
                    yield descriptor
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _run_scheduler(
        self,
        executable: Path,
        *arguments: str,
        inherited_descriptors: tuple[int, ...] = (),
    ) -> bytes:
        expected_digest = self._runtime_digests.get(executable)
        if expected_digest is None:
            raise ExecutorUnavailable("Slurm control executable is not capability-bound")
        descriptor = _open_verified_executable(executable, expected_digest)
        try:
            completed = subprocess.run(
                (os.fspath(executable), *arguments),
                executable=f"/proc/self/fd/{descriptor}",
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=_CLEAN_HOST_ENVIRONMENT,
                pass_fds=(descriptor, *inherited_descriptors),
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ExecutorUnavailable("Slurm control command is unavailable") from None
        finally:
            os.close(descriptor)
        if completed.returncode != 0 or len(completed.stdout) > 1024 * 1024:
            raise ExecutorUnavailable("Slurm control command failed")
        return completed.stdout

    @staticmethod
    def _cluster_arguments(cluster: str | None) -> tuple[str, ...]:
        return () if cluster is None else (f"--clusters={cluster}",)


def _capture_private_directory(path: Path) -> HostDirectoryBinding:
    _require_cli_safe_path(path, grammar="Slurm runtime")
    descriptor = _open_owned_directory(path)
    try:
        metadata = os.fstat(descriptor)
        resolved = path.resolve(strict=True)
        if resolved != path or any(character in os.fspath(path) for character in "\x00\r\n:"):
            raise ExecutorUnavailable("Slurm directories must use safe canonical paths")
        return HostDirectoryBinding(
            path=os.fspath(path),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            owner=metadata.st_uid,
        )
    finally:
        os.close(descriptor)


def _shared_directory(binding: HostDirectoryBinding) -> SlurmSharedDirectory:
    return SlurmSharedDirectory(path=binding.path, owner=binding.owner)


def _open_bound_directory(binding: HostDirectoryBinding) -> int:
    descriptor = _open_owned_directory(Path(binding.path))
    metadata = os.fstat(descriptor)
    if (metadata.st_dev, metadata.st_ino, metadata.st_uid) != (
        binding.device,
        binding.inode,
        binding.owner,
    ):
        os.close(descriptor)
        raise CollectionError("Slurm workspace identity changed after submission")
    return descriptor


def _payload_started(binding: HostDirectoryBinding, nonce: str) -> bool:
    descriptor = _open_bound_directory(binding)
    try:
        try:
            metadata = os.stat(
                f"{_PAYLOAD_MARKER}-{nonce}",
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        return stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
    finally:
        os.close(descriptor)


def _scheduler_identity(
    executor_id: str,
    invocation_id: str,
) -> tuple[str, str]:
    material = f"{executor_id}\x00{invocation_id}"
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()
    return f"edagym-{digest[:32]}", f"edagym-v1:{digest}"


def _parse_submission(output: bytes) -> tuple[str, str | None]:
    line = output.decode("ascii", errors="strict").strip()
    scheduler_job_id, separator, cluster = line.partition(";")
    if not _SCHEDULER_ID.fullmatch(scheduler_job_id):
        raise ExecutorUnavailable("Slurm submission returned an invalid job identity")
    if separator:
        if not _SCHEDULER_CLUSTER.fullmatch(cluster):
            raise ExecutorUnavailable("Slurm submission returned an invalid cluster identity")
        return scheduler_job_id, cluster
    return scheduler_job_id, None


def _parse_exit_code(value: str) -> tuple[int, int]:
    status, separator, signal = value.strip().partition(":")
    if not separator or not status.isdigit() or not signal.isdigit():
        raise ExecutorUnavailable("Slurm accounting returned an invalid exit code")
    status_value = int(status)
    signal_value = int(signal)
    if status_value > 255 or signal_value > 255:
        raise ExecutorUnavailable("Slurm accounting exit code exceeds its domain")
    return status_value, signal_value


def _normalize_slurm_state(value: str) -> str:
    normalized = value.strip().split(maxsplit=1)[0].removesuffix("+")
    if not normalized or not normalized.replace("_", "").isalnum():
        raise ExecutorUnavailable("Slurm returned an invalid job state")
    return normalized


def _state_from_observation(
    handle: JobHandle,
    observation: _SlurmObservation,
    *,
    payload_started: bool,
) -> JobState:
    state = observation.state
    if state in _QUEUED_SLURM_STATES:
        return JobState(handle=handle, state=JobStateKind.QUEUED)
    if state in _ACTIVE_SLURM_STATES:
        return JobState(handle=handle, state=JobStateKind.RUNNING)
    exit_code = _combined_exit_code(observation.exit_status, observation.signal)
    if state == "COMPLETED" and exit_code == 0:
        return JobState(handle=handle, state=JobStateKind.COMPLETED, exit_code=0)
    if state == "CANCELLED":
        return JobState(
            handle=handle,
            state=JobStateKind.CANCELLED,
            exit_code=exit_code,
            failure=ExecutionFailureKind.CANCELLED,
        )
    if state in {"DEADLINE", "TIMEOUT"}:
        return JobState(
            handle=handle,
            state=JobStateKind.TIMED_OUT,
            exit_code=exit_code,
            failure=ExecutionFailureKind.TIMEOUT,
        )
    if state == "OUT_OF_MEMORY":
        return JobState(
            handle=handle,
            state=JobStateKind.FAILED,
            exit_code=exit_code,
            failure=(
                ExecutionFailureKind.CANDIDATE
                if payload_started
                else ExecutionFailureKind.INFRASTRUCTURE
            ),
        )
    if state in _INFRASTRUCTURE_SLURM_STATES:
        return JobState(
            handle=handle,
            state=JobStateKind.FAILED,
            exit_code=exit_code,
            failure=ExecutionFailureKind.INFRASTRUCTURE,
        )
    if state in {"COMPLETED", "FAILED"}:
        return JobState(
            handle=handle,
            state=JobStateKind.FAILED,
            exit_code=exit_code,
            failure=(
                ExecutionFailureKind.CANDIDATE
                if payload_started
                else ExecutionFailureKind.INFRASTRUCTURE
            ),
        )
    return JobState(
        handle=handle,
        state=JobStateKind.LOST,
        exit_code=exit_code,
        failure=ExecutionFailureKind.INFRASTRUCTURE,
    )


def _combined_exit_code(status: int | None, signal: int | None) -> int:
    if status is None or signal is None:
        return 1
    return status if signal == 0 else 128 + signal


def _guest_working_directory(environment: EnvironmentSpec, plan: InvocationPlan) -> str:
    root = PurePosixPath(environment.filesystem.workspace_target)
    if plan.working_directory == ".":
        return root.as_posix()
    return (root / plan.working_directory).as_posix()


def _scope_for_plan(plan: InvocationPlan) -> FilesystemScope:
    return {
        InvocationView.PARTICIPANT: FilesystemScope.PARTICIPANT,
        InvocationView.EVALUATOR: FilesystemScope.EVALUATOR,
        InvocationView.TOOL: FilesystemScope.TOOL,
    }[plan.view]


def _write_exclusive(path: Path, content: bytes, *, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stage_worker_artifact(source: Path, destination: Path) -> tuple[Path, str]:
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("Slurm worker source is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > 1024 * 1024
        ):
            raise ExecutorUnavailable("Slurm worker source is unsafe")
        content = b""
        while block := os.read(descriptor, 1024 * 1024):
            content += block
    finally:
        os.close(descriptor)
    _write_exclusive(destination, content, mode=_PRIVATE_FILE_MODE)
    return destination, _digest_bytes(content)


def _digest_bytes(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _write_all(descriptor: int, content: bytes) -> None:
    written = 0
    while written < len(content):
        count = os.write(descriptor, content[written:])
        if count <= 0:
            raise OSError("short write while persisting Slurm state")
        written += count


def _open_verified_executable(path: Path, expected_digest: str) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("Slurm control executable is unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & stat.S_IXUSR
            or metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or _digest_descriptor(descriptor) != expected_digest
        ):
            raise ExecutorUnavailable("Slurm control executable identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _digest_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return f"sha256:{digest.hexdigest()}"


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _transition_record(
    record: SlurmJobRecord,
    updates: Mapping[str, object],
) -> SlurmJobRecord:
    values = record.model_dump(mode="python")
    values.update(updates)
    return SlurmJobRecord.model_validate(values)


def _require_cli_safe_path(path: Path | str, *, grammar: str) -> None:
    value = os.fspath(path)
    if any(character in value for character in "\x00\r\n,:%"):
        raise ExecutorUnavailable(f"{grammar} path contains a reserved delimiter")


def _require_apptainer_bind_path(path: Path | str) -> None:
    try:
        validate_slurm_absolute_path(os.fspath(path))
    except ValueError:
        raise ExecutorUnavailable("Apptainer bind path is unsafe") from None


def _validate_scheduler_resources(environment: EnvironmentSpec) -> None:
    resources = environment.resources
    if resources.cpu_millicores % 1000:
        raise ExecutorUnavailable("Slurm CPU limits require whole cores")
    if resources.memory_bytes % 1024**2:
        raise ExecutorUnavailable("Slurm memory limits require whole mebibytes")
    if resources.disk_bytes % 1024**2:
        raise ExecutorUnavailable("Slurm disk limits require whole mebibytes")
    if resources.wall_seconds % 60:
        raise ExecutorUnavailable("Slurm wall limits require whole minutes")
    if (
        resources.io_read_bytes_per_second is not None
        or resources.io_write_bytes_per_second is not None
    ):
        raise ExecutorUnavailable("Slurm site I/O throttling is not implemented")


def _validate_payload_environment(plan: InvocationPlan) -> None:
    if any(entry.name in _PAYLOAD_RESERVED_ENVIRONMENT for entry in plan.environment):
        raise ExecutorUnavailable("Slurm payload environment overrides a runtime-owned name")


def _require_image_separation(
    image_path: Path,
    *,
    workspace: Path,
    artifact_directory: Path,
    protected_paths: tuple[Path, ...],
    asset_paths: tuple[Path, ...],
) -> None:
    try:
        image = image_path.resolve(strict=True)
        image_identity = os.stat(image_path, follow_symlinks=False)
        others = tuple(
            path.resolve(strict=True)
            for path in (workspace, artifact_directory, *protected_paths, *asset_paths)
        )
    except OSError:
        raise ExecutorUnavailable("Slurm image separation cannot be verified") from None
    if any(
        image == other or image in other.parents or other in image.parents
        for other in others
    ):
        raise ExecutorUnavailable("Slurm image overlaps another execution resource")
    for asset_path in asset_paths:
        metadata = os.stat(asset_path, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) == (
            image_identity.st_dev,
            image_identity.st_ino,
        ):
            raise ExecutorUnavailable("Slurm image aliases an execution asset")


def _prepare_workspace_runtime_directories(workspace: Path) -> None:
    for name in (".cache", ".config", ".tmp"):
        path = workspace / name
        path.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
        descriptor = _open_owned_directory(path)
        os.close(descriptor)
