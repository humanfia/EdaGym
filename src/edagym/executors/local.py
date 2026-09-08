"""Contained host-tool processes shared by executor implementations."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import resource
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import IO

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers.closure import ResolvedExecutionClosure
from edagym.drivers.deployment import SiteContainerConfiguration
from edagym.drivers.site_container import site_container_license_environment
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.assets import (
    AssetSnapshot,
    AssetValidationError,
    revalidate_asset_closure,
    validate_asset_closure,
)
from edagym.executors.capabilities import (
    LOCAL_ENV_PATH,
    LOCAL_SYSTEMCTL_PATH,
    LOCAL_SYSTEMD_RUN_PATH,
    ProviderAvailability,
    probe_local_containment,
)
from edagym.executors.licenses import LicenseLease
from edagym.executors.model import (
    COMPOSITE_REPORT_PATH,
    CollectedOutput,
    EnvironmentEntry,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
    JobStateKind,
    ToolRecipeCommand,
    WorkspaceRecipeCommand,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass, Capability
from edagym.specs.environment import (
    ArtifactDisclosure,
    EnvironmentSpec,
    FilesystemScope,
)
from edagym.specs.environment import (
    BrokeredHostToolExecutor as BrokeredExecutorSpec,
)

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_SYSTEMCTL_PATH = LOCAL_SYSTEMCTL_PATH
_SYSTEMD_RUN_PATH = LOCAL_SYSTEMD_RUN_PATH
_ENV_PATH = LOCAL_ENV_PATH
_SYSTEMD_OPERATION_TIMEOUT_SECONDS = 10
_SYSTEMD_QUIESCENCE_TIMEOUT_SECONDS = 5.0
_SYSTEMD_POLL_SECONDS = 0.05
_SYSTEMD_TIMEOUT_RESULT = "timeout"
_INVOCATION_STATE_TOKEN_HEX_LENGTH = 24
_PR_SET_PDEATHSIG = 1


class ExecutorUnavailable(RuntimeError):
    """The selected executor cannot enforce the resolved environment."""


class UnknownJob(RuntimeError):
    """A job handle is not owned by this executor process."""


class CollectionError(RuntimeError):
    """Durable job output is missing or violates its artifact contract."""


@dataclass(slots=True)
class _RunningJob:
    handle: JobHandle
    plan: InvocationPlan
    environment: EnvironmentSpec
    workspace_descriptor: int
    artifact_directory_descriptor: int
    raw_directory: Path
    stdout_path: Path
    stderr_path: Path
    process: subprocess.Popen[bytes]
    isolation_unit: str
    started_monotonic: float
    transient_files: tuple[_PrivateTransientFile, ...]
    post_execution_validators: tuple[Callable[[], bool], ...]
    cancelled: bool = False
    timed_out: bool = False
    collected: ExecutionResult | None = None


@dataclass(frozen=True, slots=True)
class _PrivateTransientFile:
    path: Path
    identity: tuple[int, int, int, int, int, int]


class _ProcessManager:
    def __init__(
        self,
        *,
        executor_id: str,
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
        job_state_root: Path,
    ) -> None:
        if type(asset_source_policy) is not AssetSourcePolicy:
            raise ExecutorUnavailable("executor requires trusted asset source authority")
        self.executor_id = executor_id
        self.asset_source_policy = asset_source_policy
        self.artifact_store = artifact_store
        self.job_state_root = job_state_root
        self.job_state_root.mkdir(mode=_PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
        _require_owned_directory(self.job_state_root)
        containment = probe_local_containment(
            systemctl_path=_SYSTEMCTL_PATH,
            systemd_run_path=_SYSTEMD_RUN_PATH,
            env_path=_ENV_PATH,
        )
        if containment.availability is not ProviderAvailability.AVAILABLE:
            reason = containment.reason
            if reason is None:
                raise ExecutorUnavailable("local containment availability is inconsistent")
            raise ExecutorUnavailable(f"local containment is unavailable: {reason.value}")
        _systemd_unit_state(_isolation_unit(executor_id, "availability_probe"))
        self._jobs: dict[str, _RunningJob] = {}
        self._launch_lock = threading.Lock()
        self._lock = threading.RLock()

    def launch_command(
        self,
        *,
        plan: InvocationPlan,
        environment: EnvironmentSpec,
        command: tuple[str, ...],
        process_environment: Mapping[str, str],
        workspace: Path,
        artifact_directory: Path,
        apply_host_limits: bool,
        pass_fds: tuple[int, ...] = (),
        transient_files: tuple[_PrivateTransientFile, ...] = (),
        post_execution_validators: tuple[Callable[[], bool], ...] = (),
    ) -> JobHandle:
        with self._launch_lock, self._provider_guard():
            return self._launch_command_locked(
                plan=plan,
                environment=environment,
                command=command,
                process_environment=process_environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                apply_host_limits=apply_host_limits,
                pass_fds=pass_fds,
                transient_files=transient_files,
                post_execution_validators=post_execution_validators,
            )

    def _launch_command_locked(
        self,
        *,
        plan: InvocationPlan,
        environment: EnvironmentSpec,
        command: tuple[str, ...],
        process_environment: Mapping[str, str],
        workspace: Path,
        artifact_directory: Path,
        apply_host_limits: bool,
        pass_fds: tuple[int, ...],
        transient_files: tuple[_PrivateTransientFile, ...],
        post_execution_validators: tuple[Callable[[], bool], ...],
    ) -> JobHandle:
        job_id = plan.invocation_id
        with self._lock:
            existing = self._jobs.get(job_id)
            if existing is not None:
                if existing.plan != plan:
                    raise ExecutorUnavailable(
                        "invocation identity already owns another execution plan"
                    )
                _remove_private_transient_files(transient_files, self.job_state_root)
                return existing.handle
            self._require_concurrency_slot(environment)
        _validate_private_transient_files(transient_files, self.job_state_root)
        workspace_descriptor = _open_owned_directory(workspace)
        try:
            artifact_directory_descriptor = _open_owned_directory(artifact_directory)
        except BaseException:
            os.close(workspace_descriptor)
            raise
        try:
            working_descriptor = _open_relative_directory(
                workspace_descriptor,
                plan.working_directory,
            )
        except BaseException:
            os.close(workspace_descriptor)
            os.close(artifact_directory_descriptor)
            raise
        raw_directory = self.job_state_root / job_id
        try:
            raw_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            os.close(working_descriptor)
            os.close(workspace_descriptor)
            os.close(artifact_directory_descriptor)
            _remove_private_transient_files(transient_files, self.job_state_root)
            raise ExecutorUnavailable(
                "invocation has durable executor state and requires recovery"
            ) from None
        stdout_path = raw_directory / "stdout.bin"
        stderr_path = raw_directory / "stderr.bin"
        isolation_unit = _isolation_unit(self.executor_id, plan.invocation_id)
        stdout = _open_output(stdout_path)
        stderr = _open_output(stderr_path)
        supervised_command = _systemd_scope_command(
            isolation_unit,
            command,
            wall_seconds=environment.resources.wall_seconds,
        )
        launch_environment = _systemd_launch_environment(process_environment)
        inherited_descriptors = (*pass_fds, working_descriptor)
        try:
            process = subprocess.Popen(
                supervised_command,
                cwd=f"/proc/self/fd/{working_descriptor}",
                env=launch_environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                close_fds=True,
                pass_fds=inherited_descriptors,
                start_new_session=True,
                preexec_fn=_child_setup(environment, apply_host_limits=apply_host_limits),
            )
        except BaseException:
            os.close(workspace_descriptor)
            os.close(artifact_directory_descriptor)
            stdout.close()
            stderr.close()
            stdout_path.unlink(missing_ok=True)
            stderr_path.unlink(missing_ok=True)
            raw_directory.rmdir()
            _remove_private_transient_files(transient_files, self.job_state_root)
            raise
        finally:
            os.close(working_descriptor)
        stdout.close()
        stderr.close()
        handle = JobHandle(
            job_id=job_id,
            invocation_digest=plan.digest,
            executor_id=self.executor_id,
        )
        with self._lock:
            self._jobs[job_id] = _RunningJob(
                handle=handle,
                plan=plan,
                environment=environment,
                workspace_descriptor=workspace_descriptor,
                artifact_directory_descriptor=artifact_directory_descriptor,
                raw_directory=raw_directory,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                process=process,
                isolation_unit=isolation_unit,
                started_monotonic=time.monotonic(),
                transient_files=transient_files,
                post_execution_validators=post_execution_validators,
            )
        return handle

    def inspect(self, handle: JobHandle) -> JobState:
        with self._lock:
            return self._state(self._get(handle))

    def cancel(self, handle: JobHandle) -> JobState:
        with self._lock:
            job = self._get(handle)
            state = self._state(job)
            if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                job.cancelled = True
                _terminate_isolation(job.isolation_unit)
                with suppress(subprocess.TimeoutExpired):
                    job.process.wait(timeout=_SYSTEMD_OPERATION_TIMEOUT_SECONDS)
            return self._state(job)

    def abandon(self, invocation_id: str) -> None:
        """Destroy a durable systemd scope before restart recovery is journaled."""

        with self._launch_lock, self._provider_guard():
            unit = _isolation_unit(self.executor_id, invocation_id)
            _terminate_isolation(unit)
            _forget_isolation(unit)
            with self._lock:
                job = self._jobs.pop(invocation_id, None)
            if job is not None and job.collected is None:
                with suppress(subprocess.TimeoutExpired):
                    job.process.wait(timeout=_SYSTEMD_OPERATION_TIMEOUT_SECONDS)
                os.close(job.workspace_descriptor)
                os.close(job.artifact_directory_descriptor)
            _remove_private_transient_files(
                () if job is None else job.transient_files,
                self.job_state_root,
            )
            _remove_invocation_transient_files(self.job_state_root, invocation_id)
            _remove_abandoned_raw_state(self.job_state_root, invocation_id)

    def collect(self, handle: JobHandle) -> ExecutionResult:
        with self._lock:
            job = self._get(handle)
            if job.collected is not None:
                return job.collected
            state = self._state(job)
            if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                raise CollectionError("job output cannot be collected before termination")
            try:
                validation_failed = not all(
                    validator() for validator in job.post_execution_validators
                )
            except Exception:
                validation_failed = True
            finally:
                _remove_private_transient_files(job.transient_files, self.job_state_root)
                job.transient_files = ()
            if validation_failed:
                raise CollectionError("tool execution closure changed during execution")
            _seal_private_tree(job.workspace_descriptor)
            _seal_private_tree(job.artifact_directory_descriptor)
            diagnostic = _disclosure_for(job.environment, ArtifactClass.DIAGNOSTIC)
            stdout = self.artifact_store.put_file(
                job.stdout_path,
                artifact_class=ArtifactClass.DIAGNOSTIC,
                sensitivity=diagnostic.sensitivity,
                visibility=diagnostic.visibility,
                redistribution=diagnostic.redistribution,
            )
            stderr = self.artifact_store.put_file(
                job.stderr_path,
                artifact_class=ArtifactClass.DIAGNOSTIC,
                sensitivity=diagnostic.sensitivity,
                visibility=diagnostic.visibility,
                redistribution=diagnostic.redistribution,
            )
            outputs = []
            for declaration in job.plan.outputs:
                try:
                    descriptor = _open_relative_file(
                        job.workspace_descriptor,
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
                        job.environment,
                        declaration.artifact_class,
                    )
                    blob = self.artifact_store.put_file_descriptor(
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
            job.collected = ExecutionResult(
                state=state,
                stdout=stdout,
                stderr=stderr,
                outputs=tuple(outputs),
            )
            job.stdout_path.unlink()
            job.stderr_path.unlink()
            job.raw_directory.rmdir()
            os.close(job.workspace_descriptor)
            os.close(job.artifact_directory_descriptor)
            return job.collected

    def _get(self, handle: JobHandle) -> _RunningJob:
        job = self._jobs.get(handle.job_id)
        if job is None or job.handle != handle:
            raise UnknownJob("job handle is not owned by this executor")
        return job

    def _require_concurrency_slot(self, environment: EnvironmentSpec) -> None:
        active_ids = {
            job.handle.job_id
            for job in self._jobs.values()
            if job.environment.digest == environment.digest
            and self._state(job).state in {JobStateKind.QUEUED, JobStateKind.RUNNING}
        }
        for candidate in self.job_state_root.iterdir():
            if candidate.is_dir() and candidate.name not in self._jobs:
                active_ids.add(candidate.name)
        if len(active_ids) >= environment.resources.max_concurrency:
            raise ExecutorUnavailable("executor environment concurrency limit is exhausted")

    @contextmanager
    def _provider_guard(self) -> Iterator[None]:
        path = self.job_state_root / ".provider.lock"
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
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            ):
                raise ExecutorUnavailable("executor provider lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _state(self, job: _RunningJob) -> JobState:
        exit_code = job.process.poll()
        elapsed = time.monotonic() - job.started_monotonic
        if exit_code is None or not _systemd_unit_is_quiescent(job.isolation_unit):
            if elapsed >= job.environment.resources.wall_seconds:
                job.timed_out = True
                _terminate_isolation(job.isolation_unit)
                with suppress(subprocess.TimeoutExpired):
                    job.process.wait(timeout=_SYSTEMD_OPERATION_TIMEOUT_SECONDS)
                exit_code = job.process.poll()
            else:
                return JobState(handle=job.handle, state=JobStateKind.RUNNING)
        if exit_code is None or not _systemd_unit_is_quiescent(job.isolation_unit):
            return JobState(handle=job.handle, state=JobStateKind.RUNNING)
        if _systemd_unit_result(job.isolation_unit) == _SYSTEMD_TIMEOUT_RESULT:
            job.timed_out = True
        _forget_isolation(job.isolation_unit)
        if job.timed_out:
            return JobState(
                handle=job.handle,
                state=JobStateKind.TIMED_OUT,
                exit_code=exit_code,
                failure=ExecutionFailureKind.TIMEOUT,
            )
        if job.cancelled:
            return JobState(
                handle=job.handle,
                state=JobStateKind.CANCELLED,
                exit_code=exit_code,
                failure=ExecutionFailureKind.CANCELLED,
            )
        if exit_code == 0:
            return JobState(
                handle=job.handle,
                state=JobStateKind.COMPLETED,
                exit_code=0,
            )
        return JobState(
            handle=job.handle,
            state=JobStateKind.FAILED,
            exit_code=exit_code,
            failure=ExecutionFailureKind.CANDIDATE,
        )


class BrokeredHostExecutor:
    """Run only registered tool executables for sealed evaluation."""

    def __init__(
        self,
        *,
        executor_id: str,
        tool_paths: Mapping[str, Path],
        tool_environments: Mapping[str, Mapping[str, str]],
        tool_closures: Mapping[str, ResolvedExecutionClosure] | None = None,
        site_container_configurations: Mapping[
            str, SiteContainerConfiguration
        ] | None = None,
        asset_source_policy: AssetSourcePolicy,
        artifact_store: ContentAddressedStore,
        job_state_root: Path,
    ) -> None:
        self.executor_id = executor_id
        self._tool_paths = MappingProxyType(dict(tool_paths))
        self._tool_environments = MappingProxyType(
            {key: MappingProxyType(dict(value)) for key, value in tool_environments.items()}
        )
        self._tool_closures = MappingProxyType(
            {} if tool_closures is None else dict(tool_closures)
        )
        self._site_container_configurations = MappingProxyType(
            {}
            if site_container_configurations is None
            else dict(site_container_configurations)
        )
        self._tool_identities: dict[str, tuple[int, int, int, int, int, int]] = {}
        if set(self._tool_paths) != set(self._tool_environments):
            raise ExecutorUnavailable("tool paths and environments must have identical ownership")
        if self._tool_closures and set(self._tool_closures) != set(self._tool_paths):
            raise ExecutorUnavailable("tool execution closures must have identical ownership")
        if any(
            closure.entrypoint_path != self._tool_paths[tool_id] or not closure.revalidate()
            for tool_id, closure in self._tool_closures.items()
        ):
            raise ExecutorUnavailable("registered tool execution closure is invalid")
        site_tool_ids = {
            tool_id
            for tool_id, closure in self._tool_closures.items()
            if closure.site_container_runtime is not None
        }
        if set(self._site_container_configurations) != site_tool_ids or any(
            not configuration.revalidate()
            for configuration in self._site_container_configurations.values()
        ):
            raise ExecutorUnavailable("site-container deployment configuration is invalid")
        for path in self._tool_paths.values():
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
                raise ExecutorUnavailable("registered tool is not an executable regular file")
        self._tool_identities = {
            tool_id: _file_identity(path.stat()) for tool_id, path in self._tool_paths.items()
        }
        self._manager = _ProcessManager(
            executor_id=executor_id,
            asset_source_policy=asset_source_policy,
            artifact_store=artifact_store,
            job_state_root=job_state_root,
        )

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
        executor = environment.executor
        if (
            not isinstance(executor, BrokeredExecutorSpec)
            or executor.executor_id != self.executor_id
        ):
            raise ExecutorUnavailable("environment does not bind this brokered executor")
        if plan.view is InvocationView.PARTICIPANT:
            raise ExecutorUnavailable("participants cannot execute inside the host-tool broker")
        _validate_plan_binding(plan, environment)
        _validate_scope(plan, scope)
        _require_owned_directory(artifact_directory)
        asset_snapshots = _bind_asset_closure(
            self._manager,
            environment=environment,
            asset_paths=asset_paths,
            scope=scope,
            writable_paths=(workspace, artifact_directory),
        )
        process_environment: Mapping[str, str] = _base_process_environment(
            workspace,
            artifact_directory,
            plan,
        )
        recipe_descriptor: int | None = None
        transient_files: tuple[_PrivateTransientFile, ...] = ()
        post_execution_validators: tuple[Callable[[], bool], ...] = ()
        pass_fds: tuple[int, ...] = ()
        command: tuple[str, ...]
        if plan.recipe:
            recipe, transient_files, post_execution_validators = self._resolved_recipe(
                plan,
                environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                license_lease=license_lease,
            )
            try:
                recipe_descriptor = _sealed_bytes_file(
                    "edagym-composite-recipe",
                    canonical_bytes(recipe),
                )
            except BaseException:
                _remove_private_transient_files(
                    transient_files, self._manager.job_state_root
                )
                raise
            command = (
                sys.executable,
                os.fspath(Path(__file__).with_name("composite_driver.py")),
                f"/proc/self/fd/{recipe_descriptor}",
                COMPOSITE_REPORT_PATH,
            )
            pass_fds = (recipe_descriptor,)
        else:
            executable = self._trusted_tool_path(plan.tool_id)
            closure = self._tool_closures.get(plan.tool_id)
            runtime = None if closure is None else closure.site_container_runtime
            if runtime is None:
                command = (os.fspath(executable), *plan.arguments)
                process_environment = _tool_process_environment(
                    process_environment,
                    self._tool_environments[plan.tool_id],
                    license_lease,
                )
            else:
                if closure is None:
                    raise ExecutorUnavailable("site-container execution closure disappeared")
                arguments, environment_file = self._site_container_arguments(
                    plan=plan,
                    environment=environment,
                    tool_id=plan.tool_id,
                    capability=plan.capability,
                    arguments=plan.arguments,
                    workspace=workspace,
                    license_lease=license_lease,
                    role="primary",
                )
                transient_files = (environment_file,)
                post_execution_validators = self._tool_runtime_validators(plan.tool_id)
                command = (os.fspath(executable), *arguments)
                process_environment = runtime.host_environment
        try:
            _revalidate_bound_assets(
                asset_snapshots,
                self._manager,
                writable_paths=(workspace, artifact_directory),
            )
            if not all(validator() for validator in post_execution_validators):
                raise ExecutorUnavailable("tool execution closure changed before launch")
            return self._manager.launch_command(
                plan=plan,
                environment=environment,
                command=command,
                process_environment=process_environment,
                workspace=workspace,
                artifact_directory=artifact_directory,
                apply_host_limits=True,
                pass_fds=pass_fds,
                transient_files=transient_files,
                post_execution_validators=post_execution_validators,
            )
        except BaseException:
            _remove_private_transient_files(transient_files, self._manager.job_state_root)
            raise
        finally:
            if recipe_descriptor is not None:
                os.close(recipe_descriptor)

    def _resolved_recipe(
        self,
        plan: InvocationPlan,
        environment: EnvironmentSpec,
        *,
        workspace: Path,
        artifact_directory: Path,
        license_lease: LicenseLease | None,
    ) -> tuple[
        dict[str, object],
        tuple[_PrivateTransientFile, ...],
        tuple[Callable[[], bool], ...],
    ]:
        bindings = {
            (binding.capability, binding.tool_id): binding for binding in environment.tool_bindings
        }
        commands: list[dict[str, object]] = []
        transient_files: list[_PrivateTransientFile] = []
        validators: list[Callable[[], bool]] = []
        try:
            for position, command in enumerate(plan.recipe):
                command_environment = _base_process_environment(
                    workspace,
                    artifact_directory,
                    plan,
                )
                arguments = command.arguments
                if isinstance(command, ToolRecipeCommand):
                    binding = bindings.get((command.capability, command.tool_id))
                    executable = self._trusted_tool_path(command.tool_id)
                    if (
                        binding is None
                        or binding.driver_digest != command.driver_digest
                        or binding.locator.executable != command.executable
                    ):
                        raise ExecutorUnavailable(
                            "composite command does not match a resolved tool binding"
                        )
                    closure = self._tool_closures.get(command.tool_id)
                    runtime = None if closure is None else closure.site_container_runtime
                    command_lease = (
                        license_lease if command.tool_id == plan.tool_id else None
                    )
                    if runtime is None:
                        command_environment = _tool_process_environment(
                            command_environment,
                            self._tool_environments[command.tool_id],
                            command_lease,
                        )
                    else:
                        if closure is None:
                            raise ExecutorUnavailable(
                                "site-container execution closure disappeared"
                            )
                        arguments, environment_file = self._site_container_arguments(
                            plan=plan,
                            environment=environment,
                            tool_id=command.tool_id,
                            capability=command.capability,
                            arguments=command.arguments,
                            workspace=workspace,
                            license_lease=command_lease,
                            role=f"recipe-{position}",
                        )
                        transient_files.append(environment_file)
                        validators.extend(self._tool_runtime_validators(command.tool_id))
                        command_environment = dict(runtime.host_environment)
                    executable_token = os.fspath(executable)
                elif isinstance(command, WorkspaceRecipeCommand):
                    executable_token = command.executable
                else:
                    raise TypeError("unsupported composite recipe command")
                commands.append(
                    {
                        "kind": command.kind,
                        "identity_digest": canonical_digest(
                            command,
                            domain="composite-recipe-command-v1",
                        ),
                        "executable": executable_token,
                        "arguments": arguments,
                        "environment": command_environment,
                    }
                )
        except BaseException:
            _remove_private_transient_files(
                tuple(transient_files), self._manager.job_state_root
            )
            raise
        return (
            {"schema_version": 1, "commands": commands},
            tuple(transient_files),
            tuple(validators),
        )

    def _site_container_arguments(
        self,
        *,
        plan: InvocationPlan,
        environment: EnvironmentSpec,
        tool_id: str,
        capability: Capability,
        arguments: tuple[str, ...],
        workspace: Path,
        license_lease: LicenseLease | None,
        role: str,
    ) -> tuple[tuple[str, ...], _PrivateTransientFile]:
        closure = self._tool_closures.get(tool_id)
        runtime = None if closure is None else closure.site_container_runtime
        if runtime is None or license_lease is None or plan.working_directory != ".":
            raise ExecutorUnavailable(
                "site-container execution requires an active lease and root workspace"
            )
        matches = tuple(
            binding
            for binding in environment.tool_bindings
            if binding.tool_id == tool_id and binding.capability == capability
        )
        if len(matches) != 1 or matches[0].license_binding_id is None:
            raise ExecutorUnavailable("site-container tool lacks one license binding")
        license_binding = next(
            (
                binding
                for binding in environment.licenses
                if binding.license_binding_id == matches[0].license_binding_id
            ),
            None,
        )
        if (
            license_binding is None
            or license_lease.provider_id != license_binding.provider_id
            or license_lease.feature_class != license_binding.feature_class
        ):
            raise ExecutorUnavailable("site-container lease differs from its binding")
        transient: _PrivateTransientFile | None = None
        try:
            license_environment = site_container_license_environment(
                license_lease._process_environment()
            )
            if not license_environment:
                raise ExecutorUnavailable("site-container license environment is unavailable")
            content = runtime.environment_file_bytes(license_environment)
            transient = _write_private_transient_file(
                self._manager.job_state_root,
                plan.invocation_id,
                role,
                content,
            )
            return runtime.invocation_arguments(workspace, transient.path, arguments), transient
        except (OSError, ValueError):
            if transient is not None:
                _remove_private_transient_files(
                    (transient,), self._manager.job_state_root
                )
            raise ExecutorUnavailable("site-container invocation cannot be prepared") from None

    def _trusted_tool_path(self, tool_id: str) -> Path:
        executable = self._tool_paths.get(tool_id)
        identity = self._tool_identities.get(tool_id)
        if executable is None or identity is None:
            raise ExecutorUnavailable("tool is not registered with the broker")
        try:
            current = executable.stat()
        except OSError:
            raise ExecutorUnavailable("registered tool identity cannot be verified") from None
        if (
            _file_identity(current) != identity
            or not stat.S_ISREG(current.st_mode)
            or not os.access(executable, os.X_OK)
        ):
            raise ExecutorUnavailable("registered tool identity changed after broker startup")
        if not all(validator() for validator in self._tool_runtime_validators(tool_id)):
            raise ExecutorUnavailable("registered tool execution closure changed")
        return executable

    def _tool_runtime_validators(self, tool_id: str) -> tuple[Callable[[], bool], ...]:
        closure = self._tool_closures.get(tool_id)
        if closure is None:
            return ()
        configuration = self._site_container_configurations.get(tool_id)
        return (
            (closure.revalidate,)
            if configuration is None
            else (configuration.revalidate, closure.revalidate)
        )

    def inspect(self, handle: JobHandle) -> JobState:
        return self._manager.inspect(handle)

    def cancel(self, handle: JobHandle) -> JobState:
        return self._manager.cancel(handle)

    def collect(self, handle: JobHandle) -> ExecutionResult:
        return self._manager.collect(handle)

    def abandon(self, invocation_id: str) -> None:
        self._manager.abandon(invocation_id)




def _validate_plan_binding(plan: InvocationPlan, environment: EnvironmentSpec) -> None:
    matches = [
        binding
        for binding in environment.tool_bindings
        if binding.capability is plan.capability and binding.tool_id == plan.tool_id
    ]
    if len(matches) != 1:
        raise ExecutorUnavailable("invocation does not match one environment tool binding")
    binding = matches[0]
    if binding.driver_digest != plan.driver_digest or binding.locator.executable != plan.executable:
        raise ExecutorUnavailable("invocation driver or executable identity is stale")


def _validate_scope(plan: InvocationPlan, scope: FilesystemScope) -> None:
    expected = {
        InvocationView.PARTICIPANT: FilesystemScope.PARTICIPANT,
        InvocationView.EVALUATOR: FilesystemScope.EVALUATOR,
        InvocationView.TOOL: FilesystemScope.TOOL,
    }[plan.view]
    if expected is not scope:
        raise ExecutorUnavailable("invocation view does not match its filesystem scope")


def _bind_asset_closure(
    manager: _ProcessManager,
    *,
    environment: EnvironmentSpec,
    asset_paths: Mapping[str, Path],
    scope: FilesystemScope,
    writable_paths: tuple[Path, ...],
) -> Mapping[str, AssetSnapshot]:
    protected_paths = (manager.artifact_store.root, manager.job_state_root)
    try:
        return validate_asset_closure(
            environment,
            asset_paths,
            scope,
            source_policy=manager.asset_source_policy,
            protected_paths=protected_paths,
            writable_paths=writable_paths,
        )
    except AssetValidationError:
        raise ExecutorUnavailable("runtime asset closure is invalid") from None


def _revalidate_bound_assets(
    snapshots: Mapping[str, AssetSnapshot],
    manager: _ProcessManager,
    *,
    writable_paths: tuple[Path, ...],
) -> None:
    try:
        revalidate_asset_closure(
            snapshots,
            protected_paths=(manager.artifact_store.root, manager.job_state_root),
            writable_paths=writable_paths,
        )
    except AssetValidationError:
        raise ExecutorUnavailable("runtime asset closure changed before launch") from None


def _transient_file_prefix(invocation_id: str) -> str:
    identity = canonical_digest(
        {"invocation_id": invocation_id},
        domain="executor-private-transient-v1",
    ).removeprefix("sha256:")
    return f".site-environment-{identity[:_INVOCATION_STATE_TOKEN_HEX_LENGTH]}-"


def _write_private_transient_file(
    root: Path,
    invocation_id: str,
    role: str,
    content: bytes,
) -> _PrivateTransientFile:
    root_descriptor = _open_owned_directory(root)
    descriptor: int | None = None
    name = ""
    try:
        prefix = _transient_file_prefix(invocation_id)
        role_token = canonical_digest(
            {"role": role},
            domain="executor-private-transient-role-v1",
        ).removeprefix("sha256:")[:8]
        for _attempt in range(16):
            name = f"{prefix}{role_token}-{secrets.token_hex(8)}.private"
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    _PRIVATE_FILE_MODE,
                    dir_fd=root_descriptor,
                )
                break
            except FileExistsError:
                continue
        if descriptor is None:
            raise ExecutorUnavailable("private transient identity could not be allocated")
        _write_all_descriptor(descriptor, content)
        os.fsync(descriptor)
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
        ):
            raise ExecutorUnavailable("private transient file could not be sealed")
        return _PrivateTransientFile(
            path=root / name,
            identity=_file_identity(metadata),
        )
    except BaseException:
        if name:
            with suppress(OSError):
                os.unlink(name, dir_fd=root_descriptor)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(root_descriptor)


def _validate_private_transient_files(
    files: tuple[_PrivateTransientFile, ...],
    root: Path,
) -> None:
    root_descriptor = _open_owned_directory(root)
    try:
        for item in files:
            if item.path.parent != root or item.path.name in {"", ".", ".."}:
                raise ExecutorUnavailable("private transient path escapes executor state")
            try:
                descriptor = os.open(
                    item.path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_descriptor,
                )
            except OSError:
                raise ExecutorUnavailable("private transient file is unavailable") from None
            try:
                metadata = os.fstat(descriptor)
                if (
                    _file_identity(metadata) != item.identity
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                ):
                    raise ExecutorUnavailable("private transient file identity changed")
            finally:
                os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _remove_private_transient_files(
    files: tuple[_PrivateTransientFile, ...],
    root: Path,
) -> None:
    if not files:
        return
    root_descriptor = _open_owned_directory(root)
    try:
        for item in files:
            if item.path.parent != root or item.path.name in {"", ".", ".."}:
                raise ExecutorUnavailable("private transient path escapes executor state")
            try:
                descriptor = os.open(
                    item.path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_descriptor,
                )
            except FileNotFoundError:
                continue
            except OSError:
                raise ExecutorUnavailable("private transient file cannot be removed") from None
            try:
                metadata = os.fstat(descriptor)
                if (
                    _file_identity(metadata) != item.identity
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                ):
                    raise ExecutorUnavailable("private transient file identity changed")
                os.unlink(item.path.name, dir_fd=root_descriptor)
                if os.fstat(descriptor).st_nlink != 0:
                    raise ExecutorUnavailable("private transient file was not unlinked")
            finally:
                os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _remove_invocation_transient_files(root: Path, invocation_id: str) -> None:
    root_descriptor = _open_owned_directory(root)
    prefix = _transient_file_prefix(invocation_id)
    try:
        for name in sorted(os.listdir(root_descriptor)):
            if not name.startswith(prefix) or not name.endswith(".private"):
                continue
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_descriptor,
                )
            except FileNotFoundError:
                continue
            except OSError:
                raise ExecutorUnavailable("private transient recovery is unsafe") from None
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                ):
                    raise ExecutorUnavailable("private transient recovery is unsafe")
                os.unlink(name, dir_fd=root_descriptor)
                if os.fstat(descriptor).st_nlink != 0:
                    raise ExecutorUnavailable("private transient recovery did not unlink state")
            finally:
                os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _remove_abandoned_raw_state(root: Path, invocation_id: str) -> None:
    if Path(invocation_id).name != invocation_id or invocation_id in {"", ".", ".."}:
        raise ExecutorUnavailable("executor invocation identity is unsafe")
    root_descriptor = _open_owned_directory(root)
    raw_descriptor: int | None = None
    try:
        try:
            raw_descriptor = os.open(
                invocation_id,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_descriptor,
            )
        except FileNotFoundError:
            return
        _require_owned_directory_descriptor(raw_descriptor)
        names = sorted(os.listdir(raw_descriptor))
        if any(name not in {"stderr.bin", "stdout.bin"} for name in names):
            raise ExecutorUnavailable("abandoned executor state contains an unknown resource")
        for name in names:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=raw_descriptor,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                ):
                    raise ExecutorUnavailable("abandoned executor output is unsafe")
                os.unlink(name, dir_fd=raw_descriptor)
            finally:
                os.close(descriptor)
        os.rmdir(invocation_id, dir_fd=root_descriptor)
    except OSError:
        raise ExecutorUnavailable("abandoned executor state could not be removed") from None
    finally:
        if raw_descriptor is not None:
            os.close(raw_descriptor)
        os.close(root_descriptor)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _open_owned_directory(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError:
        raise ExecutorUnavailable("executor directory cannot be opened safely") from None
    try:
        _require_owned_directory_descriptor(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative_directory(root_descriptor: int, relative: str) -> int:
    descriptor = os.dup(root_descriptor)
    if relative == ".":
        return descriptor
    try:
        for part in PurePosixPath(relative).parts:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative_file(root_descriptor: int, relative: str) -> int:
    parts = PurePosixPath(relative).parts
    parent = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            os.close(descriptor)
            raise OSError(errno.EPERM, "output is not a regular file")
        try:
            os.fchmod(descriptor, _PRIVATE_FILE_MODE)
            sealed_metadata = os.fstat(descriptor)
            if (sealed_metadata.st_dev, sealed_metadata.st_ino, sealed_metadata.st_uid) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
            ) or stat.S_IMODE(sealed_metadata.st_mode) != _PRIVATE_FILE_MODE:
                raise OSError(errno.EPERM, "output permissions could not be sealed")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(parent)


def _seal_private_tree(root_descriptor: int) -> None:
    os.fchmod(root_descriptor, _PRIVATE_DIRECTORY_MODE)
    root_metadata = os.fstat(root_descriptor)
    if (
        root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise CollectionError("executor output root could not be made private")
    try:
        names = sorted(os.listdir(root_descriptor))
    except OSError:
        raise CollectionError("executor output tree cannot be enumerated safely") from None
    for name in names:
        try:
            observed = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        except OSError:
            raise CollectionError("executor output identity cannot be inspected") from None
        if stat.S_ISLNK(observed.st_mode):
            continue
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if not stat.S_ISDIR(observed.st_mode):
            flags |= os.O_NONBLOCK
        try:
            descriptor = os.open(name, flags, dir_fd=root_descriptor)
        except OSError:
            raise CollectionError("executor output cannot be opened safely") from None
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != (
                observed.st_dev,
                observed.st_ino,
            ) or current.st_uid != os.getuid():
                raise CollectionError("executor output identity changed during retention")
            if stat.S_ISDIR(current.st_mode):
                _seal_private_tree(descriptor)
            elif stat.S_ISREG(current.st_mode) and current.st_nlink == 1:
                os.fchmod(descriptor, _PRIVATE_FILE_MODE)
                if stat.S_IMODE(os.fstat(descriptor).st_mode) != _PRIVATE_FILE_MODE:
                    raise CollectionError("executor output file could not be made private")
            else:
                raise CollectionError("executor output tree contains an unsafe node")
        finally:
            os.close(descriptor)


def _minimal_host_environment() -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }


def _sealed_environment_file(entries: tuple[EnvironmentEntry, ...]) -> int | None:
    if not entries:
        return None
    content = "".join(f"{entry.name}={entry.value}\n" for entry in entries).encode()
    return _sealed_bytes_file("edagym-container-environment", content)


def _sealed_bytes_file(name: str, content: bytes) -> int:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        _write_all_descriptor(descriptor, content)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_all_descriptor(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("short write while preparing a container environment")
        view = view[written:]


def _base_process_environment(
    workspace: Path,
    artifact_directory: Path,
    plan: InvocationPlan,
) -> dict[str, str]:
    environment = _minimal_host_environment()
    invocation_state_digest = canonical_digest(
        {"invocation_id": plan.invocation_id},
        domain="executor-invocation-state-v1",
    )
    invocation_state = (
        artifact_directory
        / invocation_state_digest.removeprefix("sha256:")[:_INVOCATION_STATE_TOKEN_HEX_LENGTH]
    )
    invocation_state.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
    _require_owned_directory(invocation_state)
    home = _private_child_directory(invocation_state, "h")
    temporary = _private_child_directory(invocation_state, "t")
    cache = _private_child_directory(invocation_state, "c")
    configuration = _private_child_directory(invocation_state, "g")
    environment.update({entry.name: entry.value for entry in plan.environment})
    environment.update(
        {
            "HOME": os.fspath(home),
            "TMPDIR": os.fspath(temporary),
            "PWD": os.fspath(workspace),
            "XDG_CACHE_HOME": os.fspath(cache),
            "XDG_CONFIG_HOME": os.fspath(configuration),
        }
    )
    return environment


def _private_child_directory(parent: Path, name: str) -> Path:
    child = parent / name
    child.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
    _require_owned_directory(child)
    return child


def _tool_process_environment(
    base: Mapping[str, str],
    tool: Mapping[str, str],
    license_lease: LicenseLease | None,
) -> dict[str, str]:
    licensed = {} if license_lease is None else license_lease._process_environment()
    path = licensed.get("PATH", tool.get("PATH", base["PATH"]))
    environment = dict(tool)
    environment.update(licensed)
    environment.update(base)
    environment["PATH"] = path
    return environment


def _child_setup(
    environment: EnvironmentSpec,
    *,
    apply_host_limits: bool,
) -> Callable[[], None]:
    limits = environment.resources
    expected_parent = os.getpid()

    def configure_child() -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        if os.getppid() != expected_parent:
            os.kill(os.getpid(), signal.SIGKILL)
        os.umask(0o077)
        if not apply_host_limits:
            return
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.disk_bytes, limits.disk_bytes))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.wall_seconds, limits.wall_seconds))

    return configure_child


def _isolation_unit(executor_id: str, invocation_id: str) -> str:
    identity = canonical_digest(
        {"executor_id": executor_id, "invocation_id": invocation_id},
        domain="executor-isolation-unit-v1",
    ).removeprefix("sha256:")
    return f"edagym-{identity}.scope"






def _systemd_scope_command(
    unit: str,
    command: tuple[str, ...],
    *,
    wall_seconds: int,
) -> tuple[str, ...]:
    return (
        os.fspath(_SYSTEMD_RUN_PATH),
        "--user",
        "--scope",
        "--quiet",
        f"--unit={unit}",
        "--property=KillMode=control-group",
        f"--property=RuntimeMaxSec={wall_seconds}s",
        "--property=TimeoutStopSec=5s",
        "--",
        os.fspath(_ENV_PATH),
        "--unset=XDG_RUNTIME_DIR",
        "--unset=DBUS_SESSION_BUS_ADDRESS",
        *command,
    )


def _terminate_isolation(unit: str) -> None:
    if _systemd_unit_is_quiescent(unit):
        return
    result = _run_systemctl(
        "kill",
        "--kill-whom=all",
        "--signal=SIGKILL",
        unit,
    )
    if result.returncode != 0 and not _systemd_unit_is_quiescent(unit):
        raise ExecutorUnavailable("executor isolation domain could not be terminated")
    deadline = time.monotonic() + _SYSTEMD_QUIESCENCE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _systemd_unit_is_quiescent(unit):
            return
        time.sleep(_SYSTEMD_POLL_SECONDS)
    raise ExecutorUnavailable("executor isolation domain did not become quiescent")


def _systemd_unit_is_quiescent(unit: str) -> bool:
    active_state, control_group = _systemd_unit_state(unit)
    if active_state not in {"failed", "inactive"}:
        return False
    if not control_group:
        return True
    cgroup_root = Path("/sys/fs/cgroup")
    cgroup = (cgroup_root / control_group.removeprefix("/")).resolve(strict=False)
    if cgroup != cgroup_root and cgroup_root not in cgroup.parents:
        raise ExecutorUnavailable("systemd returned an invalid executor control group")
    processes = cgroup / "cgroup.procs"
    try:
        return not processes.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return True
    except OSError:
        raise ExecutorUnavailable("executor control group could not be inspected") from None


def _systemd_unit_state(unit: str) -> tuple[str, str]:
    result = _run_systemctl(
        "show",
        "--property=ActiveState",
        "--property=ControlGroup",
        unit,
    )
    if result.returncode != 0:
        raise ExecutorUnavailable("the user systemd manager is unavailable")
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    active_state = properties.get("ActiveState")
    control_group = properties.get("ControlGroup")
    if active_state is None or control_group is None:
        raise ExecutorUnavailable("systemd returned an incomplete isolation state")
    return active_state, control_group


def _systemd_unit_result(unit: str) -> str:
    result = _run_systemctl("show", "--property=Result", unit)
    if result.returncode != 0:
        raise ExecutorUnavailable("the user systemd manager is unavailable")
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    unit_result = properties.get("Result")
    if not unit_result:
        raise ExecutorUnavailable("systemd returned an incomplete isolation result")
    return unit_result


def _forget_isolation(unit: str) -> None:
    result = _run_systemctl("reset-failed", unit)
    if result.returncode != 0 and not _systemd_unit_is_quiescent(unit):
        raise ExecutorUnavailable("executor isolation metadata could not be released")


def _run_systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            (os.fspath(_SYSTEMCTL_PATH), "--user", *arguments),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=_systemd_launch_environment({}),
            timeout=_SYSTEMD_OPERATION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ExecutorUnavailable("the user systemd manager is unavailable") from None


def _systemd_launch_environment(environment: Mapping[str, str]) -> dict[str, str]:
    launched = dict(environment)
    launched["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    return launched


def _open_output(path: Path) -> IO[bytes]:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        _PRIVATE_FILE_MODE,
    )
    return os.fdopen(descriptor, "wb")


def _require_owned_directory(path: Path) -> None:
    descriptor = _open_owned_directory(path)
    try:
        return
    finally:
        os.close(descriptor)


def _require_owned_directory_descriptor(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ExecutorUnavailable("executor directories must be owned and not broadly writable")


def _disclosure_for(
    environment: EnvironmentSpec,
    artifact_class: ArtifactClass,
) -> ArtifactDisclosure:
    disclosure = environment.artifact_policy.persistent_disclosure(artifact_class)
    if disclosure is None:
        raise CollectionError("artifact policy does not permit persistence for this class")
    return disclosure
