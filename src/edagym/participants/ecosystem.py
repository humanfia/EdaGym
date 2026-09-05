"""Isolated calibration transport and journal-derived participant projection."""

from __future__ import annotations

import fcntl
import hashlib
import os
import pwd
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, NoReturn, Self
from uuid import uuid4

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.assets import (
    AssetSnapshot,
    asset_content_digest,
    revalidate_asset_closure,
    validate_asset_closure,
)
from edagym.executors.podman import rootless_podman_command
from edagym.participants.adapters import (
    ParticipantAdapterError,
    ParticipantFailureKind,
)
from edagym.participants.controller import ParticipantController
from edagym.participants.model import ParticipantView
from edagym.run.journal import RunJournal
from edagym.run.model import HarnessRunActor, RunStartedEvent, RunState, StopReason
from edagym.specs.common import (
    Digest,
    Identifier,
    ModelLabel,
    StrictModel,
)
from edagym.specs.environment import (
    ContainerRuntime,
    EnvironmentSpec,
    FilesystemScope,
    GuestTarget,
    NoNetwork,
    RootlessLocalExecutor,
)
from edagym.specs.session import SessionSpec

_READ_CHUNK_BYTES = 64 * 1024
_REAP_TIMEOUT_SECONDS = 1.0
_CONTAINER_CLEANUP_SECONDS = 10.0
_WAIT_POLL_SECONDS = 0.01
_EXECUTABLE_READ_BYTES = 1024 * 1024
_CONTROL_DIRECTORY = "participant-runtime"
_LIFECYCLE_LOCK = "lifecycle.lock"
_ACTIVE_CONTAINER = "active-container.json"
_WORKSPACE_DIRECTORY = "workspaces"
_SHELL_EXECUTABLES = frozenset(
    {
        "/bin/bash",
        "/bin/dash",
        "/bin/ksh",
        "/bin/sh",
        "/bin/zsh",
        "/usr/bin/bash",
        "/usr/bin/dash",
        "/usr/bin/ksh",
        "/usr/bin/sh",
        "/usr/bin/zsh",
    }
)
_CONTAINER_EXECUTABLE = re.compile(r"^/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9][A-Za-z0-9._+-]*$")
_CONTAINER_NAME = re.compile(r"^edagym-[0-9a-f]{16}-[0-9a-f]{16}$")


class ParticipantWorkspaceManifest(StrictModel):
    """Durable binding between a run and one writable workspace inode."""

    run_id: Digest
    task_release_digest: Digest
    environment_spec_digest: Digest
    session_spec_digest: Digest
    harness_digest: Digest
    asset_mount_binding_digest: Digest
    workspace_target: GuestTarget
    path_digest: Digest
    device: Annotated[str, Field(pattern=r"^[0-9]+$")]
    inode: Annotated[str, Field(pattern=r"^[0-9]+$")]

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="participant-workspace-manifest-v1")


class CalibrationHarnessSpec(StrictModel):
    """Frozen identity of a calibration wrapper and its immutable scaffold."""

    model_config = ConfigDict(hide_input_in_errors=True)

    harness_id: Identifier
    image_digest: Digest
    runtime_executable_digest: Digest
    executable: Annotated[str, Field(min_length=2, max_length=240)]
    arguments: Annotated[
        tuple[Annotated[str, Field(max_length=16_384)], ...],
        Field(max_length=256),
    ] = ()
    scaffold_asset_id: Identifier
    scaffold_digest: Digest
    requested_model_route: ModelLabel
    maximum_turn_seconds: Annotated[int, Field(strict=True, ge=1)]
    maximum_response_bytes: Annotated[int, Field(strict=True, ge=1)]

    @field_validator("executable")
    @classmethod
    def reject_shell(cls, executable: str) -> str:
        if not _CONTAINER_EXECUTABLE.fullmatch(executable):
            raise ValueError("calibration wrapper must be an absolute container path")
        if executable in _SHELL_EXECUTABLES:
            raise ValueError("calibration wrapper must be an argv-only executable")
        return executable

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, arguments: tuple[str, ...]) -> tuple[str, ...]:
        if any(not argument or "\0" in argument for argument in arguments):
            raise ValueError("command arguments must be non-empty and cannot contain NUL")
        return arguments

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="calibration-harness-v1")


class _ActiveContainerOwner(StrictModel):
    run_id: Digest
    container_name: Annotated[str, Field(pattern=_CONTAINER_NAME.pattern)]
    owner_pid: Annotated[int, Field(strict=True, ge=1)]
    runtime_executable_digest: Digest
    harness_digest: Digest
    workspace_manifest_digest: Digest
    launcher_pid: Annotated[int, Field(strict=True, ge=1)] | None = None
    launcher_start_ticks: Annotated[int, Field(strict=True, ge=1)] | None = None

    @model_validator(mode="after")
    def validate_launcher_identity(self) -> Self:
        if (self.launcher_pid is None) != (self.launcher_start_ticks is None):
            raise ValueError("launcher process identity must be complete")
        return self


class CalibrationCommandChannel:
    """Run a frozen wrapper inside a run-bound calibration container.

    The wrapper reads one canonical view from standard input and must emit only
    one canonical intent on standard output. This type is intentionally absent
    from paid campaign dispatch interfaces.
    """

    def __init__(
        self,
        *,
        actor_id: str,
        journal: RunJournal,
        environment: EnvironmentSpec,
        session: SessionSpec,
        harness: CalibrationHarnessSpec,
        podman_path: Path,
        image_reference: str,
        workspace: Path,
        artifact_store_root: Path,
        participant_assets: Mapping[str, Path],
        asset_source_policy: AssetSourcePolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        executor = environment.executor
        if environment.digest != journal.header.binding.environment.environment_spec_digest:
            raise ValueError("command environment differs from the run binding")
        if session.digest != journal.header.binding.session.session_spec_digest:
            raise ValueError("command session differs from the run binding")
        if (
            not isinstance(executor, RootlessLocalExecutor)
            or executor.runtime is not ContainerRuntime.PODMAN
        ):
            raise ValueError("command harness requires the bound rootless Podman executor")
        if not isinstance(environment.network, NoNetwork):
            raise ValueError("calibration command harness requires disabled task networking")
        if (
            environment.resources.io_read_bytes_per_second is not None
            or environment.resources.io_write_bytes_per_second is not None
        ):
            raise ValueError("calibration command harness cannot enforce host IO rate limits")
        if executor.image_digest != harness.image_digest:
            raise ValueError("command harness image differs from the run environment")
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}",
            image_reference,
        ) or not image_reference.endswith(f"@{harness.image_digest}"):
            raise ValueError("participant image reference must bind the exact image digest")
        actor = _bound_harness(journal, actor_id)
        if (
            actor.harness_digest != harness.digest
            or actor.scaffold_digest != harness.scaffold_digest
            or actor.requested_model_route != harness.requested_model_route
        ):
            raise ValueError("command harness differs from the run actor binding")
        if not podman_path.is_absolute() or podman_path.name != "podman":
            raise ValueError("participant container launcher must be an absolute Podman path")
        _require_executable(podman_path)
        runtime_path = podman_path.resolve(strict=True)
        if _digest_regular_file(runtime_path) != harness.runtime_executable_digest:
            raise ValueError("participant container runtime differs from the harness binding")
        workspace_path = _require_private_directory(workspace)
        protected_roots = _protected_runtime_roots(
            journal=journal,
            artifact_store_root=artifact_store_root,
        )
        assets = validate_asset_closure(
            environment,
            participant_assets,
            FilesystemScope.PARTICIPANT,
            source_policy=asset_source_policy,
            protected_paths=protected_roots,
            writable_paths=(workspace_path,),
        )
        scaffold = assets.get(harness.scaffold_asset_id)
        if scaffold is None or scaffold.restricted_digest != harness.scaffold_digest:
            raise ValueError("calibration scaffold differs from the run actor binding")
        asset_mount_binding_digest = _asset_mount_binding_digest(environment, assets)

        self.actor_id = actor_id
        self._run_id = journal.header.run_id
        self._journal = journal
        self._environment = environment
        self._session = session
        self._harness = harness
        self._podman_path = runtime_path
        self._image_reference = image_reference
        self._workspace = workspace_path
        self._assets = assets
        self._protected_roots = protected_roots
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)
        self._control_root = _private_control_directory(journal.directory / _CONTROL_DIRECTORY)
        self._workspace_manifest = _bind_workspace_manifest(
            control_root=self._control_root,
            journal=journal,
            environment=environment,
            session=session,
            harness=harness,
            asset_mount_binding_digest=asset_mount_binding_digest,
            workspace=workspace_path,
        )
        self._owner_path = self._control_root / _ACTIVE_CONTAINER
        self._lifecycle_descriptor = _acquire_lifecycle_lock(self._control_root / _LIFECYCLE_LOCK)
        self._exchange_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._active: tuple[str, subprocess.Popen[bytes]] | None = None
        self._closed = False
        try:
            if not self._recover_owned_container():
                raise ValueError("a stale participant container could not be removed")
        except BaseException:
            os.close(self._lifecycle_descriptor)
            raise

    def __repr__(self) -> str:
        return "CalibrationCommandChannel(<isolated>)"

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            active = self._active
        if active is not None:
            self._quiesce_container(*active)
        with self._exchange_lock:
            try:
                self._recover_owned_container()
            finally:
                os.close(self._lifecycle_descriptor)

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        response_bound = _validated_response_bound(maximum_response_bytes)
        if response_bound != self._harness.maximum_response_bytes:
            raise ValueError("participant response bound differs from the harness binding")
        if type(view) is not bytes:
            del view
            _raise_failure(ParticipantFailureKind.CHANNEL_FAILURE)
        try:
            parsed_view = ParticipantView.model_validate_json(view)
        except ValidationError:
            del view
            _raise_failure(ParticipantFailureKind.CHANNEL_FAILURE)
        if parsed_view.actor_id != self.actor_id or parsed_view.run_id != self._run_id:
            del parsed_view, view
            _raise_failure(ParticipantFailureKind.ACTOR_MISMATCH)
        del parsed_view
        result = self._exchange(view, response_bound)
        del view
        if isinstance(result, ParticipantFailureKind):
            _raise_failure(result)
        return result

    def _exchange(
        self,
        view: bytes,
        response_bound: int,
    ) -> bytes | ParticipantFailureKind:
        with self._exchange_lock:
            try:
                remaining = _remaining_run_wall_seconds(
                    self._journal,
                    self._environment,
                    self._session,
                    self._clock(),
                )
                _validate_workspace_manifest(self._workspace, self._workspace_manifest)
                revalidate_asset_closure(
                    self._assets,
                    protected_paths=self._protected_roots,
                    writable_paths=(self._workspace,),
                )
                if (
                    _digest_regular_file(self._podman_path)
                    != self._harness.runtime_executable_digest
                ):
                    raise ValueError("participant runtime changed after binding")
                if not self._recover_owned_container():
                    raise ValueError("stale participant container cleanup failed")
            except Exception:
                return ParticipantFailureKind.CHANNEL_FAILURE
            if remaining <= 0:
                return ParticipantFailureKind.COMMAND_TIMEOUT
            deadline = time.monotonic() + min(
                float(self._harness.maximum_turn_seconds),
                remaining,
            )
            container_name = (
                f"edagym-{self._run_id.removeprefix('sha256:')[:16]}-{uuid4().hex[:16]}"
            )
            owner = _ActiveContainerOwner(
                run_id=self._run_id,
                container_name=container_name,
                owner_pid=os.getpid(),
                runtime_executable_digest=self._harness.runtime_executable_digest,
                harness_digest=self._harness.digest,
                workspace_manifest_digest=self._workspace_manifest.digest,
            )
            try:
                _write_active_owner(self._owner_path, owner)
            except Exception:
                return ParticipantFailureKind.CHANNEL_FAILURE
            with self._state_lock:
                if self._closed:
                    _clear_active_owner(self._owner_path)
                    return ParticipantFailureKind.COMMAND_CANCELLED
                try:
                    process = self._start(container_name)
                    started_owner = owner.model_copy(
                        update={
                            "launcher_pid": process.pid,
                            "launcher_start_ticks": _process_start_ticks(process.pid),
                        }
                    )
                    _replace_active_owner(self._owner_path, started_owner)
                except Exception:
                    with suppress(UnboundLocalError):
                        _terminate_process_group(process)
                    if self._remove_container(container_name):
                        _clear_active_owner(self._owner_path)
                    return ParticipantFailureKind.CHANNEL_FAILURE
                self._active = (container_name, process)
            outcome: bytes | ParticipantFailureKind
            try:
                output = _exchange_pipes(process, view, response_bound, deadline)
                return_code = _wait_until(process, deadline)
            except ParticipantAdapterError as error:
                self._quiesce_container(container_name, process)
                outcome = error.kind
            except Exception:
                self._quiesce_container(container_name, process)
                outcome = ParticipantFailureKind.CHANNEL_FAILURE
            except BaseException:
                self._quiesce_container(container_name, process)
                raise
            else:
                outcome = output if return_code == 0 else ParticipantFailureKind.COMMAND_EXIT
            finally:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()
                cleanup_ok = self._remove_container(container_name)
                if cleanup_ok:
                    _clear_active_owner(self._owner_path)
                with self._state_lock:
                    cancelled = self._closed
                    if self._active == (container_name, process):
                        self._active = None
            if not cleanup_ok:
                return ParticipantFailureKind.CHANNEL_FAILURE
            if cancelled:
                return ParticipantFailureKind.COMMAND_CANCELLED
            return outcome

    def _start(
        self,
        container_name: str,
    ) -> subprocess.Popen[bytes]:
        command = rootless_podman_command(
            podman_path=self._podman_path,
            environment=self._environment,
            workspace=self._workspace,
            artifact_directory=None,
            asset_paths={asset_id: snapshot.path for asset_id, snapshot in self._assets.items()},
            scope=FilesystemScope.PARTICIPANT,
            image=self._image_reference,
            environment_fd=None,
            executable=self._harness.executable,
            arguments=self._harness.arguments,
            interactive=True,
            container_name=container_name,
            exact_entrypoint=True,
            hermetic_process_environment=True,
        )
        return subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            shell=False,
            close_fds=True,
            start_new_session=True,
            bufsize=0,
        )

    def _recover_owned_container(self) -> bool:
        owner = _read_active_owner(self._owner_path)
        if owner is None:
            return True
        if (
            owner.run_id != self._run_id
            or owner.runtime_executable_digest != self._harness.runtime_executable_digest
            or owner.harness_digest != self._harness.digest
            or owner.workspace_manifest_digest != self._workspace_manifest.digest
        ):
            return False
        try:
            owned_workspace = _read_workspace_manifest(
                self._control_root,
                owner.workspace_manifest_digest,
            )
        except ValueError:
            return False
        if (
            owned_workspace.run_id != self._run_id
            or owned_workspace.environment_spec_digest != self._environment.digest
            or owned_workspace.session_spec_digest != self._session.digest
        ):
            return False
        _terminate_owned_launcher(owner, self._harness.runtime_executable_digest)
        removed = self._remove_container(owner.container_name)
        if removed:
            _clear_active_owner(self._owner_path)
        return removed

    def _remove_container(self, container_name: str) -> bool:
        deadline = time.monotonic() + _CONTAINER_CLEANUP_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                completed = subprocess.run(
                    (
                        os.fspath(self._podman_path),
                        "rm",
                        "--force",
                        "--time=0",
                        "--ignore",
                        container_name,
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                    },
                    shell=False,
                    close_fds=True,
                    timeout=min(1.0, remaining),
                    check=False,
                )
            except OSError:
                return False
            except subprocess.TimeoutExpired:
                completed = None
            if completed is not None and completed.returncode == 0:
                return True
            if not self._container_exists(container_name, deadline):
                return True
            time.sleep(min(_WAIT_POLL_SECONDS, max(0.0, deadline - time.monotonic())))

    def _container_exists(self, container_name: str, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        try:
            completed = subprocess.run(
                (
                    os.fspath(self._podman_path),
                    "container",
                    "exists",
                    container_name,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                shell=False,
                close_fds=True,
                timeout=min(1.0, remaining),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return True
        return completed.returncode != 1

    def _quiesce_container(
        self,
        container_name: str,
        process: subprocess.Popen[bytes],
    ) -> None:
        with suppress(OSError, subprocess.SubprocessError):
            subprocess.run(
                (os.fspath(self._podman_path), "kill", container_name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                shell=False,
                close_fds=True,
                timeout=_CONTAINER_CLEANUP_SECONDS,
                check=False,
            )
        try:
            process.wait(timeout=_REAP_TIMEOUT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            _terminate_process_group(process)


class ParticipantActionProjection(StrictModel):
    """Typed non-confidential result of one journal-owned participant action."""

    run_id: Digest
    state_digest: Digest
    next_sequence: Annotated[int, Field(strict=True, ge=1)]
    current_writer: Identifier
    terminal_reason: StopReason | None


class ParticipantProjectedEvent(StrictModel):
    kind: Literal["result"] = "result"
    result: ParticipantActionProjection


class ParticipantSessionProjection:
    """Drive only the trusted controller that derives its view from the journal."""

    def __init__(self, controller: ParticipantController) -> None:
        if not isinstance(controller, ParticipantController):
            raise TypeError("session projection requires a participant controller")
        self._controller = controller
        self._run_id = controller.run_id
        self._lock = threading.Lock()
        self._closed = False

    def stream_once(self) -> Iterator[ParticipantProjectedEvent]:
        yield ParticipantProjectedEvent(result=self.act_once())

    def act_once(self) -> ParticipantActionProjection:
        with self._lock:
            if self._closed:
                raise ParticipantAdapterError(ParticipantFailureKind.COMMAND_CANCELLED)
            state = self._controller.act_once()
            if type(state) is not RunState or state.run_id != self._run_id:
                raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
            projection = ParticipantActionProjection(
                run_id=state.run_id,
                state_digest=canonical_digest(state, domain="run-state-v1"),
                next_sequence=state.next_sequence,
                current_writer=state.current_writer,
                terminal_reason=state.terminal_reason,
            )
            return ParticipantActionProjection.model_validate(projection.model_dump())

    def close(self) -> None:
        with self._lock:
            self._closed = True


class ParticipantProjectionRegistry:
    """Open at most one journal-derived projection for each run."""

    def __init__(self) -> None:
        self._run_ids: set[str] = set()
        self._lock = threading.Lock()

    def open(self, controller: ParticipantController) -> ParticipantSessionProjection:
        if not isinstance(controller, ParticipantController):
            raise TypeError("projection registry requires a participant controller")
        run_id = controller.run_id
        with self._lock:
            if run_id in self._run_ids:
                raise ValueError("a projected run may open only one session")
            session = ParticipantSessionProjection(controller)
            self._run_ids.add(run_id)
            return session


def _bound_harness(journal: RunJournal, actor_id: str) -> HarnessRunActor:
    matches = [
        actor
        for actor in journal.header.binding.session.actors
        if isinstance(actor, HarnessRunActor) and actor.actor_id == actor_id
    ]
    if len(matches) != 1:
        raise ValueError("command channel actor must be a bound harness")
    return matches[0]


def _asset_mount_binding_digest(
    environment: EnvironmentSpec,
    assets: Mapping[str, AssetSnapshot],
) -> Digest:
    mounts = tuple(
        {
            "asset_id": mount.asset_id,
            "restricted_digest": assets[mount.asset_id].restricted_digest,
            "scope": mount.scope,
            "target": mount.target,
        }
        for mount in environment.filesystem.readonly_assets
        if mount.scope is FilesystemScope.PARTICIPANT
    )
    return canonical_digest(mounts, domain="participant-asset-mount-binding-v1")


def participant_asset_digest(path: Path) -> Digest:
    """Compatibility alias for the neutral restricted asset identity."""

    return asset_content_digest(path)


def _digest_regular_file(path: Path) -> Digest:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError:
        raise ValueError("bound executable cannot be opened safely") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("bound executable is not a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, _EXECUTABLE_READ_BYTES):
            digest.update(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(metadata):
            raise ValueError("bound executable changed while it was hashed")
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def _protected_runtime_roots(
    *,
    journal: RunJournal,
    artifact_store_root: Path,
) -> tuple[Path, ...]:
    roots = [
        _require_absolute_existing_path(journal.directory, "journal root"),
        _require_absolute_existing_path(artifact_store_root, "artifact store root"),
    ]
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    credential_root = account_home / ".codex"
    if credential_root.exists():
        roots.append(
            _require_absolute_existing_path(credential_root, "credential configuration root")
        )
    return tuple(roots)


def _require_absolute_existing_path(path: Path, role: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{role} must be absolute")
    try:
        metadata = path.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{role} cannot be a symbolic link")
        resolved = path.resolve(strict=True)
        if _file_identity(metadata) != _file_identity(resolved.stat(follow_symlinks=False)):
            raise ValueError(f"{role} changed while it was resolved")
        return resolved
    except (OSError, RuntimeError):
        raise ValueError(f"{role} cannot be resolved safely") from None


def _private_control_directory(path: Path) -> Path:
    with suppress(FileExistsError):
        path.mkdir(mode=0o700)
    return _require_private_directory(path)


def _bind_workspace_manifest(
    *,
    control_root: Path,
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
    harness: CalibrationHarnessSpec,
    asset_mount_binding_digest: Digest,
    workspace: Path,
) -> ParticipantWorkspaceManifest:
    metadata = workspace.stat(follow_symlinks=False)
    manifest = ParticipantWorkspaceManifest(
        run_id=journal.header.run_id,
        task_release_digest=journal.header.binding.task.release_digest,
        environment_spec_digest=environment.digest,
        session_spec_digest=session.digest,
        harness_digest=harness.digest,
        asset_mount_binding_digest=asset_mount_binding_digest,
        workspace_target=environment.filesystem.workspace_target,
        path_digest=canonical_digest(
            {"path": os.fspath(workspace)},
            domain="participant-workspace-path-v1",
        ),
        device=str(metadata.st_dev),
        inode=str(metadata.st_ino),
    )
    manifest_root = _private_control_directory(control_root / _WORKSPACE_DIRECTORY)
    path = manifest_root / f"{manifest.digest.removeprefix('sha256:')}.json"
    content = canonical_bytes(manifest) + b"\n"
    if path.exists():
        if _read_secure_file(path) != content:
            raise ValueError("participant workspace manifest conflicts with durable state")
    else:
        _atomic_replace(path, content)
    _validate_workspace_manifest(workspace, manifest)
    return manifest


def _read_workspace_manifest(
    control_root: Path,
    manifest_digest: Digest,
) -> ParticipantWorkspaceManifest:
    path = control_root / _WORKSPACE_DIRECTORY / f"{manifest_digest.removeprefix('sha256:')}.json"
    content = _read_secure_file(path)
    try:
        manifest = ParticipantWorkspaceManifest.model_validate_json(content)
    except ValidationError:
        raise ValueError("participant workspace manifest is invalid") from None
    if content != canonical_bytes(manifest) + b"\n" or manifest.digest != manifest_digest:
        raise ValueError("participant workspace manifest identity is invalid")
    return manifest


def _validate_workspace_manifest(
    workspace: Path,
    manifest: ParticipantWorkspaceManifest,
) -> None:
    current = _require_private_directory(workspace)
    metadata = current.stat(follow_symlinks=False)
    if (
        canonical_digest(
            {"path": os.fspath(current)},
            domain="participant-workspace-path-v1",
        )
        != manifest.path_digest
        or str(metadata.st_dev) != manifest.device
        or str(metadata.st_ino) != manifest.inode
    ):
        raise ValueError("participant workspace differs from its durable manifest")


def _acquire_lifecycle_lock(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("participant lifecycle lock is not private")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BlockingIOError:
        os.close(descriptor)
        raise ValueError("a participant channel already owns this run") from None
    except BaseException:
        with suppress(UnboundLocalError):
            os.close(descriptor)
        raise


def _read_active_owner(path: Path) -> _ActiveContainerOwner | None:
    if not path.exists():
        return None
    content = _read_secure_file(path)
    try:
        owner = _ActiveContainerOwner.model_validate_json(content)
    except ValidationError:
        raise ValueError("participant container owner record is invalid") from None
    if content != canonical_bytes(owner) + b"\n":
        raise ValueError("participant container owner record is not canonical")
    return owner


def _write_active_owner(path: Path, owner: _ActiveContainerOwner) -> None:
    if path.exists():
        raise ValueError("participant container already has a durable owner")
    _atomic_replace(path, canonical_bytes(owner) + b"\n")


def _replace_active_owner(path: Path, owner: _ActiveContainerOwner) -> None:
    if not path.exists():
        raise ValueError("participant container owner disappeared during launch")
    _atomic_replace(path, canonical_bytes(owner) + b"\n")


def _clear_active_owner(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


def _read_secure_file(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ValueError("participant durable state cannot be opened safely") from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("participant durable state must be a private regular file")
        content = bytearray()
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            content.extend(chunk)
            if len(content) > 1024 * 1024:
                raise ValueError("participant durable state exceeds its size bound")
        if _file_identity(os.fstat(descriptor)) != _file_identity(metadata):
            raise ValueError("participant durable state changed while it was read")
        return bytes(content)
    finally:
        os.close(descriptor)


def _atomic_replace(path: Path, content: bytes) -> None:
    temporary = path.parent / f"incoming-{uuid4().hex}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _remaining_run_wall_seconds(
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
    now: datetime,
) -> float:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("participant clock must be timezone-aware")
    events = journal.read_events()
    starts = tuple(event for event in events if isinstance(event, RunStartedEvent))
    if len(starts) != 1 or journal.state().terminal_reason is not None:
        return 0.0
    elapsed = max(0.0, (now.astimezone(UTC) - starts[0].timestamp).total_seconds())
    limit = min(
        environment.resources.wall_seconds,
        session.resources.max_wall_seconds,
    )
    return max(0.0, float(limit) - elapsed)


def _process_start_ticks(process_id: int) -> int:
    try:
        content = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
        closing = content.rindex(")")
        fields = content[closing + 2 :].split()
        start_ticks = int(fields[19])
    except (OSError, ValueError, IndexError):
        raise ValueError("participant launcher process identity is unavailable") from None
    if start_ticks <= 0 or os.getpgid(process_id) != process_id:
        raise ValueError("participant launcher does not own its process group")
    return start_ticks


def _terminate_owned_launcher(
    owner: _ActiveContainerOwner,
    runtime_executable_digest: Digest,
) -> None:
    process_id = owner.launcher_pid
    start_ticks = owner.launcher_start_ticks
    if process_id is None or start_ticks is None:
        return
    try:
        if (
            _process_start_ticks(process_id) != start_ticks
            or _digest_regular_file(Path(f"/proc/{process_id}/exe").resolve(strict=True))
            != runtime_executable_digest
        ):
            return
    except (OSError, ValueError):
        return
    _signal_process_group(process_id)


def _require_private_directory(path: Path) -> Path:
    if not path.is_absolute() or ":" in os.fspath(path):
        raise ValueError("participant workspace must be absolute")
    try:
        original = path.stat(follow_symlinks=False)
        if stat.S_ISLNK(original.st_mode):
            raise ValueError("participant workspace cannot be a symbolic link")
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except (OSError, RuntimeError):
        raise ValueError("participant workspace must exist") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or _file_identity(original) != _file_identity(metadata)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("participant workspace must be private and owned")
    return resolved


def _require_executable(path: Path) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise ValueError("participant container launcher is unavailable") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(path, os.X_OK)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ValueError("participant container launcher must be a root-owned executable")


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written == 0:
            raise OSError("short write while preparing participant environment")
        remaining = remaining[written:]


def _validated_response_bound(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("participant response bound must be a positive integer")
    return value


def _raise_failure(failure: ParticipantFailureKind) -> NoReturn:
    raise ParticipantAdapterError(failure) from None


def _exchange_pipes(
    process: subprocess.Popen[bytes],
    request: bytes,
    maximum_bytes: int,
    deadline: float,
) -> bytes:
    if process.stdin is None or process.stdout is None:
        raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
    input_descriptor = process.stdin.fileno()
    output_descriptor = process.stdout.fileno()
    os.set_blocking(input_descriptor, False)
    os.set_blocking(output_descriptor, False)
    chunks: list[bytes] = []
    total = 0
    written = 0
    input_open = bool(request)
    output_open = True
    if not input_open:
        process.stdin.close()
    with selectors.DefaultSelector() as selector:
        selector.register(output_descriptor, selectors.EVENT_READ, "output")
        if input_open:
            selector.register(input_descriptor, selectors.EVENT_WRITE, "input")
        while input_open or output_open:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not (events := selector.select(remaining)):
                raise ParticipantAdapterError(ParticipantFailureKind.COMMAND_TIMEOUT)
            for key, _ in events:
                if key.data == "input":
                    try:
                        count = os.write(
                            input_descriptor,
                            request[written : written + _READ_CHUNK_BYTES],
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        count = 0
                    written += count
                    if count == 0 or written == len(request):
                        selector.unregister(input_descriptor)
                        process.stdin.close()
                        input_open = False
                    continue
                try:
                    chunk = os.read(
                        output_descriptor,
                        min(_READ_CHUNK_BYTES, maximum_bytes + 1 - total),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(output_descriptor)
                    output_open = False
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    raise ParticipantAdapterError(ParticipantFailureKind.RESPONSE_BOUND)
    return b"".join(chunks)


def _wait_until(process: subprocess.Popen[bytes], deadline: float) -> int:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ParticipantAdapterError(ParticipantFailureKind.COMMAND_TIMEOUT)
        try:
            status = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        if status is not None:
            _signal_process_group(process.pid)
            try:
                return process.wait(timeout=min(remaining, _REAP_TIMEOUT_SECONDS))
            except subprocess.TimeoutExpired:
                raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        time.sleep(min(remaining, _WAIT_POLL_SECONDS))


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    _signal_process_group(process.pid)
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=_REAP_TIMEOUT_SECONDS)


def _signal_process_group(process_group: int) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGKILL)
