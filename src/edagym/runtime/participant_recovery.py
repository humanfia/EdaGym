"""Descriptor-safe participant controller incarnation and workspace recovery."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import UUID

from edagym.canonical import canonical_digest
from edagym.executors.protocol import Executor, close_recovered_executor_invocation
from edagym.participants.execution import (
    close_interrupted_controller_tools,
    recover_interrupted_executor_tools,
)
from edagym.run.artifact_model import (
    ArtifactManifest,
)
from edagym.run.artifacts import (
    CheckpointMarker,
    ContentAddressedStore,
    manifest_tree,
)
from edagym.run.checkpoints import (
    reconcile_interrupted_evaluations,
    restore_application_checkpoint,
    restore_workspace_checkpoint,
)
from edagym.run.journal import (
    RunJournal,
    participant_incarnation_lifecycle,
    unresolved_tool_requests,
)
from edagym.run.model import (
    CheckpointCommittedEvent,
    EvaluationCompletedEvent,
    EvaluationStartedEvent,
    ParticipantIncarnationBinding,
    ParticipantIncarnationRestoredEvent,
    ParticipantIncarnationRestoredPayload,
    ParticipantIncarnationTerminatedEvent,
    ParticipantIncarnationTerminatedPayload,
    ParticipantProcessIdentity,
    ProducerKind,
    RunState,
)
from edagym.specs.common import Digest, Visibility
from edagym.specs.environment import CheckpointCapability, EnvironmentSpec

_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_PROCESS_STAT_ROOT = Path("/proc")
_MAXIMUM_PROC_BYTES = 4096


class ParticipantRecoveryError(RuntimeError):
    """A participant controller replacement cannot be proven or restored."""


def reconcile_interrupted_run_work(
    *,
    journal: RunJournal,
    executor: Executor,
    environment: EnvironmentSpec,
    timestamp: datetime,
    event_id_factory: Callable[[], UUID],
) -> RunState:
    """Close every executor-backed and controller-local interrupted action.

    Every interrupted invocation is fenced exactly once, and its executor-issued
    storage released, before its loss is journaled: evaluations here and
    participant tool invocations inside the tool closer.
    """

    def fence(invocation_id: str) -> None:
        close_recovered_executor_invocation(
            executor,
            environment=environment,
            runtime_root=journal.directory / "executor-storage",
            run_id=journal.header.run_id,
            invocation_id=invocation_id,
        )

    events = journal.read_events()
    completed = {
        event.payload.job_id
        for event in events
        if isinstance(event, EvaluationCompletedEvent)
    }
    interrupted_evaluations = tuple(
        event
        for event in events
        if isinstance(event, EvaluationStartedEvent) and event.payload.job_id not in completed
    )
    for started in interrupted_evaluations:
        try:
            fence(started.payload.job_id)
        except Exception as error:
            raise ParticipantRecoveryError(
                "executor could not prove interrupted resources quiescent"
            ) from error
    reconcile_interrupted_evaluations(
        journal=journal,
        timestamp=timestamp,
        event_id_factory=event_id_factory,
    )
    try:
        recover_interrupted_executor_tools(
            journal=journal,
            fence=fence,
            timestamp=timestamp,
            event_id_factory=event_id_factory,
        )
    except Exception as error:
        raise ParticipantRecoveryError(
            "executor could not prove an interrupted participant tool quiescent"
        ) from error
    state = close_interrupted_controller_tools(
        journal=journal,
        timestamp=timestamp,
        event_id_factory=event_id_factory,
    )
    if unresolved_tool_requests(journal.read_events()):
        raise ParticipantRecoveryError("participant tool recovery left unresolved work")
    return state


def current_participant_incarnation(
    *,
    generation: int,
    workspace: Path,
    artifact_directory: Path,
) -> ParticipantIncarnationBinding:
    """Capture the current process and exact private runtime directory identities."""

    return ParticipantIncarnationBinding(
        generation=generation,
        process=current_participant_process_identity(),
        workspace_identity_digest=private_directory_identity_digest(
            workspace,
            role="participant_workspace",
        ),
        artifact_directory_identity_digest=private_directory_identity_digest(
            artifact_directory,
            role="participant_artifacts",
        ),
    )


def current_participant_process_identity() -> ParticipantProcessIdentity:
    """Capture a PID-reuse-safe identity for the current Linux process."""

    process_id = os.getpid()
    return ParticipantProcessIdentity(
        process_id=process_id,
        start_time_ticks=_process_start_time_ticks(process_id),
        boot_id_digest=_boot_id_digest(),
    )


def participant_process_is_alive(identity: ParticipantProcessIdentity) -> bool:
    """Return whether the exact recorded process incarnation still exists."""

    if identity.boot_id_digest != _boot_id_digest():
        return False
    try:
        return _process_start_time_ticks(identity.process_id) == identity.start_time_ticks
    except ProcessLookupError:
        return False


def private_directory_identity_digest(path: Path, *, role: str) -> Digest:
    """Derive a path-free identity for one private, owner-controlled directory."""

    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ParticipantRecoveryError(
                "participant runtime directories must be private and owner-controlled"
            )
        return canonical_digest(
            {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
                "owner": metadata.st_uid,
                "role": role,
            },
            domain="participant-private-directory-identity-v1",
        )
    finally:
        os.close(descriptor)


def require_current_participant_incarnation(
    journal: RunJournal,
    *,
    workspace: Path,
    artifact_directory: Path,
) -> ParticipantIncarnationBinding:
    """Require this process and its paths to own the active journal incarnation."""

    lifecycle = participant_incarnation_lifecycle(journal.read_events())
    active = lifecycle.active_incarnation
    if active is None:
        raise ParticipantRecoveryError("participant journal has no active incarnation")
    current = current_participant_incarnation(
        generation=active.generation,
        workspace=workspace,
        artifact_directory=artifact_directory,
    )
    if current != active:
        raise ParticipantRecoveryError(
            "participant runtime differs from the active journal incarnation"
        )
    return active


def restore_participant_incarnation(
    *,
    journal: RunJournal,
    environment: EnvironmentSpec,
    artifact_store: ContentAddressedStore,
    workspace: Path,
    artifact_directory: Path,
    checkpoint_id: str,
    timestamp: Callable[[], datetime],
    event_id_factory: Callable[[], UUID],
) -> tuple[CheckpointMarker, RunState]:
    """Prove controller replacement, restore once, and journal the new generation.

    The caller must hold the journal's cross-process participant dispatch lock and
    must reconcile all executor, provider, license, and tool work before calling.
    """

    events = journal.read_events()
    lifecycle = participant_incarnation_lifecycle(events)
    if not lifecycle.incarnations:
        raise ParticipantRecoveryError("participant journal has no incarnation history")
    latest_restore = next(
        (
            event
            for event in reversed(events)
            if isinstance(event, ParticipantIncarnationRestoredEvent)
        ),
        None,
    )
    active = lifecycle.active_incarnation
    if active is not None and active.process == current_participant_process_identity():
        if (
            latest_restore is None
            or latest_restore.payload.checkpoint_id != checkpoint_id
        ):
            raise ParticipantRecoveryError(
                "an active participant process cannot claim controller recovery"
            )
        require_current_participant_incarnation(
            journal,
            workspace=workspace,
            artifact_directory=artifact_directory,
        )
        marker, _ = _load_checkpoint(artifact_store, environment, checkpoint_id)
        return marker, journal.state()

    pending = lifecycle.pending_termination
    if pending is None:
        if active is None:
            raise ParticipantRecoveryError("participant recovery has no predecessor")
        if participant_process_is_alive(active.process):
            raise ParticipantRecoveryError(
                "the previous participant process is still alive"
            )
        checkpoint = _checkpoint_event(journal, checkpoint_id)
        if checkpoint.payload.manifest_digest != _load_checkpoint(
            artifact_store,
            environment,
            checkpoint_id,
        )[0].manifest_digest:
            raise ParticipantRecoveryError("checkpoint marker differs from the journal")
        journal.transact(
            lambda state: ParticipantIncarnationTerminatedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=event_id_factory(),
                timestamp=timestamp(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=ParticipantIncarnationTerminatedPayload(
                    incarnation_digest=active.digest,
                    checkpoint_id=checkpoint_id,
                    checkpoint_manifest_digest=checkpoint.payload.manifest_digest,
                ),
            )
        )
        events = journal.read_events()
        lifecycle = participant_incarnation_lifecycle(events)
        pending = lifecycle.pending_termination
    if pending is None or pending.checkpoint_id != checkpoint_id:
        raise ParticipantRecoveryError(
            "participant recovery checkpoint differs from its pending termination"
        )

    marker, expected_manifest = _load_checkpoint(
        artifact_store,
        environment,
        checkpoint_id,
    )
    if marker.manifest_digest != pending.checkpoint_manifest_digest:
        raise ParticipantRecoveryError("pending recovery differs from the checkpoint marker")
    private_directory_identity_digest(
        workspace.parent,
        role="participant_workspace_generation_root",
    )
    private_directory_identity_digest(
        artifact_directory.parent,
        role="participant_artifact_generation_root",
    )
    if artifact_directory.exists():
        private_directory_identity_digest(
            artifact_directory,
            role="participant_artifacts",
        )
    else:
        artifact_directory.mkdir(mode=0o700)
        private_directory_identity_digest(
            artifact_directory,
            role="participant_artifacts",
        )
    if workspace.exists():
        restored_digest = _capture_restored_manifest(
            artifact_store,
            workspace,
            expected_manifest,
        )
    else:
        _restore_checkpoint(
            artifact_store,
            journal,
            environment,
            checkpoint_id,
            workspace,
        )
        restored_digest = _capture_restored_manifest(
            artifact_store,
            workspace,
            expected_manifest,
        )
    if restored_digest != marker.manifest_digest:
        raise ParticipantRecoveryError("restored workspace differs from its checkpoint")

    predecessor = lifecycle.incarnations[-1]
    incarnation = current_participant_incarnation(
        generation=predecessor.generation + 1,
        workspace=workspace,
        artifact_directory=artifact_directory,
    )
    if (
        incarnation.process.digest == predecessor.process.digest
        or incarnation.workspace_identity_digest == predecessor.workspace_identity_digest
        or incarnation.artifact_directory_identity_digest
        == predecessor.artifact_directory_identity_digest
    ):
        raise ParticipantRecoveryError(
            "participant recovery requires a new process and private runtime paths"
        )
    state = journal.transact(
        lambda current: ParticipantIncarnationRestoredEvent(
            run_id=current.run_id,
            sequence=current.next_sequence,
            event_id=event_id_factory(),
            timestamp=timestamp(),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.VERIFIER,
            payload=ParticipantIncarnationRestoredPayload(
                predecessor_incarnation_digest=predecessor.digest,
                incarnation=incarnation,
                checkpoint_id=checkpoint_id,
                checkpoint_manifest_digest=marker.manifest_digest,
                restored_manifest_digest=restored_digest,
            ),
        )
    )
    return marker, state


def _checkpoint_event(journal: RunJournal, checkpoint_id: str) -> CheckpointCommittedEvent:
    checkpoints = tuple(
        event
        for event in journal.read_events()
        if isinstance(event, CheckpointCommittedEvent)
    )
    if not checkpoints or checkpoints[-1].payload.checkpoint_id != checkpoint_id:
        raise ParticipantRecoveryError(
            "participant recovery requires the latest committed checkpoint"
        )
    return checkpoints[-1]


def _load_checkpoint(
    store: ContentAddressedStore,
    environment: EnvironmentSpec,
    checkpoint_id: str,
) -> tuple[CheckpointMarker, ArtifactManifest]:
    if environment.checkpoint is CheckpointCapability.FILESYSTEM:
        return store.load_filesystem_checkpoint(checkpoint_id)
    binding = environment.application_checkpoint
    if environment.checkpoint is CheckpointCapability.APPLICATION and binding is not None:
        return store.load_application_checkpoint(
            checkpoint_id,
            driver_digest=binding.driver_digest,
        )
    raise ParticipantRecoveryError("environment does not support participant recovery")


def _restore_checkpoint(
    store: ContentAddressedStore,
    journal: RunJournal,
    environment: EnvironmentSpec,
    checkpoint_id: str,
    workspace: Path,
) -> CheckpointMarker:
    if environment.checkpoint is CheckpointCapability.FILESYSTEM:
        return restore_workspace_checkpoint(
            store=store,
            journal=journal,
            environment=environment,
            checkpoint_id=checkpoint_id,
            destination=workspace,
        )
    return restore_application_checkpoint(
        store=store,
        journal=journal,
        environment=environment,
        checkpoint_id=checkpoint_id,
        destination=workspace,
    )


def _capture_restored_manifest(
    store: ContentAddressedStore,
    workspace: Path,
    expected: ArtifactManifest,
) -> Digest:
    captured = manifest_tree(
        store,
        workspace,
        artifact_class=expected.artifact_class,
        sensitivity=expected.sensitivity,
        visibility=expected.visibility,
        redistribution=expected.redistribution,
    )
    return captured.digest


def _boot_id_digest() -> Digest:
    content = _read_proc_file(_BOOT_ID_PATH)
    return canonical_digest(content.decode("ascii", errors="strict").strip(), domain="boot-id-v1")


def _process_start_time_ticks(process_id: int) -> int:
    try:
        content = _read_proc_file(_PROCESS_STAT_ROOT / str(process_id) / "stat")
    except FileNotFoundError:
        raise ProcessLookupError(process_id) from None
    try:
        _, remainder = content.rsplit(b") ", 1)
        fields = remainder.split()
        value = int(fields[19])
    except (IndexError, ValueError) as error:
        raise ParticipantRecoveryError("process identity is not readable") from error
    if value < 0:
        raise ParticipantRecoveryError("process start time is invalid")
    return value


def _read_proc_file(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, _MAXIMUM_PROC_BYTES - total + 1):
            total += len(chunk)
            if total > _MAXIMUM_PROC_BYTES:
                raise ParticipantRecoveryError("process identity exceeds its bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)
