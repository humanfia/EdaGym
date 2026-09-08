"""Manifest-bound run facts, controller ownership, and deterministic replay."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.model import PrivateConfigSnapshot
from edagym.executors.model import InvocationView, JobHandle, JobStateKind
from edagym.run.journal_storage import (
    EventConflict,
    InvalidTransition,
    JournalCommit,
    JournalCorruption,
    JournalStorage,
    locked_file,
    read_file,
    require_directory,
)
from edagym.run.manifest import RunManifest, RunPurpose
from edagym.run.model import (
    CancelRequestedEvent,
    CandidatePayload,
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    ControlTransferredEvent,
    EnginePhase,
    EvaluationCompletedEvent,
    EvaluationPayload,
    OperationPreparedEvent,
    OperationRunningEvent,
    OperationState,
    OperationTerminalEvent,
    QualificationCompletedEvent,
    RunCancelledEvent,
    RunCommit,
    RunCompletedEvent,
    RunEvent,
    RunPreparedEvent,
    RunProjection,
    RunRecord,
    RunStartedEvent,
    RunState,
    RunUnavailableEvent,
    WorkspaceCommittedEvent,
)
from edagym.specs.common import Digest


def journal_anchor(manifest: RunManifest) -> Digest:
    return canonical_digest(manifest, domain="run-journal-manifest-v2")


def replay(manifest: RunManifest, events: Sequence[RunEvent]) -> RunState:
    phase = EnginePhase.PREPARED
    owner = manifest.initial_writer or manifest.session_id
    unavailable = terminal = checkpoint = None
    workspace = None
    candidates: list[CandidatePayload] = []
    evaluations: list[EvaluationPayload] = []
    cancel_requested = False
    qualification_instance_id = None
    operations: dict[str, OperationState] = {}
    event_ids: set[str] = set()
    intent_keys: list[str] = []
    for sequence, event in enumerate(events):
        if event.sequence != sequence or event.run_id != manifest.run_id:
            raise InvalidTransition("run event identity or sequence is inconsistent")
        if event.event_id in event_ids:
            raise EventConflict("run event identifier is already committed")
        event_ids.add(event.event_id)
        if sequence == 0 and not isinstance(event, RunPreparedEvent):
            raise InvalidTransition("the first run fact must bind its manifest")
        if terminal is not None:
            raise InvalidTransition("terminal runs cannot accept new facts")
        if event.intent is not None:
            if event.actor_id != owner:
                raise InvalidTransition("intent actor does not own run control")
            if event.intent.idempotency_key in intent_keys:
                raise EventConflict("intent idempotency key is already committed")
            intent_keys.append(event.intent.idempotency_key)
        active = {key: item for key, item in operations.items() if item.terminal is None}
        if isinstance(event, RunPreparedEvent):
            if sequence != 0 or event.payload.manifest_digest != manifest.digest:
                raise InvalidTransition("prepared fact differs from the frozen manifest")
        elif isinstance(event, RunUnavailableEvent):
            if phase is not EnginePhase.PREPARED:
                raise InvalidTransition("only prepared runs can be unavailable")
            phase, unavailable, terminal = (
                EnginePhase.UNAVAILABLE,
                event.payload.reason,
                "unavailable",
            )
        elif isinstance(event, RunStartedEvent):
            if phase is not EnginePhase.PREPARED or manifest.participant is None:
                raise InvalidTransition("run start requires both frozen execution views")
            phase, workspace = EnginePhase.RUNNING, event.payload.workspace
        elif phase is not EnginePhase.RUNNING:
            raise InvalidTransition("run action requires a started run")
        elif isinstance(event, OperationPreparedEvent):
            if cancel_requested:
                raise InvalidTransition("cancelled runs cannot prepare new operations")
            payload, plan = event.payload, event.payload.plan
            if plan.invocation_id in operations:
                raise EventConflict("operation identifier is already prepared")
            if (
                plan.run_id != manifest.digest
                or plan.input_manifest_digest != payload.input_manifest.semantic_digest
            ):
                raise InvalidTransition("operation differs from its run or input manifest")
            if plan.view not in {InvocationView.PARTICIPANT, InvocationView.EVALUATOR}:
                raise InvalidTransition("operation requires a run filesystem view")
            if payload.parent_id is not None:
                parent = active.get(payload.parent_id)
                if parent is None or parent.running is None:
                    raise InvalidTransition("child operation requires a running parent")
                if any(
                    item.prepared.payload.parent_id == payload.parent_id for item in active.values()
                ):
                    raise InvalidTransition("parent already owns an active child")
            elif active:
                raise InvalidTransition("run already owns an active root operation")
            operations[plan.invocation_id] = OperationState(prepared=event)
        elif isinstance(event, OperationRunningEvent | OperationTerminalEvent):
            operation_id = event.payload.operation_id
            operation = active.get(operation_id)
            if operation is None:
                raise InvalidTransition("operation fact has no active preparation")
            plan = operation.prepared.payload.plan
            environment = (
                manifest.participant
                if plan.view is InvocationView.PARTICIPANT
                else manifest.evaluator
            )
            assert environment is not None
            expected = JobHandle(
                job_id=operation_id,
                invocation_digest=plan.digest,
                executor_id=environment.executor.executor_id,
            )
            handle = (
                event.payload.handle
                if isinstance(event, OperationRunningEvent)
                else event.payload.result.state.handle
            )
            if handle != expected:
                raise InvalidTransition("operation handle differs from its prepared binding")
            if isinstance(event, OperationRunningEvent):
                if operation.running is not None:
                    raise InvalidTransition("operation is already running")
                operations[operation_id] = operation.model_copy(update={"running": event})
            else:
                if event.payload.result.state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                    raise InvalidTransition("operation terminal fact contains an active result")
                if any(item.prepared.payload.parent_id == operation_id for item in active.values()):
                    raise InvalidTransition("parent cannot terminate before its children")
                if event.payload.workspace is not None:
                    if plan.view is not InvocationView.PARTICIPANT:
                        raise InvalidTransition("evaluator cannot replace participant workspace")
                    workspace = event.payload.workspace
                operations[operation_id] = operation.model_copy(update={"terminal": event})
        elif isinstance(event, CancelRequestedEvent):
            if cancel_requested:
                raise EventConflict("run cancellation is already requested")
            cancel_requested = True
        else:
            if active:
                raise InvalidTransition("run action requires quiescent operations")
            if isinstance(event, ControlTransferredEvent):
                if event.payload.next_writer == owner:
                    raise InvalidTransition("control transfer requires another writer")
                owner = event.payload.next_writer
            elif isinstance(event, WorkspaceCommittedEvent):
                workspace = event.payload.workspace
            elif isinstance(event, CheckpointCommittedEvent):
                if event.payload.workspace != workspace:
                    raise InvalidTransition("checkpoint must bind the current durable workspace")
                checkpoint = event.payload.checkpoint_id
            elif isinstance(event, CandidateSubmittedEvent):
                if any(item.candidate_id == event.payload.candidate_id for item in candidates):
                    raise EventConflict("candidate identifier is already submitted")
                candidates.append(event.payload)
            elif isinstance(event, EvaluationCompletedEvent):
                candidate = next(
                    (
                        item
                        for item in candidates
                        if item.candidate_id == event.payload.candidate_id
                    ),
                    None,
                )
                if candidate is None:
                    raise InvalidTransition("evaluation has no submitted candidate")
                if any(item.candidate_id == event.payload.candidate_id for item in evaluations):
                    raise EventConflict("candidate evaluation is already committed")
                if len(set(event.payload.operation_ids)) != len(event.payload.operation_ids) or any(
                    operation_id not in operations
                    or operations[operation_id].terminal is None
                    or operations[operation_id].prepared.payload.plan.view
                    is not InvocationView.EVALUATOR
                    for operation_id in event.payload.operation_ids
                ):
                    raise InvalidTransition("evaluation requires completed evaluator operations")
                if (
                    operations[event.payload.operation_ids[0]].prepared.payload.input_manifest
                    != candidate.submission
                ):
                    raise InvalidTransition("evaluation operation does not consume its candidate")
                evaluations.append(event.payload)
            elif isinstance(event, QualificationCompletedEvent):
                if manifest.purpose is not RunPurpose.QUALIFICATION:
                    raise InvalidTransition(
                        "only qualification runs can publish qualified instances"
                    )
                phase, terminal = EnginePhase.TERMINAL, "qualification_finished"
                qualification_instance_id = event.payload.instance_id
            elif isinstance(event, RunCancelledEvent | RunCompletedEvent):
                if (
                    isinstance(event, RunCompletedEvent)
                    and manifest.purpose is RunPurpose.QUALIFICATION
                ):
                    raise InvalidTransition("qualification termination must publish its evidence")
                phase, terminal = EnginePhase.TERMINAL, event.payload.reason
    return RunState(
        projection=RunProjection(
            run_id=manifest.run_id,
            manifest_digest=manifest.digest,
            phase=phase,
            control_owner=owner,
            unavailable_reason=unavailable,
            terminal_reason=terminal,
            accepted_intents=tuple(intent_keys),
            last_checkpoint_id=checkpoint,
            next_sequence=len(events),
            evaluations=tuple(evaluations),
            cancel_requested=cancel_requested,
            qualification_instance_id=qualification_instance_id,
        ),
        events=tuple(events),
        operations=tuple(operations.values()),
        workspace=workspace,
        candidates=tuple(candidates),
    )


class RunJournal:
    """One frozen manifest and one durable fact stream for an interactive run."""

    def __init__(self, directory: Path, manifest: RunManifest) -> None:
        self.directory = directory
        self.manifest = manifest
        self._storage = JournalStorage(directory, journal_anchor(manifest), RunCommit)

    @classmethod
    def create(
        cls, root: Path, manifest: RunManifest, snapshot: PrivateConfigSnapshot
    ) -> RunJournal:
        if snapshot.digest != manifest.private_config_snapshot_digest:
            raise EventConflict("snapshot differs from the frozen run manifest")
        directory = JournalStorage.create(
            root,
            manifest.run_id,
            {
                "manifest.json": canonical_bytes(manifest) + b"\n",
                "snapshot.json": canonical_bytes(snapshot) + b"\n",
                "controller.lock": b"",
            },
        )
        return cls.open(directory)

    @classmethod
    def open(cls, directory: Path) -> RunJournal:
        require_directory(directory)
        content = read_file(directory / "manifest.json", maximum_bytes=4 * 1024 * 1024)
        manifest = RunManifest.model_validate_json(content)
        if content != canonical_bytes(manifest) + b"\n" or manifest.run_id != directory.name:
            raise JournalCorruption("run manifest identity or encoding is corrupt")
        journal = cls(directory, manifest)
        journal.snapshot()
        return journal

    def snapshot(self) -> PrivateConfigSnapshot:
        content = read_file(self.directory / "snapshot.json", maximum_bytes=16 * 1024 * 1024)
        snapshot = PrivateConfigSnapshot.model_validate_json(content)
        if (
            content != canonical_bytes(snapshot) + b"\n"
            or snapshot.digest != self.manifest.private_config_snapshot_digest
        ):
            raise JournalCorruption("frozen run snapshot is corrupt")
        return snapshot

    @contextmanager
    def locked(self) -> Iterator[None]:
        with locked_file(self.directory / "controller.lock", exclusive=True):
            yield

    def record(self) -> RunRecord:
        records = cast(tuple[RunCommit, ...], self._storage.records())
        return RunRecord(manifest=self.manifest, commits=records)

    def read(self) -> tuple[RunEvent, ...]:
        return self.record().events

    def state(self) -> RunState:
        return replay(self.manifest, self.read())

    def append(self, event: RunEvent) -> RunState:
        return self.append_events((event,))

    def transact(self, factory: Callable[[RunState], Sequence[RunEvent]]) -> RunState:
        """Commit a command against current facts without taking controller ownership."""

        def commit(
            records: tuple[JournalCommit[RunEvent], ...],
        ) -> tuple[tuple[RunEvent, ...], RunState]:
            events = tuple(event for record in records for event in record.events)
            requested = tuple(factory(replay(self.manifest, events)))
            return requested, replay(self.manifest, (*events, *requested))

        return self._storage.transact(commit)

    def append_events(self, requested: Sequence[RunEvent]) -> RunState:
        pending = tuple(requested)
        if not pending:
            raise ValueError("a journal record requires at least one event")

        def commit(
            records: tuple[JournalCommit[RunEvent], ...],
        ) -> tuple[tuple[RunEvent, ...], RunState]:
            events = tuple(event for record in records for event in record.events)
            by_id = {event.event_id: event for event in events}
            identities = [event.event_id for event in pending]
            if len(set(identities)) != len(identities):
                raise EventConflict("one commit cannot reuse an event identifier")
            existing = [key in by_id for key in identities]
            if any(existing):
                if not all(existing) or any(by_id[event.event_id] != event for event in pending):
                    raise EventConflict("event retry differs from its durable group")
                return (), replay(self.manifest, events)
            return pending, replay(self.manifest, (*events, *pending))

        return self._storage.transact(commit)
