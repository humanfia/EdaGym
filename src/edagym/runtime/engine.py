"""Small command/event engine shared by CLI, browser, and agent adapters."""

from __future__ import annotations

import fcntl
import os
import secrets
import shutil
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import Field, TypeAdapter, field_validator

from edagym.authoring.factory import GeneratedTask, TaskFactory
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.execution import ExecutionPolicyError, project_environment
from edagym.config.model import ConfigView, PrivateConfigSnapshot
from edagym.config.qualification import resolve_profile_tools
from edagym.config.resolve import resolve_snapshot
from edagym.policy.runtime_storage import private_directory, read_private, write_private
from edagym.run.manifest import RunManifest
from edagym.specs.common import Digest, Identifier, StrictModel, Visibility
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import QualificationStatus

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_FORBIDDEN_PAYLOAD_KEY_PARTS = frozenset(
    {"credential", "token", "api_key", "apikey", "secret", "password", "private_key"}
)
_MAX_PAYLOAD_DEPTH = 16
_IDENTIFIER = TypeAdapter(Identifier)


class EngineError(RuntimeError):
    """A run command cannot be accepted under its frozen manifest or journal."""


class EnginePhase(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    TERMINAL = "terminal"
    UNAVAILABLE = "unavailable"


class IntentKind(StrEnum):
    EDIT = "edit"
    TOOL = "tool"
    SUBMIT = "submit"
    TRANSFER_CONTROL = "transfer_control"
    CHECKPOINT = "checkpoint"
    CANCEL = "cancel"


class Principal(StrictModel):
    principal_id: Identifier
    allowed_run_ids: tuple[Identifier, ...] = ()
    allowed_visibilities: tuple[Visibility, ...] = (Visibility.PUBLIC, Visibility.PARTICIPANT)

    @field_validator("allowed_run_ids")
    @classmethod
    def normalize_runs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("principal run grants must be unique")
        return tuple(sorted(value))

    @field_validator("allowed_visibilities")
    @classmethod
    def normalize_visibilities(cls, value: tuple[Visibility, ...]) -> tuple[Visibility, ...]:
        if len(value) != len(set(value)):
            raise ValueError("principal visibility grants must be unique")
        return tuple(sorted(value, key=lambda item: item.value))


class EventCursor(StrictModel):
    sequence: int = Field(strict=True, ge=0)


class InteractionIntent(StrictModel):
    intent_id: Identifier
    idempotency_key: Identifier
    actor_id: Identifier
    kind: IntentKind
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        encoded = canonical_bytes(value)
        if len(encoded) > 128 * 1024:
            raise ValueError("intent payload exceeds the bounded command size")
        _validate_payload_tree(value)
        return value


class EngineEvent(StrictModel):
    sequence: int = Field(strict=True, ge=0)
    event_id: Identifier
    run_id: Identifier
    kind: Identifier
    actor_id: Identifier | None = None
    visibility: Visibility = Visibility.PARTICIPANT
    idempotency_key: Identifier | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime
    previous_digest: Digest | None = None

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("engine event timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("payload")
    @classmethod
    def validate_event_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(canonical_bytes(value)) > 256 * 1024:
            raise ValueError("engine event payload exceeds the bounded event size")
        _validate_payload_tree(value)
        return value

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="runtime-engine-event-v1")


class AcceptedEvent(StrictModel):
    run_id: Identifier
    intent_id: Identifier
    sequence: int = Field(strict=True, ge=0)
    event_id: Identifier
    kind: Identifier
    duplicate: bool = False


class EventStream(StrictModel):
    run_id: Identifier
    cursor: EventCursor
    events: tuple[EngineEvent, ...]
    terminal: bool


class RunProjection(StrictModel):
    """Read-only replay projection. The engine never persists this object."""

    run_id: Identifier
    manifest_digest: Digest
    phase: EnginePhase
    control_owner: Identifier
    unavailable_reason: str | None = None
    terminal_reason: str | None = None
    accepted_intents: tuple[Identifier, ...] = ()
    last_checkpoint_id: Identifier | None = None
    next_sequence: int = Field(strict=True, ge=0)


class _Journal:
    """Owner-only JSONL event stream used for control-plane runs."""

    def __init__(self, directory: Path, manifest: RunManifest) -> None:
        self.directory = directory
        self.manifest = manifest
        self.events_path = directory / "events.jsonl"
        self.manifest_path = directory / "manifest.json"
        self.lock_path = directory / ".lock"

    @classmethod
    def create(cls, root: Path, manifest: RunManifest) -> _Journal:
        _private_directory(root)
        directory = root / manifest.run_id
        try:
            directory.mkdir(mode=_DIRECTORY_MODE)
        except FileExistsError:
            existing = cls.open(directory)
            if existing.manifest != manifest:
                raise EngineError("run identifier already binds a different manifest") from None
            return existing
        for path in (directory / "events.jsonl", directory / ".lock"):
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                _FILE_MODE,
            )
            os.close(descriptor)
        descriptor = os.open(
            directory / "manifest.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            _FILE_MODE,
        )
        try:
            _write_fd(descriptor, canonical_bytes(manifest) + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(root)
        return cls.open(directory)

    @classmethod
    def open(cls, directory: Path) -> _Journal:
        _require_private_directory(directory)
        try:
            content = _read_private_file(directory / "manifest.json")
            manifest = RunManifest.model_validate_json(content)
        except (OSError, ValueError) as error:
            raise EngineError("run manifest is unreadable") from error
        if content != canonical_bytes(manifest) + b"\n":
            raise EngineError("run manifest is not canonical")
        if manifest.run_id != directory.name:
            raise EngineError("run manifest belongs to another directory")
        for path in (directory / "events.jsonl", directory / ".lock"):
            _private_file(path)
        return cls(directory, manifest)

    def read(self) -> tuple[EngineEvent, ...]:
        try:
            data = _read_private_file(self.events_path)
        except OSError as error:
            raise EngineError("run journal is unreadable") from error
        return self._parse(data)

    def _parse(self, data: bytes) -> tuple[EngineEvent, ...]:
        if not data:
            return ()
        if not data.endswith(b"\n"):
            raise EngineError("run journal has an incomplete event")
        events: list[EngineEvent] = []
        for line in data.splitlines():
            try:
                event = EngineEvent.model_validate_json(line)
            except ValueError as error:
                raise EngineError("run journal contains an invalid event") from error
            if line != canonical_bytes(event):
                raise EngineError("run journal event is not canonical")
            events.append(event)
        self._validate(events)
        return tuple(events)

    @contextmanager
    def locked(self) -> Iterator[None]:
        _private_file(self.lock_path)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def append(self, event: EngineEvent) -> EngineEvent:
        descriptor = os.open(self.events_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.lseek(descriptor, 0, os.SEEK_SET)
            data = b""
            while chunk := os.read(descriptor, 1024 * 1024):
                data += chunk
            events = self._parse(data)
            if event.sequence != len(events):
                raise EngineError("event sequence does not own its journal position")
            if event.run_id != self.manifest.run_id:
                raise EngineError("event belongs to another run")
            previous = events[-1].digest if events else None
            if event.previous_digest != previous:
                raise EngineError("event hash chain is discontinuous")
            _write_fd(descriptor, canonical_bytes(event) + b"\n", append=True)
            os.fsync(descriptor)
            return event
        finally:
            os.close(descriptor)

    def _validate(self, events: Iterable[EngineEvent]) -> None:
        previous: Digest | None = None
        for sequence, event in enumerate(events):
            if sequence == 0 and (
                event.kind != "run_prepared"
                or event.payload.get("manifest_digest") != self.manifest.digest
            ):
                raise EngineError("run journal does not bind its frozen manifest")
            if event.sequence != sequence or event.run_id != self.manifest.run_id:
                raise EngineError("run journal sequence or identity is corrupt")
            if event.previous_digest != previous:
                raise EngineError("run journal hash chain is corrupt")
            previous = event.digest


class RunEngine:
    """Single command owner for browser, CLI, and direct-agent interactions."""

    def __init__(self, state_root: Path) -> None:
        self.state_root = private_directory(state_root, create=True)
        self.runs_root = self.state_root / "runs"
        private_directory(self.runs_root, create=True)

    def prepare_task(
        self,
        generated: GeneratedTask,
        snapshot: PrivateConfigSnapshot,
        session_id: str,
        principal: Principal,
        *,
        run_id: str | None = None,
        creation_intent_digest: Digest | None = None,
    ) -> RunProjection:
        """Freeze the same task and configuration binding for all user interfaces."""

        if snapshot.configuration.sites[0].state_root != self.state_root:
            raise EngineError("snapshot belongs to another private state root")
        qualification = generated.instance.qualification
        reason = (
            "task_qualification_required"
            if qualification is None or qualification.status is not QualificationStatus.QUALIFIED
            else "executor_qualification_required"
        )
        participant: EnvironmentSpec | None
        evaluator: EnvironmentSpec | None
        try:
            participant, evaluator = self._resolve_environments(snapshot)
        except ExecutionPolicyError as error:
            participant = evaluator = None
            if reason == "executor_qualification_required":
                reason = error.gap.value
        manifest = RunManifest.from_snapshot(
            run_id=run_id or f"run_{secrets.token_hex(16)}",
            task=generated.instance,
            task_spec_digest=generated.task.digest,
            snapshot=snapshot,
            session_id=session_id,
            initial_writer=principal.principal_id,
            capabilities=tuple(
                sorted(
                    {
                        capability
                        for evaluator in generated.task.evaluation.evaluators
                        for capability in (evaluator.capability, *evaluator.supporting_capabilities)
                    },
                    key=lambda item: item.value,
                )
            ),
            creation_intent_digest=creation_intent_digest,
            participant=participant,
            evaluator=evaluator,
        )
        TaskFactory().persist(generated, self.state_root)
        return self._create_run(manifest, principal, snapshot=snapshot, unavailable_reason=reason)

    def _create_run(
        self,
        manifest: RunManifest,
        principal: Principal,
        *,
        unavailable_reason: str,
        snapshot: PrivateConfigSnapshot,
    ) -> RunProjection:
        self._authorize(manifest.run_id, principal)
        if snapshot.digest != manifest.private_config_snapshot_digest:
            raise EngineError("run snapshot does not match its manifest")
        journal = _Journal.create(self.runs_root, manifest)
        with journal.locked():
            write_private(
                journal.directory / "snapshot.json",
                canonical_bytes(snapshot) + b"\n",
            )
            return self._initialize_run(journal, principal, unavailable_reason)

    def _initialize_run(
        self,
        journal: _Journal,
        principal: Principal,
        unavailable_reason: str,
    ) -> RunProjection:
        manifest = journal.manifest
        events = journal.read()
        if events:
            return self.project(manifest.run_id, principal=principal)
        now = datetime.now(UTC)
        prepared = self._event(
            journal,
            kind="run_prepared",
            actor_id=principal.principal_id,
            payload={"manifest_digest": manifest.digest},
            timestamp=now,
        )
        journal.append(prepared)
        if not unavailable_reason or "\n" in unavailable_reason:
            raise ValueError("unavailable reason must be a bounded one-line value")
        journal.append(
            self._event(
                journal,
                kind="run_unavailable",
                actor_id=None,
                payload={"reason": unavailable_reason},
                timestamp=datetime.now(UTC),
                visibility=Visibility.PARTICIPANT,
            )
        )
        return self.project(manifest.run_id, principal=principal)

    def project(self, run_id: str, principal: Principal) -> RunProjection:
        journal = self._journal_for(run_id, principal)
        events = journal.read()
        if not events:
            raise EngineError("run has no prepared event")
        phase = EnginePhase.PREPARED
        owner = journal.manifest.initial_writer or journal.manifest.session_id
        unavailable = None
        terminal = None
        accepted: list[str] = []
        checkpoint = None
        for event in events:
            if event.kind == "run_prepared" and event.actor_id is not None:
                owner = event.actor_id
            if event.kind == "run_started":
                phase = EnginePhase.RUNNING
            elif event.kind == "run_unavailable":
                phase = EnginePhase.UNAVAILABLE
                terminal = "unavailable"
                unavailable = str(event.payload.get("reason", "executor_unavailable"))
            elif event.kind == "control_transferred":
                owner = str(event.payload["next_writer"])
            elif event.kind == "checkpoint_committed":
                checkpoint = str(event.payload["checkpoint_id"])
            elif event.kind == "run_cancelled":
                phase = EnginePhase.TERMINAL
                terminal = "explicit_cancel"
            elif event.kind == "run_completed":
                phase = EnginePhase.TERMINAL
                terminal = str(event.payload.get("reason", "completed"))
            if event.idempotency_key is not None:
                accepted.append(event.idempotency_key)
        return RunProjection(
            run_id=run_id,
            manifest_digest=journal.manifest.digest,
            phase=phase,
            control_owner=owner,
            unavailable_reason=unavailable,
            terminal_reason=terminal,
            accepted_intents=tuple(accepted),
            last_checkpoint_id=checkpoint,
            next_sequence=len(events),
        )

    def manifest(self, run_id: str, principal: Principal) -> RunManifest:
        return self._journal_for(run_id, principal).manifest

    def resume(self, run_id: str, principal: Principal) -> RunProjection:
        """Verify frozen inputs before replay; current configuration cannot rebind a run."""

        journal = self._journal_for(run_id, principal)
        with journal.locked():
            snapshot = PrivateConfigSnapshot.model_validate_json(
                read_private(journal.directory / "snapshot.json")
            )
            if snapshot.digest != journal.manifest.private_config_snapshot_digest:
                raise EngineError("frozen configuration snapshot is corrupt")
            self._generated_task(journal)
            manifest = journal.manifest
            if manifest.participant is not None or manifest.evaluator is not None:
                try:
                    environments = self._resolve_environments(snapshot)
                except ExecutionPolicyError as error:
                    raise EngineError("frozen execution environment is unavailable") from error
                if environments != (manifest.participant, manifest.evaluator):
                    raise EngineError("frozen execution environment has changed")
            return self.project(run_id, principal)

    @staticmethod
    def _resolve_environments(
        snapshot: PrivateConfigSnapshot,
    ) -> tuple[EnvironmentSpec, EnvironmentSpec]:
        pair = resolve_snapshot(snapshot)
        resolutions = resolve_profile_tools(pair)
        return (
            project_environment(pair, ConfigView.PARTICIPANT, resolutions),
            project_environment(pair, ConfigView.EVALUATOR, resolutions),
        )

    def files(self, run_id: str, principal: Principal) -> tuple[dict[str, object], ...]:
        generated = self._generated_task(self._journal_for(run_id, principal))
        return tuple(
            {"path": file.path, "media_type": file.media_type, "size_bytes": file.size_bytes}
            for file in generated.instance.generated_files
            if file.visibility in principal.allowed_visibilities
        )

    def read_file(self, run_id: str, path: str, principal: Principal) -> tuple[str, bytes]:
        generated = self._generated_task(self._journal_for(run_id, principal))
        for file in generated.instance.generated_files:
            if file.path == path and file.visibility in principal.allowed_visibilities:
                return file.media_type, generated.contents[file.path]
        raise EngineError("file is not visible in this run")

    def _generated_task(self, journal: _Journal) -> GeneratedTask:
        generated = TaskFactory().load(
            self.state_root, f"task_{journal.manifest.task_instance_digest[7:]}"
        )
        if generated.task.digest != journal.manifest.task_spec_digest:
            raise EngineError("run task specification is corrupt")
        return generated

    def list_runs(self, principal: Principal) -> tuple[RunProjection, ...]:
        projections = []
        for directory in sorted(self.runs_root.iterdir()):
            if principal.allowed_run_ids and directory.name not in principal.allowed_run_ids:
                continue
            if not directory.is_dir() or directory.is_symlink():
                continue
            projections.append(self.project(directory.name, principal))
        return tuple(projections)

    def submit_intent(
        self,
        run_id: str,
        intent: InteractionIntent,
        principal: Principal,
    ) -> AcceptedEvent:
        journal = self._journal_for(run_id, principal)
        with journal.locked():
            return self._accept_intent(journal, intent, principal)

    def _accept_intent(
        self, journal: _Journal, intent: InteractionIntent, principal: Principal
    ) -> AcceptedEvent:
        run_id = journal.manifest.run_id
        events = journal.read()
        projection = self.project(run_id, principal=principal)
        if intent.actor_id != principal.principal_id:
            raise EngineError("intent actor does not match the authenticated principal")
        intent_digest = canonical_digest(
            intent.model_dump(exclude={"intent_id", "idempotency_key"}),
            domain="runtime-interaction-intent-v1",
        )
        for event in events:
            if event.idempotency_key == intent.idempotency_key:
                if event.payload.get("intent_digest") != intent_digest:
                    raise EngineError("idempotency key is already bound to another intent")
                return AcceptedEvent(
                    run_id=run_id,
                    intent_id=str(event.payload["intent_id"]),
                    sequence=event.sequence,
                    event_id=event.event_id,
                    kind=event.kind,
                    duplicate=True,
                )
        if projection.control_owner != principal.principal_id:
            raise EngineError("principal does not own current run control")
        if projection.phase in {EnginePhase.TERMINAL, EnginePhase.UNAVAILABLE}:
            raise EngineError("terminal or unavailable runs reject new intents")
        payload: dict[str, Any]
        if intent.kind is IntentKind.TRANSFER_CONTROL:
            next_writer = intent.payload.get("next_writer")
            if not isinstance(next_writer, str) or next_writer == principal.principal_id:
                raise EngineError("control transfer requires a distinct logical writer")
            _IDENTIFIER.validate_python(next_writer)
            event_kind = "control_transferred"
            payload = {"next_writer": next_writer, "previous_writer": principal.principal_id}
        elif intent.kind is IntentKind.CANCEL:
            event_kind = "run_cancelled"
            payload = {"reason": "explicit_cancel"}
        elif intent.kind is IntentKind.CHECKPOINT:
            checkpoint_id = intent.payload.get("checkpoint_id")
            if not isinstance(checkpoint_id, str) or not checkpoint_id:
                raise EngineError("checkpoint intents require a logical checkpoint ID")
            _IDENTIFIER.validate_python(checkpoint_id)
            event_kind = "checkpoint_requested"
            payload = {"checkpoint_id": checkpoint_id}
        elif intent.kind is IntentKind.SUBMIT:
            candidate_id = intent.payload.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id:
                raise EngineError("submit intents require a candidate ID")
            _IDENTIFIER.validate_python(candidate_id)
            event_kind = "candidate_submission_requested"
            payload = {"candidate_id": candidate_id}
        else:
            event_kind = "intent_accepted"
            payload = {
                "kind": intent.kind.value,
                "payload": intent.payload,
            }
        payload.update(intent_digest=intent_digest, intent_id=intent.intent_id)
        accepted = self._event(
            journal,
            kind=event_kind,
            actor_id=principal.principal_id,
            idempotency_key=intent.idempotency_key,
            payload=payload,
            timestamp=datetime.now(UTC),
        )
        journal.append(accepted)
        return AcceptedEvent(
            run_id=run_id,
            intent_id=intent.intent_id,
            sequence=accepted.sequence,
            event_id=accepted.event_id,
            kind=accepted.kind,
        )

    def stream_run(
        self,
        run_id: str,
        cursor: EventCursor,
        principal: Principal,
    ) -> EventStream:
        journal = self._journal_for(run_id, principal)
        events = journal.read()
        if cursor.sequence > len(events):
            raise EngineError("event cursor is ahead of the journal")
        projection = self.project(run_id, principal=principal)
        return EventStream(
            run_id=run_id,
            cursor=EventCursor(sequence=len(events)),
            events=tuple(
                event
                for event in events[cursor.sequence :]
                if event.visibility in principal.allowed_visibilities
            ),
            terminal=projection.phase in {EnginePhase.TERMINAL, EnginePhase.UNAVAILABLE},
        )

    def cancel(self, run_id: str, principal: Principal) -> RunProjection:
        self.submit_intent(
            run_id,
            InteractionIntent(
                intent_id=f"cancel_{secrets.token_hex(8)}",
                idempotency_key=f"cancel_{secrets.token_hex(8)}",
                actor_id=principal.principal_id,
                kind=IntentKind.CANCEL,
            ),
            principal=principal,
        )
        return self.project(run_id, principal=principal)

    def gc(self, run_id: str, principal: Principal, *, dry_run: bool = False) -> bool:
        journal = self._journal_for(run_id, principal)
        with journal.locked():
            projection = self.project(run_id, principal=principal)
            if projection.phase not in {EnginePhase.TERMINAL, EnginePhase.UNAVAILABLE}:
                raise EngineError("active runs cannot be garbage-collected")
            scratch = journal.directory / "scratch"
            if scratch.exists() or scratch.is_symlink():
                _require_private_directory(scratch)
                if not dry_run:
                    shutil.rmtree(scratch)
                    _fsync_directory(journal.directory)
        return True

    def _event(
        self,
        journal: _Journal,
        *,
        kind: str,
        actor_id: str | None,
        payload: dict[str, Any],
        timestamp: datetime,
        visibility: Visibility = Visibility.PARTICIPANT,
        idempotency_key: str | None = None,
    ) -> EngineEvent:
        events = journal.read()
        return EngineEvent(
            sequence=len(events),
            event_id=f"evt_{secrets.token_hex(16)}",
            run_id=journal.manifest.run_id,
            kind=kind,
            actor_id=actor_id,
            visibility=visibility,
            idempotency_key=idempotency_key,
            payload=payload,
            timestamp=timestamp,
            previous_digest=events[-1].digest if events else None,
        )

    def _journal_for(self, run_id: str, principal: Principal) -> _Journal:
        self._authorize(run_id, principal)
        return _Journal.open(self.runs_root / run_id)

    @staticmethod
    def _authorize(run_id: str, principal: Principal) -> None:
        try:
            _IDENTIFIER.validate_python(run_id)
        except ValueError:
            raise EngineError("invalid run identifier") from None
        if principal.allowed_run_ids and run_id not in principal.allowed_run_ids:
            raise EngineError("principal is not authorized for this run")


def stream_run(
    engine: RunEngine,
    run_id: str,
    cursor: EventCursor,
    principal: Principal,
) -> EventStream:
    """Functional adapter used by web and agent integrations."""

    return engine.stream_run(run_id, cursor, principal=principal)


def submit_intent(
    engine: RunEngine,
    run_id: str,
    intent: InteractionIntent,
    principal: Principal,
) -> AcceptedEvent:
    """Functional adapter with one typed intent contract."""

    return engine.submit_intent(run_id, intent, principal=principal)


def _private_directory(path: Path) -> None:
    private_directory(path, create=True)


def _require_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise EngineError("engine state directory is unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise EngineError("engine state directories must be owner-only")


def _private_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise EngineError("engine state file is unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise EngineError("engine state files must be owner-only")


def _read_private_file(path: Path) -> bytes:
    _private_file(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise EngineError("engine state files must be owner-only")
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        return stream.read()


def _validate_payload_tree(value: object, depth: int = 0) -> None:
    if depth > _MAX_PAYLOAD_DEPTH:
        raise ValueError("payload nesting exceeds the command boundary")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or any(
                marker in key.casefold() for marker in _FORBIDDEN_PAYLOAD_KEY_PARTS
            ):
                raise ValueError("payload cannot carry credentials or secrets")
            _validate_payload_tree(child, depth + 1)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_payload_tree(child, depth + 1)
    elif isinstance(value, str) and "\x00" in value:
        raise ValueError("payload contains a null boundary")


def _write_fd(descriptor: int, content: bytes, *, append: bool = False) -> None:
    if append:
        os.lseek(descriptor, 0, os.SEEK_END)
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise EngineError("journal write made no progress")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "AcceptedEvent",
    "EngineError",
    "EngineEvent",
    "EnginePhase",
    "EventCursor",
    "EventStream",
    "IntentKind",
    "InteractionIntent",
    "Principal",
    "RunEngine",
    "RunProjection",
    "stream_run",
    "submit_intent",
]
