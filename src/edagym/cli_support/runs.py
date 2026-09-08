"""Journal-backed run lifecycle operations exposed by the CLI."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from io import TextIOBase
from pathlib import Path
from types import MappingProxyType
from uuid import uuid4

from edagym.canonical import canonical_digest
from edagym.cli_support.documents import load_model, open_artifact_store
from edagym.cli_support.errors import CliFailure
from edagym.participants.adapters import (
    HumanParticipantAdapter,
    HybridParticipantAdapter,
    JsonLineHumanChannel,
    ParticipantAdapter,
    ParticipantAdapterError,
    ParticipantFailureKind,
    json_line_human_adapter_digest,
)
from edagym.participants.controller import CandidateSnapshot, ParticipantController
from edagym.participants.execution import participant_dispatch_lock
from edagym.participants.model import ParticipantIntent, ParticipantView, SubmitCandidateIntent
from edagym.resolution import ResolutionError, resolve_run
from edagym.run.artifact_model import (
    ArtifactRecord,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ArtifactStoreError,
    CheckpointMarker,
    manifest_tree,
)
from edagym.run.checkpoints import (
    CheckpointConsistencyError,
    commit_application_checkpoint,
    commit_workspace_checkpoint,
    restore_application_checkpoint,
    restore_workspace_checkpoint,
)
from edagym.run.journal import (
    InvalidTransition,
    JournalError,
    RunJournal,
    unresolved_tool_requests,
)
from edagym.run.model import (
    EvaluationCompletedEvent,
    EvaluationStartedEvent,
    HumanRunActor,
    JobStateKind,
    ProducerKind,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunStartedEvent,
    RunStartedPayload,
    RunState,
    StopReason,
)
from edagym.specs.common import ArtifactClass, Visibility
from edagym.specs.environment import CheckpointCapability, EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import ActorKind, HumanActor, RecoveryPolicy, SessionSpec
from edagym.specs.task import TaskSpec

_UNSATISFIED = 1
_INCOMPLETE = 3
_ACTIVE_JOB_STATES = frozenset(
    {JobStateKind.QUEUED, JobStateKind.RUNNING, JobStateKind.CHECKPOINTING}
)


class _SingleIntentAdapter(ParticipantAdapter):
    def __init__(
        self,
        actor_kinds: Mapping[str, ActorKind],
        intent: ParticipantIntent,
    ) -> None:
        self._actor_kinds = MappingProxyType(dict(actor_kinds))
        self._intent = intent

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return self._actor_kinds

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.actor_id not in self._actor_kinds:
            raise RuntimeError("active writer is not bound to this run")
        return self._intent


class _InactiveParticipantAdapter(ParticipantAdapter):
    def __init__(self, actor_id: str, actor_kind: ActorKind) -> None:
        self._actor_kinds = MappingProxyType({actor_id: actor_kind})

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return self._actor_kinds

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        del view
        raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)


def start_run(
    *,
    task: TaskSpec,
    instance: TaskInstance,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
    trial_key: str,
    state_root: Path,
) -> tuple[RunJournal, RunState]:
    """Resolve immutable inputs, create their journal, and start it once."""

    try:
        plan = resolve_run(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=trial_key,
        )
        journal = RunJournal.create(state_root, RunHeader.from_binding(plan.binding), task)
        events = journal.read_events()
        if events:
            if not isinstance(events[0], RunStartedEvent):
                raise CliFailure("invalid-run", status=_UNSATISFIED)
            return journal, journal.state()
        state = journal.append(
            RunStartedEvent(
                run_id=journal.header.run_id,
                sequence=0,
                event_id=uuid4(),
                timestamp=datetime.now(UTC),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.PUBLIC,
                payload=RunStartedPayload(binding_digest=plan.binding.digest),
            )
        )
    except ResolutionError:
        raise CliFailure("run-resolution-failed", status=_UNSATISFIED) from None
    except JournalError:
        raise CliFailure("run-journal-failed", status=_INCOMPLETE) from None
    return journal, state


def open_run(run_directory: Path, task_path: Path) -> RunJournal:
    task = load_model(task_path, "task", TaskSpec)
    try:
        return RunJournal.open(run_directory, task)
    except (OSError, ValueError, JournalError):
        raise CliFailure("invalid-run", status=_UNSATISFIED) from None


def state_payload(journal: RunJournal) -> dict[str, object]:
    state = journal.state()
    return {
        "run_id": state.run_id,
        "binding_digest": journal.header.binding.digest,
        "integrity_digest": journal.integrity_digest(),
        "next_sequence": state.next_sequence,
        "current_writer": state.current_writer,
        "candidate_count": len(state.candidates),
        "stage_result_count": len(state.stage_results),
        "artifact_count": len(state.artifacts),
        "checkpoint_ids": state.checkpoint_ids,
        "jobs": state.jobs,
        "terminal_reason": state.terminal_reason,
        "successful_candidate_id": state.successful_candidate_id,
    }


def submit_candidate(
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
    *,
    candidate_id: str,
    candidate_root: Path,
    store_root: Path,
    key_file: Path | None,
    parent_candidate_id: str | None,
) -> RunState:
    """Submit through the participant controller that owns writer attribution."""

    if environment.digest != journal.header.binding.environment.environment_spec_digest:
        raise CliFailure("environment-run-mismatch", status=_UNSATISFIED)
    if session.digest != journal.header.binding.session.session_spec_digest:
        raise CliFailure("session-run-mismatch", status=_UNSATISFIED)
    initial_state = journal.state()
    if initial_state.terminal_reason is not None:
        raise CliFailure("run-already-ended", status=_UNSATISFIED)
    if parent_candidate_id is not None and parent_candidate_id not in {
        candidate.candidate_id for candidate in initial_state.candidates
    }:
        raise CliFailure("candidate-parent-missing", status=_UNSATISFIED)
    try:
        snapshot = _candidate_snapshot(
            journal,
            environment,
            candidate_id=candidate_id,
            candidate_root=candidate_root,
            store_root=store_root,
            key_file=key_file,
        )
        state = journal.state()
        existing_candidates = {candidate.candidate_id: candidate for candidate in state.candidates}
        existing_candidate = existing_candidates.get(candidate_id)
        if existing_candidate is not None:
            if existing_candidate.digest != snapshot.digest:
                raise CliFailure("candidate-identity-conflict", status=_UNSATISFIED)
            return state
        existing_record = next(
            (
                artifact
                for artifact in state.artifacts
                if artifact.logical_id == snapshot.record.logical_id
            ),
            None,
        )
        if existing_record is not None:
            raise CliFailure("candidate-snapshot-conflict", status=_UNSATISFIED)
        intent = SubmitCandidateIntent(
            candidate_id=candidate_id,
            parent_candidate_id=parent_candidate_id,
        )
        adapter = _SingleIntentAdapter(
            {actor.actor_id: actor.kind for actor in journal.header.binding.session.actors},
            intent,
        )
        return ParticipantController(
            journal,
            adapter,
            session=session,
            snapshot_candidate=lambda _intent: snapshot,
        ).act_once()
    except CliFailure:
        raise
    except (OSError, ValueError, RuntimeError, ArtifactStoreError, JournalError):
        raise CliFailure("candidate-submission-rejected", status=_UNSATISFIED) from None


def human_turn(
    journal: RunJournal,
    session: SessionSpec,
    *,
    input_stream: TextIOBase,
    output_stream: TextIOBase,
    environment: EnvironmentSpec | None = None,
    candidate_root: Path | None = None,
    store_root: Path | None = None,
    key_file: Path | None = None,
) -> RunState:
    """Commit one bounded human intent through the journal's active writer."""

    if session.digest != journal.header.binding.session.session_spec_digest:
        raise CliFailure("session-run-mismatch", status=_UNSATISFIED)
    candidate_inputs = (environment, candidate_root, store_root)
    if any(value is not None for value in candidate_inputs) and not all(
        value is not None for value in candidate_inputs
    ):
        raise CliFailure("human-candidate-input-incomplete", status=_UNSATISFIED)
    state = journal.state()
    if state.terminal_reason is not None:
        raise CliFailure("run-already-ended", status=_UNSATISFIED)
    run_actor = next(
        (
            actor
            for actor in journal.header.binding.session.actors
            if actor.actor_id == state.current_writer
        ),
        None,
    )
    session_actor = next(
        (actor for actor in session.actors if actor.actor_id == state.current_writer),
        None,
    )
    if not isinstance(run_actor, HumanRunActor) or not isinstance(session_actor, HumanActor):
        raise CliFailure("human-writer-required", status=_UNSATISFIED)
    expected_adapter_digest = json_line_human_adapter_digest()
    if (
        run_actor.adapter_digest != expected_adapter_digest
        or session_actor.adapter_digest != expected_adapter_digest
    ):
        raise CliFailure("human-adapter-mismatch", status=_UNSATISFIED)

    active = HumanParticipantAdapter(
        state.current_writer,
        JsonLineHumanChannel(input_stream, output_stream),
    )
    children: tuple[ParticipantAdapter, ...] = (
        active,
        *(
            _InactiveParticipantAdapter(actor.actor_id, actor.kind)
            for actor in journal.header.binding.session.actors
            if actor.actor_id != state.current_writer
        ),
    )
    participant: ParticipantAdapter = (
        active if len(children) == 1 else HybridParticipantAdapter(children)
    )

    def snapshot(intent: SubmitCandidateIntent) -> CandidateSnapshot:
        if environment is None or candidate_root is None or store_root is None:
            raise ValueError("candidate submission requires candidate storage inputs")
        return _candidate_snapshot(
            journal,
            environment,
            candidate_id=intent.candidate_id,
            candidate_root=candidate_root,
            store_root=store_root,
            key_file=key_file,
        )

    try:
        return ParticipantController(
            journal,
            participant,
            session=session,
            snapshot_candidate=snapshot,
        ).act_once()
    except ParticipantAdapterError as error:
        status = (
            _INCOMPLETE
            if error.kind
            in {
                ParticipantFailureKind.CHANNEL_FAILURE,
                ParticipantFailureKind.END_OF_INPUT,
            }
            else _UNSATISFIED
        )
        raise CliFailure(f"human-{error.kind.value}", status=status) from None
    except (OSError, ValueError, RuntimeError, ArtifactStoreError, JournalError):
        raise CliFailure("human-turn-rejected", status=_UNSATISFIED) from None


def _candidate_snapshot(
    journal: RunJournal,
    environment: EnvironmentSpec,
    *,
    candidate_id: str,
    candidate_root: Path,
    store_root: Path,
    key_file: Path | None,
) -> CandidateSnapshot:
    if environment.digest != journal.header.binding.environment.environment_spec_digest:
        raise CliFailure("environment-run-mismatch", status=_UNSATISFIED)
    if _paths_overlap(candidate_root, journal.directory) or _paths_overlap(
        candidate_root, store_root
    ):
        raise CliFailure("candidate-snapshot-path-overlap", status=_UNSATISFIED)
    disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.CANDIDATE)
    if disclosure is None:
        raise CliFailure("candidate-retention-disabled", status=_UNSATISFIED)
    store = open_artifact_store(store_root, environment, key_file)
    manifest = manifest_tree(
        store,
        candidate_root,
        artifact_class=ArtifactClass.CANDIDATE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )
    committed = store.put_manifest(manifest)
    artifact_digest = canonical_digest(
        {"run_id": journal.header.run_id, "candidate_id": candidate_id},
        domain="candidate-snapshot-artifact-id-v1",
    )
    return CandidateSnapshot(
        record=ArtifactRecord(
            logical_id=f"candidate_snapshot_{artifact_digest.removeprefix('sha256:')}",
            blob=committed.blob,
            media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
            artifact_class=ArtifactClass.CANDIDATE,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
    )


def cancel_run(journal: RunJournal) -> RunState:
    """End an idle run while fenced from participant dispatch."""

    with participant_dispatch_lock(journal.directory):
        events = journal.read_events()
        state = journal.state()
        if state.terminal_reason is not None:
            if state.terminal_reason is StopReason.EXPLICIT_CANCEL:
                return state
            raise CliFailure("run-already-ended", status=_UNSATISFIED)
        if _has_unresolved_evaluation(events) or any(
            job.state in _ACTIVE_JOB_STATES for job in state.jobs
        ):
            raise CliFailure("run-has-active-evaluation", status=_INCOMPLETE)
        if unresolved_tool_requests(events):
            raise CliFailure("run-has-active-participant-tool", status=_INCOMPLETE)
        try:
            return journal.transact(
                lambda current: RunEndedEvent(
                    run_id=current.run_id,
                    sequence=current.next_sequence,
                    event_id=uuid4(),
                    timestamp=datetime.now(UTC),
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.PUBLIC,
                    payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
                )
            )
        except (InvalidTransition, JournalError):
            raise CliFailure("run-cancel-rejected", status=_UNSATISFIED) from None


def checkpoint_run(
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
    *,
    workspace: Path,
    store_root: Path,
    key_file: Path | None,
    checkpoint_id: str,
) -> tuple[CheckpointMarker, RunState]:
    with participant_dispatch_lock(journal.directory):
        _require_recovery_binding(journal, environment, session)
        state = journal.state()
        if state.terminal_reason is not None:
            raise CliFailure("run-already-ended", status=_UNSATISFIED)
        events = journal.read_events()
        if _has_unresolved_evaluation(events) or any(
            job.state in _ACTIVE_JOB_STATES for job in state.jobs
        ):
            raise CliFailure("run-has-active-evaluation", status=_INCOMPLETE)
        if unresolved_tool_requests(events):
            raise CliFailure("run-has-active-participant-tool", status=_INCOMPLETE)
        disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.CHECKPOINT)
        if disclosure is None:
            raise CliFailure("checkpoint-retention-disabled", status=_UNSATISFIED)
        store = open_artifact_store(store_root, environment, key_file)
        if checkpoint_id in state.checkpoint_ids:
            try:
                if environment.checkpoint is CheckpointCapability.FILESYSTEM:
                    marker, _ = store.load_filesystem_checkpoint(checkpoint_id)
                else:
                    binding = environment.application_checkpoint
                    if binding is None:
                        raise CliFailure(
                            "environment-checkpoint-unsupported",
                            status=_UNSATISFIED,
                        )
                    marker, _ = store.load_application_checkpoint(
                        checkpoint_id,
                        driver_digest=binding.driver_digest,
                    )
            except (OSError, ValueError, ArtifactStoreError):
                raise CliFailure("checkpoint-commit-failed", status=_INCOMPLETE) from None
            return marker, state
        artifact_digest = canonical_digest(
            {"run_id": state.run_id, "checkpoint_id": checkpoint_id},
            domain="checkpoint-manifest-artifact-id-v1",
        )
        try:
            commit = (
                commit_workspace_checkpoint
                if environment.checkpoint is CheckpointCapability.FILESYSTEM
                else commit_application_checkpoint
            )
            return commit(
                store=store,
                journal=journal,
                environment=environment,
                workspace=workspace,
                checkpoint_id=checkpoint_id,
                artifact_id=f"artifact_{artifact_digest.removeprefix('sha256:')}",
                parent_checkpoint_id=(state.checkpoint_ids[-1] if state.checkpoint_ids else None),
                timestamp=datetime.now(UTC),
                artifact_event_id=uuid4(),
                checkpoint_event_id=uuid4(),
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
        except (OSError, ValueError, ArtifactStoreError, JournalError):
            raise CliFailure("checkpoint-commit-failed", status=_INCOMPLETE) from None


def resume_run(
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
    *,
    destination: Path,
    store_root: Path,
    key_file: Path | None,
    checkpoint_id: str,
) -> CheckpointMarker:
    with participant_dispatch_lock(journal.directory):
        _require_recovery_binding(journal, environment, session)
        if destination.exists():
            raise CliFailure("resume-destination-exists", status=_UNSATISFIED)
        events = journal.read_events()
        if _has_unresolved_evaluation(events):
            raise CliFailure("run-has-active-evaluation", status=_INCOMPLETE)
        if unresolved_tool_requests(events):
            raise CliFailure("run-has-active-participant-tool", status=_INCOMPLETE)
        store = open_artifact_store(store_root, environment, key_file)
        try:
            restore = (
                restore_workspace_checkpoint
                if environment.checkpoint is CheckpointCapability.FILESYSTEM
                else restore_application_checkpoint
            )
            return restore(
                store=store,
                journal=journal,
                environment=environment,
                checkpoint_id=checkpoint_id,
                destination=destination,
            )
        except (
            OSError,
            ValueError,
            ArtifactStoreError,
            CheckpointConsistencyError,
            JournalError,
        ):
            raise CliFailure("checkpoint-restore-failed", status=_INCOMPLETE) from None


def _require_recovery_binding(
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> None:
    if environment.digest != journal.header.binding.environment.environment_spec_digest:
        raise CliFailure("environment-run-mismatch", status=_UNSATISFIED)
    if session.digest != journal.header.binding.session.session_spec_digest:
        raise CliFailure("session-run-mismatch", status=_UNSATISFIED)
    if session.recovery is RecoveryPolicy.NONE:
        raise CliFailure("session-recovery-disabled", status=_UNSATISFIED)
    if environment.checkpoint is CheckpointCapability.NONE:
        raise CliFailure("environment-checkpoint-disabled", status=_UNSATISFIED)
    if environment.checkpoint not in {
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    }:
        raise CliFailure(
            "environment-checkpoint-unsupported",
            status=_UNSATISFIED,
        )


def _has_unresolved_evaluation(events: tuple[object, ...]) -> bool:
    started = {
        event.payload.job_id for event in events if isinstance(event, EvaluationStartedEvent)
    }
    completed = {
        event.payload.job_id for event in events if isinstance(event, EvaluationCompletedEvent)
    }
    return started != completed


def _paths_overlap(left: Path, right: Path) -> bool:
    left_path = left.resolve()
    right_path = right.resolve()
    return (
        left_path == right_path
        or left_path in right_path.parents
        or right_path in left_path.parents
    )
