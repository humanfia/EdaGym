"""Portable participant-composition evidence derived from a validated run record."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self
from uuid import UUID

from pydantic import Field, model_validator

from edagym.canonical import canonical_digest
from edagym.projections.model import ParticipationKind
from edagym.run.trial_journal import TrialJournal, replay
from edagym.run.trial_model import (
    CandidateSubmittedEvent,
    ControlTransferredEvent,
    HarnessRunActor,
    HumanRunActor,
    InteractionDirection,
    InteractionRecordedEvent,
    ProducerKind,
    ProviderRequestStartedEvent,
    RunActor,
    RunEndedEvent,
    RunEvent,
    RunRecord,
    StopReason,
)
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import SessionSpec
from edagym.specs.task import TaskSpec


class ParticipantActionKind(StrEnum):
    """Actor-attributed writes that establish real participation."""

    OUTPUT = "output"
    TOOL_REQUEST = "tool_request"
    PROVIDER_REQUEST = "provider_request"
    CANDIDATE_SUBMISSION = "candidate_submission"
    CONTROL_TRANSFER = "control_transfer"
    RUN_END = "run_end"


class ParticipantActionEvidence(StrictModel):
    sequence: Annotated[int, Field(strict=True, ge=0)]
    event_id: UUID
    actor_id: Identifier
    kind: ParticipantActionKind


class ParticipantHandoffEvidence(StrictModel):
    sequence: Annotated[int, Field(strict=True, ge=0)]
    event_id: UUID
    previous_writer: Identifier
    next_writer: Identifier


class ParticipantSessionEvidence(StrictModel):
    """Exact session binding and ordered actor activity for one replayed run."""

    schema_version: SchemaVersion = 1
    run_id: Digest
    run_record_integrity_digest: Digest
    task_spec_digest: Digest
    instance_digest: Digest
    release_digest: Digest
    environment_spec_digest: Digest
    session_spec_digest: Digest
    participation: ParticipationKind
    actors: tuple[RunActor, ...]
    initial_writer: Identifier
    final_writer: Identifier
    handoff_enabled: bool
    actions: tuple[ParticipantActionEvidence, ...]
    handoffs: tuple[ParticipantHandoffEvidence, ...]
    terminal_reason: StopReason | None = None

    @model_validator(mode="after")
    def validate_writer_history(self) -> Self:
        actor_ids = {actor.actor_id for actor in self.actors}
        has_human = any(isinstance(actor, HumanRunActor) for actor in self.actors)
        has_harness = any(isinstance(actor, HarnessRunActor) for actor in self.actors)
        expected_participation = (
            ParticipationKind.HYBRID
            if has_human and has_harness
            else ParticipationKind.HUMAN
            if has_human
            else ParticipationKind.AGENT
        )
        if (
            not actor_ids
            or self.initial_writer not in actor_ids
            or self.final_writer not in actor_ids
            or self.participation is not expected_participation
            or self.handoff_enabled != (len(actor_ids) > 1)
        ):
            raise ValueError("participant evidence differs from its actor composition")
        action_sequences = tuple(item.sequence for item in self.actions)
        handoff_sequences = tuple(item.sequence for item in self.handoffs)
        if (
            action_sequences != tuple(sorted(action_sequences))
            or len(action_sequences) != len(set(action_sequences))
            or handoff_sequences != tuple(sorted(handoff_sequences))
            or len(handoff_sequences) != len(set(handoff_sequences))
        ):
            raise ValueError("participant evidence events must be uniquely ordered")
        handoffs = {(item.sequence, item.event_id): item for item in self.handoffs}
        transfer_actions = {
            (item.sequence, item.event_id): item
            for item in self.actions
            if item.kind is ParticipantActionKind.CONTROL_TRANSFER
        }
        if set(handoffs) != set(transfer_actions):
            raise ValueError("participant handoffs must exactly match transfer actions")
        writer = self.initial_writer
        for action in self.actions:
            if action.actor_id != writer:
                raise ValueError("participant action is outside the actor's writer lease")
            handoff = handoffs.get((action.sequence, action.event_id))
            if handoff is not None:
                if handoff.previous_writer != writer or handoff.next_writer not in actor_ids:
                    raise ValueError("participant handoff differs from the active writer lease")
                writer = handoff.next_writer
        if writer != self.final_writer:
            raise ValueError("participant final writer differs from the action history")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="participant-session-evidence-v1")


def project_participant_session(
    journal: TrialJournal,
    *,
    instance: TaskInstance,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> ParticipantSessionEvidence:
    """Project a live journal through the same portable record boundary."""

    return project_participant_session_record(
        journal.record(),
        task=journal.task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
    )


def project_participant_session_record(
    record: RunRecord,
    *,
    task: TaskSpec,
    instance: TaskInstance,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> ParticipantSessionEvidence:
    """Derive exact composition and actor activity from one portable run record."""

    if type(record) is not RunRecord:
        raise TypeError("participant evidence requires a canonical run record")
    binding = record.header.binding
    if (
        task.digest != binding.task.task_spec_digest
        or instance.digest != binding.task.instance_digest
        or release.digest != binding.task.release_digest
        or environment.digest != binding.environment.environment_spec_digest
        or session.digest != binding.session.session_spec_digest
    ):
        raise ValueError("participant evidence inputs differ from the run binding")
    state = replay(record.header, task, record.events)
    actions = tuple(
        action
        for event in record.events
        if (action := _participant_action(event)) is not None
    )
    handoffs = tuple(
        ParticipantHandoffEvidence(
            sequence=event.sequence,
            event_id=event.event_id,
            previous_writer=event.payload.previous_writer,
            next_writer=event.payload.next_writer,
        )
        for event in record.events
        if isinstance(event, ControlTransferredEvent)
    )
    actors = binding.session.actors
    has_human = any(isinstance(actor, HumanRunActor) for actor in actors)
    has_harness = any(isinstance(actor, HarnessRunActor) for actor in actors)
    participation = (
        ParticipationKind.HYBRID
        if has_human and has_harness
        else ParticipationKind.HUMAN
        if has_human
        else ParticipationKind.AGENT
    )
    return ParticipantSessionEvidence(
        run_id=record.header.run_id,
        run_record_integrity_digest=record.integrity_digest,
        task_spec_digest=task.digest,
        instance_digest=instance.digest,
        release_digest=release.digest,
        environment_spec_digest=environment.digest,
        session_spec_digest=session.digest,
        participation=participation,
        actors=actors,
        initial_writer=binding.session.initial_writer,
        final_writer=state.current_writer,
        handoff_enabled=binding.session.handoff_enabled,
        actions=actions,
        handoffs=handoffs,
        terminal_reason=state.terminal_reason,
    )


def _participant_action(event: RunEvent) -> ParticipantActionEvidence | None:
    if isinstance(event, InteractionRecordedEvent) and event.producer is ProducerKind.PARTICIPANT:
        if event.actor is None:
            raise ValueError("participant interaction is missing actor attribution")
        kind = (
            ParticipantActionKind.TOOL_REQUEST
            if event.payload.direction is InteractionDirection.TOOL_REQUEST
            else ParticipantActionKind.OUTPUT
        )
        return ParticipantActionEvidence(
            sequence=event.sequence,
            event_id=event.event_id,
            actor_id=event.actor,
            kind=kind,
        )
    if isinstance(event, ProviderRequestStartedEvent):
        return ParticipantActionEvidence(
            sequence=event.sequence,
            event_id=event.event_id,
            actor_id=event.payload.actor_id,
            kind=ParticipantActionKind.PROVIDER_REQUEST,
        )
    if isinstance(event, CandidateSubmittedEvent | ControlTransferredEvent | RunEndedEvent):
        if event.actor is None:
            return None
        kind = (
            ParticipantActionKind.CANDIDATE_SUBMISSION
            if isinstance(event, CandidateSubmittedEvent)
            else ParticipantActionKind.CONTROL_TRANSFER
            if isinstance(event, ControlTransferredEvent)
            else ParticipantActionKind.RUN_END
        )
        return ParticipantActionEvidence(
            sequence=event.sequence,
            event_id=event.event_id,
            actor_id=event.actor,
            kind=kind,
        )
    return None
