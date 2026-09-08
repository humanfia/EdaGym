"""Humanize-shaped session and trace semantics derived from one run journal."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self, cast
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.humanize_contract import HumanizeSessionStrategy
from edagym.participants.model import PARTICIPANT_EVENT_VISIBILITY
from edagym.projections._snapshot import ProjectionSnapshot
from edagym.projections.errors import ProjectionUnavailable
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import (
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    ControlTransferredEvent,
    EventKind,
    InteractionRecordedEvent,
    ProducerKind,
    RunEndedEvent,
    RunLineage,
    RunStartedEvent,
)
from edagym.specs.common import Digest, Identifier, StrictModel, Visibility
from edagym.specs.session import ActorKind, BenchmarkMode, ModeKind, SessionSpec, TrainingMode


class HumanizeTraceAudience(StrEnum):
    PARTICIPANT = "participant"
    REVIEWER = "reviewer"


class HumanizeAgentProjection(StrictModel):
    actor_id: Identifier
    kind: ActorKind


type HumanizeTraceVisibility = Literal[
    Visibility.PUBLIC,
    Visibility.PARTICIPANT,
    Visibility.REVIEWER,
]


class HumanizeTraceSlice(StrictModel):
    slice_index: Annotated[int, Field(strict=True, ge=1)]
    event_id: UUID
    timestamp: datetime
    event_kind: EventKind
    producer: ProducerKind
    actor_id: Identifier | None = None
    visibility: HumanizeTraceVisibility

    @field_validator("event_kind")
    @classmethod
    def require_boundary_event(cls, value: EventKind) -> EventKind:
        if value not in _TRACE_EVENT_KINDS:
            raise ValueError("Humanize traces may contain only participant boundary events")
        return value


class HumanizeTurnProjection(StrictModel):
    turn_index: Annotated[int, Field(strict=True, ge=1)]
    turn_id: Digest
    logical_session_id: Digest
    actor_id: Identifier
    event_id: UUID


class HumanizeLogicalSession(StrictModel):
    logical_session_id: Digest
    actor_id: Identifier
    strategy: HumanizeSessionStrategy
    turn_ids: Annotated[tuple[Digest, ...], Field(min_length=1)]

    @field_validator("turn_ids")
    @classmethod
    def require_unique_turns(cls, value: tuple[Digest, ...]) -> tuple[Digest, ...]:
        if len(value) != len(set(value)):
            raise ValueError("a logical session may reference each turn only once")
        return value


class HumanizeReviewerSemantics(StrictModel):
    session_strategy: Literal[HumanizeSessionStrategy.FRESH] = HumanizeSessionStrategy.FRESH
    visibility_ceiling: Literal[Visibility.REVIEWER] = Visibility.REVIEWER
    completion_authority: Literal["edagym_verifier"] = "edagym_verifier"


class HumanizeCycleProjection(StrictModel):
    run_id: Digest
    task_family: Identifier
    session_spec_digest: Digest
    mode: Literal[ModeKind.BENCHMARK, ModeKind.TRAINING]
    session_strategy: HumanizeSessionStrategy
    parent_run_id: Digest | None = None
    audience: HumanizeTraceAudience
    agents: Annotated[tuple[HumanizeAgentProjection, ...], Field(min_length=1)]
    sessions: tuple[HumanizeLogicalSession, ...] = ()
    turns: tuple[HumanizeTurnProjection, ...] = ()
    trace: tuple[HumanizeTraceSlice, ...] = ()
    reviewer: HumanizeReviewerSemantics = HumanizeReviewerSemantics()

    @field_validator("agents")
    @classmethod
    def require_ordered_agents(
        cls,
        value: tuple[HumanizeAgentProjection, ...],
    ) -> tuple[HumanizeAgentProjection, ...]:
        actor_ids = tuple(agent.actor_id for agent in value)
        if len(actor_ids) != len(set(actor_ids)) or actor_ids != tuple(sorted(actor_ids)):
            raise ValueError("Humanize agents must be unique and ordered by actor ID")
        return value

    @field_validator("sessions")
    @classmethod
    def require_ordered_sessions(
        cls,
        value: tuple[HumanizeLogicalSession, ...],
    ) -> tuple[HumanizeLogicalSession, ...]:
        session_ids = tuple(session.logical_session_id for session in value)
        if len(session_ids) != len(set(session_ids)) or session_ids != tuple(sorted(session_ids)):
            raise ValueError("Humanize logical sessions must have unique ordered identities")
        return value

    @field_validator("turns")
    @classmethod
    def require_ordered_turns(
        cls,
        value: tuple[HumanizeTurnProjection, ...],
    ) -> tuple[HumanizeTurnProjection, ...]:
        if tuple(turn.turn_index for turn in value) != tuple(range(1, len(value) + 1)):
            raise ValueError("Humanize turn indices must be contiguous and one-based")
        if len({turn.turn_id for turn in value}) != len(value):
            raise ValueError("Humanize turn identities must be unique")
        return value

    @field_validator("trace")
    @classmethod
    def require_ordered_trace(
        cls,
        value: tuple[HumanizeTraceSlice, ...],
    ) -> tuple[HumanizeTraceSlice, ...]:
        if tuple(item.slice_index for item in value) != tuple(range(1, len(value) + 1)):
            raise ValueError("Humanize trace slices must be contiguous and one-based")
        return value

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if self.mode is ModeKind.BENCHMARK:
            if self.session_strategy is not HumanizeSessionStrategy.FRESH:
                raise ValueError("benchmark projections require fresh logical sessions")
            if self.parent_run_id is not None:
                raise ValueError("benchmark projections require a fresh run lineage")
        elif self.session_strategy is not HumanizeSessionStrategy.STATEFUL:
            raise ValueError("training projections require stateful logical sessions")

        allowed_visibilities = _trace_visibilities(self.audience)
        if any(item.visibility not in allowed_visibilities for item in self.trace):
            raise ValueError("Humanize trace exceeds its audience visibility")

        agent_ids = {agent.actor_id for agent in self.agents}
        trace_by_event = {item.event_id: item for item in self.trace}
        turns_by_id = {turn.turn_id: turn for turn in self.turns}
        sessions_by_id = {session.logical_session_id: session for session in self.sessions}
        if len(trace_by_event) != len(self.trace):
            raise ValueError("Humanize trace event identities must be unique")
        if any(
            turn.actor_id not in agent_ids
            or turn.event_id not in trace_by_event
            or trace_by_event[turn.event_id].producer is not ProducerKind.PARTICIPANT
            or trace_by_event[turn.event_id].actor_id != turn.actor_id
            or turn.logical_session_id not in sessions_by_id
            or turn.turn_id != _turn_id(self.run_id, turn.event_id)
            for turn in self.turns
        ):
            raise ValueError("Humanize turns must reference their journal event and agent")
        if {item.event_id for item in self.trace if item.producer is ProducerKind.PARTICIPANT} != {
            turn.event_id for turn in self.turns
        }:
            raise ValueError("Humanize turns must cover every participant trace event")

        referenced_turn_ids: list[Digest] = []
        actors_with_sessions: set[Identifier] = set()
        for session in self.sessions:
            if (
                session.actor_id not in agent_ids
                or session.strategy is not self.session_strategy
                or (
                    session.actor_id in actors_with_sessions
                    and self.session_strategy is HumanizeSessionStrategy.STATEFUL
                )
            ):
                raise ValueError("Humanize logical session does not match the flow strategy")
            actors_with_sessions.add(session.actor_id)
            session_turns = tuple(turns_by_id.get(turn_id) for turn_id in session.turn_ids)
            if any(
                turn is None
                or turn.actor_id != session.actor_id
                or turn.logical_session_id != session.logical_session_id
                for turn in session_turns
            ):
                raise ValueError("Humanize logical session contains a foreign turn")
            if self.session_strategy is HumanizeSessionStrategy.FRESH and len(session_turns) != 1:
                raise ValueError("fresh Humanize sessions must contain exactly one turn")
            first_turn = session_turns[0]
            if first_turn is None or session.logical_session_id != _logical_session_id(
                self.run_id,
                session.actor_id,
                self.session_strategy,
                first_turn.turn_id,
            ):
                raise ValueError("Humanize logical session identity is not journal-derived")
            referenced_turn_ids.extend(session.turn_ids)
        if len(referenced_turn_ids) != len(set(referenced_turn_ids)) or set(
            referenced_turn_ids
        ) != set(turns_by_id):
            raise ValueError("Humanize logical sessions must partition every projected turn")
        return self


class HumanizeRunProjection(StrictModel):
    schema_version: Literal["edagym-humanize-v1"] = "edagym-humanize-v1"
    projection_id: Digest
    cycle: HumanizeCycleProjection

    @model_validator(mode="after")
    def validate_projection_id(self) -> Self:
        if self.projection_id != _projection_id(self.cycle):
            raise ValueError("Humanize projection identity does not match its cycle")
        return self


_TRACE_EVENT_TYPES = (
    RunStartedEvent,
    InteractionRecordedEvent,
    ControlTransferredEvent,
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    RunEndedEvent,
)
_TRACE_EVENT_KINDS = frozenset(
    {
        EventKind.RUN_STARTED,
        EventKind.INTERACTION_RECORDED,
        EventKind.CONTROL_TRANSFERRED,
        EventKind.CANDIDATE_SUBMITTED,
        EventKind.CHECKPOINT_COMMITTED,
        EventKind.RUN_ENDED,
    }
)


def project_humanize(
    journal: TrialJournal,
    session: SessionSpec,
    *,
    audience: HumanizeTraceAudience = HumanizeTraceAudience.PARTICIPANT,
) -> HumanizeRunProjection:
    """Derive Humanize session and trace concepts without opening another ledger."""

    snapshot = ProjectionSnapshot.from_journal(journal)
    if session.digest != snapshot.header.binding.session.session_spec_digest:
        raise ProjectionUnavailable("Humanize projection session does not match the run binding")
    try:
        audience = HumanizeTraceAudience(audience)
    except ValueError:
        raise ProjectionUnavailable("Humanize trace audience is unsupported") from None
    if isinstance(session.mode, BenchmarkMode):
        strategy = HumanizeSessionStrategy.FRESH
        if snapshot.header.binding.lineage != RunLineage():
            raise ProjectionUnavailable("benchmark Humanize projections require fresh lineage")
    elif isinstance(session.mode, TrainingMode):
        strategy = HumanizeSessionStrategy.STATEFUL
    else:
        raise ProjectionUnavailable("Humanize projections require benchmark or training mode")

    visible = _trace_visibilities(audience)
    traced_events = tuple(
        event
        for event in snapshot.events
        if isinstance(event, _TRACE_EVENT_TYPES) and event.visibility in visible
    )
    trace = tuple(
        HumanizeTraceSlice(
            slice_index=index,
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_kind=event.kind,
            producer=event.producer,
            actor_id=event.actor,
            visibility=cast(HumanizeTraceVisibility, event.visibility),
        )
        for index, event in enumerate(traced_events, start=1)
    )
    participant_events = tuple(
        event for event in traced_events if event.producer is ProducerKind.PARTICIPANT
    )
    turns: list[HumanizeTurnProjection] = []
    turn_ids_by_session: defaultdict[Digest, list[Digest]] = defaultdict(list)
    actor_by_session: dict[Digest, Identifier] = {}
    for event in participant_events:
        if event.actor is None:
            raise ProjectionUnavailable("participant trace event has no actor attribution")
        turn_id = _turn_id(snapshot.header.run_id, event.event_id)
        session_id = _logical_session_id(
            snapshot.header.run_id,
            event.actor,
            strategy,
            turn_id,
        )
        turns.append(
            HumanizeTurnProjection(
                turn_index=len(turns) + 1,
                turn_id=turn_id,
                logical_session_id=session_id,
                actor_id=event.actor,
                event_id=event.event_id,
            )
        )
        turn_ids_by_session[session_id].append(turn_id)
        actor_by_session[session_id] = event.actor
    sessions = tuple(
        HumanizeLogicalSession(
            logical_session_id=session_id,
            actor_id=actor_by_session[session_id],
            strategy=strategy,
            turn_ids=tuple(turn_ids_by_session[session_id]),
        )
        for session_id in sorted(turn_ids_by_session)
    )
    cycle = HumanizeCycleProjection(
        run_id=snapshot.header.run_id,
        task_family=snapshot.header.binding.task.family,
        session_spec_digest=session.digest,
        mode=session.mode.kind,
        session_strategy=strategy,
        parent_run_id=snapshot.header.binding.lineage.parent_run_id,
        audience=audience,
        agents=tuple(
            HumanizeAgentProjection(actor_id=actor.actor_id, kind=actor.kind)
            for actor in snapshot.header.binding.session.actors
        ),
        sessions=sessions,
        turns=tuple(turns),
        trace=trace,
    )
    return HumanizeRunProjection(
        projection_id=_projection_id(cycle),
        cycle=cycle,
    )


def _trace_visibilities(audience: HumanizeTraceAudience) -> frozenset[Visibility]:
    if audience is HumanizeTraceAudience.PARTICIPANT:
        return PARTICIPANT_EVENT_VISIBILITY
    return PARTICIPANT_EVENT_VISIBILITY | {Visibility.REVIEWER}


def _turn_id(run_id: Digest, event_id: UUID) -> Digest:
    return canonical_digest(
        {"event_id": str(event_id), "run_id": run_id},
        domain="humanize-turn-projection-v1",
    )


def _logical_session_id(
    run_id: Digest,
    actor_id: Identifier,
    strategy: HumanizeSessionStrategy,
    turn_id: Digest,
) -> Digest:
    identity: dict[str, str] = {
        "actor_id": actor_id,
        "run_id": run_id,
        "strategy": strategy.value,
    }
    if strategy is HumanizeSessionStrategy.FRESH:
        identity["turn_id"] = turn_id
    return canonical_digest(identity, domain="humanize-logical-session-v1")


def _projection_id(cycle: HumanizeCycleProjection) -> Digest:
    return canonical_digest(cycle, domain="humanize-run-projection-v1")
