"""Shared audience-bounded facts used by outbound projections."""

from __future__ import annotations

from collections.abc import Set

from edagym.participants.model import PARTICIPANT_EVENT_VISIBILITY
from edagym.projections._snapshot import ProjectionSnapshot
from edagym.projections.model import ParticipationKind
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    HarnessRunActor,
    HumanRunActor,
    RunEndedEvent,
    RunEvent,
)
from edagym.specs.common import Visibility


def participation_kind(snapshot: ProjectionSnapshot) -> ParticipationKind:
    has_human = any(
        isinstance(actor, HumanRunActor) for actor in snapshot.header.binding.session.actors
    )
    has_harness = any(
        isinstance(actor, HarnessRunActor) for actor in snapshot.header.binding.session.actors
    )
    if has_human and has_harness:
        return ParticipationKind.HYBRID
    if has_human:
        return ParticipationKind.HUMAN
    return ParticipationKind.AGENT


def human_intervention_count(snapshot: ProjectionSnapshot) -> int:
    human_ids = {
        actor.actor_id
        for actor in snapshot.header.binding.session.actors
        if isinstance(actor, HumanRunActor)
    }
    return sum(1 for event in snapshot.events if _is_human_participant_event(event, human_ids))


def visible_candidate_events(
    snapshot: ProjectionSnapshot,
    visibilities: Set[Visibility],
) -> tuple[CandidateSubmittedEvent, ...]:
    artifact_ids = visible_artifact_ids(snapshot, visibilities)
    visible_ids: set[str] = set()
    visible_events: list[CandidateSubmittedEvent] = []
    for event in snapshot.events:
        if not isinstance(event, CandidateSubmittedEvent) or event.visibility not in visibilities:
            continue
        if not set(event.artifact_refs).issubset(artifact_ids):
            continue
        parent_id = event.payload.parent_candidate_id
        if parent_id is not None and parent_id not in visible_ids:
            continue
        visible_ids.add(event.payload.candidate_id)
        visible_events.append(event)
    return tuple(visible_events)


def visible_checkpoint_ids(
    snapshot: ProjectionSnapshot,
    visibilities: Set[Visibility],
) -> frozenset[str]:
    artifact_ids = visible_artifact_ids(snapshot, visibilities)
    visible_ids: set[str] = set()
    for event in snapshot.events:
        if not isinstance(event, CheckpointCommittedEvent) or event.visibility not in visibilities:
            continue
        if not set(event.artifact_refs).issubset(artifact_ids):
            continue
        parent_id = event.payload.parent_checkpoint_id
        if parent_id is None or parent_id in visible_ids:
            visible_ids.add(event.payload.checkpoint_id)
    return frozenset(visible_ids)


def visible_artifact_ids(
    snapshot: ProjectionSnapshot,
    visibilities: Set[Visibility],
) -> frozenset[str]:
    return frozenset(
        event.payload.record.logical_id
        for event in snapshot.events
        if isinstance(event, ArtifactRecordedEvent)
        and event.visibility in visibilities
        and event.payload.record.visibility in visibilities
    )


def visible_run_end(
    snapshot: ProjectionSnapshot,
    visibilities: Set[Visibility],
) -> RunEndedEvent | None:
    terminal = next(
        (event for event in reversed(snapshot.events) if isinstance(event, RunEndedEvent)),
        None,
    )
    if terminal is None or terminal.visibility not in visibilities:
        return None
    return terminal


def _is_human_participant_event(event: RunEvent, human_ids: set[str]) -> bool:
    return (
        event.visibility in PARTICIPANT_EVENT_VISIBILITY
        and event.actor is not None
        and event.actor in human_ids
    )
