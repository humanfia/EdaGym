"""ATIF v1.8 projection with reference-only interaction content."""

from __future__ import annotations

from edagym.canonical import canonical_digest
from edagym.participants.model import PARTICIPANT_EVENT_VISIBILITY
from edagym.projections._facts import (
    visible_candidate_events,
    visible_checkpoint_ids,
)
from edagym.projections._snapshot import ProjectionSnapshot
from edagym.projections.errors import ProjectionUnavailable
from edagym.projections.model import (
    AtifAgent,
    AtifCandidateExtra,
    AtifCheckpointExtra,
    AtifControlTransferExtra,
    AtifFinalMetrics,
    AtifInteractionExtra,
    AtifRequestedModelRoute,
    AtifRunEndedExtra,
    AtifRunExtra,
    AtifRunStartedExtra,
    AtifSource,
    AtifStep,
    AtifTrajectory,
)
from edagym.run.journal import RunJournal
from edagym.run.model import (
    ArtifactRecordedEvent,
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    ControlTransferredEvent,
    HarnessRunActor,
    HumanRunActor,
    InteractionDirection,
    InteractionRecordedEvent,
    ProducerKind,
    RunEndedEvent,
    RunRecord,
    RunStartedEvent,
)
from edagym.specs.common import Redistribution, Sensitivity, Visibility
from edagym.specs.session import ActorKind
from edagym.specs.task import TaskSpec


def project_atif(journal: RunJournal) -> AtifTrajectory:
    """Derive a structurally valid ATIF trajectory without dereferencing content."""

    return _project_atif_snapshot(ProjectionSnapshot.from_journal(journal))


def project_atif_record(record: RunRecord, task: TaskSpec) -> AtifTrajectory:
    """Derive ATIF from a portable record through the same replay boundary."""

    return _project_atif_snapshot(ProjectionSnapshot.from_record(record, task))


def _project_atif_snapshot(snapshot: ProjectionSnapshot) -> AtifTrajectory:
    """Project one already validated journal snapshot."""

    public_artifacts = {
        event.payload.record.logical_id
        for event in snapshot.events
        if isinstance(event, ArtifactRecordedEvent)
        and event.visibility is Visibility.PUBLIC
        and event.payload.record.visibility is Visibility.PUBLIC
        and event.payload.record.sensitivity is Sensitivity.PUBLIC
        and event.payload.record.redistribution is Redistribution.ALLOWED
    }
    actor_kinds = {actor.actor_id: actor.kind for actor in snapshot.header.binding.session.actors}
    visible_candidate_ids = {
        event.payload.candidate_id
        for event in visible_candidate_events(
            snapshot,
            PARTICIPANT_EVENT_VISIBILITY,
        )
    }
    checkpoint_ids = visible_checkpoint_ids(
        snapshot,
        PARTICIPANT_EVENT_VISIBILITY,
    )
    steps: list[AtifStep] = []
    for event in snapshot.events:
        projected = _project_event(
            event,
            actor_kinds,
            public_artifacts,
            visible_candidate_ids,
            checkpoint_ids,
        )
        if projected is None:
            continue
        steps.append(projected.model_copy(update={"step_id": len(steps) + 1}))
    if not steps:
        raise ProjectionUnavailable("ATIF projection requires participant-visible run facts")
    trajectory_agent = _trajectory_agent(snapshot)
    return AtifTrajectory(
        session_id=snapshot.header.run_id,
        trajectory_id=snapshot.header.run_id,
        agent=trajectory_agent,
        steps=tuple(steps),
        final_metrics=AtifFinalMetrics(total_steps=len(steps)),
        extra=AtifRunExtra(
            task_family=snapshot.header.binding.task.family,
            authoring_revision=snapshot.header.binding.task.authoring_revision,
            task_spec_digest=snapshot.header.binding.task.task_spec_digest,
            instance_digest=snapshot.header.binding.task.instance_digest,
            release_digest=snapshot.header.binding.task.release_digest,
            environment_spec_digest=(snapshot.header.binding.environment.environment_spec_digest),
            session_spec_digest=snapshot.header.binding.session.session_spec_digest,
            requested_model_routes=tuple(
                AtifRequestedModelRoute(
                    actor_id=actor.actor_id,
                    route=actor.requested_model_route,
                )
                for actor in snapshot.header.binding.session.actors
                if isinstance(actor, HarnessRunActor)
            ),
        ),
    )


def _project_event(
    event: object,
    actor_kinds: dict[str, ActorKind],
    public_artifacts: set[str],
    visible_candidate_ids: set[str],
    checkpoint_ids: frozenset[str],
) -> AtifStep | None:
    if isinstance(event, RunStartedEvent):
        if event.visibility not in PARTICIPANT_EVENT_VISIBILITY:
            return None
        return AtifStep(
            step_id=1,
            timestamp=event.timestamp.isoformat(),
            source=AtifSource.SYSTEM,
            extra=AtifRunStartedExtra(event_id=str(event.event_id)),
        )
    if isinstance(event, InteractionRecordedEvent):
        if event.visibility not in PARTICIPANT_EVENT_VISIBILITY:
            return None
        actor_kind = None if event.actor is None else actor_kinds[event.actor]
        source = _interaction_source(
            event.payload.direction,
            actor_kind,
            event.producer,
        )
        if source is None:
            return None
        return AtifStep(
            step_id=1,
            timestamp=event.timestamp.isoformat(),
            source=source,
            extra=AtifInteractionExtra(
                event_id=str(event.event_id),
                actor_id=event.actor,
                interaction_id=event.payload.interaction_id,
                direction=event.payload.direction,
                related_interaction_id=event.payload.related_interaction_id,
                tool_name=event.payload.tool_name,
                public_artifact_refs=tuple(
                    reference for reference in event.artifact_refs if reference in public_artifacts
                ),
            ),
        )
    if isinstance(event, ControlTransferredEvent):
        if event.visibility not in PARTICIPANT_EVENT_VISIBILITY or event.actor is None:
            return None
        source = (
            AtifSource.USER if actor_kinds[event.actor] is ActorKind.HUMAN else AtifSource.AGENT
        )
        return AtifStep(
            step_id=1,
            timestamp=event.timestamp.isoformat(),
            source=source,
            extra=AtifControlTransferExtra(
                event_id=str(event.event_id),
                actor_id=event.actor,
                previous_writer=event.payload.previous_writer,
                next_writer=event.payload.next_writer,
            ),
        )
    if isinstance(event, CandidateSubmittedEvent):
        if event.payload.candidate_id not in visible_candidate_ids or event.actor is None:
            return None
        source = (
            AtifSource.USER if actor_kinds[event.actor] is ActorKind.HUMAN else AtifSource.AGENT
        )
        return AtifStep(
            step_id=1,
            timestamp=event.timestamp.isoformat(),
            source=source,
            extra=AtifCandidateExtra(
                event_id=str(event.event_id),
                actor_id=event.actor,
                candidate_id=event.payload.candidate_id,
                parent_candidate_id=event.payload.parent_candidate_id,
            ),
        )
    if isinstance(event, CheckpointCommittedEvent):
        if event.payload.checkpoint_id not in checkpoint_ids:
            return None
        return AtifStep(
            step_id=1,
            timestamp=event.timestamp.isoformat(),
            source=AtifSource.SYSTEM,
            extra=AtifCheckpointExtra(
                event_id=str(event.event_id),
                checkpoint_id=event.payload.checkpoint_id,
                parent_checkpoint_id=event.payload.parent_checkpoint_id,
            ),
        )
    if isinstance(event, RunEndedEvent):
        if event.visibility not in PARTICIPANT_EVENT_VISIBILITY:
            return None
        return AtifStep(
            step_id=1,
            timestamp=event.timestamp.isoformat(),
            source=AtifSource.SYSTEM,
            extra=AtifRunEndedExtra(
                event_id=str(event.event_id),
                reason=event.payload.reason,
                successful_candidate_id=(
                    event.payload.successful_candidate_id
                    if event.payload.successful_candidate_id in visible_candidate_ids
                    else None
                ),
            ),
        )
    return None


def _interaction_source(
    direction: InteractionDirection,
    actor_kind: ActorKind | None,
    producer: ProducerKind,
) -> AtifSource | None:
    if producer is ProducerKind.CONTROLLER:
        if direction is InteractionDirection.PARTICIPANT_INPUT:
            return AtifSource.USER
        if direction is InteractionDirection.TOOL_RESULT:
            return AtifSource.SYSTEM
        return None
    if direction not in {
        InteractionDirection.PARTICIPANT_OUTPUT,
        InteractionDirection.TOOL_REQUEST,
    }:
        return None
    return AtifSource.USER if actor_kind is ActorKind.HUMAN else AtifSource.AGENT


def _trajectory_agent(snapshot: ProjectionSnapshot) -> AtifAgent:
    actors = snapshot.header.binding.session.actors
    harnesses = [actor for actor in actors if isinstance(actor, HarnessRunActor)]
    if len(harnesses) == 1:
        harness = harnesses[0]
        return AtifAgent(
            name="edagym-harness",
            version=canonical_digest(
                {
                    "harness_digest": harness.harness_digest,
                    "scaffold_digest": harness.scaffold_digest,
                },
                domain="atif-agent-version-v1",
            ),
        )
    if harnesses:
        return AtifAgent(
            name="edagym-multi-harness",
            version=canonical_digest(
                tuple(harnesses),
                domain="atif-agent-version-v1",
            ),
        )
    human = next(actor for actor in actors if isinstance(actor, HumanRunActor))
    return AtifAgent(
        name="edagym-human-adapter",
        version=human.adapter_digest,
    )
