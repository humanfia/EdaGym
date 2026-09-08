"""Semantic boundaries for the stateless Humanize projection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from edagym.projections import (
    HumanizeSessionStrategy,
    HumanizeTraceAudience,
    ProjectionUnavailable,
    project_humanize,
)
from edagym.resolution import resolve_run
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import (
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    ProducerKind,
    RunHeader,
    RunLineage,
    RunStartedEvent,
    RunStartedPayload,
)
from edagym.specs.common import Visibility
from edagym.specs.session import BenchmarkMode, RecoveryPolicy, SessionSpec

from .factories import (
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)

_NOW = datetime(2026, 9, 4, tzinfo=UTC)
_VISIBLE_EVENT_IDS = (
    UUID("00000000-0000-0000-0000-000000000401"),
    UUID("00000000-0000-0000-0000-000000000402"),
    UUID("00000000-0000-0000-0000-000000000403"),
    UUID("00000000-0000-0000-0000-000000000404"),
)
_HIDDEN_EVENT_IDS = (
    UUID("00000000-0000-0000-0000-000000000405"),
    UUID("00000000-0000-0000-0000-000000000406"),
)


def test_humanize_fresh_projection_is_visibility_closed_and_deterministic(
    tmp_path: Path,
) -> None:
    session = _benchmark_session()
    visible_journal = _journal(tmp_path / "visible", session)
    hidden_journal = _journal(tmp_path / "hidden", session)
    _append_trace_events(visible_journal, include_hidden=False)
    _append_trace_events(hidden_journal, include_hidden=True)

    visible_projection = project_humanize(visible_journal, session)
    hidden_projection = project_humanize(hidden_journal, session)

    assert visible_projection == hidden_projection
    assert visible_projection == project_humanize(visible_journal, session)
    cycle = visible_projection.cycle
    assert cycle.session_strategy is HumanizeSessionStrategy.FRESH
    assert len(cycle.turns) == 2
    assert len(cycle.sessions) == 2
    assert all(len(logical_session.turn_ids) == 1 for logical_session in cycle.sessions)
    assert {item.visibility for item in cycle.trace} <= {
        Visibility.PUBLIC,
        Visibility.PARTICIPANT,
    }

    reviewer_projection = project_humanize(
        hidden_journal,
        session,
        audience=HumanizeTraceAudience.REVIEWER,
    )
    reviewer_event_ids = {item.event_id for item in reviewer_projection.cycle.trace}
    assert _VISIBLE_EVENT_IDS[2] in reviewer_event_ids
    assert reviewer_event_ids.isdisjoint(_HIDDEN_EVENT_IDS)
    assert reviewer_projection.cycle.reviewer.session_strategy is HumanizeSessionStrategy.FRESH
    assert reviewer_projection.cycle.reviewer.visibility_ceiling is Visibility.REVIEWER
    assert reviewer_projection.cycle.reviewer.completion_authority == "edagym_verifier"
    assert reviewer_projection.projection_id != visible_projection.projection_id


def test_humanize_training_state_and_benchmark_freshness_come_from_bound_lineage(
    tmp_path: Path,
) -> None:
    training = session_spec()
    lineage = RunLineage(
        parent_run_id="sha256:" + "a" * 64,
        parent_checkpoint_id="previous_checkpoint",
    )
    training_journal = _journal(tmp_path / "training", training, lineage=lineage)
    _append_trace_events(training_journal, include_hidden=False)

    projection = project_humanize(training_journal, training)

    assert projection.cycle.session_strategy is HumanizeSessionStrategy.STATEFUL
    assert projection.cycle.parent_run_id == lineage.parent_run_id
    assert len(projection.cycle.sessions) == 1
    assert projection.cycle.sessions[0].turn_ids == tuple(
        turn.turn_id for turn in projection.cycle.turns
    )

    benchmark = _benchmark_session()
    continued_benchmark = _journal(
        tmp_path / "continued-benchmark",
        benchmark,
        lineage=RunLineage(parent_run_id="sha256:" + "b" * 64),
    )
    with pytest.raises(ProjectionUnavailable, match="fresh lineage"):
        project_humanize(continued_benchmark, benchmark)


def _benchmark_session() -> SessionSpec:
    base = session_spec()
    return SessionSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "mode": BenchmarkMode(),
            "recovery": RecoveryPolicy.NONE,
        }
    )


def _journal(
    root: Path,
    session: SessionSpec,
    *,
    lineage: RunLineage | None = None,
) -> TrialJournal:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="humanize_projection",
        lineage=lineage,
    )
    return TrialJournal.create(root, RunHeader.from_binding(plan.binding), task)


def _append_trace_events(journal: TrialJournal, *, include_hidden: bool) -> None:
    events: list[RunStartedEvent | InteractionRecordedEvent] = []

    def append(event: RunStartedEvent | InteractionRecordedEvent) -> None:
        events.append(event.model_copy(update={"sequence": len(events)}))

    append(
        RunStartedEvent(
            run_id=journal.header.run_id,
            sequence=0,
            event_id=_VISIBLE_EVENT_IDS[0],
            timestamp=_NOW,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=journal.header.binding.digest),
        )
    )
    append(
        _interaction(
            journal,
            event_id=_VISIBLE_EVENT_IDS[1],
            timestamp=_NOW + timedelta(seconds=1),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.PARTICIPANT,
            direction=InteractionDirection.PARTICIPANT_OUTPUT,
            interaction_id="first_visible_turn",
        )
    )
    if include_hidden:
        append(
            _interaction(
                journal,
                event_id=_HIDDEN_EVENT_IDS[0],
                timestamp=_NOW + timedelta(seconds=2),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                direction=InteractionDirection.PARTICIPANT_INPUT,
                interaction_id="hidden_verifier_fact",
            )
        )
    append(
        _interaction(
            journal,
            event_id=_VISIBLE_EVENT_IDS[2],
            timestamp=_NOW + timedelta(seconds=3),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.REVIEWER,
            direction=InteractionDirection.PARTICIPANT_INPUT,
            interaction_id="reviewer_observation",
        )
    )
    if include_hidden:
        append(
            _interaction(
                journal,
                event_id=_HIDDEN_EVENT_IDS[1],
                timestamp=_NOW + timedelta(seconds=4),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                direction=InteractionDirection.PARTICIPANT_INPUT,
                interaction_id="hidden_author_fact",
            )
        )
    append(
        _interaction(
            journal,
            event_id=_VISIBLE_EVENT_IDS[3],
            timestamp=_NOW + timedelta(seconds=5),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.PARTICIPANT,
            direction=InteractionDirection.PARTICIPANT_OUTPUT,
            interaction_id="second_visible_turn",
        )
    )
    journal.append_events(tuple(events))


def _interaction(
    journal: TrialJournal,
    *,
    event_id: UUID,
    timestamp: datetime,
    producer: ProducerKind,
    visibility: Visibility,
    direction: InteractionDirection,
    interaction_id: str,
    actor: str | None = None,
) -> InteractionRecordedEvent:
    return InteractionRecordedEvent(
        run_id=journal.header.run_id,
        sequence=0,
        event_id=event_id,
        timestamp=timestamp,
        producer=producer,
        actor=actor,
        visibility=visibility,
        payload=InteractionRecordedPayload(
            direction=direction,
            interaction_id=interaction_id,
        ),
    )
