"""Course evidence and environment-partitioned leaderboard projections."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from edagym.evaluation.model import (
    MeasurementEvidence,
    MeasurementProvenance,
    OutcomeKind,
    ParetoVectorScore,
    ScorerEligibilityKind,
)
from edagym.evaluation.scoring import pareto_dominates
from edagym.participants.model import PARTICIPANT_EVENT_VISIBILITY
from edagym.projections._facts import (
    human_intervention_count,
    participation_kind,
    visible_candidate_events,
    visible_checkpoint_ids,
    visible_run_end,
)
from edagym.projections._snapshot import ProjectionSnapshot
from edagym.projections.errors import ProjectionUnavailable
from edagym.projections.model import (
    ActorCourseEvidence,
    ArtifactClassCount,
    CandidateCourseEvidence,
    CourseReport,
    LeaderboardActor,
    LeaderboardAggregate,
    LeaderboardCohort,
    LeaderboardEntry,
    LeaderboardEvaluator,
    LeaderboardHarnessActor,
    LeaderboardHumanActor,
    LeaderboardMeasurement,
    LeaderboardPartition,
    LeaderboardStageOutcome,
    ParticipationKind,
)
from edagym.run.artifact_model import (
    ArtifactRecord,
)
from edagym.run.artifacts import SANITIZED_MEASUREMENTS_MEDIA_TYPE
from edagym.run.journal import RunJournal
from edagym.run.model import (
    COMPARABLE_TRIAL_STOP_REASONS,
    ArtifactRecordedEvent,
    ControlTransferredEvent,
    EvaluationCompletedEvent,
    HarnessRunActor,
    HumanRunActor,
    InteractionRecordedEvent,
    RunRecord,
    ScoringRecordedEvent,
    StopReason,
)
from edagym.specs.common import (
    ArtifactClass,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.session import BenchmarkMode, CourseMode, SessionSpec
from edagym.specs.task import MetricDirection, NativeSealedTaskOrigin, TaskSpec

_COURSE_VISIBLE = PARTICIPANT_EVENT_VISIBILITY | {Visibility.REVIEWER}
_PUBLIC_RESULT_VISIBILITY = Visibility.PUBLIC


def project_course_report(journal: RunJournal, session: SessionSpec) -> CourseReport:
    return _project_course_report_snapshot(
        ProjectionSnapshot.from_journal(journal),
        session,
    )


def project_course_report_record(
    record: RunRecord,
    task: TaskSpec,
    session: SessionSpec,
) -> CourseReport:
    """Derive a course report from a portable record after semantic replay."""

    return _project_course_report_snapshot(
        ProjectionSnapshot.from_record(record, task),
        session,
    )


def _project_course_report_snapshot(
    snapshot: ProjectionSnapshot,
    session: SessionSpec,
) -> CourseReport:
    _require_session(snapshot, session)
    if not isinstance(session.mode, CourseMode):
        raise ProjectionUnavailable("course reports require a course session")
    interactions: defaultdict[str, int] = defaultdict(int)
    handoffs_given: defaultdict[str, int] = defaultdict(int)
    handoffs_received: defaultdict[str, int] = defaultdict(int)
    for event in snapshot.events:
        if event.visibility not in _COURSE_VISIBLE:
            continue
        if isinstance(event, InteractionRecordedEvent) and event.actor is not None:
            interactions[event.actor] += 1
        elif isinstance(event, ControlTransferredEvent):
            handoffs_given[event.payload.previous_writer] += 1
            handoffs_received[event.payload.next_writer] += 1

    candidate_events = visible_candidate_events(
        snapshot,
        _COURSE_VISIBLE,
    )
    visible_candidate_ids = {event.payload.candidate_id for event in candidate_events}
    candidates_by_actor: defaultdict[str, int] = defaultdict(int)
    for event in candidate_events:
        if event.actor is not None:
            candidates_by_actor[event.actor] += 1
    actors = tuple(
        ActorCourseEvidence(
            actor_id=actor.actor_id,
            kind=actor.kind,
            interaction_count=interactions[actor.actor_id],
            candidate_count=candidates_by_actor[actor.actor_id],
            handoffs_given=handoffs_given[actor.actor_id],
            handoffs_received=handoffs_received[actor.actor_id],
        )
        for actor in snapshot.header.binding.session.actors
    )
    outcomes_by_candidate: defaultdict[str, list[tuple[str, OutcomeKind]]] = defaultdict(list)
    for event in snapshot.events:
        if isinstance(event, EvaluationCompletedEvent) and event.visibility in _COURSE_VISIBLE:
            if event.payload.candidate_id not in visible_candidate_ids:
                continue
            outcomes_by_candidate[event.payload.candidate_id].append(
                (event.payload.result.stage_id, event.payload.result.outcome.kind)
            )
    candidates = tuple(
        CandidateCourseEvidence(
            candidate_id=event.payload.candidate_id,
            actor_id=event.actor,
            parent_candidate_id=event.payload.parent_candidate_id,
            stage_outcomes=tuple(sorted(outcomes_by_candidate[event.payload.candidate_id])),
        )
        for event in candidate_events
        if event.actor is not None
    )
    visible_artifacts = tuple(
        event.payload.record
        for event in snapshot.events
        if isinstance(event, ArtifactRecordedEvent)
        and event.visibility in _COURSE_VISIBLE
        and event.payload.record.visibility in _COURSE_VISIBLE
        and event.payload.record.sensitivity in {Sensitivity.PUBLIC, Sensitivity.INTERNAL}
        and event.payload.record.redistribution is Redistribution.ALLOWED
    )
    artifact_counts = tuple(
        ArtifactClassCount(
            artifact_class=artifact_class,
            count=sum(artifact.artifact_class is artifact_class for artifact in visible_artifacts),
        )
        for artifact_class in ArtifactClass
    )
    terminal = visible_run_end(snapshot, _COURSE_VISIBLE)
    terminal_candidate_id = None if terminal is None else terminal.payload.successful_candidate_id
    return CourseReport(
        run_id=snapshot.header.run_id,
        task_family=snapshot.header.binding.task.family,
        authoring_revision=snapshot.header.binding.task.authoring_revision,
        task_spec_digest=snapshot.header.binding.task.task_spec_digest,
        instance_digest=snapshot.header.binding.task.instance_digest,
        release_digest=snapshot.header.binding.task.release_digest,
        environment_spec_digest=(snapshot.header.binding.environment.environment_spec_digest),
        session_spec_digest=snapshot.header.binding.session.session_spec_digest,
        rubric_digest=session.mode.rubric_digest,
        oral_defense=session.mode.oral_defense,
        participation=participation_kind(snapshot),
        actors=actors,
        candidates=candidates,
        handoff_count=sum(handoffs_given.values()),
        checkpoint_count=len(visible_checkpoint_ids(snapshot, _COURSE_VISIBLE)),
        artifact_counts=artifact_counts,
        terminal_reason=None if terminal is None else terminal.payload.reason,
        successful_candidate_id=(
            terminal_candidate_id
            if terminal_candidate_id in {candidate.candidate_id for candidate in candidates}
            else None
        ),
    )


def project_leaderboard_entry(
    journal: RunJournal,
    session: SessionSpec,
) -> LeaderboardEntry:
    return _project_leaderboard_entry_snapshot(
        ProjectionSnapshot.from_journal(journal),
        session,
    )


def project_leaderboard_entry_record(
    record: RunRecord,
    task: TaskSpec,
    session: SessionSpec,
) -> LeaderboardEntry:
    """Derive a leaderboard entry from a portable record after semantic replay."""

    return _project_leaderboard_entry_snapshot(
        ProjectionSnapshot.from_record(record, task),
        session,
    )


def _project_leaderboard_entry_snapshot(
    snapshot: ProjectionSnapshot,
    session: SessionSpec,
) -> LeaderboardEntry:
    _require_session(snapshot, session)
    _require_sealed_leaderboard_task(snapshot.task)
    if not isinstance(session.mode, BenchmarkMode):
        raise ProjectionUnavailable("leaderboard entries require a benchmark session")
    if snapshot.state.terminal_reason is None:
        raise ProjectionUnavailable("leaderboard entries require a terminated run")
    terminal = visible_run_end(snapshot, {Visibility.PUBLIC})
    if terminal is None:
        raise ProjectionUnavailable("leaderboard entries require a public terminal outcome")
    participation = participation_kind(snapshot)
    actors = tuple(_leaderboard_actor(actor) for actor in snapshot.header.binding.session.actors)
    cohort = LeaderboardCohort(
        actors=actors,
        initial_writer=snapshot.header.binding.session.initial_writer,
        handoff_enabled=snapshot.header.binding.session.handoff_enabled,
        participation=participation,
    )
    measurement_schema = {
        measurement.measurement_id: measurement for measurement in snapshot.task.measurements
    }
    successful_candidate_id = terminal.payload.successful_candidate_id
    public_results = tuple(
        event.payload
        for event in snapshot.events
        if isinstance(event, EvaluationCompletedEvent)
        and event.visibility is _PUBLIC_RESULT_VISIBILITY
        and event.payload.candidate_id == successful_candidate_id
    )
    public_scoring = next(
        (
            event.payload.decision
            for event in snapshot.events
            if isinstance(event, ScoringRecordedEvent)
            and event.visibility is _PUBLIC_RESULT_VISIBILITY
            and event.payload.candidate_id == successful_candidate_id
        ),
        None,
    )
    public_measurement_artifacts = {
        event.payload.record.logical_id: event.payload.record
        for event in snapshot.events
        if isinstance(event, ArtifactRecordedEvent)
        and event.visibility is Visibility.PUBLIC
        and event.payload.record.artifact_class is ArtifactClass.MEASUREMENT
        and event.payload.record.visibility is Visibility.PUBLIC
        and event.payload.record.sensitivity is Sensitivity.PUBLIC
        and event.payload.record.redistribution is Redistribution.ALLOWED
    }
    stage_outcomes = tuple(
        LeaderboardStageOutcome(
            candidate_id=result.candidate_id,
            stage_id=result.result.stage_id,
            outcome=result.result.outcome.kind,
        )
        for result in public_results
    )
    measurements = tuple(
        _leaderboard_measurement(
            candidate_id=result.candidate_id,
            stage_id=result.result.stage_id,
            evidence=evidence,
            direction=measurement_schema[evidence.measurement_id].direction,
            public_measurement_artifacts=public_measurement_artifacts,
        )
        for result in public_results
        for evidence in result.result.measurements
    )
    evaluator_bindings = tuple(
        LeaderboardEvaluator(
            evaluator_id=evaluator.evaluator_id,
            revision_digest=evaluator.revision_digest,
        )
        for evaluator in snapshot.header.binding.evaluators
    )
    partition = LeaderboardPartition(
        task_family=snapshot.header.binding.task.family,
        authoring_revision=snapshot.header.binding.task.authoring_revision,
        task_spec_digest=snapshot.header.binding.task.task_spec_digest,
        instance_digest=snapshot.header.binding.task.instance_digest,
        release_digest=snapshot.header.binding.task.release_digest,
        environment_spec_digest=(snapshot.header.binding.environment.environment_spec_digest),
        cohort=cohort,
        feedback_policy_digest=snapshot.header.binding.session.feedback_policy_digest,
        budget_digest=snapshot.header.binding.session.budget_digest,
        evaluators=evaluator_bindings,
        measurement_schema_digest=snapshot.header.binding.measurement_schema_digest,
        scorer_revision_digest=snapshot.header.binding.scorer_revision_digest,
        trial_count=session.mode.trial_count,
    )
    return LeaderboardEntry(
        partition_id=partition.digest,
        partition=partition,
        run_id=snapshot.header.run_id,
        lineage=snapshot.header.binding.lineage,
        rank_eligible=(
            participation is ParticipationKind.AGENT
            and snapshot.header.binding.lineage.parent_run_id is None
            and snapshot.state.terminal_reason is StopReason.VERIFIER_SUCCESS
            and public_scoring is not None
            and public_scoring.eligibility.state is ScorerEligibilityKind.READY
        ),
        success=snapshot.state.successful_candidate_id is not None,
        terminal_reason=snapshot.state.terminal_reason,
        human_intervention_count=human_intervention_count(snapshot),
        stage_outcomes=stage_outcomes,
        measurements=measurements,
        scoring_eligibility=(None if public_scoring is None else public_scoring.eligibility.state),
        score=None if public_scoring is None else public_scoring.score,
    )


def aggregate_leaderboard(
    runs: Sequence[tuple[RunJournal, SessionSpec]],
) -> tuple[LeaderboardAggregate, ...]:
    entries = tuple(project_leaderboard_entry(journal, session) for journal, session in runs)
    run_ids = [entry.run_id for entry in entries]
    if len(run_ids) != len(set(run_ids)):
        raise ProjectionUnavailable("a leaderboard cannot count the same run twice")
    grouped: defaultdict[str, list[LeaderboardEntry]] = defaultdict(list)
    for entry in entries:
        grouped[entry.partition_id].append(entry)
    aggregates = []
    for partition_id, group in grouped.items():
        first = group[0]
        if len(group) != first.partition.trial_count:
            raise ProjectionUnavailable("a leaderboard partition requires its declared trial count")
        aggregates.append(
            LeaderboardAggregate(
                partition_id=partition_id,
                partition=first.partition,
                rank_eligible=all(
                    entry.partition.cohort.participation is ParticipationKind.AGENT
                    and entry.lineage.parent_run_id is None
                    and (not entry.success or entry.rank_eligible)
                    and entry.terminal_reason in COMPARABLE_TRIAL_STOP_REASONS
                    for entry in group
                ),
                run_ids=tuple(sorted(entry.run_id for entry in group)),
                success_numerator=sum(entry.success for entry in group),
                success_denominator=len(group),
            )
        )
    return tuple(sorted(aggregates, key=lambda aggregate: aggregate.partition_id))


def project_pareto_front(
    task: TaskSpec,
    entries: Sequence[LeaderboardEntry],
) -> tuple[LeaderboardEntry, ...]:
    """Derive the eligible nondominated entries within one exact partition."""

    _require_sealed_leaderboard_task(task)
    if not entries:
        raise ProjectionUnavailable("a Pareto front requires leaderboard entries")
    partition_ids = {entry.partition_id for entry in entries}
    if len(partition_ids) != 1:
        raise ProjectionUnavailable("a Pareto front cannot cross leaderboard partitions")
    run_ids = {entry.run_id for entry in entries}
    if len(run_ids) != len(entries):
        raise ProjectionUnavailable("a Pareto front cannot contain a run twice")
    partition = entries[0].partition
    if task.digest != partition.task_spec_digest:
        raise ProjectionUnavailable("the Pareto task does not match the leaderboard partition")
    if task.evaluation.scorer is not None or partition.scorer_revision_digest is not None:
        raise ProjectionUnavailable("Pareto fronts require raw-vector scoring")
    if not any(
        measurement.direction is not MetricDirection.NONE for measurement in task.measurements
    ):
        raise ProjectionUnavailable("Pareto fronts require at least one objective")

    eligible: list[tuple[LeaderboardEntry, ParetoVectorScore]] = []
    for entry in entries:
        if not entry.rank_eligible:
            continue
        score = entry.score
        if not isinstance(score, ParetoVectorScore):
            raise ProjectionUnavailable("eligible Pareto entries require raw-vector scores")
        try:
            pareto_dominates(task, score, score)
        except ValueError as error:
            raise ProjectionUnavailable(
                "Pareto entry differs from the task measurement schema"
            ) from error
        eligible.append((entry, score))
    return tuple(
        sorted(
            (
                entry
                for index, (entry, score) in enumerate(eligible)
                if not any(
                    index != other_index and pareto_dominates(task, other_score, score)
                    for other_index, (_, other_score) in enumerate(eligible)
                )
            ),
            key=lambda entry: entry.run_id,
        )
    )


def _require_sealed_leaderboard_task(task: TaskSpec) -> None:
    if not isinstance(task.identity.origin, NativeSealedTaskOrigin):
        raise ProjectionUnavailable(
            "public calibration tasks are not eligible for the sealed leaderboard"
        )


def _required_provenance(evidence: MeasurementEvidence) -> MeasurementProvenance:
    provenance = evidence.provenance
    if provenance is None:
        raise ProjectionUnavailable("leaderboard measurements require persisted provenance")
    return provenance


def _required_public_provenance(
    evidence: MeasurementEvidence,
    public_measurement_artifacts: dict[str, ArtifactRecord],
) -> MeasurementProvenance:
    provenance = _required_provenance(evidence)
    source = public_measurement_artifacts.get(provenance.source_artifact_id)
    if (
        source is None
        or source.blob.digest != provenance.source_digest
        or source.media_type != SANITIZED_MEASUREMENTS_MEDIA_TYPE
    ):
        raise ProjectionUnavailable(
            "leaderboard measurement provenance is not a public sanitized artifact"
        )
    return provenance


def _leaderboard_measurement(
    *,
    candidate_id: str,
    stage_id: str,
    evidence: MeasurementEvidence,
    direction: MetricDirection,
    public_measurement_artifacts: dict[str, ArtifactRecord],
) -> LeaderboardMeasurement:
    provenance = _required_public_provenance(evidence, public_measurement_artifacts)
    return LeaderboardMeasurement(
        candidate_id=candidate_id,
        stage_id=stage_id,
        measurement_id=evidence.measurement_id,
        unit=provenance.unit,
        sample_seeds=provenance.sample_seeds,
        source_artifact_id=provenance.source_artifact_id,
        source_digest=provenance.source_digest,
        direction=direction,
        samples=tuple(str(sample) for sample in evidence.samples),
    )


def _require_session(snapshot: ProjectionSnapshot, session: SessionSpec) -> None:
    if session.digest != snapshot.header.binding.session.session_spec_digest:
        raise ProjectionUnavailable("projection session does not match the run binding")


def _leaderboard_actor(
    actor: HumanRunActor | HarnessRunActor,
) -> LeaderboardActor:
    if isinstance(actor, HumanRunActor):
        return LeaderboardHumanActor(
            actor_id=actor.actor_id,
            adapter_digest=actor.adapter_digest,
        )
    return LeaderboardHarnessActor(
        actor_id=actor.actor_id,
        requested_model_route=actor.requested_model_route,
        harness_digest=actor.harness_digest,
        scaffold_digest=actor.scaffold_digest,
    )
