"""Strict output models for supported ecosystem projections."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.evaluation.model import CandidateScore, OutcomeKind, ScorerEligibilityKind
from edagym.run.model import (
    EventKind,
    InteractionDirection,
    RunLineage,
    StopReason,
)
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    Seed128Hex,
    StrictModel,
)
from edagym.specs.session import ActorKind, ModelRoute, OralDefensePolicy
from edagym.specs.task import MeasurementUnit, MetricDirection


class AtifSource(StrEnum):
    SYSTEM = "system"
    USER = "user"
    AGENT = "agent"


class AtifAgent(StrictModel):
    name: Annotated[str, Field(min_length=1)]
    version: Annotated[str, Field(min_length=1)]
    model_name: Annotated[str, Field(min_length=1)] | None = None


class AtifInteractionExtra(StrictModel):
    event_kind: Literal[EventKind.INTERACTION_RECORDED] = EventKind.INTERACTION_RECORDED
    event_id: str
    actor_id: Identifier | None = None
    interaction_id: Identifier
    direction: InteractionDirection
    related_interaction_id: Identifier | None = None
    tool_name: Identifier | None = None
    public_artifact_refs: tuple[Identifier, ...] = ()


class AtifRunStartedExtra(StrictModel):
    event_kind: Literal[EventKind.RUN_STARTED] = EventKind.RUN_STARTED
    event_id: str


class AtifControlTransferExtra(StrictModel):
    event_kind: Literal[EventKind.CONTROL_TRANSFERRED] = EventKind.CONTROL_TRANSFERRED
    event_id: str
    actor_id: Identifier
    previous_writer: Identifier
    next_writer: Identifier


class AtifCandidateExtra(StrictModel):
    event_kind: Literal[EventKind.CANDIDATE_SUBMITTED] = EventKind.CANDIDATE_SUBMITTED
    event_id: str
    actor_id: Identifier
    candidate_id: Identifier
    parent_candidate_id: Identifier | None = None


class AtifCheckpointExtra(StrictModel):
    event_kind: Literal[EventKind.CHECKPOINT_COMMITTED] = EventKind.CHECKPOINT_COMMITTED
    event_id: str
    checkpoint_id: Identifier
    parent_checkpoint_id: Identifier | None = None


class AtifRunEndedExtra(StrictModel):
    event_kind: Literal[EventKind.RUN_ENDED] = EventKind.RUN_ENDED
    event_id: str
    reason: StopReason
    successful_candidate_id: Identifier | None = None


AtifStepExtra = Annotated[
    AtifRunStartedExtra
    | AtifInteractionExtra
    | AtifControlTransferExtra
    | AtifCandidateExtra
    | AtifCheckpointExtra
    | AtifRunEndedExtra,
    Field(discriminator="event_kind"),
]


class AtifStep(StrictModel):
    step_id: Annotated[int, Field(strict=True, ge=1)]
    timestamp: str
    source: AtifSource
    model_name: Annotated[str, Field(min_length=1)] | None = None
    message: Literal[""] = ""
    extra: AtifStepExtra

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError("ATIF timestamps must be ISO 8601") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("ATIF timestamps must include a time zone")
        return value

    @model_validator(mode="after")
    def validate_agent_fields(self) -> Self:
        if self.source is not AtifSource.AGENT and self.model_name is not None:
            raise ValueError("only ATIF agent steps may name a model")
        return self


class AtifFinalMetrics(StrictModel):
    total_steps: Annotated[int, Field(strict=True, ge=1)]


class AtifRequestedModelRoute(StrictModel):
    actor_id: Identifier
    route: ModelRoute


class AtifRunExtra(StrictModel):
    content_policy: Literal["references_only"] = "references_only"
    task_family: Identifier
    authoring_revision: Annotated[int, Field(strict=True, ge=1)]
    task_spec_digest: Digest
    instance_digest: Digest
    release_digest: Digest
    environment_spec_digest: Digest
    session_spec_digest: Digest
    requested_model_routes: tuple[AtifRequestedModelRoute, ...] = ()

    @field_validator("requested_model_routes")
    @classmethod
    def normalize_requested_model_routes(
        cls,
        value: tuple[AtifRequestedModelRoute, ...],
    ) -> tuple[AtifRequestedModelRoute, ...]:
        actor_ids = [route.actor_id for route in value]
        if len(actor_ids) != len(set(actor_ids)):
            raise ValueError("ATIF requested model routes must have unique actors")
        return tuple(sorted(value, key=lambda route: route.actor_id))


class AtifTrajectory(StrictModel):
    schema_version: Literal["ATIF-v1.8"] = "ATIF-v1.8"
    session_id: Digest
    trajectory_id: Digest
    agent: AtifAgent
    steps: Annotated[tuple[AtifStep, ...], Field(min_length=1)]
    notes: Literal["Raw interaction content is not included in this projection."] = (
        "Raw interaction content is not included in this projection."
    )
    final_metrics: AtifFinalMetrics
    extra: AtifRunExtra

    @field_validator("steps")
    @classmethod
    def validate_step_ids(cls, value: tuple[AtifStep, ...]) -> tuple[AtifStep, ...]:
        if tuple(step.step_id for step in value) != tuple(range(1, len(value) + 1)):
            raise ValueError("ATIF step identifiers must be contiguous and one-based")
        return value

    @model_validator(mode="after")
    def validate_total_steps(self) -> Self:
        if self.final_metrics.total_steps != len(self.steps):
            raise ValueError("ATIF total_steps must equal the trajectory step count")
        return self


class HarborReward(StrictModel):
    reward: Literal[0, 1]


class HarborTrialProjection(StrictModel):
    """Documents to materialize as trajectory.json and reward.json."""

    trajectory: AtifTrajectory
    reward: HarborReward

    @model_validator(mode="after")
    def validate_terminal_reward(self) -> Self:
        final_event = self.trajectory.steps[-1].extra
        if not isinstance(final_event, AtifRunEndedExtra):
            raise ValueError("Harbor trajectories must end with a run-ended step")
        expected_reward = 1 if final_event.reason is StopReason.VERIFIER_SUCCESS else 0
        if self.reward.reward != expected_reward:
            raise ValueError("Harbor reward must match the terminal run outcome")
        return self


class NemoInputMessage(StrictModel):
    role: Literal["user"] = "user"
    content: Annotated[str, Field(min_length=1)]


class NemoResponsesCreateParams(StrictModel):
    input: Annotated[tuple[NemoInputMessage, ...], Field(min_length=1)]


class NemoDatasetProjection(StrictModel):
    """A pre-collation NeMo Gym dataset row, not a completed rollout."""

    responses_create_params: NemoResponsesCreateParams
    id: Digest


class ParticipationKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    HYBRID = "hybrid"


class ActorCourseEvidence(StrictModel):
    actor_id: Identifier
    kind: ActorKind
    interaction_count: Annotated[int, Field(strict=True, ge=0)]
    candidate_count: Annotated[int, Field(strict=True, ge=0)]
    handoffs_given: Annotated[int, Field(strict=True, ge=0)]
    handoffs_received: Annotated[int, Field(strict=True, ge=0)]


class CandidateCourseEvidence(StrictModel):
    candidate_id: Identifier
    actor_id: Identifier
    parent_candidate_id: Identifier | None = None
    stage_outcomes: tuple[tuple[Identifier, OutcomeKind], ...] = ()


class ArtifactClassCount(StrictModel):
    artifact_class: ArtifactClass
    count: Annotated[int, Field(strict=True, ge=0)]


class CourseReport(StrictModel):
    run_id: Digest
    task_family: Identifier
    authoring_revision: Annotated[int, Field(strict=True, ge=1)]
    task_spec_digest: Digest
    instance_digest: Digest
    release_digest: Digest
    environment_spec_digest: Digest
    session_spec_digest: Digest
    rubric_digest: Digest
    oral_defense: OralDefensePolicy
    participation: ParticipationKind
    actors: tuple[ActorCourseEvidence, ...]
    candidates: tuple[CandidateCourseEvidence, ...]
    handoff_count: Annotated[int, Field(strict=True, ge=0)]
    checkpoint_count: Annotated[int, Field(strict=True, ge=0)]
    artifact_counts: tuple[ArtifactClassCount, ...]
    terminal_reason: StopReason | None = None
    successful_candidate_id: Identifier | None = None


class LeaderboardStageOutcome(StrictModel):
    candidate_id: Identifier
    stage_id: Identifier
    outcome: OutcomeKind


class LeaderboardEvaluator(StrictModel):
    evaluator_id: Identifier
    revision_digest: Digest


class LeaderboardHumanActor(StrictModel):
    kind: Literal[ActorKind.HUMAN] = ActorKind.HUMAN
    actor_id: Identifier
    adapter_digest: Digest


class LeaderboardHarnessActor(StrictModel):
    kind: Literal[ActorKind.HARNESS] = ActorKind.HARNESS
    actor_id: Identifier
    requested_model_route: ModelRoute
    harness_digest: Digest
    scaffold_digest: Digest


LeaderboardActor = Annotated[
    LeaderboardHumanActor | LeaderboardHarnessActor,
    Field(discriminator="kind"),
]


class LeaderboardCohort(StrictModel):
    actors: Annotated[tuple[LeaderboardActor, ...], Field(min_length=1)]
    initial_writer: Identifier
    handoff_enabled: bool
    participation: ParticipationKind

    @field_validator("actors")
    @classmethod
    def normalize_actors(
        cls,
        value: tuple[LeaderboardActor, ...],
    ) -> tuple[LeaderboardActor, ...]:
        actor_ids = [actor.actor_id for actor in value]
        if len(actor_ids) != len(set(actor_ids)):
            raise ValueError("leaderboard actor identifiers must be unique")
        return tuple(sorted(value, key=lambda actor: actor.actor_id))

    @model_validator(mode="after")
    def validate_control_and_participation(self) -> Self:
        actor_ids = {actor.actor_id for actor in self.actors}
        if self.initial_writer not in actor_ids:
            raise ValueError("leaderboard initial writer must name an actor")
        if self.handoff_enabled != (len(actor_ids) > 1):
            raise ValueError("leaderboard handoff must match its actor count")
        has_human = any(isinstance(actor, LeaderboardHumanActor) for actor in self.actors)
        has_harness = any(isinstance(actor, LeaderboardHarnessActor) for actor in self.actors)
        if has_human:
            expected = ParticipationKind.HYBRID if has_harness else ParticipationKind.HUMAN
        else:
            expected = ParticipationKind.AGENT
        if self.participation is not expected:
            raise ValueError("leaderboard participation does not match its actors")
        return self


class LeaderboardMeasurement(StrictModel):
    candidate_id: Identifier
    stage_id: Identifier
    measurement_id: Identifier
    unit: MeasurementUnit
    sample_seeds: tuple[Seed128Hex, ...]
    source_artifact_id: Identifier
    source_digest: Digest
    direction: MetricDirection
    samples: tuple[str, ...]


class LeaderboardPartition(StrictModel):
    task_family: Identifier
    authoring_revision: Annotated[int, Field(strict=True, ge=1)]
    task_spec_digest: Digest
    instance_digest: Digest
    release_digest: Digest
    environment_spec_digest: Digest
    cohort: LeaderboardCohort
    feedback_policy_digest: Digest
    budget_digest: Digest
    evaluators: tuple[LeaderboardEvaluator, ...]
    measurement_schema_digest: Digest
    scorer_revision_digest: Digest | None = None
    trial_count: Annotated[int, Field(strict=True, ge=1)]

    @field_validator("evaluators")
    @classmethod
    def normalize_evaluators(
        cls,
        value: tuple[LeaderboardEvaluator, ...],
    ) -> tuple[LeaderboardEvaluator, ...]:
        evaluator_ids = [evaluator.evaluator_id for evaluator in value]
        if not evaluator_ids or len(evaluator_ids) != len(set(evaluator_ids)):
            raise ValueError("leaderboard evaluators must be unique")
        return tuple(sorted(value, key=lambda evaluator: evaluator.evaluator_id))

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="leaderboard-partition-v1")


class LeaderboardEntry(StrictModel):
    partition_id: Digest
    partition: LeaderboardPartition
    run_id: Digest
    lineage: RunLineage
    rank_eligible: bool
    success: bool
    terminal_reason: StopReason
    human_intervention_count: Annotated[int, Field(strict=True, ge=0)]
    stage_outcomes: tuple[LeaderboardStageOutcome, ...]
    measurements: tuple[LeaderboardMeasurement, ...]
    scoring_eligibility: ScorerEligibilityKind | None = None
    score: CandidateScore | None = None

    @model_validator(mode="after")
    def validate_eligibility_and_success(self) -> Self:
        if self.partition_id != self.partition.digest:
            raise ValueError("leaderboard partition identifier does not match its facts")
        expected_eligibility = (
            self.partition.cohort.participation is ParticipationKind.AGENT
            and self.lineage.parent_run_id is None
            and self.terminal_reason is StopReason.VERIFIER_SUCCESS
            and self.scoring_eligibility is ScorerEligibilityKind.READY
        )
        if self.rank_eligible != expected_eligibility:
            raise ValueError("leaderboard eligibility does not match the run facts")
        if self.success != (self.terminal_reason is StopReason.VERIFIER_SUCCESS):
            raise ValueError("leaderboard success must match the terminal reason")
        if self.score is not None and not self.success:
            raise ValueError("leaderboard scores require verifier success")
        if (self.scoring_eligibility is ScorerEligibilityKind.READY) != (
            self.score is not None
        ):
            raise ValueError("leaderboard score must match its scoring eligibility")
        return self


class LeaderboardAggregate(StrictModel):
    partition_id: Digest
    partition: LeaderboardPartition
    rank_eligible: bool
    run_ids: tuple[Digest, ...]
    success_numerator: Annotated[int, Field(strict=True, ge=0)]
    success_denominator: Annotated[int, Field(strict=True, ge=1)]

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.partition_id != self.partition.digest:
            raise ValueError("leaderboard partition identifier does not match its facts")
        if not self.run_ids or len(self.run_ids) != len(set(self.run_ids)):
            raise ValueError("leaderboard aggregates require unique run identifiers")
        if self.success_denominator != len(self.run_ids):
            raise ValueError("leaderboard denominator must equal its run count")
        if self.success_numerator > self.success_denominator:
            raise ValueError("leaderboard successes cannot exceed its run count")
        if (
            self.rank_eligible
            and self.partition.cohort.participation is not ParticipationKind.AGENT
        ):
            raise ValueError("only agent-only aggregates may be rank eligible")
        return self
