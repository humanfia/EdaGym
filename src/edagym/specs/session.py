"""Canonical participant, control, feedback, and budget specification."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, Identifier, StrictModel

PositiveInt = Annotated[int, Field(strict=True, ge=1)]
NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
ModelRoute = Annotated[
    str,
    Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$",
    ),
]


class ModeKind(StrEnum):
    BENCHMARK = "benchmark"
    TRAINING = "training"
    COURSE = "course"


class ActorKind(StrEnum):
    HUMAN = "human"
    HARNESS = "harness"


class CandidateAuthority(StrEnum):
    """Authority whose bytes may enter evaluator execution."""

    PARTICIPANT = "participant"
    TASK_AUTHOR = "task_author"


class WriterPolicy(StrEnum):
    FIXED = "fixed"
    HANDOFF = "handoff"


class FeedbackPolicy(StrEnum):
    NONE = "none"
    STAGE = "stage"
    SAFE_DIAGNOSTIC = "safe_diagnostic"
    METRICS = "metrics"
    COURSE = "course"


class RecoveryPolicy(StrEnum):
    NONE = "none"
    BEST_EFFORT = "best_effort"
    REQUIRED = "required"


class OralDefensePolicy(StrEnum):
    DISABLED = "disabled"
    OPTIONAL = "optional"
    REQUIRED = "required"


class BenchmarkMode(StrictModel):
    """Independent trials that each start from an immutable task release."""

    kind: Literal[ModeKind.BENCHMARK] = ModeKind.BENCHMARK
    trial_count: PositiveInt = 1


class TrainingMode(StrictModel):
    """A stateful optimization session with visible evaluator feedback."""

    kind: Literal[ModeKind.TRAINING] = ModeKind.TRAINING


class CourseMode(StrictModel):
    """A human-attributed instructional session governed by a frozen rubric."""

    kind: Literal[ModeKind.COURSE] = ModeKind.COURSE
    rubric_digest: Digest
    oral_defense: OralDefensePolicy = OralDefensePolicy.DISABLED


SessionMode = Annotated[
    BenchmarkMode | TrainingMode | CourseMode,
    Field(discriminator="kind"),
]


class HumanActor(StrictModel):
    kind: Literal[ActorKind.HUMAN] = ActorKind.HUMAN
    actor_id: Identifier
    adapter_id: Identifier
    adapter_digest: Digest


class HarnessActor(StrictModel):
    kind: Literal[ActorKind.HARNESS] = ActorKind.HARNESS
    actor_id: Identifier
    harness_id: Identifier
    harness_digest: Digest
    scaffold_digest: Digest
    requested_model_route: ModelRoute


ActorSpec = Annotated[
    HumanActor | HarnessActor,
    Field(discriminator="kind"),
]


class FixedWriter(StrictModel):
    """Permanent single-writer ownership for a one-actor session."""

    policy: Literal[WriterPolicy.FIXED] = WriterPolicy.FIXED
    writer: Identifier


class HandoffWriter(StrictModel):
    """A single-writer lease whose owner may change through journaled handoffs."""

    policy: Literal[WriterPolicy.HANDOFF] = WriterPolicy.HANDOFF
    initial_writer: Identifier


WriterControl = Annotated[
    FixedWriter | HandoffWriter,
    Field(discriminator="policy"),
]


class ResourceBudget(StrictModel):
    max_turns: PositiveInt
    max_tool_calls: PositiveInt
    max_experiments: PositiveInt
    max_wall_seconds: PositiveInt
    max_eda_compute_seconds: PositiveInt
    max_license_seconds: NonNegativeInt
    max_artifact_bytes: PositiveInt


class ModelBudget(StrictModel):
    max_requests: PositiveInt
    max_input_tokens_per_request: PositiveInt
    max_output_tokens_per_request: PositiveInt
    max_total_input_tokens: PositiveInt
    max_total_output_tokens: PositiveInt
    max_total_tokens: PositiveInt

    @model_validator(mode="after")
    def validate_token_limits(self) -> Self:
        if self.max_total_input_tokens < self.max_input_tokens_per_request:
            raise ValueError("total input tokens must admit one maximum-size request")
        if self.max_total_output_tokens < self.max_output_tokens_per_request:
            raise ValueError("total output tokens must admit one maximum-size response")
        if self.max_total_tokens < (
            self.max_input_tokens_per_request + self.max_output_tokens_per_request
        ):
            raise ValueError("total tokens must admit one maximum-size exchange")
        if self.max_total_tokens > (
            self.max_total_input_tokens + self.max_total_output_tokens
        ):
            raise ValueError("total tokens cannot exceed the directional token limits")
        return self


class SessionSpec(StrictModel):
    schema_version: Literal[1] = 1
    session_id: Identifier
    mode: SessionMode
    actors: Annotated[tuple[ActorSpec, ...], Field(min_length=1)]
    writer: WriterControl
    candidate_authority: CandidateAuthority = CandidateAuthority.PARTICIPANT
    author_candidate_digest: Digest | None = None
    feedback: FeedbackPolicy
    recovery: RecoveryPolicy
    resources: ResourceBudget
    model_budget: ModelBudget | None = None

    @field_validator("schema_version", mode="before")
    @classmethod
    def require_integer_schema_version(cls, version: object) -> object:
        if type(version) is not int:
            raise ValueError("schema_version must be an integer")
        return version

    @field_validator("actors")
    @classmethod
    def normalize_actors(cls, actors: tuple[ActorSpec, ...]) -> tuple[ActorSpec, ...]:
        actor_ids = [actor.actor_id for actor in actors]
        if len(actor_ids) != len(set(actor_ids)):
            raise ValueError("actor identifiers must be unique")
        return tuple(sorted(actors, key=lambda actor: actor.actor_id))

    @model_validator(mode="after")
    def validate_session_policy(self) -> Self:
        if (self.candidate_authority is CandidateAuthority.TASK_AUTHOR) != (
            self.author_candidate_digest is not None
        ):
            raise ValueError("task-author sessions require exactly one canonical candidate digest")
        actor_ids = {actor.actor_id for actor in self.actors}
        writer_id = (
            self.writer.writer
            if isinstance(self.writer, FixedWriter)
            else self.writer.initial_writer
        )
        if writer_id not in actor_ids:
            raise ValueError("writer must reference a declared actor")
        if len(self.actors) == 1 and not isinstance(self.writer, FixedWriter):
            raise ValueError("a one-actor session requires fixed writer control")
        if len(self.actors) > 1 and not isinstance(self.writer, HandoffWriter):
            raise ValueError("a multi-actor session requires single-writer handoff control")

        has_harness = any(isinstance(actor, HarnessActor) for actor in self.actors)
        if has_harness != (self.model_budget is not None):
            raise ValueError("model_budget is required if and only if a harness is present")
        if self.candidate_authority is CandidateAuthority.TASK_AUTHOR and (
            not isinstance(self.mode, BenchmarkMode) or has_harness
        ):
            raise ValueError("task-author candidates are limited to human benchmark calibration")

        if isinstance(self.mode, BenchmarkMode):
            if self.recovery is not RecoveryPolicy.NONE:
                raise ValueError("benchmark trials cannot recover or share prior state")
            if self.feedback in {FeedbackPolicy.METRICS, FeedbackPolicy.COURSE}:
                raise ValueError("benchmark feedback cannot expose metrics or course evidence")
        elif isinstance(self.mode, TrainingMode):
            if self.recovery is not RecoveryPolicy.REQUIRED:
                raise ValueError("training sessions require recoverable state")
            if self.feedback not in {
                FeedbackPolicy.STAGE,
                FeedbackPolicy.SAFE_DIAGNOSTIC,
                FeedbackPolicy.METRICS,
            }:
                raise ValueError("training sessions require visible non-course feedback")
        else:
            if not any(isinstance(actor, HumanActor) for actor in self.actors):
                raise ValueError("course sessions require at least one human actor")
            if self.feedback is not FeedbackPolicy.COURSE:
                raise ValueError("course sessions require course feedback")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="session-spec-v1")
