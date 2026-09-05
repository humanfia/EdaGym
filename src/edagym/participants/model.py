"""Typed participant views and intents at the controller boundary."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, field_validator

from edagym.evaluation.model import OutcomeKind, ScoringDecision
from edagym.run.model import InteractionDirection
from edagym.specs.common import Digest, Identifier, StrictModel, Visibility
from edagym.specs.task import MeasurementUnit

PARTICIPANT_EVENT_VISIBILITY = frozenset({Visibility.PUBLIC, Visibility.PARTICIPANT})


class ParticipantIntentKind(StrEnum):
    INTERACTION = "interaction"
    SUBMIT_CANDIDATE = "submit_candidate"
    FINISH_TRAINING = "finish_training"
    TRANSFER_CONTROL = "transfer_control"


class CandidateView(StrictModel):
    candidate_id: Identifier
    parent_candidate_id: Identifier | None = None


class MeasurementFeedback(StrictModel):
    measurement_id: Identifier
    unit: MeasurementUnit
    samples: tuple[str, ...]


class StageFeedback(StrictModel):
    candidate_id: Identifier
    stage_id: Identifier
    outcome: OutcomeKind
    measurements: tuple[MeasurementFeedback, ...] = ()


class ScoringFeedback(StrictModel):
    candidate_id: Identifier
    decision: ScoringDecision


class ParticipantView(StrictModel):
    """A journal-derived view containing only policy-approved structured feedback."""

    protocol_version: Literal[1] = 1
    run_id: Digest
    task_family: Identifier
    authoring_revision: Annotated[int, Field(strict=True, ge=1)]
    actor_id: Identifier
    candidates: tuple[CandidateView, ...] = ()
    feedback: tuple[StageFeedback, ...] = ()
    scoring: tuple[ScoringFeedback, ...] = ()

    @field_validator("candidates")
    @classmethod
    def normalize_candidates(cls, value: tuple[CandidateView, ...]) -> tuple[CandidateView, ...]:
        identifiers = [candidate.candidate_id for candidate in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("participant candidate identifiers must be unique")
        return tuple(sorted(value, key=lambda candidate: candidate.candidate_id))


class InteractionIntent(StrictModel):
    kind: Literal[ParticipantIntentKind.INTERACTION] = ParticipantIntentKind.INTERACTION
    interaction_id: Identifier
    direction: InteractionDirection
    artifact_refs: tuple[Identifier, ...] = ()

    @field_validator("artifact_refs")
    @classmethod
    def normalize_artifact_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("an interaction may reference each artifact only once")
        return tuple(sorted(value))

    @field_validator("direction")
    @classmethod
    def require_participant_direction(cls, value: InteractionDirection) -> InteractionDirection:
        if value not in {
            InteractionDirection.PARTICIPANT_OUTPUT,
            InteractionDirection.TOOL_REQUEST,
        }:
            raise ValueError("participant intents may only emit output or tool requests")
        return value


class SubmitCandidateIntent(StrictModel):
    kind: Literal[ParticipantIntentKind.SUBMIT_CANDIDATE] = ParticipantIntentKind.SUBMIT_CANDIDATE
    candidate_id: Identifier
    parent_candidate_id: Identifier | None = None


class FinishTrainingIntent(StrictModel):
    kind: Literal[ParticipantIntentKind.FINISH_TRAINING] = (
        ParticipantIntentKind.FINISH_TRAINING
    )
    candidate_id: Identifier


class TransferControlIntent(StrictModel):
    kind: Literal[ParticipantIntentKind.TRANSFER_CONTROL] = ParticipantIntentKind.TRANSFER_CONTROL
    next_writer: Identifier


ParticipantIntent = Annotated[
    InteractionIntent
    | SubmitCandidateIntent
    | FinishTrainingIntent
    | TransferControlIntent,
    Field(discriminator="kind"),
]

PARTICIPANT_INTENT_ADAPTER: TypeAdapter[ParticipantIntent] = TypeAdapter(ParticipantIntent)
