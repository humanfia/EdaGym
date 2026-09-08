"""Journal-backed single-writer participant coordination."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError

from edagym.evaluation.model import ScorerEligibilityKind
from edagym.participants.adapters import (
    ParticipantAdapter,
    ParticipantAdapterError,
    ParticipantFailureKind,
    _participant_admissions,
    _selected_human_adapter,
)
from edagym.participants.admission import (
    CampaignParticipantAdmission,
    SyntheticPreflightParticipantAdmission,
)
from edagym.participants.execution import participant_dispatch_lock
from edagym.participants.model import (
    PARTICIPANT_EVENT_VISIBILITY,
    CandidateView,
    FinishTrainingIntent,
    InteractionIntent,
    MeasurementFeedback,
    ParticipantIntent,
    ParticipantView,
    ScoringFeedback,
    StageFeedback,
    SubmitCandidateIntent,
    TransferControlIntent,
)
from edagym.run.artifact_model import (
    ArtifactRecord,
)
from edagym.run.artifacts import ARTIFACT_MANIFEST_MEDIA_TYPE
from edagym.run.journal import InvalidTransition, RunJournal, replay
from edagym.run.model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    CandidateSubmittedEvent,
    CandidateSubmittedPayload,
    ControlTransferredEvent,
    ControlTransferredPayload,
    EvaluationCompletedEvent,
    HarnessRunActor,
    HumanRunActor,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    ProducerKind,
    RunEndedEvent,
    RunEndedPayload,
    RunEvent,
    RunPurpose,
    RunState,
    ScoringRecordedEvent,
    StopReason,
)
from edagym.specs.common import ArtifactClass, Digest, Visibility
from edagym.specs.session import FeedbackPolicy, HumanActor, SessionSpec, TrainingMode
from edagym.specs.task import TaskSpec


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """Trusted immutable candidate manifest prepared for atomic registration."""

    record: ArtifactRecord

    def __post_init__(self) -> None:
        if (
            self.record.artifact_class is not ArtifactClass.CANDIDATE
            or self.record.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE
        ):
            raise ValueError("candidate snapshot must register a candidate manifest")

    @property
    def digest(self) -> Digest:
        return self.record.blob.digest


type CandidateSnapshotter = Callable[[SubmitCandidateIntent], CandidateSnapshot]


class ParticipantController:
    """Append one intent, binding submissions through a trusted immutable snapshotter."""

    def __init__(
        self,
        journal: RunJournal,
        adapter: ParticipantAdapter,
        *,
        session: SessionSpec,
        snapshot_candidate: CandidateSnapshotter,
        event_id_factory: Callable[[], UUID] = uuid4,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if session.digest != journal.header.binding.session.session_spec_digest:
            raise ValueError("participant session does not match the run binding")
        bound_actor_kinds = frozenset(
            (actor.actor_id, actor.kind) for actor in journal.header.binding.session.actors
        )
        if frozenset(adapter.actor_kinds.items()) != bound_actor_kinds:
            raise ValueError("participant adapters must match every bound actor and kind")
        self._journal = journal
        self._adapter = adapter
        self._actor_ids = frozenset(actor_id for actor_id, _ in bound_actor_kinds)
        self._session = session
        self._snapshot_candidate = snapshot_candidate
        self._event_id_factory = event_id_factory
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)

    @property
    def run_id(self) -> Digest:
        return self._journal.header.run_id

    def act_once(self) -> RunState:
        with participant_dispatch_lock(self._journal.directory):
            events = self._journal.read_events()
            state = replay(self._journal.header, self._journal.task, events)
            if state.terminal_reason is not None:
                raise RuntimeError("a terminated run cannot accept participant actions")
            _validate_active_actor_admission(
                self._journal,
                self._adapter,
                self._session,
                state,
            )
            visible_events = tuple(
                event for event in events if event.visibility in PARTICIPANT_EVENT_VISIBILITY
            )
            candidate_ids: set[str] = set()
            visible_candidates_list: list[CandidateSubmittedEvent] = []
            for event in visible_events:
                if not isinstance(event, CandidateSubmittedEvent):
                    continue
                parent_id = event.payload.parent_candidate_id
                if parent_id is not None and parent_id not in candidate_ids:
                    continue
                candidate_ids.add(event.payload.candidate_id)
                visible_candidates_list.append(event)
            visible_candidates = tuple(visible_candidates_list)
            view = ParticipantView(
                run_id=state.run_id,
                task_family=self._journal.header.binding.task.family,
                authoring_revision=self._journal.header.binding.task.authoring_revision,
                actor_id=state.current_writer,
                candidates=tuple(
                    CandidateView(
                        candidate_id=event.payload.candidate_id,
                        parent_candidate_id=event.payload.parent_candidate_id,
                    )
                    for event in visible_candidates
                ),
                feedback=_participant_feedback(
                    events,
                    self._journal.task,
                    self._session.feedback,
                    frozenset(event.payload.candidate_id for event in visible_candidates),
                ),
                scoring=_participant_scoring_feedback(
                    events,
                    self._session.feedback,
                    frozenset(event.payload.candidate_id for event in visible_candidates),
                ),
            )
            intent = _invoke_adapter(self._adapter, view)
            failure = (
                intent
                if isinstance(intent, ParticipantFailureKind)
                else (
                    ParticipantFailureKind.INVALID_INTENT
                    if not isinstance(
                        intent,
                        (
                            InteractionIntent,
                            SubmitCandidateIntent,
                            FinishTrainingIntent,
                            TransferControlIntent,
                        ),
                    )
                    else None
                )
            )
            candidate_snapshot: CandidateSnapshot | None = None
            if (
                failure is None
                and isinstance(
                    intent,
                    (
                        InteractionIntent,
                        SubmitCandidateIntent,
                        FinishTrainingIntent,
                        TransferControlIntent,
                    ),
                )
                and not _intent_preconditions_hold(
                    intent,
                    state,
                    self._actor_ids,
                    selection_enabled=isinstance(self._session.mode, TrainingMode),
                )
            ):
                failure = ParticipantFailureKind.INVALID_INTENT
            if failure is None and isinstance(intent, SubmitCandidateIntent):
                snapshot = _snapshot_candidate(self._snapshot_candidate, intent)
                if isinstance(snapshot, ParticipantFailureKind):
                    failure = snapshot
                else:
                    candidate_snapshot = snapshot
            if failure is not None:
                del candidate_snapshot, candidate_ids, events, intent, state, view
                del visible_candidates, visible_candidates_list, visible_events
                raise ParticipantAdapterError(failure) from None
            if not isinstance(
                intent,
                (
                    InteractionIntent,
                    SubmitCandidateIntent,
                    FinishTrainingIntent,
                    TransferControlIntent,
                ),
            ):
                raise TypeError("participant failure classification is incomplete")
            expected_writer = state.current_writer
            del candidate_ids, events, state, view
            del visible_candidates, visible_candidates_list, visible_events

            def commit(current: RunState) -> tuple[RunEvent, ...]:
                if current.current_writer != expected_writer:
                    raise RuntimeError("participant writer changed during dispatch")
                return self._events(intent, current, candidate_snapshot)

            committed = _commit_intent(self._journal, commit)
            if isinstance(committed, ParticipantFailureKind):
                del candidate_snapshot, commit, expected_writer, intent
                raise ParticipantAdapterError(committed) from None
            return committed

    def _events(
        self,
        intent: ParticipantIntent,
        state: RunState,
        candidate_snapshot: CandidateSnapshot | None,
    ) -> tuple[RunEvent, ...]:
        event_id = self._event_id_factory()
        timestamp = self._clock()
        if isinstance(intent, InteractionIntent):
            return (
                InteractionRecordedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.PARTICIPANT,
                    actor=state.current_writer,
                    visibility=Visibility.PARTICIPANT,
                    artifact_refs=intent.artifact_refs,
                    payload=InteractionRecordedPayload(
                        direction=intent.direction,
                        interaction_id=intent.interaction_id,
                    ),
                ),
            )
        if isinstance(intent, SubmitCandidateIntent):
            if candidate_snapshot is None:
                raise RuntimeError("candidate submission requires an immutable snapshot")
            record = candidate_snapshot.record
            return (
                ArtifactRecordedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=record.visibility,
                    payload=ArtifactRecordedPayload(record=record),
                ),
                CandidateSubmittedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence + 1,
                    event_id=self._event_id_factory(),
                    timestamp=timestamp,
                    producer=ProducerKind.PARTICIPANT,
                    actor=state.current_writer,
                    visibility=Visibility.PARTICIPANT,
                    payload=CandidateSubmittedPayload(
                        candidate_id=intent.candidate_id,
                        candidate_digest=candidate_snapshot.digest,
                        parent_candidate_id=intent.parent_candidate_id,
                    ),
                ),
            )
        if isinstance(intent, FinishTrainingIntent):
            return (
                RunEndedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.PARTICIPANT,
                    actor=state.current_writer,
                    visibility=Visibility.PUBLIC,
                    payload=RunEndedPayload(
                        reason=StopReason.VERIFIER_SUCCESS,
                        successful_candidate_id=intent.candidate_id,
                    ),
                ),
            )
        if isinstance(intent, TransferControlIntent):
            return (
                ControlTransferredEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.PARTICIPANT,
                    actor=state.current_writer,
                    visibility=Visibility.PARTICIPANT,
                    payload=ControlTransferredPayload(
                        previous_writer=state.current_writer,
                        next_writer=intent.next_writer,
                    ),
                ),
            )
        raise TypeError("participant intent has no journal event mapping")


def _validate_active_actor_admission(
    journal: RunJournal,
    adapter: ParticipantAdapter,
    session: SessionSpec,
    state: RunState,
) -> None:
    try:
        admission = getattr(adapter, "campaign_admission", None)
        preflight_admission = getattr(adapter, "synthetic_preflight_admission", None)
    except Exception:
        raise ValueError("participant admission is unavailable") from None
    binding = journal.header.binding
    if binding.purpose is RunPurpose.STANDARD:
        if _participant_admissions(adapter):
            raise ValueError("ordinary runs cannot carry participant admission")
        return
    if binding.purpose is RunPurpose.CAMPAIGN_TRIAL:
        run_actor = next(
            (actor for actor in binding.session.actors if actor.actor_id == state.current_writer),
            None,
        )
        if isinstance(run_actor, HumanRunActor):
            selected = _selected_human_adapter(adapter, state.current_writer)
            session_actor = next(
                (actor for actor in session.actors if actor.actor_id == state.current_writer),
                None,
            )
            if (
                _participant_admissions(adapter)
                or selected is None
                or not isinstance(session_actor, HumanActor)
                or selected.adapter_digest != run_actor.adapter_digest
                or selected.adapter_digest != session_actor.adapter_digest
            ):
                raise ValueError(
                    "campaign human turns require the exact provider-free human adapter"
                )
            return
        if (
            not isinstance(run_actor, HarnessRunActor)
            or preflight_admission is not None
            or type(admission) is not CampaignParticipantAdmission
            or admission.actor_id != state.current_writer
            or not admission.matches_run(binding, session)
        ):
            raise ValueError("campaign runs require exact participant admission")
        return
    if (
        admission is not None
        or type(preflight_admission) is not SyntheticPreflightParticipantAdmission
        or not preflight_admission.matches_run(binding, session)
    ):
        raise ValueError("synthetic preflight requires exact provider-free admission")


def _invoke_adapter(
    adapter: ParticipantAdapter,
    view: ParticipantView,
) -> object:
    try:
        return adapter.next_intent(view)
    except ParticipantAdapterError as error:
        return error.kind
    except Exception:
        return ParticipantFailureKind.CHANNEL_FAILURE


def _snapshot_candidate(
    snapshot_candidate: CandidateSnapshotter,
    intent: SubmitCandidateIntent,
) -> CandidateSnapshot | ParticipantFailureKind:
    try:
        value = snapshot_candidate(intent)
    except Exception:
        return ParticipantFailureKind.CANDIDATE_SNAPSHOT
    if not isinstance(value, CandidateSnapshot):
        return ParticipantFailureKind.CANDIDATE_SNAPSHOT
    return value


def _intent_preconditions_hold(
    intent: ParticipantIntent,
    state: RunState,
    actor_ids: frozenset[str],
    *,
    selection_enabled: bool,
) -> bool:
    if isinstance(intent, InteractionIntent):
        return intent.interaction_id not in state.interaction_ids
    if isinstance(intent, SubmitCandidateIntent):
        candidate_ids = {candidate.candidate_id for candidate in state.candidates}
        return intent.candidate_id not in candidate_ids and (
            intent.parent_candidate_id is None or intent.parent_candidate_id in candidate_ids
        )
    if isinstance(intent, FinishTrainingIntent):
        return selection_enabled and any(
            scoring.candidate_id == intent.candidate_id
            and scoring.decision.eligibility.state
            in {
                ScorerEligibilityKind.READY,
                ScorerEligibilityKind.NOT_CONFIGURED,
            }
            for scoring in state.scoring
        )
    if isinstance(intent, TransferControlIntent):
        return intent.next_writer != state.current_writer and intent.next_writer in actor_ids
    return False


def _commit_intent(
    journal: RunJournal,
    factory: Callable[[RunState], tuple[RunEvent, ...]],
) -> RunState | ParticipantFailureKind:
    try:
        return journal.transact_events(factory)
    except (InvalidTransition, ValidationError):
        return ParticipantFailureKind.INVALID_INTENT


def _participant_feedback(
    events: tuple[RunEvent, ...],
    task: TaskSpec,
    policy: FeedbackPolicy,
    visible_candidate_ids: frozenset[str],
) -> tuple[StageFeedback, ...]:
    if policy is FeedbackPolicy.NONE:
        return ()
    measurement_schema = {
        measurement.measurement_id: measurement for measurement in task.measurements
    }
    expose_metrics = policy is FeedbackPolicy.METRICS
    return tuple(
        StageFeedback(
            candidate_id=event.payload.candidate_id,
            stage_id=event.payload.result.stage_id,
            outcome=event.payload.result.outcome.kind,
            measurements=(
                tuple(
                    MeasurementFeedback(
                        measurement_id=evidence.measurement_id,
                        unit=measurement_schema[evidence.measurement_id].unit,
                        samples=tuple(str(sample) for sample in evidence.samples),
                    )
                    for evidence in event.payload.result.measurements
                )
                if expose_metrics
                else ()
            ),
        )
        for event in events
        if isinstance(event, EvaluationCompletedEvent)
        and event.visibility in PARTICIPANT_EVENT_VISIBILITY
        and event.payload.candidate_id in visible_candidate_ids
    )


def _participant_scoring_feedback(
    events: tuple[RunEvent, ...],
    policy: FeedbackPolicy,
    visible_candidate_ids: frozenset[str],
) -> tuple[ScoringFeedback, ...]:
    if policy is not FeedbackPolicy.METRICS:
        return ()
    return tuple(
        ScoringFeedback(
            candidate_id=event.payload.candidate_id,
            decision=event.payload.decision,
        )
        for event in events
        if isinstance(event, ScoringRecordedEvent)
        and event.visibility in PARTICIPANT_EVENT_VISIBILITY
        and event.payload.candidate_id in visible_candidate_ids
    )
