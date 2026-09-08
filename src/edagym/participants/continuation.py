"""Actor-scoped continuation of an admitted campaign harness."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from edagym.participants.adapters import (
    ParticipantAdapter,
    ParticipantAdapterError,
    ParticipantFailureKind,
)
from edagym.participants.admission import CampaignParticipantAdmission
from edagym.participants.execution import participant_dispatch_lock
from edagym.participants.model import ParticipantIntent, ParticipantView
from edagym.run.trial_journal import TrialJournal, replay
from edagym.run.trial_model import (
    ControlTransferredEvent,
    HarnessRunActor,
    HumanRunActor,
    RunPurpose,
    RunStartedEvent,
)
from edagym.specs.session import ActorKind, HarnessActor, HumanActor, SessionSpec


class AdmittedCampaignContinuationAdapter:
    """Expose one admitted harness after a journaled human-to-harness handoff."""

    def __init__(
        self,
        journal: TrialJournal,
        session: SessionSpec,
        harness_adapter: ParticipantAdapter,
    ) -> None:
        with participant_dispatch_lock(journal.directory):
            binding = journal.header.binding
            events = journal.read_events()
            state = replay(journal.header, journal.task, events)
            try:
                admission = harness_adapter.campaign_admission
                harness_kinds = dict(harness_adapter.actor_kinds)
            except Exception:
                raise ValueError("campaign harness admission is unavailable") from None
            if (
                binding.purpose is not RunPurpose.CAMPAIGN_TRIAL
                or session.digest != binding.session.session_spec_digest
                or not events
                or not isinstance(events[0], RunStartedEvent)
                or state.terminal_reason is not None
                or not binding.session.handoff_enabled
                or type(admission) is not CampaignParticipantAdmission
                or admission.actor_id != state.current_writer
                or harness_kinds != {state.current_writer: ActorKind.HARNESS}
                or not admission.matches_run(binding, session)
            ):
                raise ValueError("campaign continuation requires the active admitted harness")

            run_harness = _run_actor(binding.session.actors, state.current_writer)
            session_harness = _session_actor(session, state.current_writer)
            if not isinstance(run_harness, HarnessRunActor) or not isinstance(
                session_harness, HarnessActor
            ):
                raise ValueError("campaign continuation writer is not the admitted harness")

            last_transfer = next(
                (event for event in reversed(events) if isinstance(event, ControlTransferredEvent)),
                None,
            )
            if (
                last_transfer is None
                or last_transfer.payload.next_writer != state.current_writer
                or last_transfer.actor != last_transfer.payload.previous_writer
                or not isinstance(
                    _run_actor(
                        binding.session.actors,
                        last_transfer.payload.previous_writer,
                    ),
                    HumanRunActor,
                )
                or not isinstance(
                    _session_actor(session, last_transfer.payload.previous_writer),
                    HumanActor,
                )
            ):
                raise ValueError(
                    "campaign continuation requires the latest human-to-harness handoff"
                )

            actor_kinds = {actor.actor_id: actor.kind for actor in binding.session.actors}

        self._journal = journal
        self._harness = harness_adapter
        self._harness_actor_id = admission.actor_id
        self._campaign_admission = admission
        self._actor_kinds: Mapping[str, ActorKind] = MappingProxyType(actor_kinds)

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return self._actor_kinds

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission:
        return self._campaign_admission

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.run_id != self._journal.header.run_id or view.actor_id != self._harness_actor_id:
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        return self._harness.next_intent(view)


def _run_actor(
    actors: tuple[HumanRunActor | HarnessRunActor, ...],
    actor_id: str,
) -> HumanRunActor | HarnessRunActor | None:
    return next(
        (actor for actor in actors if actor.actor_id == actor_id),
        None,
    )


def _session_actor(
    session: SessionSpec,
    actor_id: str,
) -> HumanActor | HarnessActor | None:
    return next((actor for actor in session.actors if actor.actor_id == actor_id), None)
