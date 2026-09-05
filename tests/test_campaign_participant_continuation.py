"""Evidence for actor-scoped campaign admission across a human handoff."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from uuid import UUID

import pytest

from edagym.cli_support.runs import human_turn
from edagym.participants import (
    AdmittedCampaignContinuationAdapter,
    CampaignParticipantAdmission,
    CandidateSnapshot,
    HumanParticipantAdapter,
    HybridParticipantAdapter,
    JsonLineHumanChannel,
    ParticipantController,
    json_line_human_adapter_digest,
)
from edagym.participants.model import (
    InteractionIntent,
    ParticipantIntent,
    ParticipantView,
    SubmitCandidateIntent,
)
from edagym.resolution import resolve_run
from edagym.run.journal import RunJournal
from edagym.run.model import (
    CampaignTrialRunBinding,
    InteractionDirection,
    ParticipantIncarnationBinding,
    ParticipantIncarnationStartedEvent,
    ParticipantIncarnationStartedPayload,
    ParticipantProcessIdentity,
    ProducerKind,
    RunHeader,
    RunPurpose,
    RunStartedEvent,
    RunStartedPayload,
)
from edagym.specs.common import Visibility
from edagym.specs.session import (
    ActorKind,
    HandoffWriter,
    HarnessActor,
    HumanActor,
    SessionSpec,
)
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


class _HarnessAdapter:
    def __init__(
        self,
        actor_id: str,
        admission: CampaignParticipantAdmission | None,
        *,
        interaction_id: str = "campaign_harness_turn",
    ) -> None:
        self.actor_id = actor_id
        self._admission = admission
        self._interaction_id = interaction_id

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {self.actor_id: ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission | None:
        return self._admission

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.actor_id != self.actor_id:
            raise AssertionError("inactive harness was invoked")
        return InteractionIntent(
            interaction_id=self._interaction_id,
            direction=InteractionDirection.PARTICIPANT_OUTPUT,
        )


def test_campaign_handoff_selects_only_the_admitted_active_actor(tmp_path: Path) -> None:
    journal, session = _campaign_journal(tmp_path / "continued", initial_writer="operator")
    solver_admission = _admission(journal, session, "solver")
    reviewer_admission = _admission(journal, session, "reviewer")

    after_handoff = human_turn(
        journal,
        session,
        input_stream=StringIO(
            json.dumps({"kind": "transfer_control", "next_writer": "solver"}) + "\n"
        ),
        output_stream=StringIO(),
    )
    assert after_handoff.current_writer == "solver"

    continuation = AdmittedCampaignContinuationAdapter(
        journal,
        session,
        _HarnessAdapter("solver", solver_admission),
    )
    continued = ParticipantController(
        journal,
        continuation,
        session=session,
        snapshot_candidate=_unexpected_snapshot,
    ).act_once()
    assert "campaign_harness_turn" in continued.interaction_ids

    with pytest.raises(ValueError):
        AdmittedCampaignContinuationAdapter(
            journal,
            session,
            _HarnessAdapter("reviewer", reviewer_admission),
        )
    with pytest.raises(ValueError):
        AdmittedCampaignContinuationAdapter(
            journal,
            session,
            _HarnessAdapter(
                "solver",
                solver_admission.model_copy(
                    update={"session_spec_digest": digest("another-session")}
                ),
            ),
        )

    no_admission = HybridParticipantAdapter(
        (
            HumanParticipantAdapter(
                "operator",
                JsonLineHumanChannel(StringIO(), StringIO()),
            ),
            _HarnessAdapter("solver", None),
            _HarnessAdapter("reviewer", None),
        )
    )
    with pytest.raises(ValueError):
        ParticipantController(
            journal,
            no_admission,
            session=session,
            snapshot_candidate=_unexpected_snapshot,
        ).act_once()

    human_journal, human_session = _campaign_journal(
        tmp_path / "provider-backed-human",
        initial_writer="operator",
    )
    provider_backed_child = HybridParticipantAdapter(
        (
            _human_adapter("solver"),
            _HarnessAdapter("solver", _admission(human_journal, human_session, "solver")),
            _HarnessAdapter("reviewer", None),
        )
    )
    with pytest.raises(ValueError):
        ParticipantController(
            human_journal,
            provider_backed_child,
            session=human_session,
            snapshot_candidate=_unexpected_snapshot,
        ).act_once()

    no_handoff_journal, no_handoff_session = _campaign_journal(
        tmp_path / "handoff-absent",
        initial_writer="solver",
    )
    with pytest.raises(ValueError):
        AdmittedCampaignContinuationAdapter(
            no_handoff_journal,
            no_handoff_session,
            _HarnessAdapter(
                "solver",
                _admission(no_handoff_journal, no_handoff_session, "solver"),
            ),
        )


def _human_adapter(next_writer: str) -> HumanParticipantAdapter:
    response = json.dumps({"kind": "transfer_control", "next_writer": next_writer}) + "\n"
    return HumanParticipantAdapter(
        "operator",
        JsonLineHumanChannel(StringIO(response), StringIO()),
    )


def _campaign_journal(
    root: Path,
    *,
    initial_writer: str,
) -> tuple[RunJournal, SessionSpec]:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    base = session_spec()
    session = SessionSpec(
        session_id="campaign_hybrid",
        mode=base.mode,
        actors=(
            HumanActor(
                actor_id="operator",
                adapter_id="json_line",
                adapter_digest=json_line_human_adapter_digest(),
            ),
            HarnessActor(
                actor_id="reviewer",
                harness_id="reviewer_responses",
                harness_digest=digest("reviewer-harness"),
                scaffold_digest=digest("reviewer-scaffold"),
                requested_model_route="reviewer.route",
            ),
            HarnessActor(
                actor_id="solver",
                harness_id="solver_responses",
                harness_digest=digest("solver-harness"),
                scaffold_digest=digest("solver-scaffold"),
                requested_model_route="solver.route",
            ),
        ),
        writer=HandoffWriter(initial_writer=initial_writer),
        feedback=base.feedback,
        recovery=base.recovery,
        resources=base.resources,
        model_budget=base.model_budget,
    )
    campaign = CampaignTrialRunBinding(
        campaign_digest=digest("campaign"),
        schedule_digest=digest("campaign-schedule"),
        scheduled_trial_digest=digest("scheduled-trial"),
        paired_seed="1" * 32,
        repetition_index=0,
        route_id="paid-route",
        reasoning_effort="high",
        service_tier="fast",
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="campaign-hybrid-trial",
        campaign=campaign,
        purpose=RunPurpose.CAMPAIGN_TRIAL,
    )
    journal = RunJournal.create(root, RunHeader.from_binding(plan.binding), task)
    journal.append_events(
        (
            RunStartedEvent(
                run_id=journal.header.run_id,
                sequence=0,
                event_id=UUID(int=1),
                timestamp=datetime(2026, 9, 4, tzinfo=UTC),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.PUBLIC,
                payload=RunStartedPayload(binding_digest=plan.binding.digest),
            ),
            ParticipantIncarnationStartedEvent(
                run_id=journal.header.run_id,
                sequence=1,
                event_id=UUID(int=2),
                timestamp=datetime(2026, 9, 4, tzinfo=UTC),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=ParticipantIncarnationStartedPayload(
                    incarnation=ParticipantIncarnationBinding(
                        generation=0,
                        process=ParticipantProcessIdentity(
                            process_id=1,
                            start_time_ticks=1,
                            boot_id_digest=digest("boot"),
                        ),
                        workspace_identity_digest=digest("workspace"),
                        artifact_directory_identity_digest=digest("artifacts"),
                    )
                ),
            ),
        )
    )
    return journal, session


def _admission(
    journal: RunJournal,
    session: SessionSpec,
    actor_id: str,
) -> CampaignParticipantAdmission:
    actor = next(
        actor
        for actor in session.actors
        if isinstance(actor, HarnessActor) and actor.actor_id == actor_id
    )
    campaign = journal.header.binding.campaign
    assert campaign is not None
    return CampaignParticipantAdmission(
        run_id=journal.header.run_id,
        task_release_digest=journal.header.binding.task.release_digest,
        environment_spec_digest=journal.header.binding.environment.environment_spec_digest,
        session_spec_digest=session.digest,
        trial_key=journal.header.binding.trial_key,
        campaign=campaign,
        actor_id=actor.actor_id,
        harness_id=actor.harness_id,
        harness_digest=actor.harness_digest,
        scaffold_digest=actor.scaffold_digest,
        provider_profile_digest=digest(f"{actor_id}-provider-profile"),
        provider_config_digest=digest(f"{actor_id}-provider-config"),
        requested_model=actor.requested_model_route,
        instruction_digest=digest(f"{actor_id}-instruction"),
        tool_schema_digest=digest(f"{actor_id}-tools"),
        maximum_requests_per_action=1,
        budget_binding_digest=digest("campaign-budget"),
    )


def _unexpected_snapshot(intent: SubmitCandidateIntent) -> CandidateSnapshot:
    raise AssertionError(intent)
