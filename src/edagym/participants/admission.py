"""Immutable admission metadata for metered campaign participants."""

from __future__ import annotations

from typing import Literal

from edagym.canonical import canonical_digest
from edagym.run.trial_model import (
    CampaignTrialRunBinding,
    HarnessRunActor,
    RunBinding,
    RunPurpose,
)
from edagym.runtime_surface_protocol import RuntimeSurfaceBinding
from edagym.specs.common import Digest, Identifier, JcsPositiveInt, ModelLabel, StrictModel
from edagym.specs.session import HarnessActor, SessionSpec


class CampaignParticipantAdmission(StrictModel):
    """Non-secret claim tying one metered participant to one resolved run."""

    run_id: Digest
    task_release_digest: Digest
    environment_spec_digest: Digest
    session_spec_digest: Digest
    trial_key: Identifier
    campaign: CampaignTrialRunBinding
    actor_id: Identifier
    harness_id: Identifier
    harness_digest: Digest
    scaffold_digest: Digest
    provider_profile_digest: Digest
    provider_config_digest: Digest
    wire_protocol: Literal["responses"] = "responses"
    requested_model: ModelLabel
    instruction_digest: Digest
    tool_schema_digest: Digest
    maximum_requests_per_action: JcsPositiveInt
    usage_policy: Literal["exact"] = "exact"
    budget_binding_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="campaign-participant-admission-v1")

    def matches_run(self, binding: RunBinding, session: SessionSpec) -> bool:
        """Return whether this claim is an exact projection of the run boundary."""

        if (
            binding.purpose is not RunPurpose.CAMPAIGN_TRIAL
            or binding.campaign is None
            or self.run_id != binding.digest
            or self.task_release_digest != binding.task.release_digest
            or self.environment_spec_digest != binding.environment.environment_spec_digest
            or self.session_spec_digest != binding.session.session_spec_digest
            or self.session_spec_digest != session.digest
            or self.trial_key != binding.trial_key
            or self.campaign != binding.campaign
        ):
            return False
        run_actor = next(
            (actor for actor in binding.session.actors if actor.actor_id == self.actor_id),
            None,
        )
        session_actor = next(
            (actor for actor in session.actors if actor.actor_id == self.actor_id),
            None,
        )
        return (
            isinstance(run_actor, HarnessRunActor)
            and isinstance(session_actor, HarnessActor)
            and self.actor_id == run_actor.actor_id == session_actor.actor_id
            and self.harness_id == session_actor.harness_id
            and self.harness_digest == run_actor.harness_digest == session_actor.harness_digest
            and self.scaffold_digest == run_actor.scaffold_digest == session_actor.scaffold_digest
            and self.requested_model
            == run_actor.requested_model_route
            == session_actor.requested_model_route
            and self.campaign.route_id == binding.campaign.route_id
            and self.campaign.reasoning_effort == binding.campaign.reasoning_effort
            and self.campaign.service_tier == binding.campaign.service_tier
        )


class SyntheticPreflightParticipantAdmission(StrictModel):
    """Provider-free participant claim for one exact synthetic preflight run."""

    run_id: Digest
    actor_id: Identifier
    runtime_surface_binding: RuntimeSurfaceBinding

    def matches_run(self, binding: RunBinding, session: SessionSpec) -> bool:
        if (
            binding.purpose is not RunPurpose.SYNTHETIC_PREFLIGHT
            or binding.campaign is None
            or self.run_id != binding.digest
            or self.runtime_surface_binding.campaign_digest != binding.campaign.campaign_digest
            or self.runtime_surface_binding.campaign_schedule_digest
            != binding.campaign.schedule_digest
            or self.runtime_surface_binding.scheduled_trial_digest
            != binding.campaign.scheduled_trial_digest
            or self.runtime_surface_binding.task_release_digest != binding.task.release_digest
            or self.runtime_surface_binding.environment_spec_digest
            != binding.environment.environment_spec_digest
            or self.runtime_surface_binding.session_spec_digest
            != binding.session.session_spec_digest
            or session.digest != binding.session.session_spec_digest
            or len(binding.session.actors) != 1
            or len(session.actors) != 1
        ):
            return False
        run_actor = binding.session.actors[0]
        session_actor = session.actors[0]
        return (
            isinstance(run_actor, HarnessRunActor)
            and isinstance(session_actor, HarnessActor)
            and self.actor_id == run_actor.actor_id == session_actor.actor_id
            and self.runtime_surface_binding.harness_digest == run_actor.harness_digest
        )
