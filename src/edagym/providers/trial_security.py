"""Canonical runtime-surface binding for one frozen paid campaign trial."""

from __future__ import annotations

from edagym.canonical import canonical_digest
from edagym.providers.campaign_runner import CampaignRunner
from edagym.providers.campaign_schedule import MeteredProviderHarnessBinding, ScheduledTrial
from edagym.providers.provider_budget import CampaignProviderBudget
from edagym.run.trial_model import CampaignTrialRunBinding
from edagym.runtime_surface_protocol import RuntimeSurfaceBinding
from edagym.security.runtime_surface import runtime_surface_export_policy_digest
from edagym.specs.common import Digest
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest
from edagym.specs.session import HarnessActor, SessionSpec
from edagym.specs.task import TaskSpec


def runtime_surface_harness_schema_digest(
    harness: MeteredProviderHarnessBinding,
) -> Digest:
    """Bind the provider-independent participant request and tool schema."""

    return canonical_digest(
        {
            "instruction_digest": harness.instruction_digest,
            "maximum_requests_per_action": harness.maximum_requests_per_action,
            "tool_schema_digest": harness.tool_schema_digest,
            "usage_policy": harness.usage_policy,
            "wire_protocol": harness.wire_protocol,
        },
        domain="runtime-surface-harness-schema-v1",
    )


def campaign_trial_run_binding(
    runner: CampaignRunner,
    trial: ScheduledTrial,
) -> CampaignTrialRunBinding:
    """Project one exact scheduled trial into the canonical run binding."""

    scheduled = tuple(item for item in runner.schedule.trials if item.trial_id == trial.trial_id)
    if len(scheduled) != 1 or scheduled[0] != trial:
        raise ValueError("trial is not in the frozen campaign schedule")
    binding = trial.binding
    return CampaignTrialRunBinding(
        campaign_digest=binding.campaign_digest,
        schedule_digest=runner.schedule.digest,
        scheduled_trial_digest=trial.digest,
        paired_seed=binding.paired_seed,
        repetition_index=binding.repetition_index,
        route_id=binding.route_id,
        reasoning_effort=binding.reasoning_effort,
        service_tier=binding.service_tier,
    )


def runtime_surface_binding_for_trial(
    *,
    runner: CampaignRunner,
    trial: ScheduledTrial,
    task: TaskSpec,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> RuntimeSurfaceBinding:
    """Derive the sole preflight/paid join from exact frozen trial inputs."""

    scheduled = tuple(item for item in runner.schedule.trials if item.trial_id == trial.trial_id)
    if len(scheduled) != 1 or scheduled[0] != trial:
        raise ValueError("runtime surface trial is not in the frozen campaign schedule")
    binding = trial.binding
    if (
        binding.campaign_digest != runner.campaign.digest
        or binding.task_release_digest != release.digest
        or binding.task_family != task.identity.family
        or binding.task_origin != task.identity.origin
        or binding.environment_digest != environment.digest
        or runner.provider_config.digest != binding.harness.provider_config_digest
    ):
        raise ValueError("runtime surface inputs differ from the frozen campaign trial")
    harness = binding.harness
    campaign_trial_harness_actor(trial, session)
    return RuntimeSurfaceBinding(
        campaign_digest=runner.campaign.digest,
        campaign_schedule_digest=runner.schedule.digest,
        scheduled_trial_digest=trial.digest,
        provider_profile_digest=harness.provider_profile_digest,
        provider_config_digest=harness.provider_config_digest,
        budget_binding_digest=CampaignProviderBudget(runner).binding_digest,
        task_release_digest=release.digest,
        environment_spec_digest=environment.digest,
        session_spec_digest=session.digest,
        harness_digest=binding.harness_digest,
        harness_schema_digest=runtime_surface_harness_schema_digest(harness),
        executor_digest=environment.executor.implementation_digest,
        export_policy_digest=runtime_surface_export_policy_digest(environment),
    )


def campaign_trial_harness_actor(
    trial: ScheduledTrial,
    session: SessionSpec,
) -> HarnessActor:
    """Resolve the unique session harness selected by one scheduled trial."""

    harness = trial.binding.harness
    matches = tuple(
        actor
        for actor in session.actors
        if isinstance(actor, HarnessActor)
        and actor.harness_id == harness.harness_id
        and actor.harness_digest == trial.binding.harness_digest
        and actor.scaffold_digest == harness.scaffold_digest
        and actor.requested_model_route == trial.binding.requested_model
    )
    if len(matches) != 1:
        raise ValueError("runtime surface session has no unique frozen harness")
    return matches[0]
