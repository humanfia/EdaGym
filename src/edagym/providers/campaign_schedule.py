"""Immutable paid-campaign task bindings and deterministic scheduling."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.providers.campaign import (
    CampaignScope,
    CampaignSpec,
    FeatureSupport,
    ModelSetManifest,
)
from edagym.providers.model import ResolvedProviderConfig, WireProtocol
from edagym.providers.numeric import JcsNonNegativeInt, JcsPositiveInt
from edagym.specs.common import (
    Capability,
    Digest,
    Identifier,
    ModelLabel,
    SchemaVersion,
    Seed128Hex,
    ServiceTierLabel,
    StrictModel,
)
from edagym.specs.task import NativeSealedTaskOrigin, TaskOrigin


class CampaignTaskRole(StrEnum):
    RTL_GENERATION = "rtl_generation"
    DEBUG_FORMAL = "debug_formal"
    SYNTHESIS_QOR = "synthesis_qor"
    STA_CLOSURE = "sta_closure"
    PHYSICAL_ANALOG = "physical_analog"
    FPGA_IMPLEMENTATION = "fpga_implementation"
    TOOL_FAILURE_RECOVERY = "tool_failure_recovery"
    LONG_RUN_RESUME = "long_run_resume"


CAMPAIGN_ROLE_CAPABILITIES = MappingProxyType(
    {
        CampaignTaskRole.RTL_GENERATION: frozenset(
            {Capability.RTL_SIMULATION, Capability.RTL_LINT}
        ),
        CampaignTaskRole.DEBUG_FORMAL: frozenset(
            {Capability.CDC_RDC, Capability.FORMAL_PROPERTY, Capability.EQUIVALENCE}
        ),
        CampaignTaskRole.SYNTHESIS_QOR: frozenset(
            {Capability.ASIC_SYNTHESIS, Capability.HIGH_LEVEL_SYNTHESIS}
        ),
        CampaignTaskRole.STA_CLOSURE: frozenset({Capability.STATIC_TIMING}),
        CampaignTaskRole.PHYSICAL_ANALOG: frozenset(
            {
                Capability.DIGITAL_IMPLEMENTATION,
                Capability.POWER_ANALYSIS,
                Capability.POWER_INTEGRITY,
                Capability.PARASITIC_EXTRACTION,
                Capability.PHYSICAL_VERIFICATION,
                Capability.CIRCUIT_SIMULATION,
                Capability.CELL_CHARACTERIZATION,
            }
        ),
        CampaignTaskRole.FPGA_IMPLEMENTATION: frozenset(
            {Capability.FPGA_IMPLEMENTATION}
        ),
        CampaignTaskRole.TOOL_FAILURE_RECOVERY: frozenset(Capability),
        CampaignTaskRole.LONG_RUN_RESUME: frozenset(Capability),
    }
)


def campaign_role_allows_capability(
    role: CampaignTaskRole,
    capability: Capability,
) -> bool:
    return capability in CAMPAIGN_ROLE_CAPABILITIES[role]


class MeteredUsagePolicy(StrEnum):
    EXACT = "exact"


def require_paid_campaign_task_origin(origin: TaskOrigin) -> None:
    if not isinstance(origin, NativeSealedTaskOrigin):
        raise ValueError("paid campaigns require native sealed tasks")


class MeteredProviderHarnessBinding(StrictModel):
    """Provider-backed harness identity admissible for paid campaign tasks."""

    harness_id: Identifier
    provider_profile_digest: Digest
    provider_config_digest: Digest
    wire_protocol: Literal[WireProtocol.RESPONSES] = WireProtocol.RESPONSES
    instruction_digest: Digest
    tool_schema_digest: Digest
    scaffold_digest: Digest
    maximum_requests_per_action: JcsPositiveInt
    usage_policy: Literal[MeteredUsagePolicy.EXACT] = MeteredUsagePolicy.EXACT

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="metered-provider-harness-v1")


class CampaignTask(StrictModel):
    """Frozen report and execution binding for one task release."""

    task_release_digest: Digest
    task_family: Identifier
    task_origin: TaskOrigin = NativeSealedTaskOrigin()
    role: CampaignTaskRole
    device_capability: Capability
    environment_digest: Digest
    harness: MeteredProviderHarnessBinding
    evaluator_stage_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]

    @field_validator("evaluator_stage_ids")
    @classmethod
    def validate_stage_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("campaign task evaluator stages must be unique")
        return value

    @model_validator(mode="after")
    def validate_role_capability(self) -> Self:
        if not campaign_role_allows_capability(self.role, self.device_capability):
            raise ValueError("campaign task capability is not admitted for its role")
        return self

    @property
    def harness_digest(self) -> Digest:
        return self.harness.digest


class TrialBinding(StrictModel):
    campaign_digest: Digest
    task_release_digest: Digest
    task_family: Identifier
    task_origin: TaskOrigin
    task_role: CampaignTaskRole
    device_capability: Capability
    environment_digest: Digest
    harness: MeteredProviderHarnessBinding
    route_id: Identifier
    requested_model: ModelLabel
    qualified_provider_reported_model: ModelLabel
    reasoning_effort: Annotated[str, Field(min_length=1, max_length=32)]
    service_tier: ServiceTierLabel
    observed_input_token_floor: JcsNonNegativeInt
    paired_seed: Seed128Hex
    repetition_index: JcsNonNegativeInt
    task_order_index: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_role_capability(self) -> Self:
        if not campaign_role_allows_capability(
            self.task_role,
            self.device_capability,
        ):
            raise ValueError("campaign trial capability is not admitted for its role")
        return self

    @property
    def harness_digest(self) -> Digest:
        return self.harness.digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-trial-v1")


class ScheduledTrial(StrictModel):
    ordinal: JcsNonNegativeInt
    trial_id: Identifier
    binding: TrialBinding

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.trial_id != _trial_id(self.binding):
            raise ValueError("scheduled trial identifier does not match its binding")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-scheduled-trial-v1")


class CampaignSchedule(StrictModel):
    """Complete task by route by paired-seed product in one immutable order."""

    schema_version: SchemaVersion = 1
    campaign_digest: Digest
    model_set_digest: Digest
    ordered_task_release_digests: Annotated[tuple[Digest, ...], Field(min_length=1)]
    trials: Annotated[tuple[ScheduledTrial, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        ordinals = tuple(trial.ordinal for trial in self.trials)
        if ordinals != tuple(range(len(self.trials))):
            raise ValueError("campaign trial ordinals must be contiguous and zero-based")
        trial_ids = [trial.trial_id for trial in self.trials]
        if len(trial_ids) != len(set(trial_ids)):
            raise ValueError("campaign schedule trial identities must be unique")
        if len(self.ordered_task_release_digests) != len(set(self.ordered_task_release_digests)):
            raise ValueError("campaign task order cannot contain duplicate releases")
        expected_task_index = {
            release: index for index, release in enumerate(self.ordered_task_release_digests)
        }
        if any(
            trial.binding.campaign_digest != self.campaign_digest
            or expected_task_index.get(trial.binding.task_release_digest)
            != trial.binding.task_order_index
            for trial in self.trials
        ):
            raise ValueError("campaign trial bindings do not match the schedule envelope")
        if {trial.binding.task_release_digest for trial in self.trials} != set(
            self.ordered_task_release_digests
        ):
            raise ValueError("campaign trials must cover every task in the frozen order")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-schedule-v1")


def build_campaign_schedule(
    campaign: CampaignSpec,
    model_set: ModelSetManifest,
    tasks: tuple[CampaignTask, ...],
) -> CampaignSchedule:
    """Freeze the complete cross product without relying on process-local randomness."""

    if model_set.digest != campaign.model_set_digest:
        raise ValueError("campaign model set digest does not match the supplied manifest")
    task_by_release = {task.task_release_digest: task for task in tasks}
    if len(task_by_release) != len(tasks):
        raise ValueError("campaign task release digests must be unique")
    if set(task_by_release) != set(campaign.task_release_digests):
        raise ValueError("campaign tasks must exactly cover the frozen task releases")
    if {task.environment_digest for task in tasks} != set(campaign.environment_digests):
        raise ValueError("campaign tasks must exactly cover the frozen environments")
    if {task.harness_digest for task in tasks} != set(campaign.harness_digests):
        raise ValueError("campaign tasks must exactly cover the frozen harnesses")
    for task in tasks:
        require_paid_campaign_task_origin(task.task_origin)
        if not campaign_role_allows_capability(task.role, task.device_capability):
            raise ValueError("campaign task capability is not admitted for its role")
    task_roles = {task.role for task in tasks}
    if campaign.scope is CampaignScope.END_TO_END_SMOKE and not (
        CampaignTaskRole.RTL_GENERATION in task_roles
        and task_roles
        & {CampaignTaskRole.SYNTHESIS_QOR, CampaignTaskRole.STA_CLOSURE}
        and task_roles
        & {CampaignTaskRole.PHYSICAL_ANALOG, CampaignTaskRole.FPGA_IMPLEMENTATION}
    ):
        raise ValueError(
            "end-to-end smoke tasks must cover RTL generation, synthesis or STA, "
            "and physical, analog, or FPGA execution"
        )
    if campaign.scope in {
        CampaignScope.MODEL_COMPARISON_PILOT,
        CampaignScope.COMMON_CORE,
    } and task_roles != set(CampaignTaskRole):
        raise ValueError("pilot and common core tasks must cover every representative role")
    effort_roles = {
        CampaignTaskRole.RTL_GENERATION,
        CampaignTaskRole.DEBUG_FORMAL,
        CampaignTaskRole.SYNTHESIS_QOR,
        CampaignTaskRole.STA_CLOSURE,
        CampaignTaskRole.PHYSICAL_ANALOG,
        CampaignTaskRole.FPGA_IMPLEMENTATION,
    }
    if (
        campaign.scope is CampaignScope.REASONING_EFFORT_SENSITIVITY
        and task_roles != effort_roles
    ):
        raise ValueError(
            "reasoning effort sensitivity tasks must cover the six representative roles"
        )

    ordered_releases = tuple(
        sorted(
            task_by_release,
            key=lambda release: (
                canonical_digest(
                    {"seed": campaign.task_order_seed, "task_release_digest": release},
                    domain="provider-campaign-task-order-v1",
                ),
                release,
            ),
        )
    )
    route_by_id = {route.route_id: route for route in model_set.routes}
    if set(campaign.route_ids) - route_by_id.keys():
        raise ValueError("campaign routes must exist in the frozen model set")
    if campaign.scope in {
        CampaignScope.MODEL_COMPARISON_PILOT,
        CampaignScope.COMMON_CORE,
    } and set(campaign.route_ids) != set(route_by_id):
        raise ValueError("comparison campaigns require every frozen qualified route")
    reasoning_route_ids = {
        route.route_id
        for route in model_set.routes
        if route.qualification.reasoning_control is FeatureSupport.SUPPORTED
    }
    if (
        campaign.scope is CampaignScope.REASONING_EFFORT_SENSITIVITY
        and set(campaign.route_ids) != reasoning_route_ids
    ):
        raise ValueError(
            "reasoning effort sensitivity campaigns require every reasoning-qualified route"
        )
    routes = tuple(route_by_id[route_id] for route_id in campaign.route_ids)
    if any(
        route.qualification.reasoning_control is not FeatureSupport.SUPPORTED
        for route in routes
    ):
        raise ValueError("campaign reasoning efforts require qualified route support")
    if any(
        route.qualification.requested_service_tier != campaign.service_tier
        for route in routes
    ):
        raise ValueError("campaign service tier differs from its route qualifications")
    if any(
        route.qualification.observed_input_token_floor
        >= campaign.token_limits.max_input_tokens_per_request
        for route in routes
    ):
        raise ValueError("campaign input-token claim must exceed its observed route floor")
    trials: list[ScheduledTrial] = []
    for repetition_index, paired_seed in enumerate(campaign.paired_trial_seeds):
        for task_order_index, release in enumerate(ordered_releases):
            task = task_by_release[release]
            for route in routes:
                for reasoning_effort in campaign.reasoning_efforts:
                    binding = TrialBinding(
                        campaign_digest=campaign.digest,
                        task_release_digest=release,
                        task_family=task.task_family,
                        task_origin=task.task_origin,
                        task_role=task.role,
                        device_capability=task.device_capability,
                        environment_digest=task.environment_digest,
                        harness=task.harness,
                        route_id=route.route_id,
                        requested_model=route.requested_model,
                        qualified_provider_reported_model=route.provider_reported_model,
                        reasoning_effort=reasoning_effort,
                        service_tier=campaign.service_tier,
                        observed_input_token_floor=(
                            route.qualification.observed_input_token_floor
                        ),
                        paired_seed=paired_seed,
                        repetition_index=repetition_index,
                        task_order_index=task_order_index,
                    )
                    trials.append(
                        ScheduledTrial(
                            ordinal=len(trials),
                            trial_id=_trial_id(binding),
                            binding=binding,
                        )
                    )
    return CampaignSchedule(
        campaign_digest=campaign.digest,
        model_set_digest=model_set.digest,
        ordered_task_release_digests=ordered_releases,
        trials=tuple(trials),
    )


def _trial_id(binding: TrialBinding) -> str:
    return f"trial_{binding.digest.removeprefix('sha256:')}"


class CampaignHeader(StrictModel):
    """Complete non-secret identity needed to validate and replay a campaign."""

    schema_version: SchemaVersion = 1
    campaign: CampaignSpec
    model_set: ModelSetManifest
    provider_config: ResolvedProviderConfig
    tasks: Annotated[tuple[CampaignTask, ...], Field(min_length=1)]
    schedule: CampaignSchedule

    @field_validator("tasks")
    @classmethod
    def normalize_tasks(cls, value: tuple[CampaignTask, ...]) -> tuple[CampaignTask, ...]:
        releases = [task.task_release_digest for task in value]
        if len(releases) != len(set(releases)):
            raise ValueError("campaign header task releases must be unique")
        return tuple(sorted(value, key=lambda task: task.task_release_digest))

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.provider_config.digest != self.model_set.provider_config_digest:
            raise ValueError("provider configuration does not match the model set")
        expected_harness = (
            self.provider_config.profile.digest,
            self.provider_config.digest,
            self.provider_config.profile.wire_protocol,
            self.campaign.prompt_digest,
            self.campaign.tool_schema_digest,
        )
        if any(
            (
                task.harness.provider_profile_digest,
                task.harness.provider_config_digest,
                task.harness.wire_protocol,
                task.harness.instruction_digest,
                task.harness.tool_schema_digest,
            )
            != expected_harness
            for task in self.tasks
        ):
            raise ValueError("campaign harness is not bound to the metered provider")
        expected = build_campaign_schedule(self.campaign, self.model_set, self.tasks)
        if self.schedule != expected:
            raise ValueError("campaign schedule is not derived from its frozen inputs")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-header-v1")
