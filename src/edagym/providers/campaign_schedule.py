"""Immutable paid-campaign task bindings and deterministic scheduling."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.benchmark.model import BenchmarkSpec, EvaluationCell
from edagym.benchmark.schedule import ScheduledEvaluation, build_benchmark_schedule
from edagym.canonical import canonical_digest
from edagym.config.model import HarnessKind, NativeCliKind
from edagym.providers.campaign import (
    CampaignScope,
    CampaignSpec,
    FeatureSupport,
    ModelSetManifest,
)
from edagym.providers.model import ResolvedProviderConfig, WireProtocol
from edagym.specs.common import (
    Capability,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    ModelLabel,
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
        CampaignTaskRole.FPGA_IMPLEMENTATION: frozenset({Capability.FPGA_IMPLEMENTATION}),
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


class _ProviderHarnessBinding(StrictModel):
    harness_id: Identifier
    provider_profile_digest: Digest
    provider_config_digest: Digest
    wire_protocol: WireProtocol
    instruction_digest: Digest
    tool_schema_digest: Digest
    scaffold_digest: Digest
    usage_policy: Literal[MeteredUsagePolicy.EXACT] = MeteredUsagePolicy.EXACT

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="campaign-harness-v3")


class MeteredProviderHarnessBinding(_ProviderHarnessBinding):
    kind: Literal[HarnessKind.CONTROLLED_AGENT] = HarnessKind.CONTROLLED_AGENT
    wire_protocol: Literal[WireProtocol.RESPONSES] = WireProtocol.RESPONSES
    maximum_requests_per_action: JcsPositiveInt


class NativeCliHarnessBinding(_ProviderHarnessBinding):
    kind: Literal[HarnessKind.NATIVE_CLI] = HarnessKind.NATIVE_CLI
    cli: NativeCliKind
    executable_digest: Digest
    transport_digest: Digest
    cli_version: Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[ -~]+$")]

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        if self.wire_protocol is not self.cli.wire_protocol:
            raise ValueError("native harness protocol differs from its CLI adapter")
        return self


CampaignHarnessBinding = Annotated[
    MeteredProviderHarnessBinding | NativeCliHarnessBinding,
    Field(discriminator="kind"),
]


class CellPolicy(StrictModel):
    """Frozen provider controls and feedback policy for one evaluation cell."""

    reasoning_effort: Annotated[str, Field(min_length=1, max_length=32)]
    service_tier: ServiceTierLabel
    feedback_policy_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="evaluation-cell-policy-v1")


class CampaignCell(StrictModel):
    """Concrete harness and policy bound to one benchmark cell declaration."""

    definition: EvaluationCell
    harness: CampaignHarnessBinding
    policy: CellPolicy

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        if self.definition.harness_id != self.harness.harness_id:
            raise ValueError("cell harness differs from its benchmark declaration")
        if self.definition.policy_digest != self.policy.digest:
            raise ValueError("cell policy differs from its benchmark declaration")
        return self


class CampaignTask(StrictModel):
    """Frozen task facts, independent of every model and harness."""

    task_release_digest: Digest
    task_instance_digest: Digest
    task_family: Identifier
    task_origin: TaskOrigin = NativeSealedTaskOrigin()
    role: CampaignTaskRole
    device_capability: Capability
    environment_digest: Digest
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


class TrialBinding(StrictModel):
    campaign_digest: Digest
    task_release_digest: Digest
    evaluation: ScheduledEvaluation
    task_family: Identifier
    task_origin: TaskOrigin
    task_role: CampaignTaskRole
    device_capability: Capability
    environment_digest: Digest
    evaluation_cell: CampaignCell
    requested_model: ModelLabel
    qualified_provider_reported_model: ModelLabel
    observed_input_token_floor: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_role_capability(self) -> Self:
        if not campaign_role_allows_capability(self.task_role, self.device_capability):
            raise ValueError("campaign trial capability is not admitted for its role")
        definition = self.evaluation_cell.definition
        evaluation = self.evaluation
        if (
            evaluation.cell_id != definition.cell_id
            or evaluation.model_id != definition.model_id
            or evaluation.harness_id != definition.harness_id
            or evaluation.policy_digest != definition.policy_digest
        ):
            raise ValueError("campaign cell differs from its benchmark evaluation")
        return self

    @property
    def task_instance_digest(self) -> str:
        return self.evaluation.task_instance_digest

    @property
    def block_id(self) -> str:
        return self.evaluation.block_id

    @property
    def stratum_id(self) -> str:
        return self.evaluation.stratum_id

    @property
    def paired_seed(self) -> str:
        return self.evaluation.paired_seed

    @property
    def repetition_index(self) -> int:
        return self.evaluation.repetition_index

    @property
    def task_order_index(self) -> int:
        return self.evaluation.task_order_index

    @property
    def cell_id(self) -> str:
        return self.evaluation_cell.definition.cell_id

    @property
    def route_id(self) -> str:
        return self.evaluation_cell.definition.model_id

    @property
    def harness(self) -> CampaignHarnessBinding:
        return self.evaluation_cell.harness

    @property
    def harness_digest(self) -> Digest:
        return self.harness.digest

    @property
    def reasoning_effort(self) -> str:
        return self.evaluation_cell.policy.reasoning_effort

    @property
    def service_tier(self) -> str:
        return self.evaluation_cell.policy.service_tier

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-trial-v2")


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
        return canonical_digest(self, domain="provider-campaign-scheduled-trial-v2")


class CampaignSchedule(StrictModel):
    """Complete task by evaluation-cell by repetition product in a frozen order."""

    schema_version: Literal[2] = 2
    campaign_digest: Digest
    benchmark_spec_digest: Digest
    model_set_digest: Digest
    ordered_task_release_digests: Annotated[tuple[Digest, ...], Field(min_length=1)]
    trials: Annotated[tuple[ScheduledTrial, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if tuple(trial.ordinal for trial in self.trials) != tuple(range(len(self.trials))):
            raise ValueError("campaign trial ordinals must be contiguous and zero-based")
        if len({trial.trial_id for trial in self.trials}) != len(self.trials):
            raise ValueError("campaign schedule trial identities must be unique")
        if len(set(self.ordered_task_release_digests)) != len(self.ordered_task_release_digests):
            raise ValueError("campaign task order cannot contain duplicate releases")
        task_indices = dict(enumerate(self.ordered_task_release_digests))
        if any(
            trial.binding.campaign_digest != self.campaign_digest
            or trial.binding.evaluation.benchmark_digest != self.benchmark_spec_digest
            or trial.binding.evaluation.ordinal != trial.ordinal
            or task_indices.get(trial.binding.task_order_index) != trial.binding.task_release_digest
            for trial in self.trials
        ):
            raise ValueError("campaign trial bindings do not match the schedule envelope")
        if {trial.binding.task_release_digest for trial in self.trials} != set(
            task_indices.values()
        ):
            raise ValueError("campaign trials must cover every frozen task")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-schedule-v2")


def build_campaign_schedule(
    campaign: CampaignSpec,
    model_set: ModelSetManifest,
    tasks: tuple[CampaignTask, ...],
    benchmark: BenchmarkSpec,
    cells: tuple[CampaignCell, ...],
) -> CampaignSchedule:
    """Derive all trials from benchmark cases, cells, and the campaign order seed."""
    if benchmark.digest != campaign.benchmark_spec_digest:
        raise ValueError("campaign benchmark digest does not match its specification")
    if model_set.digest != campaign.model_set_digest:
        raise ValueError("campaign model set digest does not match its manifest")
    task_by_release = {task.task_release_digest: task for task in tasks}
    if len(task_by_release) != len(tasks) or set(task_by_release) != set(
        campaign.task_release_digests
    ):
        raise ValueError("campaign tasks must exactly cover the frozen releases")
    if {task.environment_digest for task in tasks} != set(campaign.environment_digests):
        raise ValueError("campaign tasks must exactly cover the frozen environments")
    cases = {
        case.task_instance_digest: (stratum.stratum_id, case.block_id)
        for stratum in benchmark.strata
        for case in stratum.cases
    }
    if len({task.task_instance_digest for task in tasks}) != len(tasks) or (
        {task.task_instance_digest for task in tasks} != set(cases)
    ):
        raise ValueError("campaign tasks must exactly cover the benchmark cases")
    definitions = {cell.definition.cell_id: cell.definition for cell in cells}
    if len(definitions) != len(cells) or definitions != {
        cell.cell_id: cell for cell in benchmark.evaluation_cells
    }:
        raise ValueError("campaign cells must exactly bind the benchmark declarations")
    routes = {route.route_id: route for route in model_set.routes}
    route_ids = {cell.definition.model_id for cell in cells}
    if not route_ids <= routes.keys():
        raise ValueError("benchmark model identifiers must name qualified routes")
    if (
        campaign.scope in {CampaignScope.MODEL_COMPARISON_PILOT, CampaignScope.COMMON_CORE}
        and route_ids != routes.keys()
    ):
        raise ValueError("comparison campaigns require every frozen qualified route")
    if campaign.scope is CampaignScope.END_TO_END_SMOKE and (
        len(cells) != 1 or benchmark.repetition_count != 1
    ):
        raise ValueError("end-to-end smoke requires one cell and one repetition")
    if campaign.scope is CampaignScope.REASONING_EFFORT_SENSITIVITY:
        if len({cell.policy.reasoning_effort for cell in cells}) < 2:
            raise ValueError("reasoning sensitivity requires multiple effort policies")
        qualified = {
            route.route_id
            for route in model_set.routes
            if route.qualification.reasoning_control is FeatureSupport.SUPPORTED
        }
        if route_ids != qualified:
            raise ValueError("reasoning sensitivity requires every reasoning-qualified route")
    if campaign.retry_policy.max_request_attempts > benchmark.episode_budget.max_requests:
        raise ValueError("episode request budget cannot satisfy the retry policy")
    for task in tasks:
        require_paid_campaign_task_origin(task.task_origin)
    for cell in cells:
        route = routes[cell.definition.model_id]
        if route.qualification.reasoning_control is not FeatureSupport.SUPPORTED:
            raise ValueError("cell reasoning controls require qualified route support")
        if route.qualification.requested_service_tier != cell.policy.service_tier:
            raise ValueError("cell service tier differs from its route qualification")
        if (
            route.qualification.observed_input_token_floor
            >= benchmark.episode_budget.max_input_tokens_per_request
        ):
            raise ValueError("request claim must exceed the observed route input floor")
    benchmark_schedule = build_benchmark_schedule(benchmark)
    task_by_instance = {task.task_instance_digest: task for task in tasks}
    cell_by_id = {cell.definition.cell_id: cell for cell in cells}
    ordered_releases = tuple(
        dict.fromkeys(
            task_by_instance[entry.task_instance_digest].task_release_digest
            for entry in benchmark_schedule.entries
        )
    )
    trials: list[ScheduledTrial] = []
    for evaluation in benchmark_schedule.entries:
        task = task_by_instance[evaluation.task_instance_digest]
        cell = cell_by_id[evaluation.cell_id]
        route = routes[evaluation.model_id]
        binding = TrialBinding(
            campaign_digest=campaign.digest,
            task_release_digest=task.task_release_digest,
            evaluation=evaluation,
            task_family=task.task_family,
            task_origin=task.task_origin,
            task_role=task.role,
            device_capability=task.device_capability,
            environment_digest=task.environment_digest,
            evaluation_cell=cell,
            requested_model=route.requested_model,
            qualified_provider_reported_model=route.provider_reported_model,
            observed_input_token_floor=route.qualification.observed_input_token_floor,
        )
        trials.append(
            ScheduledTrial(ordinal=evaluation.ordinal, trial_id=_trial_id(binding), binding=binding)
        )
    return CampaignSchedule(
        campaign_digest=campaign.digest,
        benchmark_spec_digest=benchmark.digest,
        model_set_digest=model_set.digest,
        ordered_task_release_digests=ordered_releases,
        trials=tuple(trials),
    )


def _trial_id(binding: TrialBinding) -> str:
    return f"trial_{binding.digest[7:]}"


class CampaignHeader(StrictModel):
    """The complete frozen inputs from which scheduling and budgets are derived."""

    schema_version: Literal[3] = 3
    campaign: CampaignSpec
    benchmark: BenchmarkSpec
    cells: Annotated[tuple[CampaignCell, ...], Field(min_length=1)]
    model_set: ModelSetManifest
    provider_config: ResolvedProviderConfig
    tasks: Annotated[tuple[CampaignTask, ...], Field(min_length=1)]
    schedule: CampaignSchedule

    @field_validator("tasks")
    @classmethod
    def normalize_tasks(cls, value: tuple[CampaignTask, ...]) -> tuple[CampaignTask, ...]:
        return tuple(sorted(value, key=lambda task: task.task_release_digest))

    @field_validator("cells")
    @classmethod
    def normalize_cells(cls, value: tuple[CampaignCell, ...]) -> tuple[CampaignCell, ...]:
        return tuple(sorted(value, key=lambda cell: cell.definition.cell_id))

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.provider_config.digest != self.model_set.provider_config_digest:
            raise ValueError("provider configuration does not match the model set")
        expected_provider = (
            self.provider_config.profile.digest,
            self.provider_config.digest,
            self.provider_config.profile.wire_protocol,
            self.campaign.prompt_digest,
        )
        if any(
            (
                cell.harness.provider_profile_digest,
                cell.harness.provider_config_digest,
                cell.harness.wire_protocol,
                cell.harness.instruction_digest,
            )
            != expected_provider
            for cell in self.cells
        ):
            raise ValueError("cell harness differs from the frozen provider and instruction")
        expected = build_campaign_schedule(
            self.campaign,
            self.model_set,
            self.tasks,
            self.benchmark,
            self.cells,
        )
        if self.schedule != expected:
            raise ValueError("campaign schedule is not derived from its frozen inputs")
        from edagym.providers.campaign_budget import CampaignBudgetProjection

        CampaignBudgetProjection.from_header(self)
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-campaign-header-v3")
