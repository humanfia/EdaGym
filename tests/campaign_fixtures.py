"""Frozen benchmark and campaign inputs shared by campaign integration evidence."""

from decimal import Decimal

from edagym.benchmark.model import (
    BenchmarkCase,
    BenchmarkPhase,
    BenchmarkSpec,
    BenchmarkStratum,
    EvaluationCell,
)
from edagym.providers.campaign import (
    CampaignExecutionLimits,
    CampaignScope,
    CampaignSpec,
    CampaignTokenLimits,
    ModelSetManifest,
    RetryPolicy,
    SpendLimit,
)
from edagym.providers.campaign_schedule import (
    CampaignCell,
    CampaignHeader,
    CampaignTask,
    CellPolicy,
    build_campaign_schedule,
)
from edagym.providers.model import ResolvedProviderConfig
from edagym.specs.budget import EpisodeBudget
from edagym.specs.harness import (
    CampaignHarnessBinding,
)


def campaign_cells(
    *,
    model_set: ModelSetManifest,
    harnesses: tuple[CampaignHarnessBinding, ...],
    feedback_policy_digest: str,
    reasoning_efforts: tuple[str, ...] = ("high",),
    route_ids: tuple[str, ...] | None = None,
) -> tuple[CampaignCell, ...]:
    cells = []
    for route in model_set.routes:
        if route_ids is not None and route.route_id not in route_ids:
            continue
        for harness in harnesses:
            for effort in reasoning_efforts:
                policy = CellPolicy(
                    reasoning_effort=effort,
                    service_tier=route.qualification.requested_service_tier,
                    feedback_policy_digest=feedback_policy_digest,
                )
                cells.append(
                    CampaignCell(
                        definition=EvaluationCell(
                            cell_id=f"{route.route_id}-{harness.harness_id}-{effort}",
                            model_id=route.route_id,
                            harness_id=harness.harness_id,
                            policy_digest=policy.digest,
                        ),
                        harness=harness,
                        policy=policy,
                    )
                )
    return tuple(cells)


def campaign_header(
    *,
    campaign_id: str,
    scope: CampaignScope,
    model_set: ModelSetManifest,
    provider_config: ResolvedProviderConfig,
    tasks: tuple[CampaignTask, ...],
    cells: tuple[CampaignCell, ...],
    episode_budget: EpisodeBudget,
    repetition_count: int,
    schedule_seed: str,
    retry_policy: RetryPolicy,
    token_limits: CampaignTokenLimits,
    execution_limits: CampaignExecutionLimits,
    provider_spend_limit: SpendLimit,
) -> CampaignHeader:
    benchmark = BenchmarkSpec(
        benchmark_id=campaign_id,
        revision=1,
        phase=BenchmarkPhase.DEVELOPMENT,
        strata=(
            BenchmarkStratum(
                stratum_id="integration",
                engineering_layer="rtl",
                difficulty_id="integration",
                weight=Decimal(1),
                cases=tuple(
                    BenchmarkCase(
                        task_instance_digest=task.task_instance_digest,
                        block_id=task.task_family,
                    )
                    for task in tasks
                ),
            ),
        ),
        evaluation_cells=tuple(cell.definition for cell in cells),
        repetition_count=repetition_count,
        episode_budget=episode_budget,
        schedule_seed=schedule_seed,
    )
    campaign = CampaignSpec(
        campaign_id=campaign_id,
        scope=scope,
        benchmark_spec_digest=benchmark.digest,
        model_set_digest=model_set.digest,
        task_release_digests=tuple(task.task_release_digest for task in tasks),
        environment_digests=tuple(sorted({task.environment_digest for task in tasks})),
        prompt_digest=cells[0].harness.instruction_digest,
        retry_policy=retry_policy,
        token_limits=token_limits,
        execution_limits=execution_limits,
        provider_spend_limit=provider_spend_limit,
    )
    return CampaignHeader(
        campaign=campaign,
        benchmark=benchmark,
        cells=cells,
        model_set=model_set,
        provider_config=provider_config,
        tasks=tasks,
        schedule=build_campaign_schedule(campaign, model_set, tasks, benchmark, cells),
    )
