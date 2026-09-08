"""Semantic evidence for paid campaign scheduling and reports."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

import pytest

from edagym.benchmark.schedule import build_benchmark_schedule
from edagym.evaluation.model import CandidateFailureOutcome, PassedOutcome, StageResult
from edagym.providers.campaign import (
    CampaignExecutionLimits,
    CampaignScope,
    CampaignTokenLimits,
    CappedSpendLimit,
    FeatureSupport,
    ModelCategory,
    ModelReferenceKind,
    ModelRoute,
    ModelSetManifest,
    RetryCondition,
    RetryPolicy,
    RouteQualification,
    UnknownSpendLimit,
)
from edagym.providers.campaign_journal import CampaignJournalCorruption
from edagym.providers.campaign_runner import (
    AttemptDisposition,
    BudgetDimension,
    CampaignAccountingError,
    CampaignBudgetExceeded,
    CampaignReservation,
    CampaignResources,
    CampaignRunner,
    CountRatio,
    ProviderBudgetOverrun,
    TrialDisposition,
    TrialRunOutcome,
    UnknownSpend,
    UnknownSpendReason,
)
from edagym.providers.campaign_schedule import (
    CampaignHeader,
    CampaignTask,
    CampaignTaskRole,
    build_campaign_schedule,
)
from edagym.providers.model import (
    ProviderDefaults,
    ProviderProfile,
    ProviderSecurityBinding,
    ProviderUsage,
    RequestTokenClaim,
    ResolvedProviderConfig,
)
from edagym.providers.provider_budget import CampaignProviderBudget
from edagym.run.trial_model import (
    CampaignTrialRunBinding,
    CandidateStageResult,
    EnvironmentRunBinding,
    EvaluatorRunBinding,
    HarnessRunActor,
    ProviderRequestState,
    ResolvedToolBinding,
    RunBinding,
    RunPurpose,
    SessionRunBinding,
    StopReason,
    TaskRunBinding,
)
from edagym.specs.budget import EpisodeBudget
from edagym.specs.common import Capability, ProviderResponseStatus, Redistribution
from edagym.specs.harness import (
    MeteredProviderHarnessBinding,
)
from edagym.specs.task import PublicCalibrationTaskOrigin
from tests.campaign_fixtures import campaign_cells, campaign_header
from tests.factories import SYNTHETIC_CREDENTIAL_SOURCE_DIGEST


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _seed(number: int) -> str:
    return f"{number:032x}"


def _route(
    route_id: str,
    categories: tuple[ModelCategory, ...],
) -> ModelRoute:
    return ModelRoute(
        route_id=route_id,
        requested_model=f"requested-{route_id}",
        provider_reported_model=f"qualified-{route_id}",
        reference_kind=ModelReferenceKind.UNKNOWN,
        categories=categories,
        qualification=RouteQualification(
            reasoning_control=FeatureSupport.SUPPORTED,
            requested_service_tier="fast",
            canary_tool_schema_digest=_digest(f"canary-tools-{route_id}"),
            canary_evidence_digest=_digest(f"canary-{route_id}"),
        ),
    )


def _model_set(*routes: ModelRoute) -> ModelSetManifest:
    return ModelSetManifest(
        provider_config_digest=_provider_config().digest,
        discovery_digest=_digest("model-discovery"),
        resolved_on="2026-09-04",
        routes=routes,
    )


def _provider_config() -> ResolvedProviderConfig:
    return ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="test_gateway",
        profile=ProviderProfile(
            logical_id="test.gateway", origin="https://gateway.test", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="test-default"),
    )


def _tasks(count: int = 8) -> tuple[CampaignTask, ...]:
    roles = tuple(CampaignTaskRole)
    capabilities = {
        CampaignTaskRole.RTL_GENERATION: Capability.RTL_SIMULATION,
        CampaignTaskRole.DEBUG_FORMAL: Capability.FORMAL_PROPERTY,
        CampaignTaskRole.SYNTHESIS_QOR: Capability.ASIC_SYNTHESIS,
        CampaignTaskRole.STA_CLOSURE: Capability.STATIC_TIMING,
        CampaignTaskRole.PHYSICAL_ANALOG: Capability.CIRCUIT_SIMULATION,
        CampaignTaskRole.FPGA_IMPLEMENTATION: Capability.FPGA_IMPLEMENTATION,
        CampaignTaskRole.TOOL_FAILURE_RECOVERY: Capability.RTL_LINT,
        CampaignTaskRole.LONG_RUN_RESUME: Capability.DIGITAL_IMPLEMENTATION,
    }
    return tuple(
        CampaignTask(
            task_release_digest=_digest(f"release-{index}"),
            task_instance_digest=_digest(f"instance-{index}"),
            task_family=f"task-family-{index}",
            role=roles[index % len(roles)],
            device_capability=capabilities[roles[index % len(roles)]],
            environment_digest=_digest(f"environment-{index}"),
            evaluator_stage_ids=(f"verify-{index}", f"qor-{index}"),
        )
        for index in range(count)
    )


def _header(
    *,
    scope: CampaignScope,
    tasks: tuple[CampaignTask, ...],
    model_set: ModelSetManifest,
    repetition_count: int,
    max_requests: int = 64,
    episode_max_requests: int = 4,
    episode_max_total_tokens: int = 1000,
    max_wall_seconds: int = 100,
    route_ids: tuple[str, ...] | None = None,
    reasoning_efforts: tuple[str, ...] = ("high",),
) -> CampaignHeader:
    configuration = _provider_config()
    harness = MeteredProviderHarnessBinding(
        harness_id="responses-harness",
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        instruction_digest=_digest("prompt"),
        tool_schema_digest=_digest("tools"),
        scaffold_digest=_digest("scaffold"),
        maximum_requests_per_action=4,
    )
    return campaign_header(
        campaign_id="provider-evaluation",
        scope=scope,
        model_set=model_set,
        provider_config=configuration,
        tasks=tasks,
        cells=campaign_cells(
            model_set=model_set,
            harnesses=(harness,),
            feedback_policy_digest=_digest("feedback"),
            reasoning_efforts=reasoning_efforts,
            route_ids=route_ids,
        ),
        episode_budget=EpisodeBudget(
            max_experiments=4,
            max_requests=episode_max_requests,
            max_input_tokens_per_request=100,
            max_output_tokens_per_request=100,
            max_input_tokens=600,
            max_output_tokens=600,
            max_total_tokens=episode_max_total_tokens,
            max_turns=4,
            max_tool_calls=2,
            max_wall_seconds=min(max_wall_seconds, 25),
            max_eda_compute_seconds=80,
            max_license_seconds=60,
            max_artifact_bytes=1000,
        ),
        repetition_count=repetition_count,
        schedule_seed=_seed(91),
        retry_policy=RetryPolicy(
            max_request_attempts=2,
            backoff_milliseconds=0,
            retry_conditions=(RetryCondition.CONNECT_FAILURE,),
        ),
        token_limits=CampaignTokenLimits(
            max_requests=max_requests,
            max_input_tokens=6400,
            max_output_tokens=6400,
            max_total_tokens=12800,
        ),
        execution_limits=CampaignExecutionLimits(
            max_turns=256,
            max_tool_calls=128,
            max_wall_seconds=max_wall_seconds,
            max_eda_compute_seconds=6400,
            max_license_seconds=4800,
            max_artifact_bytes=64_000,
        ),
        provider_spend_limit=(
            CappedSpendLimit(currency="USD", amount=Decimal("1"))
            if scope in {CampaignScope.END_TO_END_SMOKE, CampaignScope.EXPANDED_BREADTH}
            else UnknownSpendLimit()
        ),
    )


def _complete_outcome(
    runner: CampaignRunner,
    trial_index: int,
    *,
    successful: bool,
    stage_id: str,
    include_stage: bool = True,
    request_key: str | None = None,
    token_claim: RequestTokenClaim | None = None,
    provider_usage: ProviderUsage | None = None,
    provider_reported_model: str | None = None,
    provider_reported_service_tier: str | None = None,
) -> TrialRunOutcome:
    trial = runner.schedule.trials[trial_index]
    if request_key is None:
        request_key = f"solve_{trial_index}"
        provider_usage = ProviderUsage(input_tokens=1, output_tokens=1, total_tokens=2)
        provider_reported_model = trial.binding.qualified_provider_reported_model
        token_claim = RequestTokenClaim(input_tokens=1, output_tokens=1)
        reservation = runner.reserve_provider_attempt(
            trial_id=trial.trial_id,
            request_key=request_key,
            requested_model=trial.binding.requested_model,
            token_claim=token_claim,
            security_binding=_security_binding(runner),
        )
        reservation.mark_dispatched()
        reservation.settle_provider(
            disposition=AttemptDisposition.COMPLETED,
            usage=provider_usage,
            provider_reported_model=provider_reported_model,
            provider_reported_service_tier=provider_reported_service_tier,
            provider_response_status=ProviderResponseStatus.COMPLETED,
        )
    if token_claim is None or provider_usage is None or provider_reported_model is None:
        raise ValueError("an existing provider request requires its settled response facts")
    stage_results: tuple[CandidateStageResult, ...] = ()
    if include_stage:
        stage_results = (
            CandidateStageResult(
                candidate_id="candidate",
                result=StageResult(
                    stage_id=stage_id,
                    outcome=PassedOutcome() if successful else CandidateFailureOutcome(),
                ),
            ),
        )
    return TrialRunOutcome(
        disposition=TrialDisposition.COMPLETED_RUN,
        terminal_reason=(StopReason.VERIFIER_SUCCESS if successful else StopReason.EXPLICIT_CANCEL),
        run_id=_run_binding(runner, trial_index).digest,
        run_binding=_run_binding(runner, trial_index),
        stage_results=stage_results,
        provider_requests=(
            _provider_request_fact(
                runner,
                trial_index,
                request_key=request_key,
                token_claim=token_claim,
                usage=provider_usage,
                provider_reported_model=provider_reported_model,
                provider_reported_service_tier=provider_reported_service_tier,
            ),
        ),
        provider_spend=UnknownSpend(reason=UnknownSpendReason.PROVIDER_REPORTING_UNAVAILABLE),
    )


def _provider_request_fact(
    runner: CampaignRunner,
    trial_index: int,
    *,
    request_key: str,
    token_claim: RequestTokenClaim,
    usage: ProviderUsage,
    provider_reported_model: str,
    provider_reported_service_tier: str | None = None,
) -> ProviderRequestState:
    trial = runner.schedule.trials[trial_index]
    harness = trial.binding.harness
    return ProviderRequestState(
        request_id=request_key,
        actor_id="test-harness",
        request_artifact_id=f"{request_key}_request",
        security_evidence_artifact_id="provider_canary_evidence",
        provider_profile_digest=harness.provider_profile_digest,
        provider_config_digest=harness.provider_config_digest,
        requested_model=trial.binding.requested_model,
        requested_service_tier=trial.binding.service_tier,
        observed_input_token_floor=token_claim.observed_input_token_floor,
        security_binding=_security_binding(runner),
        reserved_input_tokens=token_claim.input_tokens,
        reserved_output_tokens=token_claim.output_tokens,
        provider_reported_model=provider_reported_model,
        provider_reported_service_tier=provider_reported_service_tier,
        status=ProviderResponseStatus.COMPLETED,
        usage=ProviderUsage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
            cached_input_tokens=usage.cached_input_tokens,
            reasoning_tokens=usage.reasoning_tokens,
        ),
    )


def _run_binding(runner: CampaignRunner, trial_index: int) -> RunBinding:
    trial = runner.schedule.trials[trial_index]
    binding = trial.binding
    return RunBinding(
        purpose=RunPurpose.CAMPAIGN_TRIAL,
        task=TaskRunBinding(
            family=binding.task_family,
            authoring_revision=1,
            task_spec_digest=_digest(f"spec-{binding.task_family}"),
            instance_seed=binding.paired_seed,
            instance_digest=binding.task_instance_digest,
            release_digest=binding.task_release_digest,
        ),
        environment=EnvironmentRunBinding(
            environment_spec_digest=binding.environment_digest,
            executor_id="test-executor",
            executor_digest=_digest("executor"),
            policy_digest=_digest("policy"),
            tools=(
                ResolvedToolBinding(
                    capability=binding.device_capability,
                    tool_id="test-tool",
                    tool_version="1",
                    driver_digest=_digest("driver"),
                    deployment_attestation_digest=_digest("deployment"),
                ),
            ),
        ),
        session=SessionRunBinding(
            session_spec_digest=_digest("session"),
            actors=(
                HarnessRunActor(
                    actor_id="test-harness",
                    harness_digest=binding.harness_digest,
                    scaffold_digest=binding.harness.scaffold_digest,
                    requested_model_route=binding.requested_model,
                ),
            ),
            initial_writer="test-harness",
            handoff_enabled=False,
            feedback_policy_digest=binding.evaluation_cell.policy.feedback_policy_digest,
            budget_digest=_digest("run-budget"),
        ),
        evaluators=(
            EvaluatorRunBinding(
                evaluator_id="test-evaluator",
                revision_digest=_digest("evaluator"),
            ),
        ),
        measurement_schema_digest=_digest("measurements"),
        trial_key=trial.trial_id,
        campaign=CampaignTrialRunBinding(
            campaign_digest=binding.campaign_digest,
            schedule_digest=runner.schedule.digest,
            scheduled_trial_digest=trial.digest,
            paired_seed=binding.paired_seed,
            repetition_index=binding.repetition_index,
            route_id=binding.route_id,
            reasoning_effort=binding.reasoning_effort,
            service_tier=binding.service_tier,
        ),
    )


def _security_binding(runner: CampaignRunner) -> ProviderSecurityBinding:
    return ProviderSecurityBinding(
        canary_receipt_digest=_digest("canary-receipt"),
        runtime_surface_manifest_digest=_digest("runtime-surface"),
        budget_binding_digest=runner.budget_projection().digest,
    )


def test_scope_contract_and_schedule_freeze_the_full_paired_product(tmp_path: Path) -> None:
    routes = (
        _route(
            "frontier-route",
            (ModelCategory.FRONTIER_REASONING, ModelCategory.CODING_AGENT),
        ),
        _route(
            "economy-route",
            (ModelCategory.BALANCED, ModelCategory.HIGH_THROUGHPUT),
        ),
    )
    model_set = _model_set(*routes)
    tasks = _tasks(3)
    header = _header(
        scope=CampaignScope.COMMON_CORE, tasks=tasks, model_set=model_set, repetition_count=3
    )

    schedule = build_campaign_schedule(
        header.campaign, model_set, tasks, header.benchmark, header.cells
    )
    rebuilt = build_campaign_schedule(
        header.campaign, model_set, tuple(reversed(tasks)), header.benchmark, header.cells
    )
    assert schedule == rebuilt
    assert len(schedule.trials) == len(tasks) * len(routes) * 3
    assert tuple(trial.ordinal for trial in schedule.trials) == tuple(range(18))
    for task in tasks:
        for repetition in range(3):
            paired = [
                trial.binding
                for trial in schedule.trials
                if trial.binding.task_instance_digest == task.task_instance_digest
                and trial.binding.repetition_index == repetition
            ]
            assert {binding.route_id for binding in paired} == {route.route_id for route in routes}
            assert len({binding.paired_seed for binding in paired}) == 1
    assert len({trial.binding.paired_seed for trial in schedule.trials}) == len(tasks) * 3
    assert len({trial.trial_id for trial in schedule.trials}) == 18
    for repetition in range(3):
        observed = tuple(
            trial.binding.task_release_digest
            for trial in schedule.trials
            if trial.binding.repetition_index == repetition
        )[:: len(routes)]
        assert observed == schedule.ordered_task_release_digests
    projection = CampaignRunner(header=header, state_root=tmp_path / "scope").budget_projection()
    assert projection.trial_count == 18
    assert projection.global_limits == CampaignResources(
        requests=64,
        input_tokens=6400,
        output_tokens=6400,
        turns=256,
        tool_calls=128,
        wall_seconds=100,
        eda_compute_seconds=6400,
        license_seconds=4800,
        artifact_bytes=64_000,
    )
    assert projection.per_trial_limits == CampaignResources(
        requests=4,
        input_tokens=600,
        output_tokens=600,
        turns=4,
        tool_calls=2,
        wall_seconds=25,
        eda_compute_seconds=80,
        license_seconds=60,
        artifact_bytes=1000,
    )
    assert projection.digest.startswith("sha256:")
    assert projection.per_trial_limits.tool_calls == 2
    assert projection.global_total_token_limit == 12800

    pilot = _header(
        scope=CampaignScope.MODEL_COMPARISON_PILOT,
        tasks=tasks,
        model_set=model_set,
        repetition_count=2,
    )
    assert len(pilot.schedule.trials) == 12
    assert {trial.binding.paired_seed for trial in pilot.schedule.trials} <= {
        trial.binding.paired_seed for trial in schedule.trials
    }
    effort_schedule = _header(
        scope=CampaignScope.EXPANDED_BREADTH,
        tasks=tasks,
        model_set=model_set,
        repetition_count=1,
        reasoning_efforts=("high", "low"),
    ).schedule
    assert len(effort_schedule.trials) == len(tasks) * len(routes) * 2
    assert {trial.binding.reasoning_effort for trial in effort_schedule.trials} == {
        "high",
        "low",
    }


def test_end_to_end_smoke_limits_model_dispatch_without_expanding_tasks() -> None:
    routes = (
        _route(
            "frontier-route",
            (ModelCategory.FRONTIER_REASONING, ModelCategory.CODING_AGENT),
        ),
        _route(
            "economy-route",
            (ModelCategory.BALANCED, ModelCategory.HIGH_THROUGHPUT),
        ),
    )
    model_set = _model_set(*routes)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.END_TO_END_SMOKE,
        tasks=tasks,
        model_set=model_set,
        repetition_count=1,
        route_ids=(routes[0].route_id,),
    )

    schedule = build_campaign_schedule(
        header.campaign, model_set, tasks, header.benchmark, header.cells
    )
    assert len(schedule.trials) == 1
    assert {trial.binding.route_id for trial in schedule.trials} == {routes[0].route_id}
    spoofed_capability = (
        *tasks[:-1],
        tasks[-1].model_copy(update={"device_capability": Capability.STATIC_TIMING}),
    )
    with pytest.raises(ValueError, match="capability is not admitted"):
        build_campaign_schedule(
            header.campaign, model_set, spoofed_capability, header.benchmark, header.cells
        )
    with pytest.raises(ValueError, match="one cell and one repetition"):
        _header(
            scope=CampaignScope.END_TO_END_SMOKE,
            tasks=tasks,
            model_set=model_set,
            repetition_count=1,
        )
    with pytest.raises(ValueError, match="one cell and one repetition"):
        _header(
            scope=CampaignScope.END_TO_END_SMOKE,
            tasks=tasks,
            model_set=model_set,
            repetition_count=3,
            route_ids=(routes[0].route_id,),
        )
    missing = header.cells[0].model_copy(
        update={
            "definition": header.cells[0].definition.model_copy(
                update={"model_id": "missing-route"}
            )
        }
    )
    benchmark = header.benchmark.model_copy(update={"evaluation_cells": (missing.definition,)})
    campaign = header.campaign.model_copy(update={"benchmark_spec_digest": benchmark.digest})
    with pytest.raises(ValueError, match="qualified routes"):
        build_campaign_schedule(campaign, model_set, tasks, benchmark, (missing,))


def test_reasoning_effort_sensitivity_is_a_distinct_paired_product() -> None:
    routes = (
        _route(
            "frontier-route",
            (ModelCategory.FRONTIER_REASONING, ModelCategory.CODING_AGENT),
        ),
        _route(
            "economy-route",
            (ModelCategory.BALANCED, ModelCategory.HIGH_THROUGHPUT),
        ),
    )
    model_set = _model_set(*routes)
    tasks = _tasks(2)
    header = _header(
        scope=CampaignScope.REASONING_EFFORT_SENSITIVITY,
        tasks=tasks,
        model_set=model_set,
        repetition_count=1,
        reasoning_efforts=("high", "max"),
    )

    schedule = build_campaign_schedule(
        header.campaign, model_set, tasks, header.benchmark, header.cells
    )
    assert len(schedule.trials) == 8
    assert {trial.binding.route_id for trial in schedule.trials} == {
        route.route_id for route in routes
    }
    assert {trial.binding.reasoning_effort for trial in schedule.trials} == {
        "high",
        "max",
    }
    for task in tasks:
        paired = [
            trial.binding
            for trial in schedule.trials
            if trial.binding.task_instance_digest == task.task_instance_digest
        ]
        assert {(binding.route_id, binding.reasoning_effort) for binding in paired} == {
            (route.route_id, effort) for route in routes for effort in ("high", "max")
        }
        assert len({binding.paired_seed for binding in paired}) == 1
    with pytest.raises(ValueError, match="multiple effort policies"):
        _header(
            scope=CampaignScope.REASONING_EFFORT_SENSITIVITY,
            tasks=tasks,
            model_set=model_set,
            repetition_count=1,
        )
    with pytest.raises(ValueError, match="every reasoning-qualified route"):
        _header(
            scope=CampaignScope.REASONING_EFFORT_SENSITIVITY,
            tasks=tasks,
            model_set=model_set,
            repetition_count=1,
            reasoning_efforts=("high", "max"),
            route_ids=(routes[0].route_id,),
        )


def test_campaign_report_preserves_requested_and_reported_service_tiers(
    tmp_path: Path,
) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "service-tier")
    runner.record_outcome(
        trial_id=runner.schedule.trials[0].trial_id,
        outcome=_complete_outcome(
            runner,
            0,
            successful=True,
            stage_id=tasks[0].evaluator_stage_ids[0],
            provider_reported_service_tier="default",
        ),
    )

    report = runner.build_report()
    accounting = report.service_tier_accounting
    assert tuple(
        (item.service_tier, item.count) for item in accounting.requested_service_tiers
    ) == (("fast", 1),)
    assert tuple(
        (item.service_tier, item.count) for item in accounting.provider_reported_service_tiers
    ) == (("default", 1),)
    assert accounting.unknown_attempts == 0
    assert accounting.reported_tier_mismatches == CountRatio(numerator=1, denominator=1)
    assert report.overall_success == CountRatio(numerator=1, denominator=1)


def test_public_calibration_is_excluded_from_every_paid_campaign_scope() -> None:
    routes = (
        _route(
            "frontier-route",
            (ModelCategory.FRONTIER_REASONING, ModelCategory.CODING_AGENT),
        ),
        _route(
            "economy-route",
            (ModelCategory.BALANCED, ModelCategory.HIGH_THROUGHPUT),
        ),
    )
    model_set = _model_set(*routes)
    origin = PublicCalibrationTaskOrigin(
        source_id="rtllm",
        source_snapshot_digest=_digest("rtllm-source-snapshot"),
        source_resource_ids=("benchmark_source",),
        license_spdx_expression="Apache-2.0",
        redistribution=Redistribution.ALLOWED,
        provenance=("https://github.com/hkust-zhiyao/rtllm",),
    )
    tasks = tuple(task.model_copy(update={"task_origin": origin}) for task in _tasks())
    for scope in CampaignScope:
        with pytest.raises(ValueError, match="native sealed"):
            _header(
                scope=scope,
                tasks=tasks,
                model_set=model_set,
                repetition_count=1,
                route_ids=(routes[0].route_id,)
                if scope is CampaignScope.END_TO_END_SMOKE
                else None,
                reasoning_efforts=("high", "max")
                if scope is CampaignScope.REASONING_EFFORT_SENSITIVITY
                else ("high",),
            )


def test_unknown_provider_usage_is_retained_and_stops_further_dispatch(
    tmp_path: Path,
) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "accounting")
    trial = runner.schedule.trials[0]

    first = runner.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="solve",
        requested_model=trial.binding.requested_model,
        token_claim=RequestTokenClaim(input_tokens=10, output_tokens=5),
        security_binding=_security_binding(runner),
    )
    assert first.attempt_number == 1
    first.mark_dispatched()
    first.settle_provider(
        disposition=AttemptDisposition.RETRYABLE_FAILURE,
        usage=None,
        failure_condition=RetryCondition.CONNECT_FAILURE,
    )
    with pytest.raises(CampaignAccountingError, match="poisoned"):
        runner.reserve_provider_attempt(
            trial_id=trial.trial_id,
            request_key="solve",
            requested_model=trial.binding.requested_model,
            token_claim=RequestTokenClaim(input_tokens=9, output_tokens=5),
            security_binding=_security_binding(runner),
        )
    with pytest.raises(CampaignAccountingError, match="poisoned"):
        runner.reserve_work(
            trial_id=trial.trial_id,
            claim=CampaignResources(tool_calls=1),
        )

    runner.record_outcome(
        trial_id=trial.trial_id,
        outcome=TrialRunOutcome(
            disposition=TrialDisposition.FAILED_BEFORE_RUN,
            terminal_reason=StopReason.INFRASTRUCTURE_FAILURE,
            provider_spend=UnknownSpend(reason=UnknownSpendReason.PROVIDER_REPORTING_INCOMPLETE),
        ),
    )
    report = runner.build_report()

    assert report.overall_success.model_dump() == {"numerator": 0, "denominator": 1}
    assert report.budget_violation is True
    assert report.resources == CampaignResources(requests=1, input_tokens=10, output_tokens=5)
    assert report.token_accounting.request_attempts == 1
    assert report.token_accounting.provider_input_tokens == 0
    assert report.token_accounting.unknown_usage_attempts == 1
    assert report.trials[0].provider_attempts[0].disposition is (
        AttemptDisposition.RETRYABLE_FAILURE
    )


def test_report_requires_every_trial_and_aggregates_failures_without_selection(
    tmp_path: Path,
) -> None:
    routes = (
        _route(
            "frontier-route",
            (ModelCategory.FRONTIER_REASONING, ModelCategory.CODING_AGENT),
        ),
        _route(
            "economy-route",
            (ModelCategory.BALANCED, ModelCategory.HIGH_THROUGHPUT),
        ),
    )
    model_set = _model_set(*routes)
    tasks = _tasks()
    header = _header(
        scope=CampaignScope.COMMON_CORE, tasks=tasks, model_set=model_set, repetition_count=3
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "report")

    with pytest.raises(CampaignAccountingError, match="every scheduled trial"):
        runner.build_report()

    for trial_index, trial in enumerate(runner.schedule.trials):
        binding = trial.binding
        successful = (
            binding.route_id == "frontier-route"
            and binding.task_family == "task-family-0"
            and binding.repetition_index == 1
        ) or (
            binding.route_id == "economy-route"
            and binding.task_family == "task-family-1"
            and binding.repetition_index == 0
        )
        runner.record_outcome(
            trial_id=trial.trial_id,
            outcome=_complete_outcome(
                runner,
                trial_index,
                successful=successful,
                stage_id=f"verify-{binding.task_family[-1]}",
                include_stage=binding.repetition_index != 2,
            ),
        )

    report = runner.build_report()

    assert len(report.trials) == 48
    assert report.overall_success.model_dump() == {"numerator": 2, "denominator": 48}
    assert {item.success.denominator for item in report.task_aggregates} == {6}
    assert {item.success.denominator for item in report.device_aggregates} == {6}
    assert {item.success.denominator for item in report.model_aggregates} == {24}
    assert {item.success.denominator for item in report.cell_aggregates} == {24}
    assert report.spend.unknown_trial_count == 48
    assert report.terminal_reasons[0].count + report.terminal_reasons[1].count == 48

    success_rows = {
        (item.route_id, item.reasoning_effort, item.k): item.success.numerator
        for item in report.success_at_k
    }
    assert success_rows[("frontier-route", "high", 1)] == 0
    assert success_rows[("frontier-route", "high", 2)] == 1
    assert success_rows[("frontier-route", "high", 3)] == 1
    assert success_rows[("economy-route", "high", 1)] == 1
    assert success_rows[("economy-route", "high", 3)] == 1
    assert all(item.reached.denominator == 6 for item in report.evaluator_funnel)
    verify_rows = [item for item in report.evaluator_funnel if item.stage_id.startswith("verify")]
    assert {item.reached.numerator for item in verify_rows} == {4}
    assert sum(item.passed.numerator for item in verify_rows) == 2


def test_global_wall_budget_rejects_before_cross_trial_dispatch(tmp_path: Path) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(2)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH,
        tasks=tasks,
        model_set=model_set,
        repetition_count=1,
        max_wall_seconds=10,
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "wall")
    first, second = runner.schedule.trials

    reservation = runner.reserve_work(
        trial_id=first.trial_id,
        claim=CampaignResources(wall_seconds=6),
    )
    reservation.mark_dispatched()
    reservation.settle_work(CampaignResources(wall_seconds=6))

    with pytest.raises(CampaignBudgetExceeded) as rejected:
        runner.reserve_work(
            trial_id=second.trial_id,
            claim=CampaignResources(wall_seconds=5),
        )
    assert rejected.value.dimension is BudgetDimension.WALL_SECONDS
    assert rejected.value.per_trial is False
    assert rejected.value.stop_reason is StopReason.WALL_BUDGET
    with pytest.raises(CampaignBudgetExceeded) as stopped:
        runner.reserve_work(
            trial_id=second.trial_id,
            claim=CampaignResources(artifact_bytes=1),
        )
    assert stopped.value.dimension is BudgetDimension.WALL_SECONDS

    runner.stop_unfinished(StopReason.WALL_BUDGET)
    report = runner.build_report()
    assert len(report.trials) == 2
    assert report.trials[0].outcome.disposition is TrialDisposition.FAILED_BEFORE_RUN
    assert report.trials[1].outcome.disposition is TrialDisposition.NOT_DISPATCHED


def test_provider_usage_overrun_is_retained_and_poisoned(tmp_path: Path) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "overrun")
    trial = runner.schedule.trials[0]
    reservation = runner.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="solve",
        requested_model=trial.binding.requested_model,
        token_claim=RequestTokenClaim(input_tokens=5, output_tokens=5),
        security_binding=_security_binding(runner),
    )
    reservation.mark_dispatched()

    with pytest.raises(ProviderBudgetOverrun, match="exceeded"):
        reservation.settle_provider(
            disposition=AttemptDisposition.COMPLETED,
            usage=ProviderUsage(input_tokens=6, output_tokens=1, total_tokens=7),
            provider_reported_model="observed-shared-route",
            provider_response_status=ProviderResponseStatus.COMPLETED,
        )
    with pytest.raises(CampaignAccountingError, match="poisoned"):
        runner.reserve_work(
            trial_id=trial.trial_id,
            claim=CampaignResources(tool_calls=1),
        )

    runner.record_outcome(
        trial_id=trial.trial_id,
        outcome=TrialRunOutcome(
            disposition=TrialDisposition.FAILED_BEFORE_RUN,
            terminal_reason=StopReason.TOKEN_BUDGET,
            provider_spend=UnknownSpend(reason=UnknownSpendReason.PROVIDER_REPORTING_INCOMPLETE),
        ),
    )
    report = runner.build_report()
    assert report.budget_violation is True
    assert report.resources.input_tokens == 6
    assert report.trials[0].provider_attempts[0].provider_usage is not None
    assert report.trials[0].provider_attempts[0].provider_usage.input_tokens == 6


def test_concurrent_provider_reservations_cannot_cross_the_global_cap(tmp_path: Path) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH,
        tasks=tasks,
        model_set=model_set,
        repetition_count=1,
        max_requests=4,
        episode_max_requests=4,
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "concurrent")
    trial = runner.schedule.trials[0]

    def reserve(index: int) -> CampaignReservation | None:
        try:
            return runner.reserve_provider_attempt(
                trial_id=trial.trial_id,
                request_key=f"request-{index}",
                requested_model=trial.binding.requested_model,
                token_claim=RequestTokenClaim(input_tokens=1, output_tokens=1),
                security_binding=_security_binding(runner),
            )
        except CampaignBudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = tuple(pool.map(reserve, range(8)))
    accepted = tuple(result for result in results if result is not None)

    assert len(accepted) == 4
    for reservation in accepted:
        reservation.cancel()


def test_provider_budget_adapter_keeps_campaign_runner_as_accounting_owner(
    tmp_path: Path,
) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "budget-adapter")
    budget = CampaignProviderBudget(runner)
    trial = runner.schedule.trials[0]

    with pytest.raises(CampaignAccountingError, match="frozen trial route"):
        budget.reserve_provider_attempt(
            trial_id=trial.trial_id,
            request_key="wrong-route",
            requested_model="different-route",
            token_claim=RequestTokenClaim(input_tokens=10, output_tokens=10),
            security_binding=_security_binding(runner),
        )
    reservation = budget.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="solve",
        requested_model=trial.binding.requested_model,
        token_claim=RequestTokenClaim(input_tokens=10, output_tokens=10),
        security_binding=_security_binding(runner),
    )
    reservation.mark_dispatched()
    reservation.settle_completed(
        usage=ProviderUsage(input_tokens=7, output_tokens=3, total_tokens=10),
        provider_reported_model="observed-shared-route",
        provider_response_status=ProviderResponseStatus.COMPLETED,
    )
    runner.record_outcome(
        trial_id=trial.trial_id,
        outcome=_complete_outcome(
            runner,
            0,
            successful=True,
            stage_id=tasks[0].evaluator_stage_ids[0],
            request_key="solve",
            token_claim=RequestTokenClaim(input_tokens=10, output_tokens=10),
            provider_usage=ProviderUsage(input_tokens=7, output_tokens=3, total_tokens=10),
            provider_reported_model="observed-shared-route",
        ),
    )

    report = runner.build_report()
    assert budget.campaign_digest == header.campaign.digest
    assert budget.binding_digest == runner.budget_projection().digest
    assert report.resources.requests == 1
    assert report.resources.input_tokens == 7
    assert report.resources.output_tokens == 3
    assert len(report.trials[0].provider_attempts) == 1


def test_campaign_restart_recovers_a_dispatched_attempt_from_durable_events(
    tmp_path: Path,
) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    state_root = tmp_path / "restart"
    first = CampaignRunner(header=header, state_root=state_root)
    trial = first.schedule.trials[0]
    reservation = first.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="interrupted-request",
        requested_model=trial.binding.requested_model,
        token_claim=RequestTokenClaim(input_tokens=11, output_tokens=7),
        security_binding=_security_binding(first),
    )
    reservation.mark_dispatched()

    resumed = CampaignRunner(header=header, state_root=state_root)
    with pytest.raises(CampaignAccountingError, match="dispatch"):
        resumed.build_report()
    recovered = resumed.recover_incomplete_dispatches()
    assert len(recovered.reservation_ids) == 1
    assert recovered.affected_trial_ids == (trial.trial_id,)
    resumed.record_outcome(
        trial_id=trial.trial_id,
        outcome=TrialRunOutcome(
            disposition=TrialDisposition.FAILED_BEFORE_RUN,
            terminal_reason=StopReason.INFRASTRUCTURE_FAILURE,
            provider_spend=UnknownSpend(reason=UnknownSpendReason.PROVIDER_REPORTING_INCOMPLETE),
        ),
    )
    report = resumed.build_report()

    assert report.resources == CampaignResources(requests=1, input_tokens=11, output_tokens=7)
    assert report.trials[0].provider_attempts[0].disposition is AttemptDisposition.TERMINAL_FAILURE
    assert report.trials[0].provider_attempts[0].provider_usage is None
    assert report.campaign_record_digest == resumed.journal.record().integrity_digest
    assert report.provider_profile == _provider_config().profile
    assert report.provider_profile_digest == _provider_config().profile.digest
    assert report.provider_config_digest == _provider_config().digest
    assert report.model_set_digest == model_set.digest
    tampered_report = report.model_dump(mode="python")
    tampered_report["schedule_digest"] = _digest("different-schedule")
    with pytest.raises(ValueError, match="schedule digest"):
        type(report).model_validate(tampered_report)

    reopened = CampaignRunner(header=header, state_root=state_root)
    assert reopened.build_report() == report


def test_completed_outcome_requires_the_exact_scheduled_run_binding(tmp_path: Path) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "binding")
    trial = runner.schedule.trials[0]
    valid = _run_binding(runner, 0)
    assert valid.campaign is not None
    with pytest.raises(ValueError, match="only completed runs"):
        TrialRunOutcome(
            disposition=TrialDisposition.FAILED_BEFORE_RUN,
            terminal_reason=StopReason.INFRASTRUCTURE_FAILURE,
            run_id=valid.digest,
            provider_spend=UnknownSpend(reason=UnknownSpendReason.PROVIDER_REPORTING_INCOMPLETE),
        )
    wrong_environment = RunBinding.model_validate(
        {
            **valid.model_dump(mode="python"),
            "environment": {
                **valid.environment.model_dump(mode="python"),
                "environment_spec_digest": _digest("wrong-environment"),
            },
        }
    )
    wrong_seed = RunBinding.model_validate(
        {
            **valid.model_dump(mode="python"),
            "campaign": {
                **valid.campaign.model_dump(mode="python"),
                "paired_seed": _seed(99),
            },
        }
    )
    wrong_harness = RunBinding.model_validate(
        {
            **valid.model_dump(mode="python"),
            "session": {
                **valid.session.model_dump(mode="python"),
                "actors": (
                    {
                        **valid.session.actors[0].model_dump(mode="python"),
                        "harness_digest": _digest("wrong-harness"),
                    },
                ),
            },
        }
    )
    for binding in (wrong_environment, wrong_seed, wrong_harness):
        with pytest.raises(ValueError, match=r"scheduled campaign trial|run harness"):
            runner.record_outcome(
                trial_id=trial.trial_id,
                outcome=TrialRunOutcome(
                    disposition=TrialDisposition.COMPLETED_RUN,
                    terminal_reason=StopReason.EXPLICIT_CANCEL,
                    run_id=binding.digest,
                    run_binding=binding,
                    provider_spend=UnknownSpend(
                        reason=UnknownSpendReason.PROVIDER_REPORTING_UNAVAILABLE
                    ),
                ),
            )

    runner.record_outcome(
        trial_id=trial.trial_id,
        outcome=_complete_outcome(
            runner,
            0,
            successful=True,
            stage_id=tasks[0].evaluator_stage_ids[0],
        ),
    )
    assert runner.build_report().overall_success.numerator == 1


def test_paid_campaign_requires_metered_harness_and_matching_provider_facts(
    tmp_path: Path,
) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    runner = CampaignRunner(header=header, state_root=tmp_path / "metered-harness")
    trial = runner.schedule.trials[0]
    reservation = runner.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="solve",
        requested_model=trial.binding.requested_model,
        token_claim=RequestTokenClaim(input_tokens=4, output_tokens=2),
        security_binding=_security_binding(runner),
    )
    reservation.mark_dispatched()
    usage = ProviderUsage(input_tokens=3, output_tokens=1, total_tokens=4)
    reported = "observed-shared-route"
    reservation.settle_provider(
        disposition=AttemptDisposition.COMPLETED,
        usage=usage,
        provider_reported_model=reported,
        provider_response_status=ProviderResponseStatus.COMPLETED,
    )
    valid = _complete_outcome(
        runner,
        0,
        successful=True,
        stage_id=tasks[0].evaluator_stage_ids[0],
        request_key="solve",
        token_claim=RequestTokenClaim(input_tokens=4, output_tokens=2),
        provider_usage=usage,
        provider_reported_model=reported,
    )
    with pytest.raises(ValueError, match="metered provider request facts"):
        runner.record_outcome(
            trial_id=trial.trial_id,
            outcome=valid.model_copy(update={"provider_requests": ()}),
        )
    request = valid.provider_requests[0]
    tampered = valid.model_copy(
        update={
            "provider_requests": (
                request.model_copy(update={"provider_config_digest": _digest("unmetered-config")}),
            )
        }
    )

    with pytest.raises(ValueError, match="provider request identity"):
        runner.record_outcome(trial_id=trial.trial_id, outcome=tampered)

    for update in (
        {"reserved_input_tokens": 5},
        {"status": ProviderResponseStatus.FAILED},
    ):
        with pytest.raises(ValueError, match=r"provider (reservation|response)"):
            runner.record_outcome(
                trial_id=trial.trial_id,
                outcome=valid.model_copy(
                    update={
                        "provider_requests": (request.model_copy(update=update),),
                    }
                ),
            )

    runner.record_outcome(trial_id=trial.trial_id, outcome=valid)
    assert runner.build_report().overall_success.numerator == 1


def test_campaign_journal_recovers_a_torn_tail_and_rejects_durable_tampering(
    tmp_path: Path,
) -> None:
    route = _route(
        "shared-route",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
    )
    model_set = _model_set(route)
    tasks = _tasks(1)
    header = _header(
        scope=CampaignScope.EXPANDED_BREADTH, tasks=tasks, model_set=model_set, repetition_count=1
    )
    state_root = tmp_path / "torn-tail"
    runner = CampaignRunner(header=header, state_root=state_root)
    trial = runner.schedule.trials[0]
    runner.reserve_work(
        trial_id=trial.trial_id,
        claim=CampaignResources(tool_calls=1),
    )
    durable = runner.journal.events_path.read_bytes()
    with runner.journal.events_path.open("ab") as stream:
        stream.write(b'{"torn"')
        stream.flush()

    resumed = CampaignRunner(header=header, state_root=state_root)
    resumed.recover_incomplete_dispatches()
    recovered_bytes = resumed.journal.events_path.read_bytes()
    assert recovered_bytes.startswith(durable)
    assert b'{"torn"' not in recovered_bytes
    first_record_end = recovered_bytes.index(b"\n")
    tampered = bytearray(recovered_bytes)
    position = recovered_bytes.index(b"reservation", 0, first_record_end)
    tampered[position] = ord("x")
    resumed.journal.events_path.write_bytes(tampered)
    with pytest.raises(CampaignJournalCorruption):
        resumed.journal.record()


def test_cells_keep_harness_denominators_and_lineage_pairing_separate(tmp_path: Path) -> None:
    model_set = _model_set(_route("shared-route", tuple(ModelCategory)))
    tasks = tuple(task.model_copy(update={"task_family": "shared-lineage"}) for task in _tasks(2))
    base = _header(
        scope=CampaignScope.EXPANDED_BREADTH,
        tasks=tasks,
        model_set=model_set,
        repetition_count=2,
    )
    harness = base.cells[0].harness
    alternate = harness.model_copy(update={"harness_id": "alternate-harness"})
    header = campaign_header(
        campaign_id=base.campaign.campaign_id,
        scope=base.campaign.scope,
        model_set=model_set,
        provider_config=base.provider_config,
        tasks=tasks,
        cells=campaign_cells(
            model_set=model_set,
            harnesses=(harness, alternate),
            feedback_policy_digest=base.cells[0].policy.feedback_policy_digest,
        ),
        episode_budget=base.benchmark.episode_budget,
        repetition_count=base.benchmark.repetition_count,
        schedule_seed=base.benchmark.schedule_seed,
        retry_policy=base.campaign.retry_policy,
        token_limits=base.campaign.token_limits,
        execution_limits=base.campaign.execution_limits,
        provider_spend_limit=base.campaign.provider_spend_limit,
    )
    assert tuple(trial.binding.evaluation for trial in header.schedule.trials) == (
        build_benchmark_schedule(header.benchmark).entries
    )
    for repetition in range(2):
        paired = [
            trial.binding
            for trial in header.schedule.trials
            if trial.binding.repetition_index == repetition
        ]
        assert len(paired) == 4
        assert len({binding.paired_seed for binding in paired}) == 1
        assert len({binding.task_instance_digest for binding in paired}) == 2
        assert len({binding.cell_id for binding in paired}) == 2
    runner = CampaignRunner(header=header, state_root=tmp_path / "cells")
    stages = {task.task_release_digest: task.evaluator_stage_ids[0] for task in tasks}
    for index, trial in enumerate(header.schedule.trials):
        runner.record_outcome(
            trial_id=trial.trial_id,
            outcome=_complete_outcome(
                runner,
                index,
                successful=trial.binding.harness_digest == harness.digest,
                stage_id=stages[trial.binding.task_release_digest],
            ),
        )
    report = runner.build_report()
    assert {
        (row.harness_digest, row.success.numerator, row.success.denominator)
        for row in report.cell_aggregates
    } == {
        (harness.digest, 4, 4),
        (alternate.digest, 0, 4),
    }
    assert len(report.success_at_k) == 4
    assert {row.success.denominator for row in report.success_at_k} == {2}
    assert {row.cell_id for row in report.success_at_k} == {
        cell.definition.cell_id for cell in header.cells
    }
    tampered = report.model_dump(mode="python")
    tampered["cell_aggregates"] = (report.cell_aggregates[0],)
    with pytest.raises(ValueError, match="cell aggregates"):
        type(report).model_validate(tampered)

    # A campaign cap cannot silently lower the benchmark's solving allowance.
    campaign = header.campaign.model_copy(
        update={
            "execution_limits": header.campaign.execution_limits.model_copy(update={"max_turns": 3})
        }
    )
    schedule = build_campaign_schedule(campaign, model_set, tasks, header.benchmark, header.cells)
    with pytest.raises(ValueError, match="per-trial turns limit"):
        CampaignHeader(
            campaign=campaign,
            benchmark=header.benchmark,
            cells=header.cells,
            model_set=model_set,
            provider_config=header.provider_config,
            tasks=tasks,
            schedule=schedule,
        )
