"""Mechanical aggregate projections over durable campaign trial reports."""

from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal

from edagym.evaluation.model import OutcomeKind
from edagym.providers.campaign import ModelCategory, ModelRoute
from edagym.providers.campaign_budget import (
    CampaignAccountingError,
    CampaignResources,
    _MutableResources,
)
from edagym.providers.campaign_runner import (
    CampaignRecord,
    CampaignReport,
    CellAggregate,
    CountRatio,
    CurrencyTotal,
    DeviceAggregate,
    EvaluatorFunnel,
    KnownSpend,
    ModelAggregate,
    ModelCategoryAggregate,
    ProviderAttemptRecord,
    ReportedModelCount,
    ServiceTierAccounting,
    ServiceTierCount,
    SpendSummary,
    StageOutcomeCount,
    SuccessAtK,
    TaskAggregate,
    TerminalReasonCount,
    TokenAccounting,
    TrialReport,
)
from edagym.providers.campaign_schedule import CampaignHeader, CampaignTask
from edagym.specs.common import Capability, Digest

_SUCCESSFUL_STAGE_OUTCOMES = frozenset({OutcomeKind.PASSED, OutcomeKind.PROVED})


def project_campaign_report(record: CampaignRecord) -> CampaignReport:
    """Replay one terminal durable record into its only valid report."""

    from edagym.providers.campaign_replay import replay_campaign_record

    state = replay_campaign_record(record)
    if state.reservations:
        raise CampaignAccountingError("campaign report requires every dispatch to settle")
    missing = [
        trial.trial_id
        for trial in record.header.schedule.trials
        if state.ledgers[trial.trial_id].outcome is None
    ]
    if missing:
        raise CampaignAccountingError(
            "campaign report requires an outcome for every scheduled trial"
        )
    reports: list[TrialReport] = []
    for trial in record.header.schedule.trials:
        ledger = state.ledgers[trial.trial_id]
        if ledger.outcome is None:
            raise CampaignAccountingError("campaign trial outcome is unavailable")
        attempts = tuple(ledger.attempts)
        reports.append(
            TrialReport(
                trial=trial,
                outcome=ledger.outcome,
                resources=ledger.committed.snapshot(),
                token_accounting=token_accounting(attempts),
                provider_attempts=attempts,
                accounting_violation=ledger.accounting_violation,
            )
        )
    return build_campaign_report(
        record.header,
        tuple(reports),
        record_digest=record.integrity_digest,
        budget_violation=state.budget_violation,
        committed_resources=state.committed.snapshot(),
    )


def build_campaign_report(
    header: CampaignHeader,
    trial_reports: tuple[TrialReport, ...],
    *,
    record_digest: Digest,
    budget_violation: bool,
    committed_resources: CampaignResources,
) -> CampaignReport:
    task_by_release = {task.task_release_digest: task for task in header.tasks}
    route_by_id = {route.route_id: route for route in header.model_set.routes}
    task_groups: defaultdict[str, list[TrialReport]] = defaultdict(list)
    device_groups: defaultdict[Capability, list[TrialReport]] = defaultdict(list)
    route_groups: defaultdict[str, list[TrialReport]] = defaultdict(list)
    for report in trial_reports:
        binding = report.trial.binding
        task_groups[binding.task_release_digest].append(report)
        device_groups[binding.device_capability].append(report)
        route_groups[binding.route_id].append(report)

    task_aggregates = tuple(
        TaskAggregate(
            task_release_digest=release,
            task_family=task_by_release[release].task_family,
            task_role=task_by_release[release].role,
            success=success_ratio(group),
            resources=aggregate_resources(group),
            token_accounting=token_accounting(all_attempts(group)),
            terminal_reasons=terminal_reason_counts(group),
            spend=spend_summary(group),
        )
        for release, group in sorted(task_groups.items())
    )
    device_aggregates = tuple(
        DeviceAggregate(
            device_capability=capability,
            success=success_ratio(group),
            resources=aggregate_resources(group),
            token_accounting=token_accounting(all_attempts(group)),
            terminal_reasons=terminal_reason_counts(group),
            spend=spend_summary(group),
        )
        for capability, group in sorted(device_groups.items(), key=lambda item: item[0])
    )
    model_aggregates = tuple(
        _model_aggregate(route_by_id[route_id], group)
        for route_id, group in sorted(route_groups.items())
    )
    cell_groups = _cell_groups(trial_reports)
    cell_aggregates = tuple(_cell_aggregate(group) for group in cell_groups.values())
    category_aggregates = tuple(
        _category_aggregate(category, header, trial_reports)
        for category in sorted(
            {category for route in header.model_set.routes for category in route.categories}
        )
    )
    attempts = all_attempts(trial_reports)
    return CampaignReport(
        campaign_digest=header.campaign.digest,
        benchmark_spec_digest=header.benchmark.digest,
        schedule_digest=header.schedule.digest,
        campaign_record_digest=record_digest,
        campaign_scope=header.campaign.scope,
        provider_profile=header.provider_config.profile,
        provider_profile_digest=header.provider_config.profile.digest,
        provider_config_digest=header.provider_config.digest,
        model_set_digest=header.model_set.digest,
        budget_violation=budget_violation,
        trials=trial_reports,
        overall_success=success_ratio(trial_reports),
        task_aggregates=task_aggregates,
        device_aggregates=device_aggregates,
        model_aggregates=model_aggregates,
        cell_aggregates=cell_aggregates,
        model_category_aggregates=category_aggregates,
        success_at_k=_success_at_k(header, cell_groups),
        evaluator_funnel=_evaluator_funnel(header, task_by_release, task_groups),
        terminal_reasons=terminal_reason_counts(trial_reports),
        resources=committed_resources,
        token_accounting=token_accounting(attempts),
        service_tier_accounting=service_tier_accounting(attempts),
        spend=spend_summary(trial_reports),
    )


def _model_aggregate(route: ModelRoute, reports: list[TrialReport]) -> ModelAggregate:
    labels = Counter(
        attempt.provider_reported_model
        for report in reports
        for attempt in report.provider_attempts
        if attempt.provider_reported_model is not None
    )
    attempts = [attempt for report in reports for attempt in report.provider_attempts]
    known = sum(labels.values())
    mismatches = sum(count for label, count in labels.items() if label != route.requested_model)
    return ModelAggregate(
        route_id=route.route_id,
        requested_model=route.requested_model,
        qualified_provider_reported_model=route.provider_reported_model,
        reference_kind=route.reference_kind,
        categories=route.categories,
        observed_provider_reported_models=tuple(
            ReportedModelCount(provider_reported_model=label, count=count)
            for label, count in sorted(labels.items())
        ),
        unknown_reported_model_attempts=len(attempts) - known,
        reported_label_mismatches=CountRatio(numerator=mismatches, denominator=known),
        success=success_ratio(reports),
        resources=aggregate_resources(reports),
        token_accounting=token_accounting(all_attempts(reports)),
        terminal_reasons=terminal_reason_counts(reports),
        spend=spend_summary(reports),
    )


def _cell_groups(
    reports: tuple[TrialReport, ...],
) -> dict[str, list[TrialReport]]:
    groups: defaultdict[str, list[TrialReport]] = defaultdict(list)
    for report in reports:
        groups[report.trial.binding.cell_id].append(report)
    return dict(sorted(groups.items()))


def _cell_aggregate(reports: list[TrialReport]) -> CellAggregate:
    binding = reports[0].trial.binding
    return CellAggregate(
        cell_id=binding.cell_id,
        harness_digest=binding.harness_digest,
        policy_digest=binding.evaluation_cell.policy.digest,
        route_id=binding.route_id,
        requested_model=binding.requested_model,
        reasoning_effort=binding.reasoning_effort,
        success=success_ratio(reports),
        resources=aggregate_resources(reports),
        token_accounting=token_accounting(all_attempts(reports)),
        terminal_reasons=terminal_reason_counts(reports),
        spend=spend_summary(reports),
    )


def _category_aggregate(
    category: ModelCategory,
    header: CampaignHeader,
    reports: tuple[TrialReport, ...],
) -> ModelCategoryAggregate:
    routes = tuple(
        route.route_id for route in header.model_set.routes if category in route.categories
    )
    route_set = set(routes)
    group = [report for report in reports if report.trial.binding.route_id in route_set]
    return ModelCategoryAggregate(
        category=category,
        route_ids=routes,
        success=success_ratio(group),
        resources=aggregate_resources(group),
        token_accounting=token_accounting(all_attempts(group)),
        terminal_reasons=terminal_reason_counts(group),
        spend=spend_summary(group),
    )


def _success_at_k(
    header: CampaignHeader,
    cell_groups: dict[str, list[TrialReport]],
) -> tuple[SuccessAtK, ...]:
    rows: list[SuccessAtK] = []
    for cell_id, reports in cell_groups.items():
        binding = reports[0].trial.binding
        by_task: defaultdict[str, list[TrialReport]] = defaultdict(list)
        for report in reports:
            by_task[report.trial.binding.task_instance_digest].append(report)
        for group in by_task.values():
            group.sort(key=lambda report: report.trial.binding.repetition_index)
        for k in range(1, header.benchmark.repetition_count + 1):
            successes = sum(
                any(report.success for report in group[:k]) for group in by_task.values()
            )
            rows.append(
                SuccessAtK(
                    cell_id=cell_id,
                    route_id=binding.route_id,
                    requested_model=binding.requested_model,
                    reasoning_effort=binding.reasoning_effort,
                    k=k,
                    success=CountRatio(numerator=successes, denominator=len(by_task)),
                )
            )
    return tuple(rows)


def _evaluator_funnel(
    header: CampaignHeader,
    task_by_release: dict[str, CampaignTask],
    task_groups: defaultdict[str, list[TrialReport]],
) -> tuple[EvaluatorFunnel, ...]:
    rows: list[EvaluatorFunnel] = []
    for release, reports in sorted(task_groups.items()):
        task = task_by_release[release]
        for stage_id in task.evaluator_stage_ids:
            reached = 0
            passed = 0
            outcomes: Counter[OutcomeKind] = Counter()
            for report in reports:
                matching = [
                    item.result.outcome.kind
                    for item in report.outcome.stage_results
                    if item.result.stage_id == stage_id
                ]
                if matching:
                    reached += 1
                    passed += any(kind in _SUCCESSFUL_STAGE_OUTCOMES for kind in matching)
                    outcomes.update(matching)
            rows.append(
                EvaluatorFunnel(
                    task_release_digest=release,
                    task_family=task.task_family,
                    stage_id=stage_id,
                    reached=CountRatio(numerator=reached, denominator=len(reports)),
                    passed=CountRatio(numerator=passed, denominator=len(reports)),
                    outcome_counts=tuple(
                        StageOutcomeCount(outcome=outcome, evaluation_count=count)
                        for outcome, count in sorted(outcomes.items(), key=lambda item: item[0])
                    ),
                )
            )
    return tuple(rows)


def success_ratio(reports: list[TrialReport] | tuple[TrialReport, ...]) -> CountRatio:
    return CountRatio(
        numerator=sum(report.success for report in reports),
        denominator=len(reports),
    )


def all_attempts(
    reports: list[TrialReport] | tuple[TrialReport, ...],
) -> tuple[ProviderAttemptRecord, ...]:
    return tuple(attempt for report in reports for attempt in report.provider_attempts)


def aggregate_resources(
    reports: list[TrialReport] | tuple[TrialReport, ...],
) -> CampaignResources:
    totals = _MutableResources()
    for report in reports:
        totals.add(report.resources)
    return totals.snapshot()


def terminal_reason_counts(
    reports: list[TrialReport] | tuple[TrialReport, ...],
) -> tuple[TerminalReasonCount, ...]:
    counts = Counter(report.outcome.terminal_reason for report in reports)
    return tuple(
        TerminalReasonCount(reason=reason, count=count)
        for reason, count in sorted(counts.items(), key=lambda item: item[0])
    )


def token_accounting(attempts: tuple[ProviderAttemptRecord, ...]) -> TokenAccounting:
    usage = [attempt.provider_usage for attempt in attempts]
    known = [item for item in usage if item is not None]
    return TokenAccounting(
        request_attempts=len(attempts),
        retry_attempts=sum(attempt.attempt_number > 1 for attempt in attempts),
        charged_input_tokens=sum(attempt.charged_resources.input_tokens for attempt in attempts),
        charged_output_tokens=sum(attempt.charged_resources.output_tokens for attempt in attempts),
        provider_input_tokens=sum(item.input_tokens for item in known),
        provider_output_tokens=sum(item.output_tokens for item in known),
        unknown_usage_attempts=sum(item is None for item in usage),
        cached_input_tokens=sum(
            item.cached_input_tokens for item in known if item.cached_input_tokens is not None
        ),
        unknown_cached_usage_attempts=sum(
            item is None or item.cached_input_tokens is None for item in usage
        ),
        reasoning_tokens=sum(
            item.reasoning_tokens for item in known if item.reasoning_tokens is not None
        ),
        unknown_reasoning_usage_attempts=sum(
            item is None or item.reasoning_tokens is None for item in usage
        ),
    )


def service_tier_accounting(
    attempts: tuple[ProviderAttemptRecord, ...],
) -> ServiceTierAccounting:
    requested = Counter(attempt.requested_service_tier for attempt in attempts)
    reported = Counter(
        attempt.provider_reported_service_tier
        for attempt in attempts
        if attempt.provider_reported_service_tier is not None
    )
    known = sum(reported.values())
    mismatches = sum(
        attempt.provider_reported_service_tier is not None
        and attempt.provider_reported_service_tier != attempt.requested_service_tier
        for attempt in attempts
    )
    return ServiceTierAccounting(
        requested_service_tiers=tuple(
            ServiceTierCount(service_tier=tier, count=count)
            for tier, count in sorted(requested.items())
        ),
        provider_reported_service_tiers=tuple(
            ServiceTierCount(service_tier=tier, count=count)
            for tier, count in sorted(reported.items())
        ),
        unknown_attempts=len(attempts) - known,
        reported_tier_mismatches=CountRatio(numerator=mismatches, denominator=known),
    )


def spend_summary(
    reports: list[TrialReport] | tuple[TrialReport, ...],
) -> SpendSummary:
    totals: defaultdict[str, Decimal] = defaultdict(Decimal)
    unknown = 0
    for report in reports:
        spend = report.outcome.provider_spend
        if isinstance(spend, KnownSpend):
            totals[spend.currency] += spend.amount
        else:
            unknown += 1
    return SpendSummary(
        known_totals=tuple(
            CurrencyTotal(currency=currency, amount=amount)
            for currency, amount in sorted(totals.items())
        ),
        unknown_trial_count=unknown,
    )
