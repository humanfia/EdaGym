"""Quality report construction and explicit incomplete-state reporting."""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal

from edagym.benchmark.model import (
    BenchmarkPhase,
    BenchmarkQualityReport,
    BenchmarkSpec,
    ContrastKind,
    DifficultyContrast,
    EvaluationCell,
    InformationStatus,
    ModelContrast,
    TrialObservation,
)
from edagym.benchmark.schedule import build_benchmark_schedule
from edagym.benchmark.statistics import compute_paired_contrasts, compute_quality_gate
from edagym.specs.release import TaskInstance


def build_quality_report(
    spec: BenchmarkSpec,
    observations: tuple[TrialObservation, ...],
    *,
    framework_ready: bool,
    station_campaign_complete: bool,
    instances: tuple[TaskInstance, ...] = (),
) -> BenchmarkQualityReport:
    """Build an evidence-only report for one frozen benchmark series."""

    gate = compute_quality_gate(spec, observations)
    rates = gate["rates"]
    uppers = gate["uppers"]
    reasons: list[str] = []
    if not framework_ready:
        reasons.append("framework_not_ready")
    if not station_campaign_complete:
        reasons.append("station_campaign_incomplete")
    if gate["information_status"] is not InformationStatus.AVAILABLE:
        reasons.append("insufficient_information")
    if spec.phase is not BenchmarkPhase.CONFIRMATORY_HOLDOUT:
        reasons.append("confirmatory_holdout_required")
    if spec.repetition_count < 2:
        reasons.append("confirmatory_repetitions_insufficient")
    if spec.bootstrap_resamples < spec.minimum_resamples:
        reasons.append("resampling_tail_resolution_insufficient")
    try:
        build_benchmark_schedule(spec, instances=instances)
    except ValueError:
        reasons.append("task_qualification_missing")
    if gate["invalid_rate"] > spec.max_invalid_rate:
        reasons.append("invalid_rate_exceeds_limit")
    if any(
        gate["block_counts_by_stratum"][stratum.stratum_id][model]
        < max(40, spec.min_valid_blocks_per_stratum)
        for stratum in spec.strata
        for model in spec.model_ids
    ):
        reasons.append("insufficient_valid_blocks")
    if any(value < Decimal("0.95") for value in gate["block_retention_by_stratum"].values()):
        reasons.append("paired_block_retention_below_limit")
    if any(value is None or value >= Decimal("0.30") for value in uppers.values()):
        reasons.append("model_upper_bound_reaches_saturation")
    if any(value is not None and value >= Decimal("0.30") for value in rates.values()):
        reasons.append("model_point_estimate_reaches_saturation")
    ideal_window = bool(rates) and all(
        value is not None and Decimal("0.10") <= value < Decimal("0.30")
        for value in rates.values()
    )
    roster_lower = gate["roster_lower"]
    if roster_lower is None or roster_lower <= 0:
        reasons.append("roster_mean_has_no_positive_information")
    if gate["roster_mean"] is None or gate["roster_mean"] < Decimal("0.10"):
        reasons.append("roster_mean_below_window")
    contrasts = compute_paired_contrasts(spec, observations)
    if any(result.information_status is not InformationStatus.AVAILABLE for result in contrasts):
        reasons.append("contrast_information_unavailable")
    if contrasts and any(not result.significant for result in contrasts):
        reasons.append("preregistered_contrast_not_significant")
    reasons.extend(_preregistration_gaps(spec))
    effects = {item.contrast_id: item.left_minus_right for item in contrasts}
    if any(
        effects[item.contrast_id] < spec.target_effect_size
        for item in spec.contrast_hypotheses
        if item.kind is ContrastKind.STRONG_WEAK_MODEL
    ):
        reasons.append("strong_weak_effect_below_limit")
    qualified = not reasons
    return BenchmarkQualityReport(
        benchmark_digest=spec.digest,
        framework_ready=framework_ready,
        station_campaign_complete=station_campaign_complete,
        benchmark_quality_qualified=qualified,
        model_rates=rates,
        model_upper_bounds=uppers,
        roster_mean=gate["roster_mean"],
        roster_lower_bound=roster_lower,
        invalid_rate=gate["invalid_rate"],
        valid_block_counts=gate["block_counts"],
        failure_counts=gate["failure_counts"],
        reasons=tuple(reasons),
        bootstrap_resamples=spec.bootstrap_resamples,
        valid_block_counts_by_stratum=gate["block_counts_by_stratum"],
        block_retention_by_stratum=gate["block_retention_by_stratum"],
        stratum_rates=gate["stratum_rates"],
        contrast_results=contrasts,
        ideal_window_all_models=ideal_window,
        information_status=gate["information_status"],
    )


__all__ = ["build_quality_report"]


def _preregistration_gaps(spec: BenchmarkSpec) -> tuple[str, ...]:
    groups: dict[str, list[EvaluationCell]] = defaultdict(list)
    for cell in spec.evaluation_cells:
        if cell.comparison_group is not None:
            groups[cell.comparison_group].append(cell)
    if len(groups) < 2 or any(len(cells) != 3 for cells in groups.values()):
        return ("three_tier_model_groups_not_preregistered",)
    registered = {
        (item.kind, item.left_model_id, item.right_model_id)
        for item in spec.contrast_hypotheses if isinstance(item, ModelContrast)
    }
    for cells in groups.values():
        ordered = sorted(cells, key=lambda cell: cell.tier_rank or 0)
        if len({cell.tier_rank for cell in ordered}) != 3:
            return ("three_tier_model_groups_not_preregistered",)
        strong, middle, weak = (cell.model_id for cell in ordered)
        required = {
            (ContrastKind.ADJACENT_MODEL, strong, middle),
            (ContrastKind.ADJACENT_MODEL, middle, weak),
            (ContrastKind.STRONG_WEAK_MODEL, strong, weak),
        }
        if required - registered:
            return ("core_model_contrasts_not_preregistered",)
    for layer in {item.engineering_layer for item in spec.strata}:
        gradients = [
            item for item in spec.contrast_hypotheses
            if isinstance(item, DifficultyContrast) and item.engineering_layer == layer
        ]
        if len(gradients) < 2 or not any(
            first.harder_difficulty_id == second.easier_difficulty_id
            for first in gradients for second in gradients if first != second
        ):
            return ("difficulty_progression_not_preregistered",)
    return ()
