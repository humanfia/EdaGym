"""Pure validation and replay for durable campaign accounting events."""

from __future__ import annotations

from dataclasses import fields

from edagym.providers.campaign import CampaignSpec
from edagym.providers.campaign_budget import (
    BudgetDimension,
    CampaignAccountingError,
    CampaignBudgetExceeded,
    CampaignBudgetProjection,
    CampaignResources,
    _MutableResources,
)
from edagym.providers.campaign_runner import (
    AttemptDisposition,
    BudgetStoppedEvent,
    CampaignEvent,
    CampaignRecord,
    ProviderAttemptSettledEvent,
    ReservationCancelledEvent,
    ReservationCreatedEvent,
    ReservationDispatchedEvent,
    TrialDisposition,
    TrialOutcomeRecordedEvent,
    TrialRunOutcome,
    WorkSettledEvent,
    _CampaignProjection,
    _ReservationLedger,
    _TrialProjection,
)
from edagym.providers.campaign_schedule import CampaignHeader, ScheduledTrial
from edagym.run.model import HarnessRunActor, RunBinding


def replay_campaign_record(record: CampaignRecord) -> _CampaignProjection:
    state = _CampaignProjection(
        ledgers={trial.trial_id: _TrialProjection() for trial in record.header.schedule.trials},
        reservations={},
        committed=_MutableResources(),
        reserved=_MutableResources(),
        run_ids=set(),
    )
    for event in record.events:
        apply_campaign_event(record.header, state, event)
    return state


def ready_campaign_projection(
    state: _CampaignProjection,
    trial_id: str,
) -> _TrialProjection:
    try:
        ledger = state.ledgers[trial_id]
    except KeyError:
        raise ValueError("trial is not part of the frozen campaign schedule") from None
    if ledger.outcome is not None:
        raise CampaignAccountingError("terminal trials cannot dispatch more work")
    if state.global_stop_dimension is not None:
        raise CampaignBudgetExceeded(state.global_stop_dimension, per_trial=False)
    if trial_id in state.trial_stop_dimensions:
        raise CampaignBudgetExceeded(state.trial_stop_dimensions[trial_id], per_trial=True)
    if state.budget_violation:
        raise CampaignAccountingError("campaign accounting is poisoned by a prior violation")
    return ledger


def reservation_rejection(
    campaign: CampaignSpec,
    state: _CampaignProjection,
    trial_id: str,
    claim: CampaignResources,
    *,
    provider_request: bool,
) -> CampaignBudgetExceeded | None:
    ready_campaign_projection(state, trial_id)
    if provider_request:
        if claim.input_tokens > campaign.token_limits.max_input_tokens_per_request:
            return CampaignBudgetExceeded(BudgetDimension.INPUT_TOKENS, per_trial=True)
        if claim.output_tokens > campaign.token_limits.max_output_tokens_per_request:
            return CampaignBudgetExceeded(BudgetDimension.OUTPUT_TOKENS, per_trial=True)
    global_current = _sum_resources(state.committed, state.reserved)
    trial = state.ledgers[trial_id]
    trial_current = _sum_resources(trial.committed, trial.reserved)
    dimension = _first_exceeded(global_current, claim, _limits(campaign, per_trial=False))
    if dimension is not None:
        return CampaignBudgetExceeded(dimension, per_trial=False)
    dimension = _first_exceeded(trial_current, claim, _limits(campaign, per_trial=True))
    if dimension is not None:
        return CampaignBudgetExceeded(dimension, per_trial=True)
    return None


def apply_campaign_event(
    header: CampaignHeader,
    state: _CampaignProjection,
    event: CampaignEvent,
) -> None:
    if isinstance(event, ReservationCreatedEvent):
        _apply_reservation_created(header, state, event)
    elif isinstance(event, ReservationDispatchedEvent):
        reservation = _reservation(state, event.payload.reservation_id)
        if reservation.dispatched:
            raise CampaignAccountingError("campaign reservation was already dispatched")
        reservation.dispatched = True
    elif isinstance(event, ReservationCancelledEvent):
        reservation = _reservation(state, event.payload.reservation_id)
        if reservation.dispatched:
            raise CampaignAccountingError("a dispatched reservation cannot be cancelled")
        if reservation.provider is not None:
            state.ledgers[reservation.trial_id].cancelled_provider_requests.add(
                reservation.provider.request_key
            )
        _release_reservation(state, event.payload.reservation_id, reservation)
    elif isinstance(event, WorkSettledEvent):
        reservation = _reservation(state, event.payload.reservation_id)
        if reservation.provider is not None:
            raise CampaignAccountingError("provider reservation cannot settle as work")
        if not reservation.dispatched:
            raise CampaignAccountingError("work settlement requires a dispatched reservation")
        actual = event.payload.actual
        if actual.requests or actual.input_tokens or actual.output_tokens:
            raise CampaignAccountingError("work settlement cannot contain provider resources")
        _settle(state, event.payload.reservation_id, reservation, actual)
    elif isinstance(event, ProviderAttemptSettledEvent):
        _apply_provider_settlement(header, state, event)
    elif isinstance(event, TrialOutcomeRecordedEvent):
        _apply_trial_outcome(header, state, event)
    elif isinstance(event, BudgetStoppedEvent):
        payload = event.payload
        expected = reservation_rejection(
            header.campaign,
            state,
            payload.trial_id,
            payload.rejected_claim,
            provider_request=bool(payload.rejected_claim.requests),
        )
        if (
            expected is None
            or expected.dimension is not payload.dimension
            or expected.per_trial != payload.per_trial
        ):
            raise CampaignAccountingError("campaign budget stop lacks matching rejected usage")
        if payload.per_trial:
            state.trial_stop_dimensions[payload.trial_id] = payload.dimension
        else:
            state.global_stop_dimension = payload.dimension
    else:
        raise CampaignAccountingError("campaign event has no replay policy")


def _apply_reservation_created(
    header: CampaignHeader,
    state: _CampaignProjection,
    event: ReservationCreatedEvent,
) -> None:
    payload = event.payload
    if payload.reservation_id in state.reservations:
        raise CampaignAccountingError("campaign reservation identifier already exists")
    if payload.claim.is_zero:
        raise CampaignAccountingError("campaign reservation claim cannot be empty")
    ledger = ready_campaign_projection(state, payload.trial_id)
    provider = payload.provider
    if provider is None:
        if payload.claim.requests or payload.claim.input_tokens or payload.claim.output_tokens:
            raise CampaignAccountingError("work reservation contains provider resources")
    else:
        claim = payload.claim
        if (
            claim.requests != 1
            or claim.turns
            or claim.tool_calls
            or claim.wall_seconds
            or claim.eda_compute_seconds
            or claim.license_seconds
            or claim.artifact_bytes
        ):
            raise CampaignAccountingError(
                "provider reservation may contain one request and token claims only"
            )
        trial = _trial(header, payload.trial_id)
        if (
            provider.observed_input_token_floor >= claim.input_tokens
            or provider.observed_input_token_floor
            != trial.binding.observed_input_token_floor
            or provider.security_binding.budget_binding_digest
            != CampaignBudgetProjection.from_campaign(
                header.campaign,
                header.schedule,
            ).digest
        ):
            raise CampaignAccountingError(
                "provider reservation floor differs from its frozen route"
            )
        matching = [
            attempt for attempt in ledger.attempts if attempt.request_key == provider.request_key
        ]
        if provider.attempt_number != len(matching) + 1:
            raise CampaignAccountingError("provider retry ordinal differs from durable attempts")
        if any(
            reservation.trial_id == payload.trial_id
            and reservation.provider is not None
            and reservation.provider.request_key == provider.request_key
            for reservation in state.reservations.values()
        ):
            raise CampaignAccountingError("provider request already has an active reservation")
        if matching:
            previous = matching[-1]
            retry_policy = header.campaign.retry_policy
            if (
                previous.reserved_token_claim.input_tokens != claim.input_tokens
                or previous.reserved_token_claim.output_tokens != claim.output_tokens
                or previous.reserved_token_claim.observed_input_token_floor
                != provider.observed_input_token_floor
                or previous.security_binding != provider.security_binding
            ):
                raise CampaignAccountingError(
                    "provider retries must preserve the request token claim"
                )
            if previous.disposition is not AttemptDisposition.RETRYABLE_FAILURE:
                raise CampaignAccountingError("only retryable failures admit another attempt")
            if provider.attempt_number > retry_policy.max_request_attempts:
                raise CampaignAccountingError("provider retry policy is exhausted")
            if previous.failure_condition not in retry_policy.retry_conditions:
                raise CampaignAccountingError("provider failure is not admitted by retry policy")
    if (
        reservation_rejection(
            header.campaign,
            state,
            payload.trial_id,
            payload.claim,
            provider_request=provider is not None,
        )
        is not None
    ):
        raise CampaignAccountingError("campaign reservation exceeds a hard budget")
    state.reserved.add(payload.claim)
    ledger.reserved.add(payload.claim)
    state.reservations[payload.reservation_id] = _ReservationLedger(
        trial_id=payload.trial_id,
        claim=payload.claim,
        provider=provider,
    )


def _apply_provider_settlement(
    header: CampaignHeader,
    state: _CampaignProjection,
    event: ProviderAttemptSettledEvent,
) -> None:
    payload = event.payload
    reservation = _reservation(state, payload.reservation_id)
    provider = reservation.provider
    if provider is None:
        raise CampaignAccountingError("work reservation cannot settle as a provider attempt")
    if not reservation.dispatched:
        raise CampaignAccountingError("provider settlement requires a dispatched reservation")
    attempt = payload.attempt
    trial = _trial(header, reservation.trial_id)
    if (
        attempt.request_key != provider.request_key
        or attempt.attempt_number != provider.attempt_number
        or attempt.requested_model != trial.binding.requested_model
        or attempt.requested_service_tier != trial.binding.service_tier
        or attempt.reserved_token_claim.input_tokens != reservation.claim.input_tokens
        or attempt.reserved_token_claim.output_tokens != reservation.claim.output_tokens
        or attempt.reserved_token_claim.observed_input_token_floor
        != provider.observed_input_token_floor
        or attempt.security_binding != provider.security_binding
    ):
        raise CampaignAccountingError("provider attempt differs from its reservation or route")
    if attempt.failure_condition is not None and (
        attempt.failure_condition not in header.campaign.retry_policy.retry_conditions
    ):
        raise CampaignAccountingError("provider failure is not admitted by retry policy")
    _settle(
        state,
        payload.reservation_id,
        reservation,
        attempt.charged_resources,
    )
    if attempt.provider_usage is None:
        state.budget_violation = True
        state.ledgers[reservation.trial_id].accounting_violation = True
    state.ledgers[reservation.trial_id].attempts.append(attempt)


def _apply_trial_outcome(
    header: CampaignHeader,
    state: _CampaignProjection,
    event: TrialOutcomeRecordedEvent,
) -> None:
    payload = event.payload
    trial = _trial(header, payload.trial_id)
    ledger = state.ledgers[payload.trial_id]
    if ledger.outcome is not None:
        raise CampaignAccountingError("campaign trial already has a terminal outcome")
    if any(reservation.trial_id == payload.trial_id for reservation in state.reservations.values()):
        raise CampaignAccountingError("trial outcome cannot precede dispatch settlement")
    outcome = payload.outcome
    task = next(
        item
        for item in header.tasks
        if item.task_release_digest == trial.binding.task_release_digest
    )
    undeclared = {item.result.stage_id for item in outcome.stage_results} - set(
        task.evaluator_stage_ids
    )
    if undeclared:
        raise ValueError("trial outcome contains an undeclared evaluator stage")
    if outcome.run_id is not None:
        if outcome.run_id in state.run_ids:
            raise ValueError("campaign run identifiers must be unique")
        _validate_run_binding(header, trial, outcome.run_binding)
        _validate_provider_requests(header, trial, outcome, ledger)
        state.run_ids.add(outcome.run_id)
    if outcome.disposition is TrialDisposition.NOT_DISPATCHED and (
        not ledger.committed.snapshot().is_zero or ledger.attempts
    ):
        raise ValueError("a trial with committed resources was dispatched")
    ledger.outcome = outcome


def _validate_run_binding(
    header: CampaignHeader,
    trial: ScheduledTrial,
    run_binding: RunBinding | None,
) -> None:
    if run_binding is None:
        raise ValueError("completed campaign outcomes require a concrete run binding")
    binding = trial.binding
    campaign = run_binding.campaign
    if campaign is None:
        raise ValueError("completed campaign runs require a campaign trial binding")
    if (
        run_binding.trial_key != trial.trial_id
        or run_binding.task.family != binding.task_family
        or run_binding.task.release_digest != binding.task_release_digest
        or run_binding.environment.environment_spec_digest != binding.environment_digest
        or run_binding.session.feedback_policy_digest != header.campaign.feedback_policy_digest
        or campaign.campaign_digest != binding.campaign_digest
        or campaign.schedule_digest != header.schedule.digest
        or campaign.scheduled_trial_digest != trial.digest
        or campaign.paired_seed != binding.paired_seed
        or campaign.repetition_index != binding.repetition_index
        or campaign.route_id != binding.route_id
        or campaign.reasoning_effort != binding.reasoning_effort
        or campaign.service_tier != binding.service_tier
    ):
        raise ValueError("run binding does not represent the scheduled campaign trial")
    harnesses = [
        actor for actor in run_binding.session.actors if isinstance(actor, HarnessRunActor)
    ]
    if len(harnesses) != 1 or (
        harnesses[0].harness_digest != binding.harness_digest
        or harnesses[0].scaffold_digest != binding.harness.scaffold_digest
        or harnesses[0].requested_model_route != binding.requested_model
    ):
        raise ValueError("run harness does not match the scheduled campaign trial")


def _validate_provider_requests(
    header: CampaignHeader,
    trial: ScheduledTrial,
    outcome: TrialRunOutcome,
    ledger: _TrialProjection,
) -> None:
    requests = outcome.provider_requests
    if not requests:
        raise ValueError("completed campaign runs require metered provider request facts")
    attempted_request_ids = {attempt.request_key for attempt in ledger.attempts}
    run_request_ids = {request.request_id for request in requests}
    if not attempted_request_ids.issubset(run_request_ids) or not run_request_ids.issubset(
        attempted_request_ids | ledger.cancelled_provider_requests
    ):
        raise ValueError("run provider requests differ from campaign dispatch evidence")
    run_binding = outcome.run_binding
    if run_binding is None:
        raise ValueError("completed campaign outcomes require a concrete run binding")
    harnesses = [
        actor for actor in run_binding.session.actors if isinstance(actor, HarnessRunActor)
    ]
    if len(harnesses) != 1:
        raise ValueError("completed campaign runs require one metered harness")
    expected_harness = trial.binding.harness
    for request in requests:
        if (
            request.actor_id != harnesses[0].actor_id
            or request.provider_profile_digest != expected_harness.provider_profile_digest
            or request.provider_config_digest != expected_harness.provider_config_digest
            or request.requested_model != trial.binding.requested_model
            or request.requested_service_tier != trial.binding.service_tier
        ):
            raise ValueError("run provider request identity differs from its campaign harness")
        attempts = tuple(
            attempt for attempt in ledger.attempts if attempt.request_key == request.request_id
        )
        if not attempts:
            if (
                request.request_id not in ledger.cancelled_provider_requests
                or request.status is not None
                or request.provider_reported_model is not None
                or request.provider_reported_service_tier is not None
                or request.usage is not None
            ):
                raise ValueError("cancelled provider requests cannot carry response facts")
            continue
        final_attempt = attempts[-1]
        claim = final_attempt.reserved_token_claim
        if (
            request.reserved_input_tokens != claim.input_tokens
            or request.reserved_output_tokens != claim.output_tokens
            or request.observed_input_token_floor
            != claim.observed_input_token_floor
            or request.security_binding != final_attempt.security_binding
        ):
            raise ValueError("run provider reservation differs from campaign dispatch evidence")
        has_response = final_attempt.disposition is AttemptDisposition.COMPLETED
        if has_response != (request.status is not None):
            raise ValueError("run provider response differs from campaign dispatch evidence")
        if has_response and (
            request.provider_reported_model != final_attempt.provider_reported_model
            or request.provider_reported_service_tier
            != final_attempt.provider_reported_service_tier
            or request.requested_service_tier != final_attempt.requested_service_tier
            or request.status is not final_attempt.provider_response_status
            or (request.usage is None) != (final_attempt.provider_usage is None)
            or (
                request.usage is not None
                and final_attempt.provider_usage is not None
                and request.usage.model_dump() != final_attempt.provider_usage.model_dump()
            )
        ):
            raise ValueError("run provider response differs from campaign dispatch evidence")
        if not has_response and (
            request.provider_reported_model is not None
            or request.provider_reported_service_tier is not None
            or request.usage is not None
        ):
            raise ValueError("failed provider dispatches cannot carry run response facts")
    if (
        expected_harness.provider_profile_digest != header.provider_config.profile.digest
        or expected_harness.provider_config_digest != header.provider_config.digest
        or expected_harness.wire_protocol is not header.provider_config.profile.wire_protocol
    ):
        raise ValueError("campaign harness provider identity differs from its header")


def _settle(
    state: _CampaignProjection,
    reservation_id: str,
    reservation: _ReservationLedger,
    actual: CampaignResources,
) -> None:
    ledger = state.ledgers[reservation.trial_id]
    state.reserved.subtract(reservation.claim)
    ledger.reserved.subtract(reservation.claim)
    state.committed.add(actual)
    ledger.committed.add(actual)
    if _exceeds(actual, reservation.claim):
        state.budget_violation = True
        ledger.accounting_violation = True
    state.reservations.pop(reservation_id)


def _release_reservation(
    state: _CampaignProjection,
    reservation_id: str,
    reservation: _ReservationLedger,
) -> None:
    ledger = state.ledgers[reservation.trial_id]
    state.reserved.subtract(reservation.claim)
    ledger.reserved.subtract(reservation.claim)
    state.reservations.pop(reservation_id)


def _reservation(state: _CampaignProjection, reservation_id: str) -> _ReservationLedger:
    try:
        return state.reservations[reservation_id]
    except KeyError:
        raise CampaignAccountingError("campaign reservation is not active") from None


def _trial(header: CampaignHeader, trial_id: str) -> ScheduledTrial:
    try:
        return next(trial for trial in header.schedule.trials if trial.trial_id == trial_id)
    except StopIteration:
        raise ValueError("trial is not part of the frozen campaign schedule") from None


def _sum_resources(first: _MutableResources, second: _MutableResources) -> _MutableResources:
    return _MutableResources(
        **{
            item.name: getattr(first, item.name) + getattr(second, item.name)
            for item in fields(first)
        }
    )


def _limits(campaign: CampaignSpec, *, per_trial: bool) -> dict[BudgetDimension, int]:
    token = campaign.token_limits
    execution = campaign.execution_limits
    suffix = "_per_trial" if per_trial else ""
    return {
        BudgetDimension.REQUESTS: getattr(token, f"max_requests{suffix}"),
        BudgetDimension.INPUT_TOKENS: getattr(token, f"max_input_tokens{suffix}"),
        BudgetDimension.OUTPUT_TOKENS: getattr(token, f"max_output_tokens{suffix}"),
        BudgetDimension.TOTAL_TOKENS: getattr(token, f"max_total_tokens{suffix}"),
        BudgetDimension.TURNS: getattr(execution, f"max_turns{suffix}"),
        BudgetDimension.TOOL_CALLS: getattr(execution, f"max_tool_calls{suffix}"),
        BudgetDimension.WALL_SECONDS: getattr(execution, f"max_wall_seconds{suffix}"),
        BudgetDimension.EDA_COMPUTE_SECONDS: getattr(execution, f"max_eda_compute_seconds{suffix}"),
        BudgetDimension.LICENSE_SECONDS: getattr(execution, f"max_license_seconds{suffix}"),
        BudgetDimension.ARTIFACT_BYTES: getattr(execution, f"max_artifact_bytes{suffix}"),
    }


def _first_exceeded(
    current: _MutableResources,
    claim: CampaignResources,
    limits: dict[BudgetDimension, int],
) -> BudgetDimension | None:
    values = {
        BudgetDimension.REQUESTS: current.requests + claim.requests,
        BudgetDimension.INPUT_TOKENS: current.input_tokens + claim.input_tokens,
        BudgetDimension.OUTPUT_TOKENS: current.output_tokens + claim.output_tokens,
        BudgetDimension.TOTAL_TOKENS: (
            current.input_tokens + current.output_tokens + claim.input_tokens + claim.output_tokens
        ),
        BudgetDimension.TURNS: current.turns + claim.turns,
        BudgetDimension.TOOL_CALLS: current.tool_calls + claim.tool_calls,
        BudgetDimension.WALL_SECONDS: current.wall_seconds + claim.wall_seconds,
        BudgetDimension.EDA_COMPUTE_SECONDS: (
            current.eda_compute_seconds + claim.eda_compute_seconds
        ),
        BudgetDimension.LICENSE_SECONDS: current.license_seconds + claim.license_seconds,
        BudgetDimension.ARTIFACT_BYTES: current.artifact_bytes + claim.artifact_bytes,
    }
    return next(
        (dimension for dimension in BudgetDimension if values[dimension] > limits[dimension]),
        None,
    )


def _exceeds(actual: CampaignResources, claim: CampaignResources) -> bool:
    return any(
        getattr(actual, item.name) > getattr(claim, item.name) for item in fields(_MutableResources)
    )
