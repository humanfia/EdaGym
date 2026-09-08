"""Explicit provider-budget adapters for transport dispatch."""

from __future__ import annotations

from typing import Protocol

from edagym.providers.budget import BudgetLedger, BudgetReservation
from edagym.providers.campaign import RetryCondition
from edagym.providers.campaign_runner import (
    AttemptDisposition,
    CampaignReservation,
    CampaignRunner,
)
from edagym.providers.model import ProviderUsage, RequestTokenClaim
from edagym.run.trial_model import ProviderSecurityBinding
from edagym.specs.common import Digest, Identifier, ModelLabel, ProviderResponseStatus


class ProviderBudgetReservation(Protocol):
    """One provider request reservation, independent of its accounting owner."""

    def mark_dispatched(self) -> None: ...

    def settle_completed(
        self,
        *,
        usage: ProviderUsage | None,
        provider_reported_model: str,
        provider_reported_service_tier: str | None = None,
        provider_response_status: ProviderResponseStatus,
    ) -> None: ...

    def settle_failed(self, *, failure_condition: RetryCondition | None) -> None: ...

    def cancel(self) -> None: ...


class ProviderBudget(Protocol):
    """Budget boundary consumed by the provider transport."""

    @property
    def campaign_digest(self) -> Digest: ...

    @property
    def binding_digest(self) -> Digest: ...

    def reserve_provider_attempt(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        requested_model: ModelLabel,
        token_claim: RequestTokenClaim,
        security_binding: ProviderSecurityBinding | None = None,
    ) -> ProviderBudgetReservation: ...


class StandaloneProviderBudget:
    """Bind the token ledger used only by pre-campaign provider probes."""

    def __init__(self, *, campaign_digest: Digest, ledger: BudgetLedger) -> None:
        self._campaign_digest = campaign_digest
        self._ledger = ledger

    @property
    def campaign_digest(self) -> Digest:
        return self._campaign_digest

    @property
    def binding_digest(self) -> Digest:
        return self._ledger.limits_digest

    def reserve_provider_attempt(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        requested_model: ModelLabel,
        token_claim: RequestTokenClaim,
        security_binding: ProviderSecurityBinding | None = None,
    ) -> ProviderBudgetReservation:
        del request_key, requested_model, security_binding
        reservation = self._ledger.reserve(
            trial_id=trial_id,
            input_tokens=token_claim.input_tokens,
            output_tokens=token_claim.output_tokens,
        )
        return _StandaloneReservation(reservation)


class CampaignProviderBudget:
    """Expose a campaign runner as the sole accounting owner for provider calls."""

    def __init__(self, runner: CampaignRunner) -> None:
        self._runner = runner

    @property
    def campaign_digest(self) -> Digest:
        return self._runner.campaign.digest

    @property
    def binding_digest(self) -> Digest:
        return self._runner.budget_projection().digest

    def reserve_provider_attempt(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        requested_model: ModelLabel,
        token_claim: RequestTokenClaim,
        security_binding: ProviderSecurityBinding | None = None,
    ) -> ProviderBudgetReservation:
        if security_binding is None:
            raise ValueError("campaign provider requests require a security binding")
        reservation = self._runner.reserve_provider_attempt(
            trial_id=trial_id,
            request_key=request_key,
            requested_model=requested_model,
            token_claim=token_claim,
            security_binding=security_binding,
        )
        return _CampaignReservation(reservation, self._runner)


class _StandaloneReservation:
    def __init__(self, reservation: BudgetReservation) -> None:
        self._reservation = reservation

    def mark_dispatched(self) -> None:
        self._reservation.mark_dispatched()

    def settle_completed(
        self,
        *,
        usage: ProviderUsage | None,
        provider_reported_model: str,
        provider_reported_service_tier: str | None = None,
        provider_response_status: ProviderResponseStatus,
    ) -> None:
        del provider_reported_model, provider_reported_service_tier, provider_response_status
        if usage is None:
            self._reservation.settle_unknown()
        else:
            self._reservation.settle(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
            )

    def settle_failed(self, *, failure_condition: RetryCondition | None) -> None:
        del failure_condition
        self._reservation.settle_unknown()

    def cancel(self) -> None:
        self._reservation.cancel()


class _CampaignReservation:
    def __init__(self, reservation: CampaignReservation, runner: CampaignRunner) -> None:
        self._reservation = reservation
        self._retry_conditions = runner.campaign.retry_policy.retry_conditions

    def mark_dispatched(self) -> None:
        self._reservation.mark_dispatched()

    def settle_completed(
        self,
        *,
        usage: ProviderUsage | None,
        provider_reported_model: str,
        provider_reported_service_tier: str | None = None,
        provider_response_status: ProviderResponseStatus,
    ) -> None:
        self._reservation.settle_provider(
            disposition=AttemptDisposition.COMPLETED,
            usage=usage,
            provider_reported_model=provider_reported_model,
            provider_reported_service_tier=provider_reported_service_tier,
            provider_response_status=provider_response_status,
        )

    def settle_failed(self, *, failure_condition: RetryCondition | None) -> None:
        admitted = (
            failure_condition
            if failure_condition is not None and failure_condition in self._retry_conditions
            else None
        )
        self._reservation.settle_provider(
            disposition=(
                AttemptDisposition.RETRYABLE_FAILURE
                if admitted is not None
                else AttemptDisposition.TERMINAL_FAILURE
            ),
            usage=None,
            failure_condition=admitted,
        )

    def cancel(self) -> None:
        self._reservation.cancel()
