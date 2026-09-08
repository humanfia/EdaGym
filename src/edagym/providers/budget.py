"""Atomic token reservations for provider campaigns."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any, SupportsIndex

from pydantic import TypeAdapter, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, Identifier, JcsPositiveInt, StrictModel

_TRIAL_ID_ADAPTER = TypeAdapter(Identifier)


class BudgetExceeded(RuntimeError):
    """Raised before network access when a hard campaign or trial cap would be crossed."""


class BudgetProtocolError(RuntimeError):
    """Raised when a reservation is settled inconsistently."""


class BudgetLimits(StrictModel):
    """Standalone provider limits for bounded pre-campaign probes."""

    max_requests: JcsPositiveInt
    max_input_tokens: JcsPositiveInt
    max_output_tokens: JcsPositiveInt
    max_total_tokens: JcsPositiveInt
    max_requests_per_trial: JcsPositiveInt
    max_input_tokens_per_trial: JcsPositiveInt
    max_output_tokens_per_trial: JcsPositiveInt
    max_total_tokens_per_trial: JcsPositiveInt

    @model_validator(mode="after")
    def validate_totals(self) -> BudgetLimits:
        if self.max_total_tokens > self.max_input_tokens + self.max_output_tokens:
            raise ValueError("total token cap cannot exceed the sum of directional caps")
        if self.max_total_tokens_per_trial > self.max_total_tokens:
            raise ValueError("per-trial token cap cannot exceed campaign total cap")
        if self.max_requests_per_trial > self.max_requests:
            raise ValueError("per-trial request cap cannot exceed campaign request cap")
        if self.max_input_tokens_per_trial > self.max_input_tokens:
            raise ValueError("per-trial input cap cannot exceed campaign input cap")
        if self.max_output_tokens_per_trial > self.max_output_tokens:
            raise ValueError("per-trial output cap cannot exceed campaign output cap")
        if self.max_total_tokens_per_trial > (
            self.max_input_tokens_per_trial + self.max_output_tokens_per_trial
        ):
            raise ValueError("per-trial total cap cannot exceed directional caps")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-budget-limits-v1")


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    committed_requests: int
    reserved_requests: int
    committed_input_tokens: int
    reserved_input_tokens: int
    committed_output_tokens: int
    reserved_output_tokens: int
    violated: bool


@dataclass(slots=True)
class _TrialUsage:
    committed_requests: int = 0
    reserved_requests: int = 0
    committed_input_tokens: int = 0
    reserved_input_tokens: int = 0
    committed_output_tokens: int = 0
    reserved_output_tokens: int = 0


class BudgetLedger:
    """Own campaign budget state and reserve worst-case cost under one lock."""

    def __init__(self, limits: BudgetLimits) -> None:
        self._limits = limits
        self._lock = Lock()
        self._committed_requests = 0
        self._reserved_requests = 0
        self._committed_input = 0
        self._reserved_input = 0
        self._committed_output = 0
        self._reserved_output = 0
        self._trials: dict[str, _TrialUsage] = {}
        self._violated = False

    def reserve(
        self,
        *,
        trial_id: Identifier,
        input_tokens: int,
        output_tokens: int,
    ) -> BudgetReservation:
        if type(input_tokens) is not int or input_tokens <= 0:
            raise ValueError("input token reservation must be a positive integer")
        if type(output_tokens) is not int or output_tokens <= 0:
            raise ValueError("output token reservation must be a positive integer")
        validated_trial_id = _TRIAL_ID_ADAPTER.validate_python(trial_id)
        total = input_tokens + output_tokens
        with self._lock:
            trial = self._trials.get(validated_trial_id, _TrialUsage())
            if (
                self._committed_requests + self._reserved_requests + 1
                > self._limits.max_requests
                or self._committed_input + self._reserved_input + input_tokens
                > self._limits.max_input_tokens
                or self._committed_output + self._reserved_output + output_tokens
                > self._limits.max_output_tokens
                or self._committed_input
                + self._reserved_input
                + self._committed_output
                + self._reserved_output
                + total
                > self._limits.max_total_tokens
                or trial.committed_requests + trial.reserved_requests + 1
                > self._limits.max_requests_per_trial
                or trial.committed_input_tokens
                + trial.reserved_input_tokens
                + input_tokens
                > self._limits.max_input_tokens_per_trial
                or trial.committed_output_tokens
                + trial.reserved_output_tokens
                + output_tokens
                > self._limits.max_output_tokens_per_trial
                or trial.committed_input_tokens
                + trial.reserved_input_tokens
                + trial.committed_output_tokens
                + trial.reserved_output_tokens
                + total
                > self._limits.max_total_tokens_per_trial
            ):
                raise BudgetExceeded("provider budget reservation rejected")
            self._reserved_requests += 1
            self._reserved_input += input_tokens
            self._reserved_output += output_tokens
            self._trials[validated_trial_id] = trial
            trial.reserved_requests += 1
            trial.reserved_input_tokens += input_tokens
            trial.reserved_output_tokens += output_tokens
        return BudgetReservation(self, validated_trial_id, input_tokens, output_tokens)

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return BudgetSnapshot(
                committed_requests=self._committed_requests,
                reserved_requests=self._reserved_requests,
                committed_input_tokens=self._committed_input,
                reserved_input_tokens=self._reserved_input,
                committed_output_tokens=self._committed_output,
                reserved_output_tokens=self._reserved_output,
                violated=self._violated,
            )

    @property
    def limits_digest(self) -> Digest:
        return self._limits.digest

    def _cancel(self, reservation: BudgetReservation) -> None:
        with self._lock:
            self._remove_reserved(reservation)

    def _settle(
        self,
        reservation: BudgetReservation,
        *,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        if type(input_tokens) is not int or input_tokens < 0:
            raise BudgetProtocolError("reported input usage must be a non-negative integer")
        if type(output_tokens) is not int or output_tokens < 0:
            raise BudgetProtocolError("reported output usage must be a non-negative integer")
        with self._lock:
            self._remove_reserved(reservation)
            self._committed_requests += 1
            self._committed_input += input_tokens
            self._committed_output += output_tokens
            trial = self._trials[reservation._trial_id]
            trial.committed_requests += 1
            trial.committed_input_tokens += input_tokens
            trial.committed_output_tokens += output_tokens
            if (
                input_tokens > reservation._input_tokens
                or output_tokens > reservation._output_tokens
                or self._committed_input > self._limits.max_input_tokens
                or self._committed_output > self._limits.max_output_tokens
                or self._committed_input + self._committed_output > self._limits.max_total_tokens
                or trial.committed_input_tokens > self._limits.max_input_tokens_per_trial
                or trial.committed_output_tokens > self._limits.max_output_tokens_per_trial
                or trial.committed_input_tokens + trial.committed_output_tokens
                > self._limits.max_total_tokens_per_trial
            ):
                self._violated = True
                raise BudgetProtocolError("provider usage exceeded its reserved hard bound")

    def _settle_unknown(self, reservation: BudgetReservation) -> None:
        self._settle(
            reservation,
            input_tokens=reservation._input_tokens,
            output_tokens=reservation._output_tokens,
        )

    def _remove_reserved(self, reservation: BudgetReservation) -> None:
        self._reserved_requests -= 1
        self._reserved_input -= reservation._input_tokens
        self._reserved_output -= reservation._output_tokens
        trial = self._trials[reservation._trial_id]
        trial.reserved_requests -= 1
        trial.reserved_input_tokens -= reservation._input_tokens
        trial.reserved_output_tokens -= reservation._output_tokens


class BudgetReservation:
    """Single-owner reservation that burns its worst case once dispatch begins."""

    __slots__ = (
        "_dispatched",
        "_input_tokens",
        "_ledger",
        "_lock",
        "_output_tokens",
        "_settled",
        "_trial_id",
    )

    def __init__(
        self,
        ledger: BudgetLedger,
        trial_id: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        self._ledger = ledger
        self._trial_id = trial_id
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._lock = Lock()
        self._dispatched = False
        self._settled = False

    def mark_dispatched(self) -> None:
        with self._lock:
            if self._settled or self._dispatched:
                raise BudgetProtocolError("reservation cannot be dispatched in its current state")
            self._dispatched = True

    def settle(self, *, input_tokens: int, output_tokens: int) -> None:
        with self._lock:
            if self._settled or not self._dispatched:
                raise BudgetProtocolError("reservation cannot be settled in its current state")
            self._settled = True
        self._ledger._settle(self, input_tokens=input_tokens, output_tokens=output_tokens)

    def settle_unknown(self) -> None:
        with self._lock:
            if self._settled or not self._dispatched:
                raise BudgetProtocolError("reservation cannot be settled in its current state")
            self._settled = True
        self._ledger._settle_unknown(self)

    def cancel(self) -> None:
        with self._lock:
            if self._settled or self._dispatched:
                raise BudgetProtocolError("a dispatched reservation cannot be cancelled")
            self._settled = True
        self._ledger._cancel(self)

    def __repr__(self) -> str:
        return "BudgetReservation(<opaque>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("budget reservations cannot be serialized")
