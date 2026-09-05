"""Pure acceptance-rule interpretation for canonical EDA-flow evaluators."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from edagym.evaluation.model import MeasurementEvidence
from edagym.flow_tasks.model import (
    AcceptanceRule,
    Comparison,
    ContainsRule,
    ExitRule,
    NumberSelection,
    RegexNumberRule,
    RuleSource,
)


class RuleInterpretationError(ValueError):
    """A released rule cannot be interpreted as its declared typed contract."""


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    accepted: bool
    measurements: tuple[MeasurementEvidence, ...] = ()


def evaluate_acceptance_rules(
    rules: Sequence[AcceptanceRule],
    *,
    exit_codes: tuple[int, ...],
    stdout: bytes,
    stderr: bytes,
    files: Mapping[str, bytes],
) -> AcceptanceResult:
    """Interpret one sealed observation without reading mutable host paths."""

    measurements: list[MeasurementEvidence] = []
    if not exit_codes:
        return AcceptanceResult(accepted=False)
    for rule in rules:
        if isinstance(rule, ExitRule):
            if any(exit_code not in rule.expected_codes for exit_code in exit_codes):
                return AcceptanceResult(False, tuple(measurements))
            continue
        source = _source(rule.source, rule.path, stdout=stdout, stderr=stderr, files=files)
        if source is None:
            return AcceptanceResult(False, tuple(measurements))
        if isinstance(rule, ContainsRule):
            if rule.token.encode("utf-8") not in source:
                return AcceptanceResult(False, tuple(measurements))
            continue
        if isinstance(rule, RegexNumberRule):
            value = _number(rule, source)
            if value is None:
                return AcceptanceResult(False, tuple(measurements))
            if rule.measurement_id is not None:
                measurements.append(
                    MeasurementEvidence(
                        measurement_id=rule.measurement_id,
                        samples=(value,),
                    )
                )
            threshold = Decimal(rule.threshold)
            if rule.comparison is Comparison.LESS_EQUAL and value > threshold:
                return AcceptanceResult(False, tuple(measurements))
            if rule.comparison is Comparison.GREATER_EQUAL and value < threshold:
                return AcceptanceResult(False, tuple(measurements))
            continue
        raise TypeError("unsupported acceptance rule")
    return AcceptanceResult(True, tuple(measurements))


def _source(
    source: RuleSource,
    path: str | None,
    *,
    stdout: bytes,
    stderr: bytes,
    files: Mapping[str, bytes],
) -> bytes | None:
    if source is RuleSource.STDOUT:
        return stdout
    if source is RuleSource.STDERR:
        return stderr
    if path is None:
        return None
    return files.get(path)


def _number(rule: RegexNumberRule, source: bytes) -> Decimal | None:
    try:
        text = source.decode("utf-8")
        matches = tuple(re.finditer(rule.pattern, text, flags=re.MULTILINE))
    except (UnicodeDecodeError, re.error) as error:
        raise RuleInterpretationError("numeric rule input or pattern is invalid") from error
    if not matches or any(len(match.groups()) != 1 for match in matches):
        return None
    try:
        values = tuple(Decimal(match.group(1)) for match in matches)
    except InvalidOperation as error:
        raise RuleInterpretationError("numeric rule captured a non-decimal value") from error
    if rule.selection is NumberSelection.FIRST:
        return values[0]
    if rule.selection is NumberSelection.MINIMUM:
        return min(values)
    return max(values)
