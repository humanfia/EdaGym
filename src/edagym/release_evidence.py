"""Shared status aggregation for immutable release evidence."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Self

from pydantic import model_validator

from edagym.release_commands import ReleaseEvidenceStatus
from edagym.specs.common import JcsNonNegativeInt, StrictModel


class EvidenceCounts(StrictModel):
    passed: JcsNonNegativeInt
    failed: JcsNonNegativeInt
    unavailable: JcsNonNegativeInt
    total: JcsNonNegativeInt

    @model_validator(mode="after")
    def validate_partition(self) -> Self:
        if self.total != self.passed + self.failed + self.unavailable:
            raise ValueError("evidence counts must partition their total")
        return self


def evidence_counts(statuses: Iterable[ReleaseEvidenceStatus]) -> EvidenceCounts:
    values = tuple(statuses)
    return EvidenceCounts(
        passed=values.count(ReleaseEvidenceStatus.PASSED),
        failed=values.count(ReleaseEvidenceStatus.FAILED),
        unavailable=values.count(ReleaseEvidenceStatus.UNAVAILABLE),
        total=len(values),
    )


def evidence_status(counts: EvidenceCounts) -> ReleaseEvidenceStatus:
    if counts.failed:
        return ReleaseEvidenceStatus.FAILED
    if counts.unavailable:
        return ReleaseEvidenceStatus.UNAVAILABLE
    return ReleaseEvidenceStatus.PASSED
