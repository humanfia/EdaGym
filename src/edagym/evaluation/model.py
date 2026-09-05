"""Typed evaluator outcomes and derived promotion decisions."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, field_validator, model_validator

from edagym.specs.common import CanonicalDecimal, Digest, Identifier, Seed128Hex, StrictModel
from edagym.specs.task import MeasurementUnit, MetricDirection


class OutcomeKind(StrEnum):
    PASSED = "passed"
    PROVED = "proved"
    COUNTEREXAMPLE = "counterexample"
    CANDIDATE_FAILURE = "candidate_failure"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    LICENSE_UNAVAILABLE = "license_unavailable"
    SECURITY_VIOLATION = "security_violation"


class PassedOutcome(StrictModel):
    kind: Literal[OutcomeKind.PASSED] = OutcomeKind.PASSED


class ProvedOutcome(StrictModel):
    kind: Literal[OutcomeKind.PROVED] = OutcomeKind.PROVED


class CounterexampleOutcome(StrictModel):
    kind: Literal[OutcomeKind.COUNTEREXAMPLE] = OutcomeKind.COUNTEREXAMPLE


class CandidateFailureOutcome(StrictModel):
    kind: Literal[OutcomeKind.CANDIDATE_FAILURE] = OutcomeKind.CANDIDATE_FAILURE


class UnknownOutcome(StrictModel):
    kind: Literal[OutcomeKind.UNKNOWN] = OutcomeKind.UNKNOWN


class TimeoutOutcome(StrictModel):
    kind: Literal[OutcomeKind.TIMEOUT] = OutcomeKind.TIMEOUT


class InfrastructureFailureOutcome(StrictModel):
    kind: Literal[OutcomeKind.INFRASTRUCTURE_FAILURE] = OutcomeKind.INFRASTRUCTURE_FAILURE


class LicenseUnavailableOutcome(StrictModel):
    kind: Literal[OutcomeKind.LICENSE_UNAVAILABLE] = OutcomeKind.LICENSE_UNAVAILABLE


class SecurityViolationOutcome(StrictModel):
    kind: Literal[OutcomeKind.SECURITY_VIOLATION] = OutcomeKind.SECURITY_VIOLATION


StageOutcome = Annotated[
    PassedOutcome
    | ProvedOutcome
    | CounterexampleOutcome
    | CandidateFailureOutcome
    | UnknownOutcome
    | TimeoutOutcome
    | InfrastructureFailureOutcome
    | LicenseUnavailableOutcome
    | SecurityViolationOutcome,
    Field(discriminator="kind"),
]


class EvidenceKind(StrEnum):
    LOG = "log"
    REPORT = "report"
    MEASUREMENT = "measurement"
    TRACE = "trace"
    WAVEFORM = "waveform"
    PROOF = "proof"
    COUNTEREXAMPLE = "counterexample"
    DIAGNOSTIC = "diagnostic"


MediaType = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$",
        max_length=127,
    ),
]


class ArtifactEvidence(StrictModel):
    kind: EvidenceKind
    artifact_id: Identifier


class MeasurementProvenance(StrictModel):
    """Resolved context needed to replay one raw measurement vector."""

    unit: MeasurementUnit
    tool_id: Identifier
    tool_version: str
    library_id: Identifier
    library_digest: Digest
    corner: Identifier
    mode: Identifier
    task_seed: Seed128Hex
    sample_seeds: tuple[Seed128Hex, ...]
    source_artifact_id: Identifier
    source_digest: Digest


class MeasurementEvidence(StrictModel):
    measurement_id: Identifier
    samples: tuple[CanonicalDecimal, ...]
    provenance: MeasurementProvenance | None = None

    @field_validator("samples")
    @classmethod
    def require_samples(
        cls, value: tuple[CanonicalDecimal, ...]
    ) -> tuple[CanonicalDecimal, ...]:
        if not value:
            raise ValueError("measurement evidence requires at least one sample")
        return value

    @model_validator(mode="after")
    def validate_provenance_shape(self) -> Self:
        if self.provenance is not None:
            sample_seeds = self.provenance.sample_seeds
            if len(sample_seeds) != len(self.samples):
                raise ValueError("measurement sample seeds must cover every raw sample")
            if len(sample_seeds) != len(set(sample_seeds)):
                raise ValueError("measurement sample seeds must be unique")
        return self


class AggregatedMeasurement(StrictModel):
    """One value derived from the samples owned by a measurement result."""

    measurement_id: Identifier
    value: CanonicalDecimal


class ScoreKind(StrEnum):
    PARETO_VECTOR = "pareto_vector"
    SCALAR = "scalar"


class ScoreBase(StrictModel):
    measurements: Annotated[tuple[AggregatedMeasurement, ...], Field(min_length=1)]

    @field_validator("measurements")
    @classmethod
    def normalize_measurements(
        cls,
        value: tuple[AggregatedMeasurement, ...],
    ) -> tuple[AggregatedMeasurement, ...]:
        identifiers = [measurement.measurement_id for measurement in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("score measurement identifiers must be unique")
        return tuple(sorted(value, key=lambda measurement: measurement.measurement_id))


class ParetoVectorScore(ScoreBase):
    kind: Literal[ScoreKind.PARETO_VECTOR] = ScoreKind.PARETO_VECTOR


class ScalarScore(ScoreBase):
    kind: Literal[ScoreKind.SCALAR] = ScoreKind.SCALAR
    value: CanonicalDecimal
    direction: Literal[MetricDirection.MINIMIZE, MetricDirection.MAXIMIZE]
    scorer_revision_digest: Digest


CandidateScore = Annotated[
    ParetoVectorScore | ScalarScore,
    Field(discriminator="kind"),
]


class StageResult(StrictModel):
    stage_id: Identifier
    outcome: StageOutcome
    measurements: tuple[MeasurementEvidence, ...] = ()
    evidence: tuple[ArtifactEvidence, ...] = ()

    @field_validator("measurements")
    @classmethod
    def normalize_measurements(
        cls, value: tuple[MeasurementEvidence, ...]
    ) -> tuple[MeasurementEvidence, ...]:
        identifiers = [measurement.measurement_id for measurement in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("stage measurement identifiers must be unique")
        return tuple(sorted(value, key=lambda measurement: measurement.measurement_id))

    @field_validator("evidence")
    @classmethod
    def normalize_evidence(
        cls, value: tuple[ArtifactEvidence, ...]
    ) -> tuple[ArtifactEvidence, ...]:
        identities = [
            (evidence.kind, evidence.artifact_id)
            for evidence in value
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("stage evidence references must be unique")
        return tuple(
            sorted(
                value,
                key=lambda evidence: (
                    evidence.kind,
                    evidence.artifact_id,
                ),
            )
        )


class StageEligibilityKind(StrEnum):
    COMPLETED = "completed"
    READY = "ready"
    WAITING = "waiting"
    BLOCKED = "blocked"


class StageEligibility(StrictModel):
    stage_id: Identifier
    state: StageEligibilityKind
    blocking_stage_ids: tuple[Identifier, ...] = ()
    waiting_stage_ids: tuple[Identifier, ...] = ()

    @field_validator("blocking_stage_ids", "waiting_stage_ids")
    @classmethod
    def normalize_stage_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("eligibility stage identifiers must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if set(self.blocking_stage_ids) & set(self.waiting_stage_ids):
            raise ValueError("a stage cannot be both blocking and waiting")
        if self.state is StageEligibilityKind.BLOCKED:
            if not self.blocking_stage_ids or self.waiting_stage_ids:
                raise ValueError("blocked eligibility requires only blocking stages")
        elif self.state is StageEligibilityKind.WAITING:
            if not self.waiting_stage_ids or self.blocking_stage_ids:
                raise ValueError("waiting eligibility requires only waiting stages")
        elif self.blocking_stage_ids or self.waiting_stage_ids:
            raise ValueError("ready and completed eligibility cannot name dependencies")
        return self


class HardGateState(StrEnum):
    SUCCEEDED = "succeeded"
    PENDING = "pending"
    FAILED = "failed"


class HardGateStatus(StrictModel):
    state: HardGateState
    failed_gate_ids: tuple[Identifier, ...] = ()
    blocking_stage_ids: tuple[Identifier, ...] = ()
    pending_gate_ids: tuple[Identifier, ...] = ()

    @field_validator("failed_gate_ids", "blocking_stage_ids", "pending_gate_ids")
    @classmethod
    def normalize_stage_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("hard-gate status identifiers must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        failed = bool(self.failed_gate_ids or self.blocking_stage_ids)
        pending = bool(self.pending_gate_ids)
        if self.state is HardGateState.SUCCEEDED and (failed or pending):
            raise ValueError("successful hard-gate status cannot contain unresolved gates")
        if self.state is HardGateState.PENDING and (failed or not pending):
            raise ValueError("pending hard-gate status requires only pending gates")
        if self.state is HardGateState.FAILED and not failed:
            raise ValueError("failed hard-gate status requires failure evidence")
        return self


class ScorerEligibilityKind(StrEnum):
    NOT_CONFIGURED = "not_configured"
    READY = "ready"
    WAITING = "waiting"
    BLOCKED = "blocked"


class ScorerEligibility(StrictModel):
    state: ScorerEligibilityKind
    blocking_stage_ids: tuple[Identifier, ...] = ()
    waiting_stage_ids: tuple[Identifier, ...] = ()

    @field_validator("blocking_stage_ids", "waiting_stage_ids")
    @classmethod
    def normalize_stage_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("scorer eligibility identifiers must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if set(self.blocking_stage_ids) & set(self.waiting_stage_ids):
            raise ValueError("a scorer dependency cannot be both blocking and waiting")
        if self.state is ScorerEligibilityKind.BLOCKED:
            if not self.blocking_stage_ids or self.waiting_stage_ids:
                raise ValueError("blocked scorer eligibility requires only blocking stages")
        elif self.state is ScorerEligibilityKind.WAITING:
            if not self.waiting_stage_ids or self.blocking_stage_ids:
                raise ValueError("waiting scorer eligibility requires only waiting stages")
        elif self.blocking_stage_ids or self.waiting_stage_ids:
            raise ValueError("ready or absent scorer eligibility cannot name dependencies")
        return self


class ScoringDecision(StrictModel):
    """A terminal scoring eligibility fact and its optional derived result."""

    eligibility: ScorerEligibility
    score: CandidateScore | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if (self.eligibility.state is ScorerEligibilityKind.READY) != (
            self.score is not None
        ):
            raise ValueError("a score exists exactly when scoring is ready")
        if self.eligibility.state is ScorerEligibilityKind.WAITING:
            raise ValueError("a waiting scoring decision is not terminal")
        return self
