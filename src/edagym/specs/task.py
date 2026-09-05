"""Canonical task-family specification and evaluator graph."""

from __future__ import annotations

import hashlib
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.specs.common import (
    CanonicalDecimal,
    Capability,
    Digest,
    Identifier,
    Redistribution,
    SchemaVersion,
    Sensitivity,
    StrictModel,
    Visibility,
    validate_relative_path,
)


class ResetKind(StrEnum):
    SYNC_ACTIVE_HIGH = "sync_active_high"
    SYNC_ACTIVE_LOW = "sync_active_low"
    ASYNC_ACTIVE_HIGH = "async_active_high"
    ASYNC_ACTIVE_LOW = "async_active_low"


class InterfaceProfile(StrEnum):
    SCALAR = "scalar"
    STREAM = "stream"
    MMIO = "mmio"
    BUS_BRIDGE = "bus_bridge"
    MEMORY_MASTER = "memory_master"
    MULTI_CLOCK = "multi_clock"
    CYCLE_TRACE = "cycle_trace"
    WORKSPACE = "workspace"


class BusProtocol(StrEnum):
    APB4 = "apb4"
    AXI4 = "axi4"
    AXI4_LITE = "axi4_lite"
    WISHBONE_B4 = "wishbone_b4"


class PortDirection(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    INOUT = "inout"


class RequirementKind(StrEnum):
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    STRUCTURAL = "structural"


class ParameterKind(StrEnum):
    INTEGER = "integer"
    BOOLEAN = "boolean"
    CHOICE = "choice"


class StagePurpose(StrEnum):
    HARD_GATE = "hard_gate"
    OBSERVATION = "observation"


class MetricDirection(StrEnum):
    NONE = "none"
    MINIMIZE = "minimize"
    MAXIMIZE = "maximize"
    TARGET = "target"


class Aggregation(StrEnum):
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    MEAN = "mean"
    MEDIAN = "median"
    WORST = "worst"


class MeasurementUnit(StrEnum):
    DIMENSIONLESS = "1"
    BOOLEAN = "bool"
    COUNT = "count"
    BYTE = "byte"
    SECOND = "s"
    NANOSECOND = "ns"
    PICOSECOND = "ps"
    HERTZ = "Hz"
    MEGAHERTZ = "MHz"
    WATT = "W"
    MILLIWATT = "mW"
    MICROWATT = "uW"
    VOLT = "V"
    AMPERE = "A"
    OHM = "ohm"
    FARAD = "F"
    MICROMETER = "um"
    SQUARE_MICROMETER = "um2"
    PERCENT = "percent"


NOT_APPLICABLE_LIBRARY_DIGEST: Digest = canonical_digest(
    {"library_id": "not_applicable"},
    domain="measurement-library-v1",
)

SpdxExpression = Annotated[str, Field(min_length=1, max_length=160)]


class DifficultyRelation(StrEnum):
    INCREASES = "increases"
    DECREASES = "decreases"
    NON_MONOTONIC = "non_monotonic"
    EMPIRICAL = "empirical"


class ClockSpec(StrictModel):
    clock_id: Identifier
    period_fs: Annotated[int, Field(gt=0)]


class ResetSpec(StrictModel):
    reset_id: Identifier
    clock_id: Identifier
    kind: ResetKind


class SignalSpec(StrictModel):
    signal_id: Identifier
    direction: PortDirection
    width: Annotated[int, Field(ge=1, le=65536)]
    clock_id: Identifier


class ScalarInterface(StrictModel):
    profile: Literal[InterfaceProfile.SCALAR] = InterfaceProfile.SCALAR
    top_module: Identifier
    clock: ClockSpec
    reset: ResetSpec
    signals: tuple[SignalSpec, ...]

    @field_validator("signals")
    @classmethod
    def normalize_signals(cls, value: tuple[SignalSpec, ...]) -> tuple[SignalSpec, ...]:
        return tuple(sorted(value, key=lambda signal: signal.signal_id))

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if self.reset.clock_id != self.clock.clock_id:
            raise ValueError("reset must reference the scalar interface clock")
        names = [signal.signal_id for signal in self.signals]
        if not names or len(names) != len(set(names)):
            raise ValueError("scalar signal identifiers must be unique and non-empty")
        if any(signal.clock_id != self.clock.clock_id for signal in self.signals):
            raise ValueError("scalar signals must reference the interface clock")
        return self


class StreamInterface(StrictModel):
    profile: Literal[InterfaceProfile.STREAM] = InterfaceProfile.STREAM
    top_module: Identifier
    clock: ClockSpec
    reset: ResetSpec
    input_streams: Annotated[int, Field(ge=1, le=64)] = 1
    output_streams: Annotated[int, Field(ge=1, le=64)] = 1
    data_width: Annotated[int, Field(ge=1, le=65536)]
    user_width: Annotated[int, Field(ge=0, le=1024)] = 0
    has_keep: bool = False
    packetized: bool = True

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if self.reset.clock_id != self.clock.clock_id:
            raise ValueError("reset must reference the stream interface clock")
        return self


class MmioInterface(StrictModel):
    profile: Literal[InterfaceProfile.MMIO] = InterfaceProfile.MMIO
    top_module: Identifier
    protocol: Literal[BusProtocol.AXI4_LITE, BusProtocol.APB4]
    clock: ClockSpec
    reset: ResetSpec
    address_width: Annotated[int, Field(ge=1, le=64)]
    data_width: Annotated[int, Field(ge=8, le=1024)]

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if self.reset.clock_id != self.clock.clock_id:
            raise ValueError("reset must reference the MMIO interface clock")
        if self.data_width % 8:
            raise ValueError("MMIO data width must be byte aligned")
        return self


class BusBridgeInterface(StrictModel):
    profile: Literal[InterfaceProfile.BUS_BRIDGE] = InterfaceProfile.BUS_BRIDGE
    top_module: Identifier
    source_protocol: BusProtocol
    destination_protocol: BusProtocol
    clock: ClockSpec
    reset: ResetSpec
    address_width: Annotated[int, Field(ge=1, le=64)]
    data_width: Annotated[int, Field(ge=8, le=1024)]

    @model_validator(mode="after")
    def validate_bridge(self) -> Self:
        if self.reset.clock_id != self.clock.clock_id:
            raise ValueError("reset must reference the bridge interface clock")
        if self.source_protocol is self.destination_protocol:
            raise ValueError("a bus bridge requires distinct protocols")
        if self.data_width % 8:
            raise ValueError("bus data width must be byte aligned")
        return self


class MemoryMasterInterface(StrictModel):
    profile: Literal[InterfaceProfile.MEMORY_MASTER] = InterfaceProfile.MEMORY_MASTER
    top_module: Identifier
    protocol: Literal[BusProtocol.AXI4, BusProtocol.WISHBONE_B4]
    clock: ClockSpec
    reset: ResetSpec
    address_width: Annotated[int, Field(ge=1, le=64)]
    data_width: Annotated[int, Field(ge=8, le=1024)]
    maximum_outstanding: Annotated[int, Field(ge=1, le=256)]

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if self.reset.clock_id != self.clock.clock_id:
            raise ValueError("reset must reference the memory interface clock")
        if self.data_width % 8:
            raise ValueError("memory data width must be byte aligned")
        return self


class MultiClockInterface(StrictModel):
    profile: Literal[InterfaceProfile.MULTI_CLOCK] = InterfaceProfile.MULTI_CLOCK
    top_module: Identifier
    clocks: tuple[ClockSpec, ...]
    resets: tuple[ResetSpec, ...]
    signals: tuple[SignalSpec, ...]

    @field_validator("clocks")
    @classmethod
    def normalize_clocks(cls, value: tuple[ClockSpec, ...]) -> tuple[ClockSpec, ...]:
        return tuple(sorted(value, key=lambda clock: clock.clock_id))

    @field_validator("resets")
    @classmethod
    def normalize_resets(cls, value: tuple[ResetSpec, ...]) -> tuple[ResetSpec, ...]:
        return tuple(sorted(value, key=lambda reset: reset.reset_id))

    @field_validator("signals")
    @classmethod
    def normalize_signals(cls, value: tuple[SignalSpec, ...]) -> tuple[SignalSpec, ...]:
        return tuple(sorted(value, key=lambda signal: signal.signal_id))

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        clocks = {clock.clock_id for clock in self.clocks}
        if len(clocks) < 2 or len(clocks) != len(self.clocks):
            raise ValueError("multi-clock interfaces require at least two unique clocks")
        resets = [reset.reset_id for reset in self.resets]
        signals = [signal.signal_id for signal in self.signals]
        if len(resets) != len(set(resets)) or len(signals) != len(set(signals)):
            raise ValueError("reset and signal identifiers must be unique")
        if any(reset.clock_id not in clocks for reset in self.resets):
            raise ValueError("reset references an unknown clock")
        if any(signal.clock_id not in clocks for signal in self.signals):
            raise ValueError("signal references an unknown clock")
        return self


class CycleTraceInterface(StrictModel):
    profile: Literal[InterfaceProfile.CYCLE_TRACE] = InterfaceProfile.CYCLE_TRACE
    top_module: Identifier
    clock: ClockSpec
    reset: ResetSpec
    command_width: Annotated[int, Field(ge=1, le=65536)]
    response_width: Annotated[int, Field(ge=1, le=65536)]
    trace_width: Annotated[int, Field(ge=1, le=65536)]

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if self.reset.clock_id != self.clock.clock_id:
            raise ValueError("reset must reference the cycle-trace interface clock")
        return self


class WorkspaceInterface(StrictModel):
    """A file contract for EDA-flow tasks without an RTL port boundary."""

    profile: Literal[InterfaceProfile.WORKSPACE] = InterfaceProfile.WORKSPACE
    submission_paths: tuple[str, ...]

    @field_validator("submission_paths")
    @classmethod
    def normalize_submission_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        paths = tuple(sorted(validate_relative_path(path) for path in value))
        path_objects = tuple(PurePosixPath(path) for path in paths)
        if (
            not paths
            or len(paths) != len(set(paths))
            or any(
                left in right.parents or right in left.parents
                for position, left in enumerate(path_objects)
                for right in path_objects[position + 1 :]
            )
        ):
            raise ValueError("workspace submissions require unique non-empty non-overlapping paths")
        return paths


InterfaceSpec = Annotated[
    ScalarInterface
    | StreamInterface
    | MmioInterface
    | BusBridgeInterface
    | MemoryMasterInterface
    | MultiClockInterface
    | CycleTraceInterface
    | WorkspaceInterface,
    Field(discriminator="profile"),
]


class IntegerDomain(StrictModel):
    kind: Literal[ParameterKind.INTEGER] = ParameterKind.INTEGER
    parameter_id: Identifier
    default: int
    minimum: int
    maximum: int
    step: Annotated[int, Field(gt=0)] = 1

    @model_validator(mode="after")
    def validate_domain(self) -> Self:
        if self.minimum > self.maximum or not self.minimum <= self.default <= self.maximum:
            raise ValueError("integer domain bounds must contain the default")
        if (self.default - self.minimum) % self.step:
            raise ValueError("integer default must lie on its declared step")
        return self


class BooleanDomain(StrictModel):
    kind: Literal[ParameterKind.BOOLEAN] = ParameterKind.BOOLEAN
    parameter_id: Identifier
    default: bool


class ChoiceDomain(StrictModel):
    kind: Literal[ParameterKind.CHOICE] = ParameterKind.CHOICE
    parameter_id: Identifier
    default: str
    choices: tuple[str, ...]

    @field_validator("choices")
    @classmethod
    def normalize_choices(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("choice domain values must be unique and non-empty")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_default(self) -> Self:
        if self.default not in self.choices:
            raise ValueError("choice default must be one of its values")
        return self


ParameterDomain = Annotated[
    IntegerDomain | BooleanDomain | ChoiceDomain,
    Field(discriminator="kind"),
]


class ResourceSpec(StrictModel):
    resource_id: Identifier
    content_digest: Digest
    media_type: Annotated[str, Field(min_length=1, max_length=120)]
    path: str
    dependencies: tuple[Identifier, ...] = ()

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @field_validator("dependencies")
    @classmethod
    def normalize_dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("resource dependencies must be unique")
        return tuple(sorted(value))


class ResourceVisibility(StrictModel):
    resource_id: Identifier
    visibility: Visibility
    sensitivity: Sensitivity


class ResourceLicense(StrictModel):
    resource_id: Identifier
    spdx_expression: SpdxExpression
    redistribution: Redistribution
    provenance: tuple[str, ...] = ()

    @field_validator("provenance")
    @classmethod
    def normalize_provenance(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("resource provenance entries must be unique")
        return tuple(sorted(value))


class GeneratorSpec(StrictModel):
    implementation_resource: Identifier
    implementation_digest: Digest
    seed_bits: Literal[32, 64, 128] = 64
    parameters: tuple[ParameterDomain, ...] = ()
    deterministic: Literal[True] = True

    @field_validator("parameters")
    @classmethod
    def normalize_parameters(
        cls, value: tuple[ParameterDomain, ...]
    ) -> tuple[ParameterDomain, ...]:
        return tuple(sorted(value, key=lambda parameter: parameter.parameter_id))

    @model_validator(mode="after")
    def validate_identifiers(self) -> Self:
        identifiers = [parameter.parameter_id for parameter in self.parameters]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("generator parameter identifiers must be unique")
        return self


class RequirementSpec(StrictModel):
    requirement_id: Identifier
    kind: RequirementKind
    description: Annotated[str, Field(min_length=1, max_length=500)]


class ContractSpec(StrictModel):
    public_behavior_resource: Identifier
    allowed_freedoms: tuple[Identifier, ...] = ()
    requirements: tuple[RequirementSpec, ...]

    @field_validator("allowed_freedoms")
    @classmethod
    def normalize_freedoms(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("allowed freedoms must be unique")
        return tuple(sorted(value))

    @field_validator("requirements")
    @classmethod
    def normalize_requirements(
        cls, value: tuple[RequirementSpec, ...]
    ) -> tuple[RequirementSpec, ...]:
        return tuple(sorted(value, key=lambda requirement: requirement.requirement_id))

    @model_validator(mode="after")
    def validate_requirements(self) -> Self:
        identifiers = [requirement.requirement_id for requirement in self.requirements]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("requirement identifiers must be unique and non-empty")
        return self


class EvaluatorSpec(StrictModel):
    evaluator_id: Identifier
    capability: Capability
    supporting_capabilities: tuple[Capability, ...] = ()
    implementation_resource: Identifier
    revision_digest: Digest

    @field_validator("supporting_capabilities")
    @classmethod
    def normalize_supporting_capabilities(
        cls, value: tuple[Capability, ...]
    ) -> tuple[Capability, ...]:
        if len(value) != len(set(value)):
            raise ValueError("evaluator supporting capabilities must be unique")
        return tuple(sorted(value, key=lambda capability: capability.value))

    @model_validator(mode="after")
    def validate_supporting_capabilities(self) -> Self:
        if self.capability in self.supporting_capabilities:
            raise ValueError("an evaluator primary capability cannot also be supporting")
        return self


class StageSpec(StrictModel):
    stage_id: Identifier
    evaluator_id: Identifier
    depends_on: tuple[Identifier, ...] = ()
    purpose: StagePurpose
    requirement_ids: tuple[Identifier, ...] = ()

    @field_validator("depends_on", "requirement_ids")
    @classmethod
    def normalize_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("stage references must be unique")
        return tuple(sorted(value))


class MeasurementSpec(StrictModel):
    measurement_id: Identifier
    producer_stage_id: Identifier
    unit: MeasurementUnit
    library_id: Identifier
    library_digest: Digest
    corner: Identifier
    mode: Identifier
    direction: MetricDirection
    repetitions: Annotated[int, Field(ge=1, le=1000)]
    aggregation: Aggregation
    aggregation_precision_digits: Annotated[int, Field(ge=1, le=100)] = 34
    valid_minimum: CanonicalDecimal | None = None
    valid_maximum: CanonicalDecimal | None = None
    target: CanonicalDecimal | None = None

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        if (
            self.valid_minimum is not None
            and self.valid_maximum is not None
            and self.valid_minimum > self.valid_maximum
        ):
            raise ValueError("measurement minimum cannot exceed maximum")
        if self.direction is MetricDirection.TARGET and self.target is None:
            raise ValueError("target measurements require a target value")
        if self.direction is not MetricDirection.TARGET and self.target is not None:
            raise ValueError("only target measurements may define target")
        if self.aggregation is Aggregation.WORST and self.direction is MetricDirection.NONE:
            raise ValueError("worst aggregation requires an optimization direction")
        return self


class ScorerKind(StrEnum):
    WEIGHTED_SUM = "weighted_sum"


MAX_SCORER_TERMS = 1000


class ScorerTerm(StrictModel):
    measurement_id: Identifier
    coefficient: CanonicalDecimal

    @field_validator("coefficient")
    @classmethod
    def reject_zero_coefficient(cls, value: CanonicalDecimal) -> CanonicalDecimal:
        if value == 0:
            raise ValueError("scorer coefficients must be nonzero")
        return value


class ScorerRef(StrictModel):
    kind: Literal[ScorerKind.WEIGHTED_SUM] = ScorerKind.WEIGHTED_SUM
    implementation_resource: Identifier
    direction: Literal[MetricDirection.MINIMIZE, MetricDirection.MAXIMIZE]
    precision_digits: Annotated[int, Field(ge=1, le=100)] = 34
    intercept: CanonicalDecimal = Decimal(0)
    terms: Annotated[
        tuple[ScorerTerm, ...],
        Field(min_length=1, max_length=MAX_SCORER_TERMS),
    ]

    @field_validator("terms")
    @classmethod
    def normalize_terms(cls, value: tuple[ScorerTerm, ...]) -> tuple[ScorerTerm, ...]:
        identifiers = [term.measurement_id for term in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("scorer measurement terms must be unique")
        return tuple(sorted(value, key=lambda term: term.measurement_id))

    @property
    def definition(self) -> dict[str, object]:
        return {
            "direction": self.direction,
            "intercept": self.intercept,
            "kind": self.kind,
            "precision_digits": self.precision_digits,
            "terms": self.terms,
        }

    @property
    def implementation_digest(self) -> Digest:
        return f"sha256:{hashlib.sha256(canonical_bytes(self.definition)).hexdigest()}"

    @property
    def revision_digest(self) -> Digest:
        return canonical_digest(self.definition, domain="weighted-sum-scorer-v1")


class EvaluationGraph(StrictModel):
    evaluators: tuple[EvaluatorSpec, ...]
    stages: tuple[StageSpec, ...]
    scorer: ScorerRef | None = None

    @field_validator("evaluators")
    @classmethod
    def normalize_evaluators(cls, value: tuple[EvaluatorSpec, ...]) -> tuple[EvaluatorSpec, ...]:
        return tuple(sorted(value, key=lambda evaluator: evaluator.evaluator_id))

    @field_validator("stages")
    @classmethod
    def normalize_stages(cls, value: tuple[StageSpec, ...]) -> tuple[StageSpec, ...]:
        return tuple(sorted(value, key=lambda stage: stage.stage_id))


class DifficultyAxis(StrictModel):
    axis_id: Identifier
    parameter_id: Identifier
    relation: DifficultyRelation = DifficultyRelation.EMPIRICAL


class QualificationKind(StrEnum):
    SAIL_RTL = "sail_rtl"
    EDA_FLOW = "eda_flow"


class QualificationSpec(StrictModel):
    kind: Literal[QualificationKind.SAIL_RTL] = QualificationKind.SAIL_RTL
    sail_oracle_resource: Identifier
    known_answer_resources: tuple[Identifier, ...]
    reference_candidate_resource: Identifier
    mutant_resources: tuple[Identifier, ...]
    cross_check_resources: tuple[Identifier, ...] = ()
    required_simulators: Annotated[int, Field(ge=1)] = 2
    require_asic_synthesis: Literal[True] = True
    require_formal: bool
    temporal_rule_ids: tuple[Identifier, ...]
    structural_rule_ids: tuple[Identifier, ...]

    @field_validator(
        "known_answer_resources",
        "mutant_resources",
        "cross_check_resources",
        "temporal_rule_ids",
        "structural_rule_ids",
    )
    @classmethod
    def normalize_resources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("qualification resource references must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if not self.known_answer_resources:
            raise ValueError("qualification requires independent known answers")
        if len(self.mutant_resources) < 3:
            raise ValueError("qualification requires at least three semantic mutants")
        if not self.temporal_rule_ids or not self.structural_rule_ids:
            raise ValueError("qualification requires temporal and structural rules")
        return self


class FlowQualificationSpec(StrictModel):
    kind: Literal[QualificationKind.EDA_FLOW] = QualificationKind.EDA_FLOW
    authoring_source_resource: Identifier
    feasibility_witness_resource: Identifier
    negative_candidate_resources: tuple[Identifier, ...]

    @field_validator("negative_candidate_resources")
    @classmethod
    def normalize_negative_candidates(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("flow qualification requires unique negative candidates")
        return tuple(sorted(value))


TaskQualificationSpec = Annotated[
    QualificationSpec | FlowQualificationSpec,
    Field(discriminator="kind"),
]


class TaskNamespace(StrEnum):
    NATIVE_SEALED = "native_sealed"
    PUBLIC_CALIBRATION = "public_calibration"


class NativeSealedTaskOrigin(StrictModel):
    namespace: Literal[TaskNamespace.NATIVE_SEALED] = TaskNamespace.NATIVE_SEALED
    provenance: tuple[str, ...] = ()

    @field_validator("provenance")
    @classmethod
    def normalize_provenance(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("task provenance entries must be unique")
        return tuple(sorted(value))


class PublicCalibrationTaskOrigin(StrictModel):
    """Immutable manifest identity for one public benchmark source snapshot."""

    namespace: Literal[TaskNamespace.PUBLIC_CALIBRATION] = TaskNamespace.PUBLIC_CALIBRATION
    source_id: Identifier
    source_snapshot_digest: Digest
    source_resource_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    license_spdx_expression: SpdxExpression
    redistribution: Redistribution
    provenance: Annotated[tuple[str, ...], Field(min_length=1)]

    @field_validator("source_resource_ids")
    @classmethod
    def normalize_source_resources(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("public benchmark source resources must be unique")
        return tuple(sorted(value))

    @field_validator("provenance")
    @classmethod
    def normalize_provenance(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not entry.strip() for entry in value):
            raise ValueError("public benchmark provenance must be unique and non-empty")
        return tuple(sorted(value))


TaskOrigin = Annotated[
    NativeSealedTaskOrigin | PublicCalibrationTaskOrigin,
    Field(discriminator="namespace"),
]


class TaskIdentity(StrictModel):
    family: Identifier
    authoring_revision: Annotated[int, Field(ge=1)]
    origin: TaskOrigin = NativeSealedTaskOrigin()

    @property
    def namespace(self) -> TaskNamespace:
        return self.origin.namespace

    @property
    def provenance(self) -> tuple[str, ...]:
        return self.origin.provenance


class TaskSpec(StrictModel):
    schema_version: SchemaVersion = 1
    identity: TaskIdentity
    interface: InterfaceSpec
    generator: GeneratorSpec
    contract: ContractSpec
    resources: tuple[ResourceSpec, ...]
    visibility: tuple[ResourceVisibility, ...]
    evaluation: EvaluationGraph
    measurements: tuple[MeasurementSpec, ...] = ()
    difficulty_axes: tuple[DifficultyAxis, ...] = ()
    qualification: TaskQualificationSpec
    licensing: tuple[ResourceLicense, ...]

    @field_validator("resources")
    @classmethod
    def normalize_resources(cls, value: tuple[ResourceSpec, ...]) -> tuple[ResourceSpec, ...]:
        return tuple(sorted(value, key=lambda resource: resource.resource_id))

    @field_validator("visibility")
    @classmethod
    def normalize_visibility(
        cls, value: tuple[ResourceVisibility, ...]
    ) -> tuple[ResourceVisibility, ...]:
        return tuple(sorted(value, key=lambda item: item.resource_id))

    @field_validator("measurements")
    @classmethod
    def normalize_measurements(
        cls, value: tuple[MeasurementSpec, ...]
    ) -> tuple[MeasurementSpec, ...]:
        return tuple(sorted(value, key=lambda measurement: measurement.measurement_id))

    @field_validator("difficulty_axes")
    @classmethod
    def normalize_difficulty(cls, value: tuple[DifficultyAxis, ...]) -> tuple[DifficultyAxis, ...]:
        return tuple(sorted(value, key=lambda axis: axis.axis_id))

    @field_validator("licensing")
    @classmethod
    def normalize_licensing(cls, value: tuple[ResourceLicense, ...]) -> tuple[ResourceLicense, ...]:
        return tuple(sorted(value, key=lambda item: item.resource_id))

    @model_validator(mode="after")
    def validate_task(self) -> Self:
        if isinstance(self.qualification, FlowQualificationSpec) != isinstance(
            self.interface, WorkspaceInterface
        ):
            raise ValueError("flow qualification and workspace interfaces must be paired")
        resources = {resource.resource_id: resource for resource in self.resources}
        if len(resources) != len(self.resources) or not resources:
            raise ValueError("resource identifiers must be unique and non-empty")
        paths = [resource.path for resource in self.resources]
        if len(paths) != len(set(paths)):
            raise ValueError("resource paths must be unique")
        for resource in self.resources:
            if set(resource.dependencies) - resources.keys():
                raise ValueError(f"resource {resource.resource_id!r} has unknown dependencies")
            if resource.resource_id in resource.dependencies:
                raise ValueError("resources cannot depend on themselves")

        visibility = {item.resource_id: item for item in self.visibility}
        licenses = {item.resource_id: item for item in self.licensing}
        if len(visibility) != len(self.visibility) or set(visibility) != set(resources):
            raise ValueError("visibility must have exactly one entry per resource")
        if len(licenses) != len(self.licensing) or set(licenses) != set(resources):
            raise ValueError("licensing must have exactly one entry per resource")
        if isinstance(self.identity.origin, PublicCalibrationTaskOrigin):
            source_resources = set(self.identity.origin.source_resource_ids)
            if source_resources - resources.keys():
                raise ValueError("public benchmark origin references unknown source resources")
            if any(
                (
                    item.spdx_expression,
                    item.redistribution,
                    item.provenance,
                )
                != (
                    self.identity.origin.license_spdx_expression,
                    self.identity.origin.redistribution,
                    self.identity.origin.provenance,
                )
                for item in self.licensing
                if item.resource_id in source_resources
            ):
                raise ValueError("public source resource licenses must derive from the task origin")
        for resource_id, item in visibility.items():
            license_item = licenses[resource_id]
            if item.visibility is Visibility.PUBLIC:
                if item.sensitivity is not Sensitivity.PUBLIC:
                    raise ValueError("public resources require public sensitivity")
                if license_item.redistribution is not Redistribution.ALLOWED:
                    raise ValueError("public resources must allow redistribution")
            if item.visibility is Visibility.PARTICIPANT and item.sensitivity is Sensitivity.SECRET:
                raise ValueError("participant resources cannot contain secrets")

        visible_dependencies = {
            Visibility.PUBLIC: {Visibility.PUBLIC},
            Visibility.PARTICIPANT: {Visibility.PUBLIC, Visibility.PARTICIPANT},
            Visibility.REVIEWER: {Visibility.PUBLIC, Visibility.PARTICIPANT, Visibility.REVIEWER},
            Visibility.VERIFIER: {Visibility.PUBLIC, Visibility.PARTICIPANT, Visibility.VERIFIER},
            Visibility.AUTHOR: set(Visibility),
        }
        for resource in self.resources:
            owner_visibility = visibility[resource.resource_id].visibility
            allowed = visible_dependencies[owner_visibility]
            if any(
                visibility[dependency].visibility not in allowed
                for dependency in resource.dependencies
            ):
                raise ValueError("resource visibility dependencies are not projection-closed")

        qualification_resources: set[str]
        hidden_qualification_resources: set[str]
        if isinstance(self.qualification, QualificationSpec):
            qualification_resources = {
                self.qualification.sail_oracle_resource,
                *self.qualification.known_answer_resources,
                self.qualification.reference_candidate_resource,
                *self.qualification.mutant_resources,
                *self.qualification.cross_check_resources,
            }
            hidden_qualification_resources = {
                self.qualification.sail_oracle_resource,
                *self.qualification.known_answer_resources,
                self.qualification.reference_candidate_resource,
                *self.qualification.mutant_resources,
            }
        else:
            qualification_resources = {
                self.qualification.authoring_source_resource,
                self.qualification.feasibility_witness_resource,
                *self.qualification.negative_candidate_resources,
            }
            hidden_qualification_resources = set(qualification_resources)

        referenced_resources = {
            self.generator.implementation_resource,
            self.contract.public_behavior_resource,
            *(evaluator.implementation_resource for evaluator in self.evaluation.evaluators),
            *(
                ()
                if self.evaluation.scorer is None
                else (self.evaluation.scorer.implementation_resource,)
            ),
            *qualification_resources,
        }
        if referenced_resources - resources.keys():
            raise ValueError("task references unknown resources")
        if self.evaluation.scorer is not None:
            scorer = self.evaluation.scorer
            if not self.measurements:
                raise ValueError("a bound scorer requires measurement inputs")
            scorer_resource = resources[scorer.implementation_resource]
            if (
                scorer_resource.media_type != "application/json"
                or scorer_resource.content_digest != scorer.implementation_digest
            ):
                raise ValueError("scorer resource must contain its canonical definition")
        if visibility[self.contract.public_behavior_resource].visibility not in {
            Visibility.PUBLIC,
            Visibility.PARTICIPANT,
        }:
            raise ValueError("public behavior must be participant-visible")
        if any(
            visibility[resource_id].visibility in {Visibility.PUBLIC, Visibility.PARTICIPANT}
            for resource_id in hidden_qualification_resources
        ):
            raise ValueError("qualification resources cannot be participant-visible")

        evaluators = {evaluator.evaluator_id: evaluator for evaluator in self.evaluation.evaluators}
        if len(evaluators) != len(self.evaluation.evaluators) or not evaluators:
            raise ValueError("evaluator identifiers must be unique and non-empty")
        stages = {stage.stage_id: stage for stage in self.evaluation.stages}
        if len(stages) != len(self.evaluation.stages) or not stages:
            raise ValueError("stage identifiers must be unique and non-empty")
        requirements = {requirement.requirement_id for requirement in self.contract.requirements}
        for stage in self.evaluation.stages:
            if stage.evaluator_id not in evaluators:
                raise ValueError(f"stage {stage.stage_id!r} references an unknown evaluator")
            if set(stage.depends_on) - stages.keys():
                raise ValueError(f"stage {stage.stage_id!r} has unknown dependencies")
            if stage.stage_id in stage.depends_on:
                raise ValueError("stages cannot depend on themselves")
            if set(stage.requirement_ids) - requirements:
                raise ValueError(f"stage {stage.stage_id!r} references unknown requirements")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(stage_id: str) -> None:
            if stage_id in visiting:
                raise ValueError("evaluation stages must form an acyclic graph")
            if stage_id in visited:
                return
            visiting.add(stage_id)
            for dependency in stages[stage_id].depends_on:
                visit(dependency)
            visiting.remove(stage_id)
            visited.add(stage_id)

        for stage_id in stages:
            visit(stage_id)

        hard_gates = [
            stage for stage in self.evaluation.stages if stage.purpose is StagePurpose.HARD_GATE
        ]
        if not hard_gates:
            raise ValueError("evaluation requires at least one hard gate")
        checked_requirements = {
            requirement for stage in hard_gates for requirement in stage.requirement_ids
        }
        if checked_requirements != requirements:
            raise ValueError("every hard requirement must be checked by a hard-gate stage")

        measurement_ids = [measurement.measurement_id for measurement in self.measurements]
        if len(measurement_ids) != len(set(measurement_ids)):
            raise ValueError("measurement identifiers must be unique")
        if (
            self.measurements
            and self.evaluation.scorer is None
            and all(
                measurement.direction is MetricDirection.NONE for measurement in self.measurements
            )
        ):
            raise ValueError("raw-vector scoring requires at least one objective")
        if self.evaluation.scorer is not None and (
            {term.measurement_id for term in self.evaluation.scorer.terms} - set(measurement_ids)
        ):
            raise ValueError("scorer terms must reference declared measurements")
        for measurement in self.measurements:
            if measurement.producer_stage_id not in stages:
                raise ValueError("measurement references an unknown producer stage")
            if measurement.library_id == "not_applicable":
                if measurement.library_digest != NOT_APPLICABLE_LIBRARY_DIGEST:
                    raise ValueError("the absent-library identity has one canonical digest")
            else:
                library = resources.get(measurement.library_id)
                if library is None or library.content_digest != measurement.library_digest:
                    raise ValueError("measurement library must bind one immutable task resource")
        repetitions_by_stage: dict[str, set[int]] = {}
        for measurement in self.measurements:
            repetitions_by_stage.setdefault(measurement.producer_stage_id, set()).add(
                measurement.repetitions
            )
        if any(len(values) != 1 for values in repetitions_by_stage.values()):
            raise ValueError("measurements from one stage must share a repetition count")

        parameters = {parameter.parameter_id for parameter in self.generator.parameters}
        axes = [axis.axis_id for axis in self.difficulty_axes]
        if len(axes) != len(set(axes)):
            raise ValueError("difficulty axis identifiers must be unique")
        if any(axis.parameter_id not in parameters for axis in self.difficulty_axes):
            raise ValueError("difficulty axes must reference generator parameters")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="task-spec-v1")
