"""Canonical semantic and release-coverage contracts for backend capabilities."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.drivers.model import Vendor
from edagym.specs.common import Capability, Digest, Identifier, StrictModel


class SemanticJoint(StrEnum):
    HW_IR_OUTPUT = "hw.ir_lowering.output_rtl"
    HW_IR_SEQUENTIAL_STRUCTURE = "hw.ir_lowering.sequential_structure"

    RTL_SIMULATION_EVENT_TRACE = "rtl.simulation.event_trace"
    RTL_SIMULATION_WAVEFORM = "rtl.simulation.waveform"
    RTL_SIMULATION_FUNCTIONAL_MISMATCH = "rtl.simulation.functional_mismatch"

    RTL_LINT_CLEAN = "rtl.lint.clean"
    RTL_LINT_RULE_VIOLATION = "rtl.lint.rule_violation"
    RTL_LINT_NATIVE_DIAGNOSTICS = "rtl.lint.native_diagnostics"

    CDC_RDC_CDC = "rtl.cdc_rdc.cdc"
    CDC_RDC_RDC = "rtl.cdc_rdc.rdc"
    CDC_RDC_CLEAN = "rtl.cdc_rdc.clean"
    CDC_RDC_VIOLATION = "rtl.cdc_rdc.violation"

    FORMAL_PROPERTY_PROVED = "formal.property.proved"
    FORMAL_PROPERTY_COUNTEREXAMPLE = "formal.property.counterexample"
    FORMAL_PROPERTY_UNKNOWN = "formal.property.unknown"
    FORMAL_PROPERTY_NONVACUOUS = "formal.property.nonvacuous"

    EQUIVALENCE_EQUIVALENT = "formal.equivalence.equivalent"
    EQUIVALENCE_MISMATCH = "formal.equivalence.mismatch"
    EQUIVALENCE_INCONCLUSIVE = "formal.equivalence.inconclusive"

    ASIC_SYNTHESIS_RTL = "asic.synthesis.rtl"
    ASIC_SYNTHESIS_CONSTRAINTS = "asic.synthesis.constraints"
    ASIC_SYNTHESIS_LIBRARY = "asic.synthesis.library"
    ASIC_SYNTHESIS_NETLIST = "asic.synthesis.netlist"
    ASIC_SYNTHESIS_AREA = "asic.synthesis.area"
    ASIC_SYNTHESIS_CELLS = "asic.synthesis.cells"
    ASIC_SYNTHESIS_TIMING = "asic.synthesis.timing"

    STATIC_TIMING_SETUP = "asic.sta.setup"
    STATIC_TIMING_HOLD = "asic.sta.hold"
    STATIC_TIMING_CORNER = "asic.sta.corner"
    STATIC_TIMING_MODE = "asic.sta.mode"
    STATIC_TIMING_CLEAN = "asic.sta.clean"
    STATIC_TIMING_VIOLATION = "asic.sta.violation"

    DIGITAL_IMPLEMENTATION_ROUTED_DATABASE = "asic.pnr.routed_database"
    DIGITAL_IMPLEMENTATION_WNS = "asic.pnr.wns"
    DIGITAL_IMPLEMENTATION_TNS = "asic.pnr.tns"
    DIGITAL_IMPLEMENTATION_DRC = "asic.pnr.drc"
    DIGITAL_IMPLEMENTATION_AREA = "asic.pnr.area"
    DIGITAL_IMPLEMENTATION_SEED = "asic.pnr.seed"

    POWER_ANALYSIS_ACTIVITY_COVERAGE = "asic.power_analysis.activity_coverage"
    POWER_ANALYSIS_DYNAMIC = "asic.power_analysis.dynamic_power"
    POWER_ANALYSIS_LEAKAGE = "asic.power_analysis.leakage_power"

    POWER_INTEGRITY_IR_DROP_GRID = "asic.power_integrity.ir_drop_grid"
    POWER_INTEGRITY_VIOLATIONS = "asic.power_integrity.violations"

    PARASITIC_EXTRACTION_ROUTED_RC = "asic.parasitic_extraction.routed_rc"
    PARASITIC_EXTRACTION_SPEF = "asic.parasitic_extraction.spef"
    PARASITIC_EXTRACTION_NET_COUNT = "asic.parasitic_extraction.net_count"
    PARASITIC_EXTRACTION_CORNER = "asic.parasitic_extraction.corner"

    PHYSICAL_VERIFICATION_DRC = "physical.verification.drc"
    PHYSICAL_VERIFICATION_LVS = "physical.verification.lvs"
    PHYSICAL_VERIFICATION_RESULTS_DATABASE = "physical.verification.results_database"

    CIRCUIT_SIMULATION_DC = "circuit.simulation.dc"
    CIRCUIT_SIMULATION_AC = "circuit.simulation.ac"
    CIRCUIT_SIMULATION_TRANSIENT = "circuit.simulation.transient"
    CIRCUIT_SIMULATION_PVT = "circuit.simulation.pvt"
    CIRCUIT_SIMULATION_CONVERGENCE_FAILURE = "circuit.simulation.convergence_failure"
    CIRCUIT_SIMULATION_MEASUREMENT_REPLAY = "circuit.simulation.measurement_replay"

    FPGA_IMPLEMENTATION_SYNTHESIS = "fpga.implementation.synthesis"
    FPGA_IMPLEMENTATION_PLACE = "fpga.implementation.place"
    FPGA_IMPLEMENTATION_ROUTE = "fpga.implementation.route"
    FPGA_IMPLEMENTATION_PRE_BITSTREAM_CHECK = "fpga.implementation.pre_bitstream_check"
    FPGA_IMPLEMENTATION_FMAX = "fpga.implementation.fmax"
    FPGA_IMPLEMENTATION_UTILIZATION = "fpga.implementation.utilization"
    FPGA_IMPLEMENTATION_SEED = "fpga.implementation.seed"

    HLS_GENERATED_RTL = "hls.synthesis.generated_rtl"
    HLS_RTL_EQUIVALENCE = "hls.synthesis.rtl_equivalence"
    HLS_LATENCY = "hls.synthesis.latency"
    HLS_RESOURCE = "hls.synthesis.resource"

    DFT_INSERTION = "dft.insertion.insertion"
    DFT_CHAIN_INTEGRITY = "dft.insertion.chain_integrity"
    DFT_COVERAGE = "dft.insertion.coverage"
    DFT_INVALID_SETUP = "dft.insertion.invalid_setup"

    CELL_CHARACTERIZATION_PVT = "cell.characterization.pvt"
    CELL_CHARACTERIZATION_ARCS = "cell.characterization.arcs"
    CELL_CHARACTERIZATION_LIBERTY = "cell.characterization.liberty"
    CELL_CHARACTERIZATION_CONSISTENCY = "cell.characterization.consistency"
    CELL_CHARACTERIZATION_FAILED_ARC = "cell.characterization.failed_arc"


class CapabilitySemanticContract(StrictModel):
    capability: Capability
    comprehensive_claim_id: Identifier
    required_joints: tuple[SemanticJoint, ...]
    minimum_independent_implementations: Annotated[int, Field(strict=True, ge=1, le=3)]
    required_vendors: tuple[Vendor, ...] = ()
    required_tool_ids: tuple[Identifier, ...] = ()

    @field_validator("required_joints")
    @classmethod
    def normalize_joints(cls, value: tuple[SemanticJoint, ...]) -> tuple[SemanticJoint, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("semantic contracts require unique nonempty joints")
        return tuple(sorted(value, key=lambda item: item.value))

    @field_validator("required_vendors")
    @classmethod
    def normalize_vendors(cls, value: tuple[Vendor, ...]) -> tuple[Vendor, ...]:
        if len(value) != len(set(value)):
            raise ValueError("semantic contracts require unique vendors")
        return tuple(sorted(value, key=lambda item: item.value))

    @field_validator("required_tool_ids")
    @classmethod
    def normalize_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("semantic contracts require unique tools")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_joint_domain(self) -> Self:
        prefix = f"{self.capability.value}."
        if any(not joint.value.startswith(prefix) for joint in self.required_joints):
            raise ValueError("semantic joint belongs to a different capability")
        if self.required_tool_ids and len(self.required_tool_ids) < (
            self.minimum_independent_implementations
        ):
            raise ValueError("required tools cannot underfill the independence requirement")
        return self

    @property
    def effective_required_implementations(self) -> int:
        return max(
            self.minimum_independent_implementations,
            len(self.required_vendors),
            len(self.required_tool_ids),
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="backend-capability-semantic-contract-v1")


def _contract(
    capability: Capability,
    claim_id: str,
    joints: tuple[SemanticJoint, ...],
    minimum: int = 1,
    *,
    vendors: tuple[Vendor, ...] = (),
    tools: tuple[str, ...] = (),
) -> CapabilitySemanticContract:
    return CapabilitySemanticContract(
        capability=capability,
        comprehensive_claim_id=claim_id,
        required_joints=joints,
        minimum_independent_implementations=minimum,
        required_vendors=vendors,
        required_tool_ids=tools,
    )


_THREE_VENDOR_CHAIN = (Vendor.OPEN_SOURCE, Vendor.CADENCE, Vendor.SYNOPSYS)

CAPABILITY_SEMANTIC_CONTRACTS: tuple[CapabilitySemanticContract, ...] = (
    _contract(
        Capability.HW_IR_LOWERING,
        "hw-ir-lowering-comprehensive-v1",
        (SemanticJoint.HW_IR_OUTPUT, SemanticJoint.HW_IR_SEQUENTIAL_STRUCTURE),
    ),
    _contract(
        Capability.RTL_SIMULATION,
        "rtl-simulation-trace-waveform-v1",
        (
            SemanticJoint.RTL_SIMULATION_EVENT_TRACE,
            SemanticJoint.RTL_SIMULATION_WAVEFORM,
            SemanticJoint.RTL_SIMULATION_FUNCTIONAL_MISMATCH,
        ),
        2,
        vendors=_THREE_VENDOR_CHAIN,
    ),
    _contract(
        Capability.RTL_LINT,
        "rtl-lint-native-diagnostics-v1",
        (
            SemanticJoint.RTL_LINT_CLEAN,
            SemanticJoint.RTL_LINT_RULE_VIOLATION,
            SemanticJoint.RTL_LINT_NATIVE_DIAGNOSTICS,
        ),
    ),
    _contract(
        Capability.CDC_RDC,
        "rtl-cdc-rdc-comprehensive-v1",
        (
            SemanticJoint.CDC_RDC_CDC,
            SemanticJoint.CDC_RDC_RDC,
            SemanticJoint.CDC_RDC_CLEAN,
            SemanticJoint.CDC_RDC_VIOLATION,
        ),
    ),
    _contract(
        Capability.FORMAL_PROPERTY,
        "formal-property-tristate-nonvacuous-v1",
        (
            SemanticJoint.FORMAL_PROPERTY_PROVED,
            SemanticJoint.FORMAL_PROPERTY_COUNTEREXAMPLE,
            SemanticJoint.FORMAL_PROPERTY_UNKNOWN,
            SemanticJoint.FORMAL_PROPERTY_NONVACUOUS,
        ),
        2,
    ),
    _contract(
        Capability.EQUIVALENCE,
        "formal-equivalence-tristate-v1",
        (
            SemanticJoint.EQUIVALENCE_EQUIVALENT,
            SemanticJoint.EQUIVALENCE_MISMATCH,
            SemanticJoint.EQUIVALENCE_INCONCLUSIVE,
        ),
        2,
    ),
    _contract(
        Capability.ASIC_SYNTHESIS,
        "asic-synthesis-reports-v1",
        (
            SemanticJoint.ASIC_SYNTHESIS_RTL,
            SemanticJoint.ASIC_SYNTHESIS_CONSTRAINTS,
            SemanticJoint.ASIC_SYNTHESIS_LIBRARY,
            SemanticJoint.ASIC_SYNTHESIS_NETLIST,
            SemanticJoint.ASIC_SYNTHESIS_AREA,
            SemanticJoint.ASIC_SYNTHESIS_CELLS,
            SemanticJoint.ASIC_SYNTHESIS_TIMING,
        ),
        2,
        vendors=_THREE_VENDOR_CHAIN,
    ),
    _contract(
        Capability.STATIC_TIMING,
        "asic-sta-setup-hold-mmmc-v1",
        (
            SemanticJoint.STATIC_TIMING_SETUP,
            SemanticJoint.STATIC_TIMING_HOLD,
            SemanticJoint.STATIC_TIMING_CORNER,
            SemanticJoint.STATIC_TIMING_MODE,
            SemanticJoint.STATIC_TIMING_CLEAN,
            SemanticJoint.STATIC_TIMING_VIOLATION,
        ),
        2,
        vendors=_THREE_VENDOR_CHAIN,
    ),
    _contract(
        Capability.DIGITAL_IMPLEMENTATION,
        "asic-pnr-routed-qor-v1",
        (
            SemanticJoint.DIGITAL_IMPLEMENTATION_ROUTED_DATABASE,
            SemanticJoint.DIGITAL_IMPLEMENTATION_WNS,
            SemanticJoint.DIGITAL_IMPLEMENTATION_TNS,
            SemanticJoint.DIGITAL_IMPLEMENTATION_DRC,
            SemanticJoint.DIGITAL_IMPLEMENTATION_AREA,
            SemanticJoint.DIGITAL_IMPLEMENTATION_SEED,
        ),
        2,
        vendors=_THREE_VENDOR_CHAIN,
    ),
    _contract(
        Capability.POWER_ANALYSIS,
        "asic-power-activity-dynamic-leakage-v1",
        (
            SemanticJoint.POWER_ANALYSIS_ACTIVITY_COVERAGE,
            SemanticJoint.POWER_ANALYSIS_DYNAMIC,
            SemanticJoint.POWER_ANALYSIS_LEAKAGE,
        ),
    ),
    _contract(
        Capability.POWER_INTEGRITY,
        "asic-power-integrity-ir-grid-v1",
        (
            SemanticJoint.POWER_INTEGRITY_IR_DROP_GRID,
            SemanticJoint.POWER_INTEGRITY_VIOLATIONS,
        ),
    ),
    _contract(
        Capability.PARASITIC_EXTRACTION,
        "asic-parasitic-routed-rc-v1",
        (
            SemanticJoint.PARASITIC_EXTRACTION_ROUTED_RC,
            SemanticJoint.PARASITIC_EXTRACTION_SPEF,
            SemanticJoint.PARASITIC_EXTRACTION_NET_COUNT,
            SemanticJoint.PARASITIC_EXTRACTION_CORNER,
        ),
    ),
    _contract(
        Capability.PHYSICAL_VERIFICATION,
        "physical-verification-drc-lvs-v1",
        (
            SemanticJoint.PHYSICAL_VERIFICATION_DRC,
            SemanticJoint.PHYSICAL_VERIFICATION_LVS,
            SemanticJoint.PHYSICAL_VERIFICATION_RESULTS_DATABASE,
        ),
        2,
    ),
    _contract(
        Capability.CIRCUIT_SIMULATION,
        "circuit-simulation-analysis-pvt-v1",
        (
            SemanticJoint.CIRCUIT_SIMULATION_DC,
            SemanticJoint.CIRCUIT_SIMULATION_AC,
            SemanticJoint.CIRCUIT_SIMULATION_TRANSIENT,
            SemanticJoint.CIRCUIT_SIMULATION_PVT,
            SemanticJoint.CIRCUIT_SIMULATION_CONVERGENCE_FAILURE,
            SemanticJoint.CIRCUIT_SIMULATION_MEASUREMENT_REPLAY,
        ),
        2,
    ),
    _contract(
        Capability.FPGA_IMPLEMENTATION,
        "fpga-implementation-complete-v1",
        (
            SemanticJoint.FPGA_IMPLEMENTATION_SYNTHESIS,
            SemanticJoint.FPGA_IMPLEMENTATION_PLACE,
            SemanticJoint.FPGA_IMPLEMENTATION_ROUTE,
            SemanticJoint.FPGA_IMPLEMENTATION_PRE_BITSTREAM_CHECK,
            SemanticJoint.FPGA_IMPLEMENTATION_FMAX,
            SemanticJoint.FPGA_IMPLEMENTATION_UTILIZATION,
            SemanticJoint.FPGA_IMPLEMENTATION_SEED,
        ),
        3,
        tools=("vivado", "quartus", "achronix_ace"),
    ),
    _contract(
        Capability.HIGH_LEVEL_SYNTHESIS,
        "hls-rtl-equivalence-qor-v1",
        (
            SemanticJoint.HLS_GENERATED_RTL,
            SemanticJoint.HLS_RTL_EQUIVALENCE,
            SemanticJoint.HLS_LATENCY,
            SemanticJoint.HLS_RESOURCE,
        ),
    ),
    _contract(
        Capability.DESIGN_FOR_TEST,
        "dft-insertion-coverage-v1",
        (
            SemanticJoint.DFT_INSERTION,
            SemanticJoint.DFT_CHAIN_INTEGRITY,
            SemanticJoint.DFT_COVERAGE,
            SemanticJoint.DFT_INVALID_SETUP,
        ),
    ),
    _contract(
        Capability.CELL_CHARACTERIZATION,
        "cell-characterization-pvt-liberty-v1",
        (
            SemanticJoint.CELL_CHARACTERIZATION_PVT,
            SemanticJoint.CELL_CHARACTERIZATION_ARCS,
            SemanticJoint.CELL_CHARACTERIZATION_LIBERTY,
            SemanticJoint.CELL_CHARACTERIZATION_CONSISTENCY,
            SemanticJoint.CELL_CHARACTERIZATION_FAILED_ARC,
        ),
    ),
)

_CONTRACTS = {item.capability: item for item in CAPABILITY_SEMANTIC_CONTRACTS}
if len(_CONTRACTS) != len(CAPABILITY_SEMANTIC_CONTRACTS) or set(_CONTRACTS) != set(Capability):
    raise ValueError("capability semantic contracts must exactly cover the capability domain")


def semantic_contract(capability: Capability) -> CapabilitySemanticContract:
    """Return the sole release contract for one capability."""

    return _CONTRACTS[capability]


def normalize_semantic_joints(
    capability: Capability,
    joints: tuple[SemanticJoint, ...],
) -> tuple[SemanticJoint, ...]:
    """Validate and canonicalize one fixture's explicitly claimed semantic joints."""

    normalized = tuple(sorted(joints, key=lambda item: item.value))
    if len(normalized) != len(set(normalized)):
        raise ValueError("fixture semantic joints must be unique")
    prefix = f"{capability.value}."
    if any(not item.value.startswith(prefix) for item in normalized):
        raise ValueError("fixture semantic joint belongs to a different capability")
    return normalized


def claim_id_for_joints(
    capability: Capability,
    joints: tuple[SemanticJoint, ...],
) -> Identifier:
    """Derive the only claim identity for an exact capability-joint set."""

    normalized = normalize_semantic_joints(capability, joints)
    contract = semantic_contract(capability)
    if normalized == contract.required_joints:
        return contract.comprehensive_claim_id
    digest = canonical_digest(
        {"capability": capability, "semantic_joints": normalized},
        domain="backend-partial-semantic-claim-v1",
    )
    return f"partial-{digest.removeprefix('sha256:')}"


def is_comprehensive_claim(
    capability: Capability,
    claim_id: str,
    joints: tuple[SemanticJoint, ...],
) -> bool:
    """Return whether a claim exactly equals the canonical release contract."""

    contract = semantic_contract(capability)
    normalized = normalize_semantic_joints(capability, joints)
    return (
        normalized == contract.required_joints
        and claim_id == contract.comprehensive_claim_id
        and claim_id_for_joints(capability, normalized) == claim_id
    )
