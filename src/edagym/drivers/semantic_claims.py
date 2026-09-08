"""Canonical semantic joints and release-coverage contracts for backend capabilities.

A fixture claims the exact joints its parser exercises. A tool-capability pair is
conformant for that claim when both fixture roles pass. Release coverage of one
capability is derived from the union of the conformant claims against the contract
owned here: every required joint must be claimed by at least one conformant tool, the
conformant implementation families must reach the independence minimum, and every
required vendor and tool must be present.
"""

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
    FORMAL_PROPERTY_NONVACUOUS = "formal.property.nonvacuous"

    EQUIVALENCE_EQUIVALENT = "formal.equivalence.equivalent"
    EQUIVALENCE_MISMATCH = "formal.equivalence.mismatch"

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

    DFT_CHAIN_INTEGRITY = "dft.insertion.chain_integrity"
    DFT_COVERAGE = "dft.insertion.coverage"
    DFT_INVALID_SETUP = "dft.insertion.invalid_setup"

    CELL_CHARACTERIZATION_PVT = "cell.characterization.pvt"
    CELL_CHARACTERIZATION_ARCS = "cell.characterization.arcs"
    CELL_CHARACTERIZATION_LIBERTY = "cell.characterization.liberty"
    CELL_CHARACTERIZATION_CONSISTENCY = "cell.characterization.consistency"
    CELL_CHARACTERIZATION_FAILED_ARC = "cell.characterization.failed_arc"


def joint_capability(joint: SemanticJoint) -> Capability:
    """Return the capability that owns one semantic joint."""

    return Capability(joint.value.rsplit(".", 1)[0])


class CapabilitySemanticContract(StrictModel):
    capability: Capability
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
        if any(joint_capability(joint) is not self.capability for joint in self.required_joints):
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
    def comprehensive_claim_id(self) -> Identifier:
        """Claim identity of a fixture that exercises every required joint."""

        return semantic_claim_id(self.capability, self.required_joints)

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="backend-capability-semantic-contract-v2")


def _contract(
    capability: Capability,
    joints: tuple[SemanticJoint, ...],
    minimum: int = 1,
    *,
    vendors: tuple[Vendor, ...] = (),
    tools: tuple[str, ...] = (),
) -> CapabilitySemanticContract:
    return CapabilitySemanticContract(
        capability=capability,
        required_joints=joints,
        minimum_independent_implementations=minimum,
        required_vendors=vendors,
        required_tool_ids=tools,
    )


_THREE_VENDOR_CHAIN = (Vendor.OPEN_SOURCE, Vendor.CADENCE, Vendor.SYNOPSYS)

CAPABILITY_SEMANTIC_CONTRACTS: tuple[CapabilitySemanticContract, ...] = (
    _contract(
        Capability.HW_IR_LOWERING,
        (SemanticJoint.HW_IR_OUTPUT, SemanticJoint.HW_IR_SEQUENTIAL_STRUCTURE),
    ),
    _contract(
        Capability.RTL_SIMULATION,
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
        (
            SemanticJoint.RTL_LINT_CLEAN,
            SemanticJoint.RTL_LINT_RULE_VIOLATION,
            SemanticJoint.RTL_LINT_NATIVE_DIAGNOSTICS,
        ),
    ),
    _contract(
        Capability.CDC_RDC,
        (
            SemanticJoint.CDC_RDC_CDC,
            SemanticJoint.CDC_RDC_RDC,
            SemanticJoint.CDC_RDC_CLEAN,
            SemanticJoint.CDC_RDC_VIOLATION,
        ),
    ),
    _contract(
        Capability.FORMAL_PROPERTY,
        (
            SemanticJoint.FORMAL_PROPERTY_PROVED,
            SemanticJoint.FORMAL_PROPERTY_COUNTEREXAMPLE,
            SemanticJoint.FORMAL_PROPERTY_NONVACUOUS,
        ),
        2,
    ),
    _contract(
        Capability.EQUIVALENCE,
        (SemanticJoint.EQUIVALENCE_EQUIVALENT, SemanticJoint.EQUIVALENCE_MISMATCH),
        2,
    ),
    _contract(
        Capability.ASIC_SYNTHESIS,
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
        (
            SemanticJoint.POWER_ANALYSIS_ACTIVITY_COVERAGE,
            SemanticJoint.POWER_ANALYSIS_DYNAMIC,
            SemanticJoint.POWER_ANALYSIS_LEAKAGE,
        ),
    ),
    _contract(
        Capability.POWER_INTEGRITY,
        (
            SemanticJoint.POWER_INTEGRITY_IR_DROP_GRID,
            SemanticJoint.POWER_INTEGRITY_VIOLATIONS,
        ),
    ),
    _contract(
        Capability.PARASITIC_EXTRACTION,
        (
            SemanticJoint.PARASITIC_EXTRACTION_ROUTED_RC,
            SemanticJoint.PARASITIC_EXTRACTION_SPEF,
            SemanticJoint.PARASITIC_EXTRACTION_NET_COUNT,
            SemanticJoint.PARASITIC_EXTRACTION_CORNER,
        ),
    ),
    _contract(
        Capability.PHYSICAL_VERIFICATION,
        (
            SemanticJoint.PHYSICAL_VERIFICATION_DRC,
            SemanticJoint.PHYSICAL_VERIFICATION_LVS,
            SemanticJoint.PHYSICAL_VERIFICATION_RESULTS_DATABASE,
        ),
        2,
    ),
    _contract(
        Capability.CIRCUIT_SIMULATION,
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
        (
            SemanticJoint.HLS_GENERATED_RTL,
            SemanticJoint.HLS_RTL_EQUIVALENCE,
            SemanticJoint.HLS_LATENCY,
            SemanticJoint.HLS_RESOURCE,
        ),
    ),
    _contract(
        Capability.DESIGN_FOR_TEST,
        (
            SemanticJoint.DFT_CHAIN_INTEGRITY,
            SemanticJoint.DFT_COVERAGE,
            SemanticJoint.DFT_INVALID_SETUP,
        ),
    ),
    _contract(
        Capability.CELL_CHARACTERIZATION,
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
    if not normalized or len(normalized) != len(set(normalized)):
        raise ValueError("fixture semantic joints must be a nonempty unique set")
    if any(joint_capability(item) is not capability for item in normalized):
        raise ValueError("fixture semantic joint belongs to a different capability")
    return normalized


def semantic_claim_id(
    capability: Capability,
    joints: tuple[SemanticJoint, ...],
) -> Identifier:
    """Derive the only claim identity for an exact capability-joint set."""

    normalized = normalize_semantic_joints(capability, joints)
    digest = canonical_digest(
        {"capability": capability, "semantic_joints": normalized},
        domain="backend-semantic-claim-v2",
    )
    return f"claim-{digest.removeprefix('sha256:')}"
