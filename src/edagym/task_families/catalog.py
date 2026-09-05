"""Clean-room Sail-rooted task family and EDA equipment catalog."""

# ruff: noqa: E501

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Capability, Identifier, StrictModel
from edagym.specs.task import InterfaceProfile


class TaskRoot(StrEnum):
    SAIL_RTL = "sail_rtl"
    EDA_FLOW = "eda_flow"


class AxisRole(StrEnum):
    ARCHITECTURAL = "architectural"
    PROTOCOL = "protocol"
    STRUCTURAL = "structural"
    STIMULUS = "stimulus"


class ExcludedReferenceAbi(StrictModel):
    stream_data_width_bits: Literal[256] = 256
    axi_lite_data_width_bits: Literal[32] = 32
    memory_window_bytes: Literal[65536] = 65536


class CleanRoomExclusionSpec(StrictModel):
    semantic_families: tuple[Identifier, ...]
    fixed_abi: ExcludedReferenceAbi = ExcludedReferenceAbi()

    @field_validator("semantic_families")
    @classmethod
    def normalize_semantic_families(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("clean-room semantic exclusions must be unique and non-empty")
        return tuple(sorted(value))

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="clean-room-exclusion-spec-v1")


CLEAN_ROOM_EXCLUSION = CleanRoomExclusionSpec(
    semantic_families=(
        "aes_round",
        "bfs",
        "chacha20",
        "cic_filter",
        "convolution_3x3",
        "crc32",
        "csr_spmv",
        "dct",
        "deflate_huffman",
        "dot_product",
        "fft_stage",
        "fixed_reciprocal",
        "ghash",
        "lz4",
        "modular_arithmetic",
        "montgomery_multiply",
        "poly1305",
        "prefix_sum",
        "radix_partition",
        "reduction",
        "smith_waterman",
        "triangle_counting",
        "vector_add",
    )
)


class ParameterAxis(StrictModel):
    axis_id: Identifier
    base_value: Annotated[int, Field(strict=True, ge=0)]
    advanced_value: Annotated[int, Field(strict=True, ge=0)]
    role: AxisRole = AxisRole.ARCHITECTURAL

    @model_validator(mode="after")
    def require_distinct_values(self) -> Self:
        if self.advanced_value <= self.base_value:
            raise ValueError("advanced task family axes must be greater than base axes")
        return self


class TaskFamilyDefinition(StrictModel):
    """Public task-family metadata shared with participants and release tooling."""

    family: Identifier
    root: TaskRoot
    interface_profile: InterfaceProfile | None
    semantic_contract: Annotated[str, Field(min_length=20, max_length=500)]
    difficulty_axes: tuple[ParameterAxis, ...]
    required_capabilities: tuple[Capability, ...]
    instance_names: tuple[Literal["base"], Literal["advanced"]] = ("base", "advanced")

    @field_validator("difficulty_axes")
    @classmethod
    def normalize_axes(cls, value: tuple[ParameterAxis, ...]) -> tuple[ParameterAxis, ...]:
        identifiers = [item.axis_id for item in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("task family difficulty axes must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.axis_id))

    @field_validator("required_capabilities")
    @classmethod
    def normalize_capabilities(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("task capabilities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        if (self.root is TaskRoot.SAIL_RTL) != (self.interface_profile is not None):
            raise ValueError("only Sail-rooted RTL families own an interface profile")
        if self.instance_names != ("base", "advanced"):
            raise ValueError("task families require canonical base and advanced instances")
        if self.root is TaskRoot.EDA_FLOW and any(
            axis.role is not AxisRole.ARCHITECTURAL for axis in self.difficulty_axes
        ):
            raise ValueError("flow task axes use their canonical authoring interpretation")
        return self

    @property
    def sail_axes(self) -> tuple[ParameterAxis, ...]:
        """Return axes that alter the architectural transition function."""

        return tuple(axis for axis in self.difficulty_axes if axis.role is AxisRole.ARCHITECTURAL)

    @property
    def rtl_axes(self) -> tuple[ParameterAxis, ...]:
        """Return axes represented by candidate RTL parameters."""

        return tuple(
            axis
            for axis in self.difficulty_axes
            if axis.role in {AxisRole.ARCHITECTURAL, AxisRole.STRUCTURAL}
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="public-task-family-metadata-v1")


class PublicTaskCatalog(StrictModel):
    """Complete public metadata boundary for private task authoring."""

    clean_room_exclusion: CleanRoomExclusionSpec
    families: tuple[TaskFamilyDefinition, ...]

    @field_validator("families")
    @classmethod
    def normalize_families(
        cls,
        value: tuple[TaskFamilyDefinition, ...],
    ) -> tuple[TaskFamilyDefinition, ...]:
        identifiers = [item.family for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("public task families must have unique identifiers")
        return tuple(sorted(value, key=lambda item: item.family))

    @model_validator(mode="after")
    def validate_roots(self) -> Self:
        sail_count = sum(item.root is TaskRoot.SAIL_RTL for item in self.families)
        flow_count = sum(item.root is TaskRoot.EDA_FLOW for item in self.families)
        if sail_count != 20 or flow_count != 12:
            raise ValueError("public task catalog requires 20 Sail and 12 flow families")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="public-task-family-catalog-v1")


def _axis(
    name: str,
    base: int,
    advanced: int,
    role: AxisRole = AxisRole.ARCHITECTURAL,
) -> ParameterAxis:
    return ParameterAxis(
        axis_id=name,
        base_value=base,
        advanced_value=advanced,
        role=role,
    )


def _sail(
    family: str,
    profile: InterfaceProfile,
    contract: str,
    axes: tuple[ParameterAxis, ...],
    capabilities: tuple[Capability, ...],
) -> TaskFamilyDefinition:
    scoped_contract = (
        "At the normalized state-transition boundary, with prior architectural state supplied "
        f"explicitly, {contract[0].lower()}{contract[1:]}"
    )
    return TaskFamilyDefinition(
        family=family,
        root=TaskRoot.SAIL_RTL,
        interface_profile=profile,
        semantic_contract=scoped_contract,
        difficulty_axes=axes,
        required_capabilities=tuple({*capabilities, Capability.ASIC_SYNTHESIS}),
    )


SAIL_RTL_FAMILIES: tuple[TaskFamilyDefinition, ...] = (
    _sail(
        "axi_lite_csr_slave",
        InterfaceProfile.MMIO,
        "Accept independently ordered address and data channels with register side effects, strobes, and typed error responses.",
        (
            _axis("csr_count", 8, 64),
            _axis("channel_skew", 1, 8, AxisRole.PROTOCOL),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "apb_wishbone_bridge",
        InterfaceProfile.BUS_BRIDGE,
        "Translate APB4 requests to Wishbone B4 while preserving waits, errors, consecutive transfers, and reset aborts.",
        (
            _axis("address_width", 12, 32, AxisRole.STIMULUS),
            _axis("wait_cycles", 1, 12, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "deficit_round_robin_arbiter",
        InterfaceProfile.CYCLE_TRACE,
        "Schedule packet requests using per-port deficits, configurable quanta, packet costs, blocking, and bounded fairness.",
        (_axis("port_count", 4, 16), _axis("maximum_cost", 8, 64)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "async_fifo_gray",
        InterfaceProfile.MULTI_CLOCK,
        "Transfer ordered data across independent clocks using Gray pointers, synchronized state, and skewed reset semantics.",
        (
            _axis("depth", 8, 64),
            _axis("synchronizer_stages", 2, 3, AxisRole.STRUCTURAL),
        ),
        (Capability.RTL_SIMULATION, Capability.CDC_RDC, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "wormhole_vc_router",
        InterfaceProfile.CYCLE_TRACE,
        "Route packets by XY coordinates with virtual channels, credits, packet locks, and contention-preserving ordering.",
        (_axis("virtual_channels", 2, 4), _axis("buffer_depth", 4, 16)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "secded_sram_scrubber",
        InterfaceProfile.CYCLE_TRACE,
        "Correct single-bit SRAM errors, report double-bit faults, and perform background scrubbing under memory stalls.",
        (
            _axis("memory_depth", 64, 1024, AxisRole.STIMULUS),
            _axis("scrub_interval", 8, 128, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "two_way_writeback_cache",
        InterfaceProfile.MEMORY_MASTER,
        "Implement two-way write-back allocation with LRU replacement, refill, eviction, flushing, and stalled memory responses.",
        (_axis("set_count", 4, 32), _axis("line_bytes", 16, 64)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "sv32_tlb_walker",
        InterfaceProfile.MEMORY_MASTER,
        "Resolve Sv32 leaf and non-leaf entries, superpages, permissions, ASIDs, accessed and dirty bits, and page faults.",
        (_axis("tlb_entries", 4, 32), _axis("walk_context_count", 1, 4)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "scatter_gather_dma",
        InterfaceProfile.MEMORY_MASTER,
        "Execute descriptor rings with burst splitting, unaligned boundaries, exact completion, faults, and interrupts without out-of-bounds access.",
        (
            _axis("descriptor_count", 4, 64, AxisRole.STIMULUS),
            _axis("maximum_burst", 4, 32, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "dram_timing_scheduler",
        InterfaceProfile.CYCLE_TRACE,
        "Schedule bank commands while satisfying activation, precharge, column, row-active, write, and refresh timing rules.",
        (
            _axis("bank_count", 4, 16, AxisRole.STIMULUS),
            _axis("queue_depth", 8, 64, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "rv32i_precise_core",
        InterfaceProfile.MEMORY_MASTER,
        "Execute RV32I and system-state transitions with memory waits, precise traps, interrupts, hazards, and architectural commit ordering.",
        (
            _axis("dependency_distance", 2, 5, AxisRole.STIMULUS),
            _axis("program_length", 32, 512, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "gshare_branch_predictor",
        InterfaceProfile.CYCLE_TRACE,
        "Predict and update branches with global history, speculative checkpoints, aliasing, and exact misprediction rollback.",
        (_axis("history_bits", 4, 16), _axis("outstanding_branches", 2, 16)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "precise_reorder_buffer",
        InterfaceProfile.CYCLE_TRACE,
        "Allocate, complete, retire, flush, and wrap tags while preserving in-order commit under out-of-order completion and exceptions.",
        (_axis("rob_depth", 8, 64), _axis("retire_width", 1, 4)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "plic_multicontext_controller",
        InterfaceProfile.MMIO,
        "Arbitrate pending interrupts across contexts using enable, priority, threshold, claim, complete, and retrigger semantics.",
        (_axis("source_count", 8, 64), _axis("context_count", 2, 8)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "uart_rx_oversample",
        InterfaceProfile.SCALAR,
        "Decode oversampled serial frames with start qualification, parity, stop, break, FIFO, jitter, and bounded baud mismatch.",
        (_axis("oversample_ratio", 8, 16), _axis("fifo_depth", 2, 16)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "i2c_multimaster_controller",
        InterfaceProfile.SCALAR,
        "Drive open-drain I2C with repeated starts, acknowledgements, stretching, arbitration loss, and concurrent masters.",
        (
            _axis("transfer_bytes", 2, 32),
            _axis("stretch_cycles", 1, 32, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "ethernet_vlan_parser",
        InterfaceProfile.STREAM,
        "Parse Ethernet II, nested VLAN, and IPv4 metadata across arbitrary beat boundaries while rejecting malformed or truncated packets.",
        (
            _axis("beat_width_bits", 8, 64, AxisRole.STIMULUS),
            _axis("maximum_vlan_tags", 1, 2),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "token_bucket_shaper",
        InterfaceProfile.CYCLE_TRACE,
        "Refill fixed-point token buckets across timestamp wrap and enforce burst caps and packet eligibility for multiple queues.",
        (_axis("queue_count", 4, 32), _axis("fraction_bits", 4, 16)),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY),
    ),
    _sail(
        "streaming_regex_nfa",
        InterfaceProfile.STREAM,
        "Execute reloadable Thompson NFA state over chunked streams with overlap, anchors, byte classes, and configuration epochs.",
        (
            _axis("state_count", 16, 128),
            _axis("active_density", 2, 32, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
    _sail(
        "ieee754_binary32_fma",
        InterfaceProfile.STREAM,
        "Compute fused binary32 multiply-add with one rounding, five modes, exceptional operands, subnormals, and status flags.",
        (
            _axis("pipeline_latency", 2, 8, AxisRole.STRUCTURAL),
            _axis("test_vector_count", 12, 16, AxisRole.STIMULUS),
        ),
        (Capability.RTL_SIMULATION, Capability.FORMAL_PROPERTY, Capability.ASIC_SYNTHESIS),
    ),
)


def _flow(
    family: str,
    contract: str,
    capabilities: tuple[Capability, ...],
    axes: tuple[ParameterAxis, ...],
) -> TaskFamilyDefinition:
    return TaskFamilyDefinition(
        family=family,
        root=TaskRoot.EDA_FLOW,
        interface_profile=None,
        semantic_contract=contract,
        difficulty_axes=axes,
        required_capabilities=capabilities,
    )


EDA_FLOW_FAMILIES: tuple[TaskFamilyDefinition, ...] = (
    _flow(
        "rtl_verification_repair",
        "Repair an RTL defect or its independent assertion and testbench evidence without weakening the specification.",
        (Capability.RTL_SIMULATION,),
        (_axis("bug_sites", 1, 4),),
    ),
    _flow(
        "cdc_reset_hardening",
        "Repair clock and reset crossings while preserving observable behavior and proving structural and temporal legality.",
        (Capability.CDC_RDC,),
        (_axis("clock_domains", 2, 6),),
    ),
    _flow(
        "synthesis_qor_tuning",
        "Improve area or delay while retaining formal equivalence and all frozen synthesis constraints.",
        (Capability.ASIC_SYNTHESIS,),
        (_axis("module_count", 4, 24),),
    ),
    _flow(
        "constraint_and_sta_closure",
        "Repair timing constraints and implementation to close setup and hold without false-path abuse.",
        (Capability.STATIC_TIMING,),
        (_axis("clock_count", 1, 6),),
    ),
    _flow(
        "physical_design_closure",
        "Close floorplan, placement, clock tree, routing, timing, and DRC under one immutable implementation contract.",
        (Capability.DIGITAL_IMPLEMENTATION,),
        (_axis("instance_count", 500, 10000),),
    ),
    _flow(
        "power_integrity_optimization",
        "Reduce dynamic, leakage, or IR risk while retaining functional, timing, and activity-coverage hard gates.",
        (Capability.POWER_ANALYSIS, Capability.POWER_INTEGRITY),
        (_axis("power_domains", 1, 4),),
    ),
    _flow(
        "drc_lvs_repair",
        "Repair geometric design-rule and connectivity violations without altering the intended circuit interface.",
        (Capability.PHYSICAL_VERIFICATION,),
        (_axis("violation_count", 1, 32),),
    ),
    _flow(
        "analog_sizing_pvt",
        "Size an analog circuit across frozen PVT hard constraints and optimize its raw multi-objective measurements.",
        (Capability.CIRCUIT_SIMULATION,),
        (_axis("device_count", 4, 24),),
    ),
    _flow(
        "fpga_mapping_closure",
        "Close FPGA constraints, resource limits, and frequency through synthesis, placement, and routing.",
        (Capability.FPGA_IMPLEMENTATION,),
        (_axis("logic_cells", 1000, 50000),),
    ),
    _flow(
        "hls_architecture_tradeoff",
        "Choose an HLS architecture and directives while preserving RTL equivalence and exposing latency-resource tradeoffs.",
        (Capability.HIGH_LEVEL_SYNTHESIS,),
        (_axis("loop_nests", 1, 5),),
    ),
    _flow(
        "dft_scan_insertion",
        "Insert and validate scan architecture with chain integrity and coverage under immutable test constraints.",
        (Capability.DESIGN_FOR_TEST,),
        (_axis("scan_chains", 2, 32),),
    ),
    _flow(
        "cell_characterization_consistency",
        "Generate timing and power arcs across PVT and validate Liberty consistency against circuit simulation.",
        (Capability.CELL_CHARACTERIZATION,),
        (_axis("pvt_corners", 3, 27),),
    ),
)


ALL_FAMILIES = (*SAIL_RTL_FAMILIES, *EDA_FLOW_FAMILIES)
PUBLIC_TASK_CATALOG = PublicTaskCatalog(
    clean_room_exclusion=CLEAN_ROOM_EXCLUSION,
    families=ALL_FAMILIES,
)
PUBLIC_TASK_CATALOG_DIGEST = PUBLIC_TASK_CATALOG.digest


def families_for_root(root: TaskRoot) -> tuple[TaskFamilyDefinition, ...]:
    """Return the public metadata owned by one private authoring capability."""

    return tuple(family for family in ALL_FAMILIES if family.root is root)


def validate_catalog() -> None:
    identifiers = [family.family for family in ALL_FAMILIES]
    if len(SAIL_RTL_FAMILIES) != 20 or len(EDA_FLOW_FAMILIES) != 12:
        raise ValueError("task catalog requires exactly 20 Sail and 12 EDA-flow families")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("task family catalog identifiers must be unique")


validate_catalog()
