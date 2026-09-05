"""Commercial full-flow FPGA implementation qualification fixtures."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from edagym.drivers.fixtures.model import (
    FixtureInput,
    FixtureObservation,
    FixtureOutput,
    MarkerLogProjection,
    QualificationFixture,
    SemanticRejectionReason,
    ToolInvocation,
)
from edagym.drivers.semantic_claims import SemanticJoint, normalize_semantic_joints
from edagym.specs.common import Capability, validate_relative_path


def _input(logical_id: str, path: str, content: str) -> FixtureInput:
    return FixtureInput(logical_id, path, content.encode("ascii"))


def _has_exact_marker(observation: FixtureObservation, marker: bytes) -> bool:
    return marker in {
        line.strip()
        for stream in (*observation.stdout, *observation.stderr)
        for line in stream.splitlines()
    }


def _key_value_report(content: bytes) -> dict[str, str] | None:
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return None
    values: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] in values:
            return None
        values[fields[0]] = fields[1]
    return values or None


def _unsigned_integer(value: str | None) -> int | None:
    if value is None or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        return None
    return int(value)


def _positive_decimal(value: str | None) -> Decimal | None:
    if value is None:
        return None
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None
    return parsed if parsed.is_finite() and parsed > 0 else None


@dataclass(frozen=True, slots=True)
class FpgaImplementationParser:
    """Validate all implementation stages, timing, utilization, and exact seed."""

    metrics_path: str
    native_report_paths: tuple[str, ...]
    completion_marker: bytes
    implementation_seed: int

    def __post_init__(self) -> None:
        validate_relative_path(self.metrics_path)
        for path in self.native_report_paths:
            validate_relative_path(path)
        if (
            not self.native_report_paths
            or len(self.native_report_paths) != len(set(self.native_report_paths))
            or self.implementation_seed < 0
        ):
            raise ValueError("FPGA implementation evidence contract is not bounded")

    def _metrics(self, observation: FixtureObservation) -> tuple[int, int] | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        metrics_output = observation.file(self.metrics_path)
        if metrics_output is None or metrics_output.truncated:
            return None
        if any(
            (output := observation.file(path)) is None or output.size_bytes == 0
            for path in self.native_report_paths
        ):
            return None
        values = _key_value_report(metrics_output.content)
        if values is None or set(values) != {
            "fmax_mhz",
            "logic_cells",
            "placement_complete",
            "pre_bitstream_check_complete",
            "registers",
            "routing_complete",
            "seed",
            "synthesis_complete",
        }:
            return None
        flags = tuple(
            _unsigned_integer(values.get(name))
            for name in (
                "synthesis_complete",
                "placement_complete",
                "routing_complete",
                "pre_bitstream_check_complete",
            )
        )
        logic_cells = _unsigned_integer(values.get("logic_cells"))
        registers = _unsigned_integer(values.get("registers"))
        seed = _unsigned_integer(values.get("seed"))
        fmax = _positive_decimal(values.get("fmax_mhz"))
        if (
            flags != (1, 1, 1, 1)
            or logic_cells is None
            or logic_cells < 1
            or registers is None
            or seed != self.implementation_seed
            or fmax is None
        ):
            return None
        return logic_cells, registers

    def accepts(self, observation: FixtureObservation) -> bool:
        metrics = self._metrics(observation)
        return metrics is not None and metrics[1] >= 1

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        metrics = self._metrics(observation)
        if metrics is not None and metrics[1] == 0:
            return SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "native_fpga_full_implementation",
            "metrics_path": self.metrics_path,
            "native_report_paths": self.native_report_paths,
            "completion_marker": self.completion_marker.decode("ascii"),
            "stage_metrics": (
                "synthesis_complete",
                "placement_complete",
                "routing_complete",
                "pre_bitstream_check_complete",
            ),
            "measurements": (
                ("fmax_mhz", "megahertz", "positive"),
                ("logic_cells", "count", "positive"),
                ("registers", "count", "nonnegative"),
                ("seed", "dimensionless", self.implementation_seed),
            ),
            "rejection_reason": SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
        }


_FPGA_SEQUENTIAL_SOURCE = """\
module dut(input clk, input rst, input [3:0] a, input [3:0] b, output reg [4:0] y);
  always @(posedge clk) begin
    if (rst) y <= 5'b0;
    else y <= a + b;
  end
endmodule
"""

_FPGA_COMBINATIONAL_SOURCE = """\
module dut(input clk, input rst, input [3:0] a, input [3:0] b, output [4:0] y);
  assign y = a + b;
endmodule
"""

_FPGA_CONSTRAINTS = """\
create_clock -name clock -period 10.000 [get_ports clk]
set_input_delay 1.000 -clock [get_clocks clock] [get_ports {a[*] b[*]}]
set_output_delay 1.000 -clock [get_clocks clock] [get_ports {y[*]}]
"""

_IMPLEMENTATION_SEED = 17

_VIVADO_COMPLETION_MARKER = b"EDAGYM_VIVADO_FPGA_IMPLEMENTATION_COMPLETE"

_VIVADO_SCRIPT = f"""\
set implementation_seed {_IMPLEMENTATION_SEED}
set_param place.seed $implementation_seed
read_verilog dut.v
read_xdc constraints.xdc
synth_design -top dut -part xc7a35tcpg236-1
write_checkpoint -force synthesized.dcp
opt_design
place_design
phys_opt_design
route_design
write_checkpoint -force routed.dcp
report_utilization -file utilization.rpt
report_timing_summary -file timing.rpt
report_route_status -file route_status.rpt
report_drc -file drc.rpt
set logic_cells [llength [get_cells -hierarchical -filter {{PRIMITIVE_GROUP == LUT}}]]
set registers [llength [get_cells -hierarchical -filter {{PRIMITIVE_GROUP == FLOP_LATCH}}]]
set placed_cells [llength [get_cells -hierarchical -filter {{LOC != ""}}]]
set routed_nets [llength [get_nets -hierarchical -filter {{ROUTE_STATUS == ROUTED}}]]
set timing_paths [get_timing_paths -delay_type max -max_paths 1]
if {{[llength $timing_paths] != 1}} {{ error "timing path is missing" }}
set timing_path [lindex $timing_paths 0]
set slack [get_property SLACK $timing_path]
set period [get_property PERIOD [get_clocks clock]]
set data_delay [expr {{$period - $slack}}]
if {{$data_delay <= 0}} {{ error "timing delay is invalid" }}
set fmax_mhz [expr {{1000.0 / $data_delay}}]
set drc_violations [llength [get_drc_violations -quiet]]
set metrics_channel [open "vivado_metrics.txt" w]
puts $metrics_channel "synthesis_complete [expr {{[file size synthesized.dcp] > 0}}]"
puts $metrics_channel "placement_complete [expr {{$placed_cells > 0}}]"
puts $metrics_channel "routing_complete [expr {{$routed_nets > 0}}]"
puts $metrics_channel "pre_bitstream_check_complete [expr {{$drc_violations == 0}}]"
puts $metrics_channel "fmax_mhz $fmax_mhz"
puts $metrics_channel "logic_cells $logic_cells"
puts $metrics_channel "registers $registers"
puts $metrics_channel "seed $implementation_seed"
close $metrics_channel
puts [join {{EDAGYM VIVADO FPGA IMPLEMENTATION COMPLETE}} _]
exit
"""

VIVADO_IMPLEMENTATION = QualificationFixture(
    tool_id="vivado",
    capability=Capability.FPGA_IMPLEMENTATION,
    semantic_joints=normalize_semantic_joints(
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
    ),
    inputs=(
        _input("dut_source", "dut.v", _FPGA_SEQUENTIAL_SOURCE),
        _input("timing_constraints", "constraints.xdc", _FPGA_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _VIVADO_SCRIPT),
    ),
    rejection_inputs=(
        _input("dut_source", "dut.v", _FPGA_COMBINATIONAL_SOURCE),
        _input("timing_constraints", "constraints.xdc", _FPGA_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _VIVADO_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(
        ToolInvocation(
            ("-mode", "batch", "-nolog", "-nojournal", "-notrace", "-source", "implement.tcl")
        ),
    ),
    outputs=(
        FixtureOutput("synthesized_checkpoint", "synthesized.dcp"),
        FixtureOutput("routed_checkpoint", "routed.dcp"),
        FixtureOutput("utilization_report", "utilization.rpt", media_type="text/plain"),
        FixtureOutput("timing_report", "timing.rpt", media_type="text/plain"),
        FixtureOutput("route_status_report", "route_status.rpt", media_type="text/plain"),
        FixtureOutput("drc_report", "drc.rpt", media_type="text/plain"),
        FixtureOutput("implementation_metrics", "vivado_metrics.txt", media_type="text/plain"),
    ),
    parser=FpgaImplementationParser(
        metrics_path="vivado_metrics.txt",
        native_report_paths=(
            "synthesized.dcp",
            "routed.dcp",
            "utilization.rpt",
            "timing.rpt",
            "route_status.rpt",
            "drc.rpt",
        ),
        completion_marker=_VIVADO_COMPLETION_MARKER,
        implementation_seed=_IMPLEMENTATION_SEED,
    ),
    log_projection=MarkerLogProjection((_VIVADO_COMPLETION_MARKER,)),
)


_QUARTUS_COMPLETION_MARKER = b"EDAGYM_QUARTUS_FPGA_IMPLEMENTATION_COMPLETE"

_QUARTUS_SCRIPT = f"""\
load_package flow
set implementation_seed {_IMPLEMENTATION_SEED}
project_new edagym -overwrite
set_global_assignment -name FAMILY "Cyclone 10 GX"
set_global_assignment -name DEVICE 10CX220YF672E5G
set_global_assignment -name TOP_LEVEL_ENTITY dut
set_global_assignment -name VERILOG_FILE dut.v
set_global_assignment -name SDC_FILE constraints.sdc
set_global_assignment -name SEED $implementation_seed
execute_module -tool map
execute_module -tool fit
execute_module -tool sta
set fit_channel [open "edagym.fit.summary" r]
set fit_summary [read $fit_channel]
close $fit_channel
if {{![regexp {{Total registers[ \t]*:[ \t]*([0-9,]+)}} $fit_summary -> registers_text]}} {{
  error "register utilization is missing"
}}
set logic_pattern {{(?:Logic utilization[^:]*|Total logic elements)[ \t]*:[ \t]*([0-9,]+)}}
if {{![regexp $logic_pattern $fit_summary -> logic_text]}} {{
  error "logic utilization is missing"
}}
set registers [string map {{, ""}} $registers_text]
set logic_cells [string map {{, ""}} $logic_text]
set timing_channel [open "edagym.sta.rpt" r]
set timing_report [read $timing_channel]
close $timing_channel
if {{![regexp {{([0-9]+(?:\\.[0-9]+)?) MHz}} $timing_report -> fmax_mhz]}} {{
  error "maximum frequency is missing"
}}
set metrics_channel [open "quartus_metrics.txt" w]
puts $metrics_channel "synthesis_complete [expr {{[file size edagym.map.summary] > 0}}]"
puts $metrics_channel "placement_complete [expr {{[file size edagym.fit.summary] > 0}}]"
puts $metrics_channel "routing_complete [expr {{[file size edagym.fit.rpt] > 0}}]"
puts $metrics_channel "pre_bitstream_check_complete [expr {{[file size edagym.sta.rpt] > 0}}]"
puts $metrics_channel "fmax_mhz $fmax_mhz"
puts $metrics_channel "logic_cells $logic_cells"
puts $metrics_channel "registers $registers"
puts $metrics_channel "seed $implementation_seed"
close $metrics_channel
puts [join {{EDAGYM QUARTUS FPGA IMPLEMENTATION COMPLETE}} _]
project_close
"""

QUARTUS_IMPLEMENTATION = QualificationFixture(
    tool_id="quartus",
    capability=Capability.FPGA_IMPLEMENTATION,
    semantic_joints=VIVADO_IMPLEMENTATION.semantic_joints,
    inputs=(
        _input("dut_source", "dut.v", _FPGA_SEQUENTIAL_SOURCE),
        _input("timing_constraints", "constraints.sdc", _FPGA_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _QUARTUS_SCRIPT),
    ),
    rejection_inputs=(
        _input("dut_source", "dut.v", _FPGA_COMBINATIONAL_SOURCE),
        _input("timing_constraints", "constraints.sdc", _FPGA_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _QUARTUS_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("-t", "implement.tcl")),),
    outputs=(
        FixtureOutput("synthesis_report", "edagym.map.summary", media_type="text/plain"),
        FixtureOutput("fitter_summary", "edagym.fit.summary", media_type="text/plain"),
        FixtureOutput("routing_report", "edagym.fit.rpt", media_type="text/plain"),
        FixtureOutput("timing_report", "edagym.sta.rpt", media_type="text/plain"),
        FixtureOutput("flow_report", "edagym.flow.rpt", media_type="text/plain"),
        FixtureOutput("implementation_metrics", "quartus_metrics.txt", media_type="text/plain"),
    ),
    parser=FpgaImplementationParser(
        metrics_path="quartus_metrics.txt",
        native_report_paths=(
            "edagym.map.summary",
            "edagym.fit.summary",
            "edagym.fit.rpt",
            "edagym.sta.rpt",
            "edagym.flow.rpt",
        ),
        completion_marker=_QUARTUS_COMPLETION_MARKER,
        implementation_seed=_IMPLEMENTATION_SEED,
    ),
    log_projection=MarkerLogProjection((_QUARTUS_COMPLETION_MARKER,)),
)


COMMERCIAL_FPGA_FIXTURES: tuple[QualificationFixture, ...] = (
    VIVADO_IMPLEMENTATION,
    QUARTUS_IMPLEMENTATION,
)
