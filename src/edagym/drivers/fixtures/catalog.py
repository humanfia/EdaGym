"""Small semantic workloads for backend qualification."""

from __future__ import annotations

from dataclasses import replace

from edagym.drivers.fixtures.analog_physical import (
    HSPICE_CIRCUIT_SIMULATION,
    ICV_PHYSICAL_VERIFICATION,
    PEGASUS_PHYSICAL_VERIFICATION,
)
from edagym.drivers.fixtures.backend_breadth import (
    BACKEND_BREADTH_FIXTURES,
    MODUS_DESIGN_FOR_TEST,
)
from edagym.drivers.fixtures.digital_signoff import DIGITAL_SIGNOFF_FIXTURES
from edagym.drivers.fixtures.hls_dft import VITIS_HLS_SYNTHESIS
from edagym.drivers.fixtures.model import (
    AbcEquivalenceParser,
    AbcSynthesisParser,
    FirtoolLoweringParser,
    FixtureAssetInput,
    FixtureInput,
    FixtureOutput,
    JasperCdcStatusParser,
    JasperPropertyStatusParser,
    KlayoutDrcParser,
    MarkerLogProjection,
    MarkerParser,
    QualificationFixture,
    SemanticRejectionReason,
    SemanticTokenParser,
    SpyglassStatusParser,
    ToolInvocation,
    VerilatorLintParser,
    YosysEquivalenceParser,
    YosysNetlistParser,
)
from edagym.drivers.fixtures.open_fpga import NEXTPNR_ICE40_IMPLEMENTATION
from edagym.drivers.fixtures.open_simulation import (
    IVERILOG_SIMULATION,
    VERILATOR_SIMULATION,
)
from edagym.drivers.semantic_claims import SemanticJoint, normalize_semantic_joints
from edagym.fixtures.synthesis_toy import (
    SYNTHESIS_LIBRARY_ASSET_ID,
    SYNTHESIS_LIBRARY_PATH,
)
from edagym.specs.common import Capability


def _input(logical_id: str, path: str, content: str) -> FixtureInput:
    return FixtureInput(logical_id=logical_id, path=path, content=content.encode("utf-8"))


_ADDER = """\
module dut(input logic [3:0] a, input logic [3:0] b, output logic [4:0] y);
  assign y = a + b;
endmodule
"""

_JASPER_PROPERTY_MARKER = b"EDAGYM_JASPER_PROPERTY_STATUS formal_probe.ap_check proven"
_JASPER_PROPERTY_REJECTION_MARKER = b"EDAGYM_JASPER_PROPERTY_STATUS formal_probe.ap_check cex"

JASPER_FORMAL_PROPERTY = QualificationFixture(
    tool_id="jaspergold",
    capability=Capability.FORMAL_PROPERTY,
    semantic_joints=normalize_semantic_joints(
        Capability.FORMAL_PROPERTY,
        (
            SemanticJoint.FORMAL_PROPERTY_PROVED,
            SemanticJoint.FORMAL_PROPERTY_COUNTEREXAMPLE,
        ),
    ),
    inputs=(
        _input(
            "formal_source",
            "formal.sv",
            """\
module formal_probe(
  input logic clock,
  input logic reset_n,
  input logic enable
);
  logic [1:0] count;
  always_ff @(posedge clock or negedge reset_n) begin
    if (!reset_n) count <= '0;
    else if (enable) count <= count + 2'd1;
  end
  ap_check: assert property (
    @(posedge clock) disable iff (!reset_n)
    !enable |=> $stable(count)
  );
endmodule
""",
        ),
        _input(
            "proof_script",
            "prove.tcl",
            """\
clear -all
analyze -sv12 formal.sv
elaborate -top formal_probe
clock clock
reset -expression !reset_n
set properties [get_property_list -include {type assert}]
if {[llength $properties] != 1} { error "expected one assertion" }
set property [lindex $properties 0]
prove -property $property
set result [get_property_info $property -list status]
puts "EDAGYM_JASPER_PROPERTY_STATUS formal_probe.ap_check $result"
exit
""",
        ),
    ),
    invocations=(ToolInvocation(("-allow_unsupported_OS", "-batch", "-tcl", "prove.tcl")),),
    outputs=(),
    parser=JasperPropertyStatusParser(
        property_name="formal_probe.ap_check",
        expected_status=b"proven",
    ),
    log_projection=MarkerLogProjection(
        (_JASPER_PROPERTY_MARKER, _JASPER_PROPERTY_REJECTION_MARKER)
    ),
)

_JASPER_CDC_MARKER = b"EDAGYM_CDC_PASS"

JASPER_CDC = QualificationFixture(
    tool_id="jaspergold",
    capability=Capability.CDC_RDC,
    semantic_joints=normalize_semantic_joints(
        Capability.CDC_RDC,
        (
            SemanticJoint.CDC_RDC_CDC,
            SemanticJoint.CDC_RDC_CLEAN,
            SemanticJoint.CDC_RDC_VIOLATION,
        ),
    ),
    inputs=(
        _input(
            "cdc_source",
            "cdc.sv",
            """\
module toggle_synchronizer(
  input logic source_clock,
  input logic destination_clock,
  input logic reset_n,
  input logic source_toggle,
  output logic synchronized_pulse
);
  logic source_value;
  (* ASYNC_REG = "TRUE" *) logic sync_meta;
  (* ASYNC_REG = "TRUE" *) logic sync_value;
  logic sync_delay;
  always_ff @(posedge source_clock or negedge reset_n) begin
    if (!reset_n) source_value <= 1'b0;
    else if (source_toggle) source_value <= ~source_value;
  end
  always_ff @(posedge destination_clock or negedge reset_n) begin
    if (!reset_n) begin
      sync_meta <= 1'b0;
      sync_value <= 1'b0;
      sync_delay <= 1'b0;
    end else begin
      sync_meta <= source_value;
      sync_value <= sync_meta;
      sync_delay <= sync_value;
    end
  end
  assign synchronized_pulse = sync_value ^ sync_delay;
endmodule
""",
        ),
        _input(
            "cdc_script",
            "cdc.tcl",
            """\
clear -all
check_cdc -init
analyze -sv cdc.sv
elaborate -top toggle_synchronizer
config_rtlds -rule -parameter {all_clocks_sync_by_default = false}
clock source_clock
clock destination_clock
config_rtlds -reset -async reset_n -polarity low
config_rtlds -port source_toggle -clock source_clock
config_rtlds -port synchronized_pulse -clock destination_clock
check_cdc -extract
set cdc_filter [check_cdc -filter -add -tag CDC_NO_SYNC]
set violations [check_cdc -list violations -filter $cdc_filter]
set violation_count [llength [dict keys $violations]]
puts "EDAGYM_CDC_VIOLATION_COUNT $violation_count"
puts EDAGYM_CDC_PASS
exit
""",
        ),
    ),
    invocations=(
        ToolInvocation(
            (
                "-allow_unsupported_OS",
                "-cdc",
                "-batch",
                "-no_wait",
                "-proj",
                "cdc-project",
                "-tcl",
                "cdc.tcl",
            )
        ),
    ),
    outputs=(),
    parser=JasperCdcStatusParser(expected_violation_count=0, pass_marker=_JASPER_CDC_MARKER),
    log_projection=MarkerLogProjection(
        (
            b"EDAGYM_CDC_VIOLATION_COUNT 0",
            b"EDAGYM_CDC_VIOLATION_COUNT 1",
            _JASPER_CDC_MARKER,
        )
    ),
)

_SPYGLASS_PASS_MARKER = b"SpyGlass Exit Code 0 (Rule-checking completed without errors or warnings)"
_SPYGLASS_REJECTION_MARKER = b"SpyGlass Exit Code 0 (Rule-checking completed with errors)"

SPYGLASS_LINT = QualificationFixture(
    tool_id="spyglass",
    capability=Capability.RTL_LINT,
    semantic_joints=normalize_semantic_joints(
        Capability.RTL_LINT,
        (
            SemanticJoint.RTL_LINT_CLEAN,
            SemanticJoint.RTL_LINT_RULE_VIOLATION,
        ),
    ),
    inputs=(
        _input(
            "lint_source",
            "lint.sv",
            """\
module lint_probe(
  input logic clock,
  input logic reset,
  input logic enable,
  output logic [3:0] count
);
  always_ff @(posedge clock) begin
    if (reset) count <= '0;
    else if (enable) count <= count + 4'd1;
  end
endmodule
""",
        ),
        _input(
            "lint_project",
            "lint.prj",
            """\
read_file -type hdl lint.sv
set_option top lint_probe
set_option enableSV yes
""",
        ),
    ),
    invocations=(ToolInvocation(("-batch", "-project", "lint.prj", "-goals", "lint/lint_rtl")),),
    outputs=(),
    parser=SpyglassStatusParser(status_marker=_SPYGLASS_PASS_MARKER),
    log_projection=MarkerLogProjection((_SPYGLASS_PASS_MARKER, _SPYGLASS_REJECTION_MARKER)),
)

SPYGLASS_CDC = QualificationFixture(
    tool_id="spyglass",
    capability=Capability.CDC_RDC,
    semantic_joints=normalize_semantic_joints(
        Capability.CDC_RDC,
        (
            SemanticJoint.CDC_RDC_CDC,
            SemanticJoint.CDC_RDC_CLEAN,
            SemanticJoint.CDC_RDC_VIOLATION,
        ),
    ),
    inputs=(
        _input(
            "cdc_source",
            "cdc.sv",
            """\
module cdc_probe(
  input logic source_clock,
  input logic destination_clock,
  input logic source_input,
  output logic destination_output
);
  logic source_value;
  logic synchronize_first;
  logic synchronize_second;
  always_ff @(posedge source_clock)
    source_value <= source_input;
  always_ff @(posedge destination_clock) begin
    synchronize_first <= source_value;
    synchronize_second <= synchronize_first;
  end
  assign destination_output = synchronize_second;
endmodule
""",
        ),
        _input(
            "cdc_constraints",
            "cdc.sgdc",
            """\
current_design cdc_probe
clock -name source_clock -domain source_domain -period 10
clock -name destination_clock -domain destination_domain -period 7
""",
        ),
        _input(
            "cdc_project",
            "cdc.prj",
            """\
read_file -type hdl cdc.sv
read_file -type sgdc cdc.sgdc
set_option top cdc_probe
set_option enableSV yes
""",
        ),
    ),
    invocations=(
        ToolInvocation(("-batch", "-project", "cdc.prj", "-goals", "cdc/cdc_verify_struct")),
    ),
    outputs=(),
    parser=SpyglassStatusParser(status_marker=_SPYGLASS_PASS_MARKER),
    log_projection=MarkerLogProjection((_SPYGLASS_PASS_MARKER, _SPYGLASS_REJECTION_MARKER)),
)

VERILATOR_LINT = QualificationFixture(
    tool_id="verilator",
    capability=Capability.RTL_LINT,
    semantic_joints=normalize_semantic_joints(
        Capability.RTL_LINT,
        (
            SemanticJoint.RTL_LINT_CLEAN,
            SemanticJoint.RTL_LINT_RULE_VIOLATION,
            SemanticJoint.RTL_LINT_NATIVE_DIAGNOSTICS,
        ),
    ),
    inputs=(
        _input(
            "lint_source",
            "lint_counter.sv",
            """\
module lint_counter(
  input logic clock,
  input logic reset,
  input logic enable,
  output logic [7:0] count
);
  always_ff @(posedge clock) begin
    if (reset) count <= '0;
    else if (enable) count <= count + 8'd1;
  end
endmodule
""",
        ),
    ),
    invocations=(
        ToolInvocation(
            (
                "--lint-only",
                "--Wall",
                "-Wno-fatal",
                "--top-module",
                "lint_counter",
                "lint_counter.sv",
            )
        ),
        ToolInvocation(
            (
                "--json-only",
                "--json-only-output",
                "lint.tree.json",
                "--json-only-meta-output",
                "lint.meta.json",
                "--Wall",
                "-Wno-fatal",
                "--top-module",
                "lint_counter",
                "lint_counter.sv",
            )
        ),
    ),
    outputs=(
        FixtureOutput("lint_metadata", "lint.meta.json", media_type="application/json"),
        FixtureOutput("lint_structure", "lint.tree.json", media_type="application/json"),
    ),
    parser=VerilatorLintParser(output_path="lint.tree.json", module_name="lint_counter"),
)

YOSYS_SYNTHESIS = QualificationFixture(
    tool_id="yosys",
    capability=Capability.ASIC_SYNTHESIS,
    semantic_joints=normalize_semantic_joints(
        Capability.ASIC_SYNTHESIS,
        (
            SemanticJoint.ASIC_SYNTHESIS_RTL,
            SemanticJoint.ASIC_SYNTHESIS_NETLIST,
            SemanticJoint.ASIC_SYNTHESIS_CELLS,
        ),
    ),
    inputs=(
        _input("dut_source", "dut.sv", _ADDER),
        _input(
            "synthesis_script",
            "synth.ys",
            """\
read_verilog -sv dut.sv
hierarchy -check -top dut
proc
opt
techmap
opt
check
stat
write_json synth.json
log EDAGYM_ASIC_SYNTHESIS_PASS
""",
        ),
    ),
    invocations=(ToolInvocation(("-s", "synth.ys")),),
    outputs=(FixtureOutput("synthesized_netlist", "synth.json", media_type="application/json"),),
    parser=YosysNetlistParser(b"EDAGYM_ASIC_SYNTHESIS_PASS", "synth.json", "dut"),
)

YOSYS_EQUIVALENCE = QualificationFixture(
    tool_id="yosys",
    capability=Capability.EQUIVALENCE,
    semantic_joints=normalize_semantic_joints(
        Capability.EQUIVALENCE,
        (
            SemanticJoint.EQUIVALENCE_EQUIVALENT,
            SemanticJoint.EQUIVALENCE_MISMATCH,
        ),
    ),
    inputs=(
        _input(
            "equivalence_source",
            "equivalence.sv",
            """\
module gold(input [3:0] a, input [3:0] b, output [4:0] y);
  assign y = a + b;
endmodule
module gate(input [3:0] a, input [3:0] b, output [4:0] y);
  wire [4:0] extended_a = {1'b0, a};
  wire [4:0] extended_b = {1'b0, b};
  assign y = extended_a + extended_b;
endmodule
""",
        ),
        _input(
            "equivalence_script",
            "equivalence.ys",
            """\
read_verilog -sv equivalence.sv
proc
equiv_make gold gate equiv
hierarchy -top equiv
equiv_simple
equiv_status
log EDAGYM_EQUIVALENCE_COMPLETE
""",
        ),
    ),
    invocations=(ToolInvocation(("-s", "equivalence.ys")),),
    outputs=(),
    parser=YosysEquivalenceParser(b"EDAGYM_EQUIVALENCE_COMPLETE"),
)

YOSYS_FORMAL = QualificationFixture(
    tool_id="yosys",
    capability=Capability.FORMAL_PROPERTY,
    semantic_joints=normalize_semantic_joints(
        Capability.FORMAL_PROPERTY,
        (
            SemanticJoint.FORMAL_PROPERTY_PROVED,
            SemanticJoint.FORMAL_PROPERTY_COUNTEREXAMPLE,
        ),
    ),
    inputs=(
        _input(
            "formal_source",
            "formal.sv",
            """\
module formal_add(input [3:0] a, input [3:0] b);
  wire [4:0] sum = a + b;
  always @* begin
    assert(sum >= a);
    assert(sum >= b);
  end
endmodule
""",
        ),
        _input(
            "formal_script",
            "formal.ys",
            """\
read_verilog -formal -sv formal.sv
prep -top formal_add
chformal -lower
sat -prove-asserts
log EDAGYM_FORMAL_PROPERTY_COMPLETE
""",
        ),
    ),
    invocations=(ToolInvocation(("-s", "formal.ys")),),
    outputs=(),
    parser=SemanticTokenParser(
        completion_marker=b"EDAGYM_FORMAL_PROPERTY_COMPLETE",
        acceptance_token=b"SAT proof finished - no model found: SUCCESS!",
        rejection_token=b"SAT proof finished - model found: FAIL!",
        rejection_reason=SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE,
    ),
)

ABC_SYNTHESIS = QualificationFixture(
    tool_id="abc",
    capability=Capability.ASIC_SYNTHESIS,
    semantic_joints=normalize_semantic_joints(
        Capability.ASIC_SYNTHESIS,
        (
            SemanticJoint.ASIC_SYNTHESIS_NETLIST,
            SemanticJoint.ASIC_SYNTHESIS_CELLS,
        ),
    ),
    inputs=(
        _input(
            "logic_network",
            "network.blif",
            """\
.model dut
.inputs a b c d
.outputs y
.names a b ab
11 1
.names c d cd
11 1
.names ab cd y
1- 1
-1 1
.end
""",
        ),
    ),
    invocations=(
        ToolInvocation(
            (
                "-c",
                "read_blif network.blif; strash; balance; rewrite; refactor; "
                "write_blif synthesized.blif; print_stats; "
                "echo EDAGYM_ABC_ASIC_SYNTHESIS_PASS",
            )
        ),
    ),
    outputs=(
        FixtureOutput(
            "synthesized_network",
            "synthesized.blif",
            media_type="application/x-blif",
        ),
    ),
    parser=AbcSynthesisParser(
        marker=b"EDAGYM_ABC_ASIC_SYNTHESIS_PASS",
        output_path="synthesized.blif",
        model_name="dut",
    ),
)

ABC_EQUIVALENCE = QualificationFixture(
    tool_id="abc",
    capability=Capability.EQUIVALENCE,
    semantic_joints=normalize_semantic_joints(
        Capability.EQUIVALENCE,
        (
            SemanticJoint.EQUIVALENCE_EQUIVALENT,
            SemanticJoint.EQUIVALENCE_MISMATCH,
        ),
    ),
    inputs=(
        _input(
            "golden_network",
            "gold.blif",
            """\
.model gold
.inputs a b c
.outputs y
.names a b c y
11- 1
1-1 1
-11 1
.end
""",
        ),
        _input(
            "revised_network",
            "revised.blif",
            """\
.model revised
.inputs a b c
.outputs y
.names a b ab
11 1
.names a c ac
11 1
.names b c bc
11 1
.names ab ac bc y
1-- 1
-1- 1
--1 1
.end
""",
        ),
    ),
    invocations=(
        ToolInvocation(
            (
                "-c",
                "cec gold.blif revised.blif; echo EDAGYM_ABC_FORMAL_EQUIVALENCE_PASS",
            )
        ),
    ),
    outputs=(),
    parser=AbcEquivalenceParser(
        marker=b"EDAGYM_ABC_FORMAL_EQUIVALENCE_PASS",
        equivalence_token=b"Networks are equivalent.",
    ),
)

FIRTOOL_LOWERING = QualificationFixture(
    tool_id="firtool",
    capability=Capability.HW_IR_LOWERING,
    semantic_joints=normalize_semantic_joints(
        Capability.HW_IR_LOWERING,
        (
            SemanticJoint.HW_IR_OUTPUT,
            SemanticJoint.HW_IR_SEQUENTIAL_STRUCTURE,
        ),
    ),
    inputs=(
        _input(
            "firrtl_source",
            "design.fir",
            """\
FIRRTL version 4.0.0
circuit Counter :
  public module Counter :
    input clock : Clock
    input reset : UInt<1>
    output count : UInt<4>
    regreset state : UInt<4>, clock, reset, UInt<4>(0)
    connect state, add(state, UInt<1>(1))
    connect count, state
""",
        ),
    ),
    invocations=(ToolInvocation(("design.fir", "-o", "lowered.sv")),),
    outputs=(FixtureOutput("lowered_rtl", "lowered.sv", media_type="text/x-systemverilog"),),
    parser=FirtoolLoweringParser(
        output_path="lowered.sv",
        module_declaration=b"module Counter(",
        sequential_token=b"always @(posedge clock)",
    ),
)

_SPECTRE_CIRCUIT_MARKER = b"EDAGYM_SPECTRE_DIVIDER_PASS"
_SPECTRE_REJECTION_MARKER = b"EDAGYM_SPECTRE_DIVIDER_REJECT"
_SPECTRE_ZERO_ERROR_MARKER = b"spectre completes with 0 errors"

SPECTRE_CIRCUIT_SIMULATION = QualificationFixture(
    tool_id="spectre",
    capability=Capability.CIRCUIT_SIMULATION,
    semantic_joints=normalize_semantic_joints(
        Capability.CIRCUIT_SIMULATION,
        (SemanticJoint.CIRCUIT_SIMULATION_TRANSIENT,),
    ),
    inputs=(
        _input(
            "circuit_checker",
            "divider_checker.va",
            """\
`include "disciplines.vams"

module divider_checker(out);
  input out;
  electrical out;

  parameter real expected = 0.5;
  parameter real tolerance = 1e-6 from [0:inf);

  analog begin
    @(final_step("tran")) begin
      if (abs(V(out) - expected) <= tolerance)
        $strobe("EDAGYM_SPECTRE_DIVIDER_PASS");
      else
        $strobe("EDAGYM_SPECTRE_DIVIDER_REJECT");
    end
  end
endmodule
""",
        ),
        _input(
            "circuit_netlist",
            "divider.scs",
            """\
simulator lang=spectre
global 0

ahdl_include "divider_checker.va"

Vsource (vin 0) vsource type=dc dc=1
Rtop (vin out) resistor r=1k
Rbottom (out 0) resistor r=1k
Check (out) divider_checker expected=0.5 tolerance=1e-6

transient tran stop=1n maxstep=100p
save out
""",
        ),
    ),
    invocations=(
        ToolInvocation(
            (
                "-64",
                "divider.scs",
                "+log",
                "divider.log",
                "-raw",
                "divider_psf",
            )
        ),
    ),
    outputs=(),
    parser=SemanticTokenParser(
        completion_marker=_SPECTRE_ZERO_ERROR_MARKER,
        acceptance_token=_SPECTRE_CIRCUIT_MARKER,
        rejection_token=_SPECTRE_REJECTION_MARKER,
        rejection_reason=SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE,
    ),
    log_projection=MarkerLogProjection(
        (
            _SPECTRE_CIRCUIT_MARKER,
            _SPECTRE_REJECTION_MARKER,
            _SPECTRE_ZERO_ERROR_MARKER,
        )
    ),
)

OPENROAD_STATIC_TIMING = QualificationFixture(
    tool_id="openroad",
    capability=Capability.STATIC_TIMING,
    semantic_joints=normalize_semantic_joints(
        Capability.STATIC_TIMING,
        (SemanticJoint.STATIC_TIMING_SETUP,),
    ),
    inputs=(
        _input(
            "timing_netlist",
            "top.v",
            """\
module top(input clk, input d, output q);
  wire launched;
  wire buffered;
  DFF launch(.CLK(clk), .D(d), .Q(launched));
  BUF data_path(.A(launched), .Y(buffered));
  DFF capture(.CLK(clk), .D(buffered), .Q(q));
endmodule
""",
        ),
        _input(
            "timing_constraints",
            "constraints.sdc",
            """\
create_clock -name clk -period 2.0 [get_ports clk]
set_input_delay 0.1 -clock clk [get_ports d]
set_output_delay 0.1 -clock clk [get_ports q]
""",
        ),
        _input(
            "timing_script",
            "sta.tcl",
            """\
read_lef technology/cells.lef
read_liberty technology/cells.lib
read_verilog top.v
link_design top
read_sdc constraints.sdc
report_checks -path_delay max > sta.rpt
puts EDAGYM_STATIC_TIMING_PASS
exit
""",
        ),
    ),
    restricted_assets=(
        FixtureAssetInput(
            "timing_library",
            SYNTHESIS_LIBRARY_PATH,
            SYNTHESIS_LIBRARY_ASSET_ID,
            "text/x-liberty",
        ),
        FixtureAssetInput(
            "physical_library",
            "technology/cells.lef",
            "openroad_static_timing_abstract",
            "text/x-lef",
        ),
    ),
    invocations=(ToolInvocation(("-no_init", "-exit", "sta.tcl")),),
    outputs=(FixtureOutput("timing_report", "sta.rpt", media_type="text/plain"),),
    parser=MarkerParser(
        b"EDAGYM_STATIC_TIMING_PASS",
        output_path="sta.rpt",
        output_token=b"Startpoint",
        missing_output_token_rejection_reason=(SemanticRejectionReason.TIMING_PATH_MISSING),
    ),
)

_NGSPICE_CIRCUIT_MARKER = b"EDAGYM_NGSPICE_DIVIDER_PASS"
_NGSPICE_REJECTION_MARKER = b"EDAGYM_NGSPICE_DIVIDER_REJECT"

NGSPICE_CIRCUIT_SIMULATION = QualificationFixture(
    tool_id="ngspice",
    capability=Capability.CIRCUIT_SIMULATION,
    semantic_joints=normalize_semantic_joints(
        Capability.CIRCUIT_SIMULATION,
        (SemanticJoint.CIRCUIT_SIMULATION_DC,),
    ),
    inputs=(
        _input(
            "circuit_netlist",
            "divider.cir",
            """\
* EdaGym ngspice qualification workload
Vsource vin 0 1
Rtop vin out 1k
Rbottom out 0 1k
.control
set noaskquit
op
let delta = abs(v(out) - 0.5)
if delta < 1e-6
  echo EDAGYM_NGSPICE_DIVIDER_PASS
else
  echo EDAGYM_NGSPICE_DIVIDER_REJECT
end
quit
.endc
.end
""",
        ),
    ),
    invocations=(ToolInvocation(("-b", "divider.cir")),),
    outputs=(),
    parser=MarkerParser(
        _NGSPICE_CIRCUIT_MARKER,
        rejection_marker=_NGSPICE_REJECTION_MARKER,
        rejection_reason=SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE,
    ),
)

KLAYOUT_PHYSICAL_VERIFICATION = QualificationFixture(
    tool_id="klayout",
    capability=Capability.PHYSICAL_VERIFICATION,
    semantic_joints=normalize_semantic_joints(
        Capability.PHYSICAL_VERIFICATION,
        (SemanticJoint.PHYSICAL_VERIFICATION_DRC,),
    ),
    inputs=(
        _input(
            "layout_geometry",
            "layout.json",
            """\
{"minimum_spacing_nm":200,"rectangles_nm":[[0,0,1000,1000],[1300,0,2300,1000]]}
""",
        ),
    ),
    invocations=(ToolInvocation(("check", "layout.json", "drc-report.json")),),
    outputs=(FixtureOutput("drc_report", "drc-report.json", media_type="application/json"),),
    parser=KlayoutDrcParser(
        output_path="drc-report.json",
        rule_id="minimum_spacing",
    ),
)


def _paired(
    fixture: QualificationFixture,
    replacements: dict[str, str],
    reason: SemanticRejectionReason,
) -> QualificationFixture:
    known_paths = {item.path for item in fixture.inputs}
    if not replacements or not set(replacements).issubset(known_paths):
        raise ValueError("qualification rejection replacements must target fixture inputs")
    rejection_inputs = tuple(
        replace(
            item,
            content=replacements.get(item.path, item.content.decode("utf-8")).encode("utf-8"),
        )
        for item in fixture.inputs
    )
    return replace(
        fixture,
        rejection_inputs=rejection_inputs,
        rejection_reason=reason,
    )


VERILATOR_LINT = _paired(
    VERILATOR_LINT,
    {
        "lint_counter.sv": """\
module lint_counter(
  input logic clock,
  input logic reset,
  input logic enable,
  output logic [7:0] count
);
  always_comb begin
    if (enable) count = 8'ha5;
  end
endmodule
"""
    },
    SemanticRejectionReason.RULE_VIOLATION,
)
YOSYS_SYNTHESIS = _paired(
    YOSYS_SYNTHESIS,
    {
        "dut.sv": """\
module dut(input logic [3:0] a, input logic [3:0] b, output logic [4:0] y);
  assign y = 5'b0;
endmodule
"""
    },
    SemanticRejectionReason.DEGENERATE_IMPLEMENTATION,
)
YOSYS_EQUIVALENCE = _paired(
    YOSYS_EQUIVALENCE,
    {
        "equivalence.sv": """\
module gold(input [3:0] a, input [3:0] b, output [4:0] y);
  assign y = a + b;
endmodule
module gate(input [3:0] a, input [3:0] b, output [4:0] y);
  assign y = {1'b0, a} - {1'b0, b};
endmodule
"""
    },
    SemanticRejectionReason.EQUIVALENCE_MISMATCH,
)
YOSYS_FORMAL = _paired(
    YOSYS_FORMAL,
    {
        "formal.sv": """\
module formal_add(input [3:0] a, input [3:0] b);
  wire [4:0] sum = a + b;
  always @* begin
    assert(sum == ({1'b0, a} + {1'b0, b} + 5'd1));
  end
endmodule
"""
    },
    SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE,
)
ABC_SYNTHESIS = _paired(
    ABC_SYNTHESIS,
    {
        "network.blif": """\
.model dut
.inputs a b c d
.outputs y
.names y
1
.end
"""
    },
    SemanticRejectionReason.DEGENERATE_IMPLEMENTATION,
)
ABC_EQUIVALENCE = _paired(
    ABC_EQUIVALENCE,
    {
        "revised.blif": """\
.model revised
.inputs a b c
.outputs y
.names a b c y
111 1
.end
"""
    },
    SemanticRejectionReason.EQUIVALENCE_MISMATCH,
)
FIRTOOL_LOWERING = _paired(
    FIRTOOL_LOWERING,
    {
        "design.fir": """\
FIRRTL version 4.0.0
circuit Counter :
  public module Counter :
    input clock : Clock
    input reset : UInt<1>
    output count : UInt<4>
    connect count, UInt<4>(0)
"""
    },
    SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
)
OPENROAD_STATIC_TIMING = _paired(
    OPENROAD_STATIC_TIMING,
    {
        "top.v": """\
module top(input clk, input d, output q);
  assign q = 1'b0;
endmodule
"""
    },
    SemanticRejectionReason.TIMING_PATH_MISSING,
)
SPECTRE_CIRCUIT_SIMULATION = _paired(
    SPECTRE_CIRCUIT_SIMULATION,
    {
        "divider.scs": """\
simulator lang=spectre
global 0

ahdl_include "divider_checker.va"

Vsource (vin 0) vsource type=dc dc=1
Rtop (vin out) resistor r=1k
Rbottom (out 0) resistor r=2k
Check (out) divider_checker expected=0.5 tolerance=1e-6

transient tran stop=1n maxstep=100p
save out
"""
    },
    SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE,
)
JASPER_FORMAL_PROPERTY = _paired(
    JASPER_FORMAL_PROPERTY,
    {
        "formal.sv": """\
module formal_probe(
  input logic clock,
  input logic reset_n,
  input logic enable
);
  logic [1:0] count;
  always_ff @(posedge clock or negedge reset_n) begin
    if (!reset_n) count <= '0;
    else if (enable) count <= count + 2'd1;
  end
  ap_check: assert property (
    @(posedge clock) disable iff (!reset_n)
    enable |=> count == $past(count)
  );
endmodule
"""
    },
    SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE,
)
JASPER_CDC = _paired(
    JASPER_CDC,
    {
        "cdc.sv": """\
module toggle_synchronizer(
  input logic source_clock,
  input logic destination_clock,
  input logic reset_n,
  input logic source_toggle,
  output logic synchronized_pulse
);
  logic source_value;
  always_ff @(posedge source_clock or negedge reset_n) begin
    if (!reset_n) source_value <= 1'b0;
    else if (source_toggle) source_value <= ~source_value;
  end
  always_ff @(posedge destination_clock or negedge reset_n) begin
    if (!reset_n) synchronized_pulse <= 1'b0;
    else synchronized_pulse <= source_value;
  end
endmodule
"""
    },
    SemanticRejectionReason.RULE_VIOLATION,
)
SPYGLASS_LINT = _paired(
    SPYGLASS_LINT,
    {
        "lint.sv": """\
module lint_probe(
  input logic clock,
  input logic reset,
  input logic enable,
  output logic [3:0] count
);
  always_comb begin
    if (reset) count = '0;
    else if (enable) count = count + 4'd1;
  end
endmodule
"""
    },
    SemanticRejectionReason.RULE_VIOLATION,
)
SPYGLASS_CDC = _paired(
    SPYGLASS_CDC,
    {
        "cdc.sv": """\
module cdc_probe(
  input logic source_clock,
  input logic destination_clock,
  input logic source_input,
  output logic destination_output
);
  logic source_value;
  always_ff @(posedge source_clock)
    source_value <= source_input;
  always_ff @(posedge destination_clock)
    destination_output <= source_value;
endmodule
"""
    },
    SemanticRejectionReason.RULE_VIOLATION,
)
NGSPICE_CIRCUIT_SIMULATION = _paired(
    NGSPICE_CIRCUIT_SIMULATION,
    {
        "divider.cir": """\
* EdaGym ngspice qualification workload
Vsource vin 0 1
Rtop vin out 1k
Rbottom out 0 2k
.control
set noaskquit
op
let delta = abs(v(out) - 0.5)
if delta < 1e-6
  echo EDAGYM_NGSPICE_DIVIDER_PASS
else
  echo EDAGYM_NGSPICE_DIVIDER_REJECT
end
quit
.endc
.end
"""
    },
    SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE,
)
KLAYOUT_PHYSICAL_VERIFICATION = _paired(
    KLAYOUT_PHYSICAL_VERIFICATION,
    {
        "layout.json": """\
{"minimum_spacing_nm":200,"rectangles_nm":[[0,0,1000,1000],[1100,0,2100,1000]]}
"""
    },
    SemanticRejectionReason.RULE_VIOLATION,
)


QUALIFICATION_FIXTURES: tuple[QualificationFixture, ...] = (
    IVERILOG_SIMULATION,
    VERILATOR_SIMULATION,
    VERILATOR_LINT,
    YOSYS_SYNTHESIS,
    YOSYS_EQUIVALENCE,
    YOSYS_FORMAL,
    ABC_SYNTHESIS,
    ABC_EQUIVALENCE,
    FIRTOOL_LOWERING,
    OPENROAD_STATIC_TIMING,
    NGSPICE_CIRCUIT_SIMULATION,
    KLAYOUT_PHYSICAL_VERIFICATION,
    *BACKEND_BREADTH_FIXTURES,
    *DIGITAL_SIGNOFF_FIXTURES,
    SPECTRE_CIRCUIT_SIMULATION,
    HSPICE_CIRCUIT_SIMULATION,
    ICV_PHYSICAL_VERIFICATION,
    PEGASUS_PHYSICAL_VERIFICATION,
    MODUS_DESIGN_FOR_TEST,
    JASPER_FORMAL_PROPERTY,
    JASPER_CDC,
    SPYGLASS_LINT,
    SPYGLASS_CDC,
    VITIS_HLS_SYNTHESIS,
    NEXTPNR_ICE40_IMPLEMENTATION,
)


def fixture_for(tool_id: str, capability: Capability) -> QualificationFixture | None:
    matches = [
        fixture
        for fixture in QUALIFICATION_FIXTURES
        if fixture.tool_id == tool_id and fixture.capability is capability
    ]
    if len(matches) > 1:
        raise RuntimeError("qualification fixture registry contains duplicate ownership")
    return matches[0] if matches else None


def validate_fixture_catalog() -> None:
    keys = [(fixture.tool_id, fixture.capability) for fixture in QUALIFICATION_FIXTURES]
    identifiers = [fixture.fixture_id for fixture in QUALIFICATION_FIXTURES]
    if len(keys) != len(set(keys)) or len(identifiers) != len(set(identifiers)):
        raise ValueError("qualification fixture identities must be globally unique")
    if any(
        not fixture.rejection_inputs or fixture.rejection_reason is None
        for fixture in QUALIFICATION_FIXTURES
    ):
        raise ValueError("every qualification fixture requires paired semantic evidence")


validate_fixture_catalog()
