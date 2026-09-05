"""Paired native-report workloads for digital signoff backends."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from edagym.drivers.fixtures.commercial_fpga import COMMERCIAL_FPGA_FIXTURES
from edagym.drivers.fixtures.commercial_frontend import COMMERCIAL_FRONTEND_FIXTURES
from edagym.drivers.fixtures.model import (
    FixtureAssetInput,
    FixtureInput,
    FixtureObservation,
    FixtureOutput,
    MarkerLogProjection,
    QualificationFixture,
    SemanticRejectionReason,
    ToolInvocation,
)
from edagym.drivers.semantic_claims import SemanticJoint, normalize_semantic_joints
from edagym.fixtures import OPENROAD_LEF, OPENROAD_LIBRARY, SEQUENTIAL_NETLIST
from edagym.fixtures.synthesis_toy import SYNTHESIS_LIBRARY
from edagym.specs.common import Capability, validate_relative_path


def _input(logical_id: str, path: str, content: str) -> FixtureInput:
    return FixtureInput(logical_id, path, content.encode("ascii"))


def _has_exact_marker(observation: FixtureObservation, marker: bytes) -> bool:
    return marker in {
        line.strip()
        for stream in (*observation.stdout, *observation.stderr)
        for line in stream.splitlines()
    }


def _content(
    observation: FixtureObservation,
    path: str,
    *,
    require_complete: bool = True,
) -> bytes | None:
    output = observation.file(path)
    if output is None or (require_complete and output.truncated):
        return None
    return output.content


def _nonempty_outputs(observation: FixtureObservation, paths: tuple[str, ...]) -> bool:
    return all(
        (output := observation.file(path)) is not None and output.size_bytes > 0
        for path in paths
    )


def _key_value_report(content: bytes) -> dict[str, str] | None:
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return None
    result: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] in result:
            return None
        result[fields[0]] = fields[1]
    return result or None


def _nonnegative_integer(value: str | None) -> int | None:
    if value is None or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        return None
    return int(value)


def _finite_decimal(value: str | None) -> Decimal | None:
    if value is None:
        return None
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None
    return parsed if parsed.is_finite() else None


@dataclass(frozen=True, slots=True)
class SynthesisReportParser:
    """Cross-check mapped structure, area, and setup timing native reports."""

    metric_path: str
    native_report_paths: tuple[str, ...]
    completion_marker: bytes
    minimum_cell_count: int = 1
    minimum_sequential_cell_count: int = 1

    def __post_init__(self) -> None:
        validate_relative_path(self.metric_path)
        for path in self.native_report_paths:
            validate_relative_path(path)
        if (
            not self.native_report_paths
            or len(self.native_report_paths) != len(set(self.native_report_paths))
            or self.minimum_cell_count <= 0
            or self.minimum_sequential_cell_count <= 0
        ):
            raise ValueError("synthesis evidence requires unique reports and a positive bound")

    def _metrics(
        self,
        observation: FixtureObservation,
    ) -> tuple[int, int, Decimal, Decimal] | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        report = _content(observation, self.metric_path)
        if report is None or not _nonempty_outputs(observation, self.native_report_paths):
            return None
        values = _key_value_report(report)
        if values is None or set(values) != {
            "area_units",
            "cell_count",
            "sequential_cell_count",
            "worst_setup_slack_ns",
        }:
            return None
        cell_count = _nonnegative_integer(values.get("cell_count"))
        sequential_count = _nonnegative_integer(values.get("sequential_cell_count"))
        area = _finite_decimal(values.get("area_units"))
        slack = _finite_decimal(values.get("worst_setup_slack_ns"))
        if (
            cell_count is None
            or sequential_count is None
            or sequential_count > cell_count
            or area is None
            or area <= 0
            or slack is None
        ):
            return None
        return cell_count, sequential_count, area, slack

    def accepts(self, observation: FixtureObservation) -> bool:
        metrics = self._metrics(observation)
        return metrics is not None and (
            metrics[0] >= self.minimum_cell_count
            and metrics[1] >= self.minimum_sequential_cell_count
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        metrics = self._metrics(observation)
        if metrics is not None and metrics[0] >= self.minimum_cell_count and metrics[1] == 0:
            return SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "native_synthesis_reports",
            "metric_path": self.metric_path,
            "native_report_paths": self.native_report_paths,
            "completion_marker": self.completion_marker.decode("ascii"),
            "measurements": (
                ("area_units", "technology_area_unit", "positive"),
                ("cell_count", "count", self.minimum_cell_count),
                (
                    "sequential_cell_count",
                    "count",
                    self.minimum_sequential_cell_count,
                ),
                ("worst_setup_slack_ns", "nanosecond", "finite"),
            ),
            "rejection_reason": SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
        }


@dataclass(frozen=True, slots=True)
class EquivalenceDecisionParser:
    """Classify a native equivalence decision encoded as an exact Boolean metric."""

    metric_path: str
    native_report_path: str
    completion_marker: bytes

    def __post_init__(self) -> None:
        validate_relative_path(self.metric_path)
        validate_relative_path(self.native_report_path)

    def _decision(self, observation: FixtureObservation) -> bool | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        report = _content(observation, self.metric_path)
        if report is None or not _nonempty_outputs(observation, (self.native_report_path,)):
            return None
        values = _key_value_report(report)
        if values is None or set(values) != {"equivalent"}:
            return None
        value = values["equivalent"]
        return True if value == "1" else False if value == "0" else None

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._decision(observation) is True

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        if self._decision(observation) is False:
            return SemanticRejectionReason.EQUIVALENCE_MISMATCH
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "native_equivalence_boolean",
            "metric_path": self.metric_path,
            "native_report_path": self.native_report_path,
            "completion_marker": self.completion_marker.decode("ascii"),
            "metric_id": "equivalent",
            "unit": "boolean",
            "rejection_reason": SemanticRejectionReason.EQUIVALENCE_MISMATCH,
        }


@dataclass(frozen=True, slots=True)
class ConformalReportParser:
    """Read Conformal's native compare result with its version-bound exit status."""

    output_path: str
    completion_marker: bytes
    rejection_exit_code: int

    def __post_init__(self) -> None:
        validate_relative_path(self.output_path)
        if self.rejection_exit_code <= 0 or self.rejection_exit_code > 255:
            raise ValueError("Conformal rejection requires a version-bound process status")

    def _decision(self, observation: FixtureObservation, exit_code: int) -> str | None:
        if observation.exit_codes != (exit_code,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        report = _content(observation, self.output_path)
        if report is None:
            return None
        matches: list[bytes] = re.findall(
            rb"^6\. Compare Results:[ \t]+(PASS|FAIL:[A-Z]+)[ \t]*$",
            report,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            return None
        return matches[0].decode("ascii")

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._decision(observation, 0) == "PASS"

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        decision = self._decision(observation, self.rejection_exit_code)
        if decision is not None and decision.startswith("FAIL:"):
            return SemanticRejectionReason.EQUIVALENCE_MISMATCH
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "conformal_native_compare_result",
            "output_path": self.output_path,
            "completion_marker": self.completion_marker.decode("ascii"),
            "acceptance_exit_code": 0,
            "rejection_exit_code": self.rejection_exit_code,
            "rejection_reason": SemanticRejectionReason.EQUIVALENCE_MISMATCH,
        }


@dataclass(frozen=True, slots=True)
class VcFormalPropertyParser:
    """Classify one non-vacuous VC Formal assertion from report_fv output."""

    output_path: str
    property_name: str
    completion_marker: bytes

    def __post_init__(self) -> None:
        validate_relative_path(self.output_path)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", self.property_name) is None:
            raise ValueError("VC Formal property names must be bounded identifiers")

    def _status(self, observation: FixtureObservation) -> bytes | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        report = _content(observation, self.output_path)
        if report is None:
            return None
        if len(re.findall(rb"^     # Assertion: 1$", report, flags=re.MULTILINE)) != 1:
            return None
        if len(re.findall(rb"^     - # non_vacuous[ \t]+: 1$", report, flags=re.MULTILINE)) != 1:
            return None
        property_pattern = (
            rb"^     \[\s*0\] (proven|falsified)\s+"
            rb"(?:\(depth=[0-9]+\)\s+)?\(non_vacuous\)\s+-\s+"
            + re.escape(self.property_name.encode("ascii"))
            + rb"\s*$"
        )
        matches: list[bytes] = re.findall(property_pattern, report, flags=re.MULTILINE)
        if len(matches) != 1:
            return None
        status = matches[0]
        expected_summary = rb"^     - # " + status + rb"[ \t]+: 1$"
        if len(re.findall(expected_summary, report, flags=re.MULTILINE)) != 1:
            return None
        opposite = b"falsified" if status == b"proven" else b"proven"
        if re.search(rb"^     - # " + opposite + rb"[ \t]+:", report, flags=re.MULTILINE):
            return None
        return status

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._status(observation) == b"proven"

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        if self._status(observation) == b"falsified":
            return SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "vc_formal_native_property_status",
            "output_path": self.output_path,
            "property_name": self.property_name,
            "completion_marker": self.completion_marker.decode("ascii"),
            "required_vacuity_status": "non_vacuous",
            "acceptance_status": "proven",
            "rejection_status": "falsified",
            "rejection_reason": SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE,
        }


@dataclass(frozen=True, slots=True)
class StaticTimingReportParser:
    """Classify setup and hold timing in one explicit corner and mode."""

    metric_path: str
    native_report_paths: tuple[str, ...]
    completion_marker: bytes

    def __post_init__(self) -> None:
        validate_relative_path(self.metric_path)
        for path in self.native_report_paths:
            validate_relative_path(path)
        if not self.native_report_paths or len(self.native_report_paths) != len(
            set(self.native_report_paths)
        ):
            raise ValueError("static-timing evidence requires unique native reports")

    def _metrics(
        self,
        observation: FixtureObservation,
    ) -> tuple[Decimal, Decimal, int] | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        report = _content(observation, self.metric_path)
        if report is None or not _nonempty_outputs(observation, self.native_report_paths):
            return None
        values = _key_value_report(report)
        if values is None or set(values) != {
            "analysis_corner",
            "analysis_mode",
            "violating_path_count",
            "worst_hold_slack_ns",
            "worst_setup_slack_ns",
        }:
            return None
        setup_slack = _finite_decimal(values.get("worst_setup_slack_ns"))
        hold_slack = _finite_decimal(values.get("worst_hold_slack_ns"))
        violations = _nonnegative_integer(values.get("violating_path_count"))
        if (
            values["analysis_corner"] != "typical"
            or values["analysis_mode"] != "functional"
            or setup_slack is None
            or hold_slack is None
            or violations is None
        ):
            return None
        return setup_slack, hold_slack, violations

    def accepts(self, observation: FixtureObservation) -> bool:
        metrics = self._metrics(observation)
        return metrics is not None and metrics[0] >= 0 and metrics[1] >= 0 and metrics[2] == 0

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        metrics = self._metrics(observation)
        if metrics is not None and (metrics[0] < 0 or metrics[1] < 0) and metrics[2] > 0:
            return SemanticRejectionReason.TIMING_CONSTRAINT_VIOLATION
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "native_setup_hold_timing",
            "metric_path": self.metric_path,
            "native_report_paths": self.native_report_paths,
            "completion_marker": self.completion_marker.decode("ascii"),
            "analysis_corner": "typical",
            "analysis_mode": "functional",
            "measurements": (
                ("worst_setup_slack_ns", "nanosecond", "finite"),
                ("worst_hold_slack_ns", "nanosecond", "finite"),
                ("violating_path_count", "count", "nonnegative"),
            ),
            "acceptance_slack_minimum": "0",
            "rejection_reason": SemanticRejectionReason.TIMING_CONSTRAINT_VIOLATION,
        }


def _def_component_count(content: bytes) -> int | None:
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return None
    headers = [
        (index, int(match.group(1)))
        for index, line in enumerate(lines)
        if (match := re.fullmatch(r"COMPONENTS ([0-9]+) ;", line.strip())) is not None
    ]
    if len(headers) != 1 or "END DESIGN" not in {line.strip() for line in lines}:
        return None
    start, declared = headers[0]
    ends = [
        index
        for index in range(start + 1, len(lines))
        if lines[index].strip() == "END COMPONENTS"
    ]
    if len(ends) != 1:
        return None
    observed = sum(line.lstrip().startswith("- ") for line in lines[start + 1 : ends[0]])
    return declared if declared == observed else None


@dataclass(frozen=True, slots=True)
class SequentialImplementationParser:
    """Bind routed DEF structure to native total and sequential cell queries."""

    metric_path: str
    routed_def_path: str
    timing_report_path: str
    completion_marker: bytes
    minimum_cell_count: int = 1
    minimum_sequential_cell_count: int = 1

    def __post_init__(self) -> None:
        validate_relative_path(self.metric_path)
        validate_relative_path(self.routed_def_path)
        validate_relative_path(self.timing_report_path)
        if self.minimum_cell_count <= 0 or self.minimum_sequential_cell_count <= 0:
            raise ValueError("implementation structure bounds must be positive")

    def _counts(self, observation: FixtureObservation) -> tuple[int, int] | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        metrics = _content(observation, self.metric_path)
        routed_def = _content(observation, self.routed_def_path)
        if (
            metrics is None
            or routed_def is None
            or not _nonempty_outputs(observation, (self.timing_report_path,))
        ):
            return None
        values = _key_value_report(metrics)
        if values is None or set(values) != {"cell_count", "sequential_cell_count"}:
            return None
        cell_count = _nonnegative_integer(values.get("cell_count"))
        sequential_count = _nonnegative_integer(values.get("sequential_cell_count"))
        def_count = _def_component_count(routed_def)
        if (
            cell_count is None
            or sequential_count is None
            or sequential_count > cell_count
            or def_count != cell_count
        ):
            return None
        return cell_count, sequential_count

    def accepts(self, observation: FixtureObservation) -> bool:
        counts = self._counts(observation)
        return counts is not None and (
            counts[0] >= self.minimum_cell_count
            and counts[1] >= self.minimum_sequential_cell_count
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        counts = self._counts(observation)
        if counts is not None and counts[0] >= self.minimum_cell_count and counts[1] == 0:
            return SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "native_routed_sequential_structure",
            "metric_path": self.metric_path,
            "routed_def_path": self.routed_def_path,
            "timing_report_path": self.timing_report_path,
            "completion_marker": self.completion_marker.decode("ascii"),
            "metrics": (
                {
                    "metric_id": "cell_count",
                    "unit": "count",
                    "minimum": self.minimum_cell_count,
                },
                {
                    "metric_id": "sequential_cell_count",
                    "unit": "count",
                    "minimum": self.minimum_sequential_cell_count,
                },
            ),
            "rejection_reason": SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
        }


_GENUS_COMPLETION_MARKER = b"EDAGYM_GENUS_ASIC_SYNTHESIS_COMPLETE"

_GENUS_SYNTHESIS_SCRIPT = """\
read_libs cells.lib
read_hdl dut.v
elaborate dut
read_sdc constraints.sdc
syn_gen
syn_map
syn_opt
write_hdl > genus_netlist.v
report gates > genus_gates.rpt
report area > genus_area.rpt
report timing -max_paths 1 > genus_timing.rpt
if {![file exists genus_netlist.v] || [file size genus_netlist.v] == 0} {
  error "synthesized netlist is missing"
}
set cell_count [llength [get_db insts]]
set sequential_count [llength [get_db insts -if {.base_cell.is_sequential == true}]]
set design_areas [get_db designs .area]
set timing_paths [get_db timing_paths -max_paths 1]
if {[llength $design_areas] != 1 || [llength $timing_paths] != 1} {
  error "synthesis QoR is incomplete"
}
set design_area [lindex $design_areas 0]
set worst_slack [get_db [lindex $timing_paths 0] .slack]
set metrics_channel [open "genus_metrics.txt" w]
puts $metrics_channel "area_units $design_area"
puts $metrics_channel "cell_count $cell_count"
puts $metrics_channel "sequential_cell_count $sequential_count"
puts $metrics_channel "worst_setup_slack_ns $worst_slack"
close $metrics_channel
puts [join {EDAGYM GENUS ASIC SYNTHESIS COMPLETE} _]
exit
"""

_SYNTHESIS_CONSTRAINTS = """\
create_clock -name clock -period 10 [get_ports clock]
set_input_delay 1 -clock clock [get_ports d]
set_output_delay 1 -clock clock [get_ports q]
"""

_GENUS_SEQUENTIAL_SOURCE = """\
module dut(input wire clock, input wire d, output reg q);
  always @(posedge clock)
    q <= ~d;
endmodule
"""

_GENUS_CONSTANT_SOURCE = """\
module dut(input wire clock, input wire d, output wire q);
  assign q = ~d;
endmodule
"""

GENUS_SYNTHESIS = QualificationFixture(
    tool_id="genus",
    capability=Capability.ASIC_SYNTHESIS,
    semantic_joints=normalize_semantic_joints(
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
    ),
    inputs=(
        _input("synthesis_library", "cells.lib", SYNTHESIS_LIBRARY),
        _input("dut_source", "dut.v", _GENUS_SEQUENTIAL_SOURCE),
        _input("timing_constraints", "constraints.sdc", _SYNTHESIS_CONSTRAINTS),
        _input("synthesis_script", "synthesize.tcl", _GENUS_SYNTHESIS_SCRIPT),
    ),
    rejection_inputs=(
        _input("synthesis_library", "cells.lib", SYNTHESIS_LIBRARY),
        _input("dut_source", "dut.v", _GENUS_CONSTANT_SOURCE),
        _input("timing_constraints", "constraints.sdc", _SYNTHESIS_CONSTRAINTS),
        _input("synthesis_script", "synthesize.tcl", _GENUS_SYNTHESIS_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("-batch", "-files", "synthesize.tcl")),),
    outputs=(
        FixtureOutput("synthesized_netlist", "genus_netlist.v", media_type="text/x-verilog"),
        FixtureOutput("gate_report", "genus_gates.rpt", media_type="text/plain"),
        FixtureOutput("area_report", "genus_area.rpt", media_type="text/plain"),
        FixtureOutput("timing_report", "genus_timing.rpt", media_type="text/plain"),
        FixtureOutput("synthesis_metrics", "genus_metrics.txt", media_type="text/plain"),
    ),
    parser=SynthesisReportParser(
        metric_path="genus_metrics.txt",
        native_report_paths=(
            "genus_netlist.v",
            "genus_gates.rpt",
            "genus_area.rpt",
            "genus_timing.rpt",
        ),
        completion_marker=_GENUS_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_GENUS_COMPLETION_MARKER,)),
)


_EQUIVALENCE_GOLDEN_SOURCE = """\
module dut(input wire [3:0] a, input wire [3:0] b, output wire [4:0] y);
  assign y = {1'b0, a} + {1'b0, b};
endmodule
"""

_EQUIVALENCE_REVISED_SOURCE = """\
module dut(input wire [3:0] a, input wire [3:0] b, output wire [4:0] y);
  wire [4:0] extended_a;
  wire [4:0] extended_b;
  assign extended_a = {1'b0, a};
  assign extended_b = {1'b0, b};
  assign y = extended_a + extended_b;
endmodule
"""

_EQUIVALENCE_MISMATCH_SOURCE = """\
module dut(input wire [3:0] a, input wire [3:0] b, output wire [4:0] y);
  assign y = {1'b0, a} - {1'b0, b};
endmodule
"""

_FORMALITY_COMPLETION_MARKER = b"EDAGYM_FORMALITY_EQUIVALENCE_COMPLETE"

_FORMALITY_EQUIVALENCE_SCRIPT = """\
read_verilog -r golden.v
set_top r:/WORK/dut
read_verilog -i revised.v
set_top i:/WORK/dut
match
set verification_result [verify]
redirect formality_status.rpt {report_status}
redirect formality_failing.rpt {report_failing_points}
set metrics_channel [open "formality_metrics.txt" w]
puts $metrics_channel "equivalent $verification_result"
close $metrics_channel
puts [join {EDAGYM FORMALITY EQUIVALENCE COMPLETE} _]
exit
"""

FORMALITY_EQUIVALENCE = QualificationFixture(
    tool_id="formality",
    capability=Capability.EQUIVALENCE,
    inputs=(
        _input("golden_source", "golden.v", _EQUIVALENCE_GOLDEN_SOURCE),
        _input("revised_source", "revised.v", _EQUIVALENCE_REVISED_SOURCE),
        _input("equivalence_script", "equivalence.tcl", _FORMALITY_EQUIVALENCE_SCRIPT),
    ),
    rejection_inputs=(
        _input("golden_source", "golden.v", _EQUIVALENCE_GOLDEN_SOURCE),
        _input("revised_source", "revised.v", _EQUIVALENCE_MISMATCH_SOURCE),
        _input("equivalence_script", "equivalence.tcl", _FORMALITY_EQUIVALENCE_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.EQUIVALENCE_MISMATCH,
    invocations=(ToolInvocation(("-f", "equivalence.tcl")),),
    outputs=(
        FixtureOutput("status_report", "formality_status.rpt", media_type="text/plain"),
        FixtureOutput(
            "failing_points_report",
            "formality_failing.rpt",
            required=False,
            media_type="text/plain",
        ),
        FixtureOutput("equivalence_metrics", "formality_metrics.txt", media_type="text/plain"),
    ),
    parser=EquivalenceDecisionParser(
        metric_path="formality_metrics.txt",
        native_report_path="formality_status.rpt",
        completion_marker=_FORMALITY_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_FORMALITY_COMPLETION_MARKER,)),
)


_CONFORMAL_COMPLETION_MARKER = b"EDAGYM_CONFORMAL_EQUIVALENCE_COMPLETE"
_CONFORMAL_REJECTION_EXIT_CODE = 16

_CONFORMAL_EQUIVALENCE_SCRIPT = """\
set log file equivalence.log -replace
read design -verilog -replace -golden golden.v
read design -verilog -replace -revised revised.v
set root module dut -both
set system mode lec
add compare point -all
compare
report verification > equivalence.rpt
tclmode
if {![file exists equivalence.rpt] || [file size equivalence.rpt] == 0} {
  error "equivalence report is missing"
}
puts [join {EDAGYM CONFORMAL EQUIVALENCE COMPLETE} _]
vpxmode
exit -force
"""

CONFORMAL_EQUIVALENCE = QualificationFixture(
    tool_id="conformal",
    capability=Capability.EQUIVALENCE,
    inputs=(
        _input("golden_source", "golden.v", _EQUIVALENCE_GOLDEN_SOURCE),
        _input("revised_source", "revised.v", _EQUIVALENCE_REVISED_SOURCE),
        _input("equivalence_script", "equivalence.do", _CONFORMAL_EQUIVALENCE_SCRIPT),
    ),
    rejection_inputs=(
        _input("golden_source", "golden.v", _EQUIVALENCE_GOLDEN_SOURCE),
        _input("revised_source", "revised.v", _EQUIVALENCE_MISMATCH_SOURCE),
        _input("equivalence_script", "equivalence.do", _CONFORMAL_EQUIVALENCE_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.EQUIVALENCE_MISMATCH,
    rejection_exit_code=_CONFORMAL_REJECTION_EXIT_CODE,
    invocations=(ToolInvocation(("-nogui", "-dofile", "equivalence.do")),),
    outputs=(
        FixtureOutput("equivalence_report", "equivalence.rpt", media_type="text/plain"),
    ),
    parser=ConformalReportParser(
        output_path="equivalence.rpt",
        completion_marker=_CONFORMAL_COMPLETION_MARKER,
        rejection_exit_code=_CONFORMAL_REJECTION_EXIT_CODE,
    ),
    log_projection=MarkerLogProjection((_CONFORMAL_COMPLETION_MARKER,)),
)


_VC_FORMAL_COMPLETION_MARKER = b"EDAGYM_VC_FORMAL_COMPLETE"
_VC_FORMAL_PROPERTY_NAME = "formal_probe.transfer_holds"

_VC_FORMAL_ACCEPTANCE_SOURCE = """\
module formal_probe (
  input logic clock,
  input logic reset_n,
  input logic request,
  output logic grant
);
  always_ff @(posedge clock or negedge reset_n) begin
    if (!reset_n) begin
      grant <= 1'b0;
    end else begin
      grant <= request;
    end
  end

  transfer_holds: assert property (
    @(posedge clock) disable iff (!reset_n) request |=> grant
  );
endmodule
"""

_VC_FORMAL_REJECTION_SOURCE = """\
module formal_probe (
  input logic clock,
  input logic reset_n,
  input logic request,
  output logic grant
);
  always_ff @(posedge clock or negedge reset_n) begin
    if (!reset_n) begin
      grant <= 1'b0;
    end else begin
      grant <= ~request;
    end
  end

  transfer_holds: assert property (
    @(posedge clock) disable iff (!reset_n) request |=> grant
  );
endmodule
"""

_VC_FORMAL_SCRIPT = """\
set_fml_appmode FPV
set_fml_var fml_witness_on true
set_fml_var fml_max_time 2M
analyze -format sverilog {formal.sv}
elaborate formal_probe -sva
create_clock clock -period 10
create_reset reset_n -sense low
sim_run -stable
check_fv -block
report_fv -list > formal.rpt
puts [join {EDAGYM VC FORMAL COMPLETE} _]
exit
"""

VC_FORMAL_PROPERTY = QualificationFixture(
    tool_id="vc_formal",
    capability=Capability.FORMAL_PROPERTY,
    inputs=(
        _input("formal_source", "formal.sv", _VC_FORMAL_ACCEPTANCE_SOURCE),
        _input("formal_script", "formal.tcl", _VC_FORMAL_SCRIPT),
    ),
    rejection_inputs=(
        _input("formal_source", "formal.sv", _VC_FORMAL_REJECTION_SOURCE),
        _input("formal_script", "formal.tcl", _VC_FORMAL_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.PROPERTY_COUNTEREXAMPLE,
    invocations=(ToolInvocation(("-f", "formal.tcl")),),
    outputs=(FixtureOutput("property_report", "formal.rpt", media_type="text/plain"),),
    parser=VcFormalPropertyParser(
        output_path="formal.rpt",
        property_name=_VC_FORMAL_PROPERTY_NAME,
        completion_marker=_VC_FORMAL_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_VC_FORMAL_COMPLETION_MARKER,)),
)


_OPENROAD_IMPLEMENTATION_COMPLETION_MARKER = (
    b"EDAGYM_OPENROAD_DIGITAL_IMPLEMENTATION_COMPLETE"
)

_OPENROAD_COMBINATIONAL_NETLIST = """\
module top(input clk, input d, output q);
  wire buffered0;
  wire buffered1;
  wire buffered2;
  BUF path0(.A(d), .Y(buffered0));
  BUF path1(.A(buffered0), .Y(buffered1));
  BUF path2(.A(buffered1), .Y(buffered2));
  BUF path3(.A(buffered2), .Y(q));
endmodule
"""

_OPENROAD_IMPLEMENTATION_CONSTRAINTS = """\
create_clock -name clk -period 2.0 [get_ports clk]
"""

_OPENROAD_IMPLEMENTATION_SCRIPT = """\
read_lef cells.lef
read_liberty cells.lib
read_verilog top.v
link_design top
read_sdc constraints.sdc
initialize_floorplan -die_area {0 0 40 40} -core_area {2 2 38 38} -site CoreSite
make_tracks met1 -x_offset 0.10 -x_pitch 0.20 -y_offset 0.10 -y_pitch 0.20
make_tracks met2 -x_offset 0.10 -x_pitch 0.20 -y_offset 0.10 -y_pitch 0.20
place_pins -hor_layers met1 -ver_layers met2
global_placement
detailed_placement
check_placement -verbose
set_routing_layers -signal met1-met2
global_route
detailed_route -output_drc drc.rpt
write_def routed.def
report_checks -path_delay max -fields {slew cap input nets fanout} > timing.rpt
set cell_count [llength [get_cells -hierarchical *]]
set sequential_count [llength [get_cells -hierarchical * -filter "ref_name == DFF"]]
set metrics_channel [open "openroad_metrics.txt" w]
puts $metrics_channel "cell_count $cell_count"
puts $metrics_channel "sequential_cell_count $sequential_count"
close $metrics_channel
puts [join {EDAGYM OPENROAD DIGITAL IMPLEMENTATION COMPLETE} _]
exit
"""

OPENROAD_DIGITAL_IMPLEMENTATION = QualificationFixture(
    tool_id="openroad",
    capability=Capability.DIGITAL_IMPLEMENTATION,
    inputs=(
        _input("physical_library", "cells.lef", OPENROAD_LEF),
        _input("timing_library", "cells.lib", OPENROAD_LIBRARY),
        _input("mapped_netlist", "top.v", SEQUENTIAL_NETLIST),
        _input("timing_constraints", "constraints.sdc", _OPENROAD_IMPLEMENTATION_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _OPENROAD_IMPLEMENTATION_SCRIPT),
    ),
    rejection_inputs=(
        _input("physical_library", "cells.lef", OPENROAD_LEF),
        _input("timing_library", "cells.lib", OPENROAD_LIBRARY),
        _input("mapped_netlist", "top.v", _OPENROAD_COMBINATIONAL_NETLIST),
        _input("timing_constraints", "constraints.sdc", _OPENROAD_IMPLEMENTATION_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _OPENROAD_IMPLEMENTATION_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("-no_init", "-exit", "implement.tcl")),),
    outputs=(
        FixtureOutput("routed_design", "routed.def", media_type="text/plain"),
        FixtureOutput("timing_report", "timing.rpt", media_type="text/plain"),
        FixtureOutput("drc_report", "drc.rpt", media_type="text/plain"),
        FixtureOutput("implementation_metrics", "openroad_metrics.txt", media_type="text/plain"),
    ),
    parser=SequentialImplementationParser(
        metric_path="openroad_metrics.txt",
        routed_def_path="routed.def",
        timing_report_path="timing.rpt",
        completion_marker=_OPENROAD_IMPLEMENTATION_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_OPENROAD_IMPLEMENTATION_COMPLETION_MARKER,)),
)


_DESIGN_COMPILER_COMPLETION_MARKER = b"EDAGYM_DESIGN_COMPILER_SYNTHESIS_COMPLETE"

_DESIGN_COMPILER_SCRIPT = """\
set_app_var search_path [list .]
set_app_var target_library [list technology.db]
set_app_var link_library [list * technology.db]
analyze -format verilog dut.v
elaborate dut
current_design dut
link
source constraints.sdc
compile
write -format verilog -hierarchy -output dc_netlist.v
report_area > dc_area.rpt
report_timing -max_paths 1 > dc_timing.rpt
set cell_count [sizeof_collection [get_cells -hierarchical]]
set sequential_count [sizeof_collection [get_cells -hierarchical -filter "is_sequential == true"]]
set timing_paths [get_timing_paths -delay_type max -max_paths 1]
if {[sizeof_collection $timing_paths] != 1} {
  error "synthesis timing path is missing"
}
set design_area [get_attribute [current_design] area]
set worst_slack [get_attribute $timing_paths slack]
set metrics_channel [open "dc_metrics.txt" w]
puts $metrics_channel "area_units $design_area"
puts $metrics_channel "cell_count $cell_count"
puts $metrics_channel "sequential_cell_count $sequential_count"
puts $metrics_channel "worst_setup_slack_ns $worst_slack"
close $metrics_channel
puts [join {EDAGYM DESIGN COMPILER SYNTHESIS COMPLETE} _]
exit
"""

DESIGN_COMPILER_SYNTHESIS = QualificationFixture(
    tool_id="design_compiler",
    capability=Capability.ASIC_SYNTHESIS,
    semantic_joints=GENUS_SYNTHESIS.semantic_joints,
    inputs=(
        _input("dut_source", "dut.v", _GENUS_SEQUENTIAL_SOURCE),
        _input("timing_constraints", "constraints.sdc", _SYNTHESIS_CONSTRAINTS),
        _input("synthesis_script", "synthesize.tcl", _DESIGN_COMPILER_SCRIPT),
    ),
    rejection_inputs=(
        _input("dut_source", "dut.v", _GENUS_CONSTANT_SOURCE),
        _input("timing_constraints", "constraints.sdc", _SYNTHESIS_CONSTRAINTS),
        _input("synthesis_script", "synthesize.tcl", _DESIGN_COMPILER_SCRIPT),
    ),
    restricted_assets=(
        FixtureAssetInput(
            "technology_library",
            "technology.db",
            "digital_synthesis_reference",
        ),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("-f", "synthesize.tcl")),),
    outputs=(
        FixtureOutput("synthesized_netlist", "dc_netlist.v", media_type="text/x-verilog"),
        FixtureOutput("area_report", "dc_area.rpt", media_type="text/plain"),
        FixtureOutput("timing_report", "dc_timing.rpt", media_type="text/plain"),
        FixtureOutput("synthesis_metrics", "dc_metrics.txt", media_type="text/plain"),
    ),
    parser=SynthesisReportParser(
        metric_path="dc_metrics.txt",
        native_report_paths=("dc_netlist.v", "dc_area.rpt", "dc_timing.rpt"),
        completion_marker=_DESIGN_COMPILER_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_DESIGN_COMPILER_COMPLETION_MARKER,)),
)


_TIMING_NETLIST_PORTS = """\
create_clock -name clock -period {period} [get_ports clock]
set_input_delay {delay} -clock clock [get_ports d]
set_output_delay {delay} -clock clock [get_ports q]
"""

_TIMING_ACCEPTANCE_CONSTRAINTS = _TIMING_NETLIST_PORTS.format(period="10", delay="0.1")
_TIMING_REJECTION_CONSTRAINTS = _TIMING_NETLIST_PORTS.format(period="0.05", delay="0.01")

_TEMPUS_COMPLETION_MARKER = b"EDAGYM_TEMPUS_STATIC_TIMING_COMPLETE"

_TEMPUS_SCRIPT = """\
read_lib -typ technology/cells.lib
read_verilog technology/top.v
set_top_module top
read_sdc constraints.sdc
set_analysis_mode -single -setup
report_timing -max_paths 3 > tempus_timing.rpt
report_analysis_coverage > tempus_coverage.rpt
set report_channel [open "tempus_timing.rpt" r]
set report_text [read $report_channel]
close $report_channel
if {![regexp {= Slack Time[ \t]+(-?[0-9]+(?:\\.[0-9]+)?)} $report_text match worst_slack]} {
  error "setup slack is missing"
}
set metrics_channel [open "tempus_metrics.txt" w]
puts $metrics_channel "worst_setup_slack_ns $worst_slack"
close $metrics_channel
puts [join {EDAGYM TEMPUS STATIC TIMING COMPLETE} _]
exit
"""

TEMPUS_STATIC_TIMING = QualificationFixture(
    tool_id="tempus",
    capability=Capability.STATIC_TIMING,
    inputs=(
        _input("timing_constraints", "constraints.sdc", _TIMING_ACCEPTANCE_CONSTRAINTS),
        _input("timing_script", "timing.tcl", _TEMPUS_SCRIPT),
    ),
    rejection_inputs=(
        _input("timing_constraints", "constraints.sdc", _TIMING_REJECTION_CONSTRAINTS),
        _input("timing_script", "timing.tcl", _TEMPUS_SCRIPT),
    ),
    restricted_assets=(
        FixtureAssetInput(
            "technology_reference",
            "technology",
            "cadence_static_timing_reference",
        ),
    ),
    rejection_reason=SemanticRejectionReason.IMPLEMENTATION_CONSTRAINT_VIOLATION,
    invocations=(ToolInvocation(("-no_gui", "-files", "timing.tcl")),),
    outputs=(
        FixtureOutput("timing_report", "tempus_timing.rpt", media_type="text/plain"),
        FixtureOutput("coverage_report", "tempus_coverage.rpt", media_type="text/plain"),
        FixtureOutput("timing_metrics", "tempus_metrics.txt", media_type="text/plain"),
    ),
    parser=StaticTimingReportParser(
        metric_path="tempus_metrics.txt",
        native_report_paths=("tempus_timing.rpt", "tempus_coverage.rpt"),
        completion_marker=_TEMPUS_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_TEMPUS_COMPLETION_MARKER,)),
)


_PRIMETIME_COMPLETION_MARKER = b"EDAGYM_PRIMETIME_STATIC_TIMING_COMPLETE"

_PRIMETIME_SCRIPT = """\
set_app_var search_path [list .]
set_app_var link_path [list * technology/cells.db]
read_verilog technology/top.v
current_design top
link_design top
read_sdc constraints.sdc
update_timing
redirect pt_timing.rpt {report_timing -delay_type max -max_paths 3}
redirect pt_constraints.rpt {report_constraint -all_violators}
set timing_paths [get_timing_paths -delay_type max -max_paths 1]
if {[sizeof_collection $timing_paths] != 1} {
  error "setup timing path is missing"
}
set worst_slack [get_attribute $timing_paths slack]
set metrics_channel [open "pt_metrics.txt" w]
puts $metrics_channel "worst_setup_slack_ns $worst_slack"
close $metrics_channel
puts [join {EDAGYM PRIMETIME STATIC TIMING COMPLETE} _]
exit
"""

PRIMETIME_STATIC_TIMING = QualificationFixture(
    tool_id="primetime",
    capability=Capability.STATIC_TIMING,
    inputs=(
        _input("timing_constraints", "constraints.sdc", _TIMING_ACCEPTANCE_CONSTRAINTS),
        _input("timing_script", "timing.tcl", _PRIMETIME_SCRIPT),
    ),
    rejection_inputs=(
        _input("timing_constraints", "constraints.sdc", _TIMING_REJECTION_CONSTRAINTS),
        _input("timing_script", "timing.tcl", _PRIMETIME_SCRIPT),
    ),
    restricted_assets=(
        FixtureAssetInput(
            "technology_reference",
            "technology",
            "synopsys_static_timing_reference",
        ),
    ),
    rejection_reason=SemanticRejectionReason.IMPLEMENTATION_CONSTRAINT_VIOLATION,
    invocations=(ToolInvocation(("-f", "timing.tcl")),),
    outputs=(
        FixtureOutput("timing_report", "pt_timing.rpt", media_type="text/plain"),
        FixtureOutput("constraint_report", "pt_constraints.rpt", media_type="text/plain"),
        FixtureOutput("timing_metrics", "pt_metrics.txt", media_type="text/plain"),
    ),
    parser=StaticTimingReportParser(
        metric_path="pt_metrics.txt",
        native_report_paths=("pt_timing.rpt", "pt_constraints.rpt"),
        completion_marker=_PRIMETIME_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_PRIMETIME_COMPLETION_MARKER,)),
)


_IMPLEMENTATION_CONSTRAINTS = """\
create_clock -name clock -period 10 [get_ports clock]
set_input_delay 1 -clock clock [get_ports {a b}]
set_output_delay 1 -clock clock [get_ports q]
"""

_INNOVUS_MMMC_SCRIPT = """\
create_library_set -name slow_library -timing [list technology/cells.lib]
create_rc_corner -name nominal_rc
create_delay_corner -name slow_delay -library_set slow_library -rc_corner nominal_rc
create_constraint_mode -name functional -sdc_files [list constraints.sdc]
create_analysis_view -name slow_view -constraint_mode functional -delay_corner slow_delay
set_analysis_view -setup [list slow_view] -hold [list slow_view]
"""

_INNOVUS_COMPLETION_MARKER = b"EDAGYM_INNOVUS_DIGITAL_IMPLEMENTATION_COMPLETE"

_INNOVUS_SCRIPT = """\
source design_role.tcl
set init_lef_file [list technology/tech.lef technology/cells.lef]
set init_verilog $mapped_netlist
set init_top_cell dut
set init_mmmc_file mmmc.tcl
init_design
floorPlan -site CoreSite -r 1.0 0.60 3 3 3 3
set_dont_touch [get_cells *] true
place_design
routeDesign
defOut -routing routed.def
report_timing > timing.rpt
verify_drc -report drc.rpt
set cell_count [llength [dbGet top.insts.name]]
set sequential_count [llength [lsearch -all -exact [dbGet top.insts.cell.isSequential] 1]]
set metrics_channel [open "innovus_metrics.txt" w]
puts $metrics_channel "cell_count $cell_count"
puts $metrics_channel "sequential_cell_count $sequential_count"
close $metrics_channel
if {![file exists routed.def] || [file size routed.def] == 0} {
  error "routed database is missing"
}
if {![file exists timing.rpt] || [file size timing.rpt] == 0} {
  error "timing report is missing"
}
if {![file exists drc.rpt] || [file size drc.rpt] == 0} {
  error "design rule report is missing"
}
puts [join {EDAGYM INNOVUS DIGITAL IMPLEMENTATION COMPLETE} _]
exit
"""

INNOVUS_DIGITAL_IMPLEMENTATION = QualificationFixture(
    tool_id="innovus",
    capability=Capability.DIGITAL_IMPLEMENTATION,
    inputs=(
        _input(
            "mapped_design_selection",
            "design_role.tcl",
            "set mapped_netlist technology/acceptance.v\n",
        ),
        _input("timing_constraints", "constraints.sdc", _IMPLEMENTATION_CONSTRAINTS),
        _input("analysis_setup", "mmmc.tcl", _INNOVUS_MMMC_SCRIPT),
        _input("implementation_script", "implement.tcl", _INNOVUS_SCRIPT),
    ),
    rejection_inputs=(
        _input(
            "mapped_design_selection",
            "design_role.tcl",
            "set mapped_netlist technology/rejection.v\n",
        ),
        _input("timing_constraints", "constraints.sdc", _IMPLEMENTATION_CONSTRAINTS),
        _input("analysis_setup", "mmmc.tcl", _INNOVUS_MMMC_SCRIPT),
        _input("implementation_script", "implement.tcl", _INNOVUS_SCRIPT),
    ),
    restricted_assets=(
        FixtureAssetInput(
            "technology_reference",
            "technology",
            "cadence_digital_implementation_reference",
        ),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("-no_gui", "-batch", "-files", "implement.tcl")),),
    outputs=(
        FixtureOutput("routed_design", "routed.def", media_type="text/plain"),
        FixtureOutput("timing_report", "timing.rpt", media_type="text/plain"),
        FixtureOutput("drc_report", "drc.rpt", media_type="text/plain"),
        FixtureOutput("implementation_metrics", "innovus_metrics.txt", media_type="text/plain"),
    ),
    parser=SequentialImplementationParser(
        metric_path="innovus_metrics.txt",
        routed_def_path="routed.def",
        timing_report_path="timing.rpt",
        completion_marker=_INNOVUS_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_INNOVUS_COMPLETION_MARKER,)),
)


_ICC2_COMPLETION_MARKER = b"EDAGYM_ICC2_DIGITAL_IMPLEMENTATION_COMPLETE"

_ICC2_CONSTRAINTS = """\
create_clock -name clock -period 10 [get_ports clock]
set_input_delay 0.1 -clock clock [get_ports d]
set_output_delay 0.1 -clock clock [get_ports q]
"""

_ICC2_SCRIPT = """\
source design_role.tcl
create_lib design.ndm -ref_libs [list technology/ref_lib.ndm]
read_verilog $mapped_netlist
current_block top
link_block
read_sdc constraints.sdc
initialize_floorplan -core_utilization 0.20 -side_ratio {1 1} -core_offset {5}
place_pins -self
create_placement
route_auto
save_block
write_def routed.def
redirect icc2_timing.rpt {report_timing -delay_type max -max_paths 3}
redirect icc2_route.rpt {check_routes}
set cell_count [sizeof_collection [get_cells -hierarchical]]
set sequential_count [sizeof_collection [get_cells -hierarchical -filter "is_sequential == true"]]
set metrics_channel [open "icc2_metrics.txt" w]
puts $metrics_channel "cell_count $cell_count"
puts $metrics_channel "sequential_cell_count $sequential_count"
close $metrics_channel
puts [join {EDAGYM ICC2 DIGITAL IMPLEMENTATION COMPLETE} _]
exit
"""

ICC2_DIGITAL_IMPLEMENTATION = QualificationFixture(
    tool_id="icc2",
    capability=Capability.DIGITAL_IMPLEMENTATION,
    inputs=(
        _input(
            "mapped_design_selection",
            "design_role.tcl",
            "set mapped_netlist technology/acceptance.v\n",
        ),
        _input("timing_constraints", "constraints.sdc", _ICC2_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _ICC2_SCRIPT),
    ),
    rejection_inputs=(
        _input(
            "mapped_design_selection",
            "design_role.tcl",
            "set mapped_netlist technology/rejection.v\n",
        ),
        _input("timing_constraints", "constraints.sdc", _ICC2_CONSTRAINTS),
        _input("implementation_script", "implement.tcl", _ICC2_SCRIPT),
    ),
    restricted_assets=(
        FixtureAssetInput(
            "technology_reference",
            "technology",
            "synopsys_digital_implementation_reference",
        ),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("-f", "implement.tcl")),),
    outputs=(
        FixtureOutput("routed_design", "routed.def", media_type="text/plain"),
        FixtureOutput("timing_report", "icc2_timing.rpt", media_type="text/plain"),
        FixtureOutput("route_report", "icc2_route.rpt", media_type="text/plain"),
        FixtureOutput("implementation_metrics", "icc2_metrics.txt", media_type="text/plain"),
    ),
    parser=SequentialImplementationParser(
        metric_path="icc2_metrics.txt",
        routed_def_path="routed.def",
        timing_report_path="icc2_timing.rpt",
        completion_marker=_ICC2_COMPLETION_MARKER,
    ),
    log_projection=MarkerLogProjection((_ICC2_COMPLETION_MARKER,)),
)


DIGITAL_SIGNOFF_FIXTURES: tuple[QualificationFixture, ...] = (
    *COMMERCIAL_FRONTEND_FIXTURES,
    *COMMERCIAL_FPGA_FIXTURES,
    GENUS_SYNTHESIS,
    DESIGN_COMPILER_SYNTHESIS,
    FORMALITY_EQUIVALENCE,
    CONFORMAL_EQUIVALENCE,
    VC_FORMAL_PROPERTY,
    TEMPUS_STATIC_TIMING,
    PRIMETIME_STATIC_TIMING,
    OPENROAD_DIGITAL_IMPLEMENTATION,
    INNOVUS_DIGITAL_IMPLEMENTATION,
    ICC2_DIGITAL_IMPLEMENTATION,
)
