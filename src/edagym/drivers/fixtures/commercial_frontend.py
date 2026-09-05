"""Commercial simulation, formal, CDC/RDC, and lint qualification fixtures."""

from __future__ import annotations

import re
from dataclasses import dataclass

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


def _complete_content(observation: FixtureObservation, path: str) -> bytes | None:
    output = observation.file(path)
    if output is None or output.truncated:
        return None
    return output.content


def _unsigned_decimal(value: str | None) -> int | None:
    if value is None or re.fullmatch(r"0|[1-9][0-9]*", value) is None:
        return None
    return int(value)


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


def _vcd_final_unsigned_values(
    content: bytes,
    required_signals: tuple[str, ...],
) -> dict[str, int] | None:
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return None
    identifiers: dict[str, tuple[str, int]] = {}
    in_definitions = True
    saw_zero_time = False
    saw_positive_time = False
    values: dict[str, int] = {}
    required = set(required_signals)
    for raw_line in lines:
        line = raw_line.strip()
        if in_definitions:
            match = re.fullmatch(
                r"\$var\s+\S+\s+([1-9][0-9]*)\s+(\S+)\s+"
                r"([A-Za-z_][A-Za-z0-9_$]*)(?:\s*\[[^]]+\])?\s+\$end",
                line,
            )
            if match is not None and match.group(3) in required:
                identifiers[match.group(2)] = (match.group(3), int(match.group(1)))
            if line == "$enddefinitions $end":
                in_definitions = False
            continue
        if line == "#0":
            saw_zero_time = True
            continue
        if re.fullmatch(r"#[1-9][0-9]*", line):
            saw_positive_time = True
            continue
        vector = re.fullmatch(r"b([01xXzZ]+)\s+(\S+)", line)
        if vector is not None and vector.group(2) in identifiers:
            signal, width = identifiers[vector.group(2)]
            bits = vector.group(1)
            if len(bits) > width or re.search(r"[xXzZ]", bits):
                return None
            values[signal] = int(bits, 2)
            continue
        scalar = re.fullmatch(r"([01xXzZ])(\S+)", line)
        if scalar is not None and scalar.group(2) in identifiers:
            signal, width = identifiers[scalar.group(2)]
            if width != 1 or scalar.group(1) not in {"0", "1"}:
                return None
            values[signal] = int(scalar.group(1))
    if (
        in_definitions
        or not saw_zero_time
        or not saw_positive_time
        or set(identifiers.values()) != {
            ("a", 4),
            ("b", 4),
            ("y", 5),
        }
        or set(values) != required
    ):
        return None
    return values


@dataclass(frozen=True, slots=True)
class SimulationTraceWaveformParser:
    """Cross-check a deterministic event trace against a native VCD waveform."""

    trace_path: str
    waveform_path: str
    completion_marker: bytes
    acceptance_marker: bytes
    rejection_marker: bytes
    expected_a: int
    expected_b: int
    expected_y: int

    def __post_init__(self) -> None:
        validate_relative_path(self.trace_path)
        validate_relative_path(self.waveform_path)
        if (
            len(
                {
                    self.completion_marker,
                    self.acceptance_marker,
                    self.rejection_marker,
                }
            )
            != 3
            or not 0 <= self.expected_a < 16
            or not 0 <= self.expected_b < 16
            or not 0 <= self.expected_y < 32
        ):
            raise ValueError("simulation trace contract is not bounded")

    def _result(self, observation: FixtureObservation) -> bool | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation, self.completion_marker
        ):
            return None
        trace = _complete_content(observation, self.trace_path)
        waveform = _complete_content(observation, self.waveform_path)
        if trace is None or waveform is None:
            return None
        report = _key_value_report(trace)
        if report is None or set(report) != {
            "expected_y",
            "input_a",
            "input_b",
            "output_y",
            "sample_time_ns",
            "trace_version",
        }:
            return None
        parsed = {
            name: _unsigned_decimal(report.get(name))
            for name in ("expected_y", "input_a", "input_b", "output_y", "sample_time_ns")
        }
        if (
            report["trace_version"] != "1"
            or parsed["sample_time_ns"] != 1
            or parsed["input_a"] != self.expected_a
            or parsed["input_b"] != self.expected_b
            or parsed["expected_y"] != self.expected_y
        ):
            return None
        waveform_values = _vcd_final_unsigned_values(waveform, ("a", "b", "y"))
        if waveform_values != {
            "a": self.expected_a,
            "b": self.expected_b,
            "y": parsed["output_y"],
        }:
            return None
        accepted_marker = _has_exact_marker(observation, self.acceptance_marker)
        rejected_marker = _has_exact_marker(observation, self.rejection_marker)
        matches = parsed["output_y"] == self.expected_y
        if accepted_marker == rejected_marker or accepted_marker != matches:
            return None
        return matches

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._result(observation) is True

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        if self._result(observation) is False:
            return SemanticRejectionReason.FUNCTIONAL_MISMATCH
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "native_simulation_trace_vcd",
            "trace_path": self.trace_path,
            "waveform_path": self.waveform_path,
            "completion_marker": self.completion_marker.decode("ascii"),
            "acceptance_marker": self.acceptance_marker.decode("ascii"),
            "rejection_marker": self.rejection_marker.decode("ascii"),
            "trace_schema": (
                "trace_version",
                "sample_time_ns",
                "input_a",
                "input_b",
                "output_y",
                "expected_y",
            ),
            "expected_vector": (self.expected_a, self.expected_b, self.expected_y),
            "waveform_signals": (("a", 4), ("b", 4), ("y", 5)),
            "rejection_reason": SemanticRejectionReason.FUNCTIONAL_MISMATCH,
        }


_SIMULATION_ACCEPTANCE_SOURCE = """\
module dut(input logic [3:0] a, input logic [3:0] b, output logic [4:0] y);
  assign y = a + b;
endmodule
"""

_SIMULATION_REJECTION_SOURCE = """\
module dut(input logic [3:0] a, input logic [3:0] b, output logic [4:0] y);
  assign y = a - b;
endmodule
"""


def _simulation_testbench(
    completion_marker: str,
    acceptance_marker: str,
    rejection_marker: str,
) -> str:
    return f"""\
`timescale 1ns/1ps
module tb;
  logic [3:0] a;
  logic [3:0] b;
  logic [4:0] y;
  integer trace_channel;
  dut dut_instance(.a(a), .b(b), .y(y));
  initial begin
    $dumpfile("wave.vcd");
    $dumpvars(0, tb);
    trace_channel = $fopen("trace.txt", "w");
    if (trace_channel == 0) $fatal(1, "trace open failed");
    a = 4'd11;
    b = 4'd6;
    #1;
    $fdisplay(trace_channel, "trace_version 1");
    $fdisplay(trace_channel, "sample_time_ns 1");
    $fdisplay(trace_channel, "input_a %0d", a);
    $fdisplay(trace_channel, "input_b %0d", b);
    $fdisplay(trace_channel, "output_y %0d", y);
    $fdisplay(trace_channel, "expected_y 17");
    $fclose(trace_channel);
    if (y === 5'd17)
      $display("{acceptance_marker}");
    else
      $display("{rejection_marker}");
    $display("{completion_marker}");
    $finish;
  end
endmodule
"""


def _simulation_fixture(
    *,
    tool_id: str,
    invocation: ToolInvocation,
    completion_marker: bytes,
    acceptance_marker: bytes,
    rejection_marker: bytes,
) -> QualificationFixture:
    testbench = _simulation_testbench(
        completion_marker.decode("ascii"),
        acceptance_marker.decode("ascii"),
        rejection_marker.decode("ascii"),
    )
    return QualificationFixture(
        tool_id=tool_id,
        capability=Capability.RTL_SIMULATION,
        semantic_joints=normalize_semantic_joints(
            Capability.RTL_SIMULATION,
            (
                SemanticJoint.RTL_SIMULATION_EVENT_TRACE,
                SemanticJoint.RTL_SIMULATION_WAVEFORM,
                SemanticJoint.RTL_SIMULATION_FUNCTIONAL_MISMATCH,
            ),
        ),
        inputs=(
            _input("dut_source", "dut.sv", _SIMULATION_ACCEPTANCE_SOURCE),
            _input("testbench_source", "tb.sv", testbench),
        ),
        rejection_inputs=(
            _input("dut_source", "dut.sv", _SIMULATION_REJECTION_SOURCE),
            _input("testbench_source", "tb.sv", testbench),
        ),
        rejection_reason=SemanticRejectionReason.FUNCTIONAL_MISMATCH,
        invocations=(invocation,),
        outputs=(
            FixtureOutput("event_trace", "trace.txt", media_type="text/plain"),
            FixtureOutput("waveform", "wave.vcd", media_type="text/x-vcd"),
        ),
        parser=SimulationTraceWaveformParser(
            trace_path="trace.txt",
            waveform_path="wave.vcd",
            completion_marker=completion_marker,
            acceptance_marker=acceptance_marker,
            rejection_marker=rejection_marker,
            expected_a=11,
            expected_b=6,
            expected_y=17,
        ),
        log_projection=MarkerLogProjection(
            (completion_marker, acceptance_marker, rejection_marker)
        ),
    )


_XCELIUM_COMPLETION_MARKER = b"EDAGYM_XCELIUM_RTL_SIMULATION_COMPLETE"
_XCELIUM_ACCEPTANCE_MARKER = b"EDAGYM_XCELIUM_RTL_SIMULATION_ACCEPTED"
_XCELIUM_REJECTION_MARKER = b"EDAGYM_XCELIUM_RTL_SIMULATION_REJECTED"

XCELIUM_SIMULATION = _simulation_fixture(
    tool_id="xcelium",
    invocation=ToolInvocation(("-64bit", "-sv", "-top", "tb", "dut.sv", "tb.sv")),
    completion_marker=_XCELIUM_COMPLETION_MARKER,
    acceptance_marker=_XCELIUM_ACCEPTANCE_MARKER,
    rejection_marker=_XCELIUM_REJECTION_MARKER,
)

_VCS_COMPLETION_MARKER = b"EDAGYM_VCS_RTL_SIMULATION_COMPLETE"
_VCS_ACCEPTANCE_MARKER = b"EDAGYM_VCS_RTL_SIMULATION_ACCEPTED"
_VCS_REJECTION_MARKER = b"EDAGYM_VCS_RTL_SIMULATION_REJECTED"

VCS_SIMULATION = _simulation_fixture(
    tool_id="vcs",
    invocation=ToolInvocation(
        ("-full64", "-sverilog", "-top", "tb", "-R", "dut.sv", "tb.sv")
    ),
    completion_marker=_VCS_COMPLETION_MARKER,
    acceptance_marker=_VCS_ACCEPTANCE_MARKER,
    rejection_marker=_VCS_REJECTION_MARKER,
)


COMMERCIAL_FRONTEND_FIXTURES: tuple[QualificationFixture, ...] = (
    XCELIUM_SIMULATION,
    VCS_SIMULATION,
)
