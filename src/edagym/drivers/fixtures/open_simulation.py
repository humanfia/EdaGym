"""Deterministic trace and waveform qualification for open RTL simulators."""

from __future__ import annotations

import re
from dataclasses import dataclass

from edagym.drivers.fixtures.model import (
    FixtureInput,
    FixtureObservation,
    FixtureOutput,
    QualificationFixture,
    SemanticRejectionReason,
    ToolInvocation,
    WorkspaceInvocation,
)
from edagym.drivers.semantic_claims import SemanticJoint, normalize_semantic_joints
from edagym.specs.common import Capability

_ACCEPTED_MARKER = b"EDAGYM_RTL_SIMULATION_ACCEPTED"
_REJECTED_MARKER = b"EDAGYM_RTL_SIMULATION_REJECTED"
_MAXIMUM_TRACE_BYTES = 4096
_MAXIMUM_WAVEFORM_BYTES = 128 * 1024
_VECTOR_SCHEDULE = ((0, 0), (3, 5), (9, 7), (15, 1))
_VCD_VARIABLE = re.compile(r"^\$var\s+\S+\s+([0-9]+)\s+(\S+)\s+(\S+)(?:\s+.*?)?\s+\$end$")


def _input(logical_id: str, path: str, content: str) -> FixtureInput:
    return FixtureInput(logical_id=logical_id, path=path, content=content.encode("ascii"))


def _file_content(
    observation: FixtureObservation,
    path: str,
    maximum_bytes: int,
) -> bytes | None:
    output = observation.file(path)
    if (
        output is None
        or output.truncated
        or output.size_bytes != len(output.content)
        or output.size_bytes > maximum_bytes
    ):
        return None
    return output.content


def _compressed(values: tuple[int, ...]) -> tuple[int, ...]:
    result: list[int] = []
    for value in values:
        if not result or result[-1] != value:
            result.append(value)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class RtlTraceWaveformParser:
    """Cross-check native event rows against VCD topology and transitions."""

    trace_path: str
    waveform_path: str

    def _result(self, observation: FixtureObservation) -> str | None:
        if observation.exit_codes != (0, 0):
            return None
        streams = b"\n".join((*observation.stdout, *observation.stderr))
        accepted_count = streams.count(_ACCEPTED_MARKER)
        rejected_count = streams.count(_REJECTED_MARKER)
        if (accepted_count, rejected_count) not in {(1, 0), (0, 1)}:
            return None
        trace = _file_content(observation, self.trace_path, _MAXIMUM_TRACE_BYTES)
        waveform = _file_content(
            observation,
            self.waveform_path,
            _MAXIMUM_WAVEFORM_BYTES,
        )
        if trace is None or waveform is None:
            return None
        rows = self._trace_rows(trace)
        if rows is None or not self._waveform_matches(waveform, rows):
            return None
        correct = all(actual == expected for _, _, _, actual, expected in rows)
        known_mutant = all(
            actual == ((left - right) & 0x1F) for _, left, right, actual, _expected in rows
        )
        if accepted_count == 1 and correct:
            return "accepted"
        if rejected_count == 1 and not correct and known_mutant:
            return "rejected"
        return None

    @staticmethod
    def _trace_rows(content: bytes) -> tuple[tuple[int, int, int, int, int], ...] | None:
        try:
            lines = content.decode("ascii").splitlines()
            rows = tuple(tuple(int(field) for field in line.split()) for line in lines)
        except (UnicodeDecodeError, ValueError):
            return None
        if len(rows) != len(_VECTOR_SCHEDULE) or any(len(row) != 5 for row in rows):
            return None
        normalized = tuple((row[0], row[1], row[2], row[3], row[4]) for row in rows)
        for index, (left, right) in enumerate(_VECTOR_SCHEDULE):
            row = normalized[index]
            if row[:3] != (index, left, right) or row[4] != left + right:
                return None
        return normalized

    @staticmethod
    def _waveform_matches(
        content: bytes,
        rows: tuple[tuple[int, int, int, int, int], ...],
    ) -> bool:
        try:
            lines = tuple(line.strip() for line in content.decode("ascii").splitlines())
        except UnicodeDecodeError:
            return False
        scopes: list[str] = []
        signal_codes: dict[str, set[str]] = {"a": set(), "b": set(), "y": set()}
        signal_widths = {"a": 4, "b": 4, "y": 5}
        definitions_end: int | None = None
        has_timescale = False
        for index, line in enumerate(lines):
            if line.startswith("$timescale"):
                has_timescale = True
            if line.startswith("$scope "):
                fields = line.split()
                if len(fields) != 4 or fields[0] != "$scope" or fields[3] != "$end":
                    return False
                scopes.append(fields[2])
                continue
            if line == "$upscope $end":
                if not scopes:
                    return False
                scopes.pop()
                continue
            if line == "$enddefinitions $end":
                definitions_end = index
                break
            match = _VCD_VARIABLE.fullmatch(line)
            if match is None:
                continue
            width, code, reference = int(match.group(1)), match.group(2), match.group(3)
            if (
                reference in signal_codes
                and len(scopes) >= 1
                and scopes[-1] == "tb"
                and width == signal_widths[reference]
            ):
                signal_codes[reference].add(code)
        if (
            not has_timescale
            or definitions_end is None
            or any(len(codes) != 1 for codes in signal_codes.values())
        ):
            return False
        code_to_signal = {next(iter(codes)): signal for signal, codes in signal_codes.items()}
        times: list[int] = []
        transitions: dict[str, list[int]] = {"a": [], "b": [], "y": []}
        for line in lines[definitions_end + 1 :]:
            if line.startswith("#"):
                try:
                    time = int(line[1:])
                except ValueError:
                    return False
                if times and time <= times[-1]:
                    return False
                times.append(time)
                continue
            if line.startswith("b"):
                fields = line[1:].split()
                if len(fields) != 2:
                    continue
                bits, code = fields
            elif line[:1] in {"0", "1", "x", "X", "z", "Z"}:
                bits, code = line[0], line[1:]
            else:
                continue
            signal = code_to_signal.get(code)
            if signal is None:
                continue
            if not bits or any(bit not in "01" for bit in bits):
                return False
            value = int(bits, 2)
            if value >= 1 << signal_widths[signal]:
                return False
            if not transitions[signal] or transitions[signal][-1] != value:
                transitions[signal].append(value)
        expected = {
            "a": _compressed(tuple(row[1] for row in rows)),
            "b": _compressed(tuple(row[2] for row in rows)),
            "y": _compressed(tuple(row[3] for row in rows)),
        }
        return times == [0, 1, 2, 3, 4] and all(
            tuple(transitions[signal]) == values for signal, values in expected.items()
        )

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._result(observation) == "accepted"

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        if self._result(observation) == "rejected":
            return SemanticRejectionReason.FUNCTIONAL_MISMATCH
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "rtl_trace_vcd_crosscheck",
            "parser_revision": 1,
            "trace_path": self.trace_path,
            "waveform_path": self.waveform_path,
            "vector_schedule": _VECTOR_SCHEDULE,
            "required_signals": {"a": 4, "b": 4, "y": 5},
            "waveform_times": (0, 1, 2, 3, 4),
            "rejection_reason": SemanticRejectionReason.FUNCTIONAL_MISMATCH,
        }


_ADDER = """\
module dut(input logic [3:0] a, input logic [3:0] b, output logic [4:0] y);
  assign y = {1'b0, a} + {1'b0, b};
endmodule
"""

_SUBTRACTOR = """\
module dut(input logic [3:0] a, input logic [3:0] b, output logic [4:0] y);
  assign y = {1'b0, a} - {1'b0, b};
endmodule
"""

_TESTBENCH = """\
module tb;
  logic [3:0] a;
  logic [3:0] b;
  logic [4:0] y;
  integer trace_file;
  integer mismatch_count;
  dut dut_instance(.a(a), .b(b), .y(y));

  task automatic apply_vector(
    input integer vector_index,
    input logic [3:0] next_a,
    input logic [3:0] next_b
  );
    logic [4:0] expected;
    begin
      a = next_a;
      b = next_b;
      expected = {1'b0, next_a} + {1'b0, next_b};
      #1;
      $fdisplay(trace_file, "%0d %0d %0d %0d %0d", vector_index, a, b, y, expected);
      if (y !== expected)
        mismatch_count = mismatch_count + 1;
    end
  endtask

  initial begin
    $dumpfile("waveform.vcd");
    $dumpvars(0, tb);
    trace_file = $fopen("trace.log", "w");
    if (trace_file == 0)
      $fatal(1, "trace file unavailable");
    mismatch_count = 0;
    apply_vector(0, 4'd0, 4'd0);
    apply_vector(1, 4'd3, 4'd5);
    apply_vector(2, 4'd9, 4'd7);
    apply_vector(3, 4'd15, 4'd1);
    $fclose(trace_file);
    if (mismatch_count == 0)
      $display("EDAGYM_RTL_SIMULATION_ACCEPTED");
    else
      $display("EDAGYM_RTL_SIMULATION_REJECTED");
    $finish;
  end
endmodule
"""

_SEMANTIC_JOINTS = normalize_semantic_joints(
    Capability.RTL_SIMULATION,
    (
        SemanticJoint.RTL_SIMULATION_EVENT_TRACE,
        SemanticJoint.RTL_SIMULATION_WAVEFORM,
        SemanticJoint.RTL_SIMULATION_FUNCTIONAL_MISMATCH,
    ),
)


def _simulation_fixture(
    tool_id: str,
    compile_invocation: ToolInvocation,
    executable: str,
) -> QualificationFixture:
    return QualificationFixture(
        tool_id=tool_id,
        capability=Capability.RTL_SIMULATION,
        semantic_joints=_SEMANTIC_JOINTS,
        inputs=(
            _input("dut_source", "dut.sv", _ADDER),
            _input("testbench_source", "tb.sv", _TESTBENCH),
        ),
        rejection_inputs=(
            _input("dut_source", "dut.sv", _SUBTRACTOR),
            _input("testbench_source", "tb.sv", _TESTBENCH),
        ),
        rejection_reason=SemanticRejectionReason.FUNCTIONAL_MISMATCH,
        invocations=(compile_invocation, WorkspaceInvocation(executable)),
        outputs=(
            FixtureOutput("simulation_binary", executable),
            FixtureOutput("event_trace", "trace.log", media_type="text/plain"),
            FixtureOutput("waveform", "waveform.vcd", media_type="text/x-vcd"),
        ),
        parser=RtlTraceWaveformParser(
            trace_path="trace.log",
            waveform_path="waveform.vcd",
        ),
    )


IVERILOG_SIMULATION = _simulation_fixture(
    "iverilog",
    ToolInvocation(("-g2012", "-s", "tb", "-o", "simulation", "dut.sv", "tb.sv")),
    "simulation",
)

VERILATOR_SIMULATION = _simulation_fixture(
    "verilator",
    ToolInvocation(
        (
            "--binary",
            "--timing",
            "--trace",
            "-CFLAGS",
            "-fcoroutines",
            "--top-module",
            "tb",
            "--Mdir",
            "obj_dir",
            "-o",
            "simulation",
            "dut.sv",
            "tb.sv",
        )
    ),
    "obj_dir/simulation",
)

OPEN_SIMULATION_FIXTURES = (IVERILOG_SIMULATION, VERILATOR_SIMULATION)
