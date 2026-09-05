"""Semantic HLS and DFT qualification workloads for commercial backends."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
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

_MAX_HLS_REPORT_BYTES = 512 * 1024
_MAX_GENERATED_RTL_BYTES = 2 * 1024 * 1024
_UNSIGNED_DECIMAL = re.compile(r"0|[1-9][0-9]*")


def _input(logical_id: str, path: str, content: str) -> FixtureInput:
    return FixtureInput(logical_id, path, content.encode("ascii"))


def _complete_content(
    observation: FixtureObservation,
    path: str,
    *,
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


def _has_exact_marker(observation: FixtureObservation, marker: bytes) -> bool:
    return marker in {
        line.strip()
        for stream in (*observation.stdout, *observation.stderr)
        for line in stream.splitlines()
    }


def _unsigned(value: str | None, *, maximum: int) -> int | None:
    if value is None or _UNSIGNED_DECIMAL.fullmatch(value) is None:
        return None
    parsed = int(value)
    return parsed if parsed <= maximum else None


def _unique_xml_text(root: ET.Element, path: str) -> str | None:
    matches = root.findall(path)
    if len(matches) != 1 or matches[0].text is None:
        return None
    return matches[0].text.strip()


@dataclass(frozen=True, slots=True)
class VitisHlsParser:
    """Cross-check generated RTL, synthesis QoR, and native C/RTL cosimulation."""

    rtl_path: str
    synthesis_report_path: str
    cosimulation_report_path: str
    completion_marker: bytes
    top_module: str
    maximum_latency_cycles: int
    acceptance_minimum_dsps: int
    rejection_maximum_dsps: int

    def __post_init__(self) -> None:
        for path in (
            self.rtl_path,
            self.synthesis_report_path,
            self.cosimulation_report_path,
        ):
            validate_relative_path(path)
        if (
            not self.completion_marker
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.top_module) is None
            or self.maximum_latency_cycles < 1
            or self.acceptance_minimum_dsps < 1
            or not 0 <= self.rejection_maximum_dsps < self.acceptance_minimum_dsps
        ):
            raise ValueError("Vitis HLS parser bounds are invalid")

    def _metrics(self, observation: FixtureObservation) -> tuple[int, int] | None:
        if observation.exit_codes != (0,) or not _has_exact_marker(
            observation,
            self.completion_marker,
        ):
            return None
        rtl = _complete_content(
            observation,
            self.rtl_path,
            maximum_bytes=_MAX_GENERATED_RTL_BYTES,
        )
        synthesis = _complete_content(
            observation,
            self.synthesis_report_path,
            maximum_bytes=_MAX_HLS_REPORT_BYTES,
        )
        cosimulation = _complete_content(
            observation,
            self.cosimulation_report_path,
            maximum_bytes=_MAX_HLS_REPORT_BYTES,
        )
        if rtl is None or synthesis is None or cosimulation is None:
            return None
        try:
            rtl_text = rtl.decode("ascii")
            cosimulation_text = cosimulation.decode("ascii")
        except UnicodeDecodeError:
            return None
        required_rtl_tokens = (
            f"module {self.top_module} (",
            "input   ap_clk;",
            "input   ap_rst;",
            "input   ap_start;",
            "output   ap_done;",
            "output  [31:0] result;",
            "always @ (posedge ap_clk)",
        )
        if (
            any(rtl_text.count(token) < 1 for token in required_rtl_tokens)
            or rtl_text.count(f"module {self.top_module} (") != 1
            or "endmodule" not in rtl_text
        ):
            return None
        if b"<!DOCTYPE" in synthesis or b"<!ENTITY" in synthesis:
            return None
        try:
            root = ET.fromstring(synthesis)
        except ET.ParseError:
            return None
        if root.tag != "profile":
            return None
        report_top = _unique_xml_text(root, "./UserAssignments/TopModelName")
        latency_values = tuple(
            _unsigned(
                _unique_xml_text(
                    root,
                    f"./PerformanceEstimates/SummaryOfOverallLatency/{name}",
                ),
                maximum=1_000_000,
            )
            for name in ("Best-caseLatency", "Average-caseLatency", "Worst-caseLatency")
        )
        resource_values = {
            name: _unsigned(
                _unique_xml_text(root, f"./AreaEstimates/Resources/{name}"),
                maximum=100_000_000,
            )
            for name in ("BRAM_18K", "DSP", "FF", "LUT", "URAM")
        }
        if (
            report_top != self.top_module
            or any(value is None for value in latency_values)
            or any(value is None for value in resource_values.values())
        ):
            return None
        normalized_latency = tuple(value for value in latency_values if value is not None)
        normalized_resources = tuple(
            value for value in resource_values.values() if value is not None
        )
        if (
            len(set(normalized_latency)) != 1
            or normalized_latency[0] < 1
            or sum(normalized_resources) < 1
        ):
            return None
        rows = re.findall(
            r"^\|\s*Verilog\|\s*(Pass|Fail)\|\s*([0-9]+|NA)\|\s*"
            r"([0-9]+|NA)\|\s*([0-9]+|NA)\|\s*([0-9]+|NA)\|\s*"
            r"([0-9]+|NA)\|\s*([0-9]+|NA)\|\s*([0-9]+|NA)\|$",
            cosimulation_text,
            flags=re.MULTILINE,
        )
        if len(rows) != 1 or rows[0][0] != "Pass":
            return None
        cosimulation_latency = tuple(
            _unsigned(value, maximum=1_000_000) for value in rows[0][1:4]
        )
        total_cycles = _unsigned(rows[0][-1], maximum=1_000_000)
        if (
            any(value is None for value in cosimulation_latency)
            or len(set(cosimulation_latency)) != 1
            or total_cycles != cosimulation_latency[0]
            or total_cycles is None
            or total_cycles < 1
            or total_cycles > normalized_latency[0]
        ):
            return None
        dsp_count = resource_values["DSP"]
        assert dsp_count is not None
        return normalized_latency[0], dsp_count

    def accepts(self, observation: FixtureObservation) -> bool:
        metrics = self._metrics(observation)
        return metrics is not None and (
            metrics[0] <= self.maximum_latency_cycles
            and metrics[1] >= self.acceptance_minimum_dsps
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        metrics = self._metrics(observation)
        if metrics is not None and (
            metrics[0] > self.maximum_latency_cycles
            and metrics[1] <= self.rejection_maximum_dsps
        ):
            return SemanticRejectionReason.IMPLEMENTATION_CONSTRAINT_VIOLATION
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "vitis_hls_rtl_cosimulation_qor",
            "rtl_path": self.rtl_path,
            "synthesis_report_path": self.synthesis_report_path,
            "cosimulation_report_path": self.cosimulation_report_path,
            "completion_marker": self.completion_marker.decode("ascii"),
            "top_module": self.top_module,
            "maximum_latency_cycles": self.maximum_latency_cycles,
            "acceptance_minimum_dsps": self.acceptance_minimum_dsps,
            "rejection_maximum_dsps": self.rejection_maximum_dsps,
            "required_rtl_ports": (
                "ap_clk",
                "ap_rst",
                "ap_start",
                "ap_done",
                "result",
            ),
            "resource_metrics": ("BRAM_18K", "DSP", "FF", "LUT", "URAM"),
            "equivalence_result": "native_c_rtl_cosimulation_pass",
            "rejection_reason": (
                SemanticRejectionReason.IMPLEMENTATION_CONSTRAINT_VIOLATION
            ),
        }


_FIR_SOURCE = """\
#include <cstdint>

void fir16(const std::int16_t samples[16], const std::int16_t taps[16], std::int32_t *result) {
  std::int32_t accumulator = 0;
accumulate:
  for (int index = 0; index < 16; ++index) {
    accumulator += static_cast<std::int32_t>(samples[index]) * taps[index];
  }
  *result = accumulator;
}
"""

_FIR_TESTBENCH = """\
#include <cstdint>

void fir16(const std::int16_t samples[16], const std::int16_t taps[16], std::int32_t *result);

int main() {
  std::int16_t samples[16];
  std::int16_t taps[16];
  std::int32_t expected = 0;
  for (int index = 0; index < 16; ++index) {
    samples[index] = static_cast<std::int16_t>(index - 4);
    taps[index] = static_cast<std::int16_t>((index % 5) - 2);
    expected += static_cast<std::int32_t>(samples[index]) * taps[index];
  }
  std::int32_t observed = 0;
  fir16(samples, taps, &observed);
  return observed == expected ? 0 : 1;
}
"""

_VITIS_HLS_SCRIPT = """\
set control_channel [open "controls.txt" r]
set control_text [string trim [read $control_channel]]
close $control_channel
if {![regexp {^parallelism=(1|2|4|8)$} $control_text -> parallelism]} {
  error "invalid declarative control"
}

open_project -reset hls_project
set_top fir16
add_files fir.cpp
add_files -tb fir_tb.cpp
open_solution -reset solution
set_part {xc7a35tcpg236-1}
create_clock -period 10 -name default
set_directive_unroll -factor $parallelism "fir16/accumulate"
csynth_design
cosim_design -rtl verilog -tool xsim -trace_level none
puts "EDAGYM_VITIS_HLS_COMPLETE"
exit
"""

_VITIS_COMPLETION_MARKER = b"EDAGYM_VITIS_HLS_COMPLETE"
_VITIS_RTL_PATH = "hls_project/solution/syn/verilog/fir16.v"
_VITIS_SYNTHESIS_REPORT_PATH = "hls_project/solution/syn/report/fir16_csynth.xml"
_VITIS_COSIMULATION_REPORT_PATH = "hls_project/solution/sim/report/fir16_cosim.rpt"

_VITIS_COMMON_INPUTS = (
    _input("trusted_kernel", "fir.cpp", _FIR_SOURCE),
    _input("trusted_testbench", "fir_tb.cpp", _FIR_TESTBENCH),
    _input("trusted_hls_driver", "run.tcl", _VITIS_HLS_SCRIPT),
)

VITIS_HLS_SYNTHESIS = QualificationFixture(
    tool_id="vitis_hls",
    capability=Capability.HIGH_LEVEL_SYNTHESIS,
    semantic_joints=normalize_semantic_joints(
        Capability.HIGH_LEVEL_SYNTHESIS,
        (
            SemanticJoint.HLS_GENERATED_RTL,
            SemanticJoint.HLS_RTL_EQUIVALENCE,
            SemanticJoint.HLS_LATENCY,
            SemanticJoint.HLS_RESOURCE,
        ),
    ),
    inputs=(
        *_VITIS_COMMON_INPUTS,
        _input("architecture_control", "controls.txt", "parallelism=4\n"),
    ),
    rejection_inputs=(
        *_VITIS_COMMON_INPUTS,
        _input("architecture_control", "controls.txt", "parallelism=1\n"),
    ),
    rejection_reason=SemanticRejectionReason.IMPLEMENTATION_CONSTRAINT_VIOLATION,
    invocations=(ToolInvocation(("--mode", "hls", "--tcl", "run.tcl")),),
    outputs=(
        FixtureOutput("generated_rtl", _VITIS_RTL_PATH, media_type="text/x-verilog"),
        FixtureOutput(
            "synthesis_report",
            _VITIS_SYNTHESIS_REPORT_PATH,
            media_type="application/xml",
        ),
        FixtureOutput(
            "cosimulation_report",
            _VITIS_COSIMULATION_REPORT_PATH,
            media_type="text/plain",
        ),
    ),
    parser=VitisHlsParser(
        rtl_path=_VITIS_RTL_PATH,
        synthesis_report_path=_VITIS_SYNTHESIS_REPORT_PATH,
        cosimulation_report_path=_VITIS_COSIMULATION_REPORT_PATH,
        completion_marker=_VITIS_COMPLETION_MARKER,
        top_module="fir16",
        maximum_latency_cycles=16,
        acceptance_minimum_dsps=2,
        rejection_maximum_dsps=1,
    ),
    log_projection=MarkerLogProjection((_VITIS_COMPLETION_MARKER,)),
)

