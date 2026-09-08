"""Image-bound open FPGA place-and-route qualification."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

from edagym.drivers.fixtures.model import (
    FixtureInput,
    FixtureObservation,
    FixtureOutput,
    QualificationFixture,
    SemanticRejectionReason,
    ToolInvocation,
)
from edagym.drivers.semantic_claims import SemanticJoint, normalize_semantic_joints
from edagym.specs.common import Capability

_DEVICE_LC_CAPACITY = 1280
_ACCEPTANCE_FLIP_FLOPS = 8
_ACCEPTANCE_LC_USAGE = 10
_REJECTION_FLIP_FLOPS = 1290
_REJECTION_LC_USAGE = 1292
_TARGET_FREQUENCY_MHZ = 12
_MAX_LOG_BYTES = 128 * 1024
_MAX_REPORT_BYTES = 64 * 1024
_MAX_ASC_BYTES = 1024 * 1024
_NORMAL_COMPLETION = "Info: Program finished normally."
_LC_UTILIZATION = re.compile(r"(?m)^Info:\s+ICESTORM_LC:\s+([0-9]+)/\s*([0-9]+)\s+([0-9]+)%$")
_FMAX = re.compile(
    r"(?m)^Info: Max frequency for clock '[^'\r\n]+': "
    r"([0-9]+(?:\.[0-9]+)?) MHz \(PASS at 12\.00 MHz\)$"
)
_CAPACITY_FAILURE = re.compile(
    r"(?m)^ERROR: Unable to place cell 'ff_1280_DFFLC', "
    r"no BELs remaining to implement cell type 'ICESTORM_LC'$"
)


def _unique_json_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-finite JSON number")


def _observed_content(
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


def _yosys_ice40_shift_register_json(flip_flops: int) -> bytes:
    cells: dict[str, object] = {}
    for index in range(flip_flops):
        output_bit = index + 3
        input_bit: int | str = "0" if index == 0 else index + 2
        cells[f"ff_{index:04d}"] = {
            "attributes": {},
            "connections": {"C": [1], "D": [input_bit], "Q": [output_bit]},
            "hide_name": 0,
            "parameters": {},
            "port_directions": {"C": "input", "D": "input", "Q": "output"},
            "type": "SB_DFF",
        }
    document = {
        "creator": "EdaGym Yosys JSON fixture generator",
        "modules": {
            "top": {
                "attributes": {"top": "00000000000000000000000000000001"},
                "cells": cells,
                "netnames": {
                    "clk": {"attributes": {}, "bits": [1], "hide_name": 0},
                    "led": {
                        "attributes": {},
                        "bits": [flip_flops + 2],
                        "hide_name": 0,
                    },
                },
                "ports": {
                    "clk": {"bits": [1], "direction": "input"},
                    "led": {"bits": [flip_flops + 2], "direction": "output"},
                },
            }
        },
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


@dataclass(frozen=True, slots=True)
class NextpnrIce40Parser:
    log_path: str
    report_path: str
    asc_path: str

    def _log(self, observation: FixtureObservation) -> str | None:
        content = _observed_content(observation, self.log_path, _MAX_LOG_BYTES)
        if content is None:
            return None
        try:
            return content.decode("ascii")
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _utilization(log: str) -> tuple[int, int, int] | None:
        matches = _LC_UTILIZATION.findall(log)
        if len(matches) != 1:
            return None
        return tuple(int(item) for item in matches[0])  # type: ignore[return-value]

    def _acceptance_report(self, observation: FixtureObservation, log_fmax: float) -> bool:
        content = _observed_content(observation, self.report_path, _MAX_REPORT_BYTES)
        asc = _observed_content(observation, self.asc_path, _MAX_ASC_BYTES)
        if content is None or asc is None:
            return False
        if not asc.startswith(b".comment from next-pnr\n.device 1k\n"):
            return False
        try:
            report = json.loads(
                content.decode("ascii"),
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_json_mapping,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(report, dict) or set(report) != {
            "critical_paths",
            "fmax",
            "utilization",
        }:
            return False
        fmax = report.get("fmax")
        utilization = report.get("utilization")
        critical_paths = report.get("critical_paths")
        if (
            not isinstance(fmax, dict)
            or len(fmax) != 1
            or not isinstance(utilization, dict)
            or not isinstance(critical_paths, list)
            or not critical_paths
        ):
            return False
        clock = next(iter(fmax.values()))
        if not isinstance(clock, dict) or set(clock) != {"achieved", "constraint"}:
            return False
        achieved = clock.get("achieved")
        constraint = clock.get("constraint")
        if (
            isinstance(achieved, bool)
            or not isinstance(achieved, (int, float))
            or not math.isfinite(achieved)
            or not 100 <= achieved <= 1000
            or abs(achieved - log_fmax) > 0.01
            or constraint != _TARGET_FREQUENCY_MHZ
        ):
            return False
        expected_utilization = {
            "ICESTORM_LC": {"available": _DEVICE_LC_CAPACITY, "used": _ACCEPTANCE_LC_USAGE},
            "ICESTORM_PLL": {"available": 1, "used": 0},
            "ICESTORM_RAM": {"available": 16, "used": 0},
            "SB_GB": {"available": 8, "used": 1},
            "SB_IO": {"available": 112, "used": 2},
            "SB_WARMBOOT": {"available": 1, "used": 0},
        }
        return utilization == expected_utilization

    def accepts(self, observation: FixtureObservation) -> bool:
        if observation.exit_codes != (0,):
            return False
        log = self._log(observation)
        if log is None or log.count(_NORMAL_COMPLETION) != 1:
            return False
        if self._utilization(log) != (_ACCEPTANCE_LC_USAGE, _DEVICE_LC_CAPACITY, 0):
            return False
        fmax_values = tuple(float(value) for value in _FMAX.findall(log))
        return (
            len(fmax_values) == 2
            and fmax_values[0] == fmax_values[1]
            and self._acceptance_report(observation, fmax_values[0])
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        if observation.exit_codes != (255,):
            return None
        log = self._log(observation)
        if (
            log is None
            or _NORMAL_COMPLETION in log
            or self._utilization(log) != (_REJECTION_LC_USAGE, _DEVICE_LC_CAPACITY, 100)
            or len(_CAPACITY_FAILURE.findall(log)) != 1
            or _FMAX.search(log) is not None
        ):
            return None
        return SemanticRejectionReason.RESOURCE_CAPACITY_EXCEEDED

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "nextpnr_ice40_capacity",
            "parser_revision": 1,
            "device": "hx1k",
            "package": "vq100",
            "seed": 1,
            "target_frequency_mhz": _TARGET_FREQUENCY_MHZ,
            "device_lc_capacity": _DEVICE_LC_CAPACITY,
            "acceptance_lc_usage": _ACCEPTANCE_LC_USAGE,
            "rejection_lc_usage": _REJECTION_LC_USAGE,
            "log_path": self.log_path,
            "report_path": self.report_path,
            "asc_path": self.asc_path,
        }


_PCF = b"set_io clk 21\nset_io led 99\n"
_INVOCATION = ToolInvocation(
    (
        "--hx1k",
        "--package",
        "vq100",
        "--json",
        "design.json",
        "--pcf",
        "pins.pcf",
        "--asc",
        "routed.asc",
        "--report",
        "report.json",
        "--seed",
        "1",
        "--freq",
        str(_TARGET_FREQUENCY_MHZ),
        "--log",
        "nextpnr.log",
    )
)

NEXTPNR_ICE40_IMPLEMENTATION = QualificationFixture(
    tool_id="nextpnr_ice40",
    capability=Capability.FPGA_IMPLEMENTATION,
    semantic_joints=normalize_semantic_joints(
        Capability.FPGA_IMPLEMENTATION,
        (
            SemanticJoint.FPGA_IMPLEMENTATION_PLACE,
            SemanticJoint.FPGA_IMPLEMENTATION_ROUTE,
            SemanticJoint.FPGA_IMPLEMENTATION_PRE_BITSTREAM_CHECK,
            SemanticJoint.FPGA_IMPLEMENTATION_FMAX,
            SemanticJoint.FPGA_IMPLEMENTATION_UTILIZATION,
            SemanticJoint.FPGA_IMPLEMENTATION_SEED,
        ),
    ),
    inputs=(
        FixtureInput(
            logical_id="yosys_json_netlist",
            path="design.json",
            content=_yosys_ice40_shift_register_json(_ACCEPTANCE_FLIP_FLOPS),
            media_type="application/json",
        ),
        FixtureInput(logical_id="pin_constraints", path="pins.pcf", content=_PCF),
    ),
    invocations=(_INVOCATION,),
    outputs=(
        FixtureOutput(logical_id="native_log", path="nextpnr.log", media_type="text/plain"),
        FixtureOutput(
            logical_id="timing_utilization_report",
            path="report.json",
            required=False,
            media_type="application/json",
        ),
        FixtureOutput(
            logical_id="routed_bitstream_ascii",
            path="routed.asc",
            required=False,
            media_type="text/plain",
        ),
    ),
    parser=NextpnrIce40Parser(
        log_path="nextpnr.log",
        report_path="report.json",
        asc_path="routed.asc",
    ),
    rejection_inputs=(
        FixtureInput(
            logical_id="yosys_json_netlist",
            path="design.json",
            content=_yosys_ice40_shift_register_json(_REJECTION_FLIP_FLOPS),
            media_type="application/json",
        ),
        FixtureInput(logical_id="pin_constraints", path="pins.pcf", content=_PCF),
    ),
    rejection_reason=SemanticRejectionReason.RESOURCE_CAPACITY_EXCEEDED,
    rejection_exit_code=255,
)
