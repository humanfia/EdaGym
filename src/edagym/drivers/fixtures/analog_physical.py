"""Paired circuit and physical-verification qualification workloads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from struct import pack

from edagym.drivers.fixtures.model import (
    FixtureInput,
    FixtureObservation,
    FixtureOutput,
    MarkerLogProjection,
    QualificationFixture,
    SemanticRejectionReason,
    ToolInvocation,
)
from edagym.specs.common import Capability

_HSPICE_COMPLETION_MARKER = b"hspice job concluded"
_HSPICE_MEASURE_NAME = "divider_voltage"
_HSPICE_EXPECTED_MICROVOLTS = 500_000
_HSPICE_TOLERANCE_MICROVOLTS = 1_000
_ICV_COMPLETION_MARKER = b"IC Validator is done."
_ICV_RULE_NAME = "minimum metal spacing"
_PEGASUS_COMPLETION_MARKER = b"Pegasus finished normally."
_PEGASUS_RULE_NAME = "M1_SPACING"


@dataclass(frozen=True, slots=True)
class HspiceMeasureParser:
    """Classify one native HSPICE measurement table by a bounded numeric range."""

    output_path: str
    measure_name: str
    expected_microvolts: int
    tolerance_microvolts: int

    def __post_init__(self) -> None:
        if (
            not self.measure_name
            or self.expected_microvolts <= 0
            or self.tolerance_microvolts <= 0
            or self.tolerance_microvolts >= self.expected_microvolts
        ):
            raise ValueError("HSPICE measurement bounds must be positive and nondegenerate")

    def _measured_microvolts(self, observation: FixtureObservation) -> Decimal | None:
        if observation.exit_codes != (0,):
            return None
        output = observation.file(self.output_path)
        if output is None or output.truncated:
            return None
        try:
            lines = output.content.decode("ascii").splitlines()
        except UnicodeDecodeError:
            return None
        if not lines or not lines[0].startswith("$DATA1 SOURCE='PrimeSim HSPICE'"):
            return None
        headers = [
            index
            for index, line in enumerate(lines)
            if line.split() and line.split()[0] == self.measure_name
        ]
        if len(headers) != 1 or headers[0] + 1 >= len(lines):
            return None
        values = lines[headers[0] + 1].split()
        if not values:
            return None
        try:
            measured = Decimal(values[0])
        except InvalidOperation:
            return None
        if not measured.is_finite():
            return None
        return measured * Decimal(1_000_000)

    def accepts(self, observation: FixtureObservation) -> bool:
        measured = self._measured_microvolts(observation)
        return measured is not None and (
            abs(measured - self.expected_microvolts) <= self.tolerance_microvolts
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        measured = self._measured_microvolts(observation)
        if measured is not None and (
            abs(measured - self.expected_microvolts) > self.tolerance_microvolts
        ):
            return SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "hspice_measure",
            "output_path": self.output_path,
            "measure_name": self.measure_name,
            "expected_microvolts": self.expected_microvolts,
            "tolerance_microvolts": self.tolerance_microvolts,
            "rejection_reason": SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE,
        }


@dataclass(frozen=True, slots=True)
class IcvDrcParser:
    """Classify the exact rule counts in an IC Validator results report."""

    output_path: str
    expected_rule_count: int

    def __post_init__(self) -> None:
        if self.expected_rule_count <= 0:
            raise ValueError("IC Validator qualification requires a positive rule count")

    @staticmethod
    def _single_count(pattern: bytes, report: bytes) -> int | None:
        matches = re.findall(pattern, report, flags=re.MULTILINE)
        if len(matches) != 1:
            return None
        return int(matches[0])

    def _summary(
        self,
        observation: FixtureObservation,
    ) -> tuple[bool, int, int, int, int] | None:
        if observation.exit_codes != (0,):
            return None
        output = observation.file(self.output_path)
        if output is None or output.truncated:
            return None
        report = output.content
        clean = b"RESULTS: CLEAN" in report
        not_clean = b"RESULTS: NOT CLEAN" in report
        if clean == not_clean or _ICV_COMPLETION_MARKER not in report:
            return None
        counts = (
            self._single_count(
                rb"^([0-9]+) total rules? (?:was|were) run\.$",
                report,
            ),
            self._single_count(rb"^([0-9]+) rules? NOT EXECUTED\.$", report),
            self._single_count(
                rb"^([0-9]+) rules? (?:has|have) violations\.$",
                report,
            ),
            self._single_count(
                rb"^There (?:is|are) ([0-9]+) total violations?\.$",
                report,
            ),
        )
        if any(count is None for count in counts):
            return None
        total_rules, not_executed, violating_rules, total_violations = counts
        assert total_rules is not None
        assert not_executed is not None
        assert violating_rules is not None
        assert total_violations is not None
        return clean, total_rules, not_executed, violating_rules, total_violations

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._summary(observation) == (
            True,
            self.expected_rule_count,
            0,
            0,
            0,
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        summary = self._summary(observation)
        if (
            summary is not None
            and not summary[0]
            and summary[1] == self.expected_rule_count
            and summary[2] == 0
            and summary[3] > 0
            and summary[4] > 0
        ):
            return SemanticRejectionReason.RULE_VIOLATION
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "icv_drc",
            "output_path": self.output_path,
            "expected_rule_count": self.expected_rule_count,
            "rule_name": _ICV_RULE_NAME,
            "rejection_reason": SemanticRejectionReason.RULE_VIOLATION,
        }


@dataclass(frozen=True, slots=True)
class PegasusDrcParser:
    """Classify one Pegasus DRC summary by its exact native result counts."""

    output_path: str
    rule_name: str
    expected_geometry_count: int
    expected_rule_count: int

    def __post_init__(self) -> None:
        if not self.rule_name or self.expected_geometry_count <= 0 or self.expected_rule_count <= 0:
            raise ValueError("Pegasus DRC bounds must be positive and named")

    @staticmethod
    def _single_count(pattern: bytes, report: bytes) -> int | None:
        matches = re.findall(pattern, report, flags=re.MULTILINE)
        if len(matches) != 1:
            return None
        return int(matches[0])

    def _summary(self, observation: FixtureObservation) -> tuple[int, int, int] | None:
        if observation.exit_codes != (0,):
            return None
        output = observation.file(self.output_path)
        if output is None or output.truncated:
            return None
        report = output.content
        rule_name = re.escape(self.rule_name.encode("ascii"))
        rule_results = self._single_count(
            rb"^RULECHECK " + rule_name + rb" +\.* +Total Result +([0-9]+) +\( *[0-9]+\)$",
            report,
        )
        geometry_count = self._single_count(
            rb"^Total Original Geometry +: +([0-9]+) +\([0-9]+\)$",
            report,
        )
        rule_count = self._single_count(rb"^Total DRC RuleChecks +: +([0-9]+)$", report)
        total_results = self._single_count(
            rb"^Total DRC Results +: +([0-9]+) +\([0-9]+\)$",
            report,
        )
        if (
            rule_results is None
            or geometry_count != self.expected_geometry_count
            or rule_count != self.expected_rule_count
            or total_results is None
            or rule_results != total_results
        ):
            return None
        return geometry_count, rule_count, total_results

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._summary(observation) == (
            self.expected_geometry_count,
            self.expected_rule_count,
            0,
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        summary = self._summary(observation)
        if summary is not None and summary[2] > 0:
            return SemanticRejectionReason.RULE_VIOLATION
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "pegasus_drc",
            "output_path": self.output_path,
            "rule_name": self.rule_name,
            "expected_geometry_count": self.expected_geometry_count,
            "expected_rule_count": self.expected_rule_count,
            "rejection_reason": SemanticRejectionReason.RULE_VIOLATION,
        }


def _hspice_netlist(top_resistance: str) -> bytes:
    return f"""\
* EdaGym HSPICE divider qualification
Vsource vin 0 0
Rtop vin out {top_resistance}
Rbottom out 0 1k
.dc Vsource 0 1 1
.measure dc {_HSPICE_MEASURE_NAME} find v(out) at=1
.end
""".encode("ascii")


HSPICE_CIRCUIT_SIMULATION = QualificationFixture(
    tool_id="hspice",
    capability=Capability.CIRCUIT_SIMULATION,
    inputs=(
        FixtureInput(
            logical_id="circuit_netlist",
            path="divider.sp",
            content=_hspice_netlist("1k"),
        ),
    ),
    rejection_inputs=(
        FixtureInput(
            logical_id="circuit_netlist",
            path="divider.sp",
            content=_hspice_netlist("2k"),
        ),
    ),
    rejection_reason=SemanticRejectionReason.ANALOG_VALUE_OUT_OF_RANGE,
    invocations=(ToolInvocation(("divider.sp", "-o", "divider")),),
    outputs=(
        FixtureOutput(
            logical_id="measurement_table",
            path="divider.ms0",
            media_type="text/plain",
        ),
    ),
    parser=HspiceMeasureParser(
        output_path="divider.ms0",
        measure_name=_HSPICE_MEASURE_NAME,
        expected_microvolts=_HSPICE_EXPECTED_MICROVOLTS,
        tolerance_microvolts=_HSPICE_TOLERANCE_MICROVOLTS,
    ),
    log_projection=MarkerLogProjection((_HSPICE_COMPLETION_MARKER,)),
)


def _gds_record(record_type: int, data_type: int, payload: bytes = b"") -> bytes:
    return pack(">HBB", len(payload) + 4, record_type, data_type) + payload


def _gds_text(value: str) -> bytes:
    encoded = value.encode("ascii")
    return encoded + (b"\0" if len(encoded) % 2 else b"")


def _gds_rectangle_pair(second_x_nm: int) -> bytes:
    timestamp = pack(">12H", 2026, 9, 4, 0, 0, 0, 2026, 9, 4, 0, 0, 0)
    records = [
        _gds_record(0x00, 0x02, pack(">H", 600)),
        _gds_record(0x01, 0x02, timestamp),
        _gds_record(0x02, 0x06, _gds_text("EDAGYM")),
        _gds_record(
            0x03,
            0x05,
            bytes.fromhex("3e4189374bc6a7f03944b82fa09b5a54"),
        ),
        _gds_record(0x05, 0x02, timestamp),
        _gds_record(0x06, 0x06, _gds_text("TOP")),
    ]
    for x1, x2 in ((0, 1_000), (second_x_nm, second_x_nm + 1_000)):
        coordinates = ((x1, 0), (x1, 1_000), (x2, 1_000), (x2, 0), (x1, 0))
        records.extend(
            (
                _gds_record(0x08, 0x00),
                _gds_record(0x0D, 0x02, pack(">H", 1)),
                _gds_record(0x0E, 0x02, pack(">H", 0)),
                _gds_record(
                    0x10,
                    0x03,
                    b"".join(pack(">ii", x, y) for x, y in coordinates),
                ),
                _gds_record(0x11, 0x00),
            )
        )
    records.extend((_gds_record(0x07, 0x00), _gds_record(0x04, 0x00)))
    return b"".join(records)


_ICV_RUNSET = b"""\
#include <icv.rh>

library(
  cell = "TOP",
  format = GDSII,
  library_name = "layout.gds"
);

metal1 = assign({{1, 0}});

metal_spacing @= { @ "minimum metal spacing";
  external1(
    metal1,
    distance < 0.2,
    extension = RADIAL,
    name = "M1.SPACE"
  );
};
"""

ICV_PHYSICAL_VERIFICATION = QualificationFixture(
    tool_id="ic_validator",
    capability=Capability.PHYSICAL_VERIFICATION,
    inputs=(
        FixtureInput(
            logical_id="layout_geometry",
            path="layout.gds",
            content=_gds_rectangle_pair(1_300),
            media_type="application/vnd.gdsii",
        ),
        FixtureInput(
            logical_id="drc_runset",
            path="spacing.rs",
            content=_ICV_RUNSET,
        ),
    ),
    rejection_inputs=(
        FixtureInput(
            logical_id="layout_geometry",
            path="layout.gds",
            content=_gds_rectangle_pair(1_100),
            media_type="application/vnd.gdsii",
        ),
        FixtureInput(
            logical_id="drc_runset",
            path="spacing.rs",
            content=_ICV_RUNSET,
        ),
    ),
    rejection_reason=SemanticRejectionReason.RULE_VIOLATION,
    invocations=(ToolInvocation(("spacing.rs",)),),
    outputs=(
        FixtureOutput(
            logical_id="drc_results",
            path="TOP.RESULTS",
            media_type="text/plain",
        ),
    ),
    parser=IcvDrcParser(output_path="TOP.RESULTS", expected_rule_count=1),
    log_projection=MarkerLogProjection((_ICV_COMPLETION_MARKER,)),
)


_PEGASUS_RUNSET = b"""\
layout_primary "TOP";
layout_path "layout.gds";
layout_format GDSII;
results_db -drc DRC.db -ascii;
report_summary -drc DRC.rep;
keep_empty -drc NO;
max_results -drc -all;

layer_def METAL1 10001;
layer_map 1 -datatype 0 10001;

rule M1_SPACING {
  caption minimum metal spacing;
  exte METAL1 METAL1 -lt 0.2 -abut lt 90 -single_point -output region;
}
"""

PEGASUS_PHYSICAL_VERIFICATION = QualificationFixture(
    tool_id="pegasus",
    capability=Capability.PHYSICAL_VERIFICATION,
    inputs=(
        FixtureInput(
            logical_id="layout_geometry",
            path="layout.gds",
            content=_gds_rectangle_pair(1_300),
            media_type="application/vnd.gdsii",
        ),
        FixtureInput(
            logical_id="drc_runset",
            path="spacing.pvl",
            content=_PEGASUS_RUNSET,
        ),
    ),
    rejection_inputs=(
        FixtureInput(
            logical_id="layout_geometry",
            path="layout.gds",
            content=_gds_rectangle_pair(1_100),
            media_type="application/vnd.gdsii",
        ),
        FixtureInput(
            logical_id="drc_runset",
            path="spacing.pvl",
            content=_PEGASUS_RUNSET,
        ),
    ),
    rejection_reason=SemanticRejectionReason.RULE_VIOLATION,
    invocations=(
        ToolInvocation(
            (
                "-drc",
                "-gds",
                "layout.gds",
                "-top_cell",
                "TOP",
                "-run_dir",
                "run",
                "-tmp_dirs",
                ".",
                "spacing.pvl",
            )
        ),
    ),
    outputs=(
        FixtureOutput(
            logical_id="drc_summary",
            path="run/DRC.rep",
            media_type="text/plain",
        ),
    ),
    parser=PegasusDrcParser(
        output_path="run/DRC.rep",
        rule_name=_PEGASUS_RULE_NAME,
        expected_geometry_count=2,
        expected_rule_count=1,
    ),
    log_projection=MarkerLogProjection((_PEGASUS_COMPLETION_MARKER,)),
)
