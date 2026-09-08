"""Comprehensive PDK-free analog and physical-verification workloads."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from struct import pack

from edagym.drivers.fixtures.model import (
    FixtureInput,
    FixtureObservation,
    FixtureOutput,
    QualificationFixture,
    SemanticRejectionReason,
    ToolInvocation,
)
from edagym.drivers.semantic_claims import semantic_contract
from edagym.specs.common import Capability

_KLAYOUT_DRC_DATABASE_PATH = "drc-results.lyrdb"
_KLAYOUT_LVS_DATABASE_PATH = "lvs-results.l2n"
_KLAYOUT_SUMMARY_PATH = "physical-verification.json"
_KLAYOUT_DRC_MEDIA_TYPE = "application/vnd.klayout.report-database+xml"
_KLAYOUT_LVS_MEDIA_TYPE = "application/vnd.klayout.layout-to-netlist"
_KLAYOUT_SUMMARY_MEDIA_TYPE = "application/vnd.edagym.physical-verification-summary+json"
_KLAYOUT_MAXIMUM_DATABASE_BYTES = 64 * 1024 * 1024
_KLAYOUT_MAXIMUM_SUMMARY_BYTES = 64 * 1024
_KLAYOUT_MINIMUM_SPACING_NM = 200
_KLAYOUT_TOP_CELL = "TOP"
_KLAYOUT_PORTS = ("IN", "OUT")
_PORT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_NET_LINE = re.compile(r"^ net\(([0-9]+) name\(([^)\r\n]{1,128})\)$", re.MULTILINE)
_PIN_LINE = re.compile(
    r"^ pin\(([0-9]+) name\(([A-Za-z_][A-Za-z0-9_]{0,63})\)\)$",
    re.MULTILINE,
)


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
        or not output.content
        or len(output.content) > maximum_bytes
    ):
        return None
    return output.content


def _unique_json_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-finite JSON number")


@dataclass(frozen=True, slots=True)
class _KlayoutPhysicalFacts:
    drc_violation_count: int
    native_lvs_matched: bool
    ports_shortened: bool
    layout_net_count: int
    layout_pin_count: int


@dataclass(frozen=True, slots=True)
class KlayoutPhysicalVerificationParser:
    """Replay bounded native KLayout DRC and LVS databases against their summary."""

    summary_path: str
    drc_database_path: str
    lvs_database_path: str
    top_cell: str
    expected_ports: tuple[str, ...]
    minimum_spacing_nm: int

    def __post_init__(self) -> None:
        if (
            self.top_cell != _KLAYOUT_TOP_CELL
            or self.expected_ports != _KLAYOUT_PORTS
            or self.minimum_spacing_nm != _KLAYOUT_MINIMUM_SPACING_NM
        ):
            raise ValueError("KLayout physical-verification contract is not canonical")

    def _facts(self, observation: FixtureObservation) -> _KlayoutPhysicalFacts | None:
        if observation.exit_codes != (0,):
            return None
        summary_content = _observed_content(
            observation,
            self.summary_path,
            _KLAYOUT_MAXIMUM_SUMMARY_BYTES,
        )
        drc_content = _observed_content(
            observation,
            self.drc_database_path,
            _KLAYOUT_MAXIMUM_DATABASE_BYTES,
        )
        lvs_content = _observed_content(
            observation,
            self.lvs_database_path,
            _KLAYOUT_MAXIMUM_DATABASE_BYTES,
        )
        if summary_content is None or drc_content is None or lvs_content is None:
            return None
        summary = self._summary(summary_content)
        drc_count = self._drc_item_count(drc_content)
        lvs_facts = self._lvs_facts(lvs_content)
        if summary is None or drc_count is None or lvs_facts is None:
            return None
        native_lvs_matched, ports_shortened, net_count, pin_count = lvs_facts
        if (
            summary["drc_violation_count"] != drc_count
            or summary["drc_database_item_count"] != drc_count
            or summary["lvs_matched"] is not native_lvs_matched
            or summary["layout_net_count"] != net_count
            or summary["layout_pin_count"] != pin_count
        ):
            return None
        return _KlayoutPhysicalFacts(
            drc_violation_count=drc_count,
            native_lvs_matched=native_lvs_matched,
            ports_shortened=ports_shortened,
            layout_net_count=net_count,
            layout_pin_count=pin_count,
        )

    def _summary(self, content: bytes) -> dict[str, object] | None:
        try:
            value = json.loads(
                content.decode("ascii"),
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_json_mapping,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return None
        expected_fields = {
            "schema_version",
            "minimum_spacing_nm",
            "drc_violation_count",
            "drc_database_item_count",
            "drc_database_nonempty",
            "lvs_compared",
            "lvs_matched",
            "layout_net_count",
            "layout_pin_count",
            "lvs_database_nonempty",
        }
        if not isinstance(value, dict) or set(value) != expected_fields:
            return None
        integer_fields = (
            "drc_violation_count",
            "drc_database_item_count",
            "layout_net_count",
            "layout_pin_count",
        )
        if (
            value["schema_version"] != 1
            or value["minimum_spacing_nm"] != self.minimum_spacing_nm
            or any(type(value[name]) is not int or value[name] < 0 for name in integer_fields)
            or value["drc_database_nonempty"] is not True
            or value["lvs_compared"] is not True
            or type(value["lvs_matched"]) is not bool
            or value["lvs_database_nonempty"] is not True
        ):
            return None
        return value

    def _drc_item_count(self, content: bytes) -> int | None:
        if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
            return None
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return None
        categories = root.findall("./categories/category")
        cells = root.findall("./cells/cell")
        items = root.findall("./items/item")
        if (
            root.tag != "report-database"
            or len(categories) != 1
            or categories[0].findtext("name") != "minimum-metal-spacing"
            or len(cells) != 1
            or cells[0].findtext("name") != self.top_cell
            or len(items) > 10_000
        ):
            return None
        for item in items:
            values = item.findall("./values/value")
            if (
                item.findtext("category") != "'minimum-metal-spacing'"
                or item.findtext("cell") != self.top_cell
                or len(values) != 1
                or values[0].text is None
                or not values[0].text.startswith("edge-pair: ")
            ):
                return None
        return len(items)

    def _lvs_facts(self, content: bytes) -> tuple[bool, bool, int, int] | None:
        try:
            report = content.decode("ascii")
        except UnicodeDecodeError:
            return None
        required_lines = (
            "#%l2n-klayout",
            f"top({self.top_cell})",
            "unit(0.001)",
            "layer(metal '1/0')",
            "layer(labels '10/0')",
            "connect(metal metal labels)",
            "connect(labels metal)",
            f"circuit({self.top_cell}",
        )
        if any(report.count(line) != 1 for line in required_lines):
            return None
        raw_nets = _NET_LINE.findall(report)
        raw_pins = _PIN_LINE.findall(report)
        if not raw_nets or not raw_pins or len(raw_nets) > 10_000 or len(raw_pins) > 1_000:
            return None
        net_names: dict[int, tuple[str, ...]] = {}
        for raw_id, raw_name in raw_nets:
            net_id = int(raw_id)
            name = (
                raw_name[1:-1] if raw_name.startswith("'") and raw_name.endswith("'") else raw_name
            )
            components = tuple(part.strip() for part in name.split(","))
            if (
                net_id in net_names
                or not components
                or any(
                    _PORT_NAME.fullmatch(component) is None and not component.startswith("$")
                    for component in components
                )
            ):
                return None
            net_names[net_id] = components
        pins: dict[str, int] = {}
        for raw_id, name in raw_pins:
            net_id = int(raw_id)
            if name in pins or net_id not in net_names:
                return None
            pins[name] = net_id
        if set(pins) != set(self.expected_ports):
            return None
        matched = all(net_names[pins[port]] == (port,) for port in self.expected_ports) and len(
            {pins[port] for port in self.expected_ports}
        ) == len(self.expected_ports)
        shortened = len({pins[port] for port in self.expected_ports}) == 1 and set(
            net_names[pins[self.expected_ports[0]]]
        ) == set(self.expected_ports)
        return matched, shortened, len(net_names), len(pins)

    def accepts(self, observation: FixtureObservation) -> bool:
        facts = self._facts(observation)
        return facts == _KlayoutPhysicalFacts(
            drc_violation_count=0,
            native_lvs_matched=True,
            ports_shortened=False,
            layout_net_count=2,
            layout_pin_count=2,
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        facts = self._facts(observation)
        if (
            facts is not None
            and facts.drc_violation_count > 0
            and not facts.native_lvs_matched
            and facts.ports_shortened
            and facts.layout_pin_count == len(self.expected_ports)
        ):
            return SemanticRejectionReason.LAYOUT_SCHEMATIC_MISMATCH
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "klayout_physical_verification",
            "summary_path": self.summary_path,
            "drc_database_path": self.drc_database_path,
            "lvs_database_path": self.lvs_database_path,
            "drc_database_media_type": _KLAYOUT_DRC_MEDIA_TYPE,
            "lvs_database_media_type": _KLAYOUT_LVS_MEDIA_TYPE,
            "summary_media_type": _KLAYOUT_SUMMARY_MEDIA_TYPE,
            "top_cell": self.top_cell,
            "expected_ports": self.expected_ports,
            "minimum_spacing_nm": self.minimum_spacing_nm,
            "maximum_database_bytes": _KLAYOUT_MAXIMUM_DATABASE_BYTES,
            "maximum_summary_bytes": _KLAYOUT_MAXIMUM_SUMMARY_BYTES,
            "rejection_reason": SemanticRejectionReason.LAYOUT_SCHEMATIC_MISMATCH,
        }


def _gds_record(record_type: int, data_type: int, payload: bytes = b"") -> bytes:
    return pack(">HBB", len(payload) + 4, record_type, data_type) + payload


def _gds_text(value: str) -> bytes:
    encoded = value.encode("ascii")
    return encoded + (b"\0" if len(encoded) % 2 else b"")


def _gds_boundary(coordinates: tuple[tuple[int, int], ...]) -> tuple[bytes, ...]:
    closed = (*coordinates, coordinates[0])
    return (
        _gds_record(0x08, 0x00),
        _gds_record(0x0D, 0x02, pack(">H", 1)),
        _gds_record(0x0E, 0x02, pack(">H", 0)),
        _gds_record(
            0x10,
            0x03,
            b"".join(pack(">ii", x, y) for x, y in closed),
        ),
        _gds_record(0x11, 0x00),
    )


def _gds_label(name: str, x: int, y: int) -> tuple[bytes, ...]:
    return (
        _gds_record(0x0C, 0x00),
        _gds_record(0x0D, 0x02, pack(">H", 10)),
        _gds_record(0x16, 0x02, pack(">H", 0)),
        _gds_record(0x10, 0x03, pack(">ii", x, y)),
        _gds_record(0x19, 0x06, _gds_text(name)),
        _gds_record(0x11, 0x00),
    )


def _physical_layout(*, rejected: bool) -> bytes:
    timestamp = pack(">12H", 2026, 9, 4, 0, 0, 0, 2026, 9, 4, 0, 0, 0)
    records = [
        _gds_record(0x00, 0x02, pack(">H", 600)),
        _gds_record(0x01, 0x02, timestamp),
        _gds_record(0x02, 0x06, _gds_text("EDAGYM")),
        _gds_record(0x03, 0x05, bytes.fromhex("3e4189374bc6a7f03944b82fa09b5a54")),
        _gds_record(0x05, 0x02, timestamp),
        _gds_record(0x06, 0x06, _gds_text(_KLAYOUT_TOP_CELL)),
    ]
    rectangles = [
        ((0, 0), (1_000, 0), (1_000, 1_000), (0, 1_000)),
        ((1_300, 0), (2_300, 0), (2_300, 1_000), (1_300, 1_000)),
    ]
    if rejected:
        rectangles.extend(
            (
                ((900, 450), (1_400, 450), (1_400, 550), (900, 550)),
                ((0, 1_150), (1_000, 1_150), (1_000, 1_300), (0, 1_300)),
            )
        )
    for rectangle in rectangles:
        records.extend(_gds_boundary(rectangle))
    records.extend(_gds_label("IN", 500, 500))
    records.extend(_gds_label("OUT", 1_800, 500))
    records.extend((_gds_record(0x07, 0x00), _gds_record(0x04, 0x00)))
    return b"".join(records)


_TWO_PORT_SCHEMATIC = b"""\
* PDK-free two-terminal connectivity reference
.subckt TOP IN OUT
.ends TOP
.end
"""


KLAYOUT_COMPREHENSIVE_PHYSICAL_VERIFICATION = QualificationFixture(
    tool_id="klayout",
    capability=Capability.PHYSICAL_VERIFICATION,
    semantic_joints=semantic_contract(Capability.PHYSICAL_VERIFICATION).required_joints,
    inputs=(
        FixtureInput(
            logical_id="layout_geometry",
            path="layout.gds",
            content=_physical_layout(rejected=False),
            media_type="application/vnd.gdsii",
        ),
        FixtureInput(
            logical_id="reference_schematic",
            path="schematic.sp",
            content=_TWO_PORT_SCHEMATIC,
            media_type="text/x-spice",
        ),
    ),
    rejection_inputs=(
        FixtureInput(
            logical_id="layout_geometry",
            path="layout.gds",
            content=_physical_layout(rejected=True),
            media_type="application/vnd.gdsii",
        ),
        FixtureInput(
            logical_id="reference_schematic",
            path="schematic.sp",
            content=_TWO_PORT_SCHEMATIC,
            media_type="text/x-spice",
        ),
    ),
    rejection_reason=SemanticRejectionReason.LAYOUT_SCHEMATIC_MISMATCH,
    invocations=(
        ToolInvocation(
            (
                "verify",
                "layout.gds",
                "schematic.sp",
                _KLAYOUT_DRC_DATABASE_PATH,
                _KLAYOUT_LVS_DATABASE_PATH,
                _KLAYOUT_SUMMARY_PATH,
            )
        ),
    ),
    outputs=(
        FixtureOutput(
            logical_id="drc_results_database",
            path=_KLAYOUT_DRC_DATABASE_PATH,
            media_type=_KLAYOUT_DRC_MEDIA_TYPE,
        ),
        FixtureOutput(
            logical_id="lvs_results_database",
            path=_KLAYOUT_LVS_DATABASE_PATH,
            media_type=_KLAYOUT_LVS_MEDIA_TYPE,
        ),
        FixtureOutput(
            logical_id="verification_summary",
            path=_KLAYOUT_SUMMARY_PATH,
            media_type=_KLAYOUT_SUMMARY_MEDIA_TYPE,
        ),
    ),
    parser=KlayoutPhysicalVerificationParser(
        summary_path=_KLAYOUT_SUMMARY_PATH,
        drc_database_path=_KLAYOUT_DRC_DATABASE_PATH,
        lvs_database_path=_KLAYOUT_LVS_DATABASE_PATH,
        top_cell=_KLAYOUT_TOP_CELL,
        expected_ports=_KLAYOUT_PORTS,
        minimum_spacing_nm=_KLAYOUT_MINIMUM_SPACING_NM,
    ),
)
