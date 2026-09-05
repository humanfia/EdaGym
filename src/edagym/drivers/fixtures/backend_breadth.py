"""Paired qualification workloads for backend capability breadth."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from itertools import pairwise

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
from edagym.fixtures.modus_dft import (
    MODUS_DFT_COMPLETION_MARKER,
    MODUS_DFT_REPORT_PATH,
    MODUS_DFT_SCRIPT,
    MODUS_PIN_ASSIGNMENTS,
    modus_scan_design,
)
from edagym.specs.common import Capability

_OPENROAD_POWER_MARKER = b"EDAGYM_OPENROAD_POWER_COMPLETE"
_OPENROAD_EXTRACTION_MARKER = b"EDAGYM_OPENROAD_EXTRACTION_COMPLETE"
_NGSPICE_CHARACTERIZATION_MARKER = b"EDAGYM_NGSPICE_CHARACTERIZATION_COMPLETE"
_SPEF_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$/\[\]:-]*$")
_DECIMAL_TOKEN = re.compile(r"^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,4})?$")
_OPENROAD_SPEF_DATE = re.compile(
    r'^\*DATE "[0-9]{2}:[0-9]{2}:[0-9]{2} [A-Za-z]{3} '
    r'[0-9]{2} [A-Za-z0-9]{2,3}, [0-9]{4}"$'
)
_POWER_ARITHMETIC_TOLERANCE_PICOWATTS = Decimal(1)
_OPENROAD_SPEF_FIXED_HEADER = (
    '*SPEF "ieee 1481-1999"',
    '*DESIGN "top"',
    '*VENDOR "The OpenROAD Project"',
    '*PROGRAM "OpenROAD"',
    '*VERSION "1.0"',
    '*DESIGN_FLOW "NAME_SCOPE LOCAL" "PIN_CAP NONE"',
    "*DIVIDER /",
    "*DELIMITER :",
    "*BUS_DELIMITER []",
    "*T_UNIT 1 NS",
    "*C_UNIT 1 PF",
    "*R_UNIT 1 OHM",
    "*L_UNIT 1 HENRY",
)
_OPENROAD_POWER_CATEGORIES = (
    "Sequential",
    "Combinational",
    "Clock",
    "Macro",
    "Pad",
)
_OPENROAD_POWER_FIELDS = ("internal", "switching", "leakage", "total")


def _has_marker(observation: FixtureObservation, marker: bytes) -> bool:
    return marker in {
        line.strip()
        for stream in (*observation.stdout, *observation.stderr)
        for line in stream.splitlines()
    }


def _observed_content(observation: FixtureObservation, path: str) -> bytes | None:
    output = observation.file(path)
    if output is None or output.truncated or output.size_bytes != len(output.content):
        return None
    return output.content


def _decimal(value: object) -> Decimal | None:
    if not isinstance(value, Decimal) or not value.is_finite():
        return None
    return value


def _bounded_decimal(
    value: str,
    *,
    minimum: Decimal,
    maximum: Decimal,
) -> Decimal | None:
    if len(value) > 96 or _DECIMAL_TOKEN.fullmatch(value) is None:
        return None
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None
    return parsed if minimum <= parsed <= maximum else None


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-finite JSON number")


def _unique_json_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


@dataclass(frozen=True, slots=True)
class OpenroadPowerParser:
    """Validate the bounded total-power field in an OpenROAD JSON report."""

    output_path: str
    activity_report_path: str
    required_annotated_input_ports: tuple[str, ...]
    minimum_dynamic_picowatts: int
    minimum_leakage_picowatts: int
    minimum_total_picowatts: int
    maximum_total_picowatts: int

    def __post_init__(self) -> None:
        if (
            not self.required_annotated_input_ports
            or len(self.required_annotated_input_ports)
            != len(set(self.required_annotated_input_ports))
            or any(
                _SPEF_IDENTIFIER.fullmatch(item) is None
                for item in self.required_annotated_input_ports
            )
            or self.minimum_dynamic_picowatts <= 0
            or self.minimum_leakage_picowatts <= 0
            or self.minimum_total_picowatts <= 0
            or self.maximum_total_picowatts <= self.minimum_total_picowatts
        ):
            raise ValueError("OpenROAD power bounds must be positive and nondegenerate")

    def _powers_picowatts(
        self,
        observation: FixtureObservation,
    ) -> tuple[Decimal, Decimal, Decimal] | None:
        if observation.exit_codes != (0,) or not _has_marker(observation, _OPENROAD_POWER_MARKER):
            return None
        content = _observed_content(observation, self.output_path)
        activity_content = _observed_content(observation, self.activity_report_path)
        if content is None or activity_content is None:
            return None
        if not self._activity_coverage_is_complete(activity_content):
            return None
        try:
            document = json.loads(
                content.decode("ascii"),
                parse_float=Decimal,
                parse_int=Decimal,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_json_mapping,
            )
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(document, dict) or set(document) != {
            *_OPENROAD_POWER_CATEGORIES,
            "Total",
        }:
            return None
        maximum_watts = Decimal(self.maximum_total_picowatts) / Decimal(1_000_000_000_000)
        parsed: dict[str, tuple[Decimal, ...]] = {}
        for category in (*_OPENROAD_POWER_CATEGORIES, "Total"):
            fields = document.get(category)
            if not isinstance(fields, dict) or set(fields) != set(_OPENROAD_POWER_FIELDS):
                return None
            values = tuple(_decimal(fields.get(name)) for name in _OPENROAD_POWER_FIELDS)
            if any(value is None or value < 0 or value > maximum_watts for value in values):
                return None
            normalized = tuple(value for value in values if value is not None)
            if (
                abs(sum(normalized[:3]) - normalized[3]) * Decimal(1_000_000_000_000)
                > _POWER_ARITHMETIC_TOLERANCE_PICOWATTS
            ):
                return None
            parsed[category] = normalized
        total_values = parsed["Total"]
        for field_index in range(len(_OPENROAD_POWER_FIELDS)):
            if (
                abs(
                    sum(parsed[category][field_index] for category in _OPENROAD_POWER_CATEGORIES)
                    - total_values[field_index]
                )
                * Decimal(1_000_000_000_000)
                > _POWER_ARITHMETIC_TOLERANCE_PICOWATTS
            ):
                return None
        dynamic = (total_values[0] + total_values[1]) * Decimal(1_000_000_000_000)
        leakage = total_values[2] * Decimal(1_000_000_000_000)
        total_power = total_values[3] * Decimal(1_000_000_000_000)
        return dynamic, leakage, total_power

    def _activity_coverage_is_complete(self, content: bytes) -> bool:
        try:
            lines = tuple(line.rstrip() for line in content.decode("ascii").splitlines())
        except UnicodeDecodeError:
            return False
        input_counts = [
            int(match.group(1))
            for line in lines
            if (match := re.fullmatch(r"input\s+([0-9]+)", line)) is not None
        ]
        try:
            annotated_start = lines.index("Annotated pins:") + 1
            annotated_end = lines.index("Unannotated pins:", annotated_start)
        except ValueError:
            return False
        annotated = {
            line.strip().removeprefix("user ")
            for line in lines[annotated_start:annotated_end]
            if line.strip().startswith("user ")
        }
        return input_counts == [len(self.required_annotated_input_ports)] and annotated == set(
            self.required_annotated_input_ports
        )

    def accepts(self, observation: FixtureObservation) -> bool:
        measured = self._powers_picowatts(observation)
        return measured is not None and (
            self.minimum_dynamic_picowatts <= measured[0]
            and self.minimum_leakage_picowatts <= measured[1]
            and self.minimum_total_picowatts <= measured[2] <= self.maximum_total_picowatts
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        measured = self._powers_picowatts(observation)
        if measured is not None and all(value == 0 for value in measured):
            return SemanticRejectionReason.DEGENERATE_IMPLEMENTATION
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "openroad_power_json_v3",
            "output_path": self.output_path,
            "activity_report_path": self.activity_report_path,
            "completion_marker": _OPENROAD_POWER_MARKER.decode("ascii"),
            "required_annotated_input_ports": self.required_annotated_input_ports,
            "metric_ids": ("dynamic_power", "leakage_power", "total_power"),
            "unit": "watt",
            "scale": "picowatt",
            "minimum_dynamic_picowatts": self.minimum_dynamic_picowatts,
            "minimum_leakage_picowatts": self.minimum_leakage_picowatts,
            "minimum_total_picowatts": self.minimum_total_picowatts,
            "maximum_total_picowatts": self.maximum_total_picowatts,
            "arithmetic_tolerance_picowatts": _POWER_ARITHMETIC_TOLERANCE_PICOWATTS,
            "zero_rejection_reason": SemanticRejectionReason.DEGENERATE_IMPLEMENTATION,
        }


@dataclass(frozen=True, slots=True)
class OpenroadPowerIntegrityParser:
    """Validate a connected routed grid and bounded native IR-drop samples."""

    voltage_report_path: str
    routed_grid_path: str
    power_net: str
    routing_layer: str
    expected_instances: tuple[str, ...]
    supply_microvolts: int
    maximum_accepted_drop_microvolts: int
    minimum_rejected_drop_microvolts: int

    def __post_init__(self) -> None:
        if (
            _SPEF_IDENTIFIER.fullmatch(self.power_net) is None
            or _SPEF_IDENTIFIER.fullmatch(self.routing_layer) is None
            or not self.expected_instances
            or len(self.expected_instances) != len(set(self.expected_instances))
            or any(_SPEF_IDENTIFIER.fullmatch(item) is None for item in self.expected_instances)
            or self.supply_microvolts <= 0
            or not 0
            < self.maximum_accepted_drop_microvolts
            < self.minimum_rejected_drop_microvolts
            < self.supply_microvolts
        ):
            raise ValueError("OpenROAD power-grid parser contract is invalid")

    def _worst_drop_microvolts(
        self,
        observation: FixtureObservation,
    ) -> Decimal | None:
        if observation.exit_codes != (0,):
            return None
        grid_content = _observed_content(observation, self.routed_grid_path)
        voltage_content = _observed_content(observation, self.voltage_report_path)
        if grid_content is None or voltage_content is None:
            return None
        try:
            grid = " ".join(grid_content.decode("ascii").split())
            voltage_lines = voltage_content.decode("ascii").splitlines()
        except UnicodeDecodeError:
            return None
        if (
            "DESIGN top ;" not in grid
            or "SPECIALNETS 2 ;" not in grid
            or f"- {self.power_net} ( * {self.power_net} ) + USE POWER" not in grid
            or f"+ ROUTED {self.routing_layer} " not in grid
            or "END SPECIALNETS" not in grid
            or any(
                f"- {instance} LOAD + PLACED" not in grid
                for instance in self.expected_instances
            )
        ):
            return None
        if not voltage_lines or voltage_lines[0] != (
            "Instance,Terminal,Layer,X location,Y location,Voltage"
        ):
            return None
        supply_volts = Decimal(self.supply_microvolts) / Decimal(1_000_000)
        voltages: dict[str, Decimal] = {}
        for line in voltage_lines[1:]:
            fields = line.split(",")
            if len(fields) != 6:
                return None
            instance, terminal, layer, x_location, y_location, voltage = fields
            if (
                instance in voltages
                or terminal != self.power_net
                or layer != self.routing_layer
                or instance not in self.expected_instances
                or _bounded_decimal(
                    x_location,
                    minimum=Decimal(0),
                    maximum=Decimal(1_000_000),
                )
                is None
                or _bounded_decimal(
                    y_location,
                    minimum=Decimal(0),
                    maximum=Decimal(1_000_000),
                )
                is None
            ):
                return None
            measured = _bounded_decimal(
                voltage,
                minimum=Decimal(0),
                maximum=supply_volts,
            )
            if measured is None:
                return None
            voltages[instance] = measured
        if set(voltages) != set(self.expected_instances):
            return None
        source_drop = supply_volts - max(voltages.values())
        if source_drop * Decimal(1_000_000) > Decimal(100):
            return None
        return (supply_volts - min(voltages.values())) * Decimal(1_000_000)

    def accepts(self, observation: FixtureObservation) -> bool:
        worst_drop = self._worst_drop_microvolts(observation)
        return worst_drop is not None and (
            worst_drop <= self.maximum_accepted_drop_microvolts
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        worst_drop = self._worst_drop_microvolts(observation)
        if worst_drop is not None and worst_drop >= self.minimum_rejected_drop_microvolts:
            return SemanticRejectionReason.POWER_GRID_VIOLATION
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "openroad_pdnsim_ir_drop_v1",
            "voltage_report_path": self.voltage_report_path,
            "routed_grid_path": self.routed_grid_path,
            "power_net": self.power_net,
            "routing_layer": self.routing_layer,
            "expected_instances": self.expected_instances,
            "supply_microvolts": self.supply_microvolts,
            "maximum_accepted_drop_microvolts": (
                self.maximum_accepted_drop_microvolts
            ),
            "minimum_rejected_drop_microvolts": (
                self.minimum_rejected_drop_microvolts
            ),
            "rejection_reason": SemanticRejectionReason.POWER_GRID_VIOLATION,
        }


@dataclass(frozen=True, slots=True)
class _SpefNet:
    total_capacitance_attofarads: Decimal
    maximum_segment_resistance_microohms: Decimal


@dataclass(frozen=True, slots=True)
class OpenroadSpefParser:
    """Validate bounded capacitance and resistance for one extracted SPEF net."""

    output_path: str
    required_net: str
    minimum_capacitance_attofarads: int
    maximum_capacitance_attofarads: int
    minimum_resistance_microohms: int
    maximum_resistance_microohms: int

    def __post_init__(self) -> None:
        if _SPEF_IDENTIFIER.fullmatch(self.required_net) is None:
            raise ValueError("required SPEF net must be a bounded identifier")
        if (
            self.minimum_capacitance_attofarads <= 0
            or self.maximum_capacitance_attofarads <= self.minimum_capacitance_attofarads
            or self.minimum_resistance_microohms <= 0
            or self.maximum_resistance_microohms <= self.minimum_resistance_microohms
        ):
            raise ValueError("SPEF metric bounds must be positive and nondegenerate")

    def _nets(self, observation: FixtureObservation) -> dict[str, _SpefNet] | None:
        if observation.exit_codes != (0,) or not _has_marker(
            observation, _OPENROAD_EXTRACTION_MARKER
        ):
            return None
        content = _observed_content(observation, self.output_path)
        if content is None:
            return None
        try:
            lines = tuple(
                line.strip() for line in content.decode("ascii").splitlines() if line.strip()
            )
        except UnicodeDecodeError:
            return None
        if len(lines) < 20 or lines[0:2] != _OPENROAD_SPEF_FIXED_HEADER[0:2]:
            return None
        if _OPENROAD_SPEF_DATE.fullmatch(lines[2]) is None:
            return None
        if lines[3:14] != _OPENROAD_SPEF_FIXED_HEADER[2:] or lines[14] != "*PORTS":
            return None

        ports: dict[str, str] = {}
        index = 15
        while index < len(lines) and not lines[index].startswith("*D_NET "):
            fields = lines[index].split()
            if (
                len(fields) != 2
                or _SPEF_IDENTIFIER.fullmatch(fields[0]) is None
                or fields[1] not in {"I", "O", "B"}
                or fields[0] in ports
            ):
                return None
            ports[fields[0]] = fields[1]
            index += 1
        if not ports:
            return None

        maximum_capacitance_picofarads = Decimal(self.maximum_capacitance_attofarads) / Decimal(
            1_000_000
        )
        maximum_resistance_ohms = Decimal(self.maximum_resistance_microohms) / Decimal(1_000_000)
        nets: dict[str, _SpefNet] = {}
        while index < len(lines):
            fields = lines[index].split()
            if (
                len(fields) != 3
                or fields[0] != "*D_NET"
                or _SPEF_IDENTIFIER.fullmatch(fields[1]) is None
                or fields[1] in nets
            ):
                return None
            total_capacitance = _bounded_decimal(
                fields[2],
                minimum=Decimal(0),
                maximum=maximum_capacitance_picofarads,
            )
            if total_capacitance is None:
                return None

            index += 1
            section: str | None = None
            connections: set[str] = set()
            capacitance_nodes: set[str] = set()
            entry_ids: set[int] = set()
            capacitances: list[Decimal] = []
            resistances: list[Decimal] = []
            while index < len(lines) and lines[index] != "*END":
                line = lines[index]
                if line == "*CONN" and section is None:
                    section = "connection"
                elif line == "*CAP" and section == "connection" and connections:
                    section = "capacitance"
                    entry_ids.clear()
                elif line == "*RES" and section == "capacitance" and capacitances:
                    section = "resistance"
                    entry_ids.clear()
                elif line.startswith("*"):
                    values = line.split()
                    if (
                        section != "connection"
                        or values[0] not in {"*I", "*P"}
                        or len(values) not in {3, 5}
                        or _SPEF_IDENTIFIER.fullmatch(values[1]) is None
                        or values[2] not in {"I", "O", "B"}
                    ):
                        return None
                    if values[0] == "*P":
                        if len(values) != 3 or ports.get(values[1]) != values[2]:
                            return None
                    else:
                        if (
                            len(values) != 5
                            or values[3] != "*D"
                            or _SPEF_IDENTIFIER.fullmatch(values[4]) is None
                        ):
                            return None
                    if values[1] in connections:
                        return None
                    connections.add(values[1])
                elif section == "capacitance":
                    values = line.split()
                    if (
                        len(values) != 3
                        or not values[0].isdigit()
                        or int(values[0]) in entry_ids
                        or _SPEF_IDENTIFIER.fullmatch(values[1]) is None
                        or not values[1].startswith(f"{fields[1]}:")
                    ):
                        return None
                    measured = _bounded_decimal(
                        values[2],
                        minimum=Decimal(0),
                        maximum=maximum_capacitance_picofarads,
                    )
                    if measured is None:
                        return None
                    entry_ids.add(int(values[0]))
                    capacitance_nodes.add(values[1])
                    capacitances.append(measured)
                elif section == "resistance":
                    values = line.split()
                    allowed_nodes = connections | capacitance_nodes
                    if (
                        len(values) != 4
                        or not values[0].isdigit()
                        or int(values[0]) in entry_ids
                        or values[1] not in allowed_nodes
                        or values[2] not in allowed_nodes
                    ):
                        return None
                    measured = _bounded_decimal(
                        values[3],
                        minimum=Decimal(0),
                        maximum=maximum_resistance_ohms,
                    )
                    if measured is None:
                        return None
                    entry_ids.add(int(values[0]))
                    resistances.append(measured)
                else:
                    return None
                index += 1
            if (
                index >= len(lines)
                or section != "resistance"
                or not connections
                or not capacitances
                or not resistances
                or not any(value > 0 for value in capacitances)
                or not any(value > 0 for value in resistances)
            ):
                return None
            if abs(sum(capacitances) - total_capacitance) > Decimal("1e-12"):
                return None
            nets[fields[1]] = _SpefNet(
                total_capacitance_attofarads=total_capacitance * Decimal(1_000_000),
                maximum_segment_resistance_microohms=max(resistances) * Decimal(1_000_000),
            )
            index += 1
        return nets or None

    def accepts(self, observation: FixtureObservation) -> bool:
        nets = self._nets(observation)
        measured = nets.get(self.required_net) if nets is not None else None
        return measured is not None and (
            self.minimum_capacitance_attofarads
            <= measured.total_capacitance_attofarads
            <= self.maximum_capacitance_attofarads
            and self.minimum_resistance_microohms
            <= measured.maximum_segment_resistance_microohms
            <= self.maximum_resistance_microohms
        )

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        nets = self._nets(observation)
        if nets is not None and self.required_net not in nets:
            return SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "openroad_placement_spef_v2",
            "output_path": self.output_path,
            "completion_marker": _OPENROAD_EXTRACTION_MARKER.decode("ascii"),
            "required_net": self.required_net,
            "metrics": (
                {
                    "metric_id": "net_total_capacitance",
                    "unit": "attofarad",
                    "minimum": self.minimum_capacitance_attofarads,
                    "maximum": self.maximum_capacitance_attofarads,
                },
                {
                    "metric_id": "maximum_segment_resistance",
                    "unit": "microohm",
                    "minimum": self.minimum_resistance_microohms,
                    "maximum": self.maximum_resistance_microohms,
                },
            ),
            "missing_net_rejection_reason": (SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE),
        }


@dataclass(frozen=True, slots=True)
class _WaveformSample:
    time_picoseconds: Decimal
    input_voltage: Decimal
    output_voltage: Decimal


@dataclass(frozen=True, slots=True)
class NgspiceCharacterizationParser:
    """Characterize an inverter from bounded native transient-waveform samples."""

    output_path: str
    low_sample_picoseconds: int
    high_sample_picoseconds: int
    logic_low_millivolts: int
    logic_high_millivolts: int
    minimum_delay_picoseconds: int
    maximum_delay_picoseconds: int
    evaluation_end_picoseconds: int
    maximum_time_picoseconds: int
    maximum_samples: int

    def __post_init__(self) -> None:
        if (
            self.low_sample_picoseconds <= 0
            or self.high_sample_picoseconds <= self.low_sample_picoseconds
            or self.logic_low_millivolts < 0
            or self.logic_high_millivolts <= self.logic_low_millivolts
            or self.logic_high_millivolts > 1_000
            or self.minimum_delay_picoseconds <= 0
            or self.maximum_delay_picoseconds <= self.minimum_delay_picoseconds
            or self.evaluation_end_picoseconds <= self.high_sample_picoseconds
            or self.maximum_time_picoseconds <= self.evaluation_end_picoseconds
            or self.maximum_samples < 32
            or self.maximum_samples > 100_000
        ):
            raise ValueError("cell-characterization bounds must be ordered and nondegenerate")

    def _samples(self, observation: FixtureObservation) -> tuple[_WaveformSample, ...] | None:
        if observation.exit_codes != (0,) or not _has_marker(
            observation, _NGSPICE_CHARACTERIZATION_MARKER
        ):
            return None
        content = _observed_content(observation, self.output_path)
        if content is None:
            return None
        try:
            lines = content.decode("ascii").splitlines()
        except UnicodeDecodeError:
            return None
        if not lines or tuple(lines[0].split()) != ("time", "v(in)", "v(out)"):
            return None
        if len(lines) - 1 > self.maximum_samples:
            return None
        samples: list[_WaveformSample] = []
        maximum_time_seconds = Decimal(self.maximum_time_picoseconds) / Decimal(1_000_000_000_000)
        for line in lines[1:]:
            fields = line.split()
            if len(fields) != 3:
                return None
            time = _bounded_decimal(fields[0], minimum=Decimal(0), maximum=maximum_time_seconds)
            input_voltage = _bounded_decimal(
                fields[1], minimum=Decimal("-0.1"), maximum=Decimal("1.1")
            )
            output_voltage = _bounded_decimal(
                fields[2], minimum=Decimal("-0.1"), maximum=Decimal("1.1")
            )
            if time is None or input_voltage is None or output_voltage is None:
                return None
            time_picoseconds = time * Decimal(1_000_000_000_000)
            if samples and time_picoseconds <= samples[-1].time_picoseconds:
                return None
            samples.append(
                _WaveformSample(
                    time_picoseconds=time_picoseconds,
                    input_voltage=input_voltage,
                    output_voltage=output_voltage,
                )
            )
        if (
            len(samples) < 32
            or samples[0].time_picoseconds != 0
            or samples[-1].time_picoseconds < self.evaluation_end_picoseconds
        ):
            return None
        return tuple(samples)

    @staticmethod
    def _crossings(
        samples: tuple[_WaveformSample, ...],
        *,
        output: bool,
        end_picoseconds: Decimal,
    ) -> tuple[tuple[Decimal, bool], ...]:
        threshold = Decimal("0.5")
        crossings: list[tuple[Decimal, bool]] = []
        for left, right in pairwise(samples):
            if left.time_picoseconds < Decimal(900):
                continue
            if left.time_picoseconds >= end_picoseconds:
                break
            left_value = left.output_voltage if output else left.input_voltage
            right_value = right.output_voltage if output else right.input_voltage
            rising = left_value < threshold <= right_value
            falling = left_value > threshold >= right_value
            if (not rising and not falling) or right_value == left_value:
                continue
            fraction = (threshold - left_value) / (right_value - left_value)
            crossing = left.time_picoseconds + fraction * (
                right.time_picoseconds - left.time_picoseconds
            )
            if crossing <= end_picoseconds:
                crossings.append((crossing, rising))
        return tuple(crossings)

    def _has_stable_levels(
        self,
        samples: tuple[_WaveformSample, ...],
        *,
        inverted: bool,
    ) -> bool:
        low_threshold = Decimal(self.logic_low_millivolts) / Decimal(1_000)
        high_threshold = Decimal(self.logic_high_millivolts) / Decimal(1_000)
        early = tuple(
            sample for sample in samples if sample.time_picoseconds <= self.low_sample_picoseconds
        )
        late = tuple(
            sample
            for sample in samples
            if self.high_sample_picoseconds
            <= sample.time_picoseconds
            <= self.evaluation_end_picoseconds
        )
        if len(early) < 2 or len(late) < 2:
            return False
        if inverted:
            return all(
                sample.input_voltage <= low_threshold and sample.output_voltage >= high_threshold
                for sample in early
            ) and all(
                sample.input_voltage >= high_threshold and sample.output_voltage <= low_threshold
                for sample in late
            )
        return all(
            sample.input_voltage <= low_threshold and sample.output_voltage <= low_threshold
            for sample in early
        ) and all(
            sample.input_voltage >= high_threshold and sample.output_voltage >= high_threshold
            for sample in late
        )

    def accepts(self, observation: FixtureObservation) -> bool:
        samples = self._samples(observation)
        if samples is None:
            return False
        end = Decimal(self.evaluation_end_picoseconds)
        input_crossings = self._crossings(samples, output=False, end_picoseconds=end)
        output_crossings = self._crossings(samples, output=True, end_picoseconds=end)
        if (
            len(input_crossings) != 1
            or not input_crossings[0][1]
            or len(output_crossings) != 1
            or output_crossings[0][1]
            or not self._has_stable_levels(samples, inverted=True)
        ):
            return False
        delay = output_crossings[0][0] - input_crossings[0][0]
        return self.minimum_delay_picoseconds <= delay <= self.maximum_delay_picoseconds

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        samples = self._samples(observation)
        if samples is None:
            return None
        end = Decimal(self.evaluation_end_picoseconds)
        input_crossings = self._crossings(samples, output=False, end_picoseconds=end)
        output_crossings = self._crossings(samples, output=True, end_picoseconds=end)
        if (
            len(input_crossings) == 1
            and input_crossings[0][1]
            and len(output_crossings) == 1
            and output_crossings[0][1]
            and self._has_stable_levels(samples, inverted=False)
        ):
            return SemanticRejectionReason.FUNCTIONAL_MISMATCH
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "ngspice_inverter_characterization_v2",
            "output_path": self.output_path,
            "completion_marker": _NGSPICE_CHARACTERIZATION_MARKER.decode("ascii"),
            "metric_id": "input_to_output_fall_delay",
            "unit": "picosecond",
            "minimum_delay_picoseconds": self.minimum_delay_picoseconds,
            "maximum_delay_picoseconds": self.maximum_delay_picoseconds,
            "logic_low_millivolts": self.logic_low_millivolts,
            "logic_high_millivolts": self.logic_high_millivolts,
            "sample_times_picoseconds": (
                self.low_sample_picoseconds,
                self.high_sample_picoseconds,
            ),
            "evaluation_end_picoseconds": self.evaluation_end_picoseconds,
            "maximum_time_picoseconds": self.maximum_time_picoseconds,
            "maximum_samples": self.maximum_samples,
            "rejection_reason": SemanticRejectionReason.FUNCTIONAL_MISMATCH,
        }


@dataclass(frozen=True, slots=True)
class ModusDftReportParser:
    """Validate exact scan-chain metrics in a bounded native Modus report."""

    output_path: str
    expected_scan_cells: int
    maximum_report_bytes: int

    def __post_init__(self) -> None:
        if (
            self.expected_scan_cells <= 1
            or self.maximum_report_bytes < 1_024
            or self.maximum_report_bytes > 1024 * 1024
        ):
            raise ValueError("Modus scan-chain bounds must describe a strict incomplete pair")

    def _chain_length(self, observation: FixtureObservation) -> int | None:
        if observation.exit_codes != (0,) or not _has_marker(
            observation, MODUS_DFT_COMPLETION_MARKER
        ):
            return None
        output = observation.file(self.output_path)
        if (
            output is None
            or output.truncated
            or output.size_bytes != len(output.content)
            or output.size_bytes > self.maximum_report_bytes
        ):
            return None
        try:
            report = output.content.decode("ascii")
        except UnicodeDecodeError:
            return None
        mode_headers = tuple(
            value
            for value in re.findall(
                r"^[ \t]*Control/Observe Chain Information for Test Mode:[ \t]+"
                r"([A-Za-z0-9_]+)[ \t]*$",
                report,
                flags=re.MULTILINE,
            )
        )
        chain_counts = tuple(
            int(value)
            for value in re.findall(
                r"^[ \t]*([0-9]+) Chains are Control and Observe[ \t]*$",
                report,
                flags=re.MULTILINE,
            )
        )
        longest = tuple(
            int(value)
            for value in re.findall(
                r"^[ \t]*Longest Scan Chain:[ \t]+([0-9]+) bits[ \t]*$",
                report,
                flags=re.MULTILINE,
            )
        )
        average = tuple(
            int(value)
            for value in re.findall(
                r"^[ \t]*Average Scan Chain Length:[ \t]+([0-9]+) bits[ \t]*$",
                report,
                flags=re.MULTILINE,
            )
        )
        if (
            mode_headers != ("FULLSCAN",)
            or chain_counts != (1,)
            or len(longest) != 1
            or len(average) != 1
            or longest[0] != average[0]
            or longest[0] <= 0
            or longest[0] > self.expected_scan_cells
        ):
            return None
        return longest[0]

    def accepts(self, observation: FixtureObservation) -> bool:
        return self._chain_length(observation) == self.expected_scan_cells

    def rejection(
        self,
        observation: FixtureObservation,
    ) -> SemanticRejectionReason | None:
        chain_length = self._chain_length(observation)
        if chain_length is not None and chain_length < self.expected_scan_cells:
            return SemanticRejectionReason.INCOMPLETE_SCAN_CHAIN
        return None

    def qualification_identity(self) -> dict[str, object]:
        return {
            "kind": "modus_scan_chain_report",
            "output_path": self.output_path,
            "completion_marker": MODUS_DFT_COMPLETION_MARKER.decode("ascii"),
            "test_mode": "FULLSCAN",
            "expected_joint_control_observe_chains": 1,
            "maximum_report_bytes": self.maximum_report_bytes,
            "metrics": (
                {
                    "metric_id": "longest_scan_chain_bits",
                    "unit": "count",
                    "minimum": self.expected_scan_cells,
                    "maximum": self.expected_scan_cells,
                },
                {
                    "metric_id": "average_scan_chain_bits",
                    "unit": "count",
                    "minimum": self.expected_scan_cells,
                    "maximum": self.expected_scan_cells,
                },
            ),
            "semantic_rejection_minimum_bits": 1,
            "semantic_rejection_maximum_bits": self.expected_scan_cells - 1,
            "rejection_reason": SemanticRejectionReason.INCOMPLETE_SCAN_CHAIN,
        }


def _input(logical_id: str, path: str, content: str) -> FixtureInput:
    return FixtureInput(logical_id, path, content.encode("ascii"))


_OPENROAD_CELL_LEF = """\
VERSION 5.8 ;
BUSBITCHARS "[]" ;
DIVIDERCHAR "/" ;
UNITS
  DATABASE MICRONS 1000 ;
END UNITS
MANUFACTURINGGRID 0.001 ;
SITE CoreSite
  CLASS CORE ;
  SIZE 1 BY 1 ;
END CoreSite
LAYER metal1
  TYPE ROUTING ;
  DIRECTION HORIZONTAL ;
  PITCH 0.10 ;
  WIDTH 0.05 ;
  SPACING 0.05 ;
  RESISTANCE RPERSQ 0.10 ;
  CAPACITANCE CPERSQDIST 0.0002 ;
  EDGECAPACITANCE 0.0001 ;
END metal1
MACRO BUF
  CLASS CORE ;
  ORIGIN 0 0 ;
  SIZE 1 BY 1 ;
  SITE CoreSite ;
  PIN A
    DIRECTION INPUT ;
    USE SIGNAL ;
    PORT
      LAYER metal1 ;
      RECT 0.10 0.10 0.20 0.20 ;
    END
  END A
  PIN Y
    DIRECTION OUTPUT ;
    USE SIGNAL ;
    PORT
      LAYER metal1 ;
      RECT 0.80 0.80 0.90 0.90 ;
    END
  END Y
END BUF
END LIBRARY
"""

_OPENROAD_CELL_LIBERTY = """\
library (edagym_backend_breadth) {
  delay_model : table_lookup;
  time_unit : "1ns";
  voltage_unit : "1V";
  current_unit : "1mA";
  leakage_power_unit : "1uW";
  capacitive_load_unit (1, pf);
  nom_process : 1.0;
  nom_temperature : 25.0;
  nom_voltage : 1.0;
  operating_conditions (typical) {
    process : 1.0;
    temperature : 25.0;
    voltage : 1.0;
  }
  default_operating_conditions : typical;
  power_lut_template (power_template) {
    variable_1 : input_transition_time;
    variable_2 : total_output_net_capacitance;
    index_1 ("0.01");
    index_2 ("0.01");
  }
  cell (BUF) {
    area : 1.0;
    cell_leakage_power : 2.0;
    pin (A) {
      direction : input;
      capacitance : 0.01;
    }
    pin (Y) {
      direction : output;
      function : "A";
      internal_power () {
        related_pin : "A";
        rise_power (power_template) { values ("0.5"); }
        fall_power (power_template) { values ("0.5"); }
      }
    }
  }
}
"""


def _openroad_power_source(*, implemented: bool) -> str:
    implementation = "BUF instance(.A(a), .Y(y));" if implemented else "assign y = a;"
    return f"""\
module top(input a, output y);
  {implementation}
endmodule
"""


_OPENROAD_POWER_SCRIPT = """\
read_lef cells.lef
read_liberty cells.lib
read_verilog top.v
link_design top
set_power_activity -input_ports [get_ports a] -density 0.2 -duty 0.5
report_activity_annotation -report_annotated -report_unannotated > activity.rpt
report_power -digits 9 -format json > power.json
puts EDAGYM_OPENROAD_POWER_COMPLETE
exit
"""

OPENROAD_POWER_ANALYSIS = QualificationFixture(
    tool_id="openroad",
    capability=Capability.POWER_ANALYSIS,
    semantic_joints=normalize_semantic_joints(
        Capability.POWER_ANALYSIS,
        (
            SemanticJoint.POWER_ANALYSIS_ACTIVITY_COVERAGE,
            SemanticJoint.POWER_ANALYSIS_DYNAMIC,
            SemanticJoint.POWER_ANALYSIS_LEAKAGE,
        ),
    ),
    inputs=(
        _input("cell_abstract", "cells.lef", _OPENROAD_CELL_LEF),
        _input("cell_library", "cells.lib", _OPENROAD_CELL_LIBERTY),
        _input("design_source", "top.v", _openroad_power_source(implemented=True)),
        _input("power_script", "power.tcl", _OPENROAD_POWER_SCRIPT),
    ),
    rejection_inputs=(
        _input("cell_abstract", "cells.lef", _OPENROAD_CELL_LEF),
        _input("cell_library", "cells.lib", _OPENROAD_CELL_LIBERTY),
        _input("design_source", "top.v", _openroad_power_source(implemented=False)),
        _input("power_script", "power.tcl", _OPENROAD_POWER_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.DEGENERATE_IMPLEMENTATION,
    invocations=(ToolInvocation(("power.tcl",)),),
    outputs=(
        FixtureOutput(
            "activity_coverage_report",
            "activity.rpt",
            media_type="text/plain",
        ),
        FixtureOutput(
            "power_report",
            "power.json",
            media_type="application/json",
        ),
    ),
    parser=OpenroadPowerParser(
        output_path="power.json",
        activity_report_path="activity.rpt",
        required_annotated_input_ports=("a",),
        minimum_dynamic_picowatts=10_000,
        minimum_leakage_picowatts=1_000,
        minimum_total_picowatts=10_000,
        maximum_total_picowatts=1_000_000_000_000,
    ),
)


_OPENROAD_PDN_LEF = """\
VERSION 5.8 ;
BUSBITCHARS "[]" ;
DIVIDERCHAR "/" ;
UNITS
  DATABASE MICRONS 1000 ;
END UNITS
SITE CoreSite
  CLASS CORE ;
  SIZE 1 BY 2 ;
END CoreSite
LAYER metal1
  TYPE ROUTING ;
  DIRECTION HORIZONTAL ;
  PITCH 0.2 ;
  WIDTH 0.1 ;
  SPACING 0.1 ;
  RESISTANCE RPERSQ 0.5 ;
END metal1
MACRO LOAD
  CLASS CORE ;
  ORIGIN 0 0 ;
  SIZE 1 BY 2 ;
  SITE CoreSite ;
  PIN VDD
    DIRECTION INOUT ;
    USE POWER ;
    PORT
      LAYER metal1 ;
      RECT 0 1.8 1 2 ;
    END
  END VDD
  PIN VSS
    DIRECTION INOUT ;
    USE GROUND ;
    PORT
      LAYER metal1 ;
      RECT 0 0 1 0.2 ;
    END
  END VSS
END LOAD
END LIBRARY
"""

_OPENROAD_PDN_DEF = """\
VERSION 5.8 ;
DIVIDERCHAR "/" ;
BUSBITCHARS "[]" ;
DESIGN top ;
UNITS DISTANCE MICRONS 1000 ;
DIEAREA ( 0 0 ) ( 10000 4000 ) ;
ROW row_0 CoreSite 0 0 N DO 10 BY 1 STEP 1000 0 ;
ROW row_1 CoreSite 0 2000 FS DO 10 BY 1 STEP 1000 0 ;
TRACKS Y 100 DO 20 STEP 200 LAYER metal1 ;
COMPONENTS 3 ;
- u_load_0 LOAD + PLACED ( 1000 0 ) N ;
- u_load_1 LOAD + PLACED ( 5000 0 ) N ;
- u_load_2 LOAD + PLACED ( 9000 0 ) N ;
END COMPONENTS
PINS 0 ;
END PINS
SPECIALNETS 2 ;
- VDD ( * VDD ) + USE POWER
  + ROUTED metal1 200 + SHAPE FOLLOWPIN ( 0 1900 ) ( 10000 * ) ;
- VSS ( * VSS ) + USE GROUND
  + ROUTED metal1 200 + SHAPE FOLLOWPIN ( 0 100 ) ( 10000 * ) ;
END SPECIALNETS
NETS 0 ;
END NETS
END DESIGN
"""

_OPENROAD_PDN_VOLTAGE_SOURCE = "0,1.9,0.2,1.0\n"


def _openroad_power_grid_script(instance_power_watts: str) -> str:
    return f"""\
read_lef power_grid.lef
read_def power_grid.def
set_pdnsim_net_voltage -net VDD -voltage 1.0
set_pdnsim_inst_power -inst u_load_0 -power {instance_power_watts}
set_pdnsim_inst_power -inst u_load_1 -power {instance_power_watts}
set_pdnsim_inst_power -inst u_load_2 -power {instance_power_watts}
check_power_grid -net VDD -dont_require_terminals
analyze_power_grid -net VDD -vsrc voltage_source.loc -voltage_file voltage.rpt
write_def analyzed_grid.def
exit
"""


OPENROAD_POWER_INTEGRITY = QualificationFixture(
    tool_id="openroad",
    capability=Capability.POWER_INTEGRITY,
    semantic_joints=normalize_semantic_joints(
        Capability.POWER_INTEGRITY,
        (
            SemanticJoint.POWER_INTEGRITY_IR_DROP_GRID,
            SemanticJoint.POWER_INTEGRITY_VIOLATIONS,
        ),
    ),
    inputs=(
        _input("power_grid_abstract", "power_grid.lef", _OPENROAD_PDN_LEF),
        _input("routed_power_grid", "power_grid.def", _OPENROAD_PDN_DEF),
        _input(
            "voltage_source",
            "voltage_source.loc",
            _OPENROAD_PDN_VOLTAGE_SOURCE,
        ),
        _input(
            "power_grid_script",
            "power_grid.tcl",
            _openroad_power_grid_script("0.001"),
        ),
    ),
    rejection_inputs=(
        _input("power_grid_abstract", "power_grid.lef", _OPENROAD_PDN_LEF),
        _input("routed_power_grid", "power_grid.def", _OPENROAD_PDN_DEF),
        _input(
            "voltage_source",
            "voltage_source.loc",
            _OPENROAD_PDN_VOLTAGE_SOURCE,
        ),
        _input(
            "power_grid_script",
            "power_grid.tcl",
            _openroad_power_grid_script("0.01"),
        ),
    ),
    rejection_reason=SemanticRejectionReason.POWER_GRID_VIOLATION,
    invocations=(ToolInvocation(("-no_init", "-exit", "power_grid.tcl")),),
    outputs=(
        FixtureOutput("power_grid_voltage", "voltage.rpt", media_type="text/csv"),
        FixtureOutput("analyzed_power_grid", "analyzed_grid.def", media_type="text/plain"),
    ),
    parser=OpenroadPowerIntegrityParser(
        voltage_report_path="voltage.rpt",
        routed_grid_path="analyzed_grid.def",
        power_net="VDD",
        routing_layer="metal1",
        expected_instances=("u_load_0", "u_load_1", "u_load_2"),
        supply_microvolts=1_000_000,
        maximum_accepted_drop_microvolts=50_000,
        minimum_rejected_drop_microvolts=100_000,
    ),
)


def _openroad_extraction_def(*, include_required_net: bool) -> str:
    if include_required_net:
        components = """\
COMPONENTS 2 ;
- U1 BUF + PLACED ( 1000 1000 ) N ;
- U2 BUF + PLACED ( 7000 1000 ) N ;
END COMPONENTS
"""
        nets = """\
NETS 3 ;
- input_net ( PIN a ) ( U1 A )
  + ROUTED metal1 ( 0 1150 ) ( 1150 * ) ;
- data_net ( U1 Y ) ( U2 A )
  + ROUTED metal1 ( 1850 1850 ) ( 7150 * ) ;
- output_net ( U2 Y ) ( PIN y )
  + ROUTED metal1 ( 7850 1850 ) ( 10000 * ) ;
END NETS
"""
    else:
        components = """\
COMPONENTS 1 ;
- U1 BUF + PLACED ( 1000 1000 ) N ;
END COMPONENTS
"""
        nets = """\
NETS 2 ;
- input_net ( PIN a ) ( U1 A )
  + ROUTED metal1 ( 0 1150 ) ( 1150 * ) ;
- output_net ( U1 Y ) ( PIN y )
  + ROUTED metal1 ( 1850 1850 ) ( 10000 * ) ;
END NETS
"""
    return f"""\
VERSION 5.8 ;
DIVIDERCHAR "/" ;
BUSBITCHARS "[]" ;
DESIGN top ;
UNITS DISTANCE MICRONS 1000 ;
DIEAREA ( 0 0 ) ( 10000 10000 ) ;
{components}PINS 2 ;
- a + NET input_net + DIRECTION INPUT + USE SIGNAL
  + LAYER metal1 ( -25 -25 ) ( 25 25 )
  + PLACED ( 0 1150 ) N ;
- y + NET output_net + DIRECTION OUTPUT + USE SIGNAL
  + LAYER metal1 ( -25 -25 ) ( 25 25 )
  + PLACED ( 10000 1850 ) N ;
END PINS
{nets}END DESIGN
"""


_OPENROAD_EXTRACTION_SCRIPT = """\
read_lef cells.lef
read_liberty cells.lib
read_def design.def
set_wire_rc -signal -layer metal1
estimate_parasitics -placement -spef_file extraction.spef
puts EDAGYM_OPENROAD_EXTRACTION_COMPLETE
exit
"""

OPENROAD_PARASITIC_EXTRACTION = QualificationFixture(
    tool_id="openroad",
    capability=Capability.PARASITIC_EXTRACTION,
    semantic_joints=normalize_semantic_joints(
        Capability.PARASITIC_EXTRACTION,
        (
            SemanticJoint.PARASITIC_EXTRACTION_SPEF,
            SemanticJoint.PARASITIC_EXTRACTION_NET_COUNT,
        ),
    ),
    inputs=(
        _input("cell_abstract", "cells.lef", _OPENROAD_CELL_LEF),
        _input("cell_library", "cells.lib", _OPENROAD_CELL_LIBERTY),
        _input(
            "placed_design",
            "design.def",
            _openroad_extraction_def(include_required_net=True),
        ),
        _input("extraction_script", "extract.tcl", _OPENROAD_EXTRACTION_SCRIPT),
    ),
    rejection_inputs=(
        _input("cell_abstract", "cells.lef", _OPENROAD_CELL_LEF),
        _input("cell_library", "cells.lib", _OPENROAD_CELL_LIBERTY),
        _input(
            "placed_design",
            "design.def",
            _openroad_extraction_def(include_required_net=False),
        ),
        _input("extraction_script", "extract.tcl", _OPENROAD_EXTRACTION_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
    invocations=(ToolInvocation(("extract.tcl",)),),
    outputs=(
        FixtureOutput(
            "parasitic_report",
            "extraction.spef",
            media_type="application/vnd.ieee.spef",
        ),
    ),
    parser=OpenroadSpefParser(
        output_path="extraction.spef",
        required_net="data_net",
        minimum_capacitance_attofarads=10,
        maximum_capacitance_attofarads=1_000_000,
        minimum_resistance_microohms=1,
        maximum_resistance_microohms=1_000_000_000_000,
    ),
    log_projection=MarkerLogProjection((_OPENROAD_EXTRACTION_MARKER,)),
)


def _ngspice_inverter_netlist(*, inverter: bool) -> str:
    devices = (
        """\
Mp out in vdd vdd pmos W=4u L=0.18u
Mn out in 0 0 nmos W=2u L=0.18u
"""
        if inverter
        else "Rcopy out in 1\n"
    )
    return f"""\
* EdaGym inverter characterization qualification
Vdd vdd 0 1.0
Vin in 0 PULSE(0 1 1n 0.1n 0.1n 4n 10n)
{devices}Cload out 0 20f
.model nmos NMOS level=1 VTO=0.4 KP=200u LAMBDA=0.02
.model pmos PMOS level=1 VTO=-0.4 KP=100u LAMBDA=0.02
.tran 0.05n 12n
.control
set wr_singlescale
set wr_vecnames
run
wrdata characterization.tsv v(in) v(out)
echo EDAGYM_NGSPICE_CHARACTERIZATION_COMPLETE
quit
.endc
.end
"""


NGSPICE_CELL_CHARACTERIZATION = QualificationFixture(
    tool_id="ngspice",
    capability=Capability.CELL_CHARACTERIZATION,
    inputs=(
        _input(
            "characterization_netlist",
            "inverter.cir",
            _ngspice_inverter_netlist(inverter=True),
        ),
    ),
    rejection_inputs=(
        _input(
            "characterization_netlist",
            "inverter.cir",
            _ngspice_inverter_netlist(inverter=False),
        ),
    ),
    rejection_reason=SemanticRejectionReason.FUNCTIONAL_MISMATCH,
    invocations=(ToolInvocation(("-b", "inverter.cir")),),
    outputs=(
        FixtureOutput(
            "characterization_waveform",
            "characterization.tsv",
            media_type="text/tab-separated-values",
        ),
    ),
    parser=NgspiceCharacterizationParser(
        output_path="characterization.tsv",
        low_sample_picoseconds=500,
        high_sample_picoseconds=3_000,
        logic_low_millivolts=200,
        logic_high_millivolts=800,
        minimum_delay_picoseconds=1,
        maximum_delay_picoseconds=1_000,
        evaluation_end_picoseconds=4_000,
        maximum_time_picoseconds=20_000,
        maximum_samples=8_192,
    ),
    log_projection=MarkerLogProjection((_NGSPICE_CHARACTERIZATION_MARKER,)),
)


MODUS_DESIGN_FOR_TEST = QualificationFixture(
    tool_id="modus",
    capability=Capability.DESIGN_FOR_TEST,
    inputs=(
        _input("design_source", "candidate.v", modus_scan_design(complete_chain=True)),
        _input("pin_assignments", "pins.assign", MODUS_PIN_ASSIGNMENTS),
        _input("dft_script", "run.tcl", MODUS_DFT_SCRIPT),
    ),
    rejection_inputs=(
        _input("design_source", "candidate.v", modus_scan_design(complete_chain=False)),
        _input("pin_assignments", "pins.assign", MODUS_PIN_ASSIGNMENTS),
        _input("dft_script", "run.tcl", MODUS_DFT_SCRIPT),
    ),
    rejection_reason=SemanticRejectionReason.INCOMPLETE_SCAN_CHAIN,
    invocations=(
        ToolInvocation(
            (
                "-batch",
                "-abort_on_error",
                "-disable_user_startup",
                "-log",
                "modus",
                "-overwrite",
                "-files",
                "run.tcl",
            )
        ),
    ),
    outputs=(
        FixtureOutput(
            "native_dft_report",
            MODUS_DFT_REPORT_PATH,
            media_type="text/plain",
        ),
    ),
    parser=ModusDftReportParser(
        output_path=MODUS_DFT_REPORT_PATH,
        expected_scan_cells=4,
        maximum_report_bytes=16 * 1024,
    ),
    log_projection=MarkerLogProjection((MODUS_DFT_COMPLETION_MARKER,)),
)


BACKEND_BREADTH_FIXTURES: tuple[QualificationFixture, ...] = (
    OPENROAD_POWER_ANALYSIS,
    OPENROAD_POWER_INTEGRITY,
    OPENROAD_PARASITIC_EXTRACTION,
    NGSPICE_CELL_CHARACTERIZATION,
)
