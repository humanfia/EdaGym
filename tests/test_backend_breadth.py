"""Regression evidence for bounded backend-breadth report parsing."""

from __future__ import annotations

import json

import pytest

from edagym.drivers.fixtures.backend_breadth import (
    MODUS_DESIGN_FOR_TEST,
    NGSPICE_CELL_CHARACTERIZATION,
    OPENROAD_PARASITIC_EXTRACTION,
    OPENROAD_POWER_ANALYSIS,
    OPENROAD_POWER_INTEGRITY,
)
from edagym.drivers.fixtures.model import (
    FixtureObservation,
    ObservedFile,
    QualificationFixture,
    SemanticRejectionReason,
)


def _observation(fixture: QualificationFixture, content: bytes) -> FixtureObservation:
    output = fixture.outputs[-1]
    marker = (
        fixture.log_projection.markers[0]
        if fixture.log_projection is not None
        else b"EDAGYM_OPENROAD_POWER_COMPLETE"
    )
    files = [
        ObservedFile(
            path=output.path,
            content=content,
            size_bytes=len(content),
            truncated=False,
        )
    ]
    if fixture is OPENROAD_POWER_ANALYSIS:
        activity_report = b"""\
input           1
unannotated     3
Annotated pins:
 user a
Unannotated pins:
 y
 instance/A
 instance/Y
"""
        files.append(
            ObservedFile(
                path="activity.rpt",
                content=activity_report,
                size_bytes=len(activity_report),
                truncated=False,
            )
        )
    return FixtureObservation(
        exit_codes=(0,),
        stdout=(marker + b"\n",),
        stderr=(b"",),
        files=tuple(files),
    )


def _power_report(
    *,
    sequential_internal: object = 0,
    sequential_leakage: object = 0,
    sequential_total: object = 0,
    total_internal: object = 0,
    total_leakage: object = 0,
    total: object = 0,
) -> bytes:
    zero: dict[str, object] = {
        "internal": 0,
        "switching": 0,
        "leakage": 0,
        "total": 0,
    }
    document: dict[str, dict[str, object]] = {
        name: dict(zero) for name in ("Sequential", "Combinational", "Clock", "Macro", "Pad")
    }
    document["Sequential"]["internal"] = sequential_internal
    document["Sequential"]["leakage"] = sequential_leakage
    document["Sequential"]["total"] = sequential_total
    document["Total"] = {
        "internal": total_internal,
        "switching": 0,
        "leakage": total_leakage,
        "total": total,
    }
    return json.dumps(document, separators=(",", ":")).encode("ascii")


def _spef(net: str, *, capacitance_node: str | None = None) -> bytes:
    port = "y" if net == "output_net" else "a"
    direction = "O" if port == "y" else "I"
    node = capacitance_node or f"{net}:0"
    return f"""\
*SPEF "ieee 1481-1999"
*DESIGN "top"
*DATE "11:11:11 Fri 11 Nov, 1111"
*VENDOR "The OpenROAD Project"
*PROGRAM "OpenROAD"
*VERSION "1.0"
*DESIGN_FLOW "NAME_SCOPE LOCAL" "PIN_CAP NONE"
*DIVIDER /
*DELIMITER :
*BUS_DELIMITER []
*T_UNIT 1 NS
*C_UNIT 1 PF
*R_UNIT 1 OHM
*L_UNIT 1 HENRY
*PORTS
a I
y O
*D_NET {net} 0.001
*CONN
*P {port} {direction}
*CAP
1 {node} 0.001
*RES
1 {node} {port} 1
*END
""".encode("ascii")


def _waveform(*, behavior: str) -> bytes:
    lines = ["time v(in) v(out)"]
    for picoseconds in range(0, 4_101, 100):
        input_voltage = 0 if picoseconds < 1_000 else 1
        if behavior == "inverting":
            output_voltage = 1 if picoseconds < 1_100 else 0
        elif behavior == "noninverting":
            output_voltage = input_voltage
        elif behavior == "glitch":
            output_voltage = int(picoseconds < 1_100 or 1_800 <= picoseconds < 2_500)
        else:
            raise ValueError("unknown waveform behavior")
        lines.append(f"{picoseconds}e-12 {input_voltage} {output_voltage}")
    return ("\n".join(lines) + "\n").encode("ascii")


def _power_grid_observation(*, voltages: tuple[str, str, str]) -> FixtureObservation:
    voltage_report = (
        "Instance,Terminal,Layer,X location,Y location,Voltage\n"
        f"u_load_0,VDD,metal1,1.5000,1.9000,{voltages[0]}\n"
        f"u_load_1,VDD,metal1,5.5000,1.9000,{voltages[1]}\n"
        f"u_load_2,VDD,metal1,9.5000,1.9000,{voltages[2]}\n"
    ).encode("ascii")
    routed_grid = b"""\
VERSION 5.8 ;
DESIGN top ;
COMPONENTS 3 ;
- u_load_0 LOAD + PLACED ( 1000 0 ) N ;
- u_load_1 LOAD + PLACED ( 5000 0 ) N ;
- u_load_2 LOAD + PLACED ( 9000 0 ) N ;
END COMPONENTS
SPECIALNETS 2 ;
- VDD ( * VDD ) + USE POWER
  + ROUTED metal1 200 + SHAPE FOLLOWPIN ( 0 1900 ) ( 10000 1900 ) ;
- VSS ( * VSS ) + USE GROUND
  + ROUTED metal1 200 + SHAPE FOLLOWPIN ( 0 100 ) ( 10000 100 ) ;
END SPECIALNETS
END DESIGN
"""
    return FixtureObservation(
        exit_codes=(0,),
        stdout=(b"",),
        stderr=(b"",),
        files=(
            ObservedFile(
                path="voltage.rpt",
                content=voltage_report,
                size_bytes=len(voltage_report),
                truncated=False,
            ),
            ObservedFile(
                path="analyzed_grid.def",
                content=routed_grid,
                size_bytes=len(routed_grid),
                truncated=False,
            ),
        ),
    )


@pytest.mark.parametrize(
    ("fixture", "corrupt_report"),
    (
        (
            OPENROAD_POWER_ANALYSIS,
            _power_report(sequential_total=float("nan"), total=float("nan")),
        ),
        (
            OPENROAD_PARASITIC_EXTRACTION,
            _spef("output_net").replace(b"0.001\n*CONN", b"1e9999\n*CONN"),
        ),
        (
            NGSPICE_CELL_CHARACTERIZATION,
            b"time v(in) v(out)\n0 NaN 0\n" * 32,
        ),
        (
            MODUS_DESIGN_FOR_TEST,
            b"""\
Control/Observe Chain Information for Test Mode: FULLSCAN
1 Chains are Control and Observe
2 Chains are Control and Observe
Longest Scan Chain: 2 bits
Average Scan Chain Length: 2 bits
""",
        ),
    ),
)
def test_corrupt_numeric_reports_are_not_semantic_rejections(
    fixture: QualificationFixture,
    corrupt_report: bytes,
) -> None:
    observation = _observation(fixture, corrupt_report)

    assert not fixture.parser.accepts(observation)
    assert fixture.parser.rejection(observation) is None


@pytest.mark.parametrize(
    ("fixture", "report", "expected"),
    (
        (
            OPENROAD_POWER_ANALYSIS,
            _power_report(),
            SemanticRejectionReason.DEGENERATE_IMPLEMENTATION,
        ),
        (
            OPENROAD_PARASITIC_EXTRACTION,
            _spef("output_net"),
            SemanticRejectionReason.MISSING_REQUIRED_STRUCTURE,
        ),
        (
            NGSPICE_CELL_CHARACTERIZATION,
            _waveform(behavior="noninverting"),
            SemanticRejectionReason.FUNCTIONAL_MISMATCH,
        ),
        (
            MODUS_DESIGN_FOR_TEST,
            b"""\
Control/Observe Chain Information for Test Mode: FULLSCAN
1 Chains are Control and Observe
Longest Scan Chain: 2 bits
Average Scan Chain Length: 2 bits
""",
            SemanticRejectionReason.INCOMPLETE_SCAN_CHAIN,
        ),
    ),
)
def test_well_formed_negative_reports_retain_typed_rejections(
    fixture: QualificationFixture,
    report: bytes,
    expected: SemanticRejectionReason,
) -> None:
    observation = _observation(fixture, report)

    assert not fixture.parser.accepts(observation)
    assert fixture.parser.rejection(observation) is expected


@pytest.mark.parametrize(
    ("fixture", "report"),
    (
        (
            OPENROAD_POWER_ANALYSIS,
            _power_report(sequential_total=0.001, total=0.001),
        ),
        (
            OPENROAD_PARASITIC_EXTRACTION,
            _spef("output_net", capacitance_node="foreign_net:0"),
        ),
        (
            NGSPICE_CELL_CHARACTERIZATION,
            _waveform(behavior="glitch"),
        ),
    ),
)
def test_internally_inconsistent_reports_cannot_count_as_semantic_results(
    fixture: QualificationFixture,
    report: bytes,
) -> None:
    observation = _observation(fixture, report)

    assert not fixture.parser.accepts(observation)
    assert fixture.parser.rejection(observation) is None


@pytest.mark.parametrize(
    ("fixture", "report"),
    (
        (
            OPENROAD_POWER_ANALYSIS,
            _power_report(
                sequential_internal=0.001,
                sequential_leakage=0.0001,
                sequential_total=0.0011,
                total_internal=0.001,
                total_leakage=0.0001,
                total=0.0011,
            ),
        ),
        (OPENROAD_PARASITIC_EXTRACTION, _spef("data_net")),
        (NGSPICE_CELL_CHARACTERIZATION, _waveform(behavior="inverting")),
        (
            MODUS_DESIGN_FOR_TEST,
            b"""\
Control/Observe Chain Information for Test Mode: FULLSCAN
1 Chains are Control and Observe
Longest Scan Chain: 4 bits
Average Scan Chain Length: 4 bits
""",
        ),
    ),
)
def test_bounded_complete_reports_are_accepted(
    fixture: QualificationFixture,
    report: bytes,
) -> None:
    observation = _observation(fixture, report)

    assert fixture.parser.accepts(observation)
    assert fixture.parser.rejection(observation) is None


def test_power_integrity_requires_a_routed_grid_and_classifies_ir_violations() -> None:
    accepted = _power_grid_observation(voltages=("0.999999", "0.979999", "0.969999"))
    rejected = _power_grid_observation(voltages=("0.999990", "0.799990", "0.699990"))

    assert OPENROAD_POWER_INTEGRITY.parser.accepts(accepted)
    assert OPENROAD_POWER_INTEGRITY.parser.rejection(accepted) is None
    assert not OPENROAD_POWER_INTEGRITY.parser.accepts(rejected)
    assert (
        OPENROAD_POWER_INTEGRITY.parser.rejection(rejected)
        is SemanticRejectionReason.POWER_GRID_VIOLATION
    )

    missing_grid = FixtureObservation(
        exit_codes=accepted.exit_codes,
        stdout=accepted.stdout,
        stderr=accepted.stderr,
        files=(accepted.files[0],),
    )
    assert not OPENROAD_POWER_INTEGRITY.parser.accepts(missing_grid)
    assert OPENROAD_POWER_INTEGRITY.parser.rejection(missing_grid) is None
