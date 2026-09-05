"""Shared executable fixtures with one semantic owner."""

from edagym.fixtures.modus_dft import (
    MODUS_DFT_COMPLETION_MARKER,
    MODUS_DFT_REPORT_PATH,
    MODUS_DFT_SCRIPT,
    MODUS_PIN_ASSIGNMENTS,
    modus_scan_design,
)
from edagym.fixtures.openroad_toy import (
    OPENROAD_LEF,
    OPENROAD_LIBRARY,
    SEQUENTIAL_NETLIST,
)

__all__ = [
    "MODUS_DFT_COMPLETION_MARKER",
    "MODUS_DFT_REPORT_PATH",
    "MODUS_DFT_SCRIPT",
    "MODUS_PIN_ASSIGNMENTS",
    "OPENROAD_LEF",
    "OPENROAD_LIBRARY",
    "SEQUENTIAL_NETLIST",
    "modus_scan_design",
]
