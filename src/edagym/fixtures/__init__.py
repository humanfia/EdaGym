"""Shared executable fixtures with one semantic owner."""

from edagym.fixtures.modus_dft import (
    MODUS_DFT_COMPLETION_MARKER,
    MODUS_DFT_REPORT_PATH,
    MODUS_DFT_SCRIPT,
    MODUS_PIN_ASSIGNMENTS,
    modus_scan_design,
)
from edagym.fixtures.openroad_toy import (
    OPENROAD_LEF_ASSET_ID,
    OPENROAD_LEF_PATH,
    OPENROAD_LIBRARY_ASSET_ID,
    OPENROAD_LIBRARY_PATH,
    SEQUENTIAL_NETLIST,
)
from edagym.fixtures.synthesis_toy import (
    SYNTHESIS_LIBRARY_ASSET_ID,
    SYNTHESIS_LIBRARY_PATH,
)

__all__ = [
    "MODUS_DFT_COMPLETION_MARKER",
    "MODUS_DFT_REPORT_PATH",
    "MODUS_DFT_SCRIPT",
    "MODUS_PIN_ASSIGNMENTS",
    "OPENROAD_LEF_ASSET_ID",
    "OPENROAD_LEF_PATH",
    "OPENROAD_LIBRARY_ASSET_ID",
    "OPENROAD_LIBRARY_PATH",
    "SEQUENTIAL_NETLIST",
    "SYNTHESIS_LIBRARY_ASSET_ID",
    "SYNTHESIS_LIBRARY_PATH",
    "modus_scan_design",
]
