"""External asset identities and public RTL for OpenROAD fixtures.

Technology abstracts and timing libraries are user-owned private assets. No
LEF or Liberty bytes are distributed with the package.
"""

from __future__ import annotations

OPENROAD_LIBRARY_ASSET_ID = "openroad_timing_library"
OPENROAD_LIBRARY_PATH = "technology/cells.lib"
OPENROAD_LEF_ASSET_ID = "openroad_cell_abstract"
OPENROAD_LEF_PATH = "technology/cells.lef"

SEQUENTIAL_NETLIST = """\
module top(input clk, input d, output q);
  wire launched;
  wire buffered0;
  wire buffered1;
  wire buffered2;
  wire buffered3;
  DFF launch(.CLK(clk), .D(d), .Q(launched));
  BUF path0(.A(launched), .Y(buffered0));
  BUF path1(.A(buffered0), .Y(buffered1));
  BUF path2(.A(buffered1), .Y(buffered2));
  BUF path3(.A(buffered2), .Y(buffered3));
  DFF capture(.CLK(clk), .D(buffered3), .Q(q));
endmodule
"""

__all__ = [
    "OPENROAD_LEF_ASSET_ID",
    "OPENROAD_LEF_PATH",
    "OPENROAD_LIBRARY_ASSET_ID",
    "OPENROAD_LIBRARY_PATH",
    "SEQUENTIAL_NETLIST",
]
