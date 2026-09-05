"""Shared Modus scan-chain design and native-report workload inputs."""

MODUS_DFT_COMPLETION_MARKER = b"EDAGYM_MODUS_DFT_COMPLETE"
MODUS_DFT_REPORT_PATH = "dft-native-report.txt"


def modus_scan_design(*, complete_chain: bool) -> str:
    """Return the canonical four-cell scan design or its incomplete-chain pair."""

    third_scan_input = "state[1]" if complete_chain else "scan_in"
    return f"""\
module scan_register(
  input wire clock,
  input wire scan_enable,
  input wire scan_in,
  input wire [3:0] functional_data,
  output wire scan_out,
  output wire [3:0] state
);
  SDFFQX1 ff0(
    .D(functional_data[0]), .SI(scan_in), .SE(scan_enable), .CK(clock), .Q(state[0])
  );
  SDFFQX1 ff1(
    .D(functional_data[1]), .SI(state[0]), .SE(scan_enable), .CK(clock), .Q(state[1])
  );
  SDFFQX1 ff2(
    .D(functional_data[2]), .SI({third_scan_input}),
    .SE(scan_enable), .CK(clock), .Q(state[2])
  );
  SDFFQX1 ff3(
    .D(functional_data[3]), .SI(state[2]), .SE(scan_enable), .CK(clock), .Q(state[3])
  );
  assign scan_out = state[3];
endmodule
"""


MODUS_PIN_ASSIGNMENTS = """\
assign pin "scan_in" test_function=SI;
assign pin "scan_out" test_function=SO;
assign pin "clock" test_function=0ES;
assign pin "scan_enable" test_function=1SE;
"""

MODUS_DFT_SCRIPT = f"""\
build_model \
  -workdir dft-work \
  -designsource candidate.v \
  -techlib $::env(EDAGYM_SCAN_TECHLIB) \
  -designtop scan_register
set_db workdir dft-work
build_testmode -workdir dft-work -assignfile pins.assign -testmode FULLSCAN
verify_test_structures -workdir dft-work -testmode FULLSCAN
redirect {MODUS_DFT_REPORT_PATH} {{report_test_structures -workdir dft-work -testmode FULLSCAN}}
puts {MODUS_DFT_COMPLETION_MARKER.decode("ascii")}
exit
"""
