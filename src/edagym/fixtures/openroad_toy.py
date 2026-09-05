"""Shared OpenROAD toy technology and sequential design fixtures."""

from __future__ import annotations

OPENROAD_LIBRARY = """\
library (edagym) {
  delay_model : table_lookup;
  time_unit : "1ns";
  voltage_unit : "1V";
  current_unit : "1mA";
  leakage_power_unit : "1uW";
  capacitive_load_unit (1, pf);
  nom_process : 1.0;
  nom_temperature : 25.0;
  nom_voltage : 1.0;
  lu_table_template(delay_template) {
    variable_1 : input_net_transition;
    variable_2 : total_output_net_capacitance;
    index_1 ("0.01");
    index_2 ("0.01");
  }
  cell (DFF) {
    area : 2.0;
    cell_leakage_power : 2.0;
    ff (IQ, IQN) { clocked_on : "CLK"; next_state : "D"; }
    pin (CLK) { direction : input; clock : true; capacitance : 0.01; }
    pin (D) { direction : input; capacitance : 0.01; }
    pin (Q) {
      direction : output;
      function : "IQ";
      timing () {
        related_pin : "CLK";
        timing_type : rising_edge;
        cell_rise (delay_template) { values ("0.10"); }
        cell_fall (delay_template) { values ("0.10"); }
        rise_transition (delay_template) { values ("0.02"); }
        fall_transition (delay_template) { values ("0.02"); }
      }
    }
  }
  cell (BUF) {
    area : 1.0;
    cell_leakage_power : 1.0;
    pin (A) { direction : input; capacitance : 0.01; }
    pin (Y) {
      direction : output;
      function : "A";
      max_capacitance : 0.20;
      max_transition : 0.20;
      timing () {
        related_pin : "A";
        timing_sense : positive_unate;
        cell_rise (delay_template) { values ("0.10"); }
        cell_fall (delay_template) { values ("0.10"); }
        rise_transition (delay_template) { values ("0.02"); }
        fall_transition (delay_template) { values ("0.02"); }
      }
    }
  }
}
"""


OPENROAD_LEF = """\
VERSION 5.8 ;
BUSBITCHARS "[]" ;
DIVIDERCHAR "/" ;
UNITS
  DATABASE MICRONS 1000 ;
END UNITS
MANUFACTURINGGRID 0.001 ;
LAYER met1
  TYPE ROUTING ;
  DIRECTION HORIZONTAL ;
  PITCH 0.20 ;
  WIDTH 0.10 ;
  SPACING 0.10 ;
END met1
LAYER via1
  TYPE CUT ;
  SPACING 0.10 ;
END via1
LAYER met2
  TYPE ROUTING ;
  DIRECTION VERTICAL ;
  PITCH 0.20 ;
  WIDTH 0.10 ;
  SPACING 0.10 ;
END met2
VIA VIA12 DEFAULT
  LAYER met1 ;
    RECT -0.05 -0.05 0.05 0.05 ;
  LAYER via1 ;
    RECT -0.04 -0.04 0.04 0.04 ;
  LAYER met2 ;
    RECT -0.05 -0.05 0.05 0.05 ;
END VIA12
SITE CoreSite
  CLASS CORE ;
  SYMMETRY Y ;
  SIZE 1.0 BY 2.0 ;
END CoreSite
MACRO BUF
  CLASS CORE ;
  ORIGIN 0 0 ;
  SIZE 1.0 BY 2.0 ;
  SYMMETRY X Y ;
  SITE CoreSite ;
  PIN A
    DIRECTION INPUT ;
    USE SIGNAL ;
    PORT
      LAYER met1 ;
      RECT 0.05 0.85 0.15 0.95 ;
    END
  END A
  PIN Y
    DIRECTION OUTPUT ;
    USE SIGNAL ;
    PORT
      LAYER met1 ;
      RECT 0.85 0.85 0.95 0.95 ;
    END
  END Y
END BUF
MACRO DFF
  CLASS CORE ;
  ORIGIN 0 0 ;
  SIZE 2.0 BY 2.0 ;
  SYMMETRY X Y ;
  SITE CoreSite ;
  PIN CLK
    DIRECTION INPUT ;
    USE CLOCK ;
    PORT
      LAYER met1 ;
      RECT 0.05 0.25 0.15 0.35 ;
    END
  END CLK
  PIN D
    DIRECTION INPUT ;
    USE SIGNAL ;
    PORT
      LAYER met1 ;
      RECT 0.05 1.25 0.15 1.35 ;
    END
  END D
  PIN Q
    DIRECTION OUTPUT ;
    USE SIGNAL ;
    PORT
      LAYER met1 ;
      RECT 1.85 1.25 1.95 1.35 ;
    END
  END Q
END DFF
END LIBRARY
"""


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

