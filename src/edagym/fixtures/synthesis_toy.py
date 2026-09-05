"""Public toy timing library for technology-mapped synthesis."""

from __future__ import annotations

SYNTHESIS_LIBRARY = """\
library (edagym) {
  delay_model : table_lookup;
  time_unit : "1ns";
  voltage_unit : "1V";
  current_unit : "1mA";
  leakage_power_unit : "1nW";
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
  lu_table_template(delay_template) {
    variable_1 : input_net_transition;
    variable_2 : total_output_net_capacitance;
    index_1 ("0.01");
    index_2 ("0.01");
  }
  lu_table_template(constraint_template) {
    variable_1 : related_pin_transition;
    variable_2 : constrained_pin_transition;
    index_1 ("0.01");
    index_2 ("0.01");
  }
  cell (DFF) {
    area : 1.0;
    ff (IQ, IQN) { clocked_on : "CLK"; next_state : "D"; }
    pin (CLK) { direction : input; clock : true; capacitance : 0.01; }
    pin (D) {
      direction : input;
      capacitance : 0.01;
      timing () {
        related_pin : "CLK";
        timing_type : setup_rising;
        rise_constraint (constraint_template) { values ("0.02"); }
        fall_constraint (constraint_template) { values ("0.02"); }
      }
      timing () {
        related_pin : "CLK";
        timing_type : hold_rising;
        rise_constraint (constraint_template) { values ("0.01"); }
        fall_constraint (constraint_template) { values ("0.01"); }
      }
    }
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
    area : 0.5;
    pin (A) { direction : input; capacitance : 0.01; }
    pin (Y) {
      direction : output;
      function : "A";
      timing () {
        related_pin : "A";
        timing_sense : positive_unate;
        cell_rise (delay_template) { values ("0.05"); }
        cell_fall (delay_template) { values ("0.05"); }
        rise_transition (delay_template) { values ("0.01"); }
        fall_transition (delay_template) { values ("0.01"); }
      }
    }
  }
  cell (INV) {
    area : 0.5;
    pin (A) { direction : input; capacitance : 0.01; }
    pin (Y) {
      direction : output;
      function : "!A";
      timing () {
        related_pin : "A";
        timing_sense : negative_unate;
        cell_rise (delay_template) { values ("0.05"); }
        cell_fall (delay_template) { values ("0.05"); }
        rise_transition (delay_template) { values ("0.01"); }
        fall_transition (delay_template) { values ("0.01"); }
      }
    }
  }
  cell (NAND2) {
    area : 1.0;
    pin (A) { direction : input; capacitance : 0.01; }
    pin (B) { direction : input; capacitance : 0.01; }
    pin (Y) {
      direction : output;
      function : "!(A & B)";
      timing () {
        related_pin : "A";
        timing_sense : negative_unate;
        cell_rise (delay_template) { values ("0.05"); }
        cell_fall (delay_template) { values ("0.05"); }
        rise_transition (delay_template) { values ("0.01"); }
        fall_transition (delay_template) { values ("0.01"); }
      }
      timing () {
        related_pin : "B";
        timing_sense : negative_unate;
        cell_rise (delay_template) { values ("0.05"); }
        cell_fall (delay_template) { values ("0.05"); }
        rise_transition (delay_template) { values ("0.01"); }
        fall_transition (delay_template) { values ("0.01"); }
      }
    }
  }
  cell (NOR2) {
    area : 1.0;
    pin (A) { direction : input; capacitance : 0.01; }
    pin (B) { direction : input; capacitance : 0.01; }
    pin (Y) {
      direction : output;
      function : "!(A | B)";
      timing () {
        related_pin : "A";
        timing_sense : negative_unate;
        cell_rise (delay_template) { values ("0.05"); }
        cell_fall (delay_template) { values ("0.05"); }
        rise_transition (delay_template) { values ("0.01"); }
        fall_transition (delay_template) { values ("0.01"); }
      }
      timing () {
        related_pin : "B";
        timing_sense : negative_unate;
        cell_rise (delay_template) { values ("0.05"); }
        cell_fall (delay_template) { values ("0.05"); }
        rise_transition (delay_template) { values ("0.01"); }
        fall_transition (delay_template) { values ("0.01"); }
      }
    }
  }
  cell (TIEHI) {
    area : 0.1;
    pin (Y) { direction : output; function : "1"; }
  }
  cell (TIELO) {
    area : 0.1;
    pin (Y) { direction : output; function : "0"; }
  }
}
"""
