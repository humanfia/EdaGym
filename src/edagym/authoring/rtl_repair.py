"""Reference-first generation of synthesizable ready/valid queue repair tasks."""

from __future__ import annotations

import hashlib
import random
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from edagym.specs.common import Capability, Redistribution, Sensitivity, Visibility
from edagym.specs.release import ChoiceParameterValue, IntegerParameterValue, ParameterValue
from edagym.specs.task import (
    ChoiceDomain,
    ContractSpec,
    DifficultyAxis,
    EvaluationGraph,
    EvaluatorSpec,
    FlowQualificationSpec,
    GeneratorSpec,
    IntegerDomain,
    RequirementKind,
    RequirementSpec,
    ResourceLicense,
    ResourceSpec,
    ResourceVisibility,
    StagePurpose,
    StageSpec,
    TaskIdentity,
    TaskSpec,
    WorkspaceInterface,
)

FAMILY = "rtl_verification_repair"
DIFFICULTIES = ("single_transaction", "buffered_stream", "flush_recovery")
_DEPTHS = (1, 2, 3)
_BASE_MECHANISMS = ("backpressure", "simultaneous_transfer", "reset_priority")


@dataclass(frozen=True)
class RepairDesign:
    task: TaskSpec
    files: dict[str, bytes]
    parameters: tuple[ParameterValue, ...]
    mechanism_ids: tuple[str, ...]


def generate_repair(seed: str, difficulty: str, revision: int) -> RepairDesign:
    """Construct an engineering task and independent queue observations."""

    if difficulty not in DIFFICULTIES or revision != 1:
        raise ValueError("unsupported RTL repair difficulty or generator revision")
    level = DIFFICULTIES.index(difficulty)
    depth = _DEPTHS[level]
    width = random.Random(int(seed, 16)).choice((8, 16, 24))
    reference = _rtl(width, depth, flush=level == 2)
    negatives = {
        "stall_loss": reference.replace("pop = out_valid && out_ready", "pop = out_valid"),
        "full_overwrite": reference.replace("in_ready = (count < DEPTH) || pop", "in_ready = 1'b1"),
        "payload_corruption": reference.replace(
            "memory[write_ptr] <= in_data", "memory[write_ptr] <= ~in_data"
        ),
        "reset_masked_by_input": reference.replace(
            "if (reset", "if ((reset && !in_valid)"
        ),
    }
    if level == 2:
        negatives["ignored_flush"] = reference.replace("if (reset || flush)", "if (reset)")
    files = {
        "task/prompt.md": _prompt(width, depth, level).encode(),
        "workspace/dut.sv": negatives["stall_loss"].encode(),
        "reference/dut.sv": reference.encode(),
        "verifier/monitor.sv": _MONITOR.encode(),
        "verifier/vectors.txt": _vectors(seed, width, depth, level == 2).encode(),
        "verifier/verify.py": _VERIFY.encode(),
        "authoring/generator.py": Path(__file__).read_bytes(),
        **{f"mutants/{name}.sv": content.encode() for name, content in negatives.items()},
    }
    resource_ids = {
        "behavior": "task/prompt.md",
        "starter": "workspace/dut.sv",
        "reference": "reference/dut.sv",
        "monitor": "verifier/monitor.sv",
        "vectors": "verifier/vectors.txt",
        "verifier": "verifier/verify.py",
        "generator": "authoring/generator.py",
        **{name: f"mutants/{name}.sv" for name in negatives},
    }
    resources = tuple(
        ResourceSpec(
            resource_id=name,
            path=path,
            content_digest=content_digest(files[path]),
            media_type="text/plain",
        )
        for name, path in resource_ids.items()
    )
    generator_digest = content_digest(files["authoring/generator.py"])
    requirements = [
        RequirementSpec(
            requirement_id="ordered_payload",
            kind=RequirementKind.BEHAVIORAL,
            description="Accepted payloads emerge once, in order, without corruption.",
        ),
        RequirementSpec(
            requirement_id="backpressure",
            kind=RequirementKind.TEMPORAL,
            description="The output remains valid and stable while stalled.",
        ),
        RequirementSpec(
            requirement_id="capacity",
            kind=RequirementKind.BEHAVIORAL,
            description="The queue obeys its capacity and supports replacement transfers.",
        ),
        RequirementSpec(
            requirement_id="reset",
            kind=RequirementKind.BEHAVIORAL,
            description="A synchronous reset discards all queued transactions.",
        ),
    ]
    if level == 2:
        requirements.append(
            RequirementSpec(
                requirement_id="flush",
                kind=RequirementKind.BEHAVIORAL,
                description="Flush discards pending and same-cycle incoming transactions.",
            )
        )
    task = TaskSpec(
        identity=TaskIdentity(family=FAMILY, authoring_revision=revision),
        interface=WorkspaceInterface(submission_paths=("dut.sv",)),
        generator=GeneratorSpec(
            implementation_resource="generator",
            implementation_digest=generator_digest,
            seed_bits=128,
            parameters=(
                ChoiceDomain(
                    parameter_id="mechanism", default=DIFFICULTIES[0], choices=DIFFICULTIES
                ),
                IntegerDomain(parameter_id="data_width", default=8, minimum=8, maximum=24),
            ),
        ),
        difficulty_axes=(DifficultyAxis(axis_id="protocol_mechanism", parameter_id="mechanism"),),
        contract=ContractSpec(
            public_behavior_resource="behavior", requirements=tuple(requirements)
        ),
        resources=resources,
        visibility=tuple(
            ResourceVisibility(
                resource_id=item.resource_id,
                visibility=_visibility(item.path),
                sensitivity=Sensitivity.INTERNAL,
            )
            for item in resources
        ),
        licensing=tuple(
            ResourceLicense(
                resource_id=item.resource_id,
                spdx_expression="Apache-2.0",
                redistribution=Redistribution.FORBIDDEN,
            )
            for item in resources
        ),
        evaluation=EvaluationGraph(
            evaluators=(
                EvaluatorSpec(
                    evaluator_id="queue_monitor",
                    capability=Capability.RTL_SIMULATION,
                    supporting_capabilities=(Capability.ASIC_SYNTHESIS,),
                    implementation_resource="verifier",
                    revision_digest=content_digest(files["verifier/verify.py"]),
                ),
            ),
            stages=(
                StageSpec(
                    stage_id="queue_contract",
                    evaluator_id="queue_monitor",
                    purpose=StagePurpose.HARD_GATE,
                    requirement_ids=tuple(item.requirement_id for item in requirements),
                ),
            ),
        ),
        qualification=FlowQualificationSpec(
            authoring_source_resource="generator",
            feasibility_witness_resource="reference",
            negative_candidate_resources=tuple(negatives),
        ),
    )
    return RepairDesign(
        task=task,
        files=files,
        parameters=(
            ChoiceParameterValue(parameter_id="mechanism", value=difficulty),
            IntegerParameterValue(parameter_id="data_width", value=width),
        ),
        mechanism_ids=_BASE_MECHANISMS + (("flush_recovery",) if level == 2 else ()),
    )


def content_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _visibility(path: str) -> Visibility:
    if path.startswith(("task/", "workspace/")):
        return Visibility.PARTICIPANT
    if path.startswith("verifier/"):
        return Visibility.VERIFIER
    return Visibility.AUTHOR


def _prompt(width: int, depth: int, level: int) -> str:
    flush = (
        "Flush has reset priority and discards both queued and same-cycle input transactions."
        if level == 2
        else "The flush input is tied to zero and has no required behavior."
    )
    return f"""# Ready/Valid Queue Repair

Repair `dut.sv` for a streaming datapath. The queue stores {depth} payloads of
{width} bits. Keep the module name `dut` and all ports unchanged.

Transactions occur on rising `clk` edges when valid and ready are both high.
Output order and payload bits must match accepted input transactions exactly.
`out_valid` indicates a nonempty queue. While stalled, output remains stable.
`in_ready` is high when there is free capacity or an output transfer on the same
edge. A full queue must accept a replacement when its head is consumed.
Synchronous active-high `reset` discards the queue. {flush}

Deliver synthesizable SystemVerilog. Generated clocks, file I/O, simulation-only
behavior, external includes, black boxes and changes to the interface are invalid.
Verification synthesizes the design before applying an independent queue monitor.
"""


def _rtl(width: int, depth: int, *, flush: bool) -> str:
    clear = "reset || flush" if flush else "reset"
    read_mux = " : ".join(f"read_ptr == {index} ? memory[{index}]" for index in range(depth))
    return f"""module dut (
    input wire clk, reset, flush,
    input wire in_valid, output wire in_ready,
    input wire [{width - 1}:0] in_data,
    output wire out_valid, input wire out_ready,
    output wire [{width - 1}:0] out_data
);
    localparam integer DEPTH = {depth};
    reg [{width - 1}:0] memory [0:DEPTH-1];
    integer count, read_ptr, write_ptr;
    wire pop = out_valid && out_ready;
    wire push = in_valid && in_ready;
    assign out_valid = count != 0;
    assign in_ready = (count < DEPTH) || pop;
    assign out_data = {read_mux} : {width}'b0;
    always @(posedge clk) begin
        if ({clear}) begin
            count <= 0;
            read_ptr <= 0;
            write_ptr <= 0;
        end else begin
            case ({{push, pop}})
                2'b10: count <= count + 1;
                2'b01: count <= count - 1;
                default: count <= count;
            endcase
            if (push) begin
                memory[write_ptr] <= in_data;
                write_ptr <= write_ptr == DEPTH-1 ? 0 : write_ptr + 1;
            end
            if (pop) read_ptr <= read_ptr == DEPTH-1 ? 0 : read_ptr + 1;
        end
    end
endmodule
"""


def _vectors(seed: str, width: int, depth: int, flush_enabled: bool) -> str:
    rng = random.Random(int(seed, 16))
    queue: deque[int] = deque()
    stimulus = [
        (0, 0, 1, 0),
        *((1, 0, 0, 0),) * (depth + 2),
        *((1, 1, 0, 0),) * (depth + 2),
        (1, 0, 1, 0),
        (0, 0, 0, 0),
    ]
    if flush_enabled:
        stimulus.extend(((1, 0, 0, 0), (1, 0, 0, 1), (0, 0, 0, 0)))
    stimulus.extend(
        (
            rng.randrange(2),
            rng.randrange(2),
            int(rng.randrange(40) == 0),
            int(flush_enabled and rng.randrange(25) == 0),
        )
        for _ in range(400)
    )
    stimulus.extend((0, 1, 0, 0) for _ in range(depth + 2))
    lines = []
    for input_valid, output_ready, reset, flush in stimulus:
        data = rng.getrandbits(width)
        valid = bool(queue)
        ready = len(queue) < depth or (valid and bool(output_ready))
        expected_data = queue[0] if queue else 0
        lines.append(
            f"{reset} {flush} {input_valid} {output_ready} {data:x} "
            f"{int(ready)} {int(valid)} {expected_data:x}"
        )
        if reset or flush:
            queue.clear()
        else:
            if valid and output_ready:
                queue.popleft()
            if ready and input_valid:
                queue.append(data)
    return "\n".join(lines) + "\n"


_MONITOR = """module monitor;
    reg clk = 0;
    reg reset = 1, flush = 0, in_valid = 0, out_ready = 0;
    reg [23:0] in_data = 0;
    wire in_ready, out_valid;
    wire [23:0] out_data;
    integer source, fields, expected_ready, expected_valid, cycles;
    reg [23:0] expected_data;
    dut candidate(clk, reset, flush, in_valid, in_ready, in_data,
                  out_valid, out_ready, out_data);
    initial begin
        #1; clk = 1; #1; clk = 0;
        source = $fopen("vectors.txt", "r");
        if (!source) $fatal(1, "monitor input missing");
        cycles = 0;
        while (!$feof(source)) begin
            fields = $fscanf(source, "%d %d %d %d %h %d %d %h\\n",
                             reset, flush, in_valid, out_ready, in_data,
                             expected_ready, expected_valid, expected_data);
            if (fields != 8) $fatal(1, "malformed monitor input");
            #1;
            if (in_ready !== expected_ready[0] || out_valid !== expected_valid[0])
                $fatal(1, "handshake contract violation");
            if (expected_valid && out_data !== expected_data)
                $fatal(1, "payload contract violation");
            clk = 1; #1; clk = 0;
            cycles = cycles + 1;
        end
        $fclose(source);
        $display("EDAGYM_QUEUE_MONITOR_PASS %0d", cycles);
        $finish;
    end
endmodule
"""

_VERIFY = '''"""Trusted evaluator; only a synthesized netlist reaches the monitor."""
import json
import subprocess
from pathlib import Path

def invoke(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=30, check=False)
    return result.returncode, result.stdout.decode("utf-8", "replace")

code, output = invoke(["yosys", "-Q", "-T", "-p",
    "read_verilog -sv dut.sv; hierarchy -check -top dut; proc; flatten; "
    "opt; memory; opt; check -assert; write_verilog -noattr netlist.v"])
stage = "synthesis"
if code == 0:
    code, output = invoke(["iverilog", "-g2012", "-s", "monitor", "-o", "monitor.vvp",
                            "netlist.v", "monitor.sv"])
    stage = "monitor_compile"
if code == 0:
    code, output = invoke(["vvp", "monitor.vvp"])
    stage = "monitor_run"
passed = code == 0 and "EDAGYM_QUEUE_MONITOR_PASS " in output
Path("verification.json").write_text(json.dumps({
    "passed": passed, "stage": stage, "exit_code": code,
    "semantic_failure": stage == "monitor_run" and code != 0,
}, sort_keys=True) + "\\n")
Path("verification.log").write_text(output)
raise SystemExit(0 if passed else 1)
'''
