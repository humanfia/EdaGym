"""Queue verifier recipes: synthesize candidate-only inputs, then run a private monitor."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field

from edagym.canonical import canonical_digest
from edagym.evaluation.model import OutcomeKind
from edagym.executors.model import (
    COMPOSITE_REPORT_LOGICAL_ID,
    COMPOSITE_REPORT_PATH,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobStateKind,
    OutputDeclaration,
    ToolRecipeCommand,
)
from edagym.executors.report import CompositeCommandReport, ReportStatus
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass, Capability, Digest, StrictModel
from edagym.specs.environment import EnvironmentSpec, ToolBinding

EVALUATOR_ID = "queue_monitor"
NETLIST_ID = "synthesized_netlist"
NETLIST_PATH = "netlist.v"
MONITOR_PASS_MARKER = b"EDAGYM_QUEUE_MONITOR_PASS "
SYNTHESIS_ARGUMENTS = (
    "-Q",
    "-T",
    "-p",
    "read_verilog -sv dut.sv; hierarchy -check -top dut; proc; flatten; "
    "opt; memory; opt; check -assert; write_verilog -noattr netlist.v",
)
MONITOR_ARGUMENTS = ("-g2012", "-s", "monitor", "-o", "monitor.vvp", NETLIST_PATH, "monitor.sv")


def implementation_source() -> bytes:
    return Path(__file__).read_bytes()


def _binding(environment: EnvironmentSpec, capability: Capability) -> ToolBinding:
    matches = [item for item in environment.tool_bindings if item.capability is capability]
    if len(matches) != 1:
        raise ValueError("queue verifier requires one binding for each capability")
    return matches[0]


def synthesis_plan(
    environment: EnvironmentSpec, run_id: Digest, operation_id: str, inputs: Digest
) -> InvocationPlan:
    binding = _binding(environment, Capability.ASIC_SYNTHESIS)
    return _plan(
        binding,
        run_id,
        operation_id,
        inputs,
        ((binding.locator.executable, SYNTHESIS_ARGUMENTS),),
        (
            OutputDeclaration(
                logical_id=NETLIST_ID,
                path=NETLIST_PATH,
                media_type="text/plain",
                artifact_class=ArtifactClass.EVIDENCE,
                required=False,
            ),
        ),
    )


def simulation_plan(
    environment: EnvironmentSpec, run_id: Digest, operation_id: str, inputs: Digest
) -> InvocationPlan:
    binding = _binding(environment, Capability.RTL_SIMULATION)
    if binding.driver_id != "iverilog":
        raise ValueError("queue verifier requires the Icarus simulation contract")
    return _plan(
        binding,
        run_id,
        operation_id,
        inputs,
        ((binding.locator.executable, MONITOR_ARGUMENTS), ("vvp", ("monitor.vvp",))),
        (),
    )


def _plan(
    binding: ToolBinding,
    run_id: Digest,
    operation_id: str,
    inputs: Digest,
    commands: tuple[tuple[str, tuple[str, ...]], ...],
    outputs: tuple[OutputDeclaration, ...],
) -> InvocationPlan:
    return InvocationPlan(
        invocation_id=operation_id,
        run_id=run_id,
        capability=binding.capability,
        tool_id=binding.tool_id,
        driver_digest=binding.driver_digest,
        view=InvocationView.EVALUATOR,
        executable=binding.locator.executable,
        input_manifest_digest=inputs,
        recipe=tuple(
            ToolRecipeCommand(
                tool_id=binding.tool_id,
                capability=binding.capability,
                driver_digest=binding.driver_digest,
                executable=program,
                arguments=arguments,
            )
            for program, arguments in commands
        ),
        outputs=(
            *outputs,
            OutputDeclaration(
                logical_id=COMPOSITE_REPORT_LOGICAL_ID,
                path=COMPOSITE_REPORT_PATH,
                media_type="application/json",
                artifact_class=ArtifactClass.EVIDENCE,
            ),
        ),
    )


def outcome(
    plan: InvocationPlan, result: ExecutionResult, store: ContentAddressedStore, *, simulation: bool
) -> tuple[OutcomeKind, bool]:
    if result.state.state is not JobStateKind.COMPLETED:
        failures: dict[ExecutionFailureKind | None, OutcomeKind] = {
            ExecutionFailureKind.TIMEOUT: OutcomeKind.TIMEOUT,
            ExecutionFailureKind.SECURITY_VIOLATION: OutcomeKind.SECURITY_VIOLATION,
            ExecutionFailureKind.CANDIDATE: OutcomeKind.CANDIDATE_FAILURE,
        }
        failures[ExecutionFailureKind.LICENSE_UNAVAILABLE] = OutcomeKind.LICENSE_UNAVAILABLE
        return failures.get(result.state.failure, OutcomeKind.INFRASTRUCTURE_FAILURE), False
    output = next(
        (item for item in result.outputs if item.logical_id == COMPOSITE_REPORT_LOGICAL_ID), None
    )
    if output is None:
        raise ValueError("verifier operation has no trusted command report")
    report = CompositeCommandReport.model_validate_json(
        store.read_bytes(output.blob, maximum_bytes=1024 * 1024)
    )
    stdout = store.read_bytes(result.stdout, maximum_bytes=8 * 1024 * 1024)
    stderr = store.read_bytes(result.stderr, maximum_bytes=8 * 1024 * 1024)
    report.verify(plan.recipe, stdout, stderr)
    if report.status is not ReportStatus.COMPLETED or any(
        item.failure is not None for item in report.commands
    ):
        return OutcomeKind.INFRASTRUCTURE_FAILURE, False
    final = report.commands[-1]
    actual = report.commands
    expected = plan.recipe
    runnable = simulation and len(actual) == len(expected)
    if final.exit_code != 0:
        return (OutcomeKind.COUNTEREXAMPLE if runnable else OutcomeKind.CANDIDATE_FAILURE), runnable
    if simulation and MONITOR_PASS_MARKER not in stdout:
        return OutcomeKind.INFRASTRUCTURE_FAILURE, False
    return OutcomeKind.PASSED, runnable


class QueueOracleContract(StrictModel):
    capacity: int = Field(strict=True, ge=1)
    width: int = Field(strict=True, ge=1, le=24)
    flush_enabled: bool


class QueueOracleEvidence(StrictModel):
    contract_digest: Digest
    vectors_digest: Digest
    checker_digest: Digest
    checked_cycles: int = Field(strict=True, ge=1)

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="queue-oracle-evidence-v1")


def check_oracle(contract: QueueOracleContract, vectors: bytes) -> QueueOracleEvidence:
    """Validate generated expectations with an independent indexed FIFO model.

    The generator uses a deque. This checker tracks cumulative reads/writes over
    a bounded slot array and consumes only the declared contract and stimuli.
    It neither imports the generator nor reads the reference RTL.
    """
    import hashlib

    slots = [0] * contract.capacity
    reads = writes = cycles = 0
    for line in vectors.decode("ascii").splitlines():
        words = line.split()
        if len(words) != 8:
            raise ValueError("queue oracle row has an invalid width")
        reset, flush, valid, ready = (int(word) for word in words[:4])
        data = int(words[4], 16)
        expected_ready, expected_valid = (int(word) for word in words[5:7])
        expected_data = int(words[7], 16)
        if any(
            bit not in (0, 1)
            for bit in (reset, flush, valid, ready, expected_ready, expected_valid)
        ):
            raise ValueError("queue oracle control value is not a bit")
        if (flush and not contract.flush_enabled) or not 0 <= data < (1 << contract.width):
            raise ValueError("queue oracle stimulus differs from its contract")
        occupancy = writes - reads
        can_read = occupancy > 0
        can_write = occupancy < contract.capacity or (can_read and bool(ready))
        if (expected_valid, expected_ready) != (int(can_read), int(can_write)):
            raise ValueError("queue oracle handshake expectation is inconsistent")
        if expected_data != (slots[reads % contract.capacity] if can_read else 0):
            raise ValueError("queue oracle data expectation is inconsistent")
        if reset or flush:
            reads = writes = 0
        else:
            if can_read and ready:
                reads += 1
            if can_write and valid:
                slots[writes % contract.capacity] = data
                writes += 1
        cycles += 1
    return QueueOracleEvidence(
        contract_digest=canonical_digest(contract, domain="queue-oracle-contract-v1"),
        vectors_digest="sha256:" + hashlib.sha256(vectors).hexdigest(),
        checker_digest="sha256:" + hashlib.sha256(implementation_source()).hexdigest(),
        checked_cycles=cycles,
    )
