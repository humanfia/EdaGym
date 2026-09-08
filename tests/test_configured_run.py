"""Real-tool evidence for the configured run and its public interaction boundary."""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import signal
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from edagym.authoring.factory import GeneratedTask, GenerationRequest, TaskFactory
from edagym.authoring.qualification import QualificationRunEvidence
from edagym.canonical import canonical_digest
from edagym.config import initialize_config, resolve_profile
from edagym.config.model import EdaGymConfig, PrivateConfigSnapshot
from edagym.evaluation.model import OutcomeKind
from edagym.executors.model import ExecutionFailureKind, JobStateKind
from edagym.executors.rootless import _InvocationReceipt
from edagym.policy.runtime_storage import PrivateStorageError
from edagym.run.journal import RunJournal
from edagym.run.model import (
    EditPayload,
    EnginePhase,
    IntentKind,
    InteractionIntent,
    Principal,
    ToolPayload,
    TransferPayload,
)
from edagym.runtime.engine import RunEngine
from edagym.specs.release import QualificationStatus
from edagym.web.app import create_web_app
from tests.test_executor_boundaries import _OPEN_EDA_DIGEST, _OPEN_EDA_REFERENCE, _rootless_runtime


@pytest.fixture(scope="module")
def configured_task(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[EdaGymConfig, PrivateConfigSnapshot, GeneratedTask]:
    root = tmp_path_factory.mktemp("configured-runtime")
    config = initialize_config(root / "config.toml", root / "state")
    document = config.model_dump(mode="python")
    document["runtimes"] = [
        {
            "runtime_id": "image",
            "image_reference": _OPEN_EDA_REFERENCE,
            "image_digest": _OPEN_EDA_DIGEST,
            "architecture": "amd64",
            "launcher_executable": "python3.12",
        }
    ]
    document["tools"] = []
    for adapter_id, capability in (("iverilog", "rtl.simulation"), ("yosys", "asic.synthesis")):
        _, installation, _ = _rootless_runtime(adapter_id)
        document["tools"].append(
            {
                "tool_id": adapter_id,
                "adapter_id": adapter_id,
                "source": {
                    "kind": "user_image",
                    "runtime_id": "image",
                    "executable": installation.executable_name,
                    "image_digest": _OPEN_EDA_DIGEST,
                },
                "version_label": installation.version_label,
                "capabilities": [capability],
            }
        )
    profile = document["profiles"][0]
    for view in ("participant", "evaluator"):
        profile[view] = {
            "runtime_id": "image",
            "tool_ids": ["iverilog", "yosys"],
            "tool_visibility": "declared_bundle",
        }
    profile["resources"] = {
        "cpu_millicores": 250,
        "memory_bytes": 128 * 1024**2,
        "process_count": 32,
        "wall_seconds": 20,
    }
    profile["storage"] = {"max_bytes": 64 * 1024**2, "output_max_bytes": 32 * 1024**2}
    config = EdaGymConfig.model_validate(document)
    pair = resolve_profile(config, "default")
    (generated,) = TaskFactory().generate(
        GenerationRequest(
            family="rtl_verification_repair",
            difficulty="single_transaction",
            seed="1" * 32,
            count=1,
        ),
        site=pair.site,
    )
    qualified = RunEngine(pair.site.state_root).qualify_task(
        generated,
        pair.snapshot,
        config.sessions[0].session_id,
        Principal(principal_id=config.web.principal_id),
    )
    assert qualified.instance.qualification is not None
    assert qualified.instance.qualification.status is QualificationStatus.QUALIFIED
    return config, pair.snapshot, qualified


def test_http_submission_handoff_and_private_evidence(
    configured_task: tuple[EdaGymConfig, PrivateConfigSnapshot, GeneratedTask],
) -> None:
    config, snapshot, qualified = configured_task
    app = create_web_app(config)
    origin = f"http://{config.web.host}"
    headers = {"Authorization": f"Bearer {app.token}", "Origin": origin}

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=origin, headers=headers
        ) as client:
            created = await client.post(
                "/api/runs",
                headers={"Idempotency-Key": "create_handoff"},
                json={
                    "instance_id": qualified.instance_id,
                    "profile_id": "default",
                    "session_id": config.sessions[0].session_id,
                },
            )
            assert created.status_code == 201, created.text
            run_id = created.json()["run_id"]
            path = f"/api/runs/{run_id}"
            denied = await client.get(path + "/file", params={"path": "reference/dut.sv"})
            assert denied.status_code == 404
            rejected = await client.post(
                path + "/intents",
                headers={"Idempotency-Key": "starter"},
                json={"kind": "submit", "payload": {"candidate_id": "starter"}},
            )
            assert rejected.status_code == 202, rejected.text
            assert (await client.get(path)).json()["evaluations"][-1]["outcome"] == "counterexample"
            transferred = await client.post(
                path + "/intents",
                headers={"Idempotency-Key": "handoff"},
                json={"kind": "transfer_control", "payload": {"next_writer": "agent"}},
            )
            assert transferred.status_code == 202
            blocked = await client.post(
                path + "/intents",
                headers={"Idempotency-Key": "stale_writer"},
                json={"kind": "edit", "payload": {"path": "dut.sv", "content": "invalid"}},
            )
            assert blocked.status_code == 409
            agent = Principal(principal_id="agent", allowed_run_ids=(run_id,))
            engine = RunEngine(snapshot.configuration.sites[0].state_root)
            await asyncio.to_thread(
                engine.submit_intent,
                run_id,
                InteractionIntent(
                    intent_id="repair",
                    idempotency_key="repair",
                    actor_id="agent",
                    kind=IntentKind.EDIT,
                    payload=EditPayload(
                        path="dut.sv", content=qualified.contents["reference/dut.sv"].decode()
                    ),
                ),
                agent,
            )
            await asyncio.to_thread(
                engine.submit_intent,
                run_id,
                InteractionIntent(
                    intent_id="return_control",
                    idempotency_key="return_control",
                    actor_id="agent",
                    kind=IntentKind.TRANSFER_CONTROL,
                    payload=TransferPayload(next_writer=config.web.principal_id),
                ),
                agent,
            )
            payload = {"kind": "submit", "payload": {"candidate_id": "repaired"}}
            accepted = await client.post(
                path + "/intents", headers={"Idempotency-Key": "repaired"}, json=payload
            )
            assert accepted.status_code == 202, accepted.text
            repeated = await client.post(
                path + "/intents", headers={"Idempotency-Key": "repaired"}, json=payload
            )
            assert repeated.status_code == 202 and repeated.json()["duplicate"]
            projection = (await client.get(path)).json()
            assert projection["terminal_reason"] == "task_passed"
            assert projection["evaluations"][-1]["outcome"] == OutcomeKind.PASSED.value
            stream = await client.get(path + "/events")
            assert stream.headers["content-type"].startswith("text/event-stream")
            events = [
                json.loads(block.removeprefix("data: "))
                for block in stream.text.split("\n\n")
                if block.startswith("data: ")
            ]
            assert all(event["visibility"] in {"public", "participant"} for event in events)
            assert not any(event["kind"].startswith("operation_") for event in events)
            resumed = await client.post(path + "/resume", headers={"Idempotency-Key": "resume"})
            assert resumed.status_code == 200 and resumed.json() == projection
            assert engine.gc(run_id, Principal(principal_id=config.web.principal_id))

    asyncio.run(exercise())


def test_http_cancel_reaches_a_running_tool(
    configured_task: tuple[EdaGymConfig, PrivateConfigSnapshot, GeneratedTask],
) -> None:
    config, snapshot, qualified = configured_task
    app = create_web_app(config)
    origin = f"http://{config.web.host}"
    headers = {"Authorization": f"Bearer {app.token}", "Origin": origin}

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=origin, headers=headers
        ) as client:
            response = await client.post(
                "/api/runs",
                headers={"Idempotency-Key": "create_cancel"},
                json={
                    "instance_id": qualified.instance_id,
                    "profile_id": "default",
                    "session_id": config.sessions[0].session_id,
                },
            )
            assert response.status_code == 201, response.text
            run_id = response.json()["run_id"]
            path = f"/api/runs/{run_id}"
            pending = asyncio.create_task(
                client.post(
                    path + "/intents",
                    headers={"Idempotency-Key": "long_tool"},
                    json={
                        "kind": "tool",
                        "payload": {"tool_id": "yosys", "arguments": ["-p", "exec -- sleep 120"]},
                    },
                )
            )
            journal = RunJournal.open(snapshot.configuration.sites[0].state_root / "runs" / run_id)
            deadline = time.monotonic() + 120
            while not any(
                operation.running is not None for operation in journal.state().operations
            ):
                assert not pending.done(), (await pending).text
                assert time.monotonic() < deadline
                await asyncio.sleep(0.05)
            cancelled = await client.post(
                path + "/intents",
                headers={"Idempotency-Key": "cancel_tool"},
                json={"kind": "cancel", "payload": {}},
            )
            assert cancelled.status_code == 202, cancelled.text
            result = await pending
            assert result.status_code == 202, result.text
            state = journal.state()
            assert state.projection.phase is EnginePhase.TERMINAL
            assert state.projection.terminal_reason == "explicit_cancel"
            assert state.operations[-1].terminal is not None
            assert (
                state.operations[-1].terminal.payload.result.state.failure
                is ExecutionFailureKind.CANCELLED
            )
            assert app.engine.gc(run_id, app.principal)

    asyncio.run(exercise())


def test_resume_requires_published_qualification_and_recovers_derived_evidence(
    configured_task: tuple[EdaGymConfig, PrivateConfigSnapshot, GeneratedTask],
) -> None:
    config, snapshot, qualified = configured_task
    state_root = snapshot.configuration.sites[0].state_root
    engine = RunEngine(state_root)
    principal = Principal(principal_id=config.web.principal_id)
    run = engine.prepare_task(qualified, snapshot, config.sessions[0].session_id, principal)
    journal = RunJournal.open(state_root / "runs" / run.run_id)
    before = journal.record()
    name = canonical_digest(
        qualified.instance.qualification, domain="task-qualification-evidence-v1"
    )[7:]
    receipt = state_root / "qualifications" / "tasks" / f"{name}.json"
    content = receipt.read_bytes()
    evidence = QualificationRunEvidence.model_validate_json(content)
    source = RunJournal.open(state_root / "runs" / evidence.run_id)
    publication = source.record()
    receipt.unlink()
    try:
        with pytest.raises(PrivateStorageError):
            engine.resume(run.run_id, principal)
        assert journal.record() == before
        engine.resume(evidence.run_id, principal)
        assert receipt.read_bytes() == content
        assert source.record() == publication
        assert engine.resume(run.run_id, principal) == run
    finally:
        if not receipt.exists():
            engine.resume(evidence.run_id, principal)
        engine.cancel(run.run_id, principal)
        engine.gc(run.run_id, principal)


def _tool_controller(state_root: Path, run_id: str, principal_id: str) -> None:
    RunEngine(state_root).submit_intent(
        run_id,
        InteractionIntent(
            intent_id="lost_tool",
            idempotency_key="lost_tool",
            actor_id=principal_id,
            kind=IntentKind.TOOL,
            payload=ToolPayload(tool_id="yosys", arguments=("-p", "exec -- sleep 120")),
        ),
        Principal(principal_id=principal_id),
    )


def test_lost_launch_receipt_fences_the_operation_without_reexecution(
    configured_task: tuple[EdaGymConfig, PrivateConfigSnapshot, GeneratedTask],
) -> None:
    config, snapshot, qualified = configured_task
    state_root = snapshot.configuration.sites[0].state_root
    engine = RunEngine(state_root)
    principal = Principal(principal_id=config.web.principal_id)
    run = engine.prepare_task(qualified, snapshot, config.sessions[0].session_id, principal)
    journal = RunJournal.open(state_root / "runs" / run.run_id)
    controller = multiprocessing.get_context("spawn").Process(
        target=_tool_controller, args=(state_root, run.run_id, principal.principal_id)
    )
    controller.start()
    try:
        deadline = time.monotonic() + 120
        while not any(operation.running is not None for operation in journal.state().operations):
            assert controller.is_alive(), "controller exited before launch"
            assert time.monotonic() < deadline
            time.sleep(0.05)
        controller.kill()
        controller.join(10)
        assert controller.exitcode == -signal.SIGKILL
    finally:
        if controller.is_alive():
            controller.kill()
            controller.join(10)
        controller.close()
    (operation,) = journal.state().operations
    plan = operation.prepared.payload.plan
    receipt_path = (
        journal.directory / plan.view.value / "jobs" / plan.invocation_id / "invocation.json"
    )
    receipt = _InvocationReceipt.model_validate_json(receipt_path.read_bytes())
    receipt_path.unlink()
    recovered = engine.resume(run.run_id, principal)
    assert recovered.phase is EnginePhase.TERMINAL
    assert recovered.terminal_reason == "infrastructure_failure"
    (finished,) = journal.state().operations
    assert finished.prepared == operation.prepared
    assert finished.terminal is not None
    assert finished.terminal.payload.result.state.state is JobStateKind.LOST
    assert finished.terminal.payload.result.state.failure is ExecutionFailureKind.INFRASTRUCTURE
    assert finished.terminal.payload.result.state.exit_code is None
    record = journal.record()
    assert engine.resume(run.run_id, principal) == recovered
    assert journal.record() == record
    assert engine.gc(run.run_id, principal)
    observed = subprocess.run(
        ["/usr/bin/podman", "container", "exists", receipt.container_name], check=False
    )
    assert observed.returncode == 1
