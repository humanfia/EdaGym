"""Security evidence for controller-side workspace and EDA participant tools."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from edagym.participants import (
    CheckpointParticipantTool,
    EdaInvocationTool,
    ParticipantAdapterError,
    ParticipantFailureKind,
    ParticipantView,
    ToolObservation,
    ToolObservationOutcome,
    WorkspaceReadTool,
    WorkspaceWriteTool,
)
from tests.factories import digest


def _view() -> ParticipantView:
    return ParticipantView(
        run_id=digest("workspace-tool-run"),
        task_family="workspace_tool_task",
        authoring_revision=1,
        actor_id="solver",
    )


def test_workspace_tools_are_allowlisted_atomic_and_symlink_safe(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (workspace / "link.txt").symlink_to(outside)
    os.link(outside, workspace / "linked.txt")

    writer = WorkspaceWriteTool(
        workspace,
        paths=("candidate/design.sv", "link.txt", "linked.txt"),
    )
    reader = WorkspaceReadTool(
        workspace,
        paths=("candidate/design.sv", "link.txt", "linked.txt"),
    )
    content = "module design; endmodule\n"
    result = writer.invoke(
        json.dumps({"path": "candidate/design.sv", "content": content}),
        _view(),
    )

    assert result.output == f"wrote {len(content)} bytes"
    assert reader.invoke(json.dumps({"path": "candidate/design.sv"}), _view()).output == content
    assert outside.read_text(encoding="utf-8") == "outside"

    for path in ("link.txt", "linked.txt"):
        with pytest.raises(ParticipantAdapterError) as rejected:
            writer.invoke(json.dumps({"path": path, "content": "changed"}), _view())
        assert rejected.value.kind is ParticipantFailureKind.CHANNEL_FAILURE
        with pytest.raises(ParticipantAdapterError) as rejected_read:
            reader.invoke(json.dumps({"path": path}), _view())
        assert rejected_read.value.kind is ParticipantFailureKind.CHANNEL_FAILURE
    assert outside.read_text(encoding="utf-8") == "outside"


class _Dispatcher:
    operation_ids = ("simulate_candidate",)

    def __init__(self) -> None:
        self.operation_id: str | None = None

    def invoke(
        self,
        *,
        operation_id: str,
        view: ParticipantView,
    ) -> ToolObservation:
        assert operation_id == "simulate_candidate"
        assert view.actor_id == "solver"
        self.operation_id = operation_id
        return ToolObservation(
            outcome=ToolObservationOutcome.PASSED,
            summary="simulation passed",
            artifact_refs=("simulation_report",),
        )


def test_eda_and_checkpoint_tools_preserve_typed_controller_boundaries() -> None:
    dispatcher = _Dispatcher()
    tool = EdaInvocationTool(dispatcher)
    result = tool.invoke(json.dumps({"operation_id": "simulate_candidate"}), _view())
    assert dispatcher.operation_id == "simulate_candidate"
    assert json.loads(result.output or "null") == {
        "artifact_refs": ["simulation_report"],
        "outcome": "passed",
        "summary": "simulation passed",
    }
    assert result.artifact_refs == ("simulation_report",)

    for injected in (
        {
            "operation_id": "simulate_candidate",
            "arguments_json": json.dumps(["-f", "../../host.tcl"]),
        },
        {"operation_id": "../../host-script"},
    ):
        with pytest.raises(ParticipantAdapterError) as rejected:
            tool.invoke(json.dumps(injected), _view())
        assert rejected.value.kind is ParticipantFailureKind.INVALID_INTENT

    with pytest.raises(ParticipantAdapterError) as rejected:
        tool.invoke(
            json.dumps({"operation_id": "unknown_operation"}),
            _view(),
        )
    assert rejected.value.kind is ParticipantFailureKind.INVALID_INTENT

    checkpoints: list[str] = []
    checkpoint = CheckpointParticipantTool(
        lambda checkpoint_id: (
            checkpoints.append(checkpoint_id)
            or ToolObservation(
                outcome=ToolObservationOutcome.PASSED,
                summary="checkpoint committed",
            )
        )
    )
    checkpoint.invoke(json.dumps({"checkpoint_id": "agent_state"}), _view())
    assert checkpoints == ["agent_state"]
