"""External CLI contracts and one complete journal lifecycle."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from pytest import CaptureFixture

from edagym.canonical import canonical_bytes
from edagym.cli import main
from edagym.config import initialize_config
from edagym.participants import json_line_human_adapter_digest
from edagym.specs.session import (
    HandoffWriter,
    HarnessActor,
    HumanActor,
    SessionSpec,
)
from tests.factories import (
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def _write_document(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")


def test_tool_qualification_requires_execution_evidence(
    tmp_path: Path, capfd: CaptureFixture[str]
) -> None:
    config_path = tmp_path / "config.toml"
    initialize_config(config_path, tmp_path / "state")
    status = main(["--config", str(config_path), "tool", "qualify", "--profile", "default"])
    output = json.loads(capfd.readouterr().out)
    assert status != 0
    assert output["status"] == "unavailable"
    assert output["reasons"] == ["execution_qualification_required"]
    assert str(tmp_path) not in json.dumps(output)
    assert "config_digest" not in output


def _documents(root: Path) -> dict[str, Path]:
    task = task_spec()
    environment = environment_spec()
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    paths = {
        "task": root / "task.json",
        "instance": root / "instance.json",
        "release": root / "release.json",
        "environment": root / "environment.json",
        "session": root / "session.json",
    }
    for name, value in (
        ("task", task),
        ("instance", instance),
        ("release", release),
        ("environment", environment),
        ("session", session),
    ):
        _write_document(paths[name], value)
    return paths


def test_cli_declares_the_supported_command_contract(
    capfd: CaptureFixture[str],
) -> None:
    expected = {
        "backend": ("list", "probe", "qualify"),
        "campaign": ("inspect", "discover", "freeze", "run", "resume", "report"),
        "task": ("validate", "generate", "qualify", "release"),
        "environment": ("resolve", "verify"),
        "run": (
            "start",
            "status",
            "events",
            "checkpoint",
            "resume",
            "submit",
            "human-turn",
            "cancel",
        ),
        "export": ("atif", "harbor", "humanize", "nemo"),
    }
    for command, children in expected.items():
        with pytest.raises(SystemExit) as stopped:
            main([command, "--help"])
        assert stopped.value.code == 0
        output = capfd.readouterr().out
        assert all(child in output for child in children)
    with pytest.raises(SystemExit) as stopped:
        main(["--help"])
    assert stopped.value.code == 0
    output = capfd.readouterr().out
    assert "doctor" in output
    assert "evaluate" in output
    assert "report" in output
    assert "release-report" in output


def test_cli_run_lifecycle_preserves_journal_and_checkpoint_evidence(
    tmp_path: Path,
    capfd: CaptureFixture[str],
) -> None:
    paths = _documents(tmp_path)
    state_root = tmp_path / "state"
    base_inputs = [
        "--task",
        str(paths["task"]),
        "--instance",
        str(paths["instance"]),
        "--release",
        str(paths["release"]),
        "--environment",
        str(paths["environment"]),
        "--session",
        str(paths["session"]),
        "--trial-key",
        "cli_contract",
    ]
    assert main(["run", "start", *base_inputs, "--state-root", str(state_root)]) == 0
    started = json.loads(capfd.readouterr().out)
    run_directory = Path(started["directory"])
    assert started["next_sequence"] == 1

    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    (candidate_root / "design.sv").write_text("module candidate; endmodule\n", encoding="utf-8")
    store_root = tmp_path / "artifacts"
    submission = [
        "run",
        "submit",
        str(run_directory),
        "--task",
        str(paths["task"]),
        "--environment",
        str(paths["environment"]),
        "--session",
        str(paths["session"]),
        "--store-root",
        str(store_root),
        "--candidate-id",
        "candidate_a",
        "--candidate-root",
        str(candidate_root),
    ]
    assert main(submission) == 0
    submitted = json.loads(capfd.readouterr().out)
    assert submitted["run"]["candidates"][0]["candidate_id"] == "candidate_a"
    assert (
        submitted["run"]["candidates"][0]["digest"]
        == (submitted["run"]["artifacts"][0]["blob"]["digest"])
    )
    assert main(submission) == 0
    repeated_submission = json.loads(capfd.readouterr().out)
    assert repeated_submission["run"]["next_sequence"] == submitted["run"]["next_sequence"]

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="utf-8")
    recovery = [
        "--environment",
        str(paths["environment"]),
        "--session",
        str(paths["session"]),
        "--store-root",
        str(store_root),
        "--checkpoint-id",
        "candidate_a_checkpoint",
    ]
    assert (
        main(
            [
                "run",
                "checkpoint",
                str(run_directory),
                "--task",
                str(paths["task"]),
                *recovery,
                "--workspace",
                str(workspace),
            ]
        )
        == 0
    )
    checkpointed = json.loads(capfd.readouterr().out)
    assert checkpointed["checkpoint"]["checkpoint_id"] == "candidate_a_checkpoint"
    assert checkpointed["run"]["checkpoint_ids"] == ["candidate_a_checkpoint"]
    assert (
        main(
            [
                "run",
                "checkpoint",
                str(run_directory),
                "--task",
                str(paths["task"]),
                *recovery,
                "--workspace",
                str(workspace),
            ]
        )
        == 0
    )
    repeated = json.loads(capfd.readouterr().out)
    assert repeated["run"]["next_sequence"] == checkpointed["run"]["next_sequence"]

    restored = tmp_path / "restored"
    assert (
        main(
            [
                "run",
                "resume",
                str(run_directory),
                "--task",
                str(paths["task"]),
                *recovery,
                "--destination",
                str(restored),
            ]
        )
        == 0
    )
    capfd.readouterr()
    assert (restored / "design.sv").read_text(encoding="utf-8") == ("module design; endmodule\n")

    assert main(["export", "atif", str(run_directory), "--task", str(paths["task"])]) == 0
    trajectory = json.loads(capfd.readouterr().out)
    assert trajectory["trajectory_id"] == started["run_id"]

    assert (
        main(
            [
                "export",
                "humanize",
                str(run_directory),
                "--task",
                str(paths["task"]),
                "--session",
                str(paths["session"]),
                "--audience",
                "reviewer",
            ]
        )
        == 0
    )
    humanize = json.loads(capfd.readouterr().out)
    assert humanize["cycle"]["run_id"] == started["run_id"]
    assert humanize["cycle"]["session_strategy"] == "stateful"
    assert humanize["cycle"]["reviewer"]["completion_authority"] == "edagym_verifier"

    assert main(["run", "cancel", str(run_directory), "--task", str(paths["task"])]) == 0
    cancelled = json.loads(capfd.readouterr().out)
    assert cancelled["terminal_reason"] == "explicit_cancel"

    assert main(["export", "harbor", str(run_directory), "--task", str(paths["task"])]) == 0
    harbor = json.loads(capfd.readouterr().out)
    assert harbor["reward"]["reward"] == 0

    assert main(["run", "events", str(run_directory), "--task", str(paths["task"])]) == 0
    events = json.loads(capfd.readouterr().out)
    assert [event["kind"] for event in events] == [
        "run_started",
        "artifact_recorded",
        "candidate_submitted",
        "artifact_recorded",
        "checkpoint_committed",
        "run_ended",
    ]


def test_cli_reports_unknown_backend_without_internal_details(
    capfd: CaptureFixture[str],
) -> None:
    assert main(["backend", "probe", "unknown_backend", "--json"]) == 2
    captured = capfd.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": "unknown-backend"}


def test_cli_human_turn_commits_an_attributed_single_writer_handoff(
    tmp_path: Path,
    capfd: CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = task_spec()
    environment = environment_spec()
    base = session_spec()
    session = SessionSpec(
        session_id="interactive_hybrid",
        mode=base.mode,
        actors=(
            HumanActor(
                actor_id="student",
                adapter_id="json_line",
                adapter_digest=json_line_human_adapter_digest(),
            ),
            HarnessActor(
                actor_id="solver",
                harness_id="external_solver",
                harness_digest=base.actors[0].harness_digest,
                scaffold_digest=base.actors[0].scaffold_digest,
                requested_model_route=base.actors[0].requested_model_route,
            ),
        ),
        writer=HandoffWriter(initial_writer="student"),
        feedback=base.feedback,
        recovery=base.recovery,
        resources=base.resources,
        model_budget=base.model_budget,
    )
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    documents = {
        "task": tmp_path / "task.json",
        "instance": tmp_path / "instance.json",
        "release": tmp_path / "release.json",
        "environment": tmp_path / "environment.json",
        "session": tmp_path / "session.json",
    }
    for name, value in (
        ("task", task),
        ("instance", instance),
        ("release", release),
        ("environment", environment),
        ("session", session),
    ):
        _write_document(documents[name], value)

    state_root = tmp_path / "state"
    assert (
        main(
            [
                "run",
                "start",
                "--task",
                str(documents["task"]),
                "--instance",
                str(documents["instance"]),
                "--release",
                str(documents["release"]),
                "--environment",
                str(documents["environment"]),
                "--session",
                str(documents["session"]),
                "--trial-key",
                "human_handoff",
                "--state-root",
                str(state_root),
            ]
        )
        == 0
    )
    started = json.loads(capfd.readouterr().out)
    monkeypatch.setattr(
        "sys.stdin",
        StringIO('{"kind":"transfer_control","next_writer":"solver"}\n'),
    )

    assert (
        main(
            [
                "run",
                "human-turn",
                started["directory"],
                "--task",
                str(documents["task"]),
                "--session",
                str(documents["session"]),
            ]
        )
        == 0
    )
    output = capfd.readouterr()
    view = json.loads(output.out)
    assert view["actor_id"] == "student"
    assert set(view) == {
        "actor_id",
        "authoring_revision",
        "candidates",
        "feedback",
        "protocol_version",
        "run_id",
        "scoring",
        "task_family",
    }
    assert output.err == ""

    assert (
        main(
            [
                "run",
                "events",
                started["directory"],
                "--task",
                str(documents["task"]),
            ]
        )
        == 0
    )
    events = json.loads(capfd.readouterr().out)
    transfer = events[-1]
    assert transfer["kind"] == "control_transferred"
    assert transfer["actor"] == "student"
    assert transfer["payload"] == {
        "next_writer": "solver",
        "previous_writer": "student",
    }
