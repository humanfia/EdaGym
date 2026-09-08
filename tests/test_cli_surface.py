"""External CLI configuration, frozen-run, and disclosure contracts."""

from __future__ import annotations

import json
from pathlib import Path

from pytest import CaptureFixture

from edagym.cli import main
from edagym.config import initialize_config


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


def test_cli_reports_unknown_backend_without_internal_details(
    capfd: CaptureFixture[str],
) -> None:
    assert main(["backend", "probe", "unknown_backend", "--json"]) == 2
    captured = capfd.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": "unknown-backend"}


def test_cli_resume_uses_the_frozen_snapshot_and_replays_unavailable_runs(
    tmp_path: Path, capfd: CaptureFixture[str]
) -> None:
    config_path = tmp_path / "config.toml"
    state_root = tmp_path / "state"
    assert main(["init", "--config", str(config_path), "--root", str(state_root)]) == 0
    capfd.readouterr()
    configured = ["--config", str(config_path)]
    assert (
        main(
            [
                *configured,
                "task",
                "generate",
                "--family",
                "rtl_verification_repair",
                "--difficulty",
                "single_transaction",
                "--seed",
                "1" * 32,
                "--profile",
                "default",
            ]
        )
        == 3
    )
    (generated,) = json.loads(capfd.readouterr().out)
    assert (
        main(
            [
                *configured,
                "run",
                "start",
                "--instance",
                generated["instance_id"],
                "--profile",
                "default",
                "--session",
                "human",
            ]
        )
        == 3
    )
    started = json.loads(capfd.readouterr().out)
    run_id = started["run_id"]
    assert started["phase"] == "unavailable"
    assert started["unavailable_reason"]
    assert str(tmp_path) not in json.dumps(started)
    directory = state_root / "runs" / run_id
    frozen = {name: (directory / name).read_bytes() for name in ("manifest.json", "snapshot.json")}

    config_path.write_text(
        config_path.read_text().replace("max_concurrency = 1", "max_concurrency = 2")
    )
    for command in ("resume", "resume", "status"):
        assert main([*configured, "run", command, run_id]) == 0
        assert json.loads(capfd.readouterr().out) == started
    assert {name: (directory / name).read_bytes() for name in frozen} == frozen

    assert main([*configured, "run", "events", run_id]) == 0
    stream = json.loads(capfd.readouterr().out)
    assert [event["kind"] for event in stream["events"]] == ["run_prepared", "run_unavailable"]
    assert stream["terminal"]
    assert (
        main([*configured, "run", "events", run_id, "--cursor", str(stream["cursor"]["sequence"])])
        == 0
    )
    assert json.loads(capfd.readouterr().out)["events"] == []

    assert main([*configured, "run", "checkpoint", run_id]) == 3
    rejected = capfd.readouterr()
    assert rejected.out == ""
    assert str(tmp_path) not in rejected.err
    assert main([*configured, "run", "status", run_id]) == 0
    assert json.loads(capfd.readouterr().out) == started
