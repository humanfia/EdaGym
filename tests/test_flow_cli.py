"""CLI evidence for journaled non-Sail flow execution."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from edagym.canonical import canonical_bytes
from edagym.cli import main
from edagym.cli_support.backends import FlowHostBindings, resolve_flow_host_bindings
from edagym.cli_support.errors import CliFailure
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.assets import asset_content_digest
from edagym.run.model import RunRecord
from edagym.specs.environment import (
    AssetBinding,
    EnvironmentSpec,
    FilesystemScope,
    ReadonlyAssetMount,
)
from edagym.specs.release import FlowReleaseQualification
from tests.factories import digest
from tests.test_flow_runtime import (
    _environment_for,
    _runtime_pack,
    _synthetic_flow_catalog,
    _synthetic_provider_canonical,
)


def test_flow_cli_qualification_and_evaluation_emit_canonical_records(
    tmp_path: Path,
    capfd: CaptureFixture[str],
    monkeypatch: MonkeyPatch,
) -> None:
    pack = _runtime_pack()
    canonical = _synthetic_provider_canonical(pack)
    asset_path = tmp_path / "evaluator-library.dat"
    asset_path.write_bytes(b"sealed evaluator library\n")
    asset_path.chmod(0o600)
    base_environment = _environment_for(pack)
    environment = EnvironmentSpec.model_validate(
        {
            **base_environment.model_dump(mode="python"),
            "assets": (
                AssetBinding(
                    asset_id="evaluator_library",
                    restricted_digest=asset_content_digest(asset_path),
                    allowed_scopes=(FilesystemScope.EVALUATOR,),
                ),
            ),
            "filesystem": base_environment.filesystem.model_copy(
                update={
                    "readonly_assets": (
                        ReadonlyAssetMount(
                            asset_id="evaluator_library",
                            scope=FilesystemScope.EVALUATOR,
                            target="/eda-assets/evaluator-library.dat",
                        ),
                    ),
                }
            ),
        }
    )
    environment_path = tmp_path / "environment.json"
    environment_path.write_bytes(canonical_bytes(environment) + b"\n")
    host_bindings = FlowHostBindings(
        tool_paths={"verilator": Path(sys.executable)},
        tool_environments={"verilator": {}},
        tool_closures={},
        site_container_configurations={},
        license_providers={},
        asset_source_policy=load_system_asset_source_policy(),
    )
    catalog = _synthetic_flow_catalog(pack, canonical)
    monkeypatch.setattr("edagym.cli._private_flow_catalog", lambda _arguments: catalog)
    provider_arguments = (
        "--authoring-provider",
        str(tmp_path / "provider"),
        "--authoring-provider-executable-digest",
        digest("provider-executable"),
        "--authoring-provider-implementation-digest",
        digest("provider-implementation"),
        "--authoring-provider-descriptor-digest",
        digest("provider-descriptor"),
    )
    monkeypatch.setattr(
        "edagym.cli_support.flows.resolve_flow_host_bindings",
        lambda _environment,
        _tool_ids,
        *,
        authorize_commercial,
        backend_deployment: host_bindings,
    )

    store_root = tmp_path / "artifacts"
    qualification_root = tmp_path / "qualification-runtime"
    assert (
        main(
            [
                "task",
                "qualify",
                "--flow",
                pack.family,
                "--environment",
                str(environment_path),
                "--scratch-root",
                str(qualification_root),
                "--store-root",
                str(store_root),
                "--asset",
                f"evaluator_library={asset_path}",
                "--timeout-seconds",
                "30",
                *provider_arguments,
            ]
        )
        == 0
    )
    qualification = json.loads(capfd.readouterr().out)
    release = qualification["release"]
    assert FlowReleaseQualification.model_validate(release["qualification"])
    assert set(qualification["records"]) == {"reference", "semantic_negative"}
    assert {
        item["candidate_resource_id"] for item in qualification["candidate_attestations"]
    } == {"witness.reference", "negative.semantic_negative"}
    assert {
        item["qualification_evidence_digest"]
        for item in qualification["candidate_attestations"]
    } == {
        RunRecord.model_validate(record).integrity_digest
        for record in qualification["records"].values()
    }
    for record in qualification["records"].values():
        assert record["commits"]
        assert any(
            event["kind"] == "evaluation_completed"
            for commit in record["commits"]
            for event in commit["events"]
        )

    release_path = tmp_path / "release.json"
    release_path.write_bytes(canonical_bytes(release) + b"\n")
    workspace = tmp_path / "candidate"
    workspace.mkdir(mode=0o700)
    witness = next(item for item in pack.candidates if item.candidate_id == "reference")
    for asset in witness.assets:
        target = workspace / asset.path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(asset.content, encoding="ascii")

    participant_runtime = tmp_path / "participant-runtime"
    assert (
        main(
            [
                "evaluate",
                pack.family,
                "participant_candidate",
                "--environment",
                str(environment_path),
                "--release",
                str(release_path),
                "--workspace",
                str(workspace),
                "--runtime-root",
                str(participant_runtime),
                "--store-root",
                str(store_root),
                "--asset",
                f"evaluator_library={asset_path}",
                "--timeout-seconds",
                "30",
                *provider_arguments,
            ]
        )
        == 1
    )
    assert json.loads(capfd.readouterr().err) == {
        "error": "flow-participant-isolation-required"
    }
    assert not participant_runtime.exists()

    assert (
        main(
            [
                "evaluate",
                pack.family,
                "submitted_reference",
                "--environment",
                str(environment_path),
                "--release",
                str(release_path),
                "--workspace",
                str(workspace),
                "--runtime-root",
                str(tmp_path / "evaluation-runtime"),
                "--store-root",
                str(store_root),
                "--asset",
                f"evaluator_library={asset_path}",
                "--timeout-seconds",
                "30",
                "--author-calibration",
                *provider_arguments,
            ]
        )
        == 0
    )
    evaluation = json.loads(capfd.readouterr().out)
    assert evaluation["candidate_id"] == "submitted_reference"
    events = [
        event
        for commit in evaluation["record"]["commits"]
        for event in commit["events"]
    ]
    assert events[-1]["kind"] == "run_ended"
    assert events[-1]["payload"]["reason"] == "verifier_success"
    assert any(event["kind"] == "artifact_recorded" for event in events)

    altered_workspace = tmp_path / "altered-candidate"
    altered_workspace.mkdir(mode=0o700)
    for asset in witness.assets:
        target = altered_workspace / asset.path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_text(asset.content + "\n", encoding="ascii")
    altered_runtime = tmp_path / "altered-runtime"
    assert (
        main(
            [
                "evaluate",
                pack.family,
                "altered_candidate",
                "--environment",
                str(environment_path),
                "--release",
                str(release_path),
                "--workspace",
                str(altered_workspace),
                "--runtime-root",
                str(altered_runtime),
                "--store-root",
                str(store_root),
                "--asset",
                f"evaluator_library={asset_path}",
                "--timeout-seconds",
                "30",
                "--author-calibration",
                *provider_arguments,
            ]
        )
        == 1
    )
    assert json.loads(capfd.readouterr().err) == {
        "error": "flow-candidate-not-author-owned"
    }
    assert not altered_runtime.exists()


def test_flow_runtime_rejects_a_nonignored_repository_path(tmp_path: Path) -> None:
    pack = _runtime_pack()
    canonical = _synthetic_provider_canonical(pack)
    catalog = _synthetic_flow_catalog(pack, canonical)
    with pytest.raises(CliFailure) as rejected:
        from edagym.cli_support.flows import qualify_flow_pack

        qualify_flow_pack(
            pack,
            canonical,
            _environment_for(pack),
            catalog=catalog,
            scratch_root=Path.cwd() / "untracked-flow-runtime",
            store_root=tmp_path / "store",
            key_file=None,
            asset_paths={},
            timeout_seconds=30,
            authorize_commercial=False,
        )
    assert rejected.value.code == "flow-runtime-path-not-ignored"
    assert not (Path.cwd() / "untracked-flow-runtime").exists()


def test_commercial_flow_resolution_requires_explicit_authorization() -> None:
    with pytest.raises(CliFailure) as rejected:
        resolve_flow_host_bindings(
            _environment_for(_runtime_pack()),
            frozenset({"xcelium"}),
            authorize_commercial=False,
        )
    assert rejected.value.code == "flow-commercial-authorization-required"
