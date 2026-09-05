"""Security evidence for restricted qualification-asset staging."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from edagym.drivers.fixtures.model import FixtureAssetInput
from edagym.drivers.qualification_assets import (
    materialize_qualification_assets,
    revalidate_materialized_qualification_assets,
)
from edagym.executors.asset_identity import capture_asset_identity
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.assets import AssetSnapshot, AssetValidationError


def _snapshot(path: Path) -> AssetSnapshot:
    captured = capture_asset_identity(path)
    return AssetSnapshot(
        path=captured.path,
        restricted_digest=captured.restricted_digest,
        root_identity=captured.root_identity,
        source_policy=load_system_asset_source_policy(),
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


def test_materialization_normalizes_every_descendant_before_launch(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o755)
    nested = source / "nested"
    nested.mkdir(mode=0o755)
    data = nested / "model.dat"
    data.write_bytes(b"restricted model\n")
    data.chmod(0o644)
    executable = source / "model-helper"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    snapshot = _snapshot(source)

    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o755)
    declaration = FixtureAssetInput(
        logical_id="restricted_model",
        path="inputs/model",
        asset_id="synthetic_model",
    )
    materialized = materialize_qualification_assets(
        workspace,
        (declaration,),
        {declaration.asset_id: snapshot},
    )

    target = materialized[0].target
    assert _mode(workspace) == 0o700
    assert _mode(workspace / "inputs") == 0o700
    assert _mode(target) == 0o700
    assert _mode(target / "nested") == 0o700
    assert _mode(target / "nested/model.dat") == 0o600
    assert _mode(target / "model-helper") == 0o700
    assert _mode(source) == 0o755
    assert _mode(data) == 0o644
    assert revalidate_materialized_qualification_assets(
        materialized,
        {declaration.asset_id: snapshot},
        workspace,
    )

    (target / "nested/model.dat").chmod(0o640)
    assert not revalidate_materialized_qualification_assets(
        materialized,
        {declaration.asset_id: snapshot},
        workspace,
    )


def test_materialization_never_follows_a_preexisting_target_link(tmp_path: Path) -> None:
    source = tmp_path / "source.dat"
    source.write_bytes(b"restricted model\n")
    source.chmod(0o600)
    snapshot = _snapshot(source)

    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    (workspace / "inputs").symlink_to(external, target_is_directory=True)
    declaration = FixtureAssetInput(
        logical_id="restricted_model",
        path="inputs/model.dat",
        asset_id="synthetic_model",
    )

    with pytest.raises(AssetValidationError, match="failed safely"):
        materialize_qualification_assets(
            workspace,
            (declaration,),
            {declaration.asset_id: snapshot},
        )
    assert list(external.iterdir()) == []


def test_materialization_rejects_a_source_that_becomes_hard_linked(tmp_path: Path) -> None:
    source = tmp_path / "source.dat"
    source.write_bytes(b"restricted model\n")
    source.chmod(0o600)
    snapshot = _snapshot(source)
    os.link(source, tmp_path / "alias.dat")

    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    declaration = FixtureAssetInput(
        logical_id="restricted_model",
        path="inputs/model.dat",
        asset_id="synthetic_model",
    )

    with pytest.raises(AssetValidationError):
        materialize_qualification_assets(
            workspace,
            (declaration,),
            {declaration.asset_id: snapshot},
        )
    assert not (workspace / "inputs/model.dat").exists()
