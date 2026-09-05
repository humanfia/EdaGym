"""Evidence for the common restricted-asset launch boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.assets import (
    AssetValidationError,
    asset_content_digest,
    revalidate_asset_closure,
    validate_asset_closure,
)
from edagym.specs.environment import (
    AssetBinding,
    EnvironmentSpec,
    FilesystemScope,
    ReadonlyAssetMount,
)
from tests.factories import environment_spec


def _environment(assets: dict[str, Path]) -> EnvironmentSpec:
    base = environment_spec()
    document = base.model_dump(mode="python")
    document["assets"] = tuple(
        AssetBinding(
            asset_id=asset_id,
            restricted_digest=asset_content_digest(path),
            allowed_scopes=(FilesystemScope.EVALUATOR,),
        )
        for asset_id, path in assets.items()
    )
    document["filesystem"] = base.filesystem.model_copy(
        update={
            "readonly_assets": tuple(
                ReadonlyAssetMount(
                    asset_id=asset_id,
                    scope=FilesystemScope.EVALUATOR,
                    target=f"/assets/{asset_id}",
                )
                for asset_id in assets
            )
        }
    )
    return EnvironmentSpec.model_validate(document)


def test_asset_closure_binds_exact_content_and_revalidates(tmp_path: Path) -> None:
    asset = tmp_path / "restricted.txt"
    asset.write_text("original\n", encoding="ascii")
    environment = _environment({"restricted": asset})

    with pytest.raises(AssetValidationError):
        validate_asset_closure(
            environment,
            {},
            FilesystemScope.EVALUATOR,
            source_policy=load_system_asset_source_policy(),
        )

    snapshots = validate_asset_closure(
        environment,
        {"restricted": asset},
        FilesystemScope.EVALUATOR,
        source_policy=load_system_asset_source_policy(),
    )
    assert str(asset) not in repr(snapshots["restricted"])

    asset.chmod(0o400)
    with pytest.raises(AssetValidationError):
        revalidate_asset_closure(snapshots)


def test_asset_closure_rejects_aliases_and_links(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    nested = tree / "nested.txt"
    nested.write_text("content\n", encoding="ascii")
    environment = _environment({"tree": tree, "nested": nested})

    with pytest.raises(AssetValidationError):
        validate_asset_closure(
            environment,
            {"tree": tree, "nested": nested},
            FilesystemScope.EVALUATOR,
            source_policy=load_system_asset_source_policy(),
        )

    symbolic = tmp_path / "symbolic"
    symbolic.symlink_to(nested)
    with pytest.raises(AssetValidationError):
        asset_content_digest(symbolic)

    hardlink_source = tmp_path / "hardlink-source"
    hardlink_source.write_text("shared\n", encoding="ascii")
    hardlink = tmp_path / "hardlink"
    hardlink.hardlink_to(hardlink_source)
    with pytest.raises(AssetValidationError):
        asset_content_digest(hardlink_source)

    unsafe_mount = tmp_path / "workspace:rw"
    unsafe_mount.mkdir()
    with pytest.raises(AssetValidationError):
        validate_asset_closure(
            environment_spec(),
            {},
            FilesystemScope.EVALUATOR,
            source_policy=load_system_asset_source_policy(),
            writable_paths=(unsafe_mount,),
        )
