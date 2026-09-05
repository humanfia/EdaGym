"""Bounded-capture evidence for restricted asset identities."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from edagym.executors.asset_identity import (
    MAX_ASSET_CAPTURE_DEPTH,
    MAX_ASSET_CAPTURE_ENTRIES,
    MAX_ASSET_CAPTURE_PATH_BYTES,
    MAX_ASSET_CAPTURE_TOTAL_BYTES,
    AssetIdentityError,
    capture_asset_identity,
)


def test_exact_leaf_asset_closure_is_captured(tmp_path: Path) -> None:
    root = tmp_path / "leaf"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    (nested / "model.dat").write_bytes(b"bounded model\n")

    captured = capture_asset_identity(root)

    assert captured.path == root
    assert captured.restricted_digest.startswith("sha256:")


def test_asset_capture_rejects_every_resource_budget_before_unbounded_read(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized.bin"
    descriptor = os.open(oversized, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.ftruncate(descriptor, MAX_ASSET_CAPTURE_TOTAL_BYTES + 1)
    finally:
        os.close(descriptor)
    with pytest.raises(AssetIdentityError, match="byte limit"):
        capture_asset_identity(oversized)

    too_deep = tmp_path / "too-deep"
    too_deep.mkdir()
    cursor = too_deep
    for position in range(MAX_ASSET_CAPTURE_DEPTH + 1):
        cursor /= f"d{position}"
        cursor.mkdir()
    with pytest.raises(AssetIdentityError, match="depth limit"):
        capture_asset_identity(too_deep)

    too_many = tmp_path / "too-many"
    too_many.mkdir()
    for position in range(MAX_ASSET_CAPTURE_ENTRIES):
        (too_many / f"entry-{position}").touch()
    with pytest.raises(AssetIdentityError, match="entry limit"):
        capture_asset_identity(too_many)

    impossible_path = Path("/") / ("x" * (MAX_ASSET_CAPTURE_PATH_BYTES + 1))
    with pytest.raises(AssetIdentityError, match="unsafe mount character"):
        capture_asset_identity(impossible_path)
