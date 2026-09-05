"""The executor source remains bound across filesystem namespace changes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from edagym.canonical import canonical_bytes
from edagym.executors.deployment import load_executor_deployment_registry
from edagym.policy.private_roots import PrivateRootRole
from tests.factories import digest


def _document() -> bytes:
    image_digest = digest("deployment-test-image")
    return canonical_bytes(
        {
            "schema_version": 1,
            "deployment_id": "deployment_test",
            "rootless": {
                "podman_path": "/usr/bin/podman",
                "mkfs_path": "/usr/sbin/mkfs.ext4",
                "fuse2fs_path": "/usr/bin/fuse2fs",
                "fusermount_path": "/usr/bin/fusermount3",
                "maximum_storage_bytes": 64 * 1024 * 1024,
                "images": (
                    {
                        "image_digest": image_digest,
                        "image_reference": f"localhost/deployment-test@{image_digest}",
                    },
                ),
            },
            "libvirt": None,
            "slurm": None,
            "microvm": None,
        }
    ) + b"\n"


def test_deployment_retains_its_source_when_an_ancestor_is_replaced(tmp_path: Path) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    source = parent / "deployment.json"
    source.write_bytes(_document())
    source.chmod(0o600)
    registry = load_executor_deployment_registry(source)
    try:
        identity = registry.digest
        retained = tmp_path / "retained"
        parent.rename(retained)
        parent.mkdir(mode=0o700)
        source.write_bytes(b"untrusted replacement")
        source.chmod(0o600)

        assert registry.revalidate()
        assert registry.digest == identity
        registration = registry.source_registration()
        try:
            assert registration.role is PrivateRootRole.EXECUTOR_DEPLOYMENT_REGISTRY
            assert registration.source_identity_digest == identity
        finally:
            registration.close()

        (retained / source.name).write_bytes(b"changed retained source")
        assert not registry.revalidate()
        with pytest.raises(ValueError):
            registry.source_registration()
    finally:
        registry.close()
    assert not registry.revalidate()


def test_deployment_rejects_shared_or_indirect_source_files(tmp_path: Path) -> None:
    source = tmp_path / "deployment.json"
    source.write_bytes(_document())
    source.chmod(0o644)
    with pytest.raises(ValueError):
        load_executor_deployment_registry(source)

    source.chmod(0o600)
    alias = tmp_path / "alias.json"
    alias.symlink_to(source)
    with pytest.raises(ValueError):
        load_executor_deployment_registry(alias)

    hardlink = tmp_path / "shared.json"
    os.link(source, hardlink)
    with pytest.raises(ValueError):
        load_executor_deployment_registry(source)
