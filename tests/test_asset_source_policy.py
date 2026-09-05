"""Authority evidence for restricted asset source selection."""

from __future__ import annotations

import copy
import pickle
import pwd
from pathlib import Path

import pytest

from edagym.canonical import canonical_bytes
from edagym.drivers.deployment import load_backend_deployment_registry
from edagym.executors.asset_policy import (
    AssetSourcePolicyError,
    load_system_asset_source_policy,
)
from edagym.policy.private_roots import PrivateRootRole


def test_system_asset_policy_rejects_broad_and_sensitive_roots(tmp_path: Path) -> None:
    policy = load_system_asset_source_policy()
    leaf = tmp_path / "asset.dat"
    leaf.write_bytes(b"bounded asset\n")

    assert policy.require_source(
        leaf,
        protected_paths=(),
        writable_paths=(),
    ) == leaf
    with pytest.raises(AssetSourcePolicyError, match="broad protected root"):
        policy.require_source(Path("/"), protected_paths=(), writable_paths=())

    home = Path(pwd.getpwuid(leaf.stat().st_uid).pw_dir).resolve(strict=True)
    with pytest.raises(AssetSourcePolicyError, match="broad protected root"):
        policy.require_source(home.parent, protected_paths=(), writable_paths=())
    with pytest.raises(AssetSourcePolicyError, match="sensitive runtime state"):
        policy.require_source(
            leaf,
            protected_paths=(tmp_path,),
            writable_paths=(),
        )

    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(policy)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(policy)


def test_deployment_asset_policy_is_bound_to_the_registry_snapshot(tmp_path: Path) -> None:
    deployment = tmp_path / "deployment.json"
    payload = canonical_bytes(
        {
            "schema_version": 2,
            "deployment_id": "asset_policy_test",
            "bindings": (
                {
                    "kind": "host_module",
                    "tool_id": "synthetic_tool",
                    "module_name": "vendor/tool/1",
                },
            ),
        }
    )
    deployment.write_bytes(payload)
    deployment.chmod(0o600)

    registry = load_backend_deployment_registry(deployment)
    policy = registry.asset_source_policy()
    registration = registry.source_registration()
    assert policy.revalidate()
    assert registration.role is PrivateRootRole.BACKEND_DEPLOYMENT_REGISTRY

    deployment.write_bytes(payload + b"\n")
    assert not policy.revalidate()
    with pytest.raises(ValueError, match="changed before source registration"):
        registry.source_registration()
