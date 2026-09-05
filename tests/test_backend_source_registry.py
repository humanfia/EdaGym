"""Release authority evidence for the private backend qualification source registry."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers.catalog import BACKEND_CATALOG
from edagym.drivers.deployment import BackendDeploymentRegistry, load_backend_deployment_registry
from edagym.drivers.qualification_verification import QualificationSourceKind
from edagym.release_backend_sources import (
    BackendQualificationSourceEntry,
    BackendQualificationSourceRegistryDocument,
    load_backend_qualification_sources,
)
from edagym.specs.common import Capability

_ABSENT_MODULE = "edagym/absent-qualification-module/1"
_ENTRY_DOMAIN = "backend-source-registry-evidence-v1"


def _private_file(path: Path, content: bytes) -> Path:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, content)
    finally:
        os.close(descriptor)
    return path


def _deployment_registry(root: Path) -> BackendDeploymentRegistry:
    root.mkdir(mode=0o700, exist_ok=True)
    document = {
        "schema_version": 2,
        "deployment_id": "release_source_registry_evidence",
        "bindings": [
            {"kind": "host_module", "tool_id": "iverilog", "module_name": _ABSENT_MODULE}
        ],
    }
    return load_backend_deployment_registry(
        _private_file(root / "deployment.json", canonical_bytes(document))
    )


def _entry(tool_id: str, capability: Capability) -> BackendQualificationSourceEntry:
    slug = f"{tool_id}-{capability.value.replace('.', '_')}"
    return BackendQualificationSourceEntry(
        tool_id=tool_id,
        capability=capability,
        source_kind=QualificationSourceKind.LIVE_PROBE_GAP,
        qualification_path=f"pairs/{slug}/qualification.json",
        qualification_digest=canonical_digest({"pair": slug}, domain=_ENTRY_DOMAIN),
    )


def _registry_document(
    entries: tuple[BackendQualificationSourceEntry, ...],
    registry: BackendDeploymentRegistry,
) -> BackendQualificationSourceRegistryDocument:
    registration = registry.source_registration()
    try:
        return BackendQualificationSourceRegistryDocument(
            backend_catalog_digest=BACKEND_CATALOG.digest,
            backend_deployment_source_digest=registration.source_identity_digest,
            entries=entries,
        )
    finally:
        registration.close()


def test_source_registry_must_cover_every_declared_capability_partition(
    tmp_path: Path,
) -> None:
    """A partial private registry cannot silently drop a declared capability."""

    complete = tuple(
        _entry(definition.tool_id, capability)
        for definition in BACKEND_CATALOG.backends
        for capability in definition.capabilities
    )
    partial_root = tmp_path / "partial"
    partial_root.mkdir(mode=0o700)
    partial_path = _private_file(
        partial_root / "registry.json",
        canonical_bytes(_registry_document(complete[:-1], _deployment_registry(partial_root))),
    )
    with pytest.raises(ValueError, match="differs from its live authorities"):
        load_backend_qualification_sources(
            partial_path,
            catalog=BACKEND_CATALOG,
            deployment_registry=_deployment_registry(tmp_path / "partial-authority"),
        )

    complete_root = tmp_path / "complete"
    complete_root.mkdir(mode=0o700)
    complete_path = _private_file(
        complete_root / "registry.json",
        canonical_bytes(_registry_document(complete, _deployment_registry(complete_root))),
    )
    with pytest.raises(OSError):
        load_backend_qualification_sources(
            complete_path,
            catalog=BACKEND_CATALOG,
            deployment_registry=_deployment_registry(tmp_path / "complete-authority"),
        )
