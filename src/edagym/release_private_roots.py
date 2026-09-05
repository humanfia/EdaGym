"""Compose release-owned live sources into the private-root policy scanner."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path

from edagym.authoring.materialization import verify_materialized_catalog
from edagym.authoring.provider import SealedCatalogAttestation
from edagym.policy.private_roots import (
    PrivateRootAuditReport,
    PrivateRootRegistration,
    PrivateRootRole,
    _bind_private_root_from_descriptor,
    audit_private_roots,
    project_private_root_audit,
)
from edagym.policy.repository import AuditReport
from edagym.release_backend_sources import VerifiedBackendQualificationSources
from edagym.release_commands import VerifiedReleaseCommandReceipt
from edagym.run.artifacts import ContentAddressedStore
from edagym.security.artifact_closure import artifact_store_identity_digest
from edagym.specs.common import Digest
from edagym.task_families.catalog import PublicTaskCatalog

_ARTIFACT_STORE_ROLES = frozenset(
    {
        PrivateRootRole.BACKEND_QUALIFICATION_STORE,
        PrivateRootRole.CAMPAIGN_ARTIFACT_STORE,
        PrivateRootRole.COMMAND_ARTIFACT_STORE,
        PrivateRootRole.EXECUTOR_QUALIFICATION_STORE,
        PrivateRootRole.FLOW_QUALIFICATION_STORE,
        PrivateRootRole.PARTICIPANT_SESSION_STORE,
    }
)


def project_release_private_root_audit(
    *,
    repository: Path,
    repository_audit: AuditReport,
    public_catalog: PublicTaskCatalog,
    sail_materialized_catalog_root: Path,
    sail_catalog_attestation: SealedCatalogAttestation,
    flow_materialized_catalog_root: Path,
    flow_catalog_attestation: SealedCatalogAttestation,
    authoring_provider_registration: PrivateRootRegistration,
    backend_sources: VerifiedBackendQualificationSources,
    command_receipts: tuple[VerifiedReleaseCommandReceipt, ...],
    flow_artifact_stores: Mapping[Digest, ContentAddressedStore],
    campaign_artifact_stores: Mapping[Digest, ContentAddressedStore],
    participant_artifact_stores: Mapping[Digest, ContentAddressedStore],
) -> PrivateRootAuditReport:
    """Derive registrations only from sources already replayed by release gates."""

    if authoring_provider_registration.role is not PrivateRootRole.AUTHORING_PROVIDER_SOURCE:
        raise ValueError("authoring provider supplied the wrong private-root authority")
    registrations = (
        _materialized_catalog_registration(
            sail_materialized_catalog_root,
            public_catalog,
            sail_catalog_attestation,
        ),
        _materialized_catalog_registration(
            flow_materialized_catalog_root,
            public_catalog,
            flow_catalog_attestation,
        ),
        authoring_provider_registration,
        *backend_sources.private_root_registrations,
        *_command_store_registrations(command_receipts),
        *_artifact_store_registrations(
            PrivateRootRole.FLOW_QUALIFICATION_STORE,
            flow_artifact_stores.values(),
        ),
        *_artifact_store_registrations(
            PrivateRootRole.CAMPAIGN_ARTIFACT_STORE,
            campaign_artifact_stores.values(),
        ),
        *_artifact_store_registrations(
            PrivateRootRole.PARTICIPANT_SESSION_STORE,
            participant_artifact_stores.values(),
        ),
    )
    return project_private_root_audit(
        audit_private_roots(repository, repository_audit, registrations)
    )


def _materialized_catalog_registration(
    root: Path,
    public_catalog: PublicTaskCatalog,
    expected_attestation: SealedCatalogAttestation,
) -> PrivateRootRegistration:
    descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        receipt = verify_materialized_catalog(
            Path(f"/proc/self/fd/{descriptor}"),
            public_catalog,
        )
        if receipt.attestation != expected_attestation:
            raise ValueError("private catalog root has a different sealed attestation")
        return _bind_private_root_from_descriptor(
            PrivateRootRole.AUTHORING_MATERIALIZATION,
            descriptor,
            receipt.digest,
        )
    finally:
        os.close(descriptor)


def _command_store_registrations(
    receipts: tuple[VerifiedReleaseCommandReceipt, ...],
) -> tuple[PrivateRootRegistration, ...]:
    stores = {id(item.store): item.store for item in receipts}
    return _artifact_store_registrations(
        PrivateRootRole.COMMAND_ARTIFACT_STORE,
        stores.values(),
    )


def _artifact_store_registrations(
    role: PrivateRootRole,
    stores: Iterable[ContentAddressedStore],
) -> tuple[PrivateRootRegistration, ...]:
    if role not in _ARTIFACT_STORE_ROLES:
        raise ValueError("artifact stores cannot claim this private-root role")
    unique = {id(store): store for store in stores}
    registrations: list[PrivateRootRegistration] = []
    for store in unique.values():
        if type(store) is not ContentAddressedStore:
            raise TypeError("private-root registration requires the concrete artifact store")
        descriptor = os.open(
            store.root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            store_identity = artifact_store_identity_digest(store, descriptor)
            registrations.append(
                _bind_private_root_from_descriptor(role, descriptor, store_identity)
            )
        finally:
            os.close(descriptor)
    return tuple(registrations)
