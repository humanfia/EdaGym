"""Canonical CAS evidence for one consumed provider canary attestation."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Self

from pydantic import TypeAdapter, ValidationError, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.run.artifacts import ArtifactStoreError, ContentAddressedStore
from edagym.run.model import ArtifactRecord
from edagym.security.canary import CanaryPolicy, CanaryReceipt
from edagym.security.runtime_surface import RuntimeSurfaceManifest
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    Redistribution,
    SchemaVersion,
    Sensitivity,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import ArtifactDisclosure

PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE = (
    "application/vnd.edagym.provider-canary-evidence+json"
)
PROVIDER_TRANSCRIPT_MEDIA_TYPE = "application/vnd.edagym.provider-transcript+json"
MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES = 1 << 20
MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES = 16 << 20
_MAX_PROVIDER_CANARY_EVIDENCE_BYTES = 4 * 1024 * 1024
_DIGEST_ADAPTER = TypeAdapter(Digest)
_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)


class ProviderCanaryEvidenceError(ValueError):
    """Provider canary bytes or disclosure do not match their canonical evidence."""


class ProviderTranscriptError(ValueError):
    """Provider transcript bytes or disclosure violate the durable CAS contract."""


class ProviderTranscriptRole(StrEnum):
    REQUEST = "request"
    RESPONSE = "response"


class ProviderCanaryEvidence(StrictModel):
    """Author-only durable join of policy, receipt, and runtime-surface evidence."""

    schema_version: SchemaVersion = 1
    policy: CanaryPolicy
    receipt: CanaryReceipt
    runtime_surface_manifest: RuntimeSurfaceManifest

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        binding = self.runtime_surface_manifest.binding
        if (
            self.receipt.policy_digest != self.policy.digest
            or self.receipt.manifest_digest != self.runtime_surface_manifest.digest
            or self.receipt.campaign_digest != binding.campaign_digest
            or self.receipt.provider_profile_digest != binding.provider_profile_digest
            or self.policy.provider_profile_digest != binding.provider_profile_digest
            or self.policy.provider_config_digest != binding.provider_config_digest
            or self.policy.budget_binding_digest != binding.budget_binding_digest
        ):
            raise ValueError("provider canary evidence has inconsistent semantic bindings")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-canary-evidence-v1")

    @property
    def artifact_id(self) -> Identifier:
        return provider_canary_evidence_artifact_id(self.digest)


def provider_canary_evidence_artifact_id(evidence_digest: Digest) -> Identifier:
    """Derive the sole logical artifact identity for canonical canary evidence."""

    digest = _DIGEST_ADAPTER.validate_python(evidence_digest)
    return _IDENTIFIER_ADAPTER.validate_python(
        f"provider_canary_{digest.removeprefix('sha256:')}"
    )


def provider_transcript_artifact_id(
    request_id: Identifier,
    role: ProviderTranscriptRole,
) -> Identifier:
    """Derive the sole raw transcript identity for one provider request role."""

    request = _IDENTIFIER_ADAPTER.validate_python(request_id)
    if type(role) is not ProviderTranscriptRole:
        raise TypeError("provider transcript identities require a typed role")
    identity = canonical_digest(
        {"request_id": request, "role": role},
        domain="provider-transcript-artifact-id-v1",
    )
    return _IDENTIFIER_ADAPTER.validate_python(
        f"provider_transcript_{identity.removeprefix('sha256:')}"
    )


def store_provider_canary_evidence(
    evidence: ProviderCanaryEvidence,
    store: ContentAddressedStore,
) -> ArtifactRecord:
    """Persist one canary document under the store's exact author-only evidence rule."""

    if type(evidence) is not ProviderCanaryEvidence:
        raise TypeError("provider canary storage requires canonical evidence")
    if type(store) is not ContentAddressedStore:
        raise TypeError("provider canary storage requires the concrete artifact store")
    disclosure = _author_only_evidence_disclosure(store)
    blob = store.put_bytes(
        canonical_bytes(evidence),
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )
    return ArtifactRecord(
        logical_id=evidence.artifact_id,
        blob=blob,
        media_type=PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE,
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )


def verify_provider_canary_evidence(
    record: ArtifactRecord,
    store: ContentAddressedStore,
) -> ProviderCanaryEvidence:
    """Reopen, scan, and decode one exact provider canary CAS artifact."""

    if type(record) is not ArtifactRecord:
        raise TypeError("provider canary verification requires an artifact record")
    if type(store) is not ContentAddressedStore:
        raise TypeError("provider canary verification requires the concrete artifact store")
    disclosure = _author_only_evidence_disclosure(store)
    if (
        record.media_type != PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE
        or record.artifact_class is not ArtifactClass.EVIDENCE
        or record.sensitivity is not disclosure.sensitivity
        or record.visibility is not disclosure.visibility
        or record.redistribution is not disclosure.redistribution
        or record.blob.size_bytes > _MAX_PROVIDER_CANARY_EVIDENCE_BYTES
    ):
        raise ProviderCanaryEvidenceError(
            "provider canary artifact has an invalid disclosure or media contract"
        )
    try:
        store.verify_disclosure(
            record.blob,
            artifact_class=record.artifact_class,
            sensitivity=record.sensitivity,
            visibility=record.visibility,
            redistribution=record.redistribution,
        )
        content = store.read_bytes(
            record.blob,
            maximum_bytes=_MAX_PROVIDER_CANARY_EVIDENCE_BYTES,
        )
        evidence = ProviderCanaryEvidence.model_validate_json(content)
    except (ArtifactStoreError, ValidationError) as error:
        raise ProviderCanaryEvidenceError(
            "provider canary artifact content is invalid"
        ) from error
    if canonical_bytes(evidence) != content or record.logical_id != evidence.artifact_id:
        raise ProviderCanaryEvidenceError("provider canary artifact is not canonical")
    return evidence


def verify_provider_transcript_artifact(
    record: ArtifactRecord,
    store: ContentAddressedStore,
    *,
    request_id: Identifier,
    role: ProviderTranscriptRole,
) -> None:
    """Reopen and verify one bounded raw provider transcript artifact."""

    if type(record) is not ArtifactRecord:
        raise TypeError("provider transcript verification requires an artifact record")
    if type(store) is not ContentAddressedStore:
        raise TypeError("provider transcript verification requires the concrete artifact store")
    if type(role) is not ProviderTranscriptRole:
        raise TypeError("provider transcript verification requires a typed role")
    disclosure = store.policy.persistent_disclosure(ArtifactClass.TRAINING)
    maximum_bytes = (
        MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES
        if role is ProviderTranscriptRole.REQUEST
        else MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES
    )
    if (
        disclosure is None
        or disclosure.sensitivity is not Sensitivity.CONFIDENTIAL
        or disclosure.visibility is not Visibility.AUTHOR
        or disclosure.redistribution is not Redistribution.FORBIDDEN
        or record.logical_id != provider_transcript_artifact_id(request_id, role)
        or record.media_type != PROVIDER_TRANSCRIPT_MEDIA_TYPE
        or record.artifact_class is not ArtifactClass.TRAINING
        or record.sensitivity is not disclosure.sensitivity
        or record.visibility is not disclosure.visibility
        or record.redistribution is not disclosure.redistribution
        or record.blob.size_bytes > maximum_bytes
    ):
        raise ProviderTranscriptError(
            "provider transcript artifact has an invalid identity or disclosure"
        )
    try:
        store.verify_disclosure(
            record.blob,
            artifact_class=record.artifact_class,
            sensitivity=record.sensitivity,
            visibility=record.visibility,
            redistribution=record.redistribution,
        )
        content = store.read_bytes(record.blob, maximum_bytes=maximum_bytes)
        document = json.loads(content)
    except (ArtifactStoreError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProviderTranscriptError("provider transcript artifact content is invalid") from error
    if not isinstance(document, dict):
        raise ProviderTranscriptError("provider transcript artifact must contain a JSON object")


def _author_only_evidence_disclosure(
    store: ContentAddressedStore,
) -> ArtifactDisclosure:
    disclosure = store.policy.persistent_disclosure(ArtifactClass.EVIDENCE)
    if disclosure is None or disclosure.visibility is not Visibility.AUTHOR:
        raise ProviderCanaryEvidenceError(
            "provider canary evidence requires one persistent author-only disclosure"
        )
    return disclosure
