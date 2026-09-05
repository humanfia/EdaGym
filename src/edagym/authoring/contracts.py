"""Canonical public receipts emitted by the authoring boundary CLI."""

from __future__ import annotations

import json
from typing import Any, Literal, Self

from pydantic import model_validator

from edagym.authoring.materialization import CatalogMaterializationReceipt
from edagym.authoring.provider import (
    AUTHORING_PROVIDER_PROTOCOL_REVISION,
    authoring_provider_schema_digest,
)
from edagym.canonical import canonical_bytes
from edagym.specs.common import Digest, SchemaVersion, StrictModel
from edagym.task_families.catalog import PUBLIC_TASK_CATALOG_DIGEST


class AuthoringContractReceipt(StrictModel):
    schema_version: SchemaVersion = 1
    protocol_revision: Literal[1] = AUTHORING_PROVIDER_PROTOCOL_REVISION
    provider_schema_digest: Digest = authoring_provider_schema_digest()
    public_catalog_digest: Digest = PUBLIC_TASK_CATALOG_DIGEST

    @model_validator(mode="after")
    def validate_owner(self) -> Self:
        if self.protocol_revision != AUTHORING_PROVIDER_PROTOCOL_REVISION:
            raise ValueError("authoring contract protocol revision mismatch")
        if self.provider_schema_digest != authoring_provider_schema_digest():
            raise ValueError("authoring contract provider schema mismatch")
        if self.public_catalog_digest != PUBLIC_TASK_CATALOG_DIGEST:
            raise ValueError("authoring contract public catalog mismatch")
        return self


class CatalogVerificationProjection(StrictModel):
    schema_version: SchemaVersion = 1
    public_catalog_digest: Digest
    provider_descriptor_digest: Digest
    attestation_digest: Digest
    receipt_digest: Digest

    @classmethod
    def from_receipt(
        cls,
        receipt: CatalogMaterializationReceipt,
    ) -> CatalogVerificationProjection:
        return cls(
            public_catalog_digest=receipt.provider.public_catalog_digest,
            provider_descriptor_digest=receipt.provider.digest,
            attestation_digest=receipt.attestation.digest,
            receipt_digest=receipt.digest,
        )


def parse_authoring_contract_output(content: bytes) -> AuthoringContractReceipt:
    return _parse_canonical_receipt(content, AuthoringContractReceipt)


def parse_catalog_verification_output(content: bytes) -> CatalogVerificationProjection:
    return _parse_canonical_receipt(content, CatalogVerificationProjection)


def _parse_canonical_receipt[TReceipt: StrictModel](
    content: bytes,
    model: type[TReceipt],
) -> TReceipt:
    if not content.endswith(b"\n") or content.endswith(b"\n\n"):
        raise ValueError("authoring receipt must have exactly one final newline")
    try:
        document = json.loads(content, object_pairs_hook=_unique_object)
        receipt = model.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("authoring receipt is invalid") from error
    if content != canonical_bytes(receipt) + b"\n":
        raise ValueError("authoring receipt is not canonically encoded")
    return receipt


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("authoring receipt contains duplicate keys")
        result[key] = value
    return result


__all__ = [
    "AuthoringContractReceipt",
    "CatalogVerificationProjection",
    "parse_authoring_contract_output",
    "parse_catalog_verification_output",
]
