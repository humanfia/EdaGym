"""Live controller-owned evidence for deterministic private task derivation."""

from __future__ import annotations

from typing import Any, Final, Literal, Self

from pydantic import model_validator

from edagym.authoring.provider import (
    AuthoringProviderError,
    ExternalAuthoringProvider,
    PrivateAuthoringCapability,
    PrivateDerivationScope,
)
from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, SchemaVersion, StrictModel
from edagym.specs.environment import EnvironmentSpec

_VERIFIED_CONSTRUCTION_KEY: Final[object] = object()


class AuthoringDeterminismReceipt(StrictModel):
    """Path-free projection of two equal live derive and qualify exchanges."""

    schema_version: SchemaVersion = 1
    provider_descriptor_digest: Digest
    provider_implementation_digest: Digest
    capability: PrivateAuthoringCapability
    public_derivation_scope_digest: Digest
    qualification_environment_digest: Digest | None = None
    instance_reference_digest: Digest
    instance_reference_id: Digest
    task_spec_digest: Digest
    task_instance_digest: Digest
    participant_bundle_digest: Digest
    verifier_bundle_digest: Digest
    release_digest: Digest
    release_qualification_digest: Digest
    derived_member_manifest_digest: Digest
    derive_response_digest: Digest
    qualification_response_digest: Digest
    repetition_count: Literal[2] = 2

    @model_validator(mode="after")
    def bind_environment_kind(self) -> Self:
        flow = self.capability is PrivateAuthoringCapability.EDA_FLOW_CATALOG
        if flow != (self.qualification_environment_digest is not None):
            raise ValueError("only flow determinism receipts bind an environment")
        if self.participant_bundle_digest == self.verifier_bundle_digest:
            raise ValueError("determinism receipt bundle identities must differ")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="authoring-determinism-receipt-v1")


class VerifiedAuthoringDeterminism:
    """Non-serializable authority created only by live dual provider exchanges."""

    __slots__ = ("_receipt",)

    def __init__(
        self,
        receipt: AuthoringDeterminismReceipt,
        construction_key: object,
    ) -> None:
        if construction_key is not _VERIFIED_CONSTRUCTION_KEY:
            raise TypeError("verified determinism requires live provider exchanges")
        self._receipt = receipt

    @property
    def receipt(self) -> AuthoringDeterminismReceipt:
        return self._receipt

    def __repr__(self) -> str:
        return (
            "VerifiedAuthoringDeterminism("
            f"receipt_digest={self._receipt.digest!r})"
        )

    def __copy__(self) -> Self:
        raise TypeError("verified authoring determinism cannot be copied")

    def __deepcopy__(self, _memo: object) -> Self:
        raise TypeError("verified authoring determinism cannot be copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("verified authoring determinism cannot be serialized")


def verify_determinism(
    provider: ExternalAuthoringProvider,
    capability: PrivateAuthoringCapability,
    derivation: PrivateDerivationScope,
    *,
    environment: EnvironmentSpec | None = None,
) -> VerifiedAuthoringDeterminism:
    """Perform two fresh derive/qualify exchanges and bind their exact equality."""

    first_derivation = provider.derive(capability, derivation)
    second_derivation = provider.derive(capability, derivation)
    if first_derivation != second_derivation:
        raise AuthoringProviderError("private derivation is not deterministic")
    first_qualification = provider.qualify(
        capability,
        first_derivation.derived_task.instance_reference,
        environment=environment,
    )
    second_qualification = provider.qualify(
        capability,
        second_derivation.derived_task.instance_reference,
        environment=environment,
    )
    if first_qualification != second_qualification:
        raise AuthoringProviderError("private qualification is not deterministic")
    reference = first_derivation.derived_task.instance_reference
    qualification = first_qualification.qualification
    receipt = AuthoringDeterminismReceipt(
        provider_descriptor_digest=first_derivation.descriptor.digest,
        provider_implementation_digest=first_derivation.descriptor.implementation_digest,
        capability=capability,
        public_derivation_scope_digest=derivation.public_digest,
        qualification_environment_digest=(
            environment.digest if environment is not None else None
        ),
        instance_reference_digest=reference.digest,
        instance_reference_id=reference.reference_id,
        task_spec_digest=reference.task_spec_digest,
        task_instance_digest=reference.task_instance_digest,
        participant_bundle_digest=reference.participant_bundle_digest,
        verifier_bundle_digest=reference.verifier_bundle_digest,
        release_digest=first_qualification.release.digest,
        release_qualification_digest=qualification.release_qualification_digest,
        derived_member_manifest_digest=first_derivation.member_manifest_digest,
        derive_response_digest=canonical_digest(
            first_derivation,
            domain="authoring-determinism-derive-response-v1",
        ),
        qualification_response_digest=canonical_digest(
            first_qualification,
            domain="authoring-determinism-qualification-response-v1",
        ),
    )
    return VerifiedAuthoringDeterminism(receipt, _VERIFIED_CONSTRUCTION_KEY)


__all__ = [
    "AuthoringDeterminismReceipt",
    "VerifiedAuthoringDeterminism",
    "verify_determinism",
]
