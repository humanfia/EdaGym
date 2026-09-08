"""Provider model discovery and evidence-driven model-set freezing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self

from pydantic import Field, TypeAdapter, ValidationError, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.providers.campaign import (
    REQUIRED_MODEL_CATEGORIES,
    CategoryExclusionReason,
    DateStamp,
    ExcludedRoute,
    ModelCategory,
    ModelReferenceKind,
    ModelRoute,
    ModelSetManifest,
    RouteExclusionReason,
    RouteQualification,
    UncoveredCategory,
)
from edagym.providers.model import (
    ModelLabel,
    ProviderConfigLabel,
    ProviderProfile,
    ProviderSecurityBinding,
    RequestTokenClaim,
    ResolvedProviderConfig,
)
from edagym.providers.qualification import (
    CanaryNonce,
    RouteCanaryEvidence,
    RouteRequestSender,
    run_route_canary,
)
from edagym.providers.responses import (
    DirectHttpsTransport,
    ProviderHttpError,
    ProviderProtocolError,
    RawHttpResponse,
)
from edagym.security.canary import CanaryAttestation, CanaryPolicy
from edagym.security.canary_artifact import ProviderCanaryEvidence
from edagym.security.credentials import (
    CredentialSource,
    _consume_attestation_for_provider_access,
)
from edagym.specs.common import (
    Digest,
    Identifier,
    JcsPositiveInt,
    SchemaVersion,
    ServiceTierLabel,
    StrictModel,
)

_MODEL_LABEL = TypeAdapter(ModelLabel)
_MAX_MODELS_RESPONSE_BYTES = 4 << 20


class ModelDiscoveryError(RuntimeError):
    """A declared provider catalog could not be read as bounded model evidence."""


class ModelDiscoverySource(StrEnum):
    MODELS_ENDPOINT = "models_endpoint"
    EXPLICIT_CANDIDATES = "explicit_candidates"


class ModelDiscoveryUnavailableReason(StrEnum):
    MODELS_ENDPOINT_NOT_DECLARED = "models_endpoint_not_declared"
    AUTHENTICATED_ENDPOINT_REQUIRES_PREFLIGHT = (
        "authenticated_endpoint_requires_preflight"
    )


class ModelDiscoveryUnavailable(StrictModel):
    """Typed evidence that automatic discovery is not available for this profile."""

    schema_version: SchemaVersion = 1
    provider_profile_digest: Digest
    provider_config_digest: Digest
    selected_provider_label: ProviderConfigLabel
    reason: ModelDiscoveryUnavailableReason

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-model-discovery-unavailable-v1")


class ModelDiscoverySnapshot(StrictModel):
    """Path-free provider catalog or explicit fallback used to select canary routes."""

    schema_version: SchemaVersion = 1
    provider_profile_digest: Digest
    provider_config_digest: Digest
    selected_provider_label: ProviderConfigLabel
    source: ModelDiscoverySource
    model_labels: Annotated[tuple[ModelLabel, ...], Field(min_length=1)]
    source_evidence_digest: Digest
    security_binding: ProviderSecurityBinding | None = None

    @field_validator("model_labels")
    @classmethod
    def normalize_model_labels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("provider model discovery labels must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_source_security(self) -> Self:
        requires_security = self.source is ModelDiscoverySource.MODELS_ENDPOINT
        if requires_security != (self.security_binding is not None):
            raise ValueError(
                "authenticated model discovery requires its exact security binding"
            )
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-model-discovery-v1")


ModelDiscoveryResult = ModelDiscoverySnapshot | ModelDiscoveryUnavailable


class ModelDiscoveryLimits(StrictModel):
    """One-request byte envelope for a credential-gated models lookup."""

    schema_version: SchemaVersion = 1
    maximum_requests: Literal[1] = 1
    maximum_response_bytes: Annotated[
        JcsPositiveInt,
        Field(le=_MAX_MODELS_RESPONSE_BYTES),
    ] = _MAX_MODELS_RESPONSE_BYTES

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-model-discovery-limits-v1")


class AuthenticatedModelDiscovery(StrictModel):
    """Portable endpoint result joined to the preflight that authorized credentials."""

    discovery: ModelDiscoverySnapshot
    canary_evidence: ProviderCanaryEvidence

    @model_validator(mode="after")
    def validate_security_join(self) -> Self:
        binding = self.canary_evidence.runtime_surface_manifest.binding
        expected = ProviderSecurityBinding(
            canary_receipt_digest=self.canary_evidence.receipt.digest,
            runtime_surface_manifest_digest=(
                self.canary_evidence.runtime_surface_manifest.digest
            ),
            budget_binding_digest=binding.budget_binding_digest,
        )
        if (
            self.discovery.source is not ModelDiscoverySource.MODELS_ENDPOINT
            or self.discovery.provider_profile_digest
            != binding.provider_profile_digest
            or self.discovery.provider_config_digest != binding.provider_config_digest
            or self.discovery.security_binding != expected
        ):
            raise ValueError("model discovery differs from its credential preflight")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="authenticated-provider-model-discovery-v1")


class ModelRouteCandidate(StrictModel):
    """Explicit route identity and categories; no category is inferred from its label."""

    route_id: Identifier
    requested_model: ModelLabel
    reference_kind: ModelReferenceKind
    categories: Annotated[tuple[ModelCategory, ...], Field(min_length=1)]
    provider_attestation_digest: Digest | None = None

    @field_validator("categories")
    @classmethod
    def normalize_categories(
        cls,
        value: tuple[ModelCategory, ...],
    ) -> tuple[ModelCategory, ...]:
        if len(value) != len(set(value)):
            raise ValueError("model route candidate categories must be unique")
        return tuple(sorted(value))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-model-route-candidate-v1")


class QualifiedModelRoute(StrictModel):
    candidate: ModelRouteCandidate
    canary: RouteCanaryEvidence

    @model_validator(mode="after")
    def validate_canary(self) -> Self:
        if self.canary.requested_model != self.candidate.requested_model:
            raise ValueError("route canary requested model differs from its candidate")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-qualified-model-route-v1")


class ExcludedModelRoute(StrictModel):
    candidate: ModelRouteCandidate
    reason: RouteExclusionReason
    evidence_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-excluded-model-route-v1")


ModelRouteOutcome = QualifiedModelRoute | ExcludedModelRoute


class ModelSetUnavailable(StrictModel):
    """Complete qualification evidence when no candidate route passed its canary."""

    schema_version: SchemaVersion = 1
    provider_config_digest: Digest
    discovery_digest: Digest
    exclusions: Annotated[tuple[ExcludedRoute, ...], Field(min_length=1)]
    uncovered_categories: tuple[UncoveredCategory, ...]

    @field_validator("exclusions")
    @classmethod
    def normalize_exclusions(
        cls,
        value: tuple[ExcludedRoute, ...],
    ) -> tuple[ExcludedRoute, ...]:
        return tuple(sorted(value, key=lambda item: item.requested_model))

    @field_validator("uncovered_categories")
    @classmethod
    def normalize_uncovered(
        cls,
        value: tuple[UncoveredCategory, ...],
    ) -> tuple[UncoveredCategory, ...]:
        return tuple(sorted(value, key=lambda item: item.category))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-model-set-unavailable-v1")


ModelSetFreezeResult = ModelSetManifest | ModelSetUnavailable


class ModelsTransport(Protocol):
    def retrieve_models(
        self,
        *,
        profile: ProviderProfile,
        headers: Mapping[str, str],
        maximum_response_bytes: int,
    ) -> RawHttpResponse: ...


def discover_provider_models(
    configuration: ResolvedProviderConfig,
) -> ModelDiscoveryUnavailable:
    """Report whether model discovery can proceed without opening credentials."""

    reason = (
        ModelDiscoveryUnavailableReason.MODELS_ENDPOINT_NOT_DECLARED
        if configuration.profile.models_path is None
        else ModelDiscoveryUnavailableReason.AUTHENTICATED_ENDPOINT_REQUIRES_PREFLIGHT
    )
    return ModelDiscoveryUnavailable(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        selected_provider_label=configuration.selected_provider_label,
        reason=reason,
    )


def discover_authenticated_provider_models(
    configuration: ResolvedProviderConfig,
    limits: ModelDiscoveryLimits,
    *,
    policy: CanaryPolicy,
    attestation: CanaryAttestation,
    credentials: CredentialSource,
    transport: ModelsTransport | None = None,
) -> AuthenticatedModelDiscovery:
    """Consume one exact preflight before one bounded authenticated models lookup."""

    if configuration.profile.models_path is None:
        raise ModelDiscoveryError("provider profile declares no models endpoint")
    if (
        policy.provider_profile_digest != configuration.profile.digest
        or policy.provider_config_digest != configuration.digest
        or policy.budget_binding_digest != limits.digest
    ):
        raise ModelDiscoveryError("model discovery policy differs from its immutable inputs")
    manifest = attestation.runtime_surface_manifest
    grant, receipt = _consume_attestation_for_provider_access(
        policy=policy,
        attestation=attestation,
    )
    access = credentials.acquire(grant=grant)
    try:
        if access.resolved != configuration:
            raise ProviderProtocolError(
                "credential source returned a different provider projection"
            )
        headers = {"Accept": "application/json"}
        access.credential.authorize(
            headers,
            profile=configuration.profile,
        )
        response = (transport or DirectHttpsTransport()).retrieve_models(
            profile=configuration.profile,
            headers=headers,
            maximum_response_bytes=limits.maximum_response_bytes,
        )
    finally:
        access.close()
    if len(response.body) > limits.maximum_response_bytes:
        raise ModelDiscoveryError("provider models response exceeded its byte limit")
    if not 200 <= response.status < 300:
        raise ProviderHttpError(response.status)
    if not response.headers.get("content-type", "").casefold().startswith(
        "application/json"
    ):
        raise ModelDiscoveryError("provider models response is not JSON")
    discovery = ModelDiscoverySnapshot(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        selected_provider_label=configuration.selected_provider_label,
        source=ModelDiscoverySource.MODELS_ENDPOINT,
        model_labels=_decode_model_labels(response.body),
        source_evidence_digest=(
            f"sha256:{hashlib.sha256(response.body).hexdigest()}"
        ),
        security_binding=ProviderSecurityBinding(
            canary_receipt_digest=receipt.digest,
            runtime_surface_manifest_digest=manifest.digest,
            budget_binding_digest=limits.digest,
        ),
    )
    return AuthenticatedModelDiscovery(
        discovery=discovery,
        canary_evidence=ProviderCanaryEvidence(
            policy=policy,
            receipt=receipt,
            runtime_surface_manifest=manifest,
        ),
    )


def declare_explicit_model_candidates(
    configuration: ResolvedProviderConfig,
    unavailable: ModelDiscoveryUnavailable,
    candidates: tuple[ModelRouteCandidate, ...],
) -> ModelDiscoverySnapshot:
    """Create the only admitted fallback when the trusted profile has no catalog endpoint."""

    if (
        configuration.profile.models_path is not None
        or unavailable.reason
        is not ModelDiscoveryUnavailableReason.MODELS_ENDPOINT_NOT_DECLARED
    ):
        raise ValueError("explicit candidates require a profile without model discovery")
    if (
        unavailable.provider_profile_digest != configuration.profile.digest
        or unavailable.provider_config_digest != configuration.digest
        or unavailable.selected_provider_label != configuration.selected_provider_label
    ):
        raise ValueError("model discovery limitation differs from the provider configuration")
    _validate_candidate_set(candidates)
    return ModelDiscoverySnapshot(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        selected_provider_label=configuration.selected_provider_label,
        source=ModelDiscoverySource.EXPLICIT_CANDIDATES,
        model_labels=tuple(candidate.requested_model for candidate in candidates),
        source_evidence_digest=canonical_digest(
            {
                "candidates": candidates,
                "unavailable_digest": unavailable.digest,
            },
            domain="provider-explicit-model-candidates-v1",
        ),
    )


def qualify_model_route(
    sender: RouteRequestSender,
    candidate: ModelRouteCandidate,
    *,
    trial_id: Identifier,
    nonce: CanaryNonce,
    token_claim: RequestTokenClaim,
    reasoning_effort: str | None,
    service_tier: ServiceTierLabel | None,
) -> QualifiedModelRoute:
    """Issue exactly one schema-bound paid canary for one explicit candidate route."""

    evidence = run_route_canary(
        sender,
        trial_id=trial_id,
        requested_model=candidate.requested_model,
        nonce=nonce,
        token_claim=token_claim,
        reasoning_effort=reasoning_effort,
        service_tier=service_tier,
    )
    return QualifiedModelRoute(candidate=candidate, canary=evidence)


def freeze_model_set(
    configuration: ResolvedProviderConfig,
    discovery: ModelDiscoverySnapshot,
    candidates: tuple[ModelRouteCandidate, ...],
    outcomes: tuple[ModelRouteOutcome, ...],
    *,
    resolved_on: DateStamp,
) -> ModelSetFreezeResult:
    """Mechanically freeze every selected candidate from its sole canary outcome."""

    if (
        discovery.provider_profile_digest != configuration.profile.digest
        or discovery.provider_config_digest != configuration.digest
        or discovery.selected_provider_label != configuration.selected_provider_label
    ):
        raise ValueError("model discovery differs from its provider configuration")
    _validate_candidate_set(candidates)
    if {candidate.requested_model for candidate in candidates} - set(
        discovery.model_labels
    ):
        raise ValueError("model candidates are absent from the discovery evidence")
    candidates_by_route = {candidate.route_id: candidate for candidate in candidates}
    outcomes_by_route = {outcome.candidate.route_id: outcome for outcome in outcomes}
    if len(outcomes_by_route) != len(outcomes) or set(outcomes_by_route) != set(
        candidates_by_route
    ):
        raise ValueError("model route outcomes must exactly cover every candidate")
    if any(
        outcome.candidate != candidates_by_route[route_id]
        for route_id, outcome in outcomes_by_route.items()
    ):
        raise ValueError("model route outcome differs from its selected candidate")

    qualified = tuple(
        outcome
        for outcome in outcomes
        if isinstance(outcome, QualifiedModelRoute)
    )
    excluded = tuple(
        outcome
        for outcome in outcomes
        if isinstance(outcome, ExcludedModelRoute)
    )
    routes = tuple(_freeze_route(outcome) for outcome in qualified)
    exclusions = tuple(
        ExcludedRoute(
            requested_model=outcome.candidate.requested_model,
            reason=outcome.reason,
            evidence_digest=outcome.evidence_digest,
        )
        for outcome in excluded
    )
    uncovered = _uncovered_categories(discovery, candidates, outcomes, routes)
    if not routes:
        return ModelSetUnavailable(
            provider_config_digest=configuration.digest,
            discovery_digest=discovery.digest,
            exclusions=exclusions,
            uncovered_categories=uncovered,
        )
    return ModelSetManifest(
        provider_config_digest=configuration.digest,
        discovery_digest=discovery.digest,
        resolved_on=resolved_on,
        routes=routes,
        exclusions=exclusions,
        uncovered_categories=uncovered,
    )


def _decode_model_labels(raw: bytes) -> tuple[ModelLabel, ...]:
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ModelDiscoveryError("provider models response is not valid UTF-8 JSON") from None
    if not isinstance(decoded, dict) or not isinstance(decoded.get("data"), list):
        raise ModelDiscoveryError("provider models response lacks a data list")
    labels: list[ModelLabel] = []
    try:
        for item in decoded["data"]:
            if not isinstance(item, dict):
                raise ModelDiscoveryError("provider model entry is not an object")
            labels.append(_MODEL_LABEL.validate_python(item.get("id")))
    except ValidationError:
        raise ModelDiscoveryError("provider model entry has an invalid identifier") from None
    if not labels or len(labels) != len(set(labels)):
        raise ModelDiscoveryError("provider models response must contain unique model labels")
    return tuple(sorted(labels))


def _validate_candidate_set(candidates: tuple[ModelRouteCandidate, ...]) -> None:
    route_ids = [candidate.route_id for candidate in candidates]
    models = [candidate.requested_model for candidate in candidates]
    if not candidates or len(route_ids) != len(set(route_ids)):
        raise ValueError("model route candidates require unique non-empty route identities")
    if len(models) != len(set(models)):
        raise ValueError("one requested model may define only one route candidate")


def _freeze_route(outcome: QualifiedModelRoute) -> ModelRoute:
    candidate = outcome.candidate
    canary = outcome.canary
    return ModelRoute(
        route_id=candidate.route_id,
        requested_model=candidate.requested_model,
        provider_reported_model=canary.provider_reported_model,
        reference_kind=candidate.reference_kind,
        categories=candidate.categories,
        qualification=RouteQualification(
            reasoning_control=canary.reasoning_control,
            requested_service_tier=canary.service_tier_requested,
            provider_reported_service_tier=canary.provider_reported_service_tier,
            observed_input_token_floor=canary.observed_input_token_floor,
            canary_tool_schema_digest=canary.tool_schema_digest,
            canary_evidence_digest=canary.digest,
        ),
        provider_attestation_digest=candidate.provider_attestation_digest,
    )


def _uncovered_categories(
    discovery: ModelDiscoverySnapshot,
    candidates: tuple[ModelRouteCandidate, ...],
    outcomes: tuple[ModelRouteOutcome, ...],
    routes: tuple[ModelRoute, ...],
) -> tuple[UncoveredCategory, ...]:
    covered = {category for route in routes for category in route.categories}
    candidates_by_category = {
        category: tuple(
            candidate for candidate in candidates if category in candidate.categories
        )
        for category in REQUIRED_MODEL_CATEGORIES
    }
    outcome_by_route = {outcome.candidate.route_id: outcome for outcome in outcomes}
    result: list[UncoveredCategory] = []
    for category in sorted(REQUIRED_MODEL_CATEGORIES - covered):
        selected = candidates_by_category[category]
        category_outcomes = tuple(outcome_by_route[item.route_id] for item in selected)
        if not selected:
            reason = CategoryExclusionReason.NO_DISCOVERED_ROUTE
        elif any(
            isinstance(outcome, ExcludedModelRoute)
            and outcome.reason is RouteExclusionReason.PROBE_BUDGET_EXHAUSTED
            for outcome in category_outcomes
        ):
            reason = CategoryExclusionReason.PROBE_BUDGET_EXHAUSTED
        else:
            reason = CategoryExclusionReason.NO_QUALIFIED_ROUTE
        result.append(
            UncoveredCategory(
                category=category,
                reason=reason,
                evidence_digest=canonical_digest(
                    {
                        "category": category,
                        "discovery_digest": discovery.digest,
                        "outcome_digests": tuple(
                            outcome.digest for outcome in category_outcomes
                        ),
                    },
                    domain="provider-model-category-coverage-v1",
                ),
            )
        )
    return tuple(result)
