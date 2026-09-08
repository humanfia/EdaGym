"""Evidence-driven provider model discovery and freezing semantics."""

from __future__ import annotations

import hashlib

import pytest

from edagym.providers.campaign import (
    CategoryExclusionReason,
    FeatureSupport,
    ModelCategory,
    ModelReferenceKind,
    ModelSetManifest,
    RouteExclusionReason,
)
from edagym.providers.model import (
    FunctionCall,
    FunctionCallStatus,
    ProviderDefaults,
    ProviderProfile,
    ProviderUsage,
    RequestTokenClaim,
    ResolvedProviderConfig,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
)
from edagym.providers.model_discovery import (
    ExcludedModelRoute,
    ModelDiscoverySource,
    ModelDiscoveryUnavailable,
    ModelDiscoveryUnavailableReason,
    ModelRouteCandidate,
    ModelSetUnavailable,
    QualifiedModelRoute,
    declare_explicit_model_candidates,
    discover_provider_models,
    freeze_model_set,
    qualify_model_route,
)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _configuration(*, models_path: str | None) -> ResolvedProviderConfig:
    return ResolvedProviderConfig(
        selected_provider_label="DeclaredGateway",
        profile=ProviderProfile(
            logical_id="declared.gateway",
            origin="https://gateway.test",
            request_path="/v1/responses",
            models_path=models_path,
        ),
        defaults=ProviderDefaults(requested_model="default-route"),
    )


class _CanarySender:
    def __init__(self) -> None:
        self.payloads: list[dict[str, object]] = []

    def request(
        self,
        *,
        trial_id: str,
        request_key: str,
        request: ResponsesRequest,
    ) -> ResponsesResult:
        assert trial_id == "route-probe"
        assert request_key == "route_canary_request"
        self.payloads.append(request._wire_payload())
        return ResponsesResult(
            response_id="response",
            reported_model=request.model,
            status=ResponseStatus.COMPLETED,
            outputs=(
                FunctionCall(
                    call_id="call",
                    name="edagym_protocol_canary",
                    arguments='{"nonce":"00000000000000000000000000000001",'
                    '"protocol":"responses"}',
                    status=FunctionCallStatus.COMPLETED,
                ),
            ),
            usage=ProviderUsage(
                input_tokens=20,
                output_tokens=5,
                total_tokens=25,
            ),
        )


def _candidate(
    route_id: str,
    requested_model: str,
    categories: tuple[ModelCategory, ...],
) -> ModelRouteCandidate:
    return ModelRouteCandidate(
        route_id=route_id,
        requested_model=requested_model,
        reference_kind=ModelReferenceKind.UNKNOWN,
        categories=categories,
    )


def test_discovery_never_opens_an_authenticated_endpoint_before_preflight() -> None:
    configuration = _configuration(models_path="/v1/models")
    gated = discover_provider_models(configuration)
    assert (
        gated.reason
        is ModelDiscoveryUnavailableReason.AUTHENTICATED_ENDPOINT_REQUIRES_PREFLIGHT
    )

    fallback_configuration = _configuration(models_path=None)
    unavailable = discover_provider_models(fallback_configuration)
    assert isinstance(unavailable, ModelDiscoveryUnavailable)
    assert (
        unavailable.reason
        is ModelDiscoveryUnavailableReason.MODELS_ENDPOINT_NOT_DECLARED
    )

    candidates = (
        _candidate("frontier", "route-z", (ModelCategory.FRONTIER_REASONING,)),
        _candidate("balanced", "route-a", (ModelCategory.BALANCED,)),
    )
    fallback = declare_explicit_model_candidates(
        fallback_configuration,
        unavailable,
        candidates,
    )
    assert fallback.source is ModelDiscoverySource.EXPLICIT_CANDIDATES
    assert fallback.model_labels == ("route-a", "route-z")
    with pytest.raises(ValueError, match="without model discovery"):
        declare_explicit_model_candidates(configuration, gated, candidates)


def test_route_canary_omits_unqualified_reasoning_and_records_supported_control() -> None:
    candidate = _candidate(
        "frontier",
        "route-frontier",
        (ModelCategory.FRONTIER_REASONING,),
    )
    sender = _CanarySender()
    claim = RequestTokenClaim(input_tokens=100, output_tokens=20)

    unknown = qualify_model_route(
        sender,
        candidate,
        trial_id="route-probe",
        nonce="00000000000000000000000000000001",
        token_claim=claim,
        reasoning_effort=None,
        service_tier=None,
    )
    supported = qualify_model_route(
        sender,
        candidate,
        trial_id="route-probe",
        nonce="00000000000000000000000000000001",
        token_claim=claim,
        reasoning_effort="high",
        service_tier="fast",
    )

    assert unknown.canary.reasoning_control is FeatureSupport.UNKNOWN
    assert "reasoning" not in sender.payloads[0]
    assert "service_tier" not in sender.payloads[0]
    assert supported.canary.reasoning_control is FeatureSupport.SUPPORTED
    assert sender.payloads[1]["reasoning"] == {"effort": "high"}
    assert sender.payloads[1]["service_tier"] == "fast"
    assert all(payload["store"] is False for payload in sender.payloads)


def test_freeze_projects_exact_route_outcomes_and_required_category_gaps() -> None:
    configuration = _configuration(models_path=None)
    unavailable = ModelDiscoveryUnavailable(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        selected_provider_label=configuration.selected_provider_label,
        reason=ModelDiscoveryUnavailableReason.MODELS_ENDPOINT_NOT_DECLARED,
    )
    qualified_candidate = _candidate(
        "frontier",
        "route-frontier",
        (
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
        ),
    )
    excluded_candidate = _candidate(
        "balanced",
        "route-balanced",
        (ModelCategory.BALANCED,),
    )
    candidates = (qualified_candidate, excluded_candidate)
    discovery = declare_explicit_model_candidates(
        configuration,
        unavailable,
        candidates,
    )
    sender = _CanarySender()
    qualified = qualify_model_route(
        sender,
        qualified_candidate,
        trial_id="route-probe",
        nonce="00000000000000000000000000000001",
        token_claim=RequestTokenClaim(input_tokens=100, output_tokens=20),
        reasoning_effort="high",
        service_tier="fast",
    )
    excluded = ExcludedModelRoute(
        candidate=excluded_candidate,
        reason=RouteExclusionReason.USAGE_UNAVAILABLE,
        evidence_digest=_digest("balanced-canary-failure"),
    )

    frozen = freeze_model_set(
        configuration,
        discovery,
        candidates,
        (qualified, excluded),
        resolved_on="2026-09-04",
    )

    assert isinstance(frozen, ModelSetManifest)
    assert tuple(route.route_id for route in frozen.routes) == ("frontier",)
    assert frozen.routes[0].qualification.observed_input_token_floor == 20
    assert frozen.exclusions[0].requested_model == "route-balanced"
    uncovered = {item.category: item.reason for item in frozen.uncovered_categories}
    assert uncovered == {
        ModelCategory.BALANCED: CategoryExclusionReason.NO_QUALIFIED_ROUTE,
        ModelCategory.HIGH_THROUGHPUT: CategoryExclusionReason.NO_DISCOVERED_ROUTE,
    }

    no_routes = freeze_model_set(
        configuration,
        discovery,
        candidates,
        (
            ExcludedModelRoute(
                candidate=qualified_candidate,
                reason=RouteExclusionReason.PROBE_BUDGET_EXHAUSTED,
                evidence_digest=_digest("frontier-budget"),
            ),
            excluded,
        ),
        resolved_on="2026-09-04",
    )
    assert isinstance(no_routes, ModelSetUnavailable)
    assert {item.requested_model for item in no_routes.exclusions} == {
        "route-frontier",
        "route-balanced",
    }

    with pytest.raises(ValueError, match="exactly cover"):
        freeze_model_set(
            configuration,
            discovery,
            candidates,
            (QualifiedModelRoute(candidate=qualified_candidate, canary=qualified.canary),),
            resolved_on="2026-09-04",
        )
