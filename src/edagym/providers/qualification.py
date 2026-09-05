"""Paid, bounded capability evidence for one Responses-compatible route."""

from __future__ import annotations

import json
from typing import Annotated, Literal, Protocol, Self

from pydantic import StringConstraints, model_validator

from edagym.canonical import canonical_digest
from edagym.providers.campaign import FeatureSupport
from edagym.providers.model import (
    FunctionCall,
    FunctionCallStatus,
    FunctionTool,
    InputMessage,
    InputRole,
    ModelLabel,
    RequestTokenClaim,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
    ToolParameter,
    ToolValueKind,
)
from edagym.providers.numeric import JcsNonNegativeInt, JcsPositiveInt
from edagym.specs.common import (
    Digest,
    Identifier,
    SchemaVersion,
    ServiceTierLabel,
    StrictModel,
)

CanaryNonce = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class RouteCanaryError(RuntimeError):
    """The paid route response did not prove the required protocol subset."""


class RouteRequestSender(Protocol):
    def request(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        request: ResponsesRequest,
    ) -> ResponsesResult: ...


class RouteCanaryUsage(StrictModel):
    input_tokens: JcsPositiveInt
    output_tokens: JcsPositiveInt
    total_tokens: JcsPositiveInt
    cached_input_tokens: JcsNonNegativeInt | None = None
    reasoning_tokens: JcsNonNegativeInt | None = None

    @model_validator(mode="after")
    def validate_counters(self) -> Self:
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("canary total tokens must equal input plus output tokens")
        if self.cached_input_tokens is not None and self.cached_input_tokens > self.input_tokens:
            raise ValueError("canary cached input tokens cannot exceed input tokens")
        if self.reasoning_tokens is not None and self.reasoning_tokens > self.output_tokens:
            raise ValueError("canary reasoning tokens cannot exceed output tokens")
        return self


class RouteCanaryEvidence(StrictModel):
    """Secret-free result of one route's single paid protocol request."""

    schema_version: SchemaVersion = 1
    requested_model: ModelLabel
    provider_reported_model: ModelLabel
    response_status: Literal[ResponseStatus.COMPLETED] = ResponseStatus.COMPLETED
    reasoning_control: FeatureSupport
    service_tier_requested: ServiceTierLabel | None = None
    provider_reported_service_tier: ServiceTierLabel | None = None
    request_body_bytes: JcsPositiveInt
    tool_schema_digest: Digest
    usage: RouteCanaryUsage

    @property
    def observed_input_token_floor(self) -> int:
        return self.usage.input_tokens

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-route-canary-evidence-v1")


def run_route_canary(
    sender: RouteRequestSender,
    *,
    trial_id: Identifier,
    requested_model: str,
    nonce: CanaryNonce,
    token_claim: RequestTokenClaim,
    reasoning_effort: str | None,
    service_tier: str | None,
) -> RouteCanaryEvidence:
    """Require one schema-constrained tool call and non-zero provider usage."""

    tool = _canary_tool(nonce)
    request = ResponsesRequest(
        model=requested_model,
        inputs=(
            InputMessage(
                role=InputRole.USER,
                content=(
                    "Call the declared protocol canary exactly once with the supplied "
                    "values. Do not answer in prose."
                ),
            ),
        ),
        tools=(tool,),
        reasoning_effort=reasoning_effort,
        service_tier=service_tier,
        tool_choice_required=True,
        token_claim=token_claim,
    )
    result = sender.request(
        trial_id=trial_id,
        request_key="route_canary_request",
        request=request,
    )
    if result.status is not ResponseStatus.COMPLETED:
        raise RouteCanaryError("route canary did not complete")
    calls = [output for output in result.outputs if isinstance(output, FunctionCall)]
    if (
        len(calls) != 1
        or calls[0].name != tool.name
        or calls[0].status is not FunctionCallStatus.COMPLETED
    ):
        raise RouteCanaryError("route canary did not return the required tool call")
    try:
        arguments = json.loads(calls[0].arguments)
    except json.JSONDecodeError:
        raise RouteCanaryError("route canary arguments are not JSON") from None
    if arguments != {"nonce": nonce, "protocol": "responses"}:
        raise RouteCanaryError("route canary arguments do not match the schema-bound values")
    usage = result.usage
    if usage is None or usage.input_tokens <= 0 or usage.output_tokens <= 0:
        raise RouteCanaryError("route canary did not report non-zero token usage")
    return RouteCanaryEvidence(
        requested_model=requested_model,
        provider_reported_model=result.reported_model,
        reasoning_control=(
            FeatureSupport.SUPPORTED
            if reasoning_effort is not None
            else FeatureSupport.UNKNOWN
        ),
        service_tier_requested=service_tier,
        provider_reported_service_tier=result.reported_service_tier,
        request_body_bytes=len(request._wire_body()),
        tool_schema_digest=canonical_digest(tool, domain="provider-function-tool-v1"),
        usage=RouteCanaryUsage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
            cached_input_tokens=usage.cached_input_tokens,
            reasoning_tokens=usage.reasoning_tokens,
        ),
    )


def _canary_tool(nonce: str) -> FunctionTool:
    return FunctionTool(
        name="edagym_protocol_canary",
        description="Return the exact fixed values to prove typed function calling.",
        parameters=(
            ToolParameter(
                name="nonce",
                kind=ToolValueKind.STRING,
                description="The fixed protocol probe nonce.",
                choices=(nonce,),
            ),
            ToolParameter(
                name="protocol",
                kind=ToolValueKind.STRING,
                description="The fixed wire protocol name.",
                choices=("responses",),
            ),
        ),
    )
