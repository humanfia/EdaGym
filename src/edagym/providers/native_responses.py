"""Native Responses wire preservation with controller-owned request limits."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import TypeAdapter, ValidationError

from edagym.providers.model import RequestTokenClaim, ResponseStatus
from edagym.providers.native_wire import NativeProviderResult, json_object, sse_data
from edagym.providers.responses import ProviderProtocolError, RawHttpResponse, _decode_usage
from edagym.specs.common import ModelLabel, ServiceTierLabel

_MODEL = TypeAdapter(ModelLabel)
_TIER = TypeAdapter(ServiceTierLabel)
_REQUEST_FIELDS = frozenset(
    {
        "model",
        "input",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "include",
        "prompt_cache_key",
        "text",
        "client_metadata",
        "max_output_tokens",
        "service_tier",
    }
)


class _InputKind(StrEnum):
    MESSAGE = "message"
    ADDITIONAL_TOOLS = "additional_tools"
    FUNCTION_CALL = "function_call"
    FUNCTION_OUTPUT = "function_call_output"
    CUSTOM_CALL = "custom_tool_call"
    CUSTOM_OUTPUT = "custom_tool_call_output"
    REASONING = "reasoning"


class _ToolKind(StrEnum):
    FUNCTION = "function"
    CUSTOM = "custom"
    NAMESPACE = "namespace"


class _EventKind(StrEnum):
    CREATED = "response.created"
    IN_PROGRESS = "response.in_progress"
    QUEUED = "response.queued"
    OUTPUT_ITEM_ADDED = "response.output_item.added"
    OUTPUT_ITEM_DONE = "response.output_item.done"
    CONTENT_PART_ADDED = "response.content_part.added"
    CONTENT_PART_DONE = "response.content_part.done"
    OUTPUT_TEXT_DELTA = "response.output_text.delta"
    OUTPUT_TEXT_DONE = "response.output_text.done"
    OUTPUT_TEXT_ANNOTATION = "response.output_text.annotation.added"
    FUNCTION_ARGUMENTS_DELTA = "response.function_call_arguments.delta"
    FUNCTION_ARGUMENTS_DONE = "response.function_call_arguments.done"
    CUSTOM_INPUT_DELTA = "response.custom_tool_call_input.delta"
    CUSTOM_INPUT_DONE = "response.custom_tool_call_input.done"
    REASONING_SUMMARY_PART_ADDED = "response.reasoning_summary_part.added"
    REASONING_SUMMARY_PART_DONE = "response.reasoning_summary_part.done"
    REASONING_SUMMARY_TEXT_DELTA = "response.reasoning_summary_text.delta"
    REASONING_SUMMARY_TEXT_DONE = "response.reasoning_summary_text.done"
    REASONING_TEXT_DELTA = "response.reasoning_text.delta"
    REASONING_TEXT_DONE = "response.reasoning_text.done"
    REFUSAL_DELTA = "response.refusal.delta"
    REFUSAL_DONE = "response.refusal.done"
    COMPLETED = "response.completed"
    INCOMPLETE = "response.incomplete"
    FAILED = "response.failed"
    ERROR = "error"


_TERMINAL_EVENTS = {
    _EventKind.COMPLETED: ResponseStatus.COMPLETED,
    _EventKind.INCOMPLETE: ResponseStatus.INCOMPLETE,
    _EventKind.FAILED: ResponseStatus.FAILED,
}


def normalize_responses_request(
    payload: dict[str, Any], *, token_claim: RequestTokenClaim, effort: str
) -> None:
    if set(payload) - _REQUEST_FIELDS:
        raise ProviderProtocolError("native request contains unsupported fields")
    if payload.get("store", False) is not False:
        raise ProviderProtocolError("native requests require stateless streaming")
    reasoning = payload.get("reasoning", {})
    if not isinstance(reasoning, dict) or reasoning.get("effort", effort) != effort:
        raise ProviderProtocolError("native reasoning effort differs from the frozen policy")
    inputs = payload.get("input")
    if not isinstance(inputs, list) or not inputs:
        raise ProviderProtocolError("native requests require an explicit input history")
    for item in inputs:
        if not isinstance(item, dict):
            raise ProviderProtocolError("native input items must be objects")
        try:
            kind = _InputKind(item.get("type", "message"))
        except ValueError:
            raise ProviderProtocolError("native input type is unsupported") from None
        if kind is _InputKind.ADDITIONAL_TOOLS:
            _validate_tools(item.get("tools"))
    if "tools" in payload:
        _validate_tools(payload["tools"])
    maximum = payload.get("max_output_tokens", token_claim.output_tokens)
    if type(maximum) is not int or maximum <= 0:
        raise ProviderProtocolError("native output limit must be a positive integer")
    payload["max_output_tokens"] = min(maximum, token_claim.output_tokens)
    payload["store"] = False
    payload["reasoning"] = {**reasoning, "effort": effort}


def _validate_tools(value: object, *, depth: int = 0) -> None:
    if not isinstance(value, list) or depth > 8:
        raise ProviderProtocolError("native tool declarations exceed their structural bound")
    for item in value:
        if not isinstance(item, dict):
            raise ProviderProtocolError("native tools must be objects")
        tool_type = item.get("type")
        if not isinstance(tool_type, str):
            raise ProviderProtocolError("native tools require a declared type")
        try:
            kind = _ToolKind(tool_type)
        except ValueError:
            raise ProviderProtocolError(
                "provider-hosted tools are outside the native grant"
            ) from None
        if kind is _ToolKind.NAMESPACE:
            _validate_tools(item.get("tools"), depth=depth + 1)


def decode_responses_stream(response: RawHttpResponse) -> NativeProviderResult:
    """Require one terminal receipt; an interrupted stream has no refundable usage."""

    terminal: dict[str, Any] | None = None
    expected_status: ResponseStatus | None = None
    for event_name, payload in sse_data(response):
        if payload == "[DONE]" and terminal is not None:
            continue
        item = json_object(payload)
        item_type = item.get("type")
        if not isinstance(item_type, str) or (event_name is not None and event_name != item_type):
            raise ProviderProtocolError("native stream event identity is inconsistent")
        try:
            kind = _EventKind(item_type)
        except ValueError:
            raise ProviderProtocolError("native provider stream event is unsupported") from None
        if terminal is not None:
            raise ProviderProtocolError("native stream contains data after its terminal receipt")
        if kind in _TERMINAL_EVENTS:
            terminal = item.get("response")
            expected_status = _TERMINAL_EVENTS[kind]
            if not isinstance(terminal, dict):
                raise ProviderProtocolError("native terminal event has no response")
        elif kind is _EventKind.ERROR:
            raise ProviderProtocolError("native stream ended with a provider error")
    if terminal is None or terminal.get("status") != expected_status:
        raise ProviderProtocolError("native stream has no complete terminal receipt")
    try:
        model = _MODEL.validate_python(terminal.get("model"))
        tier = terminal.get("service_tier")
        if tier is not None:
            tier = _TIER.validate_python(tier)
    except ValidationError:
        raise ProviderProtocolError("native response identity is invalid") from None
    assert expected_status is not None
    usage = _decode_usage(terminal.get("usage"))
    if usage is None:
        raise ProviderProtocolError("native provider terminal receipt has no exact usage")
    return NativeProviderResult(
        reported_model=model,
        reported_service_tier=tier,
        status=expected_status,
        usage=usage,
        response=response,
    )
