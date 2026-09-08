"""Native Responses wire preservation with controller-owned request limits."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, SupportsIndex

from pydantic import TypeAdapter, ValidationError

from edagym.providers.model import (
    ProviderContentType,
    ProviderUsage,
    RequestTokenClaim,
    ResponseStatus,
)
from edagym.providers.responses import (
    ProviderProtocolError,
    RawHttpResponse,
    _decode_usage,
)
from edagym.security.canary_artifact import MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES
from edagym.specs.common import ModelLabel, Sensitivity, ServiceTierLabel

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


class NativeResponsesRequest:
    """An opaque CLI request, constrained without rewriting its native tool protocol."""

    __slots__ = ("_body", "_model", "_token_claim")
    classification = Sensitivity.CONFIDENTIAL

    def __init__(
        self,
        body: bytes,
        *,
        requested_model: str,
        token_claim: RequestTokenClaim,
        reasoning_effort: str,
        service_tier: str,
    ) -> None:
        if len(body) > MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES:
            raise ProviderProtocolError("native request exceeds its wire byte bound")
        payload = _json_object(body)
        if set(payload) - _REQUEST_FIELDS:
            raise ProviderProtocolError("native request contains unsupported fields")
        try:
            model = _MODEL.validate_python(payload.get("model"))
            tier = _TIER.validate_python(service_tier)
        except ValidationError:
            raise ProviderProtocolError("native request identity is invalid") from None
        if model != requested_model or payload.get("service_tier", tier) != tier:
            raise ProviderProtocolError("native request differs from its frozen model or tier")
        if payload.get("stream") is not True or payload.get("store", False) is not False:
            raise ProviderProtocolError("native requests require stateless streaming")
        reasoning = payload.get("reasoning", {})
        if (
            not isinstance(reasoning, dict)
            or reasoning.get("effort", reasoning_effort) != reasoning_effort
        ):
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
        payload["service_tier"] = tier
        payload["reasoning"] = {**reasoning, "effort": reasoning_effort}
        try:
            encoded = json.dumps(
                payload, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
            ).encode()
        except (ValueError, UnicodeError, RecursionError):
            raise ProviderProtocolError("native request cannot be encoded") from None
        if len(encoded) > MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES:
            raise ProviderProtocolError("native request exceeds its wire byte bound")
        self._body = encoded
        self._model = model
        self._token_claim = token_claim

    @property
    def model(self) -> str:
        return self._model

    @property
    def token_claim(self) -> RequestTokenClaim:
        return self._token_claim

    @property
    def wire_body(self) -> bytes:
        return self._body

    def __repr__(self) -> str:
        return "NativeResponsesRequest(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("native requests cannot be implicitly serialized")


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


@dataclass(frozen=True, slots=True, repr=False)
class NativeResponsesResult:
    """A verified terminal receipt alongside the exact stream consumed by the CLI."""

    reported_model: str
    reported_service_tier: str | None
    status: ResponseStatus
    usage: ProviderUsage
    response: RawHttpResponse

    classification = Sensitivity.CONFIDENTIAL

    def __repr__(self) -> str:
        return "NativeResponsesResult(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("native responses cannot be implicitly serialized")


def decode_native_response(response: RawHttpResponse) -> NativeResponsesResult:
    """Require one terminal SSE receipt; an interrupted stream has no refundable usage."""

    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if media_type != ProviderContentType.EVENT_STREAM:
        raise ProviderProtocolError("native provider success response is not an event stream")
    try:
        text = response.body.decode("utf-8")
    except UnicodeError:
        raise ProviderProtocolError("native provider stream is not UTF-8") from None
    terminal: dict[str, Any] | None = None
    expected_status: ResponseStatus | None = None
    event_name: str | None = None
    data: list[str] = []
    for line in text.split("\n"):
        line = line.removesuffix("\r")
        if line:
            field, separator, value = line.partition(":")
            if not separator:
                value = ""
            value = value.removeprefix(" ")
            if field == "event":
                event_name = value
            elif field == "data":
                data.append(value)
            continue
        if not data:
            event_name = None
            continue
        payload = "\n".join(data)
        data = []
        if payload == "[DONE]" and terminal is not None:
            event_name = None
            continue
        item = _json_object(payload)
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
        event_name = None
    if data or terminal is None or terminal.get("status") != expected_status:
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
    return NativeResponsesResult(
        reported_model=model,
        reported_service_tier=tier,
        status=expected_status,
        usage=usage,
        response=response,
    )


def _json_object(value: bytes | str) -> dict[str, Any]:
    try:
        result = json.loads(
            value, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ProviderProtocolError("native wire JSON is invalid") from None
    if not isinstance(result, dict):
        raise ProviderProtocolError("native wire record must be an object")
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate wire key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite wire number")
