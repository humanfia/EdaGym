"""Native Messages wire constraints and cumulative stream accounting."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import TypeAdapter, ValidationError

from edagym.providers.model import InputRole, ProviderUsage, RequestTokenClaim, ResponseStatus
from edagym.providers.native_wire import NativeProviderResult, json_object, sse_data
from edagym.providers.responses import (
    ProviderModelChangeError,
    ProviderProtocolError,
    RawHttpResponse,
)
from edagym.specs.common import ModelLabel, ServiceTierLabel

_MODEL = TypeAdapter(ModelLabel)
_TIER = TypeAdapter(ServiceTierLabel)
_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "system",
        "tools",
        "tool_choice",
        "max_tokens",
        "stream",
        "thinking",
        "output_config",
        "service_tier",
        "metadata",
        "temperature",
        "top_p",
        "top_k",
        "stop_sequences",
        "cache_control",
        "context_management",
    }
)


class _BlockKind(StrEnum):
    TEXT = "text"
    THINKING = "thinking"
    REDACTED_THINKING = "redacted_thinking"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    FALLBACK = "fallback"


class _ThinkingKind(StrEnum):
    ADAPTIVE = "adaptive"
    DISABLED = "disabled"


class _Effort(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"


class _ServiceTier(StrEnum):
    AUTO = "auto"
    STANDARD_ONLY = "standard_only"


class _EventKind(StrEnum):
    MESSAGE_START = "message_start"
    MESSAGE_DELTA = "message_delta"
    MESSAGE_STOP = "message_stop"
    BLOCK_START = "content_block_start"
    BLOCK_DELTA = "content_block_delta"
    BLOCK_STOP = "content_block_stop"
    PING = "ping"
    ERROR = "error"


class _DeltaKind(StrEnum):
    TEXT = "text_delta"
    INPUT_JSON = "input_json_delta"
    THINKING = "thinking_delta"
    SIGNATURE = "signature_delta"


class _StopReason(StrEnum):
    END_TURN = "end_turn"
    STOP_SEQUENCE = "stop_sequence"
    TOOL_USE = "tool_use"
    MAX_TOKENS = "max_tokens"
    CONTEXT_WINDOW = "model_context_window_exceeded"
    REFUSAL = "refusal"


_DELTA_BLOCKS = {
    _DeltaKind.TEXT: _BlockKind.TEXT,
    _DeltaKind.INPUT_JSON: _BlockKind.TOOL_USE,
    _DeltaKind.THINKING: _BlockKind.THINKING,
    _DeltaKind.SIGNATURE: _BlockKind.THINKING,
}
_INPUT_BLOCKS = frozenset(
    {
        _BlockKind.TEXT,
        _BlockKind.THINKING,
        _BlockKind.REDACTED_THINKING,
        _BlockKind.TOOL_USE,
        _BlockKind.TOOL_RESULT,
    }
)
_TEXT_BLOCKS = frozenset({_BlockKind.TEXT})
_COUNTERS = frozenset(
    {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"}
)
_USAGE_FIELDS = _COUNTERS | {
    "cache_creation",
    "server_tool_use",
    "service_tier",
    "inference_geo",
    "output_tokens_details",
}


def normalize_messages_request(
    payload: dict[str, Any], *, token_claim: RequestTokenClaim, effort: str, service_tier: str
) -> None:
    if set(payload) - _REQUEST_FIELDS:
        raise ProviderProtocolError("native Messages request contains unsupported fields")
    try:
        _Effort(effort)
        _ServiceTier(service_tier)
    except ValueError:
        raise ProviderProtocolError("native Messages controls are unsupported") from None
    output = payload.get("output_config", {})
    if (
        not isinstance(output, dict)
        or set(output) - {"effort", "format"}
        or output.get("effort", effort) != effort
    ):
        raise ProviderProtocolError("native Messages effort differs from the frozen policy")
    thinking = payload.get("thinking")
    if thinking is not None:
        if not isinstance(thinking, dict) or set(thinking) != {"type"}:
            raise ProviderProtocolError("native thinking configuration is unsupported")
        try:
            _ThinkingKind(thinking["type"])
        except ValueError:
            raise ProviderProtocolError("native thinking configuration is unsupported") from None
    context = payload.get("context_management")
    if context is not None and context != {
        "edits": [{"type": "clear_thinking_20251015", "keep": "all"}]
    }:
        raise ProviderProtocolError("native context management must retain the supplied history")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ProviderProtocolError("native Messages requires an explicit message history")
    for message in messages:
        if not isinstance(message, dict):
            raise ProviderProtocolError("native Messages entries must be objects")
        try:
            role = InputRole(message.get("role", ""))
        except ValueError:
            raise ProviderProtocolError("native Messages role is unsupported") from None
        if role is InputRole.DEVELOPER:
            raise ProviderProtocolError("native Messages role is unsupported")
        _validate_content(message.get("content"), allowed=_INPUT_BLOCKS)
    if "system" in payload:
        _validate_content(payload["system"], allowed=_TEXT_BLOCKS)
    tools = payload.get("tools", [])
    if not isinstance(tools, list):
        raise ProviderProtocolError("native Messages tools must be an array")
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type", "custom") != "custom":
            raise ProviderProtocolError("provider-hosted tools are outside the native grant")
    maximum = payload.get("max_tokens")
    if type(maximum) is not int or maximum <= 0:
        raise ProviderProtocolError("native Messages requires a positive output bound")
    payload["max_tokens"] = min(maximum, token_claim.output_tokens)
    payload["output_config"] = {**output, "effort": effort}


def _validate_content(value: object, *, allowed: frozenset[_BlockKind]) -> None:
    if isinstance(value, str):
        return
    if not isinstance(value, list):
        raise ProviderProtocolError("native Messages content must be text or blocks")
    for block in value:
        if not isinstance(block, dict):
            raise ProviderProtocolError("native Messages content blocks must be objects")
        try:
            kind = _BlockKind(block.get("type", ""))
        except ValueError:
            raise ProviderProtocolError("native Messages content type is unsupported") from None
        if kind not in allowed:
            raise ProviderProtocolError("native Messages content type is outside its context")
        if kind is _BlockKind.TOOL_RESULT and "content" in block:
            _validate_content(block["content"], allowed=_TEXT_BLOCKS)


def decode_messages_stream(response: RawHttpResponse) -> NativeProviderResult:
    """Settle only a complete, single-model stream with exact cumulative token usage."""

    message: dict[str, Any] | None = None
    usage: dict[str, Any] = {}
    blocks: dict[int, _BlockKind] = {}
    next_index = 0
    stop_reason: _StopReason | None = None
    ended = False
    for name, data in sse_data(response):
        item = json_object(data)
        try:
            kind = _EventKind(item.get("type", ""))
        except ValueError:
            raise ProviderProtocolError("native Messages event type is unsupported") from None
        if name is not None and name != kind:
            raise ProviderProtocolError("native Messages event identity is inconsistent")
        if ended:
            raise ProviderProtocolError(
                "native Messages contains events after its terminal receipt"
            )
        if kind is _EventKind.PING:
            continue
        if kind is _EventKind.MESSAGE_START:
            if message is not None:
                raise ProviderProtocolError("native Messages stream contains multiple messages")
            value = item.get("message")
            if (
                not isinstance(value, dict)
                or value.get("type") != "message"
                or value.get("role") != InputRole.ASSISTANT
                or value.get("content") != []
                or value.get("stop_reason") is not None
                or value.get("container") is not None
            ):
                raise ProviderProtocolError("native Messages start is inconsistent")
            message = value
            usage = _merge_usage({}, message.get("usage"))
            _counter(usage, "input_tokens")
            continue
        if message is None:
            raise ProviderProtocolError("native Messages stream has no initial message")
        if kind is _EventKind.MESSAGE_DELTA:
            delta = item.get("delta")
            if isinstance(delta, dict) and "model" in delta:
                raise ProviderModelChangeError("native Messages changed its serving model")
            if (
                blocks
                or not isinstance(delta, dict)
                or set(delta) - {"stop_reason", "stop_sequence", "stop_details", "container"}
                or delta.get("container") is not None
            ):
                raise ProviderProtocolError("native Messages delta changes an unsupported field")
            reason = delta.get("stop_reason")
            if reason is not None:
                try:
                    current_reason = _StopReason(reason)
                except ValueError:
                    raise ProviderProtocolError(
                        "native Messages stop reason is unsupported"
                    ) from None
                if stop_reason is not None and current_reason is not stop_reason:
                    raise ProviderProtocolError("native Messages stop reason changed")
                stop_reason = current_reason
            usage = _merge_usage(usage, item.get("usage"))
        elif kind is _EventKind.MESSAGE_STOP:
            if blocks or stop_reason is None:
                raise ProviderProtocolError("native Messages terminal receipt is incomplete")
            ended = True
        elif kind is _EventKind.ERROR:
            raise ProviderProtocolError("native Messages stream ended with a provider error")
        else:
            if stop_reason is not None:
                raise ProviderProtocolError("native Messages content follows its stop reason")
            index = item.get("index")
            if type(index) is not int or index < 0:
                raise ProviderProtocolError("native Messages block index is invalid")
            if kind is _EventKind.BLOCK_START:
                block = item.get("content_block")
                if index != next_index or not isinstance(block, dict):
                    raise ProviderProtocolError("native Messages block start is inconsistent")
                try:
                    block_kind = _BlockKind(block.get("type", ""))
                except ValueError:
                    raise ProviderProtocolError(
                        "native Messages output type is unsupported"
                    ) from None
                if block_kind is _BlockKind.FALLBACK:
                    raise ProviderModelChangeError("native Messages contains a model fallback")
                if block_kind is _BlockKind.TOOL_RESULT:
                    raise ProviderProtocolError("native Messages returned a server tool result")
                blocks[index] = block_kind
                next_index += 1
            elif index not in blocks:
                raise ProviderProtocolError("native Messages block was not started")
            elif kind is _EventKind.BLOCK_STOP:
                del blocks[index]
            else:
                delta = item.get("delta")
                if not isinstance(delta, dict):
                    raise ProviderProtocolError("native Messages content delta is invalid")
                try:
                    delta_kind = _DeltaKind(delta.get("type", ""))
                except ValueError:
                    raise ProviderProtocolError(
                        "native Messages content delta is unsupported"
                    ) from None
                if _DELTA_BLOCKS[delta_kind] is not blocks[index]:
                    raise ProviderProtocolError("native Messages delta differs from its block type")
    if not ended or message is None:
        raise ProviderProtocolError("native Messages stream has no complete terminal receipt")
    try:
        model = _MODEL.validate_python(message.get("model"))
        tier = usage.get("service_tier")
        if tier is not None:
            tier = _TIER.validate_python(tier)
    except ValidationError:
        raise ProviderProtocolError("native Messages response identity is invalid") from None
    status = (
        ResponseStatus.INCOMPLETE
        if stop_reason in {_StopReason.MAX_TOKENS, _StopReason.CONTEXT_WINDOW}
        else ResponseStatus.COMPLETED
    )
    return NativeProviderResult(
        reported_model=model,
        reported_service_tier=tier,
        status=status,
        usage=_decode_usage(usage),
        response=response,
    )


def _counter(value: dict[str, Any], field: str) -> int:
    result = value.get(field)
    if type(result) is not int or result < 0:
        raise ProviderProtocolError("native Messages usage counter is missing or invalid")
    return result


def _merge_usage(previous: dict[str, Any], update: object) -> dict[str, Any]:
    if not isinstance(update, dict) or set(update) - _USAGE_FIELDS:
        raise ProviderProtocolError("native Messages usage is unsupported")
    server = update.get("server_tool_use")
    if server is not None and (
        not isinstance(server, dict)
        or set(server) - {"web_fetch_requests", "web_search_requests"}
        or any(_counter(server, field) for field in server)
    ):
        raise ProviderProtocolError("native Messages returned ungranted server usage")
    _counter(update, "output_tokens")
    result = dict(previous)
    for field, value in update.items():
        if value is None:
            continue
        if field in _COUNTERS:
            current = _counter(update, field)
            if field in previous and current < _counter(previous, field):
                raise ProviderProtocolError("native Messages cumulative usage decreased")
        result[field] = value
    return result


def _decode_usage(value: dict[str, Any]) -> ProviderUsage:
    uncached = _counter(value, "input_tokens")
    created = _counter(value, "cache_creation_input_tokens")
    cached = _counter(value, "cache_read_input_tokens")
    output = _counter(value, "output_tokens")
    creation = value.get("cache_creation")
    if creation is not None and (
        not isinstance(creation, dict)
        or set(creation) != {"ephemeral_1h_input_tokens", "ephemeral_5m_input_tokens"}
        or sum(_counter(creation, field) for field in creation) != created
    ):
        raise ProviderProtocolError("native Messages cache usage is inconsistent")
    details = value.get("output_tokens_details")
    reasoning = None
    if details is not None:
        if not isinstance(details, dict) or set(details) != {"thinking_tokens"}:
            raise ProviderProtocolError("native Messages output token details are unsupported")
        reasoning = _counter(details, "thinking_tokens")
    inputs = uncached + created + cached
    try:
        return ProviderUsage(
            input_tokens=inputs,
            output_tokens=output,
            total_tokens=inputs + output,
            cached_input_tokens=cached,
            reasoning_tokens=reasoning,
        )
    except ValueError:
        raise ProviderProtocolError("native Messages usage counters are inconsistent") from None
