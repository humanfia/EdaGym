"""Confidential native request normalization and bounded stream receipts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, SupportsIndex

from pydantic import TypeAdapter, ValidationError

from edagym.providers.model import (
    MessagesWire,
    ProviderContentType,
    ProviderUsage,
    ProviderWire,
    RequestTokenClaim,
    ResponseStatus,
    WireProtocol,
)
from edagym.providers.responses import ProviderProtocolError, RawHttpResponse
from edagym.security.canary_artifact import (
    MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES,
    MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES,
)
from edagym.specs.common import ModelLabel, Sensitivity, ServiceTierLabel

_MODEL = TypeAdapter(ModelLabel)
_TIER = TypeAdapter(ServiceTierLabel)


class NativeProviderRequest:
    """A native wire request constrained by the controller's frozen request grant."""

    __slots__ = ("_beta_features", "_body", "_model", "_token_claim", "_wire_protocol")
    classification = Sensitivity.CONFIDENTIAL

    def __init__(
        self,
        body: bytes,
        *,
        wire: ProviderWire,
        requested_model: str,
        token_claim: RequestTokenClaim,
        reasoning_effort: str,
        service_tier: str,
        beta_features: tuple[str, ...] = (),
    ) -> None:
        from edagym.providers.native_messages import normalize_messages_request
        from edagym.providers.native_responses import normalize_responses_request

        if len(body) > MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES:
            raise ProviderProtocolError("native request exceeds its wire byte bound")
        payload = json_object(body)
        try:
            model = _MODEL.validate_python(payload.get("model"))
            tier = _TIER.validate_python(service_tier)
        except ValidationError:
            raise ProviderProtocolError("native request identity is invalid") from None
        if model != requested_model or payload.get("service_tier", tier) != tier:
            raise ProviderProtocolError("native request differs from its frozen model or tier")
        if payload.get("stream") is not True:
            raise ProviderProtocolError("native requests require streaming")
        if isinstance(wire, MessagesWire):
            try:
                beta_features = wire.admit_features(beta_features)
            except ValueError:
                raise ProviderProtocolError(
                    "native request beta features are not granted"
                ) from None
        elif beta_features:
            raise ProviderProtocolError("Responses requests do not accept Messages features")
        if wire.protocol is WireProtocol.RESPONSES:
            normalize_responses_request(payload, token_claim=token_claim, effort=reasoning_effort)
        elif wire.protocol is WireProtocol.MESSAGES:
            normalize_messages_request(
                payload, token_claim=token_claim, effort=reasoning_effort, service_tier=tier
            )
        else:
            raise ProviderProtocolError("native request wire protocol is unsupported")
        payload["service_tier"] = tier
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
        self._wire_protocol = wire.protocol
        self._beta_features = beta_features

    @property
    def model(self) -> str:
        return self._model

    @property
    def token_claim(self) -> RequestTokenClaim:
        return self._token_claim

    @property
    def wire_protocol(self) -> WireProtocol:
        return self._wire_protocol

    @property
    def beta_features(self) -> tuple[str, ...]:
        return self._beta_features

    @property
    def wire_body(self) -> bytes:
        return self._body

    def __repr__(self) -> str:
        return "NativeProviderRequest(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("native requests cannot be implicitly serialized")


@dataclass(frozen=True, slots=True, repr=False)
class NativeProviderResult:
    """A verified terminal receipt alongside the exact stream consumed by the CLI."""

    reported_model: str
    reported_service_tier: str | None
    status: ResponseStatus
    usage: ProviderUsage
    response: RawHttpResponse

    classification = Sensitivity.CONFIDENTIAL

    def __repr__(self) -> str:
        return "NativeProviderResult(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("native responses cannot be implicitly serialized")


def sse_data(response: RawHttpResponse) -> Iterator[tuple[str | None, str]]:
    """Read complete SSE records without interpreting protocol-specific events."""

    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if media_type != ProviderContentType.EVENT_STREAM:
        raise ProviderProtocolError("native provider success response is not an event stream")
    if len(response.body) > MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES:
        raise ProviderProtocolError("native provider stream exceeds its wire byte bound")
    try:
        text = response.body.decode("utf-8")
    except UnicodeError:
        raise ProviderProtocolError("native provider stream is not UTF-8") from None
    event_name: str | None = None
    data: list[str] = []
    for line in text.split("\n"):
        line = line.removesuffix("\r")
        if line:
            field, separator, value = line.partition(":")
            value = value.removeprefix(" ") if separator else ""
            if field == "event":
                event_name = value
            elif field == "data":
                data.append(value)
        else:
            if data:
                yield event_name, "\n".join(data)
            event_name, data = None, []
    if data:
        raise ProviderProtocolError("native provider stream ends within an event")


def json_object(value: bytes | str) -> dict[str, Any]:
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
