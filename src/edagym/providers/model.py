"""Typed, secret-free provider identities and request contracts."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Literal, SupportsIndex
from urllib.parse import urlsplit

from pydantic import Field, StringConstraints, TypeAdapter, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import (
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    ProviderResponseStatus,
    Sensitivity,
    ServiceTierLabel,
    StrictModel,
)
from edagym.specs.common import (
    ModelLabel as ModelLabel,
)

ResponseStatus = ProviderResponseStatus


class FunctionCallStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"


ToolName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z_][A-Za-z0-9_-]*$"),
]
ProviderConfigLabel = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[\x20-\x7e]+$"),
]
_TOOL_NAME_ADAPTER: TypeAdapter[str] = TypeAdapter(ToolName)


def _https_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("origin must be an HTTPS origin without credentials or a path")
    host = parsed.hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or label[0] == "-"
            or label[-1] == "-"
            or not all(
                character.isascii() and (character.isalnum() or character == "-")
                for character in label
            )
            for label in labels
        ):
            raise ValueError("origin host must be an ASCII DNS name or IP address") from None
    if ":" in host:
        host = f"[{host}]"
    try:
        port_number = parsed.port
    except ValueError:
        raise ValueError("origin port is invalid") from None
    if port_number == 0:
        raise ValueError("origin port is invalid")
    port = f":{port_number}" if port_number is not None else ""
    return f"https://{host}{port}"


class WireProtocol(StrEnum):
    RESPONSES = "responses"
    MESSAGES = "messages"


class ProviderAuthorization(StrEnum):
    BEARER = "bearer"
    API_KEY = "x_api_key"


BetaFeature = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9-]*$")
]


class ResponsesWire(StrictModel):
    protocol: Literal[WireProtocol.RESPONSES] = WireProtocol.RESPONSES
    authorization: Literal[ProviderAuthorization.BEARER] = ProviderAuthorization.BEARER


class MessagesWire(StrictModel):
    protocol: Literal[WireProtocol.MESSAGES] = WireProtocol.MESSAGES
    authorization: ProviderAuthorization
    api_version: Literal["2023-06-01"] = "2023-06-01"
    beta_features: tuple[BetaFeature, ...] = Field(
        default=(), max_length=32, exclude_if=lambda value: not value
    )

    @field_validator("beta_features")
    @classmethod
    def normalize_features(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("provider beta features must be unique")
        return tuple(sorted(value))

    def admit_features(self, selected: tuple[str, ...]) -> tuple[str, ...]:
        if len(selected) != len(set(selected)) or not set(selected) <= set(self.beta_features):
            raise ValueError("request beta features are outside the frozen provider profile")
        return tuple(sorted(selected))


ProviderWire = Annotated[ResponsesWire | MessagesWire, Field(discriminator="protocol")]


class ProviderContentType(StrEnum):
    JSON = "application/json"
    EVENT_STREAM = "text/event-stream"


class ProviderProfile(StrictModel):
    """Non-secret identity and fixed network target for one provider."""

    schema_version: Literal[2] = 2
    logical_id: Identifier
    origin: str
    request_path: str
    models_path: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    wire: ProviderWire = Field(default_factory=ResponsesWire)

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return _https_origin(value)

    @field_validator("request_path", "models_path")
    @classmethod
    def validate_endpoint_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        segments = value.split("/")[1:]
        if (
            not value.startswith("/")
            or value.startswith("//")
            or not segments
            or any(segment in {"", ".", ".."} for segment in segments)
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
            or "\\" in value
            or "?" in value
            or "#" in value
        ):
            raise ValueError("provider endpoints must be fixed origin-relative paths")
        return value

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-profile-v2")

    @property
    def wire_protocol(self) -> WireProtocol:
        return self.wire.protocol


RUST_CAT_PROFILE = ProviderProfile(
    logical_id="rust.cat",
    origin="https://rust.cat",
    request_path="/codex/v1/responses",
)


class ProviderDefaults(StrictModel):
    """Allowlisted request defaults projected from controller configuration."""

    requested_model: ModelLabel
    reasoning_effort: str | None = Field(default=None, min_length=1, max_length=32)
    service_tier: ServiceTierLabel | None = None


class ResolvedProviderConfig(StrictModel):
    """Secret-free interpretation of a trusted local provider configuration."""

    schema_version: Literal[2] = 2
    selected_provider_label: ProviderConfigLabel
    profile: ProviderProfile
    defaults: ProviderDefaults

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-config-projection-v2")


class InputRole(StrEnum):
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"


class InputMessage(StrictModel):
    role: InputRole
    content: Annotated[
        str,
        StringConstraints(min_length=1, max_length=1_000_000),
        Field(repr=False),
    ]


class FunctionCallOutput:
    """Confidential continuation item for one provider function call."""

    __slots__ = ("_call_id", "_output")

    classification = Sensitivity.CONFIDENTIAL

    def __init__(self, *, call_id: str, output: str) -> None:
        if not call_id or len(call_id) > 256:
            raise ValueError("function call output requires a bounded call identifier")
        if not output or len(output) > 1_000_000:
            raise ValueError("function call output requires bounded non-empty content")
        self._call_id = call_id
        self._output = output

    @property
    def call_id(self) -> str:
        return self._call_id

    def _wire_item(self) -> dict[str, str]:
        return {
            "type": "function_call_output",
            "call_id": self._call_id,
            "output": self._output,
        }

    def __repr__(self) -> str:
        return "FunctionCallOutput(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("function call outputs cannot be serialized")


class FunctionCallInput:
    """Confidential stateless replay of one prior provider function call."""

    __slots__ = ("_arguments", "_call_id", "_name")

    classification = Sensitivity.CONFIDENTIAL

    def __init__(self, *, call_id: str, name: str, arguments: str) -> None:
        if not call_id or len(call_id) > 256:
            raise ValueError("function call input requires a bounded call identifier")
        if not arguments or len(arguments) > 1_000_000:
            raise ValueError("function call input requires bounded arguments")
        self._call_id = call_id
        self._name = _TOOL_NAME_ADAPTER.validate_python(name)
        self._arguments = arguments

    @property
    def call_id(self) -> str:
        return self._call_id

    def _wire_item(self) -> dict[str, str]:
        return {
            "type": "function_call",
            "call_id": self._call_id,
            "name": self._name,
            "arguments": self._arguments,
        }

    def __repr__(self) -> str:
        return "FunctionCallInput(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("function call inputs cannot be serialized")


ResponseInput = InputMessage | FunctionCallInput | FunctionCallOutput


class ToolValueKind(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"


class ToolParameter(StrictModel):
    name: ToolName
    kind: ToolValueKind
    description: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    required: bool = True
    choices: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_choices(self) -> ToolParameter:
        if len(set(self.choices)) != len(self.choices):
            raise ValueError("tool parameter choices must be unique")
        if self.choices and self.kind is not ToolValueKind.STRING:
            raise ValueError("tool parameter choices require string kind")
        return self


class FunctionTool(StrictModel):
    name: ToolName
    description: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    parameters: tuple[ToolParameter, ...] = ()
    strict: Literal[True] = True

    @model_validator(mode="after")
    def validate_parameter_names(self) -> FunctionTool:
        names = [parameter.name for parameter in self.parameters]
        if len(set(names)) != len(names):
            raise ValueError("tool parameter names must be unique")
        if any(not parameter.required for parameter in self.parameters):
            raise ValueError("strict function tools require every parameter")
        return self

    def wire_schema(self) -> dict[str, object]:
        properties: dict[str, object] = {}
        required: list[str] = []
        for parameter in self.parameters:
            schema: dict[str, object] = {
                "type": parameter.kind.value,
                "description": parameter.description,
            }
            if parameter.choices:
                schema["enum"] = list(parameter.choices)
            properties[parameter.name] = schema
            if parameter.required:
                required.append(parameter.name)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }


class RequestTokenClaim(StrictModel):
    """Worst-case reservation required before a request may leave the controller.

    Input tokens are one total reservation, not an API-enforced input cap. The
    observed floor is the route canary's provider-reported input usage and does
    not claim to decompose provider-added context. Exact response usage remains
    authoritative after dispatch.
    """

    input_tokens: JcsPositiveInt
    output_tokens: JcsPositiveInt
    observed_input_token_floor: JcsNonNegativeInt = 0

    @model_validator(mode="after")
    def validate_observed_floor(self) -> RequestTokenClaim:
        if self.observed_input_token_floor >= self.input_tokens:
            raise ValueError("input token reservation must exceed the observed route floor")
        return self

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class ResponsesRequest:
    """Confidential typed request that cannot be implicitly serialized or logged."""

    __slots__ = (
        "_inputs",
        "_max_output_tokens",
        "_model",
        "_reasoning_effort",
        "_service_tier",
        "_token_claim",
        "_tool_choice_required",
        "_tools",
    )

    classification = Sensitivity.CONFIDENTIAL

    def __init__(
        self,
        *,
        model: str,
        inputs: tuple[ResponseInput, ...],
        tools: tuple[FunctionTool, ...] = (),
        reasoning_effort: str | None = None,
        service_tier: str | None = None,
        tool_choice_required: bool = False,
        token_claim: RequestTokenClaim,
    ) -> None:
        if not inputs:
            raise ValueError("a Responses request requires at least one input")
        continuation_outputs = tuple(
            item for item in inputs if isinstance(item, FunctionCallOutput)
        )
        continuation_inputs = tuple(item for item in inputs if isinstance(item, FunctionCallInput))
        input_call_ids = [item.call_id for item in continuation_inputs]
        output_call_ids = [item.call_id for item in continuation_outputs]
        if len(input_call_ids) != len(set(input_call_ids)) or len(output_call_ids) != len(
            set(output_call_ids)
        ):
            raise ValueError("function call output identifiers must be unique")
        if set(input_call_ids) != set(output_call_ids):
            raise ValueError("stateless continuation requires matched call and output items")
        positions = {
            item.call_id: position
            for position, item in enumerate(inputs)
            if isinstance(item, FunctionCallInput)
        }
        if any(
            positions[item.call_id] >= position
            for position, item in enumerate(inputs)
            if isinstance(item, FunctionCallOutput)
        ):
            raise ValueError("function call input must precede its output")
        if len({tool.name for tool in tools}) != len(tools):
            raise ValueError("tool names must be unique")
        defaults = ProviderDefaults(
            requested_model=model,
            reasoning_effort=reasoning_effort,
            service_tier=service_tier,
        )
        self._model = defaults.requested_model
        self._inputs = inputs
        self._tools = tools
        self._reasoning_effort = defaults.reasoning_effort
        self._service_tier = defaults.service_tier
        if tool_choice_required and not tools:
            raise ValueError("required tool choice needs at least one declared tool")
        self._tool_choice_required = tool_choice_required
        self._token_claim = token_claim
        self._max_output_tokens = token_claim.output_tokens

    @property
    def model(self) -> str:
        return self._model

    @property
    def token_claim(self) -> RequestTokenClaim:
        return self._token_claim

    def _wire_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "model": self._model,
            "input": [
                (
                    item._wire_item()
                    if isinstance(item, (FunctionCallInput, FunctionCallOutput))
                    else item.model_dump(mode="json")
                )
                for item in self._inputs
            ],
            "max_output_tokens": self._max_output_tokens,
            "store": False,
        }
        if self._tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.wire_schema(),
                    "strict": tool.strict,
                }
                for tool in self._tools
            ]
            if self._tool_choice_required:
                payload["tool_choice"] = "required"
        if self._reasoning_effort is not None:
            payload["reasoning"] = {"effort": self._reasoning_effort}
        if self._service_tier is not None:
            payload["service_tier"] = self._service_tier
        return payload

    def _wire_body(self) -> bytes:
        return json.dumps(
            self._wire_payload(),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def _accepts_tool_call(self, name: str) -> bool:
        return any(tool.name == name for tool in self._tools)

    @property
    def tool_choice_required(self) -> bool:
        return self._tool_choice_required

    def __repr__(self) -> str:
        return "ResponsesRequest(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("confidential requests cannot be serialized")


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cached_input_tokens: int | None = None
    reasoning_tokens: int | None = None

    def __post_init__(self) -> None:
        values = (
            self.input_tokens,
            self.output_tokens,
            self.total_tokens,
            self.cached_input_tokens,
            self.reasoning_tokens,
        )
        if any(value is not None and (type(value) is not int or value < 0) for value in values):
            raise ValueError("usage counters must be non-negative integers")
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("total usage must equal input plus output usage")
        if self.cached_input_tokens is not None and self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input usage cannot exceed input usage")
        if self.reasoning_tokens is not None and self.reasoning_tokens > self.output_tokens:
            raise ValueError("reasoning usage cannot exceed output usage")


class _ConfidentialOutput:
    classification = Sensitivity.CONFIDENTIAL

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("provider output cannot be serialized")


class OutputText(_ConfidentialOutput):
    __slots__ = ("_text",)

    def __init__(self, text: str) -> None:
        self._text = text

    @property
    def text(self) -> str:
        return self._text


class FunctionCall(_ConfidentialOutput):
    __slots__ = ("_arguments", "_call_id", "_name", "_status")

    def __init__(
        self,
        *,
        call_id: str,
        name: str,
        arguments: str,
        status: FunctionCallStatus | None = None,
    ) -> None:
        self._call_id = call_id
        self._name = name
        self._arguments = arguments
        self._status = status

    @property
    def call_id(self) -> str:
        return self._call_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def arguments(self) -> str:
        return self._arguments

    @property
    def status(self) -> FunctionCallStatus | None:
        return self._status


class Refusal(_ConfidentialOutput):
    __slots__ = ("_text",)

    def __init__(self, text: str) -> None:
        self._text = text

    @property
    def text(self) -> str:
        return self._text


class ReasoningSummary(_ConfidentialOutput):
    __slots__ = ("_texts",)

    def __init__(self, texts: tuple[str, ...]) -> None:
        self._texts = texts

    @property
    def texts(self) -> tuple[str, ...]:
        return self._texts


ResponseOutput = OutputText | FunctionCall | Refusal | ReasoningSummary


class ResponsesResult:
    """Confidential parsed response with provider metadata kept out of repr."""

    __slots__ = (
        "_id",
        "_outputs",
        "_reported_model",
        "_reported_service_tier",
        "_status",
        "_usage",
    )

    classification = Sensitivity.CONFIDENTIAL

    def __init__(
        self,
        *,
        response_id: str,
        reported_model: str,
        reported_service_tier: ServiceTierLabel | None = None,
        status: ResponseStatus,
        outputs: tuple[ResponseOutput, ...],
        usage: ProviderUsage | None,
    ) -> None:
        self._id = response_id
        self._reported_model = reported_model
        self._reported_service_tier = reported_service_tier
        self._status = status
        self._outputs = outputs
        self._usage = usage

    @property
    def response_id(self) -> str:
        return self._id

    @property
    def reported_model(self) -> str:
        return self._reported_model

    @property
    def reported_service_tier(self) -> str | None:
        return self._reported_service_tier

    @property
    def status(self) -> ResponseStatus:
        return self._status

    @property
    def outputs(self) -> tuple[ResponseOutput, ...]:
        return self._outputs

    @property
    def usage(self) -> ProviderUsage | None:
        return self._usage

    def __repr__(self) -> str:
        return "ResponsesResult(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("confidential responses cannot be serialized")


def immutable_headers(values: Mapping[str, str]) -> Mapping[str, str]:
    """Return an immutable copy so authorization cannot be added after dispatch."""

    return MappingProxyType(dict(values))
