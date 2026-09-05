"""Human, command, and hybrid adapters for the participant protocol."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from io import TextIOBase
from types import MappingProxyType
from typing import NoReturn, Protocol

from pydantic import TypeAdapter, ValidationError

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.participants.admission import CampaignParticipantAdmission
from edagym.participants.model import (
    PARTICIPANT_INTENT_ADAPTER,
    ParticipantIntent,
    ParticipantView,
)
from edagym.specs.common import Digest, Identifier
from edagym.specs.session import ActorKind

_MAXIMUM_RESPONSE_BYTES = 1024 * 1024
_IDENTIFIER_ADAPTER: TypeAdapter[str] = TypeAdapter(Identifier)
_DIGEST_ADAPTER: TypeAdapter[str] = TypeAdapter(Digest)


def json_line_human_adapter_digest(
    maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
) -> Digest:
    response_bound = _require_response_bound(maximum_response_bytes)
    return canonical_digest(
        {
            "protocol": "json-line-human-v1",
            "maximum_response_bytes": response_bound,
            "view_schema": ParticipantView.model_json_schema(mode="validation"),
            "intent_schema": PARTICIPANT_INTENT_ADAPTER.json_schema(mode="validation"),
        },
        domain="json-line-human-adapter-v1",
    )


class ParticipantFailureKind(StrEnum):
    CHANNEL_FAILURE = "channel_failure"
    COMMAND_CANCELLED = "command_cancelled"
    COMMAND_EXIT = "command_exit"
    COMMAND_TIMEOUT = "command_timeout"
    TOOL_BUDGET = "tool_budget"
    WALL_BUDGET = "wall_budget"
    EDA_COMPUTE_BUDGET = "eda_compute_budget"
    LICENSE_BUDGET = "license_budget"
    PROVIDER_BUDGET_OVERRUN = "provider_budget_overrun"
    END_OF_INPUT = "end_of_input"
    RESPONSE_BOUND = "response_bound"
    INVALID_INTENT = "invalid_intent"
    ACTOR_MISMATCH = "actor_mismatch"
    CANDIDATE_SNAPSHOT = "candidate_snapshot"


_FAILURE_MESSAGES = {
    ParticipantFailureKind.CHANNEL_FAILURE: "participant channel failed",
    ParticipantFailureKind.COMMAND_CANCELLED: "participant command was cancelled",
    ParticipantFailureKind.COMMAND_EXIT: "participant command exited unsuccessfully",
    ParticipantFailureKind.COMMAND_TIMEOUT: "participant command exceeded its time bound",
    ParticipantFailureKind.TOOL_BUDGET: "participant tool-call budget is exhausted",
    ParticipantFailureKind.WALL_BUDGET: "participant wall-time budget is exhausted",
    ParticipantFailureKind.EDA_COMPUTE_BUDGET: ("participant EDA compute budget is exhausted"),
    ParticipantFailureKind.LICENSE_BUDGET: "participant license budget is exhausted",
    ParticipantFailureKind.PROVIDER_BUDGET_OVERRUN: (
        "provider usage exceeded its reserved token budget"
    ),
    ParticipantFailureKind.END_OF_INPUT: "human participant input ended",
    ParticipantFailureKind.RESPONSE_BOUND: "participant response exceeds its bound",
    ParticipantFailureKind.INVALID_INTENT: "participant response is not a valid intent",
    ParticipantFailureKind.ACTOR_MISMATCH: "participant adapter does not own the active writer",
    ParticipantFailureKind.CANDIDATE_SNAPSHOT: "candidate snapshot failed",
}


class ParticipantAdapterError(RuntimeError):
    """A typed participant failure that never includes raw channel data."""

    def __init__(self, kind: ParticipantFailureKind) -> None:
        self.kind = kind
        super().__init__(_FAILURE_MESSAGES[kind])


class ParticipantAdapter(Protocol):
    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]: ...

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission | None: ...

    def next_intent(self, view: ParticipantView) -> ParticipantIntent: ...


class ParticipantChannel(Protocol):
    """Bounded JSON transport whose implementation owns isolation and credentials.

    The response limit is a transport read bound, not a post-read validation hint.
    """

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes: ...


class HumanParticipantChannel(ParticipantChannel, Protocol):
    """Human channel with a canonical non-secret adapter identity."""

    @property
    def adapter_digest(self) -> Digest: ...


class JsonLineHumanChannel:
    """Exchange one bounded JSON intent with a human-facing text stream."""

    def __init__(
        self,
        input_stream: TextIOBase,
        output_stream: TextIOBase,
        *,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
    ) -> None:
        self._input = input_stream
        self._output = output_stream
        self._maximum_response_bytes = _require_response_bound(maximum_response_bytes)

    @property
    def adapter_digest(self) -> Digest:
        return json_line_human_adapter_digest(self._maximum_response_bytes)

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        response_bound = min(
            self._maximum_response_bytes,
            _require_response_bound(maximum_response_bytes),
        )
        self._output.write(view.decode("utf-8"))
        self._output.write("\n")
        self._output.flush()
        result = _read_human_line(self._input, response_bound)
        if isinstance(result, ParticipantFailureKind):
            _raise_failure(result)
        return result


class HumanParticipantAdapter:
    def __init__(
        self,
        actor_id: str,
        channel: HumanParticipantChannel,
        *,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
    ) -> None:
        self.actor_id = _IDENTIFIER_ADAPTER.validate_python(actor_id)
        try:
            adapter_digest = _DIGEST_ADAPTER.validate_python(channel.adapter_digest)
        except (AttributeError, ValidationError):
            raise ValueError("human participant channel has no bound adapter identity") from None
        if adapter_digest != json_line_human_adapter_digest(maximum_response_bytes):
            raise ValueError("human participant channel differs from its adapter identity")
        self._channel = channel
        self._maximum_response_bytes = _require_response_bound(maximum_response_bytes)
        self._adapter_digest = adapter_digest

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {self.actor_id: ActorKind.HUMAN}

    @property
    def adapter_digest(self) -> Digest:
        return self._adapter_digest

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.actor_id not in self.actor_kinds:
            del view
            _raise_inactive_actor()
        result = _exchange_and_decode(
            self._channel,
            canonical_bytes(view),
            self._maximum_response_bytes,
        )
        del view
        return _require_intent(result)


class CommandAgentAdapter:
    """Translate a sandboxed command transport response into a typed intent."""

    def __init__(
        self,
        *,
        actor_id: str,
        channel: ParticipantChannel,
        maximum_response_bytes: int = _MAXIMUM_RESPONSE_BYTES,
    ) -> None:
        self.actor_id = _IDENTIFIER_ADAPTER.validate_python(actor_id)
        self._channel = channel
        self._maximum_response_bytes = _require_response_bound(maximum_response_bytes)

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {self.actor_id: ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.actor_id not in self.actor_kinds:
            del view
            _raise_inactive_actor()
        result = _exchange_and_decode(
            self._channel,
            canonical_bytes(view),
            self._maximum_response_bytes,
        )
        del view
        return _require_intent(result)


class HybridParticipantAdapter:
    """Dispatch exclusively to the actor holding the journaled writer lease."""

    def __init__(self, adapters: Sequence[ParticipantAdapter]) -> None:
        by_actor: dict[str, ParticipantAdapter] = {}
        actor_kinds: dict[str, ActorKind] = {}
        for adapter in adapters:
            child_kinds = dict(adapter.actor_kinds)
            if len(child_kinds) != 1:
                raise ValueError("hybrid children must each own exactly one actor")
            actor_id, actor_kind = next(iter(child_kinds.items()))
            if actor_id in by_actor:
                raise ValueError("hybrid participant actor identifiers must be unique")
            by_actor[actor_id] = adapter
            actor_kinds[actor_id] = actor_kind
        if len(by_actor) < 2:
            raise ValueError("hybrid participant control requires at least two actors")
        self._adapters: Mapping[str, ParticipantAdapter] = MappingProxyType(by_actor)
        self._actor_kinds: Mapping[str, ActorKind] = MappingProxyType(actor_kinds)

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return self._actor_kinds

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        adapter = self._adapters.get(view.actor_id)
        if adapter is None:
            del view
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        result = _invoke_child(adapter, view)
        del adapter, view
        return _require_intent(result)


def _selected_human_adapter(
    adapter: ParticipantAdapter,
    actor_id: str,
) -> HumanParticipantAdapter | None:
    """Return the exact human child selected by a journaled writer lease."""

    if type(adapter) is HumanParticipantAdapter:
        return adapter if adapter.actor_id == actor_id else None
    if type(adapter) is HybridParticipantAdapter:
        child = adapter._adapters.get(actor_id)
        return child if type(child) is HumanParticipantAdapter else None
    return None


def _participant_admissions(adapter: ParticipantAdapter) -> tuple[object, ...]:
    """Collect admission claims reachable through the supported adapter composition."""

    if type(adapter) is HybridParticipantAdapter:
        return tuple(
            admission
            for child in adapter._adapters.values()
            for admission in _participant_admissions(child)
        )
    try:
        claims = (
            getattr(adapter, "campaign_admission", None),
            getattr(adapter, "synthetic_preflight_admission", None),
        )
    except Exception:
        raise ValueError("participant admission is unavailable") from None
    return tuple(claim for claim in claims if claim is not None)


def _invoke_child(
    adapter: ParticipantAdapter,
    view: ParticipantView,
) -> ParticipantIntent | ParticipantFailureKind:
    try:
        return adapter.next_intent(view)
    except ParticipantAdapterError as error:
        return error.kind


def _decode_intent(payload: bytes) -> ParticipantIntent | None:
    try:
        return PARTICIPANT_INTENT_ADAPTER.validate_json(payload)
    except ValidationError:
        return None


def _read_human_line(
    stream: TextIOBase,
    maximum_response_bytes: int,
) -> bytes | ParticipantFailureKind:
    chunks: list[bytes] = []
    size = 0
    while True:
        remaining = maximum_response_bytes - size
        maximum_characters = max(1, remaining // 4)
        try:
            fragment = stream.readline(maximum_characters)
        except Exception:
            return ParticipantFailureKind.CHANNEL_FAILURE
        if type(fragment) is not str:
            return ParticipantFailureKind.CHANNEL_FAILURE
        if not fragment:
            return b"".join(chunks) if chunks else ParticipantFailureKind.END_OF_INPUT
        try:
            encoded = fragment.encode("utf-8")
        except UnicodeEncodeError:
            return ParticipantFailureKind.CHANNEL_FAILURE
        if len(encoded) > remaining:
            return ParticipantFailureKind.RESPONSE_BOUND
        chunks.append(encoded)
        size += len(encoded)
        if fragment.endswith("\n"):
            return b"".join(chunks)
        if size == maximum_response_bytes:
            try:
                overflow = stream.read(1)
            except Exception:
                return ParticipantFailureKind.CHANNEL_FAILURE
            if type(overflow) is not str:
                return ParticipantFailureKind.CHANNEL_FAILURE
            if overflow:
                return ParticipantFailureKind.RESPONSE_BOUND
            return b"".join(chunks)


def _exchange_and_decode(
    channel: ParticipantChannel,
    view: bytes,
    maximum_response_bytes: int,
) -> ParticipantIntent | ParticipantFailureKind:
    try:
        response = channel.exchange(
            view,
            maximum_response_bytes=maximum_response_bytes,
        )
    except ParticipantAdapterError as error:
        return error.kind
    except Exception:
        return ParticipantFailureKind.CHANNEL_FAILURE
    if type(response) is not bytes:
        return ParticipantFailureKind.CHANNEL_FAILURE
    if len(response) > maximum_response_bytes:
        return ParticipantFailureKind.RESPONSE_BOUND
    intent = _decode_intent(response)
    if intent is None:
        return ParticipantFailureKind.INVALID_INTENT
    return intent


def _require_intent(
    result: ParticipantIntent | ParticipantFailureKind,
) -> ParticipantIntent:
    if isinstance(result, ParticipantFailureKind):
        _raise_failure(result)
    return result


def _raise_failure(failure: ParticipantFailureKind) -> NoReturn:
    raise ParticipantAdapterError(failure) from None


def _raise_inactive_actor() -> NoReturn:
    raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH) from None


def _require_response_bound(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("maximum response size must be positive")
    return value
