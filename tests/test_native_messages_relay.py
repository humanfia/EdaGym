"""Messages-specific settlement evidence over real Unix and TLS connections."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from edagym.providers.budget import BudgetLedger
from edagym.providers.model import (
    MessagesWire,
    ProviderAuthorization,
    RequestTokenClaim,
    ResponseStatus,
)
from edagym.providers.relay import NativeProviderRelay, RelayRefusal
from tests.test_native_provider_relay import _Evidence, _request
from tests.test_provider_security import _HttpsStub, _open_local_campaign, _tls_contexts

_FEATURES = ("feature-a-2026-01-01", "feature-b-2026-01-01")
_BODY = {
    "model": "route.test",
    "messages": [{"role": "user", "content": [{"type": "text", "text": "Run the check."}]}],
    "tools": [{"name": "Bash", "input_schema": {"type": "object"}}],
    "thinking": {"type": "adaptive"},
    "output_config": {"effort": "high"},
    "max_tokens": 1000,
    "stream": True,
}


def _events(stop_reason: str = "tool_use") -> list[dict[str, Any]]:
    return [
        {
            "type": "message_start",
            "message": {
                "id": "msg_native",
                "type": "message",
                "role": "assistant",
                "model": "route.test",
                "content": [],
                "stop_reason": None,
                "usage": {
                    "input_tokens": 2,
                    "cache_creation_input_tokens": 1,
                    "cache_read_input_tokens": 1,
                    "output_tokens": 1,
                    "service_tier": "standard",
                },
            },
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tool_native", "name": "Bash", "input": {}},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": '{"command":"echo checked"}'},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": None},
            "usage": {
                "cache_creation_input_tokens": 3,
                "cache_read_input_tokens": 4,
                "output_tokens": 3,
            },
        },
        {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason},
            "usage": {"output_tokens": 5, "output_tokens_details": {"thinking_tokens": 2}},
        },
        {"type": "message_stop"},
    ]


def _encode(events: list[dict[str, Any]]) -> bytes:
    return "".join(
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
    ).encode()


@contextmanager
def _exchange(
    root: Path, response: bytes, observations: dict[str, _Evidence]
) -> Iterator[tuple[NativeProviderRelay, BudgetLedger, _HttpsStub]]:
    server_context, client_context = _tls_contexts(root)
    with _HttpsStub(
        server_context,
        status=200,
        response_body=response,
        response_headers={"Content-Type": "text/event-stream"},
    ) as upstream:
        sender, _, ledger = _open_local_campaign(
            upstream.origin,
            client_context,
            root / "preflight",
            wire=MessagesWire(authorization=ProviderAuthorization.API_KEY, beta_features=_FEATURES),
        )

        def observe(key: str) -> _Evidence:
            value = _Evidence(ledger)
            observations[key] = value
            return value

        with (
            sender,
            NativeProviderRelay(
                directory=root / "relay",
                sender=sender,
                trial_id="native",
                requested_model="route.test",
                token_claim=RequestTokenClaim(input_tokens=20, output_tokens=10),
                reasoning_effort="high",
                service_tier="standard_only",
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
                observer_factory=observe,
            ) as relay,
        ):
            yield relay, ledger, upstream


@pytest.mark.parametrize(
    ("reason", "status"),
    [("tool_use", ResponseStatus.COMPLETED), ("max_tokens", ResponseStatus.INCOMPLETE)],
)
def test_native_messages_settles_cumulative_cache_usage_and_freezes_feature_selection(
    tmp_path: Path, reason: str, status: ResponseStatus
) -> None:
    raw = _encode(_events(reason))
    observations: dict[str, _Evidence] = {}
    with _exchange(tmp_path, raw, observations) as (relay, ledger, upstream):
        for feature in _FEATURES:
            result = _request(
                relay,
                path="/v1/messages?beta=true",
                body=json.dumps(_BODY).encode(),
                protocol_headers={"anthropic-beta": feature, "anthropic-version": "2023-06-01"},
            )
            assert result == (200, raw)
        assert len(observations) == len(upstream.records) == 2
        for (path, authorization, body), headers in zip(
            upstream.records, upstream.request_headers, strict=True
        ):
            assert path == "/v1/messages" and authorization is None
            assert headers["x-api-key"] == "stub"
            assert headers["anthropic-version"] == "2023-06-01"
            payload = json.loads(body)
            assert payload["messages"] == _BODY["messages"] and payload["tools"] == _BODY["tools"]
            assert payload["max_tokens"] == 10 and payload["service_tier"] == "standard_only"
            assert relay.bearer_token.encode() not in body
        assert [headers["anthropic-beta"] for headers in upstream.request_headers] == list(
            _FEATURES
        )
        assert {value.beta_features for value in observations.values()} == {(x,) for x in _FEATURES}
        for value in observations.values():
            assert value.result is not None and value.result.status is status
            assert value.result.usage.cached_input_tokens == 4
            assert value.result.usage.reasoning_tokens == 2
            assert value.result.reported_model == "route.test"
            assert value.result.reported_service_tier == "standard"
        usage = ledger.snapshot()
        assert usage.committed_requests == 2 and usage.reserved_requests == 0
        assert usage.committed_input_tokens == 18 and usage.committed_output_tokens == 10


@pytest.mark.parametrize(
    ("change", "status", "reason"),
    [
        pytest.param(
            lambda events: events.pop(),
            502,
            RelayRefusal.PROVIDER_EXCHANGE_FAILED,
            id="interrupted-stream",
        ),
        pytest.param(
            lambda events: (
                events[0]["message"]["usage"].pop("cache_read_input_tokens"),
                events[-3]["usage"].pop("cache_read_input_tokens"),
            ),
            502,
            RelayRefusal.PROVIDER_EXCHANGE_FAILED,
            id="unknown-cache-usage",
        ),
        pytest.param(
            lambda events: events[-2]["usage"].update(output_tokens=0),
            502,
            RelayRefusal.PROVIDER_EXCHANGE_FAILED,
            id="decreasing-cumulative",
        ),
        pytest.param(
            lambda events: events[1].update(content_block={"type": "fallback", "model": "other"}),
            403,
            RelayRefusal.PROVIDER_MODEL_CHANGED,
            id="fallback-block",
        ),
        pytest.param(
            lambda events: events[-2]["delta"].update(model="other"),
            403,
            RelayRefusal.PROVIDER_MODEL_CHANGED,
            id="changed-serving-model",
        ),
        pytest.param(
            lambda events: (
                events[-3]["usage"].update(server_tool_use={"web_search_requests": 1}),
                events[-2]["usage"].update(server_tool_use={"web_search_requests": 0}),
            ),
            502,
            RelayRefusal.PROVIDER_EXCHANGE_FAILED,
            id="ungranted-server-usage",
        ),
    ],
)
def test_native_messages_unsettleable_receipt_retains_evidence_and_full_reservation(
    tmp_path: Path,
    change: Callable[[list[dict[str, Any]]], object],
    status: int,
    reason: RelayRefusal,
) -> None:
    events = _events()
    change(events)
    body = _encode(events)
    observations: dict[str, _Evidence] = {}
    with _exchange(tmp_path, body, observations) as (relay, ledger, upstream):
        actual_status, error = _request(relay, path="/v1/messages", body=json.dumps(_BODY).encode())
        assert actual_status == status and json.loads(error)["error"] == reason
        assert len(upstream.records) == 1
        (observation,) = observations.values()
        assert observation.rejected and observation.response == body and observation.result is None
        usage = ledger.snapshot()
        assert usage.committed_requests == 1 and usage.reserved_requests == 0
        assert usage.committed_input_tokens == 20 and usage.committed_output_tokens == 10


def test_native_messages_refuses_ungranted_protocol_and_server_tools(tmp_path: Path) -> None:
    observations: dict[str, _Evidence] = {}
    with _exchange(tmp_path, _encode(_events()), observations) as (relay, ledger, upstream):
        for change in (
            {"tools": [{"type": "web_search_20250305", "name": "web_search"}]},
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "image", "source": {"url": "https://other.invalid"}}],
                    }
                ]
            },
            {"output_config": {"effort": "low"}},
            {"thinking": {"type": "enabled", "budget_tokens": 1000}},
        ):
            assert (
                _request(relay, path="/v1/messages", body=json.dumps({**_BODY, **change}).encode())[
                    0
                ]
                == 400
            )
        for headers in (
            {"anthropic-beta": "ungranted-feature"},
            {"anthropic-version": "1900-01-01"},
        ):
            assert (
                _request(
                    relay,
                    path="/v1/messages",
                    body=json.dumps(_BODY).encode(),
                    protocol_headers=headers,
                )[0]
                == 400
            )
        assert (
            _request(relay, path="/v1/messages/count_tokens", body=json.dumps(_BODY).encode())[0]
            == 400
        )
        assert not observations and not upstream.records
        assert ledger.snapshot().committed_requests == ledger.snapshot().reserved_requests == 0
