"""Real Unix/TLS evidence for native wire preservation and shared reservations."""

from __future__ import annotations

import http.client
import json
import os
import socket
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from edagym.providers.budget import BudgetLedger
from edagym.providers.model import RequestTokenClaim
from edagym.providers.native_wire import NativeProviderResult
from edagym.providers.relay import NativeProviderRelay
from edagym.providers.responses import ResponsesCampaign
from edagym.run.trial_model import ProviderSecurityBinding
from edagym.security.canary_artifact import ProviderCanaryEvidence
from tests.test_provider_security import _HttpsStub, _open_local_campaign, _tls_contexts

_CLAIM = RequestTokenClaim(input_tokens=10, output_tokens=10)
_REQUEST = {
    "model": "route.test",
    "input": [
        {
            "type": "additional_tools",
            "role": "developer",
            "tools": [
                {
                    "type": "namespace",
                    "name": "functions",
                    "tools": [
                        {"type": "custom", "name": "exec", "format": {"type": "text"}},
                    ],
                },
            ],
        },
        {"type": "message", "role": "user", "content": "Run the synthetic check."},
    ],
    "stream": True,
    "store": False,
    "max_output_tokens": 1000,
}


def _stream(*, usage: bool = True) -> bytes:
    response: dict[str, object] = {
        "id": "response_native",
        "model": "route.test",
        "status": "completed",
        "service_tier": "default",
        "output": [
            {
                "type": "custom_tool_call",
                "name": "exec",
                "namespace": "functions",
                "call_id": "call_native",
                "input": "text(await tools.exec_command({cmd:'pwd'}));",
            }
        ],
    }
    if usage:
        response["usage"] = {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3}
    event = {"type": "response.completed", "response": response}
    return ("event: response.completed\ndata: " + json.dumps(event) + "\n\n").encode()


class _Evidence:
    def __init__(self, ledger: BudgetLedger) -> None:
        self.ledger = ledger
        self.request: bytes | None = None
        self.response: bytes | None = None
        self.result: NativeProviderResult | None = None
        self.beta_features: tuple[str, ...] | None = None
        self.rejected = False

    def request_reserved(
        self,
        *,
        trial_id: str,
        provider_profile_digest: str,
        provider_config_digest: str,
        security_binding: ProviderSecurityBinding,
        canary_evidence: ProviderCanaryEvidence,
        request_body: bytes,
        beta_features: tuple[str, ...],
    ) -> None:
        assert self.ledger.snapshot().reserved_requests > 0
        assert security_binding.budget_binding_digest == self.ledger.limits_digest
        assert canary_evidence.receipt.digest == security_binding.canary_receipt_digest
        self.request = request_body
        self.beta_features = beta_features

    def response_received(self, *, response_body: bytes, result: NativeProviderResult) -> None:
        self.response, self.result = response_body, result

    def response_rejected(self, *, response_body: bytes) -> None:
        self.response, self.rejected = response_body, True


@contextmanager
def _provider(
    root: Path,
    response: bytes,
) -> Iterator[tuple[ResponsesCampaign, BudgetLedger, _HttpsStub]]:
    server_context, client_context = _tls_contexts(root)
    with _HttpsStub(
        server_context,
        status=200,
        response_body=response,
        response_headers={"Content-Type": "text/event-stream"},
    ) as upstream:
        sender, _, ledger = _open_local_campaign(
            upstream.origin, client_context, root / "preflight"
        )
        with sender:
            yield sender, ledger, upstream


def _relay(
    root: Path,
    sender: ResponsesCampaign,
    ledger: BudgetLedger,
    evidence: list[_Evidence],
    *,
    trial_id: str,
) -> NativeProviderRelay:
    def observe(_key: str) -> _Evidence:
        observer = _Evidence(ledger)
        evidence.append(observer)
        return observer

    return NativeProviderRelay(
        directory=root,
        sender=sender,
        trial_id=trial_id,
        requested_model="route.test",
        token_claim=_CLAIM,
        reasoning_effort="high",
        service_tier="default",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        observer_factory=observe,
    )


def _request(
    relay: NativeProviderRelay,
    *,
    body: bytes | None = None,
    token: str | None = None,
    path: str = "/v1/responses",
    method: str = "POST",
    protocol_headers: Mapping[str, str] | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("unused.invalid", timeout=5)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.settimeout(5)
    descriptor = os.open(relay.socket_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        connection.sock.connect(f"/proc/self/fd/{descriptor}/{relay.socket_path.name}")
    finally:
        os.close(descriptor)
    try:
        connection.request(
            method,
            path,
            body=body or json.dumps(_REQUEST).encode(),
            headers={
                "Authorization": "Bearer " + (relay.bearer_token if token is None else token),
                "Content-Type": "application/json",
                **(protocol_headers or {}),
            },
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_native_relays_preserve_wire_and_share_pre_dispatch_caps(tmp_path: Path) -> None:
    raw = _stream()
    evidence: list[_Evidence] = []
    with (
        _provider(tmp_path, raw) as (sender, ledger, upstream),
        _relay(tmp_path / "first", sender, ledger, evidence, trial_id="first") as first,
        _relay(tmp_path / "second", sender, ledger, evidence, trial_id="second") as second,
    ):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = tuple(
                pool.map(lambda index: _request(first if index % 2 else second), range(8))
            )
        assert sorted(status for status, _ in results) == [200] * 4 + [403] * 4
        assert all(body == raw for status, body in results if status == 200)
        assert len(upstream.records) == 4
        for path, authorization, body in upstream.records:
            assert path == "/v1/responses" and authorization == "Bearer stub"
            assert (
                first.bearer_token.encode() not in body and second.bearer_token.encode() not in body
            )
            payload = json.loads(body)
            assert payload["input"] == _REQUEST["input"]
            assert payload["max_output_tokens"] == 10
            assert payload["reasoning"]["effort"] == "high" and payload["service_tier"] == "default"
        snapshot = ledger.snapshot()
        assert snapshot.committed_requests == 4 and snapshot.reserved_requests == 0
        assert snapshot.committed_input_tokens == 8 and snapshot.committed_output_tokens == 4
        assert sum(item.result is not None and item.response == raw for item in evidence) == 4
    assert not first.socket_path.exists() and not second.socket_path.exists()


@pytest.mark.parametrize(
    "body",
    [
        b'event: response.created\ndata: {"type":"response.created"}\n\n',
        _stream(usage=False),
        _stream() + _stream(),
        b'event: response.unknown\ndata: {"type":"response.unknown"}\n\n' + _stream(),
    ],
)
def test_native_unsettleable_stream_keeps_raw_evidence_and_full_charge(
    tmp_path: Path, body: bytes
) -> None:
    evidence: list[_Evidence] = []
    with (
        _provider(tmp_path, body) as (sender, ledger, upstream),
        _relay(tmp_path / "relay", sender, ledger, evidence, trial_id="native") as relay,
    ):
        assert _request(relay)[0] == 502
        assert len(upstream.records) == 1
        (observation,) = evidence
        assert observation.rejected and observation.response == body and observation.result is None
        snapshot = ledger.snapshot()
        assert snapshot.committed_requests == 1 and snapshot.reserved_requests == 0
        assert snapshot.committed_input_tokens == 10 and snapshot.committed_output_tokens == 10


def test_native_grant_refuses_other_targets_models_and_hosted_tools(tmp_path: Path) -> None:
    evidence: list[_Evidence] = []
    with (
        _provider(tmp_path, _stream()) as (sender, ledger, upstream),
        _relay(tmp_path / "relay", sender, ledger, evidence, trial_id="native") as relay,
    ):
        assert _request(relay, token="unissued")[0] == 403
        assert _request(relay, path="https://another.invalid/v1/responses")[0] == 400
        assert _request(relay, path="another.invalid:443", method="CONNECT")[0] == 501
        for change in (
            {"model": "other.model"},
            {"input": [{"role": "user", "content": relay.bearer_token}]},
            {"service_tier": "priority"},
            {"tools": [{"type": "web_search"}]},
            {"previous_response_id": "old"},
        ):
            assert _request(relay, body=json.dumps({**_REQUEST, **change}).encode())[0] == 400
        assert not upstream.records and not evidence
        assert (
            ledger.snapshot().committed_requests == 0 and ledger.snapshot().reserved_requests == 0
        )


def test_expired_native_grant_cannot_start_a_provider_request(tmp_path: Path) -> None:
    import time

    with _provider(tmp_path, _stream()) as (sender, ledger, upstream):
        expires_at = datetime.now(UTC) + timedelta(seconds=1)
        with NativeProviderRelay(
            directory=tmp_path / "relay",
            sender=sender,
            trial_id="native",
            requested_model="route.test",
            token_claim=_CLAIM,
            reasoning_effort="high",
            service_tier="default",
            expires_at=expires_at,
            observer_factory=lambda _key: _Evidence(ledger),
        ) as relay:
            time.sleep(max(0, expires_at.timestamp() - time.time()) + 0.02)
            assert _request(relay)[0] == 410
            assert not upstream.records
            assert ledger.snapshot().committed_requests == 0
