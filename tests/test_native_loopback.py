"""The sandbox HTTP bridge preserves relay accounting and rejects proxy framing."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from edagym.providers.native_loopback import NativeLoopbackBridge
from edagym.security.canary_artifact import MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES
from tests.test_native_provider_relay import _REQUEST, _Evidence, _provider, _relay, _stream


def test_loopback_preserves_receipts_and_never_refunds_a_lost_cli_response(tmp_path: Path) -> None:
    raw = _stream()
    evidence: list[_Evidence] = []
    with (
        _provider(tmp_path, raw) as (sender, ledger, upstream),
        _relay(tmp_path / "relay", sender, ledger, evidence, trial_id="native") as relay,
    ):
        descriptor = os.open(relay.socket_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for bound, expected in ((len(raw), 200), (len(raw) - 1, 502)):
                with NativeLoopbackBridge(
                    f"/proc/self/fd/{descriptor}/{relay.socket_path.name}",
                    maximum_request_bytes=MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES,
                    maximum_response_bytes=bound,
                    timeout_seconds=2,
                ) as bridge:
                    endpoint = urlsplit(bridge.origin)
                    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port)
                    try:
                        connection.request("POST", "/v1/responses", json.dumps(_REQUEST), {
                            "Authorization": "Bearer " + relay.bearer_token,
                            "Content-Type": "application/json",
                            "X-Untrusted-Header": "must-not-forward",
                        })
                        response = connection.getresponse()
                        assert response.status == expected
                        body = response.read()
                        if expected == 200:
                            assert body == raw
                    finally:
                        connection.close()
        finally:
            os.close(descriptor)
        assert len(upstream.records) == ledger.snapshot().committed_requests == 2
        assert ledger.snapshot().reserved_requests == 0
        assert all(item.response == raw for item in evidence)
        assert all("x-untrusted-header" not in headers for headers in upstream.request_headers)


def test_loopback_refuses_ambiguous_framing_and_arbitrary_destinations(tmp_path: Path) -> None:
    evidence: list[_Evidence] = []
    with (
        _provider(tmp_path, _stream()) as (sender, ledger, upstream),
        _relay(tmp_path / "relay", sender, ledger, evidence, trial_id="native") as relay,
        NativeLoopbackBridge(
            str(relay.socket_path), maximum_request_bytes=64,
            maximum_response_bytes=4096, timeout_seconds=2,
        ) as bridge,
    ):
        endpoint = urlsplit(bridge.origin)
        for method, target, extra_headers, expected in (
            ("CONNECT", "example.invalid:443", (), 405),
            ("POST", "https://example.invalid/v1/responses", (), 400),
            ("POST", "//example.invalid/v1/responses", (), 400),
            ("POST", "/v1/responses", (("Content-Length", "2"),), 400),
            ("POST", "/v1/responses", (("Transfer-Encoding", "chunked"),), 400),
            ("POST", "/v1/responses", (("Authorization", "Bearer extra"),), 400),
        ):
            connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
            try:
                connection.putrequest(method, target)
                connection.putheader("Content-Length", "2")
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Authorization", "Bearer " + relay.bearer_token)
                for name, value in extra_headers:
                    connection.putheader(name, value)
                connection.endheaders(b"{}")
                response = connection.getresponse()
                assert response.status == expected
                response.read()
            finally:
                connection.close()
        assert upstream.records == []
        assert evidence == []
        assert ledger.snapshot().committed_requests == ledger.snapshot().reserved_requests == 0
