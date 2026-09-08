"""Evidence for profile-bound HTTP identity and cross-protocol dispatch refusal."""

from pathlib import Path

import pytest

from edagym.providers.model import (
    MessagesWire,
    ProviderAuthorization,
    ProviderDefaults,
    ProviderProfile,
    ProviderWire,
    ResolvedProviderConfig,
    ResponsesWire,
)
from edagym.providers.provider_budget import StandaloneProviderBudget
from edagym.providers.responses import DirectHttpsTransport, ProviderProtocolError, ResponsesBroker
from edagym.security.credentials import CredentialLease, CredentialSecurityError
from tests.test_provider_security import (
    _budget,
    _clean_attestation,
    _digest,
    _HttpsStub,
    _request,
    _StaticCredentialSource,
    _tls_contexts,
)


@pytest.mark.parametrize(
    ("wire", "path", "expected"),
    [
        (ResponsesWire(), "/v1/responses", {"authorization": "Bearer synthetic-key"}),
        (
            MessagesWire(authorization=ProviderAuthorization.API_KEY),
            "/v1/messages",
            {"x-api-key": "synthetic-key", "anthropic-version": "2023-06-01"},
        ),
        (
            MessagesWire(authorization=ProviderAuthorization.BEARER),
            "/gateway/messages",
            {"authorization": "Bearer synthetic-key", "anthropic-version": "2023-06-01"},
        ),
    ],
)
def test_bound_profile_owns_protocol_and_credential_headers_on_the_wire(
    tmp_path: Path,
    wire: ProviderWire,
    path: str,
    expected: dict[str, str],
) -> None:
    server_context, client_context = _tls_contexts(tmp_path)
    with _HttpsStub(server_context, status=200, response_body=b"{}") as stub:
        profile = ProviderProfile(
            logical_id="local.stub", origin=stub.origin, request_path=path, wire=wire
        )
        value = bytearray(b"synthetic-key")
        with CredentialLease(value, profile_digest=profile.digest) as credential:
            mismatched = profile.model_copy(update={"request_path": "/other/messages"})
            headers: dict[str, str] = {}
            with pytest.raises(CredentialSecurityError):
                credential.authorize(headers, profile=mismatched)
            assert headers == {}
            for name in ("AUTHORIZATION", "X-API-KEY", "ANTHROPIC-VERSION"):
                conflicting = {name: "caller-supplied"}
                with pytest.raises(CredentialSecurityError):
                    credential.authorize(conflicting, profile=profile)
                assert conflicting == {name: "caller-supplied"}
            credential.authorize(headers, profile=profile)
            DirectHttpsTransport(ssl_context=client_context).exchange(
                profile=profile, headers=headers, body=b"{}"
            )
        assert value == bytearray(len(value))
        with pytest.raises(CredentialSecurityError):
            credential.authorize({}, profile=profile)
    assert stub.records[0][0] == path
    identity = {
        name: value
        for name, value in stub.request_headers[0].items()
        if name in {"authorization", "x-api-key", "anthropic-version"}
    }
    assert identity == expected


def test_responses_request_cannot_dispatch_to_a_messages_profile(tmp_path: Path) -> None:
    server_context, client_context = _tls_contexts(tmp_path)
    with _HttpsStub(server_context, status=200, response_body=b"{}") as stub:
        configuration = ResolvedProviderConfig(
            selected_provider_label="local_stub",
            profile=ProviderProfile(
                logical_id="local.stub",
                origin=stub.origin,
                request_path="/v1/messages",
                wire=MessagesWire(authorization=ProviderAuthorization.API_KEY),
            ),
            defaults=ProviderDefaults(requested_model="route.test"),
        )
        campaign_digest = _digest("messages-protocol-probe")
        ledger = _budget()
        budget = StandaloneProviderBudget(campaign_digest=campaign_digest, ledger=ledger)
        policy, attestation = _clean_attestation(
            configuration, campaign_digest, budget, tmp_path / "preflight"
        )
        broker = ResponsesBroker(DirectHttpsTransport(ssl_context=client_context))
        with broker.open_probe(
            configuration=configuration,
            campaign_digest=campaign_digest,
            policy=policy,
            attestation=attestation,
            credentials=_StaticCredentialSource(configuration),
            budget=budget,
        ) as sender:
            before = ledger.snapshot()
            with pytest.raises(ProviderProtocolError):
                sender.request(trial_id="protocol_probe", request_key="request", request=_request())
            assert ledger.snapshot() == before
        assert stub.records == []
