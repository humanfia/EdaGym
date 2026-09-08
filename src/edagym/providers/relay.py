"""A short-lived, single-trial provider capability over a private Unix socket."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socketserver
import threading
from collections.abc import Callable
from contextlib import ExitStack
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Self, SupportsIndex

from edagym.policy.runtime_storage import private_directory
from edagym.providers.budget import BudgetExceeded
from edagym.providers.campaign_budget import CampaignAccountingError, CampaignBudgetExceeded
from edagym.providers.model import (
    MessagesWire,
    ProviderContentType,
    RequestTokenClaim,
    WireProtocol,
)
from edagym.providers.native_wire import NativeProviderRequest, NativeProviderResult
from edagym.providers.responses import (
    ProviderExchangeObserver,
    ProviderModelChangeError,
    ProviderTransportError,
    ResponsesCampaign,
)
from edagym.security.canary_artifact import MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES

_REQUEST_PATHS = {
    WireProtocol.RESPONSES: frozenset({"/v1/responses"}),
    WireProtocol.MESSAGES: frozenset({"/v1/messages", "/v1/messages?beta=true"}),
}
_SOCKET_NAME = "provider.sock"
_CONNECTION_TIMEOUT_SECONDS = 5


class RelayRefusal(StrEnum):
    REQUEST_REFUSED = "request_refused"
    GRANT_EXPIRED = "grant_expired"
    GRANT_REFUSED = "grant_refused"
    REQUEST_BOUND = "request_bound"
    REQUEST_EXPIRED = "request_expired"
    NATIVE_REQUEST_UNSUPPORTED = "native_request_unsupported"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ACCOUNTING_REFUSED = "accounting_refused"
    PROVIDER_EXCHANGE_FAILED = "provider_exchange_failed"
    PROVIDER_MODEL_CHANGED = "provider_model_changed"
    EVIDENCE_COMMIT_FAILED = "evidence_commit_failed"
    CAPABILITY_IN_BODY = "capability_in_body"


class NativeProviderRelay:
    """Expose only a frozen model request, with all usage owned by the existing sender.

    The controller supplies the episode deadline and request controls from its
    frozen run. This object issues a narrower transport capability; it does not
    grant provider access or replace the broker's preflight admission.
    """

    def __init__(
        self,
        *,
        directory: Path,
        sender: ResponsesCampaign,
        trial_id: str,
        requested_model: str,
        token_claim: RequestTokenClaim,
        reasoning_effort: str,
        service_tier: str,
        expires_at: datetime,
        observer_factory: Callable[[str], ProviderExchangeObserver[NativeProviderResult]],
    ) -> None:
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("relay expiration requires an absolute timezone-aware deadline")
        if expires_at <= datetime.now(UTC):
            raise ValueError("relay grant has already expired")
        if sender.bound_trial_id is not None and sender.bound_trial_id != trial_id:
            raise ValueError("relay trial differs from its metered sender")
        self._directory = private_directory(directory, create=True)
        self._sender = sender
        self._trial_id = trial_id
        self._requested_model = requested_model
        self._token_claim = token_claim
        self._reasoning_effort = reasoning_effort
        self._service_tier = service_tier
        self._expires_at = expires_at.astimezone(UTC)
        self._observer_factory = observer_factory
        self._token = secrets.token_urlsafe(32)
        self._closed = False
        self._resources = ExitStack()
        self._directory_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._resources.callback(os.close, self._directory_fd)
        self._socket_identity: int | None = None
        self._resources.callback(self._unlink_owned_socket)
        try:
            address = f"/proc/self/fd/{self._directory_fd}/{_SOCKET_NAME}"
            self._server = self._resources.enter_context(
                _RelayServer(address, _RelayHandler, bind_and_activate=False)
            )
            self._server.relay = self
            self._server.server_bind()
            self._socket_identity = os.stat(_SOCKET_NAME, dir_fd=self._directory_fd).st_ino
            os.chmod(_SOCKET_NAME, 0o600, dir_fd=self._directory_fd)
            self._server.server_activate()
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        except BaseException:
            self._resources.close()
            raise

    @property
    def socket_path(self) -> Path:
        return self._directory / _SOCKET_NAME

    @property
    def bearer_token(self) -> str:
        if self._closed:
            raise RuntimeError("relay grant is closed")
        return self._token

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._token = ""
        self._server.shutdown()
        self._thread.join()
        self._resources.close()

    def _unlink_owned_socket(self) -> None:
        if self._socket_identity is None:
            return
        try:
            identity = os.stat(_SOCKET_NAME, dir_fd=self._directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if identity.st_ino != self._socket_identity:
            raise RuntimeError("relay socket identity changed before cleanup")
        os.unlink(_SOCKET_NAME, dir_fd=self._directory_fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "NativeProviderRelay(<restricted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("relay capabilities cannot be serialized")


class _RelayServer(socketserver.UnixStreamServer):
    relay: NativeProviderRelay

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Native payloads and capability tokens must not enter ambient stderr.
        return


class _RelayHandler(BaseHTTPRequestHandler):
    server: _RelayServer
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        self.request.settimeout(_CONNECTION_TIMEOUT_SECONDS)
        super().setup()

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._failure(code, RelayRefusal.REQUEST_REFUSED)

    def _failure(self, status: int, reason: RelayRefusal) -> None:
        self._respond(
            status, ProviderContentType.JSON, json.dumps({"error": reason.value}).encode()
        )

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self) -> None:
        relay = self.server.relay
        if relay._closed or datetime.now(UTC) >= relay._expires_at:
            self._failure(HTTPStatus.GONE, RelayRefusal.GRANT_EXPIRED)
            return
        authorization = self.headers.get_all("Authorization", [])
        if len(authorization) != 1 or not hmac.compare_digest(
            authorization[0].encode("utf-8"), f"Bearer {relay._token}".encode()
        ):
            self._failure(HTTPStatus.FORBIDDEN, RelayRefusal.GRANT_REFUSED)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (
            self.path not in _REQUEST_PATHS[relay._sender.provider_wire.protocol]
            or self.headers.get_all("Transfer-Encoding") is not None
            or len(lengths) != 1
            or len(lengths[0]) > 10
            or not lengths[0].isascii()
            or not lengths[0].isdecimal()
        ):
            self._failure(HTTPStatus.BAD_REQUEST, RelayRefusal.REQUEST_REFUSED)
            return
        size = int(lengths[0])
        if not 0 < size <= MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES:
            self._failure(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, RelayRefusal.REQUEST_BOUND)
            return
        body = self.rfile.read(size)
        if relay._closed or len(body) != size or datetime.now(UTC) >= relay._expires_at:
            self._failure(HTTPStatus.REQUEST_TIMEOUT, RelayRefusal.REQUEST_EXPIRED)
            return
        try:
            wire = relay._sender.provider_wire
            versions = self.headers.get_all("anthropic-version", [])
            if versions and (not isinstance(wire, MessagesWire) or versions != [wire.api_version]):
                self._failure(HTTPStatus.BAD_REQUEST, RelayRefusal.NATIVE_REQUEST_UNSUPPORTED)
                return
            request = NativeProviderRequest(
                body,
                wire=wire,
                requested_model=relay._requested_model,
                token_claim=relay._token_claim,
                reasoning_effort=relay._reasoning_effort,
                service_tier=relay._service_tier,
                beta_features=tuple(
                    feature.strip()
                    for value in self.headers.get_all("anthropic-beta", [])
                    for feature in value.split(",")
                ),
            )
        except ProviderTransportError:
            self._failure(HTTPStatus.BAD_REQUEST, RelayRefusal.NATIVE_REQUEST_UNSUPPORTED)
            return
        if relay._closed or datetime.now(UTC) >= relay._expires_at:
            self._failure(HTTPStatus.GONE, RelayRefusal.GRANT_EXPIRED)
            return
        if relay._token.encode() in request.wire_body:
            self._failure(HTTPStatus.BAD_REQUEST, RelayRefusal.CAPABILITY_IN_BODY)
            return
        identity = (
            request.wire_protocol.value.encode()
            + b"\0"
            + ",".join(request.beta_features).encode()
            + b"\0"
            + request.wire_body
        )
        key = "native_" + hashlib.sha256(identity).hexdigest()
        try:
            result = relay._sender.request_native(
                trial_id=relay._trial_id,
                request_key=key,
                request=request,
                observer=relay._observer_factory(key),
            )
        except (CampaignBudgetExceeded, BudgetExceeded):
            self._failure(HTTPStatus.FORBIDDEN, RelayRefusal.BUDGET_EXHAUSTED)
            return
        except CampaignAccountingError:
            self._failure(HTTPStatus.CONFLICT, RelayRefusal.ACCOUNTING_REFUSED)
            return
        except ProviderModelChangeError:
            self._failure(HTTPStatus.FORBIDDEN, RelayRefusal.PROVIDER_MODEL_CHANGED)
            return
        except ProviderTransportError:
            self._failure(HTTPStatus.BAD_GATEWAY, RelayRefusal.PROVIDER_EXCHANGE_FAILED)
            return
        except Exception:
            self._failure(HTTPStatus.INTERNAL_SERVER_ERROR, RelayRefusal.EVIDENCE_COMMIT_FAILED)
            return
        self._respond(HTTPStatus.OK, ProviderContentType.EVENT_STREAM, result.response.body)
