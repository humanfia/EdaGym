"""Standard-library-only HTTP bridge for a native CLI inside its task sandbox.

The controller mounts this module alongside the native launcher. All upstream
traffic goes to one preselected Unix socket. Provider routes, credentials, and
request reservations remain owned by the controller relay.
"""

from __future__ import annotations

import http.client
import http.server
import socket
import threading
from contextlib import suppress
from types import TracebackType
from typing import Self

_FORWARDED_REQUEST_HEADERS = ("Authorization", "anthropic-beta", "anthropic-version")


class NativeLoopbackBridge:
    """Expose a bounded loopback endpoint without granting network forwarding.

    Socket timeouts bound idle I/O; the enclosing executor owns the run deadline.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        maximum_request_bytes: int,
        maximum_response_bytes: int,
        timeout_seconds: float,
    ) -> None:
        if (
            maximum_request_bytes <= 0 or maximum_response_bytes <= 0
            or not 0 < timeout_seconds < float("inf")
        ):
            raise ValueError("native bridge requires finite positive bounds")
        self._socket_path = socket_path
        self._maximum_request_bytes = maximum_request_bytes
        self._maximum_response_bytes = maximum_response_bytes
        self._timeout_seconds = timeout_seconds
        bridge = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self) -> None:
                self.request.settimeout(bridge._timeout_seconds)
                super().setup()

            def log_message(self, format: str, *args: object) -> None:
                # Paths and provider bodies are private; HTTP status is the API.
                pass

            def do_POST(self) -> None:
                try:
                    bridge._forward(self)
                except (OSError, http.client.HTTPException, ValueError):
                    self.close_connection = True
                    with suppress(OSError):
                        self.send_error(502, "Native relay exchange failed")

            def do_CONNECT(self) -> None:
                self.send_error(405, "Method not allowed")

            def do_GET(self) -> None:
                self.send_error(405, "Method not allowed")

        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def _forward(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        target = handler.requestline.split()[1]
        if (
            not target.startswith("/") or target.startswith("//")
            or handler.headers.get_all("Transfer-Encoding")
            or len(handler.headers.get_all("Content-Length", [])) != 1
        ):
            handler.send_error(400, "Invalid native request framing")
            return
        for name in ("Content-Type", *_FORWARDED_REQUEST_HEADERS):
            if len(handler.headers.get_all(name, [])) > 1:
                handler.send_error(400, "Duplicate native protocol header")
                return
        raw_size = handler.headers["Content-Length"]
        if not raw_size.isascii() or not raw_size.isdigit():
            handler.send_error(400, "Invalid native request length")
            return
        size = int(raw_size)
        if not 0 < size <= self._maximum_request_bytes:
            handler.send_error(413, "Native request exceeds its bound")
            return
        if handler.headers.get_content_type() != "application/json":
            handler.send_error(415, "Native request must be JSON")
            return
        body = handler.rfile.read(size)
        if len(body) != size:
            handler.send_error(400, "Incomplete native request")
            return
        headers = {"Content-Type": "application/json"}
        for name in _FORWARDED_REQUEST_HEADERS:
            value = handler.headers.get(name)
            if value is not None:
                headers[name] = value
        connection = http.client.HTTPConnection("relay.invalid", timeout=self._timeout_seconds)
        try:
            upstream = socket.socket(socket.AF_UNIX)
            connection.sock = upstream
            upstream.settimeout(self._timeout_seconds)
            upstream.connect(self._socket_path)
            connection.request("POST", handler.path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(self._maximum_response_bytes + 1)
            if (
                len(response_body) > self._maximum_response_bytes
                or response.length not in {None, 0}
            ):
                handler.send_error(502, "Native response is incomplete or exceeds its bound")
                return
            content_type = response.getheader("Content-Type")
            if (
                content_type is None
                or any(character in content_type for character in "\r\n")
                or content_type.partition(";")[0].strip().lower()
                not in {"application/json", "text/event-stream"}
            ):
                handler.send_error(502, "Invalid native response media type")
                return
            handler.send_response(response.status)
            handler.send_header("Content-Type", content_type)
            handler.send_header("Content-Length", str(len(response_body)))
            handler.end_headers()
            handler.wfile.write(response_body)
        finally:
            connection.close()
