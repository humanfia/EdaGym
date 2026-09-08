"""Loopback-first browser application with token and intent boundaries."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from edagym.authoring.factory import GenerationRequest, TaskFactory
from edagym.authoring.rtl_repair import DIFFICULTIES, FAMILY
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.model import (
    EdaGymConfig,
    WebExposure,
)
from edagym.config.resolve import resolve_profile, resolve_site
from edagym.policy.runtime_storage import write_private
from edagym.runtime.engine import (
    EngineError,
    EventCursor,
    IntentKind,
    InteractionIntent,
    Principal,
    RunEngine,
)


class WebApplication:
    """ASGI wrapper exposing the same typed intent and cursor contracts as agents."""

    def __init__(self, config: EdaGymConfig) -> None:
        if config.web.exposure is WebExposure.EXTERNAL:
            raise ValueError("external principal and TLS integration is unavailable")
        self.config = config
        site_id = config.profiles[0].site_id if config.profiles else config.sites[0].site_id
        self._site_root = resolve_site(config, site_id).state_root
        self.engine = RunEngine(self._site_root)
        self.principal = Principal(principal_id=config.web.principal_id)
        self.token_path = _token_path(config, self._site_root)
        self.token = _new_token(self.token_path)
        self._asgi = Starlette(
            middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=[config.web.host])],
            routes=[
                Route("/", self._index, methods=["GET"]),
                Route("/api/session", self._session, methods=["GET"]),
                Route("/api/tasks", self._tasks, methods=["GET"]),
                Route("/api/tasks/{family}", self._task, methods=["GET"]),
                Route("/api/runs", self._create_run, methods=["POST"]),
                Route("/api/runs", self._runs, methods=["GET"]),
                Route("/api/runs/{run_id}", self._run, methods=["GET"]),
                Route("/api/runs/{run_id}/events", self._events, methods=["GET"]),
                Route("/api/runs/{run_id}/intents", self._intent, methods=["POST"]),
                Route("/api/runs/{run_id}/files", self._files, methods=["GET"]),
                Route("/api/runs/{run_id}/file", self._file, methods=["GET"]),
                Route("/api/runs/{run_id}/resume", self._resume, methods=["POST"]),
                Mount(
                    "/static",
                    app=StaticFiles(directory=Path(__file__).with_name("static")),
                    name="static",
                ),
            ],
        )

    @property
    def startup_info(self) -> dict[str, str | int]:
        """Return non-secret startup values; the bearer itself stays in the private file."""

        return {
            "url": f"http://{self.config.web.host}:{self.config.web.port}",
            "token_file": os.fspath(self.token_path),
        }

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        await self._asgi(scope, receive, send)

    async def _index(self, _request: Request) -> Response:
        static = Path(__file__).with_name("static") / "index.html"
        return Response(
            static.read_bytes(),
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            },
        )

    async def _session(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        return JSONResponse(
            {
                "principal_id": self.principal.principal_id,
                "profiles": [item.profile_id for item in self.config.profiles],
                "sessions": [item.session_id for item in self.config.sessions],
            },
            headers={"Cache-Control": "no-store"},
        )

    async def _runs(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        try:
            return JSONResponse(
                {
                    "runs": [
                        item.model_dump(mode="json")
                        for item in self.engine.list_runs(self.principal)
                    ]
                },
                headers={"Cache-Control": "no-store"},
            )
        except EngineError:
            return JSONResponse({"error": "run_journal_unavailable"}, status_code=409)

    async def _tasks(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        return JSONResponse({"families": TaskFactory.catalog()})

    async def _task(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        task = next(
            (
                item
                for item in TaskFactory.catalog()
                if item["family"] == request.path_params["family"]
            ),
            None,
        )
        if task is None:
            return JSONResponse({"error": "task_not_found"}, status_code=404)
        return JSONResponse(task)

    async def _create_run(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        if not _same_origin(request, self.config.web.host):
            return JSONResponse({"error": "origin_required"}, status_code=403)
        key = request.headers.get("idempotency-key")
        if not key or len(key) > 96:
            return JSONResponse({"error": "idempotency_key_required"}, status_code=400)
        try:
            body = await _json_body(request)
            if set(body) - {"family", "difficulty", "session_id", "profile_id", "instance_id"}:
                raise ValueError("unknown run request field")
            creation_digest = canonical_digest(body, domain="web-run-request-v1")
            run_id = (
                "run_"
                + canonical_digest((self.principal.principal_id, key), domain="web-run-id-v1")[7:47]
            )
            if (self.engine.runs_root / run_id).exists():
                existing = self.engine.manifest(run_id, self.principal)
                if existing.creation_intent_digest != creation_digest:
                    return JSONResponse({"error": "idempotency_conflict"}, status_code=409)
                return JSONResponse(
                    self.engine.project(run_id, self.principal).model_dump(mode="json")
                )
            profile_id = body.get("profile_id")
            if profile_id is None and self.config.profiles:
                profile_id = self.config.profiles[0].profile_id
            if not isinstance(profile_id, str):
                raise ValueError("a configured profile is required")
            resolved = resolve_profile(self.config, profile_id)
            if resolved.site.state_root != self.engine.state_root:
                raise ValueError("profile belongs to another browser site")
            factory = TaskFactory()
            instance_id = body.get("instance_id")
            if instance_id is not None:
                if not isinstance(instance_id, str) or {"family", "difficulty"} & body.keys():
                    raise ValueError("an instance cannot be rebound to generation parameters")
                generated = factory.load(resolved.site.state_root, instance_id)
            else:
                generated = factory.generate(
                    GenerationRequest(
                        family=body.get("family", FAMILY),
                        difficulty=body.get("difficulty", DIFFICULTIES[0]),
                        seed=secrets.token_hex(16),
                        count=1,
                    ),
                    site=resolved.site,
                )[0]
            session_id = body.get("session_id", "human")
            if not isinstance(session_id, str):
                raise ValueError("a configured session is required")
            projection = await run_in_threadpool(
                self.engine.prepare_task,
                generated,
                resolved.snapshot,
                session_id,
                self.principal,
                run_id=run_id,
                creation_intent_digest=creation_digest,
            )
            return JSONResponse(projection.model_dump(mode="json"), status_code=201)
        except (EngineError, ValueError, KeyError, IndexError):
            return JSONResponse({"error": "invalid_run_request"}, status_code=400)

    async def _run(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        try:
            projection = self.engine.project(
                request.path_params["run_id"], principal=self.principal
            )
        except EngineError:
            return JSONResponse({"error": "run_not_found"}, status_code=404)
        return JSONResponse(projection.model_dump(mode="json"))

    async def _events(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        try:
            cursor = int(request.query_params.get("cursor", "0"))
            stream = self.engine.stream_run(
                request.path_params["run_id"],
                EventCursor(sequence=cursor),
                principal=self.principal,
            )
        except (EngineError, ValueError):
            return JSONResponse({"error": "invalid_event_cursor"}, status_code=400)

        async def body() -> Any:
            for event in stream.events:
                yield b"data: " + canonical_bytes(event) + b"\n\n"
            yield f"event: cursor\ndata: {stream.cursor.sequence}\n\n".encode()

        return StreamingResponse(body(), media_type="text/event-stream")

    async def _files(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        try:
            return JSONResponse(
                {"files": self.engine.files(request.path_params["run_id"], self.principal)}
            )
        except (EngineError, ValueError):
            return JSONResponse({"error": "run_files_unavailable"}, status_code=404)

    async def _file(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        try:
            media_type, content = self.engine.read_file(
                request.path_params["run_id"],
                request.query_params.get("path", ""),
                self.principal,
            )
            return Response(
                content,
                media_type=media_type,
                headers={
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "sandbox; default-src 'none'",
                },
            )
        except (EngineError, ValueError):
            return JSONResponse({"error": "file_unavailable"}, status_code=404)

    async def _resume(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        if not _same_origin(request, self.config.web.host):
            return JSONResponse({"error": "origin_required"}, status_code=403)
        if not request.headers.get("idempotency-key"):
            return JSONResponse({"error": "idempotency_key_required"}, status_code=400)
        try:
            result = await run_in_threadpool(
                self.engine.resume, request.path_params["run_id"], self.principal
            )
            return JSONResponse(result.model_dump(mode="json"))
        except (EngineError, ValueError):
            return JSONResponse({"error": "frozen_run_unavailable"}, status_code=409)

    async def _intent(self, request: Request) -> Response:
        if not self._authorized(request):
            return _unauthorized()
        if not _same_origin(request, self.config.web.host):
            return JSONResponse({"error": "origin_required"}, status_code=403)
        key = request.headers.get("idempotency-key")
        if not key:
            return JSONResponse({"error": "idempotency_key_required"}, status_code=400)
        try:
            body = await _json_body(request)
            kind = IntentKind(str(body.get("kind", "edit")))
            intent = InteractionIntent(
                intent_id=str(body.get("intent_id", f"intent_{secrets.token_hex(8)}")),
                idempotency_key=key,
                actor_id=self.principal.principal_id,
                kind=kind,
                payload=body.get("payload", {}),
            )
            accepted = await run_in_threadpool(
                self.engine.submit_intent,
                request.path_params["run_id"], intent, principal=self.principal
            )
            return JSONResponse(accepted.model_dump(mode="json"), status_code=202)
        except (EngineError, ValueError, json.JSONDecodeError):
            return JSONResponse({"error": "intent_rejected"}, status_code=409)

    def _authorized(self, request: Request) -> bool:
        header = request.headers.get("authorization", "")
        return secrets.compare_digest(header.encode(), f"Bearer {self.token}".encode())


def create_web_app(config: EdaGymConfig) -> WebApplication:
    """Create a token-protected app from one already parsed private configuration."""

    return WebApplication(config)


def stream_run(
    application: WebApplication,
    run_id: str,
    cursor: EventCursor,
    principal: Principal,
) -> Any:
    return application.engine.stream_run(run_id, cursor, principal=principal)


def submit_intent(
    application: WebApplication,
    run_id: str,
    intent: InteractionIntent,
    principal: Principal,
) -> Any:
    return application.engine.submit_intent(run_id, intent, principal=principal)


async def _json_body(request: Request) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > 256 * 1024:
        raise ValueError("request body is too large")
    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > 256 * 1024:
            raise ValueError("request body is too large")
    body = json.loads(chunks)
    if not isinstance(body, dict):
        raise ValueError("request body must be an object")
    return body


def _same_origin(request: Request, host: str) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return False
    try:
        parsed = urlsplit(origin)
        return (
            parsed.scheme == request.url.scheme
            and parsed.netloc == request.url.netloc
            and parsed.hostname == host
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and parsed.username is None
        )
    except ValueError:
        return False


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        {"error": "unauthorized"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _token_path(config: EdaGymConfig, root: Path) -> Path:
    configured = config.web.token_file
    path = (
        configured if configured is not None
        else root / "web" / f"session-{secrets.token_hex(16)}"
    )
    if not path.is_absolute():
        source = config.source_path
        if source is None:
            raise ValueError("relative token path requires a config source")
        path = source.parent / path
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(root):
        raise ValueError("web token file must be inside the private state root")
    return path


def _new_token(path: Path) -> str:
    token = secrets.token_urlsafe(32)
    write_private(path, (token + "\n").encode(), replace=True)
    return token


__all__ = ["WebApplication", "create_web_app", "stream_run", "submit_intent"]
