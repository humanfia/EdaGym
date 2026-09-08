"""Configuration-based CLI adapter for the shared run engine."""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

from edagym.authoring.factory import TaskFactory
from edagym.canonical import canonical_bytes
from edagym.config import load_config, resolve_profile, resolve_site
from edagym.run.model import (
    CheckpointPayload,
    EnginePhase,
    EventCursor,
    IntentKind,
    InteractionIntent,
    Principal,
)
from edagym.runtime.engine import RunEngine


def add_run_commands[P: argparse.ArgumentParser](
    commands: argparse._SubParsersAction[P],
) -> None:
    parser = commands.add_parser("run", help="operate a run using its frozen private configuration")
    operations = parser.add_subparsers(dest="run_command", required=True)
    start = operations.add_parser("start", help="bind a generated task instance to a session")
    start.add_argument("--instance", required=True)
    start.add_argument("--session", required=True)
    start.add_argument("--profile", required=True)
    start.set_defaults(handler=_start)
    for name in ("status", "events", "resume", "cancel", "checkpoint", "gc"):
        command = operations.add_parser(name)
        command.add_argument("run_id")
        if name == "events":
            command.add_argument("--cursor", type=int, default=0)
        if name == "gc":
            command.add_argument("--dry-run", action="store_true")
        command.set_defaults(handler=_operation)


def _start(arguments: argparse.Namespace) -> int:
    config_path = _config_path(arguments)
    config = load_config(config_path)
    resolved = resolve_profile(config, arguments.profile)
    generated = TaskFactory().load(resolved.site.state_root, arguments.instance)
    projection = RunEngine(resolved.site.state_root).prepare_task(
        generated,
        resolved.snapshot,
        arguments.session,
        Principal(principal_id=config.web.principal_id),
    )
    sys.stdout.buffer.write(canonical_bytes(projection) + b"\n")
    return 3 if projection.phase is EnginePhase.UNAVAILABLE else 0


def _operation(arguments: argparse.Namespace) -> int:
    config = load_config(_config_path(arguments))
    principal = Principal(principal_id=config.web.principal_id)
    engines = [
        RunEngine(site.state_root)
        for declared in config.sites
        if (site := resolve_site(config, declared.site_id)).available
        and (site.state_root / "runs" / arguments.run_id).is_dir()
    ]
    if len(engines) != 1:
        raise ValueError("run identifier is absent or ambiguous across configured sites")
    engine = engines[0]
    name = arguments.run_command
    if name == "events":
        result: object = engine.stream_run(
            arguments.run_id,
            EventCursor(sequence=arguments.cursor),
            principal,
        )
    elif name == "resume":
        result = engine.resume(arguments.run_id, principal)
    elif name == "cancel":
        result = engine.cancel(arguments.run_id, principal)
    elif name == "checkpoint":
        key = f"checkpoint_{secrets.token_hex(16)}"
        result = engine.submit_intent(
            arguments.run_id,
            InteractionIntent(
                intent_id=key,
                idempotency_key=key,
                actor_id=principal.principal_id,
                kind=IntentKind.CHECKPOINT,
                payload=CheckpointPayload(checkpoint_id=key),
            ),
            principal,
        )
    elif name == "gc":
        result = {
            "run_id": arguments.run_id,
            "dry_run": arguments.dry_run,
            "complete": engine.gc(arguments.run_id, principal, dry_run=arguments.dry_run),
        }
    else:
        result = engine.project(arguments.run_id, principal)
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


def _config_path(arguments: argparse.Namespace) -> Path:
    if not isinstance(arguments.config_path, Path):
        raise ValueError("an explicit private configuration is required")
    return arguments.config_path
