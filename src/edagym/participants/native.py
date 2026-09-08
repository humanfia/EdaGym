"""Bounded native CLI transcript adapters with lossless private source retention."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from edagym.config.model import NativeCliKind
from edagym.participants.harness import (
    HarnessAssistant,
    HarnessEvent,
    HarnessFailure,
    HarnessFailureKind,
    HarnessFinal,
    HarnessInput,
    HarnessSession,
    HarnessToolRequest,
    HarnessToolResult,
    HarnessUsage,
)
from edagym.providers.model import ProviderUsage
from edagym.specs.common import Digest, Sensitivity

MAX_NATIVE_TRANSCRIPT_BYTES = 16 << 20


@dataclass(frozen=True, slots=True, repr=False)
class NativeTranscript:
    """Raw stdout must be persisted privately alongside its derived observations."""

    cli: NativeCliKind
    stdout: bytes = field(repr=False)
    events: tuple[HarnessEvent, ...]
    exit_code: int
    classification = Sensitivity.CONFIDENTIAL

    @property
    def source_digest(self) -> Digest:
        return "sha256:" + hashlib.sha256(self.stdout).hexdigest()

    @property
    def supported(self) -> bool:
        return not any(
            isinstance(event, HarnessFailure)
            and event.failure is not HarnessFailureKind.CLI_FAILURE
            for event in self.events
        )

    def __repr__(self) -> str:
        return "NativeTranscript(<confidential>)"


class _UnsupportedEvent(ValueError):
    pass


def adapt_native_transcript(
    cli: NativeCliKind, stdout: bytes, *, exit_code: int
) -> NativeTranscript:
    """Project one non-interactive invocation; never infer missing usage or actions.

    The process owner must bound capture before calling this adapter and persist
    stdout, including unsupported events. This function makes no provider calls.
    """

    if len(stdout) > MAX_NATIVE_TRANSCRIPT_BYTES:
        raise ValueError("native transcript exceeds the capture bound")
    events: list[HarnessEvent] = []
    terminal = False
    session_seen = False
    line_number = 0
    try:
        for line_number, raw in enumerate(stdout.splitlines()):
            if terminal:
                raise ValueError("native stream continues after its terminal event")
            payload = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid)
            if not isinstance(payload, dict):
                raise ValueError("native event is not an object")
            if cli is NativeCliKind.CODEX_EXEC:
                observations, terminal = _codex(payload, line_number)
            elif cli is NativeCliKind.CLAUDE_CODE:
                observations, terminal = _claude(payload, line_number)
            else:
                raise _UnsupportedEvent
            for observation in observations:
                if isinstance(observation, HarnessSession):
                    if session_seen:
                        raise ValueError("native invocation repeats its session identity")
                    session_seen = True
                elif isinstance(observation, HarnessFinal) and not session_seen:
                    raise ValueError("native completion has no session identity")
            events.extend(observations)
    except _UnsupportedEvent:
        events.append(HarnessFailure(
            source_line=line_number, failure=HarnessFailureKind.UNSUPPORTED_EVENT
        ))
    except (ValueError, TypeError, KeyError, RecursionError):
        events.append(HarnessFailure(
            source_line=line_number, failure=HarnessFailureKind.INVALID_EVENT
        ))
    else:
        if not terminal:
            events.append(HarnessFailure(
                source_line=line_number, failure=HarnessFailureKind.INCOMPLETE_STREAM
            ))
        if exit_code != 0 and not (
            events and isinstance(events[-1], HarnessFailure)
            and events[-1].failure is HarnessFailureKind.CLI_FAILURE
        ):
            events.append(HarnessFailure(
                source_line=line_number, failure=HarnessFailureKind.CLI_FAILURE
            ))
    return NativeTranscript(cli=cli, stdout=stdout, events=tuple(events), exit_code=exit_code)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native event key")
        result[key] = value
    return result


def _invalid(value: str) -> Any:
    raise ValueError("non-finite native event value")


def _string(payload: dict[str, Any], key: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise ValueError("native event field is not text")
    return value


def _counter(payload: dict[str, Any], key: str) -> int:
    value = payload[key]
    if type(value) is not int or value < 0:
        raise ValueError("native usage counter is invalid")
    return value


def _encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def _codex(payload: dict[str, Any], line: int) -> tuple[list[HarnessEvent], bool]:
    kind = _string(payload, "type")
    if kind == "thread.started":
        return [HarnessSession(source_line=line, session_id=_string(payload, "thread_id"))], False
    if kind == "turn.started":
        return [], False
    if kind == "turn.completed":
        usage = payload["usage"]
        input_tokens = _counter(usage, "input_tokens")
        output_tokens = _counter(usage, "output_tokens")
        return [
            HarnessUsage(source_line=line, usage=ProviderUsage(
                input_tokens=input_tokens, output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                cached_input_tokens=_counter(usage, "cached_input_tokens"),
                reasoning_tokens=(
                    _counter(usage, "reasoning_output_tokens")
                    if "reasoning_output_tokens" in usage else None
                ),
            )),
            HarnessFinal(source_line=line),
        ], True
    if kind in {"turn.failed", "error"}:
        return [HarnessFailure(source_line=line, failure=HarnessFailureKind.CLI_FAILURE)], (
            kind == "turn.failed"
        )
    if kind not in {"item.started", "item.updated", "item.completed"}:
        raise _UnsupportedEvent
    item = payload["item"]
    item_kind = _string(item, "type")
    call_id = _string(item, "id")
    completed = kind == "item.completed"
    if item_kind == "agent_message":
        return ([HarnessAssistant(source_line=line, text=_string(item, "text"))]
                if completed else []), False
    if item_kind in {"reasoning", "todo_list"}:
        # Available summaries and plan updates remain in the private original.
        return [], False
    if item_kind == "command_execution":
        if kind == "item.started":
            return [HarnessToolRequest(
                source_line=line, call_id=call_id, tool_name="shell",
                arguments_json=_encoded({"command": _string(item, "command")}),
            )], False
        if completed:
            status = _string(item, "status")
            if status not in {"completed", "failed"}:
                raise ValueError("command result has no terminal status")
            code = item["exit_code"]
            if code is not None and type(code) is not int:
                raise ValueError("command exit code is invalid")
            return [HarnessToolResult(
                source_line=line, call_id=call_id,
                output_json=_encoded({
                    "output": _string(item, "aggregated_output"), "exit_code": code,
                }),
                failed=status == "failed" or (code is not None and code != 0),
            )], False
        return [], False
    if item_kind == "mcp_tool_call":
        if kind == "item.started":
            return [HarnessToolRequest(
                source_line=line, call_id=call_id,
                tool_name=_string(item, "server") + "/" + _string(item, "tool"),
                arguments_json=_encoded(item["arguments"]),
            )], False
        if completed:
            status = _string(item, "status")
            if status not in {"completed", "failed"}:
                raise ValueError("MCP result has no terminal status")
            return [HarnessToolResult(
                source_line=line, call_id=call_id,
                output_json=_encoded({"result": item.get("result"), "error": item.get("error")}),
                failed=status == "failed",
            )], False
        return [], False
    if item_kind == "file_change" and completed:
        status = _string(item, "status")
        if status not in {"completed", "failed"} or not isinstance(item["changes"], list):
            raise ValueError("file change result is invalid")
        # Codex can report only the completed patch. Do not invent a request.
        return [HarnessToolResult(
            source_line=line, call_id=call_id, output_json=_encoded(item["changes"]),
            failed=status == "failed",
        )], False
    raise _UnsupportedEvent


def _claude(payload: dict[str, Any], line: int) -> tuple[list[HarnessEvent], bool]:
    kind = _string(payload, "type")
    if kind == "system" and payload.get("subtype") == "init":
        return [HarnessSession(
            source_line=line, session_id=_string(payload, "session_id"),
            reported_model=_string(payload, "model"),
        )], False
    if kind == "result":
        failed = payload["is_error"]
        if type(failed) is not bool:
            raise ValueError("Claude result error flag is invalid")
        observations: list[HarnessEvent] = []
        if "usage" in payload or not failed:
            usage = payload["usage"]
            input_tokens = sum(_counter(usage, key) for key in (
                "input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"
            ))
            output_tokens = _counter(usage, "output_tokens")
            observations.append(HarnessUsage(source_line=line, usage=ProviderUsage(
                input_tokens=input_tokens, output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                cached_input_tokens=_counter(usage, "cache_read_input_tokens"),
            )))
        observations.append(
            HarnessFailure(source_line=line, failure=HarnessFailureKind.CLI_FAILURE)
            if failed else HarnessFinal(source_line=line)
        )
        return observations, True
    if kind not in {"assistant", "user"}:
        raise _UnsupportedEvent
    # Nested agents need their own tool-call namespace and frozen admission.
    if payload.get("parent_tool_use_id") is not None:
        raise _UnsupportedEvent
    message = payload["message"]
    content = message["content"]
    if isinstance(content, str) and kind == "user":
        return [HarnessInput(source_line=line, text=content)], False
    if not isinstance(content, list):
        raise ValueError("Claude content is not a block list")
    observations = []
    for block in content:
        block_kind = _string(block, "type")
        if block_kind == "text":
            text = _string(block, "text")
            observations.append(
                HarnessAssistant(source_line=line, text=text)
                if kind == "assistant" else HarnessInput(source_line=line, text=text)
            )
        elif block_kind == "tool_use" and kind == "assistant":
            observations.append(HarnessToolRequest(
                source_line=line, call_id=_string(block, "id"),
                tool_name=_string(block, "name"), arguments_json=_encoded(block["input"]),
            ))
        elif block_kind == "tool_result" and kind == "user":
            failed = block.get("is_error", False)
            if type(failed) is not bool:
                raise ValueError("Claude tool error flag is invalid")
            observations.append(HarnessToolResult(
                source_line=line, call_id=_string(block, "tool_use_id"),
                output_json=_encoded(block["content"]), failed=failed,
            ))
        elif block_kind in {"thinking", "redacted_thinking"} and kind == "assistant":
            continue
        else:
            raise _UnsupportedEvent
    return observations, False
