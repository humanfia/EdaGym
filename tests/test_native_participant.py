"""External CLI event contracts retain traces and refuse invented completion."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from edagym.config.model import NativeCliKind
from edagym.participants.harness import (
    HarnessAssistant,
    HarnessFailure,
    HarnessFailureKind,
    HarnessFinal,
    HarnessToolRequest,
    HarnessToolResult,
    HarnessUsage,
)
from edagym.participants.native import adapt_native_transcript


def _events(cli: NativeCliKind) -> list[dict[str, Any]]:
    if cli is NativeCliKind.CODEX_EXEC:
        return [
            {"type": "thread.started", "thread_id": "native-session"},
            {"type": "turn.started"},
            {"type": "item.started", "item": {
                "type": "command_execution", "id": "call-a", "command": "check-design",
                "status": "in_progress",
            }},
            {"type": "item.completed", "item": {
                "type": "command_execution", "id": "call-a", "command": "check-design",
                "status": "completed", "aggregated_output": "PASS", "exit_code": 0,
            }},
            {"type": "item.completed", "item": {
                "type": "agent_message", "id": "message-a", "text": "Design checked.",
            }},
            {"type": "turn.completed", "usage": {
                "input_tokens": 15, "cached_input_tokens": 4, "output_tokens": 3,
            }},
        ]
    return [
        {"type": "system", "subtype": "init", "session_id": "native-session", "model": "m"},
        {"type": "assistant", "parent_tool_use_id": None, "message": {"content": [
            {"type": "tool_use", "id": "call-a", "name": "Bash",
             "input": {"command": "check-design"}},
        ]}},
        {"type": "user", "parent_tool_use_id": None, "message": {"content": [
            {"type": "tool_result", "tool_use_id": "call-a", "content": "PASS"},
        ]}},
        {"type": "assistant", "message": {"content": [
            {"type": "text", "text": "Design checked."},
        ]}},
        {"type": "result", "subtype": "success", "is_error": False, "usage": {
            "input_tokens": 6, "cache_creation_input_tokens": 5,
            "cache_read_input_tokens": 4, "output_tokens": 3,
        }},
    ]


def _encode(events: list[dict[str, Any]]) -> bytes:
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


@pytest.mark.parametrize("cli", tuple(NativeCliKind))
def test_native_trace_preserves_actions_and_normalizes_cache_usage(cli: NativeCliKind) -> None:
    raw = _encode(_events(cli))
    transcript = adapt_native_transcript(cli, raw, exit_code=0)
    assert transcript.supported
    assert transcript.stdout == raw
    assert transcript.source_digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    requests = [e for e in transcript.events if isinstance(e, HarnessToolRequest)]
    results = [e for e in transcript.events if isinstance(e, HarnessToolResult)]
    assert len(requests) == len(results) == 1
    assert requests[0].call_id == results[0].call_id == "call-a"
    assert json.loads(requests[0].arguments_json) == {"command": "check-design"}
    assert not results[0].failed
    assert [e.text for e in transcript.events if isinstance(e, HarnessAssistant)] == [
        "Design checked."
    ]
    usage, = [e.usage for e in transcript.events if isinstance(e, HarnessUsage)]
    assert (usage.input_tokens, usage.output_tokens, usage.total_tokens) == (15, 3, 18)
    assert usage.cached_input_tokens == 4
    assert isinstance(transcript.events[-1], HarnessFinal)


@pytest.mark.parametrize("cli", tuple(NativeCliKind))
def test_native_unknown_and_truncated_streams_keep_raw_without_final(cli: NativeCliKind) -> None:
    events = _events(cli)[:-1]
    for suffix, failure in (
        ([], HarnessFailureKind.INCOMPLETE_STREAM),
        ([{"type": "new_protocol_event", "private": "retained-marker"}],
         HarnessFailureKind.UNSUPPORTED_EVENT),
    ):
        raw = _encode(events + suffix)
        transcript = adapt_native_transcript(cli, raw, exit_code=0)
        assert not transcript.supported
        assert transcript.stdout == raw
        assert "retained-marker" not in repr(transcript)
        assert not any(isinstance(e, (HarnessFinal, HarnessUsage)) for e in transcript.events)
        assert isinstance(transcript.events[-1], HarnessFailure)
        assert transcript.events[-1].failure is failure


@pytest.mark.parametrize("cli", tuple(NativeCliKind))
def test_native_terminal_and_usage_corruption_cannot_look_successful(cli: NativeCliKind) -> None:
    events = _events(cli)
    malformed = _events(cli)
    malformed[-1]["usage"]["input_tokens"] = True
    for raw in (
        _encode(malformed),
        _encode([*events, events[-1]]),
        _encode(events[1:]),
        b'{"type":"turn.started","type":"turn.completed"}\n',
    ):
        transcript = adapt_native_transcript(cli, raw, exit_code=0)
        assert not transcript.supported
        assert transcript.stdout == raw
        assert isinstance(transcript.events[-1], HarnessFailure)
        assert transcript.events[-1].failure is HarnessFailureKind.INVALID_EVENT
    transcript = adapt_native_transcript(cli, _encode(events), exit_code=9)
    assert isinstance(transcript.events[-1], HarnessFailure)
    assert transcript.events[-1].failure is HarnessFailureKind.CLI_FAILURE
