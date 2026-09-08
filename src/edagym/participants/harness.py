"""Observed harness events, independent of run control and provider accounting.

These are private transcript projections. A CLI's usage report is an observation,
not a receipt that can settle a provider reservation. Likewise, a final message
does not submit a candidate or establish an evaluator outcome.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from edagym.providers.model import ProviderUsage
from edagym.specs.common import JcsNonNegativeInt, StrictModel


class HarnessEventKind(StrEnum):
    SESSION = "session"
    INPUT = "input"
    ASSISTANT = "assistant"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    USAGE = "usage"
    FINAL = "final"
    FAILURE = "failure"


class HarnessFailureKind(StrEnum):
    INVALID_EVENT = "invalid_event"
    UNSUPPORTED_EVENT = "unsupported_event"
    INCOMPLETE_STREAM = "incomplete_stream"
    CLI_FAILURE = "cli_failure"


class HarnessEventBase(StrictModel):
    """A line in the retained stdout transcript is the source of each observation."""

    source_line: JcsNonNegativeInt


class HarnessSession(HarnessEventBase):
    kind: Literal[HarnessEventKind.SESSION] = HarnessEventKind.SESSION
    session_id: str = Field(min_length=1)
    reported_model: str | None = None


class HarnessInput(HarnessEventBase):
    kind: Literal[HarnessEventKind.INPUT] = HarnessEventKind.INPUT
    text: str


class HarnessAssistant(HarnessEventBase):
    kind: Literal[HarnessEventKind.ASSISTANT] = HarnessEventKind.ASSISTANT
    text: str


class HarnessToolRequest(HarnessEventBase):
    kind: Literal[HarnessEventKind.TOOL_REQUEST] = HarnessEventKind.TOOL_REQUEST
    call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments_json: str


class HarnessToolResult(HarnessEventBase):
    kind: Literal[HarnessEventKind.TOOL_RESULT] = HarnessEventKind.TOOL_RESULT
    call_id: str = Field(min_length=1)
    output_json: str
    failed: bool


class HarnessUsage(HarnessEventBase):
    kind: Literal[HarnessEventKind.USAGE] = HarnessEventKind.USAGE
    usage: ProviderUsage


class HarnessFinal(HarnessEventBase):
    kind: Literal[HarnessEventKind.FINAL] = HarnessEventKind.FINAL


class HarnessFailure(HarnessEventBase):
    kind: Literal[HarnessEventKind.FAILURE] = HarnessEventKind.FAILURE
    failure: HarnessFailureKind


HarnessEvent = Annotated[
    HarnessSession | HarnessInput | HarnessAssistant | HarnessToolRequest
    | HarnessToolResult | HarnessUsage | HarnessFinal | HarnessFailure,
    Field(discriminator="kind"),
]
