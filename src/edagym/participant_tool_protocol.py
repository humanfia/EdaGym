"""Canonical identities for participant tools."""

from __future__ import annotations

from typing import Final

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, Identifier

EXECUTOR_PARTICIPANT_TOOL_NAME: Final = "edagym_run_tool"
CHECKPOINT_PARTICIPANT_TOOL_NAME: Final = "edagym_checkpoint"
COMMIT_INTENT_PARTICIPANT_TOOL_NAME: Final = "edagym_commit_intent"
WORKSPACE_READ_PARTICIPANT_TOOL_NAME: Final = "edagym_read_file"
WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME: Final = "edagym_write_file"
CONTROLLER_PARTICIPANT_TOOL_NAMES: Final = frozenset(
    {
        CHECKPOINT_PARTICIPANT_TOOL_NAME,
        COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
        WORKSPACE_READ_PARTICIPANT_TOOL_NAME,
        WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
    }
)


def participant_tool_invocation_id(
    run_id: Digest,
    request_interaction_id: Identifier,
) -> Identifier:
    """Derive the executor isolation identity for one journaled tool request."""

    identity = canonical_digest(
        {
            "request_interaction_id": request_interaction_id,
            "run_id": run_id,
        },
        domain="participant-tool-invocation-id-v1",
    ).removeprefix("sha256:")
    return f"tool_{identity[:48]}"
