"""Typed bridges for externally managed participant runtimes."""

from __future__ import annotations

import importlib.util
import os
import stat
import threading
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Literal, Protocol

from pydantic import Field, ValidationError, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.humanize_contract import HumanizeSessionStrategy
from edagym.participants.adapters import (
    CommandAgentAdapter,
    ParticipantAdapterError,
    ParticipantChannel,
    ParticipantFailureKind,
)
from edagym.participants.admission import CampaignParticipantAdmission
from edagym.participants.model import ParticipantIntent, ParticipantView
from edagym.run.journal import RunJournal
from edagym.run.model import HarnessRunActor
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.environment import EnvironmentSpec, GuestTarget
from edagym.specs.session import (
    ActorKind,
    BenchmarkMode,
    HarnessActor,
    ModelRoute,
    SessionSpec,
    TrainingMode,
)

_MAXIMUM_RESPONSE_BYTES = 1024 * 1024
_MAXIMUM_INSTRUCTION_BYTES = 1024 * 1024
_CODEX_SCHEMA_TARGET = "/edagym-control/participant-intent.schema.json"
_CODEX_RESPONSE_TARGET = "/edagym-control/participant-intent.json"


class ParticipantIntentEnvelope(StrictModel):
    intent: ParticipantIntent


_INTENT_SCHEMA = ParticipantIntentEnvelope.model_json_schema(mode="validation")
_INTENT_SCHEMA_BYTES = canonical_bytes(_INTENT_SCHEMA)
_INTENT_SCHEMA_DIGEST = canonical_digest(
    _INTENT_SCHEMA,
    domain="participant-intent-envelope-schema-v1",
)


def participant_instruction_digest(instruction: str) -> Digest:
    encoded = _bounded_instruction(instruction)
    return canonical_digest(
        {"instruction": encoded.decode("utf-8")},
        domain="external-participant-instruction-v1",
    )


class HumanizeRuntimeState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class HumanizeRuntimeProbe(StrictModel):
    state: HumanizeRuntimeState
    integration: Literal["injected_python_protocol"] = "injected_python_protocol"
    reason_code: Literal["module_discoverable", "module_not_installed"]


def probe_humanize_runtime() -> HumanizeRuntimeProbe:
    """Report discovery only; importing and configuring the runtime stays external."""

    try:
        available = importlib.util.find_spec("hmz") is not None
    except (ImportError, AttributeError, ValueError):
        available = False
    return HumanizeRuntimeProbe(
        state=(
            HumanizeRuntimeState.AVAILABLE
            if available
            else HumanizeRuntimeState.UNAVAILABLE
        ),
        reason_code="module_discoverable" if available else "module_not_installed",
    )


class HumanizeSession(Protocol):
    def __call__(
        self,
        prompt: str,
        *,
        suppress: bool = False,
        schema: type[ParticipantIntentEnvelope],
    ) -> object: ...

    def close(self) -> None: ...


class HumanizeAgent(Protocol):
    def __call__(
        self,
        prompt: str,
        *,
        suppress: bool = False,
        schema: type[ParticipantIntentEnvelope],
        cwd: Path | None = None,
    ) -> object: ...

    def new(self, cwd: Path | None = None) -> HumanizeSession: ...


class HumanizeHarnessSpec(StrictModel):
    harness_id: Identifier
    requested_model_route: ModelRoute
    agent_config_digest: Digest
    instruction_digest: Digest
    permission: Literal["workspace-write"] = "workspace-write"
    maximum_response_bytes: Annotated[
        int,
        Field(strict=True, ge=1, le=_MAXIMUM_RESPONSE_BYTES),
    ] = _MAXIMUM_RESPONSE_BYTES

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            {
                "protocol": "humanize-python-agent-v1",
                "intent_schema_digest": _INTENT_SCHEMA_DIGEST,
                "spec": self,
            },
            domain="humanize-participant-harness-v1",
        )


class HumanizeParticipantAdapter:
    """Drive an injected agent with fresh or stateful documented turn semantics."""

    def __init__(
        self,
        *,
        actor_id: str,
        journal: RunJournal,
        environment: EnvironmentSpec,
        session: SessionSpec,
        harness: HumanizeHarnessSpec,
        agent: HumanizeAgent,
        workspace: Path,
        instruction: str,
    ) -> None:
        _validate_run_bindings(journal, environment, session)
        actor = _bound_harness(journal, session, actor_id)
        if (
            actor.harness_digest != harness.digest
            or actor.scaffold_digest != harness.instruction_digest
            or actor.requested_model_route != harness.requested_model_route
            or participant_instruction_digest(instruction) != harness.instruction_digest
        ):
            raise ValueError("external participant harness differs from the run binding")
        if harness.harness_id != _session_harness(session, actor_id).harness_id:
            raise ValueError("external participant harness identifier differs from the session")
        if isinstance(session.mode, BenchmarkMode):
            strategy = HumanizeSessionStrategy.FRESH
        elif isinstance(session.mode, TrainingMode):
            strategy = HumanizeSessionStrategy.STATEFUL
        else:
            raise ValueError("external agent participants require benchmark or training mode")
        self.actor_id = actor_id
        self._run_id = journal.header.run_id
        self._agent = agent
        self._workspace = _private_workspace(workspace, journal.directory)
        self._instruction = instruction
        self._maximum_response_bytes = harness.maximum_response_bytes
        self._strategy = strategy
        self._held_session: HumanizeSession | None = None
        self._lock = threading.Lock()
        self._closed = False

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return MappingProxyType({self.actor_id: ActorKind.HARNESS})

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission | None:
        return None

    @property
    def session_strategy(self) -> HumanizeSessionStrategy:
        return self._strategy

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.actor_id != self.actor_id or view.run_id != self._run_id:
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        prompt = _participant_prompt(self._instruction, view)
        with self._lock:
            if self._closed:
                raise ParticipantAdapterError(ParticipantFailureKind.COMMAND_CANCELLED)
            response = self._invoke(prompt)
        if isinstance(response, ParticipantFailureKind):
            raise ParticipantAdapterError(response) from None
        if type(response) is not ParticipantIntentEnvelope:
            del response
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        encoded = canonical_bytes(response)
        if len(encoded) > self._maximum_response_bytes:
            del encoded, response
            raise ParticipantAdapterError(ParticipantFailureKind.RESPONSE_BOUND)
        validated = _decode_intent_envelope(encoded)
        del encoded, response
        if validated is None:
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        return validated.intent

    def _invoke(
        self,
        prompt: str,
    ) -> object | ParticipantFailureKind:
        try:
            if self._strategy is HumanizeSessionStrategy.FRESH:
                return self._agent(
                    prompt,
                    suppress=False,
                    schema=ParticipantIntentEnvelope,
                    cwd=self._workspace,
                )
            if self._held_session is None:
                self._held_session = self._agent.new(self._workspace)
            return self._held_session(
                prompt,
                suppress=False,
                schema=ParticipantIntentEnvelope,
            )
        except ParticipantAdapterError as error:
            return error.kind
        except Exception:
            return ParticipantFailureKind.CHANNEL_FAILURE

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            held = self._held_session
            self._held_session = None
        if held is not None and not _close_humanize_session(held):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None


class CodexExecSandbox(StrEnum):
    WORKSPACE_WRITE = "workspace-write"


class CodexExecHarnessSpec(StrictModel):
    harness_id: Identifier
    requested_model_route: ModelRoute
    cli_version: Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[ -~]+$")]
    executable_digest: Digest
    transport_digest: Digest
    instruction_digest: Digest
    workspace_target: GuestTarget
    sandbox: Literal[CodexExecSandbox.WORKSPACE_WRITE] = CodexExecSandbox.WORKSPACE_WRITE
    ephemeral: Literal[True] = True
    maximum_response_bytes: Annotated[
        int,
        Field(strict=True, ge=1, le=_MAXIMUM_RESPONSE_BYTES),
    ] = _MAXIMUM_RESPONSE_BYTES

    @model_validator(mode="after")
    def require_control_target_separation(self) -> CodexExecHarnessSpec:
        if _targets_overlap(self.workspace_target, "/edagym-control"):
            raise ValueError("CLI control files must be outside the participant workspace")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            {
                "protocol": "codex-exec-v1",
                "intent_schema_digest": _INTENT_SCHEMA_DIGEST,
                "spec": self,
            },
            domain="codex-exec-participant-harness-v1",
        )


class CodexExecInvocation(StrictModel):
    requested_model_route: ModelRoute
    cli_version: Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[ -~]+$")]
    executable_digest: Digest
    transport_digest: Digest
    instruction_digest: Digest
    prompt_digest: Digest
    output_schema_digest: Digest = _INTENT_SCHEMA_DIGEST
    workspace_target: GuestTarget
    sandbox: Literal[CodexExecSandbox.WORKSPACE_WRITE] = CodexExecSandbox.WORKSPACE_WRITE
    ephemeral: Literal[True] = True

    @field_validator("output_schema_digest")
    @classmethod
    def require_intent_schema(cls, value: Digest) -> Digest:
        if value != _INTENT_SCHEMA_DIGEST:
            raise ValueError("CLI invocation requires the canonical participant intent schema")
        return value

    @property
    def arguments(self) -> tuple[str, ...]:
        return (
            "exec",
            "--ephemeral",
            "--color",
            "never",
            "--json",
            "--model",
            self.requested_model_route,
            "--sandbox",
            self.sandbox.value,
            "--output-schema",
            _CODEX_SCHEMA_TARGET,
            "--output-last-message",
            _CODEX_RESPONSE_TARGET,
            "--cd",
            self.workspace_target,
            "-",
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="codex-exec-invocation-v1")


class CodexExecTransport(Protocol):
    @property
    def executable_digest(self) -> Digest: ...

    @property
    def transport_digest(self) -> Digest: ...

    @property
    def cli_version(self) -> str: ...

    def execute(
        self,
        invocation: CodexExecInvocation,
        *,
        stdin: bytes,
        output_schema: bytes,
        maximum_response_bytes: int,
    ) -> bytes: ...


class CodexExecChannel(ParticipantChannel):
    """Compile a participant view into one fixed non-interactive CLI request."""

    def __init__(
        self,
        *,
        harness: CodexExecHarnessSpec,
        transport: CodexExecTransport,
        instruction: str,
    ) -> None:
        if participant_instruction_digest(instruction) != harness.instruction_digest:
            raise ValueError("CLI participant instruction differs from its harness binding")
        transport_identity = _codex_transport_identity(transport)
        if transport_identity is None:
            raise ValueError("CLI participant transport identity is unavailable")
        if transport_identity != (
            harness.executable_digest,
            harness.transport_digest,
            harness.cli_version,
        ):
            raise ValueError("CLI participant transport differs from its harness binding")
        self._harness = harness
        self._transport = transport
        self._instruction = instruction

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        response_bound = min(
            self._harness.maximum_response_bytes,
            _response_bound(maximum_response_bytes),
        )
        participant_view = _decode_participant_view(view)
        if participant_view is None:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        prompt = _participant_prompt(self._instruction, participant_view).encode("utf-8")
        invocation = CodexExecInvocation(
            requested_model_route=self._harness.requested_model_route,
            cli_version=self._harness.cli_version,
            executable_digest=self._harness.executable_digest,
            transport_digest=self._harness.transport_digest,
            instruction_digest=self._harness.instruction_digest,
            prompt_digest=canonical_digest(
                {"prompt": prompt.decode("utf-8")},
                domain="codex-exec-prompt-v1",
            ),
            workspace_target=self._harness.workspace_target,
        )
        response = _invoke_codex_transport(
            self._transport,
            invocation,
            prompt=prompt,
            response_bound=response_bound,
        )
        if isinstance(response, ParticipantFailureKind):
            raise ParticipantAdapterError(response) from None
        if type(response) is not bytes:
            del response
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        if len(response) > response_bound:
            del response
            raise ParticipantAdapterError(ParticipantFailureKind.RESPONSE_BOUND)
        envelope = _decode_intent_envelope(response)
        if envelope is None:
            del response
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        del response
        return canonical_bytes(envelope.intent)

    def __repr__(self) -> str:
        return "CodexExecChannel(<injected>)"


class CodexExecParticipantAdapter:
    """Bind one injected non-interactive channel to a fresh benchmark actor."""

    def __init__(
        self,
        *,
        actor_id: str,
        journal: RunJournal,
        environment: EnvironmentSpec,
        session: SessionSpec,
        harness: CodexExecHarnessSpec,
        transport: CodexExecTransport,
        instruction: str,
    ) -> None:
        _validate_run_bindings(journal, environment, session)
        if not isinstance(session.mode, BenchmarkMode):
            raise ValueError("ephemeral CLI participants require benchmark mode")
        actor = _bound_harness(journal, session, actor_id)
        if (
            actor.harness_digest != harness.digest
            or actor.scaffold_digest != harness.instruction_digest
            or actor.requested_model_route != harness.requested_model_route
            or harness.workspace_target != environment.filesystem.workspace_target
            or not _codex_control_target_is_disjoint(environment)
        ):
            raise ValueError("CLI participant harness differs from the run binding")
        if harness.harness_id != _session_harness(session, actor_id).harness_id:
            raise ValueError("CLI participant harness identifier differs from the session")
        self.actor_id = actor_id
        self._run_id = journal.header.run_id
        self._adapter = CommandAgentAdapter(
            actor_id=actor_id,
            channel=CodexExecChannel(
                harness=harness,
                transport=transport,
                instruction=instruction,
            ),
            maximum_response_bytes=harness.maximum_response_bytes,
        )

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return self._adapter.actor_kinds

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission | None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.run_id != self._run_id:
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        return self._adapter.next_intent(view)


class ClaudeCodeSandbox(StrEnum):
    WORKSPACE_WRITE = "workspace-write"


class ClaudeCodeHarnessSpec(StrictModel):
    """Versioned native Claude Code CLI binding with an injected transport."""

    harness_id: Identifier
    requested_model_route: ModelRoute
    cli_version: Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[ -~]+$")]
    executable_digest: Digest
    transport_digest: Digest
    instruction_digest: Digest
    workspace_target: GuestTarget
    sandbox: Literal[ClaudeCodeSandbox.WORKSPACE_WRITE] = ClaudeCodeSandbox.WORKSPACE_WRITE
    ephemeral: Literal[True] = True
    maximum_response_bytes: Annotated[
        int, Field(strict=True, ge=1, le=_MAXIMUM_RESPONSE_BYTES)
    ] = _MAXIMUM_RESPONSE_BYTES

    @model_validator(mode="after")
    def require_control_target_separation(self) -> ClaudeCodeHarnessSpec:
        if _targets_overlap(self.workspace_target, "/edagym-control"):
            raise ValueError("CLI control files must be outside the participant workspace")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            {"protocol": "claude-code-cli-v1", "intent_schema_digest": _INTENT_SCHEMA_DIGEST,
             "spec": self},
            domain="claude-code-participant-harness-v1",
        )


class ClaudeCodeInvocation(StrictModel):
    requested_model_route: ModelRoute
    cli_version: Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[ -~]+$")]
    executable_digest: Digest
    transport_digest: Digest
    instruction_digest: Digest
    prompt_digest: Digest
    output_schema_digest: Digest = _INTENT_SCHEMA_DIGEST
    workspace_target: GuestTarget
    sandbox: Literal[ClaudeCodeSandbox.WORKSPACE_WRITE] = ClaudeCodeSandbox.WORKSPACE_WRITE
    ephemeral: Literal[True] = True

    @field_validator("output_schema_digest")
    @classmethod
    def require_intent_schema(cls, value: Digest) -> Digest:
        if value != _INTENT_SCHEMA_DIGEST:
            raise ValueError("Claude Code invocation requires the canonical intent schema")
        return value

    @property
    def arguments(self) -> tuple[str, ...]:
        return (
            "--print", "--output-format", "json", "--model", self.requested_model_route,
            "--permission-mode", "acceptEdits", "--add-dir", self.workspace_target,
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="claude-code-invocation-v1")


class ClaudeCodeTransport(Protocol):
    @property
    def executable_digest(self) -> Digest: ...

    @property
    def transport_digest(self) -> Digest: ...

    @property
    def cli_version(self) -> str: ...

    def execute(
        self,
        invocation: ClaudeCodeInvocation,
        *,
        stdin: bytes,
        output_schema: bytes,
        maximum_response_bytes: int,
    ) -> bytes: ...


class ClaudeCodeChannel(ParticipantChannel):
    """Invoke Claude Code only through a transport that owns process isolation."""

    def __init__(
        self,
        *,
        harness: ClaudeCodeHarnessSpec,
        transport: ClaudeCodeTransport,
        instruction: str,
    ) -> None:
        if participant_instruction_digest(instruction) != harness.instruction_digest:
            raise ValueError("Claude Code instruction differs from its harness binding")
        identity = _claude_transport_identity(transport)
        if identity != (harness.executable_digest, harness.transport_digest, harness.cli_version):
            raise ValueError("Claude Code transport differs from its harness binding")
        self._harness = harness
        self._transport = transport
        self._instruction = instruction

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        response_bound = min(
            self._harness.maximum_response_bytes,
            _response_bound(maximum_response_bytes),
        )
        participant_view = _decode_participant_view(view)
        if participant_view is None:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        prompt = _participant_prompt(self._instruction, participant_view).encode("utf-8")
        invocation = ClaudeCodeInvocation(
            requested_model_route=self._harness.requested_model_route,
            cli_version=self._harness.cli_version,
            executable_digest=self._harness.executable_digest,
            transport_digest=self._harness.transport_digest,
            instruction_digest=self._harness.instruction_digest,
            prompt_digest=canonical_digest(
                {"prompt": prompt.decode("utf-8")}, domain="claude-code-prompt-v1"
            ),
            workspace_target=self._harness.workspace_target,
        )
        try:
            response = self._transport.execute(
                invocation, stdin=prompt, output_schema=_INTENT_SCHEMA_BYTES,
                maximum_response_bytes=response_bound,
            )
        except ParticipantAdapterError:
            raise
        except Exception:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        if len(response) > response_bound:
            raise ParticipantAdapterError(ParticipantFailureKind.RESPONSE_BOUND)
        envelope = _decode_intent_envelope(response)
        if envelope is None:
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        return canonical_bytes(envelope.intent)


class ClaudeCodeParticipantAdapter:
    """Bind one ephemeral Claude Code process to a benchmark harness actor."""

    def __init__(
        self,
        *,
        actor_id: str,
        journal: RunJournal,
        environment: EnvironmentSpec,
        session: SessionSpec,
        harness: ClaudeCodeHarnessSpec,
        transport: ClaudeCodeTransport,
        instruction: str,
    ) -> None:
        _validate_run_bindings(journal, environment, session)
        if not isinstance(session.mode, BenchmarkMode):
            raise ValueError("ephemeral CLI participants require benchmark mode")
        actor = _bound_harness(journal, session, actor_id)
        if (
            actor.harness_digest != harness.digest
            or actor.scaffold_digest != harness.instruction_digest
            or actor.requested_model_route != harness.requested_model_route
            or harness.workspace_target != environment.filesystem.workspace_target
            or not _codex_control_target_is_disjoint(environment)
        ):
            raise ValueError("Claude Code harness differs from the run binding")
        if harness.harness_id != _session_harness(session, actor_id).harness_id:
            raise ValueError("Claude Code harness identifier differs from the session")
        self.actor_id = actor_id
        self._run_id = journal.header.run_id
        self._adapter = CommandAgentAdapter(
            actor_id=actor_id,
            channel=ClaudeCodeChannel(
                harness=harness,
                transport=transport,
                instruction=instruction,
            ),
            maximum_response_bytes=harness.maximum_response_bytes,
        )

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return self._adapter.actor_kinds

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission | None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.run_id != self._run_id:
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        return self._adapter.next_intent(view)


def _participant_prompt(instruction: str, view: ParticipantView) -> str:
    return "\n".join(
        (
            instruction,
            "Return exactly one structured participant intent for this view.",
            canonical_bytes(view).decode("utf-8"),
        )
    )


def _close_humanize_session(session: HumanizeSession) -> bool:
    try:
        session.close()
    except Exception:
        return False
    return True


def _codex_transport_identity(
    transport: CodexExecTransport,
) -> tuple[Digest, Digest, str] | None:
    try:
        return (
            transport.executable_digest,
            transport.transport_digest,
            transport.cli_version,
        )
    except Exception:
        return None


def _claude_transport_identity(
    transport: ClaudeCodeTransport,
) -> tuple[Digest, Digest, str] | None:
    try:
        return transport.executable_digest, transport.transport_digest, transport.cli_version
    except Exception:
        return None


def _invoke_codex_transport(
    transport: CodexExecTransport,
    invocation: CodexExecInvocation,
    *,
    prompt: bytes,
    response_bound: int,
) -> bytes | ParticipantFailureKind:
    try:
        return transport.execute(
            invocation,
            stdin=prompt,
            output_schema=_INTENT_SCHEMA_BYTES,
            maximum_response_bytes=response_bound,
        )
    except ParticipantAdapterError as error:
        return error.kind
    except Exception:
        return ParticipantFailureKind.CHANNEL_FAILURE


def _decode_participant_view(payload: bytes) -> ParticipantView | None:
    try:
        return ParticipantView.model_validate_json(payload)
    except (TypeError, ValidationError):
        return None


def _decode_intent_envelope(payload: bytes) -> ParticipantIntentEnvelope | None:
    try:
        return ParticipantIntentEnvelope.model_validate_json(payload)
    except (TypeError, ValidationError):
        return None


def _bounded_instruction(instruction: str) -> bytes:
    if not instruction:
        raise ValueError("participant instruction must be non-empty")
    try:
        encoded = instruction.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("participant instruction must be valid UTF-8") from None
    if len(encoded) > _MAXIMUM_INSTRUCTION_BYTES:
        raise ValueError("participant instruction exceeds its byte bound")
    return encoded


def _response_bound(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("maximum response size must be positive")
    return min(value, _MAXIMUM_RESPONSE_BYTES)


def _validate_run_bindings(
    journal: RunJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> None:
    if environment.digest != journal.header.binding.environment.environment_spec_digest:
        raise ValueError("participant environment differs from the run binding")
    if session.digest != journal.header.binding.session.session_spec_digest:
        raise ValueError("participant session differs from the run binding")


def _bound_harness(
    journal: RunJournal,
    session: SessionSpec,
    actor_id: str,
) -> HarnessRunActor:
    session_actor = _session_harness(session, actor_id)
    del session_actor
    matches = tuple(
        actor
        for actor in journal.header.binding.session.actors
        if actor.actor_id == actor_id
    )
    if len(matches) != 1 or not isinstance(matches[0], HarnessRunActor):
        raise ValueError("external participant actor must be a bound harness")
    return matches[0]


def _session_harness(session: SessionSpec, actor_id: str) -> HarnessActor:
    matches = tuple(actor for actor in session.actors if actor.actor_id == actor_id)
    if len(matches) != 1 or not isinstance(matches[0], HarnessActor):
        raise ValueError("external participant actor must be a session harness")
    return matches[0]


def _private_workspace(workspace: Path, journal_root: Path) -> Path:
    if not workspace.is_absolute():
        raise ValueError("participant workspace must be absolute")
    try:
        metadata = workspace.stat(follow_symlinks=False)
        resolved = workspace.resolve(strict=True)
        journal = journal_root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("participant workspace cannot be resolved safely") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or (metadata.st_dev, metadata.st_ino)
        != (
            resolved.stat(follow_symlinks=False).st_dev,
            resolved.stat(follow_symlinks=False).st_ino,
        )
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or resolved == journal
        or resolved in journal.parents
        or journal in resolved.parents
    ):
        raise ValueError("participant workspace is not a private independent directory")
    return resolved


def _codex_control_target_is_disjoint(environment: EnvironmentSpec) -> bool:
    targets = (
        environment.filesystem.workspace_target,
        environment.filesystem.artifact_target,
        *(mount.target for mount in environment.filesystem.readonly_assets),
    )
    return all(not _targets_overlap(target, "/edagym-control") for target in targets)


def _targets_overlap(left: str, right: str) -> bool:
    left_path = PurePosixPath(left)
    right_path = PurePosixPath(right)
    return (
        left_path == right_path
        or left_path in right_path.parents
        or right_path in left_path.parents
    )
