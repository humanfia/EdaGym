"""Contract evidence for externally managed participant adapters."""

from __future__ import annotations

import traceback
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from edagym.canonical import canonical_bytes
from edagym.participants import (
    CodexExecHarnessSpec,
    CodexExecInvocation,
    CodexExecParticipantAdapter,
    HumanizeHarnessSpec,
    HumanizeParticipantAdapter,
    HumanizeSessionStrategy,
    ParticipantAdapterError,
    ParticipantIntentEnvelope,
    ParticipantView,
    SubmitCandidateIntent,
    participant_instruction_digest,
)
from edagym.resolution import resolve_run
from edagym.run.journal import RunJournal
from edagym.run.model import ProducerKind, RunHeader, RunStartedEvent, RunStartedPayload
from edagym.specs.common import Visibility
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.session import (
    BenchmarkMode,
    FeedbackPolicy,
    FixedWriter,
    HarnessActor,
    RecoveryPolicy,
    SessionSpec,
)

from .factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)

_NOW = datetime(2026, 9, 4, tzinfo=UTC)
_INSTRUCTION = "Inspect the bounded workspace and choose the next participant intent."


class _HumanizeSession:
    def __init__(self, responses: Iterator[ParticipantIntentEnvelope]) -> None:
        self._responses = responses
        self.prompts: list[str] = []
        self.closed = False

    def __call__(
        self,
        prompt: str,
        *,
        suppress: bool = False,
        schema: type[ParticipantIntentEnvelope],
    ) -> object:
        assert not suppress
        assert schema is ParticipantIntentEnvelope
        self.prompts.append(prompt)
        return next(self._responses)

    def close(self) -> None:
        self.closed = True


class _HumanizeAgent:
    def __init__(self, responses: tuple[ParticipantIntentEnvelope, ...]) -> None:
        self._responses = iter(responses)
        self.direct_prompts: list[str] = []
        self.opened_at: list[Path | None] = []
        self.session = _HumanizeSession(self._responses)
        self.invalid_response = False
        self.failure: str | None = None

    def __call__(
        self,
        prompt: str,
        *,
        suppress: bool = False,
        schema: type[ParticipantIntentEnvelope],
        cwd: Path | None = None,
    ) -> object:
        assert not suppress
        assert schema is ParticipantIntentEnvelope
        assert cwd is not None
        self.direct_prompts.append(prompt)
        if self.failure is not None:
            raise ValueError(self.failure)
        if self.invalid_response:
            return {"intent": {"kind": "submit_candidate", "candidate_id": "candidate_b"}}
        return next(self._responses)

    def new(self, cwd: Path | None = None) -> _HumanizeSession:
        self.opened_at.append(cwd)
        return self.session


class _CodexTransport:
    def __init__(self, response: ParticipantIntentEnvelope) -> None:
        self.executable_digest = digest("codex-executable")
        self.transport_digest = digest("credential-proxy")
        self.cli_version = "codex-cli 0.153.2"
        self._response = canonical_bytes(response)
        self.invocations: list[CodexExecInvocation] = []
        self.stdin: list[bytes] = []
        self.schemas: list[bytes] = []

    def execute(
        self,
        invocation: CodexExecInvocation,
        *,
        stdin: bytes,
        output_schema: bytes,
        maximum_response_bytes: int,
    ) -> bytes:
        assert maximum_response_bytes == 4096
        self.invocations.append(invocation)
        self.stdin.append(stdin)
        self.schemas.append(output_schema)
        return self._response


def test_humanize_adapter_uses_fresh_and_stateful_session_semantics(
    tmp_path: Path,
) -> None:
    responses = (
        ParticipantIntentEnvelope(
            intent=SubmitCandidateIntent(candidate_id="candidate_a")
        ),
        ParticipantIntentEnvelope(
            intent=SubmitCandidateIntent(candidate_id="candidate_b")
        ),
    )

    fresh_agent = _HumanizeAgent(responses)
    fresh_adapter, fresh_view = _humanize_adapter(
        tmp_path / "fresh",
        fresh_agent,
        benchmark=True,
    )
    assert fresh_adapter.next_intent(fresh_view).candidate_id == "candidate_a"
    assert fresh_adapter.next_intent(fresh_view).candidate_id == "candidate_b"
    assert fresh_adapter.session_strategy is HumanizeSessionStrategy.FRESH
    assert len(fresh_agent.direct_prompts) == 2
    assert not fresh_agent.opened_at
    fresh_adapter.close()

    stateful_agent = _HumanizeAgent(responses)
    stateful_adapter, stateful_view = _humanize_adapter(
        tmp_path / "stateful",
        stateful_agent,
        benchmark=False,
    )
    assert stateful_adapter.next_intent(stateful_view).candidate_id == "candidate_a"
    assert stateful_adapter.next_intent(stateful_view).candidate_id == "candidate_b"
    assert stateful_adapter.session_strategy is HumanizeSessionStrategy.STATEFUL
    assert len(stateful_agent.opened_at) == 1
    assert len(stateful_agent.session.prompts) == 2
    stateful_adapter.close()
    assert stateful_agent.session.closed


def test_codex_exec_adapter_compiles_only_fixed_ephemeral_arguments(
    tmp_path: Path,
) -> None:
    response = ParticipantIntentEnvelope(
        intent=SubmitCandidateIntent(candidate_id="candidate_a")
    )
    transport = _CodexTransport(response)
    environment = environment_spec()
    harness = CodexExecHarnessSpec(
        harness_id="codex_exec",
        requested_model_route="route.snapshot",
        cli_version=transport.cli_version,
        executable_digest=transport.executable_digest,
        transport_digest=transport.transport_digest,
        instruction_digest=participant_instruction_digest(_INSTRUCTION),
        workspace_target=environment.filesystem.workspace_target,
        maximum_response_bytes=4096,
    )
    session = _harness_session(
        "codex_exec",
        harness.digest,
        harness.instruction_digest,
        benchmark=True,
    )
    journal = _journal(tmp_path, environment, session)
    adapter = CodexExecParticipantAdapter(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session,
        harness=harness,
        transport=transport,
        instruction=_INSTRUCTION,
    )
    view = _view(journal)

    intent = adapter.next_intent(view)

    assert intent == response.intent
    assert len(transport.invocations) == 1
    invocation = transport.invocations[0]
    assert invocation.arguments == (
        "exec",
        "--ephemeral",
        "--color",
        "never",
        "--json",
        "--model",
        "route.snapshot",
        "--sandbox",
        "workspace-write",
        "--output-schema",
        "/edagym-control/participant-intent.schema.json",
        "--output-last-message",
        "/edagym-control/participant-intent.json",
        "--cd",
        "/workspace",
        "-",
    )
    assert canonical_bytes(view) in transport.stdin[0]
    assert all("candidate_a" not in argument for argument in invocation.arguments)
    assert transport.schemas[0]


def test_external_adapters_fail_closed_on_unbound_or_unshaped_results(
    tmp_path: Path,
) -> None:
    agent = _HumanizeAgent(
        (ParticipantIntentEnvelope(intent=SubmitCandidateIntent(candidate_id="candidate_a")),)
    )
    adapter, view = _humanize_adapter(tmp_path / "invalid", agent, benchmark=True)
    wrong_view = view.model_copy(update={"actor_id": "another_actor"})
    with pytest.raises(ParticipantAdapterError):
        adapter.next_intent(wrong_view)

    agent.invalid_response = True
    with pytest.raises(ParticipantAdapterError):
        adapter.next_intent(view)

    canary = "EXTERNAL-TRANSPORT-SECRET-CANARY"
    agent.invalid_response = False
    agent.failure = canary
    with pytest.raises(ParticipantAdapterError) as captured:
        adapter.next_intent(view)
    del adapter, agent, canary, view, wrong_view
    rendered = "".join(
        traceback.TracebackException.from_exception(
            captured.value,
            capture_locals=True,
        ).format()
    )
    assert "EXTERNAL-TRANSPORT-SECRET-CANARY" not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def _humanize_adapter(
    root: Path,
    agent: _HumanizeAgent,
    *,
    benchmark: bool,
) -> tuple[HumanizeParticipantAdapter, ParticipantView]:
    root.mkdir(mode=0o700)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700)
    environment = environment_spec()
    harness = HumanizeHarnessSpec(
        harness_id="humanize_agent",
        requested_model_route="route.snapshot",
        agent_config_digest=digest("humanize-agent-config"),
        instruction_digest=participant_instruction_digest(_INSTRUCTION),
        maximum_response_bytes=4096,
    )
    session = _harness_session(
        "humanize_agent",
        harness.digest,
        harness.instruction_digest,
        benchmark=benchmark,
    )
    journal = _journal(root, environment, session)
    adapter = HumanizeParticipantAdapter(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session,
        harness=harness,
        agent=agent,
        workspace=workspace,
        instruction=_INSTRUCTION,
    )
    return adapter, _view(journal)


def _harness_session(
    harness_id: str,
    harness_digest: str,
    instruction_digest: str,
    *,
    benchmark: bool,
) -> SessionSpec:
    base = session_spec()
    return SessionSpec(
        session_id="external_participant",
        mode=BenchmarkMode() if benchmark else base.mode,
        actors=(
            HarnessActor(
                actor_id="solver",
                harness_id=harness_id,
                harness_digest=harness_digest,
                scaffold_digest=instruction_digest,
                requested_model_route="route.snapshot",
            ),
        ),
        writer=FixedWriter(writer="solver"),
        feedback=FeedbackPolicy.STAGE if benchmark else base.feedback,
        recovery=RecoveryPolicy.NONE if benchmark else base.recovery,
        resources=base.resources,
        model_budget=base.model_budget,
    )


def _journal(
    root: Path,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> RunJournal:
    task = task_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="external_participant",
    )
    journal = RunJournal.create(root / "journal", RunHeader.from_binding(plan.binding), task)
    journal.append(
        RunStartedEvent(
            run_id=journal.header.run_id,
            sequence=0,
            event_id=UUID("00000000-0000-0000-0000-000000000501"),
            timestamp=_NOW,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=plan.binding.digest),
        )
    )
    return journal


def _view(journal: RunJournal) -> ParticipantView:
    return ParticipantView(
        run_id=journal.header.run_id,
        task_family=journal.header.binding.task.family,
        authoring_revision=journal.header.binding.task.authoring_revision,
        actor_id="solver",
    )
