"""Evidence for participant view isolation and journaled hybrid handoff."""

from __future__ import annotations

import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from uuid import UUID

import pytest

from edagym.evaluation.model import PassedOutcome, StageResult
from edagym.participants import (
    CandidateSnapshot,
    CommandAgentAdapter,
    HumanParticipantAdapter,
    HybridParticipantAdapter,
    JsonLineHumanChannel,
    ParticipantActionKind,
    ParticipantAdapterError,
    ParticipantController,
    ParticipantFailureKind,
    ParticipantView,
    project_participant_session_record,
)
from edagym.projections.model import ParticipationKind
from edagym.resolution import resolve_run
from edagym.run.artifact_model import (
    ArtifactRecord,
    BlobRef,
)
from edagym.run.artifacts import ARTIFACT_MANIFEST_MEDIA_TYPE
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import (
    CandidateSubmittedEvent,
    CandidateSubmittedPayload,
    EvaluationCompletedEvent,
    EvaluationCompletedPayload,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    ProducerKind,
    RunHeader,
    RunStartedEvent,
    RunStartedPayload,
)
from edagym.specs.common import (
    ArtifactClass,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.session import (
    HandoffWriter,
    HarnessActor,
    HumanActor,
    SessionSpec,
)
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def _snapshot(candidate_id: str, candidate_digest: str | None = None) -> CandidateSnapshot:
    value = digest(candidate_id) if candidate_digest is None else candidate_digest
    return CandidateSnapshot(
        record=ArtifactRecord(
            logical_id=f"candidate_snapshot_{candidate_id}",
            blob=BlobRef(digest=value, size_bytes=0),
            media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
            artifact_class=ArtifactClass.CANDIDATE,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.AUTHOR,
            redistribution=Redistribution.RESTRICTED,
        )
    )


def test_hybrid_handoff_preserves_actor_attribution_and_view_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    base_session = session_spec()
    session = SessionSpec(
        session_id="hybrid_training",
        mode=base_session.mode,
        actors=(
            HumanActor(
                actor_id="student",
                adapter_id="json_line",
                adapter_digest=digest("json-line-adapter"),
            ),
            HarnessActor(
                actor_id="solver",
                harness_id="command_agent",
                harness_digest=digest("command-agent"),
                scaffold_digest=digest("command-scaffold"),
                requested_model_route="test-route",
            ),
        ),
        writer=HandoffWriter(initial_writer="student"),
        feedback=base_session.feedback,
        recovery=base_session.recovery,
        resources=base_session.resources,
        model_budget=base_session.model_budget,
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="hybrid-0001",
    )
    header = RunHeader.from_binding(plan.binding)
    journal = TrialJournal.create(tmp_path / "journal", header, task)
    journal.append(
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID("00000000-0000-0000-0000-000000000101"),
            timestamp=datetime(2026, 9, 4, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        )
    )

    human_input = StringIO(json.dumps({"kind": "transfer_control", "next_writer": "solver"}) + "\n")
    human_output = StringIO()
    human = HumanParticipantAdapter(
        "student",
        JsonLineHumanChannel(human_input, human_output),
    )
    candidate_digest = digest("hybrid-candidate")
    monkeypatch.setenv("SECRET_CANARY", "must-not-enter-participant-view")
    command_channel = _CommandChannel()
    command = CommandAgentAdapter(
        actor_id="solver",
        channel=command_channel,
        maximum_response_bytes=512,
    )
    adapter = HybridParticipantAdapter((human, command))
    event_ids = iter(
        (
            UUID("00000000-0000-0000-0000-000000000102"),
            UUID("00000000-0000-0000-0000-000000000103"),
            UUID("00000000-0000-0000-0000-000000000104"),
        )
    )
    controller = ParticipantController(
        journal,
        adapter,
        session=session,
        snapshot_candidate=lambda intent: _snapshot(intent.candidate_id, candidate_digest),
        event_id_factory=lambda: next(event_ids),
        clock=lambda: datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
    )

    after_handoff = controller.act_once()
    final_state = controller.act_once()

    assert after_handoff.current_writer == "solver"
    assert final_state.candidates[0].actor == "solver"
    assert final_state.candidates[0].digest == candidate_digest
    emitted_view = json.loads(human_output.getvalue())
    assert emitted_view["actor_id"] == "student"
    assert "must-not-enter-participant-view" not in human_output.getvalue()
    assert command_channel.request_actor == "solver"
    assert command_channel.response_bound == 512
    evidence = project_participant_session_record(
        journal.record(),
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
    )
    assert evidence.participation is ParticipationKind.HYBRID
    assert tuple((action.actor_id, action.kind) for action in evidence.actions) == (
        ("student", ParticipantActionKind.CONTROL_TRANSFER),
        ("solver", ParticipantActionKind.CANDIDATE_SUBMISSION),
    )
    assert tuple(
        (handoff.previous_writer, handoff.next_writer) for handoff in evidence.handoffs
    ) == (("student", "solver"),)


class _CommandChannel:
    def __init__(self) -> None:
        self.request_actor: str | None = None
        self.response_bound: int | None = None

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        self.response_bound = maximum_response_bytes
        assert b"must-not-enter-participant-view" not in view
        self.request_actor = json.loads(view)["actor_id"]
        return json.dumps(
            {
                "kind": "submit_candidate",
                "candidate_id": "candidate_a",
                "parent_candidate_id": None,
            }
        ).encode()


def test_invalid_participant_response_is_typed_and_not_retained_in_traceback() -> None:
    canary = "CANARY-SHOULD-NOT-LOG"
    view = ParticipantView(
        run_id=digest("invalid-response-run"),
        task_family="stream_guard",
        authoring_revision=1,
        actor_id="solver",
    )

    _assert_sanitized_failure(
        _InvalidCommandChannel(canary),
        view,
        canary,
        ParticipantFailureKind.INVALID_INTENT,
    )
    _assert_sanitized_failure(
        _FailingCommandChannel(canary),
        view,
        canary,
        ParticipantFailureKind.CHANNEL_FAILURE,
    )
    _assert_sanitized_failure(
        _HostileBytesChannel(canary),
        view,
        canary,
        ParticipantFailureKind.CHANNEL_FAILURE,
    )

    human_input = StringIO("\U0001f642" * 100 + "\n")
    human_channel = JsonLineHumanChannel(
        human_input,
        StringIO(),
        maximum_response_bytes=8,
    )
    with pytest.raises(ParticipantAdapterError) as human_failure:
        human_channel.exchange(b"{}", maximum_response_bytes=8)
    assert human_failure.value.kind is ParticipantFailureKind.RESPONSE_BOUND
    assert human_input.tell() <= 3


def _assert_sanitized_failure(
    channel: _InvalidCommandChannel | _FailingCommandChannel | _HostileBytesChannel,
    view: ParticipantView,
    canary: str,
    expected_kind: ParticipantFailureKind,
) -> None:
    adapter = CommandAgentAdapter(actor_id="solver", channel=channel)
    with pytest.raises(ParticipantAdapterError) as captured:
        adapter.next_intent(view)

    del adapter, canary, channel, view
    rendered = "".join(
        traceback.TracebackException.from_exception(
            captured.value,
            capture_locals=True,
        ).format()
    )
    assert "CANARY-SHOULD-NOT-LOG" not in rendered
    assert captured.value.kind is expected_kind
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


class _InvalidCommandChannel:
    def __init__(self, canary: str) -> None:
        self._canary = canary

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view
        del maximum_response_bytes
        return json.dumps({"kind": "invalid", "secret": self._canary}).encode()

    def __repr__(self) -> str:
        return self._canary


class _FailingCommandChannel:
    def __init__(self, canary: str) -> None:
        self._canary = canary

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view
        del maximum_response_bytes
        raise ValueError(self._canary)

    def __repr__(self) -> str:
        return self._canary


class _HostileBytes(bytes):
    _canary: str

    def __new__(cls, canary: str) -> _HostileBytes:
        value = super().__new__(cls, b"{}")
        value._canary = canary
        return value

    def __len__(self) -> int:
        raise ValueError(self._canary)

    def __repr__(self) -> str:
        return self._canary


class _HostileBytesChannel:
    def __init__(self, canary: str) -> None:
        self._canary = canary

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view, maximum_response_bytes
        return _HostileBytes(self._canary)

    def __repr__(self) -> str:
        return self._canary


def test_controller_rejects_adapter_kind_misattribution(tmp_path: Path) -> None:
    journal, session = _agent_journal(tmp_path / "kind-journal")
    human = HumanParticipantAdapter(
        "solver",
        JsonLineHumanChannel(StringIO(), StringIO()),
    )

    with pytest.raises(ValueError, match="actor and kind"):
        ParticipantController(
            journal,
            human,
            session=session,
            snapshot_candidate=lambda intent: _snapshot(intent.candidate_id),
        )


def test_invalid_candidate_parent_is_rejected_before_snapshot(tmp_path: Path) -> None:
    journal, session = _agent_journal(tmp_path / "candidate-parent-journal")
    snapshot_calls = 0

    def snapshot_candidate(intent: object) -> CandidateSnapshot:
        nonlocal snapshot_calls
        del intent
        snapshot_calls += 1
        return _snapshot("should-not-be-snapshotted")

    controller = ParticipantController(
        journal,
        CommandAgentAdapter(
            actor_id="solver",
            channel=_MissingParentCandidateChannel(),
        ),
        session=session,
        snapshot_candidate=snapshot_candidate,
    )

    with pytest.raises(ParticipantAdapterError) as captured:
        controller.act_once()

    assert captured.value.kind is ParticipantFailureKind.INVALID_INTENT
    assert snapshot_calls == 0
    assert journal.state().candidates == ()


class _MissingParentCandidateChannel:
    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view, maximum_response_bytes
        return json.dumps(
            {
                "kind": "submit_candidate",
                "candidate_id": "candidate_a",
                "parent_candidate_id": "missing_parent",
            }
        ).encode()


def test_concurrent_controllers_serialize_participant_dispatch(tmp_path: Path) -> None:
    journal, session = _agent_journal(tmp_path / "concurrent-journal")
    channel = _ConcurrentCommandChannel()
    adapter = CommandAgentAdapter(actor_id="solver", channel=channel)
    controllers = (
        ParticipantController(
            journal,
            adapter,
            session=session,
            snapshot_candidate=lambda intent: _snapshot(intent.candidate_id),
        ),
        ParticipantController(
            journal,
            adapter,
            session=session,
            snapshot_candidate=lambda intent: _snapshot(intent.candidate_id),
        ),
    )
    start = threading.Barrier(3)

    def act(controller: ParticipantController) -> None:
        start.wait()
        controller.act_once()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = tuple(pool.submit(act, controller) for controller in controllers)
        start.wait()
        for future in futures:
            future.result()

    assert channel.call_ids == [0, 1]
    assert channel.maximum_concurrent_calls == 1
    assert journal.state().interaction_ids == ("turn_0", "turn_1")


class _ConcurrentCommandChannel:
    def __init__(self) -> None:
        self.call_ids: list[int] = []
        self.maximum_concurrent_calls = 0
        self._active_calls = 0
        self._lock = threading.Lock()

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view
        del maximum_response_bytes
        with self._lock:
            call_id = len(self.call_ids)
            self.call_ids.append(call_id)
            self._active_calls += 1
            self.maximum_concurrent_calls = max(
                self.maximum_concurrent_calls,
                self._active_calls,
            )
        time.sleep(0.05)
        with self._lock:
            self._active_calls -= 1
        return json.dumps(
            {
                "kind": "interaction",
                "interaction_id": f"turn_{call_id}",
                "direction": "participant_output",
                "artifact_refs": [],
            }
        ).encode()


def test_participant_view_excludes_hidden_events_and_evaluator_feedback(
    tmp_path: Path,
) -> None:
    journal, session = _agent_journal(tmp_path / "visibility-journal")
    header = journal.header
    journal.append(
        CandidateSubmittedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID("00000000-0000-0000-0000-000000000310"),
            timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.AUTHOR,
            payload=CandidateSubmittedPayload(
                candidate_id="hidden_parent",
                candidate_digest=digest("hidden-parent-candidate"),
            ),
        )
    )
    journal.append(
        CandidateSubmittedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID("00000000-0000-0000-0000-000000000311"),
            timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.PARTICIPANT,
            payload=CandidateSubmittedPayload(
                candidate_id="candidate_a",
                candidate_digest=digest("visibility-candidate"),
                parent_candidate_id="hidden_parent",
            ),
        )
    )
    journal.append(
        EvaluationStartedEvent(
            run_id=header.run_id,
            sequence=3,
            event_id=UUID("00000000-0000-0000-0000-000000000312"),
            timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationStartedPayload(
                stage_id="functional",
                candidate_id="candidate_a",
                job_id="hidden_job",
            ),
        )
    )
    journal.append(
        JobStateChangedEvent(
            run_id=header.run_id,
            sequence=4,
            event_id=UUID("00000000-0000-0000-0000-000000000313"),
            timestamp=datetime(2026, 9, 4, 0, 0, 3, tzinfo=UTC),
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.AUTHOR,
            payload=JobStateChangedPayload(
                job_id="hidden_job",
                state=JobStateKind.RUNNING,
            ),
        )
    )
    journal.append(
        JobStateChangedEvent(
            run_id=header.run_id,
            sequence=5,
            event_id=UUID("00000000-0000-0000-0000-000000000314"),
            timestamp=datetime(2026, 9, 4, 0, 0, 4, tzinfo=UTC),
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.AUTHOR,
            payload=JobStateChangedPayload(
                job_id="hidden_job",
                state=JobStateKind.COMPLETED,
            ),
        )
    )
    journal.append(
        EvaluationCompletedEvent(
            run_id=header.run_id,
            sequence=6,
            event_id=UUID("00000000-0000-0000-0000-000000000315"),
            timestamp=datetime(2026, 9, 4, 0, 0, 5, tzinfo=UTC),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationCompletedPayload(
                candidate_id="candidate_a",
                job_id="hidden_job",
                result=StageResult(
                    stage_id="functional",
                    outcome=PassedOutcome(),
                ),
            ),
        )
    )
    journal.append(
        InteractionRecordedEvent(
            run_id=header.run_id,
            sequence=7,
            event_id=UUID("00000000-0000-0000-0000-000000000316"),
            timestamp=datetime(2026, 9, 4, 0, 0, 6, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.AUTHOR,
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.PARTICIPANT_OUTPUT,
                interaction_id="controller_trace_canary",
            ),
        )
    )
    channel = _CapturingCommandChannel()
    controller = ParticipantController(
        journal,
        CommandAgentAdapter(actor_id="solver", channel=channel),
        session=session,
        snapshot_candidate=lambda intent: _snapshot(intent.candidate_id),
    )

    controller.act_once()

    assert "visible_event_count" not in channel.view
    assert channel.view["feedback"] == []
    assert channel.view["candidates"] == []
    assert "hidden_parent" not in json.dumps(channel.view)
    assert "controller_trace_canary" not in json.dumps(channel.view)

    failing_channel = _InvalidCommandChannel("CONTROLLER-RESPONSE-CANARY")
    failing_controller = ParticipantController(
        journal,
        CommandAgentAdapter(actor_id="solver", channel=failing_channel),
        session=session,
        snapshot_candidate=lambda intent: _snapshot(intent.candidate_id),
    )
    with pytest.raises(ParticipantAdapterError) as captured:
        failing_controller.act_once()
    del failing_channel, failing_controller
    rendered = "".join(
        traceback.TracebackException.from_exception(
            captured.value,
            capture_locals=True,
        ).format()
    )
    assert "controller_trace_canary" not in rendered
    assert "CONTROLLER-RESPONSE-CANARY" not in rendered


class _CapturingCommandChannel:
    def __init__(self) -> None:
        self.view: dict[str, object] = {}

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del maximum_response_bytes
        self.view = json.loads(view)
        return json.dumps(
            {
                "kind": "interaction",
                "interaction_id": "visible_response",
                "direction": "participant_output",
            }
        ).encode()


def _agent_journal(directory: Path) -> tuple[TrialJournal, SessionSpec]:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    session = session_spec()
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="participant-0001",
    )
    header = RunHeader.from_binding(plan.binding)
    journal = TrialJournal.create(directory, header, task)
    journal.append(
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID("00000000-0000-0000-0000-000000000301"),
            timestamp=datetime(2026, 9, 4, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        )
    )
    return journal, session
