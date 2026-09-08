"""Crash-recovery evidence for journaled participant executor requests."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest

from edagym.participant_tool_protocol import (
    CHECKPOINT_PARTICIPANT_TOOL_NAME,
    COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
    CONTROLLER_PARTICIPANT_TOOL_NAMES,
    EXECUTOR_PARTICIPANT_TOOL_NAME,
    WORKSPACE_READ_PARTICIPANT_TOOL_NAME,
    WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
    participant_tool_invocation_id,
)
from edagym.participants.execution import (
    close_interrupted_controller_tools,
    participant_tool_interaction_id,
    recover_interrupted_executor_tools,
)
from edagym.participants.operation_runtime import participant_operation_input_digest
from edagym.resolution import resolve_run
from edagym.run.journal_storage import InvalidTransition
from edagym.run.trial_journal import (
    TrialJournal,
    active_license_leases,
    participant_tool_dispatches,
    participant_tool_usage,
    unresolved_tool_requests,
)
from edagym.run.trial_model import (
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseAcquiredPayload,
    LicenseLeaseLostEvent,
    ParticipantToolLostEvent,
    ParticipantToolLostPayload,
    ParticipantToolReservedEvent,
    ParticipantToolReservedPayload,
    ProducerKind,
    RunEvent,
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
from edagym.specs.environment import (
    ArtifactDisclosure,
    EnvironmentSpec,
    LicenseBinding,
    ManagedEncryption,
)
from edagym.specs.operation import ParticipantOperationBinding
from edagym.specs.session import SessionSpec
from tests.factories import (
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)

_NOW = datetime(2026, 9, 4, tzinfo=UTC)


class _RecoveryExecutor:
    def __init__(self, *, fail: bool = False) -> None:
        self.abandoned: list[str] = []
        self._fail = fail

    def abandon(self, invocation_id: str) -> None:
        self.abandoned.append(invocation_id)
        if self._fail:
            raise RuntimeError("executor isolation cannot be proven empty")


def _journal(
    tmp_path: Path,
    *,
    environment: EnvironmentSpec | None = None,
    session: SessionSpec | None = None,
) -> TrialJournal:
    task = task_spec()
    environment = environment_spec() if environment is None else environment
    if not environment.participant_operations:
        tool = environment.tool_bindings[0]
        environment = EnvironmentSpec.model_validate(
            {
                **environment.model_dump(mode="python"),
                "participant_operations": (
                    ParticipantOperationBinding(
                        operation_id="recovery_operation",
                        capability=tool.capability,
                        tool_id=tool.tool_id,
                    ),
                ),
            }
        )
    session = session_spec() if session is None else session
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="participant_tool_recovery",
    )
    journal = TrialJournal.create(tmp_path, RunHeader.from_binding(plan.binding), task)
    journal.append(
        RunStartedEvent(
            run_id=journal.header.run_id,
            sequence=0,
            event_id=UUID(int=1),
            timestamp=_NOW,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunStartedPayload(binding_digest=journal.header.binding.digest),
        )
    )
    return journal


def _request(
    journal: TrialJournal,
    *,
    interaction_id: str,
    tool_name: str,
    event_id: UUID,
) -> InteractionRecordedEvent:
    return InteractionRecordedEvent(
        run_id=journal.header.run_id,
        sequence=journal.state().next_sequence,
        event_id=event_id,
        timestamp=_NOW,
        producer=ProducerKind.PARTICIPANT,
        actor="solver",
        visibility=Visibility.PARTICIPANT,
        payload=InteractionRecordedPayload(
            direction=InteractionDirection.TOOL_REQUEST,
            interaction_id=interaction_id,
            tool_name=tool_name,
        ),
    )


def _reserve(
    journal: TrialJournal,
    request: InteractionRecordedEvent,
    *,
    tool_id: str | None = None,
    license_binding_id: str | None = None,
    reserved_license_milliseconds: int = 0,
) -> ParticipantToolReservedEvent:
    tool = next(
        item
        for item in journal.header.binding.environment.tools
        if tool_id is None or item.tool_id == tool_id
    )
    resolved_operation = next(
        item
        for item in journal.header.binding.environment.participant_operations
        if item.tool_id == tool.tool_id and item.capability is tool.capability
    )
    operation = ParticipantOperationBinding(
        operation_id=resolved_operation.operation_id,
        capability=resolved_operation.capability,
        tool_id=resolved_operation.tool_id,
    )
    assert operation.digest == resolved_operation.operation_digest
    return ParticipantToolReservedEvent(
        run_id=journal.header.run_id,
        sequence=journal.state().next_sequence,
        event_id=UUID(int=20),
        timestamp=_NOW,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.VERIFIER,
        payload=ParticipantToolReservedPayload(
            request_interaction_id=request.payload.interaction_id,
            invocation_id=participant_tool_invocation_id(
                journal.header.run_id,
                request.payload.interaction_id,
            ),
            invocation_digest="sha256:" + "1" * 64,
            operation_id=resolved_operation.operation_id,
            operation_digest=resolved_operation.operation_digest,
            input_manifest_digest=participant_operation_input_digest(
                journal.directory,
                operation,
                maximum_bytes=1,
            ),
            tool_id=tool.tool_id,
            capability=tool.capability,
            executor_id=journal.header.binding.environment.executor_id,
            license_binding_id=license_binding_id,
            budget_digest=journal.header.binding.session.budget_digest,
            reserved_compute_milliseconds=1_000,
            reserved_license_milliseconds=reserved_license_milliseconds,
        ),
    )


def _licensed_interrupted_dispatch(
    tmp_path: Path,
) -> tuple[
    TrialJournal,
    InteractionRecordedEvent,
    ParticipantToolReservedEvent,
    LicenseLeaseAcquiredEvent,
]:
    base_environment = environment_spec()
    license_binding = LicenseBinding(
        license_binding_id="participant_tool_license",
        provider_id="license_provider",
        provider_digest="sha256:" + "2" * 64,
        feature_class="rtl_simulation",
        lease_ttl_seconds=30,
    )
    licensed_tool = base_environment.tool_bindings[0].model_copy(
        update={"license_binding_id": license_binding.license_binding_id}
    )
    protected = ArtifactDisclosure(
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    artifact_policy = base_environment.artifact_policy.model_copy(
        update={
            "encryption": ManagedEncryption(
                provider_id="participant_tool_test_encryption",
                policy_digest="sha256:" + "3" * 64,
            ),
            "rules": tuple(
                rule.model_copy(update={"allowed_disclosures": (protected,)})
                if rule.artifact_class
                in {ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE}
                else rule
                for rule in base_environment.artifact_policy.rules
            ),
        }
    )
    environment = EnvironmentSpec.model_validate(
        {
            **base_environment.model_dump(mode="python"),
            "tool_bindings": (licensed_tool, *base_environment.tool_bindings[1:]),
            "licenses": (license_binding,),
            "artifact_policy": artifact_policy,
        }
    )
    base_session = session_spec()
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "resources": base_session.resources.model_copy(
                update={"max_license_seconds": 30}
            ),
        }
    )
    journal = _journal(tmp_path, environment=environment, session=session)
    request = _request(
        journal,
        interaction_id="licensed_executor_request",
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
        event_id=UUID(int=2),
    )
    journal.append(request)
    reservation = _reserve(
        journal,
        request,
        tool_id=licensed_tool.tool_id,
        license_binding_id=license_binding.license_binding_id,
        reserved_license_milliseconds=500,
    )
    journal.append(reservation)
    acquisition = LicenseLeaseAcquiredEvent(
        run_id=journal.header.run_id,
        sequence=journal.state().next_sequence,
        event_id=UUID(int=22),
        timestamp=_NOW,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.VERIFIER,
        payload=LicenseLeaseAcquiredPayload(
            job_id=reservation.payload.invocation_id,
            license_binding_id=license_binding.license_binding_id,
            provider_id=license_binding.provider_id,
            feature_class=license_binding.feature_class,
        ),
    )
    journal.append(acquisition)
    return journal, request, reservation, acquisition


def test_recovery_abandons_only_executor_requests_and_closes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = _journal(tmp_path)
    checkpoint_request = _request(
        journal,
        interaction_id="checkpoint_request",
        tool_name=CHECKPOINT_PARTICIPANT_TOOL_NAME,
        event_id=UUID(int=2),
    )
    journal.append(checkpoint_request)
    executor_request = _request(
        journal,
        interaction_id="executor_request",
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
        event_id=UUID(int=3),
    )
    journal.append(executor_request)

    original_append = journal.append
    original_append_events = journal.append_events
    inserted_race = False

    def append_after_competing_event(events: Sequence[RunEvent]) -> object:
        nonlocal inserted_race
        if not inserted_race:
            inserted_race = True
            original_append(
                InteractionRecordedEvent(
                    run_id=journal.header.run_id,
                    sequence=journal.state().next_sequence,
                    event_id=UUID(int=4),
                    timestamp=_NOW,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.PARTICIPANT,
                    payload=InteractionRecordedPayload(
                        direction=InteractionDirection.PARTICIPANT_INPUT,
                        interaction_id="recovery_race",
                    ),
                )
            )
        return original_append_events(events)

    monkeypatch.setattr(journal, "append_events", append_after_competing_event)
    executor = _RecoveryExecutor()
    event_ids = iter((UUID(int=5), UUID(int=6)))
    recovered = recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: next(event_ids),
    )

    expected_invocation_id = participant_tool_invocation_id(
        journal.header.run_id,
        executor_request.payload.interaction_id,
    )
    assert executor.abandoned == [expected_invocation_id]
    results = tuple(
        event
        for event in journal.read_events()
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
    )
    assert len(results) == 1
    result = results[0]
    assert result.producer is ProducerKind.CONTROLLER
    assert result.visibility is Visibility.PARTICIPANT
    assert result.artifact_refs == ()
    assert result.payload.related_interaction_id == executor_request.payload.interaction_id
    assert result.payload.tool_name == EXECUTOR_PARTICIPANT_TOOL_NAME
    assert result.payload.interaction_id == participant_tool_interaction_id(
        executor_request.payload.interaction_id,
        EXECUTOR_PARTICIPANT_TOOL_NAME,
        "result",
    )
    assert unresolved_tool_requests(journal.read_events()) == (checkpoint_request,)

    sequence = recovered.next_sequence
    repeated = recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: UUID(int=7),
    )
    assert repeated.next_sequence == sequence
    assert executor.abandoned == [expected_invocation_id]

    with pytest.raises(InvalidTransition, match="already has a result"):
        original_append(
            result.model_copy(
                update={
                    "sequence": sequence,
                    "event_id": UUID(int=8),
                    "payload": result.payload.model_copy(
                        update={"interaction_id": "duplicate_executor_result"}
                    ),
                }
            )
        )


def test_recovery_does_not_close_request_when_abandon_fails(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    request = _request(
        journal,
        interaction_id="executor_request",
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
        event_id=UUID(int=2),
    )
    journal.append(request)
    reservation = _reserve(journal, request)
    journal.append(reservation)
    executor = _RecoveryExecutor(fail=True)

    with pytest.raises(RuntimeError, match="cannot be proven empty"):
        recover_interrupted_executor_tools(
            journal=journal,
            fence=executor.abandon,
            timestamp=_NOW,
            event_id_factory=lambda: UUID(int=3),
        )

    assert unresolved_tool_requests(journal.read_events()) == (request,)
    dispatch = participant_tool_dispatches(journal.read_events())[
        request.payload.interaction_id
    ]
    assert dispatch.reservation == reservation
    assert dispatch.terminal is None


def test_reserved_executor_recovery_records_lost_and_result_atomically(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    request = _request(
        journal,
        interaction_id="reserved_executor_request",
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
        event_id=UUID(int=2),
    )
    journal.append(request)
    reservation = _reserve(journal, request)
    journal.append(reservation)
    executor = _RecoveryExecutor()
    event_ids = iter((UUID(int=3), UUID(int=4)))

    recovered = recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: next(event_ids),
    )

    events = journal.read_events()
    dispatch = participant_tool_dispatches(events)[request.payload.interaction_id]
    assert executor.abandoned == [reservation.payload.invocation_id]
    assert isinstance(dispatch.terminal, ParticipantToolLostEvent)
    assert dispatch.terminal.payload.request_interaction_id == request.payload.interaction_id
    assert dispatch.terminal.payload.invocation_id == reservation.payload.invocation_id
    assert dispatch.terminal.payload.invocation_digest == reservation.payload.invocation_digest
    result = cast(InteractionRecordedEvent, events[-1])
    assert result.payload.related_interaction_id == request.payload.interaction_id
    assert journal.events_committed_together((dispatch.terminal.event_id, result.event_id))
    usage = participant_tool_usage(events)
    assert usage.eda_compute_milliseconds == reservation.payload.reserved_compute_milliseconds
    assert usage.license_milliseconds == 0
    assert recovered.next_sequence == len(events)

    repeated = recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: UUID(int=5),
    )
    assert repeated.next_sequence == recovered.next_sequence
    assert executor.abandoned == [reservation.payload.invocation_id]


def test_terminal_executor_dispatch_recovery_only_closes_request(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    request = _request(
        journal,
        interaction_id="lost_executor_request",
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
        event_id=UUID(int=2),
    )
    journal.append(request)
    reservation = _reserve(journal, request)
    journal.append(reservation)
    lost = ParticipantToolLostEvent(
        run_id=journal.header.run_id,
        sequence=journal.state().next_sequence,
        event_id=UUID(int=21),
        timestamp=_NOW,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.VERIFIER,
        payload=ParticipantToolLostPayload(
            request_interaction_id=reservation.payload.request_interaction_id,
            invocation_id=reservation.payload.invocation_id,
            invocation_digest=reservation.payload.invocation_digest,
        ),
    )
    journal.append(lost)
    executor = _RecoveryExecutor(fail=True)

    recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: UUID(int=3),
    )

    assert executor.abandoned == []
    dispatch = participant_tool_dispatches(journal.read_events())[
        request.payload.interaction_id
    ]
    assert dispatch.terminal == lost
    results = tuple(
        event
        for event in journal.read_events()
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
    )
    assert len(results) == 1
    assert results[0].payload.related_interaction_id == request.payload.interaction_id


def test_licensed_dispatch_recovery_loses_custody_and_charges_reservation_once(
    tmp_path: Path,
) -> None:
    journal, request, reservation, acquisition = _licensed_interrupted_dispatch(tmp_path)
    executor = _RecoveryExecutor()
    event_ids = iter((UUID(int=30), UUID(int=31), UUID(int=32)))

    recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: next(event_ids),
    )

    events = journal.read_events()
    lease_loss, tool_loss, result = events[-3:]
    assert isinstance(lease_loss, LicenseLeaseLostEvent)
    assert lease_loss.payload.model_dump(mode="python") == acquisition.payload.model_dump(
        mode="python"
    )
    assert isinstance(tool_loss, ParticipantToolLostEvent)
    assert isinstance(result, InteractionRecordedEvent)
    assert result.payload.related_interaction_id == request.payload.interaction_id
    assert journal.events_committed_together(
        (lease_loss.event_id, tool_loss.event_id, result.event_id)
    )
    assert active_license_leases(events) == {}
    usage = participant_tool_usage(events)
    assert usage.eda_compute_milliseconds == reservation.payload.reserved_compute_milliseconds
    assert usage.license_milliseconds == reservation.payload.reserved_license_milliseconds
    assert executor.abandoned == [reservation.payload.invocation_id]

    recover_interrupted_executor_tools(
        journal=journal,
        fence=executor.abandon,
        timestamp=_NOW,
        event_id_factory=lambda: UUID(int=33),
    )
    assert participant_tool_usage(journal.read_events()) == usage
    assert executor.abandoned == [reservation.payload.invocation_id]


def test_failed_licensed_abandon_appends_no_recovery_facts(tmp_path: Path) -> None:
    journal, request, reservation, acquisition = _licensed_interrupted_dispatch(tmp_path)
    before = journal.read_events()
    executor = _RecoveryExecutor(fail=True)

    with pytest.raises(RuntimeError, match="cannot be proven empty"):
        recover_interrupted_executor_tools(
            journal=journal,
            fence=executor.abandon,
            timestamp=_NOW,
            event_id_factory=lambda: UUID(int=30),
        )

    assert journal.read_events() == before
    assert unresolved_tool_requests(before) == (request,)
    assert participant_tool_dispatches(before)[request.payload.interaction_id].terminal is None
    assert active_license_leases(before) == {
        reservation.payload.invocation_id: acquisition
    }


def test_explicit_controller_recovery_closes_only_canonical_builtins(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    builtins: list[InteractionRecordedEvent] = []
    for index, tool_name in enumerate(
        (
            WORKSPACE_READ_PARTICIPANT_TOOL_NAME,
            WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
            CHECKPOINT_PARTICIPANT_TOOL_NAME,
            COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
        )
    ):
        request = _request(
            journal,
            interaction_id=f"controller_request_{index}",
            tool_name=tool_name,
            event_id=UUID(int=index + 2),
        )
        journal.append(request)
        builtins.append(request)
    extension_request = _request(
        journal,
        interaction_id="extension_request",
        tool_name="extension_observe",
        event_id=UUID(int=6),
    )
    journal.append(extension_request)

    event_ids = iter((UUID(int=7), UUID(int=8), UUID(int=9), UUID(int=10)))
    recovered = close_interrupted_controller_tools(
        journal=journal,
        timestamp=_NOW,
        event_id_factory=lambda: next(event_ids),
    )

    assert frozenset(
        {
            WORKSPACE_READ_PARTICIPANT_TOOL_NAME,
            WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
            CHECKPOINT_PARTICIPANT_TOOL_NAME,
            COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
        }
    ) == CONTROLLER_PARTICIPANT_TOOL_NAMES
    assert unresolved_tool_requests(journal.read_events()) == (extension_request,)
    results = tuple(
        event
        for event in journal.read_events()
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
    )
    assert tuple(result.payload.related_interaction_id for result in results) == tuple(
        request.payload.interaction_id for request in builtins
    )
    for request, result in zip(builtins, results, strict=True):
        tool_name = cast(str, request.payload.tool_name)
        assert result.payload.tool_name == tool_name
        assert result.payload.interaction_id == participant_tool_interaction_id(
            request.payload.interaction_id,
            tool_name,
            "result",
        )
        assert result.producer is ProducerKind.CONTROLLER
        assert result.visibility is Visibility.PARTICIPANT
        assert result.artifact_refs == ()

    sequence = recovered.next_sequence
    repeated = close_interrupted_controller_tools(
        journal=journal,
        timestamp=_NOW,
        event_id_factory=lambda: UUID(int=11),
    )
    assert repeated.next_sequence == sequence
