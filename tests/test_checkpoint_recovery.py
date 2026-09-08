from __future__ import annotations

import json
import multiprocessing
import os
import signal
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

from edagym.drivers.catalog import BACKENDS
from edagym.drivers.probe import probe_backend
from edagym.drivers.rootless_image import (
    RootlessImageConfiguration,
    RootlessImageExecutionRecipe,
)
from edagym.evaluation import StageResult
from edagym.evaluation.model import OutcomeKind
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.capabilities import (
    ProviderAvailability,
    RootlessContainerCapability,
    probe_rootless_container,
)
from edagym.executors.local import ExecutorUnavailable
from edagym.executors.model import (
    COMPOSITE_REPORT_LOGICAL_ID,
    COMPOSITE_REPORT_PATH,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    OutputDeclaration,
    ToolRecipeCommand,
    WorkspaceRecipeCommand,
)
from edagym.executors.protocol import acquire_executor_storage
from edagym.executors.rootless import RootlessContainerExecutor
from edagym.executors.rootless_storage import RootlessStorageProvider
from edagym.participant_tool_protocol import (
    EXECUTOR_PARTICIPANT_TOOL_NAME,
    participant_tool_invocation_id,
)
from edagym.participants.adapters import CommandAgentAdapter
from edagym.participants.controller import ParticipantController
from edagym.participants.execution import participant_tool_interaction_id
from edagym.participants.operation_runtime import (
    materialize_participant_operation_inputs,
    participant_operation_input_digest,
)
from edagym.run.artifacts import ArtifactManifest, ContentAddressedStore
from edagym.run.journal import (
    InvalidTransition,
    RunJournal,
    participant_incarnation_lifecycle,
    participant_tool_dispatches,
    participant_tool_usage,
    unresolved_tool_requests,
)
from edagym.run.model import (
    EvaluationCompletedEvent,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseAcquiredPayload,
    LicenseLeaseLostEvent,
    LicenseLeaseReleasedEvent,
    ParticipantToolLostEvent,
    ParticipantToolReservedEvent,
    ParticipantToolReservedPayload,
    ProducerKind,
    RunEndedEvent,
    RunEndedPayload,
    StopReason,
)
from edagym.runtime import EvaluationContext, OrchestrationError, RunOrchestrator
from edagym.runtime.budget import budget_usage
from edagym.runtime.model import EvaluationArtifacts
from edagym.specs.common import ArtifactClass, Capability, Visibility
from edagym.specs.environment import (
    ApplicationCheckpointBinding,
    CheckpointCapability,
    ContainerRuntime,
    EnvironmentSpec,
    FilesystemScope,
    ImageToolLocator,
    RootlessLocalExecutor,
    ToolBinding,
)
from edagym.specs.operation import (
    CandidateInputOperationArgument,
    FixedOperationArgument,
    ParticipantOperationBinding,
)

from .factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)
from .test_executor_boundaries import (
    _OPEN_EDA_DIGEST,
    _OPEN_EDA_MANIFEST_DIGEST,
    _OPEN_EDA_REFERENCE,
    _rootless_runtime,
)
from .test_runtime_orchestration import (
    _evaluators,
    _FixtureEvaluator,
    _FixtureExecutor,
    _licensed_environment,
    _licensed_session,
    _licensed_store,
    _private_directory,
    _SingleSubmission,
)

if TYPE_CHECKING:
    from edagym.drivers.probe import ResolvedInstallation

_NOW = datetime(2026, 9, 4, tzinfo=UTC)
_RECOVERY_NOW = _NOW + timedelta(seconds=3)
_HEARTBEAT_SCRIPT = "heartbeat.tcl"
_YOSYS_SCRIPT_FLAGS = ("-Q", "-T", "-q", "-c")
_HEARTBEAT_ARGUMENTS = (*_YOSYS_SCRIPT_FLAGS, _HEARTBEAT_SCRIPT)
_HEARTBEAT_TCL = (
    "for {set tick 0} {$tick < 1200} {incr tick} {\n"
    "  set output [open heartbeat.next w]\n"
    "  puts $output $tick\n"
    "  close $output\n"
    "  file rename -force heartbeat.next heartbeat\n"
    "  after 100\n"
    "}\n"
)


def _write_heartbeat_script(workspace: Path, script: str = _HEARTBEAT_SCRIPT) -> Path:
    """Place the long-running yosys Tcl heartbeat and return the file it maintains."""

    path = workspace / script
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(_HEARTBEAT_TCL, encoding="ascii")
    path.chmod(0o600)
    return workspace / "heartbeat"


def _participant_release_path() -> str:
    """The one release path a participant operation may take as candidate input."""

    return next(
        item.path
        for item in task_instance(task_spec()).generated_files
        if item.visibility is Visibility.PARTICIPANT
    )


def _await_heartbeat(heartbeat: Path, *, failure: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not heartbeat.exists():
        time.sleep(0.05)
    if not heartbeat.exists():
        raise RuntimeError(failure)


def _require_rootless_recovery_runtime() -> None:
    try:
        _rootless_recovery_installations()
    except ExecutorUnavailable as error:
        pytest.skip(str(error))


def _rootless_recovery_installations(
) -> tuple[RootlessContainerCapability, dict[str, ResolvedInstallation]]:
    capability = probe_rootless_container(
        image_references={_OPEN_EDA_DIGEST: _OPEN_EDA_REFERENCE}
    )
    if capability.availability is not ProviderAvailability.AVAILABLE:
        raise ExecutorUnavailable("the pinned rootless recovery image is unavailable")
    installations: dict[str, ResolvedInstallation] = {}
    for tool_id in ("verilator", "yosys"):
        definition = next(item for item in BACKENDS if item.tool_id == tool_id)
        probe, installation = probe_backend(
            definition,
            rootless_image_configuration=RootlessImageConfiguration(
                recipe=RootlessImageExecutionRecipe(
                    image_digest=_OPEN_EDA_DIGEST,
                    tool_entrypoint=f"/usr/bin/{tool_id}",
                    package_manifest_path="/usr/share/edagym/dpkg-manifest.tsv",
                    package_manifest_digest=_OPEN_EDA_MANIFEST_DIGEST,
                    package_manifest_checksum_path=(
                        "/usr/share/edagym/dpkg-manifest.sha256"
                    ),
                ),
                engine_path=Path("/usr/bin/podman"),
                image_reference=_OPEN_EDA_REFERENCE,
            ),
        )
        if installation is None:
            raise ExecutorUnavailable(
                f"rootless recovery backend {tool_id} is unavailable: {probe.reason}"
            )
        installations[tool_id] = installation
    return capability, installations


def _rootless_recovery_executor(
    root: Path,
    environment: EnvironmentSpec,
    store: ContentAddressedStore,
    *,
    executor_type: type[RootlessContainerExecutor] = RootlessContainerExecutor,
) -> RootlessContainerExecutor:
    capability, installations = _rootless_recovery_installations()
    return executor_type(
        executor_id=environment.executor.executor_id,
        implementation_digest=environment.executor.implementation_digest,
        capability=capability,
        tool_installations=installations,
        storage_provider=RootlessStorageProvider(
            maximum_quota_bytes=1024 * 1024 * 1024
        ),
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=root / "executor-state",
    )


def _interrupted_artifact_writer(root_text: str, ready: Connection) -> None:
    root = Path(root_text)
    policy = environment_spec().artifact_policy
    store = ContentAddressedStore(root, policy=policy)

    disclosure = policy.persistent_disclosure(ArtifactClass.EVIDENCE)
    assert disclosure is not None

    def chunks() -> Iterator[bytes]:
        yield b"a" * (1024 * 1024)
        ready.send(True)
        time.sleep(120)
        yield b"b" * (1024 * 1024)

    store.put_chunks(
        chunks(),
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )


def test_cas_discards_an_interrupted_upload_after_writer_sigkill(tmp_path: Path) -> None:
    store_root = tmp_path / "interrupted-store"
    context = multiprocessing.get_context("spawn")
    received, ready = context.Pipe(duplex=False)
    writer = context.Process(
        target=_interrupted_artifact_writer,
        args=(store_root.as_posix(), ready),
    )
    writer.start()
    ready.close()
    try:
        assert received.poll(30), "artifact writer did not enter its durable write"
        assert received.recv() is True
        writer.kill()
        writer.join(10)
        assert writer.exitcode == -signal.SIGKILL
    finally:
        if writer.is_alive():
            writer.kill()
            writer.join(10)
        received.close()
        writer.close()

    store = ContentAddressedStore(store_root, policy=environment_spec().artifact_policy)
    assert store.stored_bytes() == 0
    assert not tuple(store_root.glob("incoming-*"))


def _container_controller(root_text: str, ready: Connection) -> None:
    root = Path(root_text)
    environment, installation, _ = _rootless_runtime()
    binding = environment.tool_bindings[0]
    store = ContentAddressedStore(root / "store", policy=environment.artifact_policy)
    executor = _rootless_recovery_executor(root, environment, store)
    invocation_id = "interrupted_container"
    lease = executor.create_storage(
        environment=environment,
        runtime_root=_private_directory(root / "executor-storage"),
        run_id=digest("interrupted-container-run"),
        invocation_id=invocation_id,
    )
    heartbeat = _write_heartbeat_script(lease.workspace)
    executor.launch(
        InvocationPlan(
            invocation_id=invocation_id,
            run_id=lease.receipt.run_id,
            capability=binding.capability,
            tool_id=binding.tool_id,
            driver_digest=installation.definition.driver_digest,
            view=InvocationView.PARTICIPANT,
            executable=binding.locator.executable,
            arguments=_HEARTBEAT_ARGUMENTS,
            input_manifest_digest=digest("interrupted-container-input"),
        ),
        environment=environment,
        workspace=lease.workspace,
        artifact_directory=lease.artifact_directory,
        asset_paths={},
        scope=FilesystemScope.PARTICIPANT,
    )
    _await_heartbeat(heartbeat, failure="container did not enter its writable workspace")
    ready.send(invocation_id)
    signal.pause()


@pytest.mark.skipif(not Path("/usr/bin/podman").exists(), reason="Podman is unavailable")
def test_rootless_container_is_removed_after_controller_sigkill(tmp_path: Path) -> None:
    environment, _, _ = _rootless_runtime()
    root = _private_directory(tmp_path / "container-recovery")
    context = multiprocessing.get_context("spawn")
    received, ready = context.Pipe(duplex=False)
    controller = context.Process(
        target=_container_controller,
        args=(root.as_posix(), ready),
    )
    controller.start()
    ready.close()
    try:
        assert received.poll(30), "container controller did not launch its invocation"
        invocation_id = received.recv()
        controller.kill()
        controller.join(10)
        assert controller.exitcode == -signal.SIGKILL
    finally:
        if controller.is_alive():
            controller.kill()
            controller.join(10)
        received.close()
        controller.close()

    store = ContentAddressedStore(root / "store", policy=environment.artifact_policy)
    executor = _rootless_recovery_executor(root, environment, store)
    lease = executor.recover_storage(
        environment=environment,
        runtime_root=root / "executor-storage",
        run_id=digest("interrupted-container-run"),
        invocation_id=invocation_id,
    )
    assert lease is not None
    try:
        cleanup = executor.cleanup(invocation_id)
        assert not cleanup.remaining_resources
        heartbeat = lease.workspace / "heartbeat"
        stopped_value = heartbeat.read_text(encoding="ascii")
        time.sleep(0.3)
        assert heartbeat.read_text(encoding="ascii") == stopped_value
    finally:
        executor.abandon(invocation_id)
        lease.close()


def _participant_tool_controller(root_text: str, ready: Connection) -> None:
    root = Path(root_text)
    task = task_spec()
    environment = _checkpoint_environment(
        CheckpointCapability.FILESYSTEM,
        participant_operation=True,
    )
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=environment.artifact_policy,
    )
    workspace = _private_directory(root / "workspace")
    executor = _rootless_recovery_executor(root, environment, store)
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="interrupted_participant_tool",
        state_root=root / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(root / "executor-artifacts"),
        artifact_store=store,
        executor=executor,
        evaluators=_recovery_evaluators(environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    request_interaction_id = participant_tool_interaction_id(
        "provider_request",
        EXECUTOR_PARTICIPANT_TOOL_NAME,
        "request",
    )
    runtime.journal.transact(
        lambda state: InteractionRecordedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW,
            producer=ProducerKind.PARTICIPANT,
            actor=state.current_writer,
            visibility=Visibility.PARTICIPANT,
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.TOOL_REQUEST,
                interaction_id=request_interaction_id,
                tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
            ),
        )
    )
    operation = environment.participant_operations[0]
    binding = next(
        item
        for item in environment.tool_bindings
        if (item.capability, item.tool_id) == (operation.capability, operation.tool_id)
    )
    invocation_id = participant_tool_invocation_id(
        runtime.journal.header.run_id,
        request_interaction_id,
    )
    _write_heartbeat_script(workspace, operation.candidate_input_paths[0])
    input_manifest_digest = participant_operation_input_digest(
        workspace,
        operation,
        maximum_bytes=environment.resources.disk_bytes,
    )
    plan = InvocationPlan(
        invocation_id=invocation_id,
        run_id=runtime.journal.header.run_id,
        capability=binding.capability,
        tool_id=binding.tool_id,
        driver_digest=binding.driver_digest,
        view=InvocationView.TOOL,
        executable=binding.locator.executable,
        arguments=operation.argv,
        input_manifest_digest=input_manifest_digest,
    )
    runtime.journal.transact(
        lambda state: ParticipantToolReservedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.VERIFIER,
            payload=ParticipantToolReservedPayload(
                request_interaction_id=request_interaction_id,
                invocation_id=invocation_id,
                invocation_digest=plan.digest,
                operation_id=operation.operation_id,
                operation_digest=operation.digest,
                input_manifest_digest=input_manifest_digest,
                tool_id=binding.tool_id,
                capability=binding.capability,
                executor_id=environment.executor.executor_id,
                license_binding_id=binding.license_binding_id,
                budget_digest=runtime.journal.header.binding.session.budget_digest,
                reserved_compute_milliseconds=10_000,
                reserved_license_milliseconds=0,
            ),
        )
    )
    storage = acquire_executor_storage(
        executor,
        environment=environment,
        runtime_root=runtime.journal.directory / "executor-storage",
        run_id=runtime.journal.header.run_id,
        invocation_id=invocation_id,
    )
    projected_input_digest = materialize_participant_operation_inputs(
        workspace,
        storage.workspace,
        operation,
        maximum_bytes=environment.resources.disk_bytes,
    )
    if projected_input_digest != input_manifest_digest:
        raise RuntimeError("participant operation input changed before isolation")
    executor.launch(
        plan,
        environment=environment,
        workspace=storage.workspace,
        artifact_directory=storage.artifact_directory,
        asset_paths={},
        scope=FilesystemScope.TOOL,
    )
    heartbeat = storage.workspace / "heartbeat"
    _await_heartbeat(heartbeat, failure="participant tool did not enter its isolation scope")
    ready.send(
        {
            "controller_pid": os.getpid(),
            "heartbeat": heartbeat.as_posix(),
            "interaction_id": request_interaction_id,
            "invocation_digest": plan.digest,
        }
    )
    signal.pause()


def test_participant_executor_tool_recovers_after_controller_sigkill(
    tmp_path: Path,
) -> None:
    _require_rootless_recovery_runtime()
    root = _private_directory(tmp_path / "participant-tool-recovery")
    context = multiprocessing.get_context("spawn")
    received, ready = context.Pipe(duplex=False)
    controller = context.Process(
        target=_participant_tool_controller,
        args=(root.as_posix(), ready),
    )
    controller.start()
    ready.close()
    try:
        assert received.poll(60), "participant tool controller did not publish its state"
        interrupted: dict[str, Any] = received.recv()
        controller.kill()
        controller.join(10)
        assert controller.exitcode == -signal.SIGKILL
    finally:
        if controller.is_alive():
            controller.kill()
            controller.join(10)
        received.close()
        controller.close()

    heartbeat = Path(interrupted["heartbeat"])
    surviving_value = heartbeat.read_text(encoding="ascii")
    time.sleep(0.3)
    assert heartbeat.read_text(encoding="ascii") != surviving_value

    task = task_spec()
    environment = _checkpoint_environment(
        CheckpointCapability.FILESYSTEM,
        participant_operation=True,
    )
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(root / "store", policy=environment.artifact_policy)
    assert os.getpid() != interrupted["controller_pid"]
    reopened = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="interrupted_participant_tool",
        state_root=root / "runs",
        workspace=_private_directory(root / "recovered-workspace"),
        artifact_directory=_private_directory(root / "recovered-executor-artifacts"),
        artifact_store=store,
        executor=_rootless_recovery_executor(root, environment, store),
        evaluators=_recovery_evaluators(environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _RECOVERY_NOW,
        poll_interval_seconds=0,
    )
    events_before = reopened.journal.read_events()
    pending = unresolved_tool_requests(
        events_before,
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
    )
    assert [event.payload.interaction_id for event in pending] == [interrupted["interaction_id"]]

    reopened.recover_interrupted()

    events_after = reopened.journal.read_events()
    assert not unresolved_tool_requests(
        events_after,
        tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
    )
    results = tuple(
        event
        for event in events_after
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
        and event.payload.related_interaction_id == interrupted["interaction_id"]
    )
    assert len(results) == 1
    assert not results[0].artifact_refs
    dispatch = participant_tool_dispatches(events_after)[interrupted["interaction_id"]]
    assert isinstance(dispatch.terminal, ParticipantToolLostEvent)
    assert dispatch.reservation.payload.invocation_digest == interrupted["invocation_digest"]
    assert dispatch.reservation.payload.operation_id == "hold_for_recovery"
    recovery_events = events_after[-2:]
    assert recovery_events[0] == dispatch.terminal
    assert recovery_events[1] == results[0]
    assert reopened.journal.events_committed_together(
        tuple(event.event_id for event in recovery_events)
    )
    usage = participant_tool_usage(events_after)
    assert usage.eda_compute_milliseconds == 10_000
    assert usage.license_milliseconds == 0
    recovered_usage = budget_usage(
        journal=reopened.journal,
        task=task,
        artifact_store=store,
        now=_RECOVERY_NOW,
    )
    assert recovered_usage.eda_compute_seconds == 10
    assert recovered_usage.license_seconds == 0
    assert not heartbeat.exists()
    recovered_digest = reopened.journal.integrity_digest()
    reopened.recover_interrupted()
    assert reopened.journal.integrity_digest() == recovered_digest


class _LockProbeChannel:
    def __init__(
        self,
        ready: Connection,
        *,
        interaction_id: str,
        block: bool,
    ) -> None:
        self._ready = ready
        self._interaction_id = interaction_id
        self._block = block

    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view, maximum_response_bytes
        self._ready.send(True)
        if self._block:
            signal.pause()
        return json.dumps(
            {
                "artifact_refs": [],
                "direction": "participant_output",
                "interaction_id": self._interaction_id,
                "kind": "interaction",
            }
        ).encode("ascii")


def _participant_controller_contender(
    run_directory_text: str,
    ready: Connection,
    interaction_id: str,
    block: bool,
) -> None:
    journal = RunJournal.open(Path(run_directory_text), task_spec())
    controller = ParticipantController(
        journal,
        CommandAgentAdapter(
            actor_id="solver",
            channel=_LockProbeChannel(
                ready,
                interaction_id=interaction_id,
                block=block,
            ),
        ),
        session=session_spec(),
        snapshot_candidate=lambda intent: (_ for _ in ()).throw(
            AssertionError(intent.candidate_id)
        ),
    )
    controller.act_once()


def test_participant_dispatch_lock_fences_takeover_until_controller_sigkill(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = environment_spec()
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(tmp_path / "store"),
        policy=environment.artifact_policy,
    )
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="participant_controller_fencing",
        state_root=tmp_path / "runs",
        workspace=_private_directory(tmp_path / "workspace"),
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=_FixtureExecutor(environment, store),
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    context = multiprocessing.get_context("spawn")
    first_received, first_ready = context.Pipe(duplex=False)
    second_received, second_ready = context.Pipe(duplex=False)
    first = context.Process(
        target=_participant_controller_contender,
        args=(runtime.journal.directory.as_posix(), first_ready, "stale_action", True),
    )
    second = context.Process(
        target=_participant_controller_contender,
        args=(runtime.journal.directory.as_posix(), second_ready, "takeover_action", False),
    )
    first.start()
    first_ready.close()
    try:
        assert first_received.poll(10), "first participant controller did not acquire its lock"
        assert first_received.recv() is True
        second.start()
        second_ready.close()
        assert not second_received.poll(0.3)
        assert second.is_alive()
        first.kill()
        first.join(10)
        assert first.exitcode == -signal.SIGKILL
        assert second_received.poll(10), "takeover did not acquire the released controller lock"
        assert second_received.recv() is True
        second.join(10)
        assert second.exitcode == 0
    finally:
        for process in (first, second):
            if process.is_alive():
                process.kill()
                process.join(10)
            process.close()
        first_received.close()
        second_received.close()

    interactions = tuple(
        event
        for event in runtime.journal.read_events()
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.PARTICIPANT_OUTPUT
    )
    assert [event.payload.interaction_id for event in interactions] == ["takeover_action"]


def test_run_cannot_end_with_an_unresolved_participant_tool(tmp_path: Path) -> None:
    task = task_spec()
    environment = environment_spec()
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(tmp_path / "store"),
        policy=environment.artifact_policy,
    )
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="unresolved_tool_terminal_guard",
        state_root=tmp_path / "runs",
        workspace=_private_directory(tmp_path / "workspace"),
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=_FixtureExecutor(environment, store),
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    runtime.journal.transact(
        lambda state: InteractionRecordedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW,
            producer=ProducerKind.PARTICIPANT,
            actor=state.current_writer,
            visibility=Visibility.PARTICIPANT,
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.TOOL_REQUEST,
                interaction_id="unfinished_tool_request",
                tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
            ),
        )
    )

    with pytest.raises(InvalidTransition, match="unresolved participant tools"):
        runtime.journal.transact(
            lambda state: RunEndedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=uuid4(),
                timestamp=_NOW,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.PUBLIC,
                payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
            )
        )

    assert runtime.state.terminal_reason is None


class _RecoveryEvaluator(_FixtureEvaluator):
    def prepare(self, context: EvaluationContext) -> InvocationPlan:
        plan = super().prepare(context)
        if context.stage.stage_id == "functional":
            program = "printf '%s\\n' '{\"accepted\":true}' > functional.report"
        elif context.candidate.candidate_id == "candidate_a":
            program = (
                "sleep 120 & child=$!; n=1; printf '%s' \"$n\" > qor.heartbeat.next; "
                "mv qor.heartbeat.next qor.heartbeat; "
                "printf '%s' \"$child\" > qor.started; "
                'while kill -0 "$child" 2>/dev/null; do '
                "n=$((n + 1)); printf '%s' \"$n\" > qor.heartbeat.next; "
                "mv qor.heartbeat.next qor.heartbeat; sleep 0.1; done; "
                "wait \"$child\"; printf '%s\\n' '{\"accepted\":true}' > qor.report"
            )
        else:
            program = "printf '%s\\n' '{\"accepted\":true}' > qor.report"
        driver = context.environment.tool_bindings
        binding = next(item for item in driver if item.capability is plan.capability)
        checker = context.workspace / "recovery-check.sh"
        checker.write_text("#!/bin/sh\nset -eu\n" + program + "\n", encoding="ascii")
        checker.chmod(0o700)
        tool_arguments = (
            ("--lint-only", "design.sv")
            if context.stage.stage_id == "functional"
            else ("-Q", "-T", "-q", "-p", "read_verilog -sv design.sv; synth")
        )
        return InvocationPlan.model_validate(
            {
                **plan.model_dump(mode="python"),
                "recipe": (
                    ToolRecipeCommand(
                        tool_id=binding.tool_id,
                        capability=binding.capability,
                        driver_digest=binding.driver_digest,
                        executable=binding.locator.executable,
                        arguments=tool_arguments,
                    ),
                    WorkspaceRecipeCommand(executable=checker.name),
                ),
                "outputs": (
                    *plan.outputs,
                    OutputDeclaration(
                        logical_id=COMPOSITE_REPORT_LOGICAL_ID,
                        path=COMPOSITE_REPORT_PATH,
                        media_type="application/json",
                        artifact_class=ArtifactClass.EVIDENCE,
                    ),
                ),
            }
        )

    def evaluate(
        self,
        context: EvaluationContext,
        execution: ExecutionResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult:
        stage_artifacts = EvaluationArtifacts(
            tuple(
                item
                for name, item in artifacts.items()
                if name != COMPOSITE_REPORT_LOGICAL_ID
            )
        )
        return super().evaluate(context, execution, stage_artifacts)


def _recovery_evaluators(
    environment: EnvironmentSpec,
) -> tuple[_RecoveryEvaluator, ...]:
    task = task_spec()
    tools = {item.capability: item for item in environment.tool_bindings}
    return tuple(
        _RecoveryEvaluator(
            evaluator_id=item.evaluator_id,
            evaluator_revision_digest=item.revision_digest,
            driver_digest=tools[item.capability].driver_digest,
            executable=tools[item.capability].locator.executable,
        )
        for item in task.evaluation.evaluators
    )


def _checkpoint_environment(
    capability: CheckpointCapability,
    *,
    participant_operation: bool = False,
) -> EnvironmentSpec:
    """Bind the fixture environment to the exact open EDA image on this host."""

    base = environment_spec()
    runtime_capability, installations = _rootless_recovery_installations()
    assert runtime_capability.runtime is not None
    bindings = tuple(
        ToolBinding(
            capability=binding.capability,
            tool_id=binding.tool_id,
            tool_version=installations[binding.tool_id].version_label,
            driver_id=binding.driver_id,
            driver_digest=installations[binding.tool_id].definition.driver_digest,
            locator=ImageToolLocator(
                image_digest=_OPEN_EDA_DIGEST,
                executable=installations[binding.tool_id].executable_name,
                deployment_attestation_digest=(
                    installations[binding.tool_id].deployment_attestation_digest
                ),
            ),
        )
        for binding in base.tool_bindings
    )
    operations: tuple[ParticipantOperationBinding, ...] = ()
    if participant_operation:
        synthesis = next(
            item for item in bindings if item.capability is Capability.ASIC_SYNTHESIS
        )
        operations = (
            ParticipantOperationBinding(
                operation_id="hold_for_recovery",
                capability=synthesis.capability,
                tool_id=synthesis.tool_id,
                arguments=(
                    *(FixedOperationArgument(value=flag) for flag in _YOSYS_SCRIPT_FLAGS),
                    CandidateInputOperationArgument(path=_participant_release_path()),
                ),
            ),
        )
    return EnvironmentSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "executor": RootlessLocalExecutor(
                executor_id="recovery_rootless",
                implementation_digest=digest("recovery-rootless"),
                runtime=ContainerRuntime.PODMAN,
                runtime_version=runtime_capability.runtime.version,
                runtime_probe_digest=runtime_capability.runtime.version_output_digest,
                image_digest=_OPEN_EDA_DIGEST,
            ),
            "tool_bindings": bindings,
            "participant_operations": operations,
            "resources": base.resources.model_copy(
                update={
                    "disk_bytes": 256 * 1024 * 1024,
                    "wall_seconds": 120,
                }
            ),
            "checkpoint": capability,
            "application_checkpoint": (
                ApplicationCheckpointBinding(
                    driver_id="simulation_database",
                    driver_digest=digest("simulation-database-checkpoint"),
                    capture_paths=("design.sv",),
                    after_stage_ids=("functional",),
                )
                if capability is CheckpointCapability.APPLICATION
                else None
            ),
        }
    )


def _checkpoint_controller(
    root_text: str,
    capability: CheckpointCapability,
    ready: Connection,
) -> None:
    root = Path(root_text)
    task = task_spec()
    environment = _checkpoint_environment(capability)
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=environment.artifact_policy,
    )
    workspace = _private_directory(root / "workspace")
    (workspace / "design.sv").write_text(
        "module recovered_design; endmodule\n",
        encoding="ascii",
    )
    (workspace / "controller-only.log").write_text("discardable\n", encoding="ascii")
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="killed_checkpoint_controller",
        state_root=root / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(root / "executor-artifacts"),
        artifact_store=store,
        executor=_rootless_recovery_executor(root, environment, store),
        evaluators=_recovery_evaluators(environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    runtime.advance()
    runtime.advance()
    marker, state = runtime.checkpoint("durable_checkpoint")
    ready.send(
        {
            "artifact_count": len(state.artifacts),
            "controller_pid": os.getpid(),
            "integrity_digest": runtime.journal.integrity_digest(),
            "manifest_digest": marker.manifest_digest,
            "run_id": state.run_id,
            "workspace_inode": workspace.stat().st_ino,
        }
    )
    runtime.advance()


@pytest.mark.parametrize(
    "capability",
    (CheckpointCapability.FILESYSTEM, CheckpointCapability.APPLICATION),
)
def test_checkpoint_survives_controller_sigkill_without_repeating_completed_work(
    tmp_path: Path,
    capability: CheckpointCapability,
) -> None:
    _require_rootless_recovery_runtime()
    root = _private_directory(tmp_path / capability.value)
    context = multiprocessing.get_context("spawn")
    received, ready = context.Pipe(duplex=False)
    controller = context.Process(
        target=_checkpoint_controller,
        args=(root.as_posix(), capability, ready),
    )
    controller.start()
    ready.close()
    try:
        assert received.poll(30), "checkpoint controller did not publish its durable state"
        committed: dict[str, Any] = received.recv()
        deadline = time.monotonic() + 30
        started_paths: list[Path] = []
        while time.monotonic() < deadline:
            started_paths = list(
                (root / "runs").glob("*/executor-storage/*/mount/workspace/qor.started")
            )
            if started_paths:
                break
            if not controller.is_alive():
                break
            time.sleep(0.05)
        assert len(started_paths) == 1, "long evaluator did not enter its isolation scope"
        controller.kill()
        controller.join(10)
        assert controller.exitcode == -signal.SIGKILL
    finally:
        if controller.is_alive():
            controller.kill()
            controller.join(10)
        received.close()
        controller.close()

    heartbeat = started_paths[0].with_name("qor.heartbeat")
    surviving_value = heartbeat.read_text(encoding="ascii")
    time.sleep(0.3)
    assert heartbeat.read_text(encoding="ascii") != surviving_value

    task = task_spec()
    environment = _checkpoint_environment(capability)
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(root / "store", policy=environment.artifact_policy)
    executor = _rootless_recovery_executor(root, environment, store)
    resumed_workspace = root / "resumed-workspace"
    resumed = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="killed_checkpoint_controller",
        state_root=root / "runs",
        workspace=resumed_workspace,
        artifact_directory=_private_directory(root / "resumed-executor-artifacts"),
        artifact_store=store,
        executor=executor,
        evaluators=_recovery_evaluators(environment),
        participant=_SingleSubmission("candidate_b"),
        clock=lambda: _RECOVERY_NOW,
        poll_interval_seconds=0,
    )

    assert resumed.journal.header.run_id == committed["run_id"]
    assert committed["integrity_digest"] in {
        commit.record_digest for commit in resumed.journal.record().commits
    }
    marker, recovered = resumed.resume("durable_checkpoint")
    assert marker.manifest_digest == committed["manifest_digest"]
    assert len(recovered.artifacts) == committed["artifact_count"]
    assert os.getpid() != committed["controller_pid"]
    assert resumed.workspace.stat().st_ino != committed["workspace_inode"]
    assert (resumed.workspace / "design.sv").read_text(encoding="ascii") == (
        "module recovered_design; endmodule\n"
    )
    assert (resumed.workspace / "controller-only.log").exists() == (
        capability is CheckpointCapability.FILESYSTEM
    )
    lifecycle = participant_incarnation_lifecycle(resumed.journal.read_events())
    assert lifecycle.initial_started_sequence == 1
    assert [item.generation for item in lifecycle.incarnations] == [0, 1]
    predecessor, active = lifecycle.incarnations
    assert predecessor.process.process_id == committed["controller_pid"]
    assert active.process.process_id == os.getpid()
    assert predecessor.process.digest != active.process.digest
    assert predecessor.workspace_identity_digest != active.workspace_identity_digest
    assert (
        predecessor.artifact_directory_identity_digest != active.artifact_directory_identity_digest
    )
    assert lifecycle.active_incarnation == active
    assert lifecycle.pending_termination is None
    assert len(lifecycle.recoveries) == 1
    recovery = lifecycle.recoveries[0]
    assert recovery.termination.incarnation_digest == predecessor.digest
    assert recovery.termination.checkpoint_id == "durable_checkpoint"
    assert recovery.termination.checkpoint_manifest_digest == marker.manifest_digest
    assert recovery.restored_manifest_digest == marker.manifest_digest
    assert recovery.restored_incarnation_digest == active.digest
    assert recovery.terminated_sequence < recovery.restored_sequence
    if capability is CheckpointCapability.FILESYSTEM:
        stored_marker, stored_manifest = store.load_filesystem_checkpoint("durable_checkpoint")
    else:
        checkpoint_binding = environment.application_checkpoint
        assert checkpoint_binding is not None
        stored_marker, stored_manifest = store.load_application_checkpoint(
            "durable_checkpoint",
            driver_digest=checkpoint_binding.driver_digest,
        )
    assert stored_marker == marker
    assert stored_manifest.digest == recovery.restored_manifest_digest
    assert not heartbeat.exists()

    for record in recovered.artifacts:
        store.verify(record.blob)
        if record.artifact_class in {ArtifactClass.CANDIDATE, ArtifactClass.CHECKPOINT}:
            manifest = ArtifactManifest.model_validate_json(
                store.read_bytes(record.blob, maximum_bytes=record.blob.size_bytes)
            )
            for entry in manifest.entries:
                store.verify(entry.blob)

    completed = tuple(
        event
        for event in resumed.journal.read_events()
        if isinstance(event, EvaluationCompletedEvent)
        and event.payload.candidate_id == "candidate_a"
    )
    assert [event.payload.result.stage_id for event in completed] == ["functional", "qor"]
    assert completed[0].payload.result.outcome.kind is OutcomeKind.PASSED
    assert completed[1].payload.result.outcome.kind is OutcomeKind.INFRASTRUCTURE_FAILURE

    final_state = resumed.run_to_completion()
    assert final_state.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert final_state.successful_candidate_id == "candidate_b"
    assert [
        event.payload.result.stage_id
        for event in resumed.journal.read_events()
        if isinstance(event, EvaluationCompletedEvent)
        and event.payload.candidate_id == "candidate_b"
    ] == ["functional", "qor"]
    final_lifecycle = participant_incarnation_lifecycle(resumed.journal.read_events())
    assert final_lifecycle == lifecycle


def test_interrupted_licensed_evaluation_records_lost_custody_atomically(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = _licensed_environment()
    session = _licensed_session()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = _licensed_store(tmp_path / "store", environment)
    workspace = _private_directory(tmp_path / "workspace")
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="ascii")
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="interrupted_licensed_evaluation",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=_FixtureExecutor(
            environment,
            store,
            licensed_capabilities=frozenset({Capability.RTL_SIMULATION}),
        ),
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    runtime.advance()
    identity = {
        "job_id": "interrupted_license_job",
        "license_binding_id": "fixture_license_binding",
        "provider_id": "fixture_license_provider",
        "feature_class": "rtl_simulation",
    }
    runtime.journal.transact_events(
        lambda state: (
            EvaluationStartedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=uuid4(),
                timestamp=_NOW,
                producer=ProducerKind.EVALUATOR,
                visibility=Visibility.PARTICIPANT,
                payload=EvaluationStartedPayload(
                    stage_id="functional",
                    candidate_id="candidate_a",
                    job_id=identity["job_id"],
                ),
            ),
            LicenseLeaseAcquiredEvent(
                run_id=state.run_id,
                sequence=state.next_sequence + 1,
                event_id=uuid4(),
                timestamp=_NOW,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=LicenseLeaseAcquiredPayload(**identity),
            ),
            JobStateChangedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence + 2,
                event_id=uuid4(),
                timestamp=_NOW,
                producer=ProducerKind.EXECUTOR,
                visibility=Visibility.VERIFIER,
                payload=JobStateChangedPayload(
                    job_id=identity["job_id"],
                    state=JobStateKind.RUNNING,
                ),
            ),
        )
    )

    recovered = runtime.recover_interrupted()

    recovery_events = runtime.journal.read_events()[-3:]
    assert isinstance(recovery_events[0], JobStateChangedEvent)
    assert recovery_events[0].payload.state is JobStateKind.FAILED
    assert recovery_events[0].payload.reason_code == "runner_restart"
    assert isinstance(recovery_events[1], LicenseLeaseLostEvent)
    assert recovery_events[1].payload.model_dump(mode="python") == identity
    assert isinstance(recovery_events[2], EvaluationCompletedEvent)
    assert recovery_events[2].payload.result.outcome.kind is OutcomeKind.INFRASTRUCTURE_FAILURE
    assert runtime.journal.events_committed_together(
        tuple(event.event_id for event in recovery_events)
    )
    assert not any(isinstance(event, LicenseLeaseReleasedEvent) for event in recovery_events)
    assert recovered.jobs[-1].state is JobStateKind.FAILED


class _UnrecoverableRootlessExecutor(RootlessContainerExecutor):
    def abandon(self, invocation_id: str) -> None:
        raise RuntimeError(f"cannot abandon {invocation_id}")


def test_resume_does_not_mutate_state_when_executor_cannot_prove_quiescence(
    tmp_path: Path,
) -> None:
    _require_rootless_recovery_runtime()
    task = task_spec()
    environment = _checkpoint_environment(CheckpointCapability.FILESYSTEM)
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(tmp_path / "store"),
        policy=environment.artifact_policy,
    )
    workspace = _private_directory(tmp_path / "workspace")
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="ascii")
    executor_artifacts = _private_directory(tmp_path / "executor-artifacts")
    executor = _rootless_recovery_executor(tmp_path, environment, store)
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="unrecoverable_evaluation",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=executor_artifacts,
        artifact_store=store,
        executor=executor,
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    runtime.advance()
    runtime.checkpoint("durable_checkpoint")
    runtime.journal.transact(
        lambda state: EvaluationStartedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW,
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.PARTICIPANT,
            payload=EvaluationStartedPayload(
                stage_id="functional",
                candidate_id="candidate_a",
                job_id="unrecoverable_job",
            ),
        )
    )
    binding = next(
        item for item in environment.tool_bindings if item.capability is Capability.ASIC_SYNTHESIS
    )
    storage = acquire_executor_storage(
        executor,
        environment=environment,
        runtime_root=runtime.journal.directory / "executor-storage",
        run_id=runtime.journal.header.run_id,
        invocation_id="unrecoverable_job",
    )
    try:
        heartbeat = _write_heartbeat_script(storage.workspace)
        executor.launch(
            InvocationPlan(
                invocation_id="unrecoverable_job",
                run_id=storage.receipt.run_id,
                capability=binding.capability,
                tool_id=binding.tool_id,
                driver_digest=binding.driver_digest,
                view=InvocationView.EVALUATOR,
                executable=binding.locator.executable,
                arguments=_HEARTBEAT_ARGUMENTS,
                input_manifest_digest=digest("unrecoverable-evaluation-input"),
            ),
            environment=environment,
            workspace=storage.workspace,
            artifact_directory=storage.artifact_directory,
            asset_paths={},
            scope=FilesystemScope.EVALUATOR,
        )
        runtime.journal.transact(
            lambda state: JobStateChangedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=uuid4(),
                timestamp=_NOW,
                producer=ProducerKind.EXECUTOR,
                visibility=Visibility.VERIFIER,
                payload=JobStateChangedPayload(
                    job_id="unrecoverable_job",
                    state=JobStateKind.RUNNING,
                ),
            )
        )
        _await_heartbeat(
            heartbeat,
            failure="interrupted evaluator did not enter its rootless scope",
        )
        journal_content = runtime.journal.events_path.read_bytes()
        journal_digest = runtime.journal.integrity_digest()
        stored_bytes = store.stored_bytes()
        destination = tmp_path / "restored-workspace"
        reopened = RunOrchestrator.create(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key="unrecoverable_evaluation",
            state_root=tmp_path / "runs",
            workspace=destination,
            artifact_directory=executor_artifacts,
            artifact_store=store,
            executor=_rootless_recovery_executor(
                tmp_path,
                environment,
                store,
                executor_type=_UnrecoverableRootlessExecutor,
            ),
            evaluators=_evaluators(task, environment),
            participant=_SingleSubmission("candidate_b"),
            clock=lambda: _NOW,
            poll_interval_seconds=0,
        )

        try:
            with pytest.raises(OrchestrationError, match="could not be reconciled"):
                reopened.resume("durable_checkpoint")

            assert not destination.exists()
            assert reopened.journal.events_path.read_bytes() == journal_content
            assert reopened.journal.integrity_digest() == journal_digest
            assert store.stored_bytes() == stored_bytes
            running_value = heartbeat.read_text(encoding="ascii")
            time.sleep(0.3)
            assert heartbeat.read_text(encoding="ascii") != running_value
        finally:
            executor.abandon("unrecoverable_job")

        stopped_value = heartbeat.read_text(encoding="ascii")
        time.sleep(0.3)
        assert heartbeat.read_text(encoding="ascii") == stopped_value
    finally:
        storage.close()
