"""One controller for interactive commands and recoverable run operations."""

from __future__ import annotations

import secrets
import time
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from edagym.authoring.factory import GeneratedTask, TaskFactory
from edagym.authoring.qualification import QualificationRunEvidence, qualification_from_run
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.execution import ExecutionPolicyError, project_environment
from edagym.config.model import ConfigView, PrivateConfigSnapshot
from edagym.config.qualification import ConfiguredToolResolution, resolve_profile_tools
from edagym.config.resolve import ResolvedEnvironmentPair, resolve_snapshot
from edagym.config.view_qualification import (
    ViewQualificationReceipt,
    qualify_view,
    verify_view_receipt,
)
from edagym.evaluation import rtl_queue
from edagym.evaluation.model import OutcomeKind
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.model import (
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobStateKind,
)
from edagym.executors.rootless import RootlessContainerExecutor
from edagym.executors.rootless_storage import RootlessStorageProvider
from edagym.implementation import framework_implementation_digest
from edagym.policy.runtime_storage import private_directory, read_private, write_private
from edagym.run.artifact_model import ArtifactManifest, BlobRef, CommittedManifest, ManifestEntry
from edagym.run.artifacts import ContentAddressedStore, manifest_tree
from edagym.run.journal import RunJournal
from edagym.run.journal_storage import JournalError, locked_file, write_exclusive
from edagym.run.manifest import QualificationBinding, RunManifest, RunPurpose
from edagym.run.materialization import populate_disposable_empty_directory
from edagym.run.model import (
    BUDGETED_EVENT_KINDS,
    RUN_EVENT,
    AcceptedEvent,
    CancelPayload,
    CheckpointPayload,
    EditPayload,
    EnginePhase,
    EvaluationPayload,
    EventCursor,
    EventKind,
    EventStream,
    IntentReceipt,
    InteractionIntent,
    OperationState,
    Principal,
    QualificationCompletedEvent,
    RunEvent,
    RunInterface,
    RunProjection,
    RunState,
    RunTimedOutEvent,
    SubmitPayload,
    ToolPayload,
    TransferPayload,
)
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import EnvironmentSpec, FilesystemScope
from edagym.specs.release import QualificationStatus, TaskQualificationEvidence
from edagym.specs.task import FlowQualificationSpec, WorkspaceInterface

_IDENTIFIER = TypeAdapter(Identifier)
_POLL_SECONDS = 0.05


class EngineError(JournalError):
    """A command cannot be accepted under its frozen run or execution policy."""


class _RunDeadlineExceeded(EngineError):
    """The run journal has recorded its exhausted episode deadline."""


class RunEngine:
    """The browser, CLI, and agent adapters share this command and execution owner."""

    def __init__(self, state_root: Path) -> None:
        self.state_root = private_directory(state_root, create=True)
        self.runs_root = private_directory(self.state_root / "runs", create=True)
        self._implementation_digest = framework_implementation_digest()
        self._admission_lock = self.state_root / "operations.lock"
        with suppress(FileExistsError):
            write_exclusive(self._admission_lock, b"")

    def prepare_task(
        self,
        generated: GeneratedTask,
        snapshot: PrivateConfigSnapshot,
        session_id: str,
        principal: Principal,
        *,
        run_id: str | None = None,
        creation_intent_digest: Digest | None = None,
    ) -> RunProjection:
        self._require_implementation()
        if snapshot.configuration.sites[0].state_root != self.state_root:
            raise EngineError("snapshot belongs to another private state root")
        qualification = generated.instance.qualification
        reason = (
            "task_qualification_required"
            if qualification is None or qualification.status is not QualificationStatus.QUALIFIED
            else None
        )
        participant: EnvironmentSpec | None
        evaluator: EnvironmentSpec | None
        try:
            participant, evaluator = self._resolve_environments(snapshot)
        except ExecutionPolicyError as error:
            participant = evaluator = None
            reason = reason or error.gap.value
        if reason is None:
            self._require_task_qualification(generated, snapshot, participant, evaluator)
        manifest = self._manifest(
            generated,
            snapshot,
            session_id,
            principal,
            run_id=run_id,
            creation_intent_digest=creation_intent_digest,
            participant=participant,
            evaluator=evaluator,
        )
        TaskFactory().persist(generated, self.state_root)
        return self._create_run(manifest, principal, snapshot=snapshot, unavailable_reason=reason)

    def _manifest(
        self,
        generated: GeneratedTask,
        snapshot: PrivateConfigSnapshot,
        session_id: str,
        principal: Principal,
        *,
        participant: EnvironmentSpec | None,
        evaluator: EnvironmentSpec | None,
        run_id: str | None = None,
        creation_intent_digest: Digest | None = None,
        purpose: RunPurpose = RunPurpose.TASK,
        qualification: QualificationBinding | None = None,
    ) -> RunManifest:
        return RunManifest.from_snapshot(
            run_id=run_id or f"run_{secrets.token_hex(16)}",
            task=generated.instance,
            task_spec_digest=generated.task.digest,
            snapshot=snapshot,
            session_id=session_id,
            initial_writer=principal.principal_id,
            capabilities=tuple(
                sorted(
                    {
                        capability
                        for specification in generated.task.evaluation.evaluators
                        for capability in (
                            specification.capability,
                            *specification.supporting_capabilities,
                        )
                    },
                    key=lambda item: item.value,
                )
            ),
            creation_intent_digest=creation_intent_digest,
            participant=participant,
            evaluator=evaluator,
            purpose=purpose,
            qualification=qualification,
        )

    def _create_run(
        self,
        manifest: RunManifest,
        principal: Principal,
        *,
        snapshot: PrivateConfigSnapshot,
        unavailable_reason: str | None,
    ) -> RunProjection:
        self._authorize(manifest.run_id, principal)
        journal = RunJournal.create(self.runs_root, manifest, snapshot)
        with journal.locked():
            return self._initialize_run(journal, principal, unavailable_reason)

    def _initialize_run(
        self, journal: RunJournal, principal: Principal, unavailable_reason: str | None
    ) -> RunProjection:
        if journal.read():
            return journal.state().projection
        prepared = self._event(
            journal,
            EventKind.RUN_PREPARED,
            {"manifest_digest": journal.manifest.digest},
            actor_id=principal.principal_id,
        )
        if unavailable_reason is not None:
            next_event = self._event(
                journal, EventKind.RUN_UNAVAILABLE, {"reason": unavailable_reason}, sequence=1
            )
        else:
            generated = self._generated_task(journal)
            files = {
                name.removeprefix("workspace/"): content
                for name, content in generated.contents.items()
                if name.startswith("workspace/")
            }
            committed = self._commit_files(journal, InvocationView.PARTICIPANT, files)
            next_event = self._event(
                journal, EventKind.RUN_STARTED, {"workspace": committed}, sequence=1
            )
        journal.append_events((prepared, next_event))
        return journal.state().projection

    def project(self, run_id: str, principal: Principal) -> RunProjection:
        journal = self._journal_for(run_id, principal)
        if not journal.read():
            raise EngineError("run has no prepared event")
        return journal.state().projection

    def manifest(self, run_id: str, principal: Principal) -> RunManifest:
        return self._journal_for(run_id, principal).manifest

    def resume(self, run_id: str, principal: Principal) -> RunProjection:
        journal = self._journal_for(run_id, principal)
        with journal.locked():
            generated = self._generated_task(journal)
            self._bindings(journal)
            qualification = generated.instance.qualification
            if journal.manifest.purpose is RunPurpose.QUALIFICATION:
                self._qualification_inputs(journal, generated)
            elif (
                journal.manifest.participant is not None
                and qualification is not None
                and qualification.status is QualificationStatus.QUALIFIED
            ):
                self._require_task_qualification(
                    generated,
                    journal.snapshot(),
                    journal.manifest.participant,
                    journal.manifest.evaluator,
                )
            if not journal.read():
                qualification = generated.instance.qualification
                reason = None
                if journal.manifest.purpose is RunPurpose.TASK:
                    if (
                        qualification is None
                        or qualification.status is not QualificationStatus.QUALIFIED
                    ):
                        reason = "task_qualification_required"
                    elif journal.manifest.participant is None:
                        reason = "frozen_view_unavailable"
                self._initialize_run(journal, principal, reason)
            for operation in journal.state().operations:
                if operation.terminal is None:
                    self._execute_operation(journal, operation)
                else:
                    self._cleanup_operation(journal, operation)
            self._finish_expired_run(journal)
            state = journal.state()
            if state.projection.phase is EnginePhase.RUNNING and state.projection.cancel_requested:
                self._commit_event(journal, EventKind.RUN_CANCELLED, {"reason": "explicit_cancel"})
            elif (
                journal.manifest.purpose is RunPurpose.QUALIFICATION
                and state.projection.phase is EnginePhase.RUNNING
            ) or state.projection.qualification_instance_id is not None:
                self._continue_qualification(journal, generated)
            elif state.projection.phase is EnginePhase.RUNNING:
                for candidate in state.candidates:
                    self._evaluate_candidate(journal, candidate.candidate_id)
            return journal.state().projection

    @staticmethod
    def _resolve_environments(
        snapshot: PrivateConfigSnapshot,
    ) -> tuple[EnvironmentSpec, EnvironmentSpec]:
        pair = resolve_snapshot(snapshot)
        resolutions = resolve_profile_tools(pair)
        return (
            project_environment(pair, ConfigView.PARTICIPANT, resolutions),
            project_environment(pair, ConfigView.EVALUATOR, resolutions),
        )

    def _require_implementation(self) -> None:
        if framework_implementation_digest() != self._implementation_digest:
            raise EngineError("controller implementation changed after startup")

    def _bindings(
        self, journal: RunJournal
    ) -> tuple[ResolvedEnvironmentPair, tuple[ConfiguredToolResolution, ...]]:
        self._require_implementation()
        pair = resolve_snapshot(journal.snapshot())
        resolutions = resolve_profile_tools(pair)
        manifest = journal.manifest
        if manifest.participant is not None:
            current = tuple(project_environment(pair, view, resolutions) for view in ConfigView)
            if current != (manifest.participant, manifest.evaluator):
                raise EngineError("frozen execution environment has changed")
        return pair, resolutions

    def files(self, run_id: str, principal: Principal) -> tuple[dict[str, object], ...]:
        generated = self._generated_task(self._journal_for(run_id, principal))
        return tuple(
            {"path": file.path, "media_type": file.media_type, "size_bytes": file.size_bytes}
            for file in generated.instance.generated_files
            if file.visibility in principal.allowed_visibilities
        )

    def interface(self, run_id: str, principal: Principal) -> RunInterface:
        journal = self._journal_for(run_id, principal)
        task = self._generated_task(journal).task
        projection = journal.state().projection
        environment = journal.manifest.participant
        return RunInterface(
            submission_paths=task.interface.submission_paths
            if isinstance(task.interface, WorkspaceInterface)
            else (),
            tool_ids=()
            if environment is None
            else tuple(sorted({item.tool_id for item in environment.tool_bindings})),
            writable=(
                journal.manifest.purpose is RunPurpose.TASK
                and projection.phase is EnginePhase.RUNNING
                and not projection.cancel_requested
                and projection.control_owner == principal.principal_id
            ),
        )

    def read_file(self, run_id: str, path: str, principal: Principal) -> tuple[str, bytes]:
        journal = self._journal_for(run_id, principal)
        generated = self._generated_task(journal)
        for file in generated.instance.generated_files:
            if file.path == path and file.visibility in principal.allowed_visibilities:
                state = journal.state()
                if path.startswith("workspace/") and state.workspace is not None:
                    store = self._store(journal, InvocationView.PARTICIPANT)
                    manifest = self._read_manifest(store, state.workspace)
                    entry = next(
                        (
                            item
                            for item in manifest.entries
                            if item.path == path.removeprefix("workspace/")
                        ),
                        None,
                    )
                    if entry is None:
                        raise EngineError("workspace file is absent")
                    return file.media_type, store.read_bytes(
                        entry.blob, maximum_bytes=entry.blob.size_bytes
                    )
                return file.media_type, generated.contents[file.path]
        raise EngineError("file is not visible in this run")

    def _generated_task(self, journal: RunJournal) -> GeneratedTask:
        generated = TaskFactory().load(
            self.state_root, f"task_{journal.manifest.task_instance_digest[7:]}"
        )
        if generated.task.digest != journal.manifest.task_spec_digest:
            raise EngineError("run task specification is corrupt")
        return generated

    def list_runs(self, principal: Principal) -> tuple[RunProjection, ...]:
        return tuple(
            self.project(path.name, principal)
            for path in sorted(self.runs_root.iterdir())
            if not path.name.startswith(".")
            and path.is_dir()
            and not path.is_symlink()
            and (not principal.allowed_run_ids or path.name in principal.allowed_run_ids)
        )

    def submit_intent(
        self, run_id: str, intent: InteractionIntent, principal: Principal
    ) -> AcceptedEvent:
        journal = self._journal_for(run_id, principal)
        if isinstance(intent.payload, CancelPayload):
            return self._request_cancel(journal, intent, principal)
        with journal.locked():
            if intent.actor_id != principal.principal_id:
                raise EngineError("intent actor differs from the authenticated principal")
            state = journal.state()
            for event in state.events:
                if (
                    event.intent is not None
                    and event.intent.idempotency_key == intent.idempotency_key
                ):
                    if (
                        event.intent.intent_digest != intent.digest
                        or event.actor_id != intent.actor_id
                    ):
                        raise EngineError("idempotency key is already bound to another intent")
                    return self._accepted(event, duplicate=True)
            if state.projection.control_owner != principal.principal_id:
                raise EngineError("principal does not own current run control")
            if state.projection.phase is not EnginePhase.RUNNING:
                raise EngineError("terminal or unavailable runs reject new intents")
            if any(operation.terminal is None for operation in state.operations):
                raise EngineError("pending operations must be resumed before another intent")
            if journal.manifest.purpose is not RunPurpose.TASK:
                raise EngineError("qualification runs do not accept participant intents")
            self._bindings(journal)
            if self._finish_expired_run(journal):
                raise _RunDeadlineExceeded("run episode wall budget is exhausted")
            payload = intent.payload
            if isinstance(payload, EditPayload):
                assert state.workspace is not None
                generated = self._generated_task(journal)
                if (
                    not isinstance(generated.task.interface, WorkspaceInterface)
                    or payload.path not in generated.task.interface.submission_paths
                ):
                    raise EngineError("edit path is outside the task submission interface")
                store = self._store(journal, InvocationView.PARTICIPANT)
                manifest = self._read_manifest(store, state.workspace)
                blob = self._put_bytes(store, payload.content.encode(), InvocationView.PARTICIPANT)
                entries = tuple(item for item in manifest.entries if item.path != payload.path)
                changed = manifest.model_copy(
                    update={
                        "entries": (
                            *entries,
                            ManifestEntry(path=payload.path, blob=blob, mode=0o644),
                        )
                    }
                )
                committed = store.put_manifest(
                    ArtifactManifest.model_validate(changed.model_dump())
                )
                event = self._commit_event(
                    journal, EventKind.WORKSPACE_COMMITTED, {"workspace": committed}, intent=intent
                )
            elif isinstance(payload, ToolPayload):
                assert state.workspace is not None
                environment = journal.manifest.participant
                assert environment is not None
                binding = next(
                    (item for item in environment.tool_bindings if item.tool_id == payload.tool_id),
                    None,
                )
                if binding is None:
                    raise EngineError("tool is outside the participant grant")
                plan = InvocationPlan(
                    invocation_id=f"op_{secrets.token_hex(16)}",
                    run_id=journal.manifest.digest,
                    capability=binding.capability,
                    tool_id=binding.tool_id,
                    driver_digest=binding.driver_digest,
                    view=InvocationView.PARTICIPANT,
                    executable=binding.locator.executable,
                    arguments=payload.arguments,
                    working_directory=payload.working_directory,
                    input_manifest_digest=state.workspace.semantic_digest,
                    deadline=state.projection.deadline,
                )
                event = self._prepare_operation(journal, plan, state.workspace, intent=intent)
                self._execute_operation(journal, journal.state().operations[-1], recovery=False)
                if (
                    journal.state().projection.cancel_requested
                    and journal.state().projection.phase is EnginePhase.RUNNING
                ):
                    self._commit_event(
                        journal, EventKind.RUN_CANCELLED, {"reason": "explicit_cancel"}
                    )
            elif isinstance(payload, TransferPayload):
                event = self._commit_event(
                    journal, EventKind.CONTROL_TRANSFERRED, payload.model_dump(), intent=intent
                )
            elif isinstance(payload, CheckpointPayload):
                event = self._commit_event(
                    journal,
                    EventKind.CHECKPOINT_COMMITTED,
                    {"checkpoint_id": payload.checkpoint_id, "workspace": state.workspace},
                    intent=intent,
                )
            elif isinstance(payload, SubmitPayload):
                event = self._submit_candidate(journal, intent)
            else:
                raise EngineError("unsupported run intent")
            return self._accepted(event)

    def _request_cancel(
        self, journal: RunJournal, intent: InteractionIntent, principal: Principal
    ) -> AcceptedEvent:
        duplicate = False

        def request(state: RunState) -> tuple[RunEvent, ...]:
            nonlocal duplicate
            if intent.actor_id != principal.principal_id:
                raise EngineError("intent actor differs from the authenticated principal")
            for event in state.events:
                if (
                    event.intent is not None
                    and event.intent.idempotency_key == intent.idempotency_key
                ):
                    if (
                        event.intent.intent_digest != intent.digest
                        or event.actor_id != intent.actor_id
                    ):
                        raise EngineError("idempotency key is already bound to another intent")
                    duplicate = True
                    return ()
            if (
                state.projection.control_owner != principal.principal_id
                or state.projection.phase is not EnginePhase.RUNNING
            ):
                raise EngineError("principal cannot cancel this run")
            event = self._event(
                journal,
                EventKind.CANCEL_REQUESTED,
                {"reason": "explicit_cancel"},
                intent=intent,
                sequence=state.projection.next_sequence,
            )
            if any(operation.terminal is None for operation in state.operations):
                return (event,)
            return (
                event,
                self._event(
                    journal,
                    EventKind.RUN_CANCELLED,
                    {"reason": "explicit_cancel"},
                    sequence=event.sequence + 1,
                ),
            )

        state = journal.transact(request)
        accepted = next(
            event
            for event in state.events
            if event.intent is not None and event.intent.idempotency_key == intent.idempotency_key
        )
        return self._accepted(accepted, duplicate=duplicate)

    @staticmethod
    def _accepted(event: RunEvent, *, duplicate: bool = False) -> AcceptedEvent:
        assert event.intent is not None
        return AcceptedEvent(
            run_id=event.run_id,
            intent_id=event.intent.intent_id,
            sequence=event.sequence,
            event_id=event.event_id,
            kind=event.kind,
            duplicate=duplicate,
        )

    def _prepare_operation(
        self,
        journal: RunJournal,
        plan: InvocationPlan,
        inputs: CommittedManifest,
        *,
        intent: InteractionIntent | None = None,
    ) -> RunEvent:
        with locked_file(self._admission_lock, exclusive=True):
            active = sum(
                operation.terminal is None
                for path in self.runs_root.iterdir()
                if path.is_dir() and not path.name.startswith(".")
                for operation in RunJournal.open(path).state().operations
            )
            if active >= journal.snapshot().configuration.sites[0].max_concurrency:
                raise EngineError("site operation concurrency limit is exhausted")
            event = self._commit_event(
                journal,
                EventKind.OPERATION_PREPARED,
                {"plan": plan, "input_manifest": inputs},
                intent=intent,
                visibility=Visibility.PARTICIPANT
                if plan.view is InvocationView.PARTICIPANT
                else Visibility.VERIFIER,
            )
            return event

    def _executor(
        self, journal: RunJournal, view: InvocationView
    ) -> tuple[RootlessContainerExecutor, EnvironmentSpec, Path, dict[str, Path]]:
        pair, resolutions = self._bindings(journal)
        selected = pair.participant if view is InvocationView.PARTICIPANT else pair.evaluator
        environment = (
            journal.manifest.participant
            if view is InvocationView.PARTICIPANT
            else journal.manifest.evaluator
        )
        if environment is None:
            raise EngineError("run has no executable environment")
        observed = [item for item in resolutions if item.receipt.view.value == view.value]
        capability = observed[0].capability
        assert capability is not None
        root = private_directory(journal.directory / view.value, create=True)
        runtime_root = private_directory(
            (
                root
                if selected.storage.root is None
                else selected.storage.root / journal.manifest.run_id / view.value
            )
            / "storage",
            create=True,
        )
        return (
            RootlessContainerExecutor(
                executor_id=environment.executor.executor_id,
                implementation_digest=environment.executor.implementation_digest,
                capability=capability,
                tool_installations={
                    item.receipt.tool_id: item.installation
                    for item in observed
                    if item.installation is not None
                },
                storage_provider=RootlessStorageProvider(
                    maximum_quota_bytes=environment.resources.disk_bytes
                ),
                asset_source_policy=load_system_asset_source_policy(),
                artifact_store=self._store(journal, view),
                job_state_root=root / "jobs",
            ),
            environment,
            runtime_root,
            dict(selected.library_paths),
        )

    def _execute_operation(
        self, journal: RunJournal, operation: OperationState, *, recovery: bool = True
    ) -> ExecutionResult:
        plan = operation.prepared.payload.plan
        executor, environment, runtime_root, assets = self._executor(journal, plan.view)
        store = self._store(journal, plan.view)
        job_directory = journal.directory / plan.view.value / "jobs" / plan.invocation_id
        lease = executor.recover_storage(
            environment=environment,
            runtime_root=runtime_root,
            run_id=plan.run_id,
            invocation_id=plan.invocation_id,
        )
        result = executor.recover_result(
            plan, environment=environment, storage_available=lease is not None, required=recovery
        )
        if result is None and not job_directory.exists() and lease is not None:
            lease.close()
            lease = None
        if result is None and lease is None:
            lease = executor.create_storage(
                environment=environment,
                runtime_root=runtime_root,
                run_id=plan.run_id,
                invocation_id=plan.invocation_id,
            )
        if result is None and not job_directory.exists():
            assert lease is not None
            manifest = self._read_manifest(store, operation.prepared.payload.input_manifest)
            populate_disposable_empty_directory(store, manifest, lease.workspace)
        if result is None:
            assert lease is not None
            handle = executor.launch(
                plan,
                environment=environment,
                workspace=lease.workspace,
                artifact_directory=lease.artifact_directory,
                asset_paths=assets,
                scope=FilesystemScope.PARTICIPANT
                if plan.view is InvocationView.PARTICIPANT
                else FilesystemScope.EVALUATOR,
            )
            if operation.running is None:
                self._commit_event(
                    journal,
                    EventKind.OPERATION_RUNNING,
                    {"operation_id": plan.invocation_id, "handle": handle},
                    visibility=operation.prepared.visibility,
                )
            while executor.inspect(handle).state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
                if plan.deadline is not None and datetime.now(UTC) >= plan.deadline:
                    executor.cancel(handle, reason=ExecutionFailureKind.TIMEOUT)
                elif journal.state().projection.cancel_requested:
                    executor.cancel(handle)
                time.sleep(_POLL_SECONDS)
            if executor.inspect(handle).state is JobStateKind.LOST:
                result = executor.recover_result(
                    plan, environment=environment, storage_available=True
                )
                assert result is not None
            else:
                result = executor.collect(handle)
        workspace = None
        failed = result.state.state is JobStateKind.LOST or (
            plan.view is InvocationView.PARTICIPANT and lease is None
        )
        if plan.view is InvocationView.PARTICIPANT and not failed:
            assert lease is not None
            workspace = store.put_manifest(
                manifest_tree(
                    store,
                    lease.workspace,
                    artifact_class=ArtifactClass.CHECKPOINT,
                    sensitivity=Sensitivity.INTERNAL,
                    visibility=Visibility.PARTICIPANT,
                    redistribution=Redistribution.FORBIDDEN,
                )
            )

        def finish(state: RunState) -> tuple[RunEvent, ...]:
            terminal = self._event(
                journal,
                EventKind.OPERATION_TERMINAL,
                {"operation_id": plan.invocation_id, "result": result, "workspace": workspace},
                sequence=state.projection.next_sequence,
                visibility=operation.prepared.visibility,
            )
            if not failed:
                return (terminal,)
            return (
                terminal,
                self._event(
                    journal,
                    EventKind.RUN_FAILED,
                    {"failure": ExecutionFailureKind.INFRASTRUCTURE},
                    sequence=terminal.sequence + 1,
                ),
            )

        journal.transact(finish)
        executor.fence(plan, environment=environment)
        if lease is not None:
            lease.close()
        self._finish_expired_run(journal)
        return result

    def _cleanup_operation(self, journal: RunJournal, operation: OperationState) -> None:
        plan = operation.prepared.payload.plan
        executor, environment, runtime_root, _ = self._executor(journal, plan.view)
        assert operation.terminal is not None
        result = operation.terminal.payload.result
        store = self._store(journal, plan.view)
        for blob in (result.stdout, result.stderr, *(item.blob for item in result.outputs)):
            store.read_bytes(blob, maximum_bytes=environment.artifact_policy.quota_bytes)
        if operation.terminal.payload.workspace is not None:
            manifest = self._read_manifest(store, operation.terminal.payload.workspace)
            for entry in manifest.entries:
                store.read_bytes(entry.blob, maximum_bytes=environment.artifact_policy.quota_bytes)
        executor.fence(plan, environment=environment)
        lease = executor.recover_storage(
            environment=environment,
            runtime_root=runtime_root,
            run_id=plan.run_id,
            invocation_id=plan.invocation_id,
        )
        if lease is not None:
            lease.close()

    def _store(self, journal: RunJournal, view: InvocationView) -> ContentAddressedStore:
        environment = (
            journal.manifest.participant
            if view is InvocationView.PARTICIPANT
            else journal.manifest.evaluator
        )
        if environment is None:
            raise EngineError("run has no artifact policy for this view")
        return ContentAddressedStore.open_private(
            journal.directory / view.value / "cas", policy=environment.artifact_policy
        )

    @staticmethod
    def _read_manifest(
        store: ContentAddressedStore, committed: CommittedManifest
    ) -> ArtifactManifest:
        manifest = store.read_manifest(committed.blob)
        if manifest.digest != committed.semantic_digest:
            raise EngineError("artifact manifest identity differs from its journal fact")
        return manifest

    @staticmethod
    def _put_bytes(store: ContentAddressedStore, content: bytes, view: InvocationView) -> BlobRef:
        return store.put_bytes(
            content,
            artifact_class=ArtifactClass.CHECKPOINT,
            sensitivity=Sensitivity.INTERNAL,
            visibility=Visibility.PARTICIPANT
            if view is InvocationView.PARTICIPANT
            else Visibility.VERIFIER,
            redistribution=Redistribution.FORBIDDEN,
        )

    def _commit_files(
        self, journal: RunJournal, view: InvocationView, files: dict[str, bytes]
    ) -> CommittedManifest:
        store = self._store(journal, view)
        entries = tuple(
            ManifestEntry(path=path, blob=self._put_bytes(store, content, view), mode=0o644)
            for path, content in files.items()
        )
        return store.put_manifest(
            ArtifactManifest(
                artifact_class=ArtifactClass.CHECKPOINT,
                sensitivity=Sensitivity.INTERNAL,
                visibility=Visibility.PARTICIPANT
                if view is InvocationView.PARTICIPANT
                else Visibility.VERIFIER,
                redistribution=Redistribution.FORBIDDEN,
                entries=entries,
            )
        )

    def stream_run(self, run_id: str, cursor: EventCursor, principal: Principal) -> EventStream:
        journal = self._journal_for(run_id, principal)
        state = journal.state()
        if cursor.sequence > len(state.events):
            raise EngineError("event cursor is ahead of the journal")
        return EventStream(
            run_id=run_id,
            cursor=EventCursor(sequence=len(state.events)),
            events=tuple(
                event
                for event in state.events[cursor.sequence :]
                if event.visibility in principal.allowed_visibilities
            ),
            terminal=state.projection.phase in {EnginePhase.TERMINAL, EnginePhase.UNAVAILABLE},
        )

    def cancel(self, run_id: str, principal: Principal) -> RunProjection:
        from edagym.run.model import IntentKind

        self.submit_intent(
            run_id,
            InteractionIntent(
                intent_id=f"cancel_{secrets.token_hex(8)}",
                idempotency_key=f"cancel_{secrets.token_hex(8)}",
                actor_id=principal.principal_id,
                kind=IntentKind.CANCEL,
            ),
            principal,
        )
        return self.project(run_id, principal)

    def gc(self, run_id: str, principal: Principal, *, dry_run: bool = False) -> bool:
        journal = self._journal_for(run_id, principal)
        with journal.locked():
            state = journal.state()
            if state.projection.phase not in {EnginePhase.TERMINAL, EnginePhase.UNAVAILABLE}:
                raise EngineError("active runs cannot be garbage-collected")
            if not dry_run:
                for operation in state.operations:
                    self._cleanup_operation(journal, operation)
        return True

    def _commit_event(
        self,
        journal: RunJournal,
        kind: EventKind,
        payload: Any,
        *,
        actor_id: str | None = None,
        intent: InteractionIntent | None = None,
        visibility: Visibility = Visibility.PARTICIPANT,
    ) -> RunEvent:
        def commit(current: RunState) -> tuple[RunEvent, ...]:
            event = self._event(
                journal,
                kind,
                payload,
                actor_id=actor_id,
                intent=intent,
                visibility=visibility,
                sequence=current.projection.next_sequence,
            )
            deadline = current.projection.deadline
            if (
                deadline is not None
                and event.timestamp >= deadline
                and kind in BUDGETED_EVENT_KINDS
            ):
                event = self._event(
                    journal, EventKind.RUN_TIMED_OUT, None,
                    sequence=current.projection.next_sequence,
                )
            return (event,)

        event = journal.transact(commit).events[-1]
        if isinstance(event, RunTimedOutEvent) and kind is not EventKind.RUN_TIMED_OUT:
            raise _RunDeadlineExceeded("run episode wall budget is exhausted")
        return event

    def _finish_expired_run(self, journal: RunJournal) -> bool:
        def finish(state: RunState) -> tuple[RunEvent, ...]:
            deadline = state.projection.deadline
            if (
                state.projection.phase is not EnginePhase.RUNNING
                or deadline is None
                or datetime.now(UTC) < deadline
                or any(operation.terminal is None for operation in state.operations)
            ):
                return ()
            return (
                self._event(
                    journal, EventKind.RUN_TIMED_OUT, None,
                    sequence=state.projection.next_sequence,
                ),
            )

        state = journal.transact(finish)
        return state.projection.terminal_reason == EventKind.RUN_TIMED_OUT.value

    def _event(
        self,
        journal: RunJournal,
        kind: EventKind,
        payload: Any,
        *,
        actor_id: str | None = None,
        intent: InteractionIntent | None = None,
        visibility: Visibility = Visibility.PARTICIPANT,
        sequence: int | None = None,
    ) -> RunEvent:
        return RUN_EVENT.validate_python(
            dict(
                sequence=len(journal.read()) if sequence is None else sequence,
                event_id=f"evt_{secrets.token_hex(16)}",
                run_id=journal.manifest.run_id,
                kind=kind,
                actor_id=actor_id if intent is None else intent.actor_id,
                visibility=visibility,
                intent=None
                if intent is None
                else IntentReceipt(
                    intent_id=intent.intent_id,
                    idempotency_key=intent.idempotency_key,
                    intent_digest=intent.digest,
                ),
                timestamp=datetime.now(UTC),
                payload=payload,
            )
        )

    def _journal_for(self, run_id: str, principal: Principal) -> RunJournal:
        self._authorize(run_id, principal)
        return RunJournal.open(self.runs_root / run_id)

    @staticmethod
    def _authorize(run_id: str, principal: Principal) -> None:
        try:
            _IDENTIFIER.validate_python(run_id)
        except ValueError:
            raise EngineError("invalid run identifier") from None
        if principal.allowed_run_ids and run_id not in principal.allowed_run_ids:
            raise EngineError("principal is not authorized for this run")

    def _submit_candidate(self, journal: RunJournal, intent: InteractionIntent) -> RunEvent:
        payload = intent.payload
        assert isinstance(payload, SubmitPayload)
        state = journal.state()
        assert state.workspace is not None
        generated = self._generated_task(journal)
        if not isinstance(generated.task.interface, WorkspaceInterface):
            raise EngineError("task has no workspace submission interface")
        store = self._store(journal, InvocationView.PARTICIPANT)
        manifest = self._read_manifest(store, state.workspace)
        entries = {entry.path: entry for entry in manifest.entries}
        paths = generated.task.interface.submission_paths
        if any(path not in entries for path in paths):
            raise EngineError("candidate omits a required submission path")
        files = {
            path: store.read_bytes(entries[path].blob, maximum_bytes=entries[path].blob.size_bytes)
            for path in paths
        }
        submission = self._commit_files(journal, InvocationView.EVALUATOR, files)
        event = self._commit_event(
            journal,
            EventKind.CANDIDATE_SUBMITTED,
            {"candidate_id": payload.candidate_id, "submission": submission},
            intent=intent,
        )
        self._evaluate_candidate(journal, payload.candidate_id)
        if journal.state().projection.phase is EnginePhase.TERMINAL:
            return event
        if journal.state().projection.cancel_requested:
            self._commit_event(journal, EventKind.RUN_CANCELLED, {"reason": "explicit_cancel"})
        return event

    def _evaluate_candidate(
        self, journal: RunJournal, candidate_id: str
    ) -> EvaluationPayload | None:
        state = journal.state()
        if (
            state.projection.cancel_requested
            or state.projection.phase is not EnginePhase.RUNNING
            or self._finish_expired_run(journal)
        ):
            return None
        existing = next(
            (item for item in state.projection.evaluations if item.candidate_id == candidate_id),
            None,
        )
        if existing is not None:
            return existing
        generated = self._generated_task(journal)
        verifier = generated.contents.get("verifier/verify.py")
        if verifier != rtl_queue.implementation_source() or tuple(
            item.evaluator_id for item in generated.task.evaluation.evaluators
        ) != (rtl_queue.EVALUATOR_ID,):
            raise EngineError("task verifier is not supported by this implementation")
        candidate = next(item for item in state.candidates if item.candidate_id == candidate_id)
        store = self._store(journal, InvocationView.EVALUATOR)
        submission = self._read_manifest(store, candidate.submission)
        if tuple(entry.path for entry in submission.entries) != ("dut.sv",):
            raise EngineError("queue verifier requires exactly its declared RTL submission")
        environment = journal.manifest.evaluator
        assert environment is not None
        prefix = (
            "eval_"
            + canonical_digest(
                {"run": journal.manifest.digest, "candidate": candidate_id},
                domain="candidate-operation-v1",
            )[7:39]
        )
        synthesis = rtl_queue.synthesis_plan(
            environment,
            journal.manifest.digest,
            prefix + "_synthesis",
            candidate.submission.semantic_digest,
        )
        try:
            result = self._ensure_operation(journal, synthesis, candidate.submission)
        except _RunDeadlineExceeded:
            return None
        if (
            journal.state().projection.cancel_requested
            or journal.state().projection.phase is EnginePhase.TERMINAL
        ):
            return None
        outcome, runnable = rtl_queue.outcome(synthesis, result, store, simulation=False)
        operation_ids = [synthesis.invocation_id]
        if outcome is OutcomeKind.PASSED:
            netlist = next(
                (item for item in result.outputs if item.logical_id == rtl_queue.NETLIST_ID), None
            )
            if netlist is None:
                raise EngineError("successful synthesis omitted its netlist")
            inputs = self._commit_files(
                journal,
                InvocationView.EVALUATOR,
                {
                    rtl_queue.NETLIST_PATH: store.read_bytes(
                        netlist.blob, maximum_bytes=environment.artifact_policy.quota_bytes
                    ),
                    "monitor.sv": generated.contents["verifier/monitor.sv"],
                    "vectors.txt": generated.contents["verifier/vectors.txt"],
                },
            )
            simulation = rtl_queue.simulation_plan(
                environment, journal.manifest.digest, prefix + "_simulation", inputs.semantic_digest
            )
            try:
                result = self._ensure_operation(journal, simulation, inputs)
            except _RunDeadlineExceeded:
                return None
            if (
                journal.state().projection.cancel_requested
                or journal.state().projection.phase is EnginePhase.TERMINAL
            ):
                return None
            operation_ids.append(simulation.invocation_id)
            outcome, runnable = rtl_queue.outcome(simulation, result, store, simulation=True)
        evaluation = EvaluationPayload(
            candidate_id=candidate_id,
            outcome=outcome,
            runnable=runnable,
            operation_ids=tuple(operation_ids),
        )
        self._commit_event(journal, EventKind.EVALUATION_COMPLETED, evaluation.model_dump())
        return evaluation

    def _ensure_operation(
        self, journal: RunJournal, plan: InvocationPlan, inputs: CommittedManifest
    ) -> ExecutionResult:
        plan = plan.model_copy(update={"deadline": journal.state().projection.deadline})
        operation = next(
            (
                item
                for item in journal.state().operations
                if item.prepared.payload.plan.invocation_id == plan.invocation_id
            ),
            None,
        )
        recovery = operation is not None
        if operation is None:
            self._prepare_operation(journal, plan, inputs)
            operation = journal.state().operations[-1]
        if (
            operation.prepared.payload.plan != plan
            or operation.prepared.payload.input_manifest != inputs
        ):
            raise EngineError("resumed evaluation differs from its prepared operation")
        if operation.terminal is not None:
            return operation.terminal.payload.result
        return self._execute_operation(journal, operation, recovery=recovery)

    def qualify_task(
        self,
        generated: GeneratedTask,
        snapshot: PrivateConfigSnapshot,
        session_id: str,
        principal: Principal,
        *,
        run_id: str | None = None,
    ) -> GeneratedTask:
        """Execute or resume the declared canaries under one immutable run identity."""
        self._require_implementation()
        if snapshot.configuration.sites[0].state_root != self.state_root:
            raise EngineError("snapshot belongs to another private state root")
        generated = replace(
            generated,
            instance=generated.instance.model_copy(
                update={
                    "qualification": TaskQualificationEvidence(status=QualificationStatus.PENDING),
                }
            ),
        )
        if run_id is not None:
            self._authorize(run_id, principal)
            if (self.runs_root / run_id).exists():
                journal = self._journal_for(run_id, principal)
                manifest = journal.manifest
                if (
                    manifest.purpose is not RunPurpose.QUALIFICATION
                    or manifest.task_instance_digest != generated.instance.digest
                    or manifest.private_config_snapshot_digest != snapshot.digest
                    or manifest.session_id != session_id
                ):
                    raise EngineError("qualification retry differs from its frozen run")
                result = self.resume(run_id, principal)
                if result.qualification_instance_id is None:
                    raise EngineError("qualification run has no completed result")
                return TaskFactory().load(self.state_root, result.qualification_instance_id)
        if not isinstance(generated.task.qualification, FlowQualificationSpec):
            raise EngineError("task does not declare flow qualification canaries")
        TaskFactory().persist(generated, self.state_root)
        pair = resolve_snapshot(snapshot)
        resolutions = resolve_profile_tools(pair)
        environments = tuple(project_environment(pair, view, resolutions) for view in ConfigView)
        views = tuple(qualify_view(pair, view, resolutions) for view in ConfigView)
        for environment, receipt in zip(environments, views, strict=True):
            verify_view_receipt(pair, environment, receipt)
        oracle = rtl_queue.check_oracle(
            rtl_queue.QueueOracleContract.model_validate_json(
                generated.contents["verifier/oracle.json"]
            ),
            generated.contents["verifier/vectors.txt"],
        )
        oracle_root = private_directory(self.state_root / "qualifications" / "oracles", create=True)
        write_private(oracle_root / f"{oracle.digest[7:]}.json", canonical_bytes(oracle))
        manifest = self._manifest(
            generated,
            snapshot,
            session_id,
            principal,
            run_id=run_id,
            participant=environments[0],
            evaluator=environments[1],
            purpose=RunPurpose.QUALIFICATION,
            qualification=QualificationBinding(
                participant_view_digest=views[0].digest,
                evaluator_view_digest=views[1].digest,
                independent_evidence_digest=oracle.digest,
            ),
        )
        self._create_run(manifest, principal, snapshot=snapshot, unavailable_reason=None)
        journal = self._journal_for(manifest.run_id, principal)
        with journal.locked():
            return self._continue_qualification(journal, generated)

    def _qualification_inputs(
        self, journal: RunJournal, generated: GeneratedTask
    ) -> tuple[
        tuple[ViewQualificationReceipt, ...],
        rtl_queue.QueueOracleEvidence,
    ]:
        binding = journal.manifest.qualification
        if binding is None:
            raise EngineError("qualification run has no frozen evidence inputs")
        root = self.state_root / "qualifications"
        views = tuple(
            ViewQualificationReceipt.model_validate_json(
                read_private(root / "views" / f"{digest[7:]}.json")
            )
            for digest in (binding.participant_view_digest, binding.evaluator_view_digest)
        )
        oracle = rtl_queue.QueueOracleEvidence.model_validate_json(
            read_private(root / "oracles" / f"{binding.independent_evidence_digest[7:]}.json")
        )
        if (
            tuple(item.digest for item in views)
            != (binding.participant_view_digest, binding.evaluator_view_digest)
            or tuple(item.view for item in views) != tuple(ConfigView)
            or oracle.digest != binding.independent_evidence_digest
        ):
            raise EngineError("qualification inputs differ from the frozen manifest")
        expected = rtl_queue.check_oracle(
            rtl_queue.QueueOracleContract.model_validate_json(
                generated.contents["verifier/oracle.json"]
            ),
            generated.contents["verifier/vectors.txt"],
        )
        if oracle != expected:
            raise EngineError("qualification oracle differs from its declared task")
        pair = resolve_snapshot(journal.snapshot())
        for environment, receipt in zip(
            (journal.manifest.participant, journal.manifest.evaluator), views, strict=True
        ):
            if environment is None:
                raise EngineError("qualification run has no frozen execution view")
            verify_view_receipt(pair, environment, receipt)
        return views, oracle

    def _continue_qualification(
        self, journal: RunJournal, generated: GeneratedTask
    ) -> GeneratedTask:
        views, oracle = self._qualification_inputs(journal, generated)
        contract = generated.task.qualification
        if not isinstance(contract, FlowQualificationSpec):
            raise EngineError("task does not declare flow qualification canaries")
        state = journal.state()
        publication = (
            state.events[-1]
            if state.events and isinstance(state.events[-1], QualificationCompletedEvent)
            else None
        )
        if publication is None:
            if (
                state.projection.phase is not EnginePhase.RUNNING
                or state.projection.cancel_requested
            ):
                raise EngineError("qualification run cannot continue after cancellation")
            resources = {item.resource_id: item for item in generated.task.resources}
            required = (
                contract.feasibility_witness_resource,
                *contract.negative_candidate_resources,
            )
            if any(item.candidate_id not in required for item in state.candidates):
                raise EngineError("qualification run contains an undeclared candidate")
            for resource_id in required:
                submission = self._commit_files(
                    journal,
                    InvocationView.EVALUATOR,
                    {"dut.sv": generated.contents[resources[resource_id].path]},
                )
                existing = next(
                    (
                        item
                        for item in journal.state().candidates
                        if item.candidate_id == resource_id
                    ),
                    None,
                )
                if existing is None:
                    self._commit_event(
                        journal,
                        EventKind.CANDIDATE_SUBMITTED,
                        {"candidate_id": resource_id, "submission": submission},
                        visibility=Visibility.VERIFIER,
                    )
                elif existing.submission != submission:
                    raise EngineError("qualification candidate differs from its declared source")
                if self._evaluate_candidate(journal, resource_id) is None:
                    if journal.state().projection.phase is EnginePhase.RUNNING:
                        self._commit_event(
                            journal, EventKind.RUN_CANCELLED, {"reason": "explicit_cancel"}
                        )
                    raise EngineError("qualification run terminated before completing its canaries")
            record = journal.record()
        else:
            complete = journal.record()
            record = complete.prefix(complete.commits[-1].previous_record_digest)
        evidence = qualification_from_run(generated.instance, generated.task, record, views, oracle)
        qualified = replace(
            generated,
            instance=generated.instance.model_copy(
                update={"qualification": evidence.qualification}
            ),
        )
        if publication is not None and (
            publication.payload.instance_id != qualified.instance_id
            or publication.payload.evidence_digest != evidence.digest
        ):
            raise EngineError("qualification publication differs from its journal evidence")
        root = private_directory(self.state_root / "qualifications" / "tasks", create=True)
        name = canonical_digest(evidence.qualification, domain="task-qualification-evidence-v1")[7:]
        write_private(root / f"{name}.json", canonical_bytes(evidence))
        TaskFactory().persist(qualified, self.state_root)
        if publication is None:
            self._commit_event(
                journal,
                EventKind.QUALIFICATION_COMPLETED,
                {"instance_id": qualified.instance_id, "evidence_digest": evidence.digest},
            )
        return qualified

    def _require_task_qualification(
        self,
        generated: GeneratedTask,
        snapshot: PrivateConfigSnapshot,
        participant: EnvironmentSpec | None,
        evaluator: EnvironmentSpec | None,
    ) -> None:
        if participant is None or evaluator is None or generated.instance.qualification is None:
            raise EngineError("task qualification has no frozen environments")
        name = canonical_digest(
            generated.instance.qualification, domain="task-qualification-evidence-v1"
        )[7:]
        evidence = QualificationRunEvidence.model_validate_json(
            read_private(self.state_root / "qualifications" / "tasks" / f"{name}.json")
        )
        if (
            evidence.snapshot_digest != snapshot.digest
            or evidence.qualification != generated.instance.qualification
        ):
            raise EngineError("task qualification belongs to another frozen configuration")
        source = RunJournal.open(self.runs_root / evidence.run_id)
        if source.manifest.purpose is not RunPurpose.QUALIFICATION or (
            source.manifest.participant,
            source.manifest.evaluator,
        ) != (participant, evaluator):
            raise EngineError("task qualification run has different view bindings")
        complete = source.record()
        if not complete.events or not isinstance(complete.events[-1], QualificationCompletedEvent):
            raise EngineError("task qualification has not published its result")
        publication = complete.events[-1]
        if (
            publication.payload.instance_id != generated.instance_id
            or publication.payload.evidence_digest != evidence.digest
        ):
            raise EngineError("task qualification publication is corrupt")
        record = complete.prefix(evidence.journal_head_digest)
        original = self._generated_task(source)
        views, oracle = self._qualification_inputs(source, original)
        if original.task != generated.task or original.contents != generated.contents:
            raise EngineError("qualified task differs from its executed canaries")
        if (
            qualification_from_run(original.instance, original.task, record, views, oracle)
            != evidence
        ):
            raise EngineError("task qualification does not replay from its execution facts")
        store = self._store(source, InvocationView.EVALUATOR)
        resources = {item.resource_id: item for item in generated.task.resources}
        state = source.state()
        for candidate in state.candidates:
            submission = self._read_manifest(store, candidate.submission)
            if (
                len(submission.entries) != 1
                or submission.entries[0].path != "dut.sv"
                or submission.entries[0].blob.digest
                != resources[candidate.candidate_id].content_digest
            ):
                raise EngineError("qualification candidate differs from its declared source")
        for operation in state.operations:
            if operation.terminal is None:
                raise EngineError("qualification operation is incomplete")
            result = operation.terminal.payload.result
            for blob in (result.stdout, result.stderr, *(item.blob for item in result.outputs)):
                store.read_bytes(blob, maximum_bytes=evaluator.artifact_policy.quota_bytes)
