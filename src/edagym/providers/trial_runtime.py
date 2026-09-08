"""Production bridge from one frozen campaign trial to the run runtime."""

from __future__ import annotations

import math
import os
import pwd
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from uuid import UUID, uuid4

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.assets import (
    AssetSnapshot,
    AssetValidationError,
    revalidate_asset_closure,
    validate_asset_closure,
)
from edagym.executors.licenses import (
    LeaseState,
    LicenseLease,
    LicenseProvider,
    LicenseUnavailable,
)
from edagym.executors.model import (
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    OutputDeclaration,
)
from edagym.executors.model import (
    JobStateKind as ExecutorJobStateKind,
)
from edagym.executors.protocol import (
    Executor,
    ExecutorStorageProvider,
    InvocationStorageLease,
    acquire_executor_storage,
    release_executor_storage,
)
from edagym.participant_tool_protocol import (
    EXECUTOR_PARTICIPANT_TOOL_NAME,
    participant_tool_invocation_id,
)
from edagym.participants.adapters import ParticipantAdapterError, ParticipantFailureKind
from edagym.participants.admission import CampaignParticipantAdmission
from edagym.participants.continuation import AdmittedCampaignContinuationAdapter
from edagym.participants.execution import participant_dispatch_lock
from edagym.participants.model import ParticipantView
from edagym.participants.operation_runtime import (
    materialize_participant_operation_inputs,
    materialize_participant_operation_outputs,
    participant_operation_input_digest,
)
from edagym.participants.responses import (
    MeteredResponsesParticipantSender,
    ProviderUsagePolicy,
    ResponsesParticipantAdapter,
    ResponsesParticipantTool,
    responses_instruction_digest,
    responses_tool_schema_digest,
)
from edagym.participants.workspace import (
    CheckpointParticipantTool,
    EdaInvocationTool,
    ToolObservation,
    ToolObservationOutcome,
    WorkspaceReadTool,
    WorkspaceWriteTool,
)
from edagym.providers.campaign_budget import CampaignResources
from edagym.providers.campaign_runner import (
    CampaignAccountingError,
    CampaignRunner,
    SpendObservation,
    TrialRunOutcome,
    UnknownSpend,
    UnknownSpendReason,
)
from edagym.providers.campaign_schedule import (
    CampaignTask,
    MeteredProviderHarnessBinding,
    ScheduledTrial,
    require_paid_campaign_task_origin,
)
from edagym.providers.model import RequestTokenClaim
from edagym.providers.trial_evidence import (
    TERMINAL_EXECUTOR_STATES,
    TOOL_EXECUTION_MEDIA_TYPE,
    CampaignTrialResult,
    ParticipantToolExecutionEvidence,
    evaluator_elapsed_milliseconds,
    evaluator_license_milliseconds,
    project_campaign_trial_run_evidence,
)
from edagym.providers.trial_security import (
    campaign_trial_harness_actor,
    campaign_trial_run_binding,
    runtime_surface_binding_for_trial,
)
from edagym.providers.trial_workspace import (
    participant_release_paths,
    prepare_trial_workspace,
    require_private_directory,
)
from edagym.resolution import resolve_run
from edagym.run.artifact_model import (
    ArtifactRecord,
    BlobRef,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.trial_journal import (
    TrialJournal,
    participant_tool_usage,
)
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    InteractionDirection,
    InteractionRecordedEvent,
    LicenseDenialReason,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseAcquiredPayload,
    LicenseLeaseDeniedEvent,
    LicenseLeaseDeniedPayload,
    LicenseLeaseLostEvent,
    LicenseLeaseLostPayload,
    LicenseLeaseReleasedEvent,
    LicenseLeaseReleasedPayload,
    ParticipantToolReservedEvent,
    ParticipantToolReservedPayload,
    ParticipantToolSettledEvent,
    ParticipantToolSettledPayload,
    ProducerKind,
    RunBinding,
    RunEvent,
    RunHeader,
    RunState,
)
from edagym.runtime.model import EvaluatorRuntime
from edagym.runtime.orchestrator import RunOrchestrator
from edagym.runtime.participant_recovery import (
    reconcile_interrupted_run_work,
    restore_participant_incarnation,
)
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import EnvironmentSpec, FilesystemScope, ToolBinding
from edagym.specs.operation import ParticipantOperationBinding
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import RecoveryPolicy, SessionSpec
from edagym.specs.task import TaskSpec


class CampaignTrialContinuation(StrictModel):
    """Exact existing-run snapshot authorized for one hybrid harness continuation."""

    run_binding: RunBinding
    run_record_digest: Digest
    current_harness_actor_id: Identifier
    campaign_budget_binding_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="campaign-trial-continuation-v1")


@dataclass(frozen=True, slots=True)
class _ToolDispatchReservation:
    payload: ParticipantToolReservedPayload
    compute_limit_failure: ParticipantFailureKind | None
    license_limit_failure: ParticipantFailureKind | None


class _ToolDeadlineExpired(RuntimeError):
    pass


class _ParticipantLicenseCustodyError(RuntimeError):
    pass


class ExecutorParticipantToolDispatcher:
    """Execute resolved finite operations and persist typed, secret-free evidence."""

    def __init__(
        self,
        *,
        journal: TrialJournal,
        environment: EnvironmentSpec,
        session: SessionSpec,
        artifact_store: ContentAddressedStore,
        executor: Executor,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: Mapping[str, Path],
        asset_source_policy: AssetSourcePolicy,
        license_providers: Mapping[str, LicenseProvider],
        protected_paths: Sequence[Path] = (),
        clock: Callable[[], datetime],
        monotonic: Callable[[], float] = time.monotonic,
        poll_interval_seconds: float = 0.05,
        event_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        if poll_interval_seconds < 0:
            raise ValueError("participant tool poll interval cannot be negative")
        if environment.digest != journal.header.binding.environment.environment_spec_digest:
            raise ValueError("participant tool environment differs from the run binding")
        if session.digest != journal.header.binding.session.session_spec_digest:
            raise ValueError("participant tool session differs from the run binding")
        if artifact_store.policy != environment.artifact_policy:
            raise ValueError("participant tool artifact policy differs from the environment")
        if type(asset_source_policy) is not AssetSourcePolicy:
            raise ValueError("participant tools require trusted asset source authority")
        require_private_directory(workspace)
        require_private_directory(artifact_directory)
        resolved_tools = {
            (item.capability, item.tool_id): item
            for item in journal.header.binding.environment.tools
        }
        tools = {
            (binding.capability, binding.tool_id): binding for binding in environment.tool_bindings
        }
        resolved_operations = {
            item.operation_id: item
            for item in journal.header.binding.environment.participant_operations
        }
        if not environment.participant_operations:
            raise ValueError("participant tools require finite run-resolved operations")
        for operation in environment.participant_operations:
            binding = tools[(operation.capability, operation.tool_id)]
            run_binding = resolved_tools[(binding.capability, binding.tool_id)]
            if (
                run_binding.driver_digest != binding.driver_digest
                or run_binding.deployment_attestation_digest
                != binding.locator.deployment_attestation_digest
            ):
                raise ValueError("participant tool binding differs from the resolved run")
            resolved_operation = resolved_operations.get(operation.operation_id)
            if (
                resolved_operation is None
                or resolved_operation.operation_digest != operation.digest
                or resolved_operation.capability is not operation.capability
                or resolved_operation.tool_id != operation.tool_id
            ):
                raise ValueError("participant operation differs from the resolved run")
        controller_paths = [journal.directory, artifact_store.root, *protected_paths]
        credential_root = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".codex"
        if credential_root.exists():
            controller_paths.append(credential_root)
        asset_snapshots = validate_asset_closure(
            environment,
            asset_paths,
            FilesystemScope.TOOL,
            source_policy=asset_source_policy,
            protected_paths=controller_paths,
            writable_paths=(workspace, artifact_directory),
        )
        self._journal = journal
        self._environment = environment
        self._session = session
        self._store = artifact_store
        self._executor = executor
        self._workspace = workspace
        self._artifact_directory = artifact_directory
        self._asset_paths = {
            asset_id: snapshot.path for asset_id, snapshot in asset_snapshots.items()
        }
        self._asset_snapshots: Mapping[str, AssetSnapshot] = asset_snapshots
        self._protected_paths = tuple(controller_paths)
        self._writable_paths = (workspace, artifact_directory)
        self._license_providers = dict(license_providers)
        self._operations = MappingProxyType(
            {operation.operation_id: operation for operation in environment.participant_operations}
        )
        self._bindings = MappingProxyType(
            {
                operation.operation_id: tools[(operation.capability, operation.tool_id)]
                for operation in environment.participant_operations
            }
        )
        self._clock = clock
        self._monotonic = monotonic
        self._poll_interval_seconds = poll_interval_seconds
        self._event_id_factory = event_id_factory

    @property
    def operation_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._operations))

    def invoke(
        self,
        *,
        operation_id: str,
        view: ParticipantView,
    ) -> ToolObservation:
        state = self._journal.state()
        if (
            view.run_id != state.run_id
            or view.actor_id != state.current_writer
            or state.terminal_reason is not None
        ):
            raise ValueError("participant tool invocation has a stale run view")
        operation = self._operations.get(operation_id)
        binding = self._bindings.get(operation_id)
        if operation is None or binding is None:
            raise ValueError("participant operation is not run-resolved")
        request_interaction_id = _pending_tool_request(self._journal, view.actor_id)
        input_digest = participant_operation_input_digest(
            self._workspace,
            operation,
            maximum_bytes=self._environment.resources.disk_bytes,
        )
        invocation_id = participant_tool_invocation_id(
            state.run_id,
            request_interaction_id,
        )
        plan = InvocationPlan(
            invocation_id=invocation_id,
            run_id=state.run_id,
            capability=binding.capability,
            tool_id=binding.tool_id,
            driver_digest=binding.driver_digest,
            view=InvocationView.TOOL,
            executable=binding.locator.executable,
            arguments=operation.argv,
            input_manifest_digest=input_digest,
            outputs=tuple(
                OutputDeclaration(
                    logical_id=output.logical_id,
                    path=output.path,
                    media_type=output.media_type,
                    artifact_class=output.artifact_class,
                    required=output.required,
                )
                for output in operation.outputs
            ),
        )
        reservation = self._reserve_dispatch(
            plan=plan,
            binding=binding,
            operation=operation,
            request_interaction_id=request_interaction_id,
        )
        evidence, records, budget_failure, storage_lease = self._execute(
            plan=plan,
            binding=binding,
            operation=operation,
            request_interaction_id=request_interaction_id,
            reservation=reservation,
        )
        evidence_record = self._store_evidence(evidence)
        self._record_artifacts_and_settlement(
            records=(*records, evidence_record),
            evidence_record=evidence_record,
            evidence=evidence,
            reservation=reservation.payload,
        )
        if storage_lease is not None:
            release_executor_storage(self._executor, storage_lease, plan.invocation_id)
        if budget_failure is not None:
            raise ParticipantAdapterError(budget_failure)
        return ToolObservation(
            outcome=evidence.outcome,
            summary=_tool_summary(evidence),
            artifact_refs=(evidence_record.logical_id,),
        )

    def _reserve_dispatch(
        self,
        *,
        plan: InvocationPlan,
        binding: ToolBinding,
        operation: ParticipantOperationBinding,
        request_interaction_id: str,
    ) -> _ToolDispatchReservation:
        events = self._journal.read_events()
        if not events:
            raise ValueError("participant tool reservation requires a started run")
        now = self._clock()
        participant_usage = participant_tool_usage(events)
        used_compute = (
            evaluator_elapsed_milliseconds(events) + participant_usage.eda_compute_milliseconds
        )
        used_license = (
            evaluator_license_milliseconds(events) + participant_usage.license_milliseconds
        )
        resources = self._session.resources
        remaining_wall = resources.max_wall_seconds * 1000 - _datetime_milliseconds(
            events[0].timestamp, now
        )
        remaining_compute = resources.max_eda_compute_seconds * 1000 - used_compute
        if remaining_wall <= 0:
            raise ParticipantAdapterError(ParticipantFailureKind.WALL_BUDGET)
        if remaining_compute <= 0:
            raise ParticipantAdapterError(ParticipantFailureKind.EDA_COMPUTE_BUDGET)

        environment_limit = self._environment.resources.wall_seconds * 1000
        compute_reservation = min(
            remaining_wall,
            remaining_compute,
            environment_limit,
        )
        if compute_reservation == remaining_wall:
            compute_limit_failure = ParticipantFailureKind.WALL_BUDGET
        elif compute_reservation == remaining_compute:
            compute_limit_failure = ParticipantFailureKind.EDA_COMPUTE_BUDGET
        else:
            compute_limit_failure = None

        license_reservation = 0
        license_limit_failure: ParticipantFailureKind | None = None
        if binding.license_binding_id is not None:
            license_binding = next(
                item
                for item in self._environment.licenses
                if item.license_binding_id == binding.license_binding_id
            )
            remaining_license = resources.max_license_seconds * 1000 - used_license
            if remaining_license <= 0:
                raise ParticipantAdapterError(ParticipantFailureKind.LICENSE_BUDGET)
            license_reservation = min(
                remaining_license,
                license_binding.lease_ttl_seconds * 1000,
                compute_reservation,
            )
            if license_reservation == remaining_license:
                license_limit_failure = ParticipantFailureKind.LICENSE_BUDGET

        payload = ParticipantToolReservedPayload(
            request_interaction_id=request_interaction_id,
            invocation_id=plan.invocation_id,
            invocation_digest=plan.digest,
            operation_id=operation.operation_id,
            operation_digest=operation.digest,
            input_manifest_digest=plan.input_manifest_digest,
            tool_id=plan.tool_id,
            capability=plan.capability,
            executor_id=self._journal.header.binding.environment.executor_id,
            license_binding_id=binding.license_binding_id,
            budget_digest=self._journal.header.binding.session.budget_digest,
            reserved_compute_milliseconds=compute_reservation,
            reserved_license_milliseconds=license_reservation,
        )
        event_id = self._event_id_factory()
        self._journal.transact(
            lambda state: ParticipantToolReservedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=event_id,
                timestamp=now,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=payload,
            )
        )
        return _ToolDispatchReservation(
            payload=payload,
            compute_limit_failure=compute_limit_failure,
            license_limit_failure=license_limit_failure,
        )

    def _execute(
        self,
        *,
        plan: InvocationPlan,
        binding: ToolBinding,
        operation: ParticipantOperationBinding,
        request_interaction_id: str,
        reservation: _ToolDispatchReservation,
    ) -> tuple[
        ParticipantToolExecutionEvidence,
        tuple[ArtifactRecord, ...],
        ParticipantFailureKind | None,
        InvocationStorageLease | None,
    ]:
        started = self._monotonic()
        lease: LicenseLease | None = None
        storage_lease: InvocationStorageLease | None = None
        license_started: float | None = None
        result: ExecutionResult | None = None
        handle = None
        pre_execution_outcome: ToolObservationOutcome | None = None
        budget_failure: ParticipantFailureKind | None = None
        cancellation_sent = False
        launch_attempted = False
        isolation_closed = False
        abandonment_error: Exception | None = None
        try:
            revalidate_asset_closure(
                self._asset_snapshots,
                protected_paths=self._protected_paths,
                writable_paths=self._writable_paths,
            )
            if binding.license_binding_id is not None:
                license_started = self._monotonic()
                lease = self._acquire_license(binding, plan.invocation_id)
            deadline_reached, budget_failure = _participant_tool_deadline(
                reservation,
                started=started,
                license_started=license_started,
                now=self._monotonic(),
            )
            if deadline_reached:
                pre_execution_outcome = ToolObservationOutcome.TIMEOUT
                raise _ToolDeadlineExpired
            execution_workspace = self._workspace
            execution_artifact_directory = self._artifact_directory
            if isinstance(self._executor, ExecutorStorageProvider):
                storage_lease = acquire_executor_storage(
                    self._executor,
                    environment=self._environment,
                    runtime_root=self._journal.directory / "executor-storage",
                    run_id=self._journal.header.run_id,
                    invocation_id=plan.invocation_id,
                )
                execution_workspace = storage_lease.workspace
                execution_artifact_directory = storage_lease.artifact_directory
                projected_input_digest = materialize_participant_operation_inputs(
                    self._workspace,
                    execution_workspace,
                    operation,
                    maximum_bytes=self._environment.resources.disk_bytes,
                )
                if projected_input_digest != plan.input_manifest_digest:
                    raise RuntimeError("participant operation input changed before isolation")
                revalidate_asset_closure(
                    self._asset_snapshots,
                    protected_paths=self._protected_paths,
                    writable_paths=(execution_workspace, execution_artifact_directory),
                )
            launch_attempted = True
            handle = self._executor.launch(
                plan,
                environment=self._environment,
                workspace=execution_workspace,
                artifact_directory=execution_artifact_directory,
                asset_paths=self._asset_paths,
                scope=FilesystemScope.TOOL,
                license_lease=lease,
            )
            if (
                handle.job_id != plan.invocation_id
                or handle.invocation_digest != plan.digest
                or handle.executor_id != self._journal.header.binding.environment.executor_id
            ):
                raise RuntimeError("participant executor returned a mismatched handle")
            while True:
                terminal = self._executor.inspect(handle)
                if terminal.handle != handle:
                    raise RuntimeError("participant executor returned state for another job")
                if terminal.state in TERMINAL_EXECUTOR_STATES:
                    isolation_closed = True
                    break
                deadline_reached, deadline_failure = _participant_tool_deadline(
                    reservation,
                    started=started,
                    license_started=license_started,
                    now=self._monotonic(),
                )
                if deadline_reached and not cancellation_sent:
                    budget_failure = deadline_failure
                    cancellation_sent = True
                    terminal = self._executor.cancel(handle)
                    if terminal.handle != handle:
                        raise RuntimeError("participant executor cancelled another job")
                    if terminal.state in TERMINAL_EXECUTOR_STATES:
                        isolation_closed = True
                        break
                    pre_execution_outcome = ToolObservationOutcome.TIMEOUT
                    raise _ToolDeadlineExpired
                if self._poll_interval_seconds:
                    time.sleep(self._poll_interval_seconds)
            collected = self._executor.collect(handle)
            if collected.state != terminal:
                raise RuntimeError("participant executor changed its terminal state")
            if storage_lease is not None:
                materialize_participant_operation_outputs(
                    execution_workspace,
                    self._workspace,
                    operation,
                    collected,
                    maximum_bytes=self._environment.resources.disk_bytes,
                )
            result = collected
        except _ToolDeadlineExpired:
            pass
        except _ParticipantLicenseCustodyError:
            raise
        except LicenseUnavailable:
            pre_execution_outcome = ToolObservationOutcome.LICENSE_UNAVAILABLE
        except AssetValidationError:
            pre_execution_outcome = ToolObservationOutcome.SECURITY_VIOLATION
        except Exception:
            pre_execution_outcome = ToolObservationOutcome.INFRASTRUCTURE_FAILURE
        if launch_attempted and not isolation_closed:
            try:
                self._executor.abandon(plan.invocation_id)
            except Exception as error:
                abandonment_error = error
            else:
                isolation_closed = True
        release_failed = False
        if lease is not None:
            release_failed = self._release_license(
                invocation_id=plan.invocation_id,
                tool=binding,
                lease=lease,
            )
        if abandonment_error is not None:
            raise RuntimeError(
                "participant executor could not prove failed invocation quiescent"
            ) from abandonment_error
        finished = self._monotonic()
        measured_elapsed_milliseconds = _elapsed_milliseconds(started, finished)
        elapsed_milliseconds = min(
            measured_elapsed_milliseconds,
            reservation.payload.reserved_compute_milliseconds,
        )
        measured_license_milliseconds = (
            0 if license_started is None else _elapsed_milliseconds(license_started, finished)
        )
        deadline_overrun = (
            measured_elapsed_milliseconds > reservation.payload.reserved_compute_milliseconds
            or measured_license_milliseconds > reservation.payload.reserved_license_milliseconds
        )
        if license_started is None:
            license_milliseconds = 0
        elif release_failed:
            license_milliseconds = reservation.payload.reserved_license_milliseconds
            elapsed_milliseconds = max(elapsed_milliseconds, license_milliseconds)
        else:
            license_milliseconds = min(
                elapsed_milliseconds,
                measured_license_milliseconds,
                reservation.payload.reserved_license_milliseconds,
            )
        if (
            budget_failure is None
            and reservation.compute_limit_failure is not None
            and elapsed_milliseconds >= reservation.payload.reserved_compute_milliseconds
        ):
            budget_failure = reservation.compute_limit_failure
        if (
            budget_failure is None
            and reservation.license_limit_failure is not None
            and license_milliseconds >= reservation.payload.reserved_license_milliseconds
        ):
            budget_failure = reservation.license_limit_failure
        if result is None:
            outcome = (
                ToolObservationOutcome.INFRASTRUCTURE_FAILURE
                if release_failed or pre_execution_outcome is None
                else pre_execution_outcome
            )
            evidence = ParticipantToolExecutionEvidence(
                run_id=self._journal.header.run_id,
                request_interaction_id=request_interaction_id,
                invocation_digest=plan.digest,
                input_manifest_digest=plan.input_manifest_digest,
                operation_id=operation.operation_id,
                operation_digest=operation.digest,
                tool_id=plan.tool_id,
                capability=plan.capability,
                executor_id=self._journal.header.binding.environment.executor_id,
                outcome=outcome,
                elapsed_milliseconds=elapsed_milliseconds,
                license_milliseconds=license_milliseconds,
            )
            return evidence, (), budget_failure, storage_lease

        prefix = _derived_identifier(
            "tool-artifact",
            {"invocation_digest": plan.digest, "run_id": self._journal.header.run_id},
            domain="participant-tool-artifact-id-v1",
        )
        stdout = self._artifact_record(
            logical_id=f"{prefix}.stdout",
            blob=result.stdout,
            media_type="application/octet-stream",
            artifact_class=ArtifactClass.DIAGNOSTIC,
        )
        stderr = self._artifact_record(
            logical_id=f"{prefix}.stderr",
            blob=result.stderr,
            media_type="application/octet-stream",
            artifact_class=ArtifactClass.DIAGNOSTIC,
        )
        output_records = self._operation_output_records(plan, result)
        outcome = (
            ToolObservationOutcome.INFRASTRUCTURE_FAILURE
            if release_failed
            else (
                ToolObservationOutcome.TIMEOUT if deadline_overrun else _observation_outcome(result)
            )
        )
        evidence = ParticipantToolExecutionEvidence(
            run_id=self._journal.header.run_id,
            request_interaction_id=request_interaction_id,
            invocation_digest=plan.digest,
            input_manifest_digest=plan.input_manifest_digest,
            operation_id=operation.operation_id,
            operation_digest=operation.digest,
            tool_id=plan.tool_id,
            capability=plan.capability,
            executor_id=self._journal.header.binding.environment.executor_id,
            outcome=outcome,
            executor_state=result.state.state,
            failure=result.state.failure,
            exit_code=result.state.exit_code,
            elapsed_milliseconds=elapsed_milliseconds,
            license_milliseconds=license_milliseconds,
            stdout_artifact_id=stdout.logical_id,
            stderr_artifact_id=stderr.logical_id,
            output_artifact_ids=tuple(record.logical_id for record in output_records),
        )
        return evidence, (stdout, stderr, *output_records), budget_failure, storage_lease

    def _acquire_license(
        self,
        tool: ToolBinding,
        invocation_id: str,
    ) -> LicenseLease:
        binding_id = tool.license_binding_id
        if binding_id is None:
            raise ValueError("license acquisition requires a licensed tool")
        binding = next(
            item for item in self._environment.licenses if item.license_binding_id == binding_id
        )
        provider = self._license_providers.get(binding.provider_id)
        if provider is None:
            self._record_license_denied(
                invocation_id=invocation_id,
                tool=tool,
                reason=LicenseDenialReason.PROVIDER_UNAVAILABLE,
            )
            raise LicenseUnavailable("bound license provider is unavailable")
        try:
            lease = provider.acquire(
                feature_class=binding.feature_class,
                run_id=self._journal.header.run_id,
                ttl_seconds=binding.lease_ttl_seconds,
            )
        except LicenseUnavailable:
            self._record_license_denied(
                invocation_id=invocation_id,
                tool=tool,
                reason=LicenseDenialReason.FEATURE_UNAVAILABLE,
            )
            raise
        except Exception as error:
            self._record_license_denied(
                invocation_id=invocation_id,
                tool=tool,
                reason=LicenseDenialReason.PROVIDER_FAILURE,
            )
            raise _ParticipantLicenseCustodyError(
                "license provider failed without a custody result"
            ) from error
        if (
            lease.provider_id != binding.provider_id
            or lease.feature_class != binding.feature_class
            or lease.state is not LeaseState.ACTIVE
        ):
            try:
                released = provider.release(lease) is LeaseState.RELEASED
            except Exception:
                released = False
            self._record_license_denied(
                invocation_id=invocation_id,
                tool=tool,
                reason=LicenseDenialReason.INVALID_LEASE,
            )
            if not released:
                raise _ParticipantLicenseCustodyError("invalid license lease could not be released")
            raise LicenseUnavailable("license provider returned an invalid lease")
        try:
            self._journal.transact(
                lambda state: LicenseLeaseAcquiredEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=self._event_id_factory(),
                    timestamp=self._clock(),
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.VERIFIER,
                    payload=LicenseLeaseAcquiredPayload(
                        job_id=invocation_id,
                        license_binding_id=binding.license_binding_id,
                        provider_id=binding.provider_id,
                        feature_class=binding.feature_class,
                    ),
                )
            )
        except Exception as error:
            with suppress(Exception):
                provider.release(lease)
            raise _ParticipantLicenseCustodyError(
                "license acquisition could not be journaled"
            ) from error
        return lease

    def _record_license_denied(
        self,
        *,
        invocation_id: str,
        tool: ToolBinding,
        reason: LicenseDenialReason,
    ) -> None:
        binding_id = tool.license_binding_id
        if binding_id is None:
            raise ValueError("license denial requires a licensed tool")
        binding = next(
            item for item in self._environment.licenses if item.license_binding_id == binding_id
        )
        self._journal.transact(
            lambda state: LicenseLeaseDeniedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=LicenseLeaseDeniedPayload(
                    job_id=invocation_id,
                    license_binding_id=binding.license_binding_id,
                    provider_id=binding.provider_id,
                    feature_class=binding.feature_class,
                    reason=reason,
                ),
            )
        )

    def _release_license(
        self,
        *,
        invocation_id: str,
        tool: ToolBinding,
        lease: LicenseLease,
    ) -> bool:
        binding_id = tool.license_binding_id
        if binding_id is None:
            raise ValueError("license release requires a licensed tool")
        binding = next(
            item for item in self._environment.licenses if item.license_binding_id == binding_id
        )
        provider = self._license_providers.get(binding.provider_id)
        try:
            released = provider is not None and provider.release(lease) is LeaseState.RELEASED
        except Exception:
            released = False
        timestamp = self._clock()
        event_id = self._event_id_factory()
        if released:
            self._journal.transact(
                lambda state: LicenseLeaseReleasedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.VERIFIER,
                    payload=LicenseLeaseReleasedPayload(
                        job_id=invocation_id,
                        license_binding_id=binding.license_binding_id,
                        provider_id=binding.provider_id,
                        feature_class=binding.feature_class,
                    ),
                )
            )
        else:
            self._journal.transact(
                lambda state: LicenseLeaseLostEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.VERIFIER,
                    payload=LicenseLeaseLostPayload(
                        job_id=invocation_id,
                        license_binding_id=binding.license_binding_id,
                        provider_id=binding.provider_id,
                        feature_class=binding.feature_class,
                    ),
                )
            )
        return not released

    def _artifact_record(
        self,
        *,
        logical_id: str,
        blob: BlobRef,
        media_type: str,
        artifact_class: ArtifactClass,
    ) -> ArtifactRecord:
        disclosure = self._environment.artifact_policy.persistent_disclosure(artifact_class)
        if disclosure is None:
            raise ValueError("participant tool artifact class is not retainable")
        return ArtifactRecord(
            logical_id=logical_id,
            blob=blob,
            media_type=media_type,
            artifact_class=artifact_class,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )

    def _operation_output_records(
        self,
        plan: InvocationPlan,
        result: ExecutionResult,
    ) -> tuple[ArtifactRecord, ...]:
        declarations = {item.logical_id: item for item in plan.outputs}
        outputs = {item.logical_id: item for item in result.outputs}
        if len(outputs) != len(result.outputs) or set(outputs) - declarations.keys():
            raise ValueError("participant executor returned undeclared or duplicate outputs")
        if {item.logical_id for item in plan.outputs if item.required} - outputs.keys():
            raise ValueError("participant executor omitted a required operation output")
        records = []
        for logical_id, output in sorted(outputs.items()):
            declaration = declarations[logical_id]
            if (
                output.media_type != declaration.media_type
                or output.artifact_class is not declaration.artifact_class
            ):
                raise ValueError("participant executor output differs from its operation")
            records.append(
                self._artifact_record(
                    logical_id=_derived_identifier(
                        "tool-output",
                        {
                            "invocation_digest": plan.digest,
                            "logical_id": logical_id,
                        },
                        domain="participant-tool-output-id-v1",
                    ),
                    blob=output.blob,
                    media_type=output.media_type,
                    artifact_class=output.artifact_class,
                )
            )
        return tuple(records)

    def _store_evidence(
        self,
        evidence: ParticipantToolExecutionEvidence,
    ) -> ArtifactRecord:
        disclosure = self._environment.artifact_policy.persistent_disclosure(ArtifactClass.EVIDENCE)
        if disclosure is None:
            raise ValueError("participant tool execution evidence is not retainable")
        blob = self._store.put_bytes(
            canonical_bytes(evidence),
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
        logical_id = _derived_identifier(
            "tool-evidence",
            {"digest": evidence.digest, "run_id": evidence.run_id},
            domain="participant-tool-evidence-id-v1",
        )
        return self._artifact_record(
            logical_id=logical_id,
            blob=blob,
            media_type=TOOL_EXECUTION_MEDIA_TYPE,
            artifact_class=ArtifactClass.EVIDENCE,
        )

    def _record_artifacts_and_settlement(
        self,
        *,
        records: tuple[ArtifactRecord, ...],
        evidence_record: ArtifactRecord,
        evidence: ParticipantToolExecutionEvidence,
        reservation: ParticipantToolReservedPayload,
    ) -> None:
        timestamp = self._clock()
        event_ids = tuple(self._event_id_factory() for _ in range(len(records) + 1))

        def events(state: RunState) -> tuple[RunEvent, ...]:
            existing = {record.logical_id for record in state.artifacts}
            if existing.intersection(record.logical_id for record in records):
                raise ValueError("participant tool artifact identity is already registered")
            artifact_events = tuple(
                ArtifactRecordedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence + offset,
                    event_id=event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.AUTHOR,
                    payload=ArtifactRecordedPayload(record=record),
                )
                for offset, (event_id, record) in enumerate(
                    zip(event_ids[:-1], records, strict=True)
                )
            )
            return (
                *artifact_events,
                ParticipantToolSettledEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence + len(records),
                    event_id=event_ids[-1],
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.AUTHOR,
                    artifact_refs=(evidence_record.logical_id,),
                    payload=ParticipantToolSettledPayload(
                        request_interaction_id=reservation.request_interaction_id,
                        invocation_id=reservation.invocation_id,
                        invocation_digest=reservation.invocation_digest,
                        operation_id=reservation.operation_id,
                        operation_digest=reservation.operation_digest,
                        input_manifest_digest=reservation.input_manifest_digest,
                        evidence_artifact_id=evidence_record.logical_id,
                        elapsed_milliseconds=evidence.elapsed_milliseconds,
                        license_milliseconds=evidence.license_milliseconds,
                    ),
                ),
            )

        self._journal.transact_events(events)


class CampaignTrialDispatcher:
    """Validate, dispatch, resume, and atomically settle one scheduled trial."""

    def __init__(self, runner: CampaignRunner) -> None:
        self.runner = runner

    def dispatch(
        self,
        *,
        trial_id: str,
        task: TaskSpec,
        instance: TaskInstance,
        release: ReleaseManifest,
        environment: EnvironmentSpec,
        session: SessionSpec,
        sender: MeteredResponsesParticipantSender,
        instruction: str,
        run_state_root: Path,
        runtime_root: Path,
        artifact_store: ContentAddressedStore,
        executor: Executor,
        evaluators: Sequence[EvaluatorRuntime],
        participant_files: Mapping[str, Path],
        asset_source_policy: AssetSourcePolicy,
        continuation: CampaignTrialContinuation | None = None,
        evaluator_asset_paths: Mapping[str, Path] | None = None,
        tool_asset_paths: Mapping[str, Path] | None = None,
        license_providers: Mapping[str, LicenseProvider] | None = None,
        provider_spend: SpendObservation | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        event_id_factory: Callable[[], UUID] = uuid4,
        request_id_factory: Callable[[], UUID] = uuid4,
        poll_interval_seconds: float = 0.05,
    ) -> CampaignTrialResult:
        if not isinstance(sender, MeteredResponsesParticipantSender):
            raise ValueError("campaign trials require the metered Responses campaign sender")
        if type(asset_source_policy) is not AssetSourcePolicy:
            raise ValueError("campaign trials require trusted asset source authority")
        trial = _scheduled_trial(self.runner, trial_id)
        harness = trial.binding.harness
        if not isinstance(harness, MeteredProviderHarnessBinding):
            raise ValueError("native CLI cells require a native campaign dispatcher")
        campaign_task = _campaign_task(self.runner, trial)
        campaign_binding = campaign_trial_run_binding(self.runner, trial)
        _validate_trial_inputs(
            runner=self.runner,
            trial=trial,
            campaign_task=campaign_task,
            instance=instance,
            task=task,
            release=release,
            environment=environment,
            session=session,
        )
        expected_surface_binding = runtime_surface_binding_for_trial(
            runner=self.runner,
            trial=trial,
            task=task,
            release=release,
            environment=environment,
            session=session,
        )
        if (
            sender.provider_canary_evidence.runtime_surface_manifest.binding
            != expected_surface_binding
        ):
            raise ValueError("provider preflight differs from the scheduled trial")
        runtime_clock = clock if clock is not None else lambda: datetime.now(UTC)
        plan = resolve_run(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=trial.trial_id,
            campaign=campaign_binding,
        )
        run_header = RunHeader.from_binding(plan.binding)
        journal = TrialJournal.create(run_state_root, run_header, task)
        if continuation is None:
            if len(session.actors) != 1:
                raise ValueError("multi-actor campaign trials require an existing-run continuation")
        else:
            _validate_campaign_continuation(
                continuation,
                journal=journal,
                plan_binding=plan.binding,
                runner=self.runner,
                trial=trial,
                session=session,
            )
        prepared_workspace = prepare_trial_workspace(
            runtime_root=runtime_root,
            journal=journal,
            environment=environment,
            session=session,
            release=release,
            participant_files=participant_files,
        )
        workspace = prepared_workspace.workspace
        artifact_directory = prepared_workspace.artifact_directory
        if prepared_workspace.resume_checkpoint_id is not None:
            self.runner.recover_incomplete_provider_dispatches(
                trial_id=trial.trial_id,
                provider_requests=journal.state().provider_requests,
            )
            with participant_dispatch_lock(journal.directory):
                reconcile_interrupted_run_work(
                    journal=journal,
                    executor=executor,
                    environment=environment,
                    timestamp=runtime_clock(),
                    event_id_factory=event_id_factory,
                )
                restore_participant_incarnation(
                    journal=journal,
                    environment=environment,
                    artifact_store=artifact_store,
                    workspace=workspace,
                    artifact_directory=artifact_directory,
                    checkpoint_id=prepared_workspace.resume_checkpoint_id,
                    timestamp=runtime_clock,
                    event_id_factory=event_id_factory,
                )
        evaluator_assets = {} if evaluator_asset_paths is None else dict(evaluator_asset_paths)
        tool_assets = {} if tool_asset_paths is None else dict(tool_asset_paths)
        providers = {} if license_providers is None else dict(license_providers)
        normalized_writable = tuple(
            sorted(
                {
                    path
                    for operation in environment.participant_operations
                    for path in operation.candidate_input_paths
                }
            )
        )
        read_paths = tuple(
            sorted(
                {
                    *(participant_release_paths(release)),
                    *normalized_writable,
                    *(
                        path
                        for operation in environment.participant_operations
                        for path in operation.output_paths
                    ),
                }
            )
        )
        tools: list[ResponsesParticipantTool] = [WorkspaceReadTool(workspace, paths=read_paths)]
        if environment.participant_operations:
            tool_dispatcher = ExecutorParticipantToolDispatcher(
                journal=journal,
                environment=environment,
                session=session,
                artifact_store=artifact_store,
                executor=executor,
                workspace=workspace,
                artifact_directory=artifact_directory,
                asset_paths=tool_assets,
                asset_source_policy=asset_source_policy,
                license_providers=providers,
                protected_paths=(self.runner.journal.directory,),
                clock=runtime_clock,
                monotonic=monotonic,
                poll_interval_seconds=poll_interval_seconds,
                event_id_factory=event_id_factory,
            )
            tools.append(EdaInvocationTool(tool_dispatcher))
        elif tool_assets:
            raise ValueError("tool assets require at least one participant operation")
        if normalized_writable:
            tools.append(WorkspaceWriteTool(workspace, paths=normalized_writable))
        runtime_holder: dict[str, RunOrchestrator] = {}
        if session.recovery is not RecoveryPolicy.NONE:
            tools.append(
                CheckpointParticipantTool(
                    lambda checkpoint_id: _checkpoint_observation(
                        runtime_holder,
                        checkpoint_id,
                    )
                )
            )
        actor = campaign_trial_harness_actor(trial, session)
        admission = CampaignParticipantAdmission(
            run_id=plan.binding.digest,
            task_release_digest=release.digest,
            environment_spec_digest=environment.digest,
            session_spec_digest=session.digest,
            trial_key=trial.trial_id,
            campaign=campaign_binding,
            actor_id=actor.actor_id,
            harness_id=trial.binding.harness.harness_id,
            harness_digest=trial.binding.harness_digest,
            scaffold_digest=trial.binding.harness.scaffold_digest,
            provider_profile_digest=trial.binding.harness.provider_profile_digest,
            provider_config_digest=trial.binding.harness.provider_config_digest,
            requested_model=trial.binding.requested_model,
            instruction_digest=responses_instruction_digest(instruction),
            tool_schema_digest=responses_tool_schema_digest(
                tuple(tool.definition for tool in tools)
            ),
            maximum_requests_per_action=(harness.maximum_requests_per_action),
            budget_binding_digest=self.runner.budget_projection().digest,
        )
        responses_participant = ResponsesParticipantAdapter(
            actor_id=actor.actor_id,
            journal=journal,
            environment=environment,
            session=session,
            artifact_store=artifact_store,
            sender=sender,
            instruction=instruction,
            token_claim=RequestTokenClaim(
                input_tokens=self.runner.header.benchmark.episode_budget.max_input_tokens_per_request,
                output_tokens=self.runner.header.benchmark.episode_budget.max_output_tokens_per_request,
                observed_input_token_floor=(trial.binding.observed_input_token_floor),
            ),
            tools=tuple(tools),
            usage_policy=ProviderUsagePolicy.EXACT,
            maximum_requests_per_action=harness.maximum_requests_per_action,
            campaign_admission=admission,
            reasoning_effort=trial.binding.reasoning_effort,
            service_tier=trial.binding.service_tier,
            clock=runtime_clock,
            event_id_factory=event_id_factory,
            request_id_factory=request_id_factory,
        )
        participant = (
            responses_participant
            if continuation is None
            else AdmittedCampaignContinuationAdapter(
                journal,
                session,
                responses_participant,
            )
        )
        runtime = RunOrchestrator.create(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=trial.trial_id,
            campaign=campaign_binding,
            state_root=run_state_root,
            workspace=workspace,
            artifact_directory=artifact_directory,
            artifact_store=artifact_store,
            executor=executor,
            evaluators=evaluators,
            participant=participant,
            asset_paths=evaluator_assets,
            license_providers=providers,
            clock=runtime_clock,
            event_id_factory=event_id_factory,
            poll_interval_seconds=poll_interval_seconds,
        )
        runtime_holder["runtime"] = runtime
        if runtime.plan != plan:
            raise RuntimeError("campaign run resolution changed during construction")

        self.runner.recover_incomplete_provider_dispatches(
            trial_id=trial.trial_id,
            provider_requests=journal.state().provider_requests,
        )
        reservation = self.runner.resume_work_reservation(trial_id=trial.trial_id)
        if continuation is not None and (reservation is None or not reservation.dispatched):
            raise CampaignAccountingError(
                "campaign continuation requires its existing dispatched work reservation"
            )
        if reservation is None:
            reservation = self.runner.reserve_work(
                trial_id=trial.trial_id,
                claim=_run_work_claim(session),
            )
        if reservation.claim != _run_work_claim(session):
            raise CampaignAccountingError("resumed run work claim differs from the session")
        if not reservation.dispatched:
            reservation.mark_dispatched()

        runtime.recover_interrupted()
        state = runtime.run_to_completion()
        self.runner.recover_incomplete_provider_dispatches(
            trial_id=trial.trial_id,
            provider_requests=state.provider_requests,
        )
        spend = (
            UnknownSpend(reason=UnknownSpendReason.PROVIDER_REPORTING_UNAVAILABLE)
            if provider_spend is None
            else provider_spend
        )
        outcome = TrialRunOutcome.from_run_state(
            state,
            run_binding=plan.binding,
            provider_spend=spend,
        )
        resources = project_campaign_trial_run_evidence(
            journal.record(),
            task,
            artifact_store,
        ).resources
        reservation.finalize_run(actual=resources, outcome=outcome)
        campaign_record = self.runner.journal.record()
        return CampaignTrialResult(
            trial_id=trial.trial_id,
            run_id=state.run_id,
            run_record_digest=journal.integrity_digest(),
            campaign_record_digest=campaign_record.integrity_digest,
            resources=resources,
            outcome=outcome,
        )


def _validate_campaign_continuation(
    continuation: CampaignTrialContinuation,
    *,
    journal: TrialJournal,
    plan_binding: RunBinding,
    runner: CampaignRunner,
    trial: ScheduledTrial,
    session: SessionSpec,
) -> None:
    if type(continuation) is not CampaignTrialContinuation:
        raise TypeError("campaign continuation requires its exact typed snapshot")
    events = journal.read_events()
    state = journal.state()
    actor = campaign_trial_harness_actor(trial, session)
    if (
        len(session.actors) <= 1
        or not events
        or state.terminal_reason is not None
        or journal.header.binding != plan_binding
        or continuation.run_binding != plan_binding
        or continuation.run_record_digest != journal.integrity_digest()
        or continuation.current_harness_actor_id != state.current_writer
        or continuation.current_harness_actor_id != actor.actor_id
        or continuation.campaign_budget_binding_digest != runner.budget_projection().digest
    ):
        raise ValueError("campaign continuation differs from the active hybrid run")


def _scheduled_trial(runner: CampaignRunner, trial_id: str) -> ScheduledTrial:
    matches = tuple(trial for trial in runner.schedule.trials if trial.trial_id == trial_id)
    if len(matches) != 1:
        raise ValueError("trial is not a unique member of the frozen campaign schedule")
    pending = {trial.trial_id for trial in runner.pending_trials()}
    if trial_id not in pending:
        raise ValueError("campaign trial already has a terminal outcome")
    return matches[0]


def _campaign_task(runner: CampaignRunner, trial: ScheduledTrial) -> CampaignTask:
    matches = tuple(
        task
        for task in runner.tasks
        if task.task_release_digest == trial.binding.task_release_digest
    )
    if len(matches) != 1:
        raise ValueError("scheduled trial has no unique campaign task")
    return matches[0]


def _validate_trial_inputs(
    *,
    runner: CampaignRunner,
    trial: ScheduledTrial,
    campaign_task: CampaignTask,
    instance: TaskInstance,
    task: TaskSpec,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> None:
    binding = trial.binding
    if (
        binding.campaign_digest != runner.campaign.digest
        or binding.task_release_digest != release.digest
        or binding.task_family != task.identity.family
        or binding.task_origin != task.identity.origin
        or binding.environment_digest != environment.digest
        or campaign_task.task_family != task.identity.family
        or campaign_task.task_origin != task.identity.origin
        or campaign_task.environment_digest != environment.digest
        or binding.task_instance_digest != instance.digest
        or release.task_instance_digest != instance.digest
        or campaign_task.task_instance_digest != instance.digest
    ):
        raise ValueError("campaign trial inputs differ from the frozen schedule")
    require_paid_campaign_task_origin(task.identity.origin)
    if set(campaign_task.evaluator_stage_ids) != {
        stage.stage_id for stage in task.evaluation.stages
    }:
        raise ValueError("campaign task evaluator stages differ from the TaskSpec")
    task_capabilities = {evaluator.capability for evaluator in task.evaluation.evaluators}
    if binding.device_capability not in task_capabilities:
        raise ValueError("campaign device capability is absent from the TaskSpec")
    actor = campaign_trial_harness_actor(trial, session)
    if (
        actor.harness_id != binding.harness.harness_id
        or actor.harness_digest != binding.harness_digest
        or actor.scaffold_digest != binding.harness.scaffold_digest
        or actor.requested_model_route != binding.requested_model
        or canonical_digest(session.feedback, domain="feedback-policy-v1")
        != binding.evaluation_cell.policy.feedback_policy_digest
    ):
        raise ValueError("campaign session differs from the scheduled metered harness")
    model = session.model_budget
    if model is None:
        raise ValueError("campaign session requires a provider model budget")
    budget = runner.header.benchmark.episode_budget
    if model != budget.model_budget or session.resources != budget.resources:
        raise ValueError("session budgets differ from the frozen benchmark episode budget")
    harness = binding.harness
    if not isinstance(harness, MeteredProviderHarnessBinding):
        raise ValueError("native CLI cells require a native campaign dispatcher")
    if harness.maximum_requests_per_action > model.max_requests:
        raise ValueError("campaign harness request bound exceeds its session budget")


def _run_work_claim(session: SessionSpec) -> CampaignResources:
    resources = session.resources
    return CampaignResources(
        turns=resources.max_turns,
        tool_calls=resources.max_tool_calls,
        wall_seconds=resources.max_wall_seconds,
        eda_compute_seconds=resources.max_eda_compute_seconds,
        license_seconds=resources.max_license_seconds,
        artifact_bytes=resources.max_artifact_bytes,
    )


def _pending_tool_request(journal: TrialJournal, actor_id: str) -> str:
    events = journal.read_events()
    if not events:
        raise ValueError("participant tool invocation requires a started run")
    event = events[-1]
    if (
        not isinstance(event, InteractionRecordedEvent)
        or event.producer is not ProducerKind.PARTICIPANT
        or event.actor != actor_id
        or event.payload.direction is not InteractionDirection.TOOL_REQUEST
        or event.payload.tool_name != EXECUTOR_PARTICIPANT_TOOL_NAME
    ):
        raise ValueError("participant tool invocation lacks its journaled request")
    return event.payload.interaction_id


def _observation_outcome(result: ExecutionResult) -> ToolObservationOutcome:
    failure = result.state.failure
    if result.state.state is ExecutorJobStateKind.COMPLETED:
        return ToolObservationOutcome.PASSED
    if failure is ExecutionFailureKind.CANDIDATE:
        return ToolObservationOutcome.CANDIDATE_FAILURE
    if failure is ExecutionFailureKind.TIMEOUT:
        return ToolObservationOutcome.TIMEOUT
    if failure is ExecutionFailureKind.LICENSE_UNAVAILABLE:
        return ToolObservationOutcome.LICENSE_UNAVAILABLE
    if failure is ExecutionFailureKind.SECURITY_VIOLATION:
        return ToolObservationOutcome.SECURITY_VIOLATION
    return ToolObservationOutcome.INFRASTRUCTURE_FAILURE


def _tool_summary(evidence: ParticipantToolExecutionEvidence) -> str:
    summaries = {
        ToolObservationOutcome.PASSED: "tool invocation completed",
        ToolObservationOutcome.CANDIDATE_FAILURE: "tool rejected the current workspace",
        ToolObservationOutcome.TIMEOUT: "tool invocation reached its time bound",
        ToolObservationOutcome.LICENSE_UNAVAILABLE: "tool license was unavailable",
        ToolObservationOutcome.INFRASTRUCTURE_FAILURE: "tool infrastructure failed",
        ToolObservationOutcome.SECURITY_VIOLATION: "tool invocation violated policy",
    }
    return summaries[evidence.outcome]


def _checkpoint_observation(
    holder: Mapping[str, RunOrchestrator],
    checkpoint_id: str,
) -> ToolObservation:
    runtime = holder.get("runtime")
    if runtime is None:
        raise RuntimeError("campaign runtime is not ready to checkpoint")
    marker, state = runtime.checkpoint(checkpoint_id)
    records = {
        record.logical_id: record
        for record in state.artifacts
        if record.artifact_class is ArtifactClass.CHECKPOINT and record.blob == marker.manifest_blob
    }
    if len(records) != 1:
        raise RuntimeError("checkpoint marker has no unique run artifact")
    return ToolObservation(
        outcome=ToolObservationOutcome.PASSED,
        summary="checkpoint committed",
        artifact_refs=tuple(records),
    )


def _datetime_milliseconds(started: datetime, finished: datetime) -> int:
    return math.ceil(max(0.0, (finished - started).total_seconds()) * 1000)


def _elapsed_milliseconds(started: float, finished: float) -> int:
    return math.ceil(max(0.0, finished - started) * 1000)


def _participant_tool_deadline(
    reservation: _ToolDispatchReservation,
    *,
    started: float,
    license_started: float | None,
    now: float,
) -> tuple[bool, ParticipantFailureKind | None]:
    if _elapsed_milliseconds(started, now) >= reservation.payload.reserved_compute_milliseconds:
        return True, reservation.compute_limit_failure
    if (
        license_started is not None
        and _elapsed_milliseconds(license_started, now)
        >= reservation.payload.reserved_license_milliseconds
    ):
        return True, reservation.license_limit_failure
    return False, None


def _derived_identifier(prefix: str, value: object, *, domain: str) -> str:
    digest = canonical_digest(value, domain=domain).removeprefix("sha256:")
    return f"{prefix}_{digest[:48]}"
