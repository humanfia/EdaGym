"""Journal-driven orchestration for participant and evaluator execution."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock, RLock
from uuid import UUID, uuid4

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.evaluation.model import (
    ArtifactEvidence,
    EvidenceKind,
    HardGateState,
    InfrastructureFailureOutcome,
    LicenseUnavailableOutcome,
    OutcomeKind,
    ScorerEligibilityKind,
    ScoringDecision,
    SecurityViolationOutcome,
    StageEligibilityKind,
    StageOutcome,
    StageResult,
)
from edagym.evaluation.promotion import (
    hard_gate_status,
    scorer_eligibility,
    stage_eligibility,
    topological_stage_ids,
)
from edagym.evaluation.scoring import build_candidate_score
from edagym.executors.licenses import (
    LeaseState,
    LicenseLease,
    LicenseProvider,
    LicenseUnavailable,
)
from edagym.executors.model import (
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
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
from edagym.participant_tool_protocol import EXECUTOR_PARTICIPANT_TOOL_NAME
from edagym.participants.adapters import (
    ParticipantAdapter,
    ParticipantAdapterError,
    ParticipantFailureKind,
)
from edagym.participants.controller import CandidateSnapshot, ParticipantController
from edagym.participants.execution import (
    participant_dispatch_lock,
)
from edagym.participants.model import SubmitCandidateIntent
from edagym.resolution import ResolvedRunPlan, StageDriverAssignment, resolve_run
from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    RAW_MEASUREMENT_LINKS_MEDIA_TYPE,
    SANITIZED_MEASUREMENTS_MEDIA_TYPE,
    ArtifactIntegrityError,
    ArtifactPolicyViolation,
    ArtifactQuotaExceeded,
    CheckpointMarker,
    ContentAddressedStore,
    RawMeasurementLink,
    RawMeasurementLinks,
    SanitizedMeasurement,
    SanitizedMeasurements,
    candidate_snapshot_artifact_id,
    manifest_paths,
    manifest_tree,
    restore_manifest,
)
from edagym.run.checkpoints import (
    commit_application_checkpoint,
    commit_workspace_checkpoint,
)
from edagym.run.journal_storage import EventConflict
from edagym.run.materialization import populate_disposable_empty_directory
from edagym.run.trial_journal import TrialJournal, unresolved_tool_requests
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    CampaignTrialRunBinding,
    CandidateState,
    CandidateSubmittedEvent,
    EvaluationCompletedEvent,
    EvaluationCompletedPayload,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    LicenseDenialReason,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseAcquiredPayload,
    LicenseLeaseDeniedEvent,
    LicenseLeaseDeniedPayload,
    LicenseLeaseReleasedEvent,
    LicenseLeaseReleasedPayload,
    ParticipantIncarnationStartedEvent,
    ParticipantIncarnationStartedPayload,
    ProducerKind,
    RunEndedEvent,
    RunEndedPayload,
    RunEvent,
    RunHeader,
    RunLineage,
    RunPurpose,
    RunStartedEvent,
    RunStartedPayload,
    RunState,
    ScoringRecordedEvent,
    ScoringRecordedPayload,
    StopReason,
)
from edagym.runtime.budget import (
    RuntimeActionKind,
    RuntimeBudgetError,
    active_runtime_stop,
    budget_stop,
)
from edagym.runtime.errors import OrchestrationError
from edagym.runtime.execution import (
    evaluation_job_id,
    execution_artifact_id,
    execution_failure_outcome,
    run_job_state,
)
from edagym.runtime.model import (
    EvaluationArtifact,
    EvaluationArtifacts,
    EvaluationContext,
    EvaluatorRuntime,
)
from edagym.runtime.participant_recovery import (
    ParticipantRecoveryError,
    current_participant_incarnation,
    reconcile_interrupted_run_work,
    require_current_participant_incarnation,
    restore_participant_incarnation,
)
from edagym.runtime.paths import (
    require_private_runtime_directory,
    require_separate_runtime_paths,
)
from edagym.specs.common import ArtifactClass, Visibility
from edagym.specs.environment import (
    PROTECTED_RAW_DISCLOSURE,
    RAW_EDA_ARTIFACT_CLASSES,
    CheckpointCapability,
    EnvironmentSpec,
    FilesystemScope,
    LicenseBinding,
)
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import FeedbackPolicy, RecoveryPolicy, SessionSpec, TrainingMode
from edagym.specs.task import StageSpec, TaskSpec, WorkspaceInterface

_LOGGER = logging.getLogger(__name__)
_RUN_TERMINAL_STATES = frozenset(
    {JobStateKind.COMPLETED, JobStateKind.FAILED, JobStateKind.CANCELLED}
)
_EXECUTOR_TERMINAL_STATES = frozenset(
    {
        ExecutorJobStateKind.COMPLETED,
        ExecutorJobStateKind.FAILED,
        ExecutorJobStateKind.CANCELLED,
        ExecutorJobStateKind.TIMED_OUT,
        ExecutorJobStateKind.LOST,
    }
)
_PARTICIPANT_STOP_REASONS = {
    ParticipantFailureKind.RESPONSE_BOUND: StopReason.POLICY_FAILURE,
    ParticipantFailureKind.INVALID_INTENT: StopReason.POLICY_FAILURE,
    ParticipantFailureKind.ACTOR_MISMATCH: StopReason.POLICY_FAILURE,
    ParticipantFailureKind.CHANNEL_FAILURE: StopReason.INFRASTRUCTURE_FAILURE,
    ParticipantFailureKind.COMMAND_CANCELLED: StopReason.EXPLICIT_CANCEL,
    ParticipantFailureKind.COMMAND_EXIT: StopReason.INFRASTRUCTURE_FAILURE,
    ParticipantFailureKind.COMMAND_TIMEOUT: StopReason.INFRASTRUCTURE_FAILURE,
    ParticipantFailureKind.TOOL_BUDGET: StopReason.TOOL_CALL_BUDGET,
    ParticipantFailureKind.WALL_BUDGET: StopReason.WALL_BUDGET,
    ParticipantFailureKind.EDA_COMPUTE_BUDGET: StopReason.EDA_COMPUTE_BUDGET,
    ParticipantFailureKind.LICENSE_BUDGET: StopReason.LICENSE_BUDGET,
    ParticipantFailureKind.PROVIDER_BUDGET_OVERRUN: StopReason.PROVIDER_BUDGET_OVERRUN,
    ParticipantFailureKind.END_OF_INPUT: StopReason.INFRASTRUCTURE_FAILURE,
    ParticipantFailureKind.CANDIDATE_SNAPSHOT: StopReason.INFRASTRUCTURE_FAILURE,
}


class RunOrchestrator:
    """Advance one resolved run entirely through append-only journal facts."""

    def __init__(
        self,
        *,
        plan: ResolvedRunPlan,
        task: TaskSpec,
        instance: TaskInstance,
        release: ReleaseManifest,
        environment: EnvironmentSpec,
        session: SessionSpec,
        journal: TrialJournal,
        artifact_store: ContentAddressedStore,
        executor: Executor,
        evaluators: Sequence[EvaluatorRuntime],
        workspace: Path,
        artifact_directory: Path,
        participant: ParticipantAdapter | None,
        asset_paths: Mapping[str, Path],
        license_providers: Mapping[str, LicenseProvider],
        clock: Callable[[], datetime],
        event_id_factory: Callable[[], UUID],
        poll_interval_seconds: float,
    ) -> None:
        if poll_interval_seconds < 0:
            raise ValueError("poll interval cannot be negative")
        if artifact_store.policy != environment.artifact_policy:
            raise OrchestrationError("artifact store policy does not match the environment")
        if environment.licenses:
            if not artifact_store.encrypted:
                raise OrchestrationError("licensed execution requires managed artifact encryption")
            if any(
                environment.artifact_policy.persistent_disclosure(artifact_class)
                != PROTECTED_RAW_DISCLOSURE
                for artifact_class in RAW_EDA_ARTIFACT_CLASSES
            ):
                raise OrchestrationError(
                    "licensed raw diagnostics and evidence require author-only disclosure"
                )
        if journal.header.binding != plan.binding:
            raise OrchestrationError("journal binding does not match the resolved run")
        if task.digest != plan.binding.task.task_spec_digest:
            raise OrchestrationError("task does not match the resolved run")
        if instance.digest != plan.binding.task.instance_digest:
            raise OrchestrationError("task instance does not match the resolved run")
        if release.digest != plan.binding.task.release_digest:
            raise OrchestrationError("release does not match the resolved run")
        if environment.digest != plan.binding.environment.environment_spec_digest:
            raise OrchestrationError("environment does not match the resolved run")
        if session.digest != plan.binding.session.session_spec_digest:
            raise OrchestrationError("session does not match the resolved run")
        if plan.binding.campaign is not None and participant is None:
            raise OrchestrationError("campaign runs require an admitted participant")
        require_private_runtime_directory(artifact_directory)
        if workspace.exists():
            require_private_runtime_directory(workspace)
        require_separate_runtime_paths(
            workspace,
            journal.directory,
            artifact_directory,
            artifact_store.root,
        )

        self.plan = plan
        self.task = task
        self.instance = instance
        self.release = release
        self.environment = environment
        self.session = session
        self.journal = journal
        self.artifact_store = artifact_store
        self.executor = executor
        self.workspace = workspace
        self.artifact_directory = artifact_directory
        self.asset_paths = dict(asset_paths)
        self.license_providers = dict(license_providers)
        self._clock = clock
        self._event_id_factory = event_id_factory
        self._poll_interval_seconds = poll_interval_seconds
        self._evaluators = self._bind_evaluators(evaluators)
        self._participant = (
            None
            if participant is None
            else ParticipantController(
                journal,
                participant,
                session=session,
                snapshot_candidate=self._snapshot_candidate,
                event_id_factory=event_id_factory,
                clock=clock,
            )
        )
        self._operation_lock = RLock()
        self._active_lock = Lock()
        self._active_handle: JobHandle | None = None
        self._requested_stop: StopReason | None = None

    @classmethod
    def create(
        cls,
        *,
        task: TaskSpec,
        instance: TaskInstance,
        release: ReleaseManifest,
        environment: EnvironmentSpec,
        session: SessionSpec,
        trial_key: str,
        campaign: CampaignTrialRunBinding | None = None,
        purpose: RunPurpose | None = None,
        state_root: Path,
        workspace: Path,
        artifact_directory: Path,
        artifact_store: ContentAddressedStore,
        executor: Executor,
        evaluators: Sequence[EvaluatorRuntime],
        participant: ParticipantAdapter | None,
        lineage: RunLineage | None = None,
        asset_paths: Mapping[str, Path] | None = None,
        license_providers: Mapping[str, LicenseProvider] | None = None,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], UUID] = uuid4,
        poll_interval_seconds: float = 0.25,
    ) -> RunOrchestrator:
        """Resolve canonical inputs, open their run record, and start it once."""

        require_separate_runtime_paths(
            workspace,
            state_root,
            artifact_directory,
            artifact_store.root,
        )
        plan = resolve_run(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=trial_key,
            campaign=campaign,
            purpose=purpose,
            lineage=lineage,
        )
        header = RunHeader.from_binding(plan.binding)
        journal = TrialJournal.create(state_root, header, task)
        runtime_clock = clock if clock is not None else lambda: datetime.now(UTC)
        runtime = cls(
            plan=plan,
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            journal=journal,
            artifact_store=artifact_store,
            executor=executor,
            evaluators=evaluators,
            workspace=workspace,
            artifact_directory=artifact_directory,
            participant=participant,
            asset_paths={} if asset_paths is None else asset_paths,
            license_providers=({} if license_providers is None else license_providers),
            clock=runtime_clock,
            event_id_factory=event_id_factory,
            poll_interval_seconds=poll_interval_seconds,
        )
        runtime._start_once()
        return runtime

    @property
    def state(self) -> RunState:
        return self.journal.state()

    def advance(self) -> RunState:
        """Perform one participant action, stage evaluation, or terminal decision."""

        with self._operation_lock:
            return self._advance_once()

    def _advance_once(self) -> RunState:
        self._require_active_incarnation()
        state = self.state
        if state.terminal_reason is not None:
            return state
        if self._unresolved_evaluations(self.journal.read_events()):
            raise OrchestrationError(
                "the journal has an interrupted evaluation; recover it before advancing"
            )
        if unresolved_tool_requests(self.journal.read_events()):
            raise OrchestrationError(
                "the journal has an interrupted participant tool; recover it before advancing"
            )
        candidate = state.candidates[-1] if state.candidates else None
        if candidate is None:
            reason = self._budget_stop(RuntimeActionKind.PARTICIPANT)
            return self._end(reason) if reason is not None else self._act()

        results = tuple(
            item.result
            for item in state.stage_results
            if item.candidate_id == candidate.candidate_id
        )
        gate_status = hard_gate_status(self.task, results)
        scoring_recorded = any(
            item.candidate_id == candidate.candidate_id for item in state.scoring
        )
        if gate_status.state is not HardGateState.FAILED:
            ready = tuple(
                stage_id
                for stage_id in topological_stage_ids(self.task)
                if stage_eligibility(self.task, results, stage_id).state
                is StageEligibilityKind.READY
            )
            if ready:
                reason = self._budget_stop(RuntimeActionKind.EVALUATION, candidate=candidate)
                if reason is not None:
                    return self._end(reason)
                return self._execute_stage(candidate, self._stage(ready[0]))

        if not scoring_recorded:
            self._record_scoring(candidate, results)

        scoring = next(
            item for item in self.state.scoring if item.candidate_id == candidate.candidate_id
        )
        if isinstance(self.session.mode, TrainingMode):
            if scoring.decision.eligibility.state is ScorerEligibilityKind.BLOCKED:
                failure_reason = _scoring_failure_stop_reason(
                    results,
                    scoring.decision.eligibility.blocking_stage_ids,
                )
                if failure_reason is StopReason.SECURITY_FAILURE:
                    return self._end(failure_reason)
            reason = self._budget_stop(RuntimeActionKind.PARTICIPANT)
            return self._end(reason) if reason is not None else self._act()
        if gate_status.state is HardGateState.SUCCEEDED and scoring.decision.eligibility.state in {
            ScorerEligibilityKind.READY,
            ScorerEligibilityKind.NOT_CONFIGURED,
        }:
            return self._end(
                StopReason.VERIFIER_SUCCESS,
                candidate.candidate_id,
            )

        return self._end(
            _scoring_failure_stop_reason(
                results,
                scoring.decision.eligibility.blocking_stage_ids,
            )
        )

    def run_to_completion(self) -> RunState:
        """Advance synchronously until the journal reaches a terminal state."""

        state = self.state
        while state.terminal_reason is None:
            state = self.advance()
        return state

    def cancel(self) -> RunState:
        """Request cancellation and durably terminate once active work is settled."""

        with self._active_lock:
            self._requested_stop = StopReason.EXPLICIT_CANCEL
            handle = self._active_handle
        if handle is not None:
            self.executor.cancel(handle)
            return self.state
        with self._operation_lock, participant_dispatch_lock(self.journal.directory):
            if self._unresolved_evaluations(self.journal.read_events()):
                return self.state
            self._recover_interrupted()
            return self._end(StopReason.EXPLICIT_CANCEL)

    def checkpoint(self, checkpoint_id: str) -> tuple[CheckpointMarker, RunState]:
        """Commit the current workspace through the environment checkpoint policy."""

        with self._operation_lock:
            return self._checkpoint(checkpoint_id)

    def _checkpoint(self, checkpoint_id: str) -> tuple[CheckpointMarker, RunState]:
        self._require_active_incarnation()
        if self.session.recovery is RecoveryPolicy.NONE:
            raise OrchestrationError("the session does not permit recovery")
        if self.environment.checkpoint is CheckpointCapability.NONE:
            raise OrchestrationError("the environment cannot checkpoint this workspace")
        if self.environment.checkpoint not in {
            CheckpointCapability.APPLICATION,
            CheckpointCapability.FILESYSTEM,
        }:
            raise OrchestrationError(
                "the runtime does not implement the environment checkpoint capability"
            )
        if (
            self.environment.checkpoint is CheckpointCapability.APPLICATION
            and self.environment.application_checkpoint is None
        ):
            raise OrchestrationError(
                "the runtime does not implement an unbound application checkpoint"
            )
        require_private_runtime_directory(self.workspace)
        state = self.state
        if state.terminal_reason is not None:
            raise OrchestrationError("a terminated run cannot create a checkpoint")
        if self._unresolved_evaluations(self.journal.read_events()):
            raise OrchestrationError("an active evaluation cannot be checkpointed")
        if unresolved_tool_requests(
            self.journal.read_events(),
            tool_name=EXECUTOR_PARTICIPANT_TOOL_NAME,
        ):
            raise OrchestrationError(
                "an active participant executor invocation cannot be checkpointed"
            )
        if checkpoint_id in state.checkpoint_ids:
            if self.environment.checkpoint is CheckpointCapability.FILESYSTEM:
                marker, _ = self.artifact_store.load_filesystem_checkpoint(checkpoint_id)
            else:
                binding = self.environment.application_checkpoint
                if binding is None:
                    raise OrchestrationError("application checkpoint binding is absent")
                marker, _ = self.artifact_store.load_application_checkpoint(
                    checkpoint_id,
                    driver_digest=binding.driver_digest,
                )
            return marker, state
        disclosure = self.environment.artifact_policy.persistent_disclosure(
            ArtifactClass.CHECKPOINT
        )
        if disclosure is None:
            raise OrchestrationError("checkpoint artifacts are not retainable")
        commit = (
            commit_workspace_checkpoint
            if self.environment.checkpoint is CheckpointCapability.FILESYSTEM
            else commit_application_checkpoint
        )
        return commit(
            store=self.artifact_store,
            journal=self.journal,
            environment=self.environment,
            workspace=self.workspace,
            checkpoint_id=checkpoint_id,
            artifact_id=execution_artifact_id(
                self.journal.header.run_id,
                checkpoint_id,
                "manifest",
            ),
            parent_checkpoint_id=(state.checkpoint_ids[-1] if state.checkpoint_ids else None),
            timestamp=self._clock(),
            artifact_event_id=self._event_id_factory(),
            checkpoint_event_id=self._event_id_factory(),
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )

    def resume(self, checkpoint_id: str) -> tuple[CheckpointMarker, RunState]:
        """Reconcile interrupted work and restore a committed workspace into a new path."""

        with self._operation_lock, participant_dispatch_lock(self.journal.directory):
            return self._resume(checkpoint_id)

    def _resume(self, checkpoint_id: str) -> tuple[CheckpointMarker, RunState]:
        if self.session.recovery is RecoveryPolicy.NONE:
            raise OrchestrationError("the session does not permit recovery")
        if self.environment.checkpoint not in {
            CheckpointCapability.APPLICATION,
            CheckpointCapability.FILESYSTEM,
        }:
            raise OrchestrationError(
                "the runtime does not implement the environment checkpoint capability"
            )
        if (
            self.environment.checkpoint is CheckpointCapability.APPLICATION
            and self.environment.application_checkpoint is None
        ):
            raise OrchestrationError(
                "the runtime does not implement an unbound application checkpoint"
            )
        state = self._recover_interrupted()
        if checkpoint_id not in state.checkpoint_ids:
            raise OrchestrationError("checkpoint is not committed by this run")
        try:
            return restore_participant_incarnation(
                journal=self.journal,
                environment=self.environment,
                artifact_store=self.artifact_store,
                workspace=self.workspace,
                artifact_directory=self.artifact_directory,
                checkpoint_id=checkpoint_id,
                timestamp=self._clock,
                event_id_factory=self._event_id_factory,
            )
        except ParticipantRecoveryError as error:
            raise OrchestrationError("participant incarnation recovery failed") from error

    def recover_interrupted(self) -> RunState:
        """Close journaled work whose executor process cannot be reattached."""

        with self._operation_lock, participant_dispatch_lock(self.journal.directory):
            return self._recover_interrupted()

    def _recover_interrupted(self) -> RunState:
        with self._active_lock:
            if self._active_handle is not None:
                raise OrchestrationError("an attached executor job cannot be recovered")
        try:
            return reconcile_interrupted_run_work(
                journal=self.journal,
                executor=self.executor,
                environment=self.environment,
                timestamp=self._clock(),
                event_id_factory=self._event_id_factory,
            )
        except Exception as error:
            raise OrchestrationError(
                "interrupted participant work could not be reconciled"
            ) from error

    def _start_once(self) -> None:
        if self.journal.read_events():
            return
        started = RunStartedEvent(
            run_id=self.journal.header.run_id,
            sequence=0,
            event_id=self._event_id_factory(),
            timestamp=self._clock(),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=self.plan.binding.digest),
        )
        requested: tuple[RunEvent, ...] = (started,)
        if self._participant is not None:
            incarnation = current_participant_incarnation(
                generation=0,
                workspace=self.workspace,
                artifact_directory=self.artifact_directory,
            )
            requested = (
                started,
                ParticipantIncarnationStartedEvent(
                    run_id=self.journal.header.run_id,
                    sequence=1,
                    event_id=self._event_id_factory(),
                    timestamp=self._clock(),
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.VERIFIER,
                    payload=ParticipantIncarnationStartedPayload(
                        incarnation=incarnation,
                    ),
                ),
            )
        try:
            self.journal.append_events(requested)
        except EventConflict:
            events = self.journal.read_events()
            if not events or not isinstance(events[0], RunStartedEvent):
                raise

    def _require_active_incarnation(self) -> None:
        if self._participant is None:
            return
        try:
            require_current_participant_incarnation(
                self.journal,
                workspace=self.workspace,
                artifact_directory=self.artifact_directory,
            )
        except ParticipantRecoveryError as error:
            raise OrchestrationError(
                "participant runtime does not own the active journal incarnation"
            ) from error

    def _bind_evaluators(
        self,
        evaluators: Sequence[EvaluatorRuntime],
    ) -> dict[str, EvaluatorRuntime]:
        indexed = {evaluator.evaluator_id: evaluator for evaluator in evaluators}
        expected = {item.evaluator_id: item for item in self.task.evaluation.evaluators}
        if len(indexed) != len(evaluators) or set(indexed) != set(expected):
            raise OrchestrationError("evaluator runtimes must exactly cover the task evaluators")
        assignments = {item.stage_id: item for item in self.plan.stage_drivers}
        for evaluator_id, runtime in indexed.items():
            if runtime.evaluator_revision_digest != expected[evaluator_id].revision_digest:
                raise OrchestrationError(
                    "evaluator runtime revision does not match the run binding"
                )
            stage_driver_digests = {
                assignments[stage.stage_id].driver_digest
                for stage in self.task.evaluation.stages
                if stage.evaluator_id == evaluator_id
            }
            if stage_driver_digests != {runtime.driver_digest}:
                raise OrchestrationError("evaluator runtime driver does not match the run binding")
        return indexed

    def _record_scoring(
        self,
        candidate: CandidateState,
        results: Sequence[StageResult],
    ) -> RunState:
        """Derive once, then atomically journal the sole terminal scoring fact.

        The scorer is a bounded pure task expression. Derivation happens before the
        transaction so an exception leaves the evaluated journal prefix retryable.
        """

        eligibility = scorer_eligibility(self.task, results)
        try:
            score = None
            if eligibility.state is ScorerEligibilityKind.READY:
                score = build_candidate_score(self.task, results)
            decision = ScoringDecision(eligibility=eligibility, score=score)
        except Exception as error:
            raise OrchestrationError("task-bound score derivation failed") from error
        return self.journal.transact(
            lambda state: ScoringRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.EVALUATOR,
                visibility=self._result_visibility(),
                payload=ScoringRecordedPayload(
                    candidate_id=candidate.candidate_id,
                    decision=decision,
                ),
            )
        )

    def _act(self) -> RunState:
        if self._participant is None:
            raise OrchestrationError("the run has no participant adapter")
        try:
            return self._participant.act_once()
        except ParticipantAdapterError as error:
            with participant_dispatch_lock(self.journal.directory):
                self._recover_interrupted()
                return self._end(_PARTICIPANT_STOP_REASONS[error.kind])

    def _snapshot_candidate(self, intent: SubmitCandidateIntent) -> CandidateSnapshot:
        """Bind a submission to an immutable CAS manifest before it is journaled."""

        require_private_runtime_directory(self.workspace)
        disclosure = self.environment.artifact_policy.persistent_disclosure(ArtifactClass.CANDIDATE)
        if disclosure is None:
            raise OrchestrationError("candidate artifacts are not retainable")
        if isinstance(self.task.interface, WorkspaceInterface):
            manifest = manifest_paths(
                self.artifact_store,
                self.workspace,
                self.task.interface.submission_paths,
                artifact_class=ArtifactClass.CANDIDATE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
        else:
            manifest = manifest_tree(
                self.artifact_store,
                self.workspace,
                artifact_class=ArtifactClass.CANDIDATE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
        committed = self.artifact_store.put_manifest(manifest)
        return CandidateSnapshot(
            record=ArtifactRecord(
                logical_id=candidate_snapshot_artifact_id(
                    self.journal.header.run_id,
                    intent.candidate_id,
                ),
                blob=committed.blob,
                media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
                artifact_class=ArtifactClass.CANDIDATE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            ),
        )

    def _candidate_workspace(self, job_id: str) -> Path:
        root = self.journal.directory / "evaluation-workspaces"
        with suppress(FileExistsError):
            root.mkdir(mode=0o700)
        require_private_runtime_directory(root)
        return root / job_id

    def _restore_candidate(
        self,
        candidate: CandidateState,
        destination: Path,
        *,
        disposable_workspace: bool = False,
    ) -> None:
        events = self.journal.read_events()
        candidate_events = tuple(
            event
            for event in events
            if isinstance(event, CandidateSubmittedEvent)
            and event.payload.candidate_id == candidate.candidate_id
        )
        artifact_events = tuple(
            event
            for event in events
            if isinstance(event, ArtifactRecordedEvent)
            and event.payload.record.logical_id
            == candidate_snapshot_artifact_id(
                self.journal.header.run_id,
                candidate.candidate_id,
            )
        )
        if len(candidate_events) != 1 or len(artifact_events) != 1:
            raise ArtifactIntegrityError(
                "candidate snapshot does not have one submission and registration"
            )
        candidate_event = candidate_events[0]
        artifact_event = artifact_events[0]
        record = artifact_event.payload.record
        if (
            not self.journal.events_committed_together(
                (artifact_event.event_id, candidate_event.event_id)
            )
            or artifact_event.sequence >= candidate_event.sequence
            or candidate_event.payload.candidate_digest != candidate.digest
            or record.artifact_class is not ArtifactClass.CANDIDATE
            or record.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE
            or record.blob.digest != candidate.digest
        ):
            raise ArtifactIntegrityError(
                "candidate submission is not atomically bound to its snapshot registration"
            )
        content = self.artifact_store.read_bytes(
            record.blob,
            maximum_bytes=record.blob.size_bytes,
        )
        try:
            manifest = ArtifactManifest.model_validate_json(content)
        except Exception as error:
            raise ArtifactIntegrityError("candidate snapshot manifest is invalid") from error
        if (
            canonical_bytes(manifest) != content
            or manifest.artifact_class is not ArtifactClass.CANDIDATE
            or manifest.sensitivity is not record.sensitivity
            or manifest.visibility is not record.visibility
            or manifest.redistribution is not record.redistribution
        ):
            raise ArtifactIntegrityError(
                "candidate snapshot manifest disagrees with its registration"
            )
        if disposable_workspace:
            populate_disposable_empty_directory(
                self.artifact_store,
                manifest,
                destination,
            )
        else:
            restore_manifest(self.artifact_store, manifest, destination)

    def _evaluation_context(
        self,
        *,
        candidate: CandidateState,
        stage: StageSpec,
        assignment: StageDriverAssignment,
        job_id: str,
        workspace: Path,
    ) -> EvaluationContext:
        return EvaluationContext(
            run_id=self.journal.header.run_id,
            job_id=job_id,
            input_manifest_digest=canonical_digest(
                {
                    "candidate_digest": candidate.digest,
                    "verifier_bundle_digest": self.release.verifier_bundle_digest,
                    "task_spec_digest": self.task.digest,
                    "environment_policy_digest": self.plan.binding.environment.policy_digest,
                    "evaluator_revision_digest": self._evaluators[
                        stage.evaluator_id
                    ].evaluator_revision_digest,
                    "stage_id": stage.stage_id,
                },
                domain="evaluation-input-manifest-v1",
            ),
            task=self.task,
            instance=self.instance,
            release=self.release,
            environment=self.environment,
            session=self.session,
            candidate=candidate,
            stage=stage,
            assignment=assignment,
            workspace=workspace,
        )

    def _execute_stage(self, candidate: CandidateState, stage: StageSpec) -> RunState:
        assignment = self._assignment(stage.stage_id)
        job_id = evaluation_job_id(
            self.journal.header.run_id,
            candidate.candidate_id,
            stage.stage_id,
        )
        candidate_workspace = self._candidate_workspace(job_id)
        storage_lease: InvocationStorageLease | None = None
        artifact_directory = self.artifact_directory
        if isinstance(self.executor, ExecutorStorageProvider):
            try:
                storage_lease = acquire_executor_storage(
                    self.executor,
                    environment=self.environment,
                    runtime_root=self.journal.directory / "executor-storage",
                    run_id=self.journal.header.run_id,
                    invocation_id=job_id,
                )
            except Exception:
                context = self._evaluation_context(
                    candidate=candidate,
                    stage=stage,
                    assignment=assignment,
                    job_id=job_id,
                    workspace=candidate_workspace,
                )
                self._evaluation_started(context)
                return self._failed_evaluation(
                    context,
                    InfrastructureFailureOutcome(),
                    "executor_storage_unavailable",
                )
            candidate_workspace = storage_lease.workspace
            artifact_directory = storage_lease.artifact_directory
        context = self._evaluation_context(
            candidate=candidate,
            stage=stage,
            assignment=assignment,
            job_id=job_id,
            workspace=candidate_workspace,
        )
        self._evaluation_started(context)
        evaluator = self._evaluators[stage.evaluator_id]
        try:
            self._restore_candidate(
                candidate,
                candidate_workspace,
                disposable_workspace=storage_lease is not None,
            )
            plan = evaluator.prepare(context)
            self._validate_invocation(context, plan)
        except (ArtifactIntegrityError, ArtifactPolicyViolation):
            if storage_lease is not None:
                release_executor_storage(self.executor, storage_lease, job_id)
                storage_lease = None
            return self._failed_evaluation(
                context,
                SecurityViolationOutcome(),
                "candidate_snapshot_invalid",
            )
        except Exception:
            if storage_lease is not None:
                release_executor_storage(self.executor, storage_lease, job_id)
                storage_lease = None
            return self._failed_evaluation(
                context,
                InfrastructureFailureOutcome(),
                "prepare_failed",
            )

        lease: LicenseLease | None = None
        try:
            lease = self._acquire_license(assignment, context.job_id)
        except LicenseUnavailable:
            if storage_lease is not None:
                release_executor_storage(self.executor, storage_lease, job_id)
                storage_lease = None
            return self._failed_evaluation(
                context,
                LicenseUnavailableOutcome(),
                "license_unavailable",
            )
        except Exception:
            if storage_lease is not None:
                release_executor_storage(self.executor, storage_lease, job_id)
                storage_lease = None
            return self._failed_evaluation(
                context,
                InfrastructureFailureOutcome(),
                "license_provider_failed",
            )

        handle: JobHandle | None = None
        evaluation_committed = False
        try:
            require_private_runtime_directory(candidate_workspace)
            handle = self.executor.launch(
                plan,
                environment=self.environment,
                workspace=candidate_workspace,
                artifact_directory=artifact_directory,
                asset_paths=self.asset_paths,
                scope=FilesystemScope.EVALUATOR,
                license_lease=lease,
            )
            self._validate_handle(plan, handle)
            with self._active_lock:
                self._active_handle = handle
            self._job_state(context.job_id, JobStateKind.RUNNING)
            terminal, requested_stop = self._wait_for_terminal(handle)
            self._job_state(
                context.job_id,
                run_job_state(terminal),
                reason_code=(None if terminal.failure is None else terminal.failure.value),
            )
            execution = self.executor.collect(handle)
            if execution.state != terminal:
                raise OrchestrationError("collected result changed the terminal job state")
            if lease is not None:
                self._release_license(context.job_id, lease)
                lease = None
            artifacts = self._record_execution_artifacts(context, plan, execution)
            result = self._interpret_result(evaluator, context, execution, artifacts)
            state = self._evaluation_completed(
                candidate_id=candidate.candidate_id,
                job_id=context.job_id,
                result=result,
                artifact_refs=tuple(evidence.artifact_id for evidence in result.evidence),
            )
            evaluation_committed = True
            if requested_stop is not None:
                return self._end(requested_stop)
            return state
        except ArtifactQuotaExceeded:
            if evaluation_committed:
                raise
            if lease is not None:
                self._release_license(context.job_id, lease)
                lease = None
            self._abort_evaluation(
                context,
                handle,
                InfrastructureFailureOutcome(),
                "artifact_quota_exceeded",
            )
            evaluation_committed = True
            return self._end(StopReason.STORAGE_BUDGET)
        except (ArtifactIntegrityError, ArtifactPolicyViolation):
            if evaluation_committed:
                raise
            if lease is not None:
                self._release_license(context.job_id, lease)
                lease = None
            self._abort_evaluation(
                context,
                handle,
                SecurityViolationOutcome(),
                "artifact_policy_violation",
            )
            evaluation_committed = True
            return self._end(StopReason.SECURITY_FAILURE)
        except Exception:
            if evaluation_committed:
                raise
            _LOGGER.debug(
                "Evaluation execution failed for run %s, operation %s",
                context.run_id,
                context.job_id,
                exc_info=True,
            )
            if lease is not None:
                self._release_license(context.job_id, lease)
                lease = None
            state = self._abort_evaluation(
                context,
                handle,
                InfrastructureFailureOutcome(),
                "execution_failed",
            )
            evaluation_committed = True
            return state
        finally:
            with self._active_lock:
                if self._active_handle == handle:
                    self._active_handle = None
            if lease is not None:
                with suppress(Exception):
                    self._release_license(context.job_id, lease)
            if storage_lease is not None and evaluation_committed:
                release_executor_storage(self.executor, storage_lease, context.job_id)

    def _wait_for_terminal(self, handle: JobHandle) -> tuple[JobState, StopReason | None]:
        requested_stop = None
        cancellation_sent = False
        while True:
            state = self.executor.inspect(handle)
            if state.handle != handle:
                raise OrchestrationError("executor returned state for another job")
            requested_stop = requested_stop or self._runtime_stop()
            if state.state in _EXECUTOR_TERMINAL_STATES:
                return state, requested_stop
            if requested_stop is not None and not cancellation_sent:
                cancellation_sent = True
                state = self.executor.cancel(handle)
                if state.handle != handle:
                    raise OrchestrationError("executor cancelled another job")
                if state.state in _EXECUTOR_TERMINAL_STATES:
                    return state, requested_stop
            if self._poll_interval_seconds:
                time.sleep(self._poll_interval_seconds)

    def _interpret_result(
        self,
        evaluator: EvaluatorRuntime,
        context: EvaluationContext,
        execution: ExecutionResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult:
        if execution.state.state is not ExecutorJobStateKind.COMPLETED:
            return StageResult(
                stage_id=context.stage.stage_id,
                outcome=execution_failure_outcome(execution.state),
            )
        try:
            result = evaluator.evaluate(context, execution, artifacts)
            if not isinstance(result, StageResult) or result.stage_id != context.stage.stage_id:
                raise OrchestrationError("evaluator returned a result for another stage")
            available = {artifact.record.logical_id for artifact in artifacts.values()}
            evidence = {item.artifact_id for item in result.evidence}
            if not evidence.issubset(available):
                raise OrchestrationError("evaluator referenced evidence outside this execution")
            if result.measurements:
                result = self._persist_sanitized_measurements(context, result, artifacts)
            else:
                result = StageResult(
                    stage_id=result.stage_id,
                    outcome=result.outcome,
                    evidence=self._visible_execution_evidence(result, artifacts),
                )
            if not self._evidence_is_visible(result):
                raise OrchestrationError("evaluator evidence exceeds result visibility")
            return result
        except Exception:
            return StageResult(
                stage_id=context.stage.stage_id,
                outcome=InfrastructureFailureOutcome(),
            )

    def _persist_sanitized_measurements(
        self,
        context: EvaluationContext,
        result: StageResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult:
        raw_records = {
            artifact.record.logical_id: artifact.record for artifact in artifacts.values()
        }
        declared_evidence = {evidence.artifact_id for evidence in result.evidence}
        raw_links: list[RawMeasurementLink] = []
        sanitized: list[SanitizedMeasurement] = []
        for measurement in result.measurements:
            provenance = measurement.provenance
            if provenance is None:
                raise OrchestrationError("evaluator measurement omitted raw provenance")
            source = raw_records.get(provenance.source_artifact_id)
            if (
                source is None
                or source.blob.digest != provenance.source_digest
                or source.artifact_class not in RAW_EDA_ARTIFACT_CLASSES
                or source.logical_id not in declared_evidence
            ):
                raise OrchestrationError(
                    "evaluator measurement does not bind one declared raw artifact"
                )
            sanitized.append(
                SanitizedMeasurement(
                    measurement_id=measurement.measurement_id,
                    unit=provenance.unit,
                    samples=measurement.samples,
                    sample_seeds=provenance.sample_seeds,
                )
            )
            raw_links.append(
                RawMeasurementLink(
                    measurement_id=measurement.measurement_id,
                    source_artifact_id=source.logical_id,
                    source_digest=source.blob.digest,
                )
            )

        disclosure = self.environment.artifact_policy.persistent_disclosure(
            ArtifactClass.MEASUREMENT
        )
        if disclosure is None:
            raise OrchestrationError("measurement artifacts are not retainable")
        document = SanitizedMeasurements(
            stage_id=context.stage.stage_id,
            measurements=tuple(sanitized),
        )
        blob = self.artifact_store.put_bytes(
            canonical_bytes(document),
            artifact_class=ArtifactClass.MEASUREMENT,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
        record = ArtifactRecord(
            logical_id=execution_artifact_id(
                context.run_id,
                context.job_id,
                "measurements",
            ),
            blob=blob,
            media_type=SANITIZED_MEASUREMENTS_MEDIA_TYPE,
            artifact_class=ArtifactClass.MEASUREMENT,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
        if self.environment.licenses:
            self._record_raw_measurement_links(context, record, tuple(raw_links))
        self._artifact_recorded(record)

        visible_evidence = self._visible_execution_evidence(result, artifacts)
        measurement_evidence = ArtifactEvidence(
            kind=EvidenceKind.MEASUREMENT,
            artifact_id=record.logical_id,
        )
        rewritten_measurements = []
        for measurement in result.measurements:
            provenance = measurement.provenance
            if provenance is None:
                raise OrchestrationError("evaluator measurement omitted raw provenance")
            rewritten_measurements.append(
                measurement.model_copy(
                    update={
                        "provenance": provenance.model_copy(
                            update={
                                "source_artifact_id": record.logical_id,
                                "source_digest": record.blob.digest,
                            }
                        )
                    }
                )
            )
        return StageResult(
            stage_id=result.stage_id,
            outcome=result.outcome,
            measurements=tuple(rewritten_measurements),
            evidence=(*visible_evidence, measurement_evidence),
        )

    def _record_raw_measurement_links(
        self,
        context: EvaluationContext,
        sanitized: ArtifactRecord,
        links: tuple[RawMeasurementLink, ...],
    ) -> None:
        disclosure = self.environment.artifact_policy.persistent_disclosure(ArtifactClass.EVIDENCE)
        if disclosure != PROTECTED_RAW_DISCLOSURE:
            raise OrchestrationError(
                "licensed raw measurement links require author-only disclosure"
            )
        document = RawMeasurementLinks(
            sanitized_artifact_id=sanitized.logical_id,
            sanitized_digest=sanitized.blob.digest,
            links=links,
        )
        blob = self.artifact_store.put_bytes(
            canonical_bytes(document),
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
        self._artifact_recorded(
            ArtifactRecord(
                logical_id=execution_artifact_id(
                    context.run_id,
                    context.job_id,
                    "raw.measurement-links",
                ),
                blob=blob,
                media_type=RAW_MEASUREMENT_LINKS_MEDIA_TYPE,
                artifact_class=ArtifactClass.EVIDENCE,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
        )

    def _artifact_is_result_visible(self, record: ArtifactRecord) -> bool:
        allowed = {
            Visibility.PUBLIC: {Visibility.PUBLIC},
            Visibility.PARTICIPANT: {Visibility.PUBLIC, Visibility.PARTICIPANT},
        }[self._result_visibility()]
        return record.visibility in allowed

    def _visible_execution_evidence(
        self,
        result: StageResult,
        artifacts: EvaluationArtifacts,
    ) -> tuple[ArtifactEvidence, ...]:
        records = {artifact.record.logical_id: artifact.record for artifact in artifacts.values()}
        return tuple(
            evidence
            for evidence in result.evidence
            if self._artifact_is_result_visible(records[evidence.artifact_id])
        )

    def _record_execution_artifacts(
        self,
        context: EvaluationContext,
        plan: InvocationPlan,
        execution: ExecutionResult,
    ) -> EvaluationArtifacts:
        declarations = {item.logical_id: item for item in plan.outputs}
        outputs = {item.logical_id: item for item in execution.outputs}
        if len(outputs) != len(execution.outputs) or set(outputs) - set(declarations):
            raise OrchestrationError("executor returned undeclared or duplicate outputs")
        for local_id, output in outputs.items():
            declaration = declarations[local_id]
            if (
                output.media_type != declaration.media_type
                or output.artifact_class is not declaration.artifact_class
            ):
                raise OrchestrationError("executor output diverges from its declaration")
        missing = {
            item.logical_id
            for item in plan.outputs
            if item.required and item.logical_id not in outputs
        }
        if missing:
            raise OrchestrationError("executor omitted a required declared output")

        material = [
            (
                "executor.stdout",
                execution.stdout,
                "application/octet-stream",
                ArtifactClass.DIAGNOSTIC,
            ),
            (
                "executor.stderr",
                execution.stderr,
                "application/octet-stream",
                ArtifactClass.DIAGNOSTIC,
            ),
            *(
                (
                    local_id,
                    output.blob,
                    output.media_type,
                    output.artifact_class,
                )
                for local_id, output in sorted(outputs.items())
            ),
        ]
        artifacts: list[EvaluationArtifact] = []
        for local_id, blob, media_type, artifact_class in material:
            disclosure = self.environment.artifact_policy.persistent_disclosure(artifact_class)
            if disclosure is None:
                raise OrchestrationError("executor persisted a non-retainable artifact class")
            self.artifact_store.verify_disclosure(
                blob,
                artifact_class=artifact_class,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
            record = ArtifactRecord(
                logical_id=execution_artifact_id(context.run_id, context.job_id, local_id),
                blob=blob,
                media_type=media_type,
                artifact_class=artifact_class,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
            self._artifact_recorded(record)
            artifacts.append(EvaluationArtifact(local_id=local_id, record=record))
        return EvaluationArtifacts(tuple(artifacts))

    def _acquire_license(
        self,
        assignment: StageDriverAssignment,
        job_id: str,
    ) -> LicenseLease | None:
        tool = next(
            item
            for item in self.environment.tool_bindings
            if item.capability is assignment.capability
        )
        if tool.license_binding_id is None:
            return None
        binding = next(
            item
            for item in self.environment.licenses
            if item.license_binding_id == tool.license_binding_id
        )
        provider = self.license_providers.get(binding.provider_id)
        if provider is None:
            self._license_denied(
                job_id,
                binding,
                LicenseDenialReason.PROVIDER_UNAVAILABLE,
            )
            raise LicenseUnavailable("bound license provider is unavailable")
        try:
            lease = provider.acquire(
                feature_class=binding.feature_class,
                run_id=self.journal.header.run_id,
                ttl_seconds=binding.lease_ttl_seconds,
            )
        except LicenseUnavailable:
            self._license_denied(
                job_id,
                binding,
                LicenseDenialReason.FEATURE_UNAVAILABLE,
            )
            raise
        except Exception:
            self._license_denied(
                job_id,
                binding,
                LicenseDenialReason.PROVIDER_FAILURE,
            )
            raise
        if (
            lease.provider_id != binding.provider_id
            or lease.feature_class != binding.feature_class
            or lease.state is not LeaseState.ACTIVE
        ):
            with suppress(Exception):
                provider.release(lease)
            self._license_denied(
                job_id,
                binding,
                LicenseDenialReason.INVALID_LEASE,
            )
            raise LicenseUnavailable("license provider returned an invalid lease")
        try:
            self._license_acquired(job_id, binding)
        except Exception:
            with suppress(Exception):
                provider.release(lease)
            raise
        return lease

    def _release_license(self, job_id: str, lease: LicenseLease) -> None:
        binding = self._license_binding(lease.provider_id, lease.feature_class)
        provider = self.license_providers.get(lease.provider_id)
        if provider is None or provider.release(lease) is not LeaseState.RELEASED:
            raise OrchestrationError("license provider did not release its lease")
        self._license_released(job_id, binding)

    def _license_binding(self, provider_id: str, feature_class: str) -> LicenseBinding:
        try:
            return next(
                binding
                for binding in self.environment.licenses
                if binding.provider_id == provider_id and binding.feature_class == feature_class
            )
        except StopIteration as error:
            raise OrchestrationError("license lease has no resolved binding") from error

    def _license_acquired(self, job_id: str, binding: LicenseBinding) -> RunState:
        return self.journal.transact(
            lambda state: LicenseLeaseAcquiredEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=LicenseLeaseAcquiredPayload(
                    job_id=job_id,
                    license_binding_id=binding.license_binding_id,
                    provider_id=binding.provider_id,
                    feature_class=binding.feature_class,
                ),
            )
        )

    def _license_denied(
        self,
        job_id: str,
        binding: LicenseBinding,
        reason: LicenseDenialReason,
    ) -> RunState:
        return self.journal.transact(
            lambda state: LicenseLeaseDeniedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=LicenseLeaseDeniedPayload(
                    job_id=job_id,
                    license_binding_id=binding.license_binding_id,
                    provider_id=binding.provider_id,
                    feature_class=binding.feature_class,
                    reason=reason,
                ),
            )
        )

    def _license_released(self, job_id: str, binding: LicenseBinding) -> RunState:
        return self.journal.transact(
            lambda state: LicenseLeaseReleasedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.VERIFIER,
                payload=LicenseLeaseReleasedPayload(
                    job_id=job_id,
                    license_binding_id=binding.license_binding_id,
                    provider_id=binding.provider_id,
                    feature_class=binding.feature_class,
                ),
            )
        )

    def _validate_invocation(
        self,
        context: EvaluationContext,
        plan: InvocationPlan,
    ) -> None:
        expected = context.assignment
        if (
            plan.invocation_id != context.job_id
            or plan.run_id != context.run_id
            or plan.input_manifest_digest != context.input_manifest_digest
            or plan.capability is not expected.capability
            or plan.tool_id != expected.tool_id
            or plan.driver_digest != expected.driver_digest
            or plan.view is not InvocationView.EVALUATOR
        ):
            raise OrchestrationError("evaluator invocation does not match its resolved binding")
        if {item.logical_id for item in plan.outputs} & {"executor.stdout", "executor.stderr"}:
            raise OrchestrationError("invocation output uses a reserved artifact identity")

    def _validate_handle(self, plan: InvocationPlan, handle: JobHandle) -> None:
        if (
            handle.job_id != plan.invocation_id
            or handle.invocation_digest != plan.digest
            or handle.executor_id != self.plan.binding.environment.executor_id
        ):
            raise OrchestrationError("executor handle does not match the resolved invocation")

    def _failed_evaluation(
        self,
        context: EvaluationContext,
        outcome: StageOutcome,
        reason_code: str,
    ) -> RunState:
        state = self.state
        jobs = {job.job_id: job.state for job in state.jobs}
        job_state = jobs.get(context.job_id)
        if job_state is None:
            raise OrchestrationError("failed evaluation has no journaled job")
        if job_state not in _RUN_TERMINAL_STATES:
            state = self._job_state(
                context.job_id,
                JobStateKind.FAILED,
                reason_code=reason_code,
            )
        result = StageResult(stage_id=context.stage.stage_id, outcome=outcome)
        return self._evaluation_completed(
            candidate_id=context.candidate.candidate_id,
            job_id=context.job_id,
            result=result,
            artifact_refs=(),
        )

    def _abort_evaluation(
        self,
        context: EvaluationContext,
        handle: JobHandle | None,
        outcome: StageOutcome,
        reason_code: str,
    ) -> RunState:
        if handle is not None:
            with suppress(Exception):
                self.executor.cancel(handle)
        return self._failed_evaluation(context, outcome, reason_code)

    def _evaluation_started(self, context: EvaluationContext) -> RunState:
        return self.journal.transact(
            lambda state: EvaluationStartedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.EVALUATOR,
                visibility=self._result_visibility(),
                payload=EvaluationStartedPayload(
                    stage_id=context.stage.stage_id,
                    candidate_id=context.candidate.candidate_id,
                    job_id=context.job_id,
                ),
            )
        )

    def _evaluation_completed(
        self,
        *,
        candidate_id: str,
        job_id: str,
        result: StageResult,
        artifact_refs: tuple[str, ...],
    ) -> RunState:
        return self.journal.transact(
            lambda state: EvaluationCompletedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.EVALUATOR,
                visibility=self._result_visibility(),
                artifact_refs=artifact_refs,
                payload=EvaluationCompletedPayload(
                    candidate_id=candidate_id,
                    job_id=job_id,
                    result=result,
                ),
            )
        )

    def _job_state(
        self,
        job_id: str,
        state_kind: JobStateKind,
        *,
        reason_code: str | None = None,
    ) -> RunState:
        return self.journal.transact(
            lambda state: JobStateChangedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.EXECUTOR,
                visibility=Visibility.VERIFIER,
                payload=JobStateChangedPayload(
                    job_id=job_id,
                    state=state_kind,
                    reason_code=reason_code,
                ),
            )
        )

    def _artifact_recorded(self, record: ArtifactRecord) -> RunState:
        return self.journal.transact(
            lambda state: ArtifactRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=record.visibility,
                payload=ArtifactRecordedPayload(record=record),
            )
        )

    def _end(self, reason: StopReason, candidate_id: str | None = None) -> RunState:
        self._require_active_incarnation()
        state = self.state
        if state.terminal_reason is not None:
            return state
        return self.journal.transact(
            lambda current: RunEndedEvent(
                run_id=current.run_id,
                sequence=current.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.PUBLIC,
                payload=RunEndedPayload(
                    reason=reason,
                    successful_candidate_id=candidate_id,
                ),
            )
        )

    def _budget_stop(
        self,
        action: RuntimeActionKind,
        *,
        candidate: CandidateState | None = None,
    ) -> StopReason | None:
        try:
            return budget_stop(
                action,
                journal=self.journal,
                task=self.task,
                environment=self.environment,
                session=self.session,
                artifact_store=self.artifact_store,
                now=self._clock(),
                candidate_id=(None if candidate is None else candidate.candidate_id),
            )
        except RuntimeBudgetError as error:
            raise OrchestrationError(str(error)) from error

    def _runtime_stop(self) -> StopReason | None:
        with self._active_lock:
            requested = self._requested_stop
        if requested is not None:
            return requested
        try:
            return active_runtime_stop(
                journal=self.journal,
                task=self.task,
                environment=self.environment,
                session=self.session,
                artifact_store=self.artifact_store,
                now=self._clock(),
            )
        except RuntimeBudgetError as error:
            raise OrchestrationError(str(error)) from error

    def _result_visibility(self) -> Visibility:
        return (
            Visibility.PUBLIC
            if self.session.feedback is FeedbackPolicy.NONE
            else Visibility.PARTICIPANT
        )

    def _evidence_is_visible(self, result: StageResult) -> bool:
        records = {record.logical_id: record for record in self.state.artifacts}
        allowed = {
            Visibility.PUBLIC: {Visibility.PUBLIC},
            Visibility.PARTICIPANT: {Visibility.PUBLIC, Visibility.PARTICIPANT},
        }[self._result_visibility()]
        return all(
            records[item.artifact_id].visibility in allowed
            for item in result.evidence
            if item.artifact_id in records
        )

    def _stage(self, stage_id: str) -> StageSpec:
        return next(item for item in self.task.evaluation.stages if item.stage_id == stage_id)

    def _assignment(self, stage_id: str) -> StageDriverAssignment:
        return next(item for item in self.plan.stage_drivers if item.stage_id == stage_id)

    @staticmethod
    def _unresolved_evaluations(
        events: Sequence[RunEvent],
    ) -> tuple[EvaluationStartedEvent, ...]:
        completed = {
            event.payload.job_id for event in events if isinstance(event, EvaluationCompletedEvent)
        }
        return tuple(
            event
            for event in events
            if isinstance(event, EvaluationStartedEvent) and event.payload.job_id not in completed
        )


def _scoring_failure_stop_reason(
    results: Sequence[StageResult],
    blocking_stage_ids: Sequence[str],
) -> StopReason:
    outcomes = {
        result.stage_id: result.outcome.kind
        for result in results
        if result.stage_id in blocking_stage_ids
    }
    if set(outcomes) != set(blocking_stage_ids):
        raise OrchestrationError("scoring blockers do not have terminal evaluator outcomes")
    if OutcomeKind.SECURITY_VIOLATION in outcomes.values():
        return StopReason.SECURITY_FAILURE
    if set(outcomes.values()) & {
        OutcomeKind.INFRASTRUCTURE_FAILURE,
        OutcomeKind.LICENSE_UNAVAILABLE,
    }:
        return StopReason.INFRASTRUCTURE_FAILURE
    return StopReason.UNRANKABLE
