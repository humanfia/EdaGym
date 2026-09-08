from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest

import edagym.runtime.orchestrator as orchestrator_module
from edagym.authoring.public_benchmarks import import_public_calibration_task
from edagym.evaluation.model import (
    ArtifactEvidence,
    CandidateFailureOutcome,
    EvidenceKind,
    MeasurementEvidence,
    MeasurementProvenance,
    OutcomeKind,
    ParetoVectorScore,
    PassedOutcome,
    ScalarScore,
    ScorerEligibilityKind,
    StageResult,
)
from edagym.evaluation.scoring import build_candidate_score, measurement_sample_seeds
from edagym.executors.licenses import FakeLicenseProvider, LicenseLease
from edagym.executors.model import (
    CollectedOutput,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
    OutputDeclaration,
)
from edagym.executors.model import (
    JobStateKind as ExecutorJobStateKind,
)
from edagym.participants.adapters import (
    ParticipantAdapter,
    ParticipantAdapterError,
    ParticipantFailureKind,
)
from edagym.participants.model import (
    FinishTrainingIntent,
    ParticipantIntent,
    ParticipantView,
    SubmitCandidateIntent,
)
from edagym.projections import (
    ProjectionUnavailable,
    aggregate_leaderboard,
    project_leaderboard_entry,
    project_pareto_front,
)
from edagym.run.artifacts import (
    RAW_MEASUREMENT_LINKS_MEDIA_TYPE,
    SANITIZED_MEASUREMENTS_MEDIA_TYPE,
    ContentAddressedStore,
    EncryptionKey,
    RawMeasurementLinks,
    SanitizedMeasurements,
)
from edagym.run.checkpoints import restore_application_checkpoint
from edagym.run.journal_storage import InvalidTransition
from edagym.run.trial_journal import replay
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    CandidateSubmittedEvent,
    EvaluationCompletedEvent,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    LicenseDenialReason,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseAcquiredPayload,
    LicenseLeaseDeniedEvent,
    LicenseLeaseReleasedEvent,
    LicenseLeaseReleasedPayload,
    ProducerKind,
    ProviderUsageFact,
    RunEndedEvent,
    ScoringRecordedEvent,
    StopReason,
)
from edagym.runtime import (
    EvaluationArtifacts,
    EvaluationContext,
    EvaluatorRuntime,
    OrchestrationError,
    RunOrchestrator,
)
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    ApplicationCheckpointBinding,
    ArtifactDisclosure,
    CheckpointCapability,
    EnvironmentSpec,
    FilesystemScope,
    LicenseBinding,
    ManagedEncryption,
)
from edagym.specs.session import (
    ActorKind,
    BenchmarkMode,
    FeedbackPolicy,
    ModelBudget,
    RecoveryPolicy,
    SessionSpec,
)
from edagym.specs.task import (
    NOT_APPLICABLE_LIBRARY_DIGEST,
    MeasurementUnit,
    MetricDirection,
    PublicCalibrationTaskOrigin,
    TaskSpec,
    WorkspaceInterface,
)

from .factories import (
    digest,
    environment_spec,
    provider_exchange_fixture,
    release_manifest,
    scalar_task_spec,
    session_spec,
    task_instance,
    task_spec,
)

_NOW = datetime(2026, 9, 4, tzinfo=UTC)


class _SingleSubmission:
    def __init__(self, candidate_id: str) -> None:
        self._candidate_id = candidate_id
        self._used = False

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {"solver": ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        assert view.actor_id == "solver"
        if not self._used:
            self._used = True
            return SubmitCandidateIntent(candidate_id=self._candidate_id)
        return FinishTrainingIntent(candidate_id=self._candidate_id)


class _ImprovingTraining:
    def __init__(self) -> None:
        self._action = 0

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {"solver": ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        assert view.actor_id == "solver"
        if self._action == 0:
            intent: ParticipantIntent = SubmitCandidateIntent(candidate_id="candidate_a")
        elif self._action == 1:
            assert tuple(item.candidate_id for item in view.scoring) == ("candidate_a",)
            intent = SubmitCandidateIntent(
                candidate_id="candidate_b",
                parent_candidate_id="candidate_a",
            )
        else:
            assert tuple(item.candidate_id for item in view.scoring) == (
                "candidate_a",
                "candidate_b",
            )
            intent = FinishTrainingIntent(candidate_id="candidate_b")
        self._action += 1
        return intent


class _FailingParticipant:
    def __init__(self, failure: ParticipantFailureKind) -> None:
        self._failure = failure

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {"solver": ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> SubmitCandidateIntent:
        del view
        raise ParticipantAdapterError(self._failure)


class _FixtureEvaluator(EvaluatorRuntime):
    def __init__(
        self,
        *,
        evaluator_id: str,
        evaluator_revision_digest: str,
        driver_digest: str,
        executable: str,
        candidate_values: Mapping[str, Decimal] | None = None,
        failed_candidates: frozenset[str] = frozenset(),
    ) -> None:
        self._evaluator_id = evaluator_id
        self._evaluator_revision_digest = evaluator_revision_digest
        self._driver_digest = driver_digest
        self._executable = executable
        self._candidate_values = {} if candidate_values is None else dict(candidate_values)
        self._failed_candidates = failed_candidates

    @property
    def evaluator_id(self) -> str:
        return self._evaluator_id

    @property
    def evaluator_revision_digest(self) -> str:
        return self._evaluator_revision_digest

    @property
    def driver_digest(self) -> str:
        return self._driver_digest

    def prepare(self, context: EvaluationContext) -> InvocationPlan:
        return InvocationPlan(
            invocation_id=context.job_id,
            run_id=context.run_id,
            capability=context.assignment.capability,
            tool_id=context.assignment.tool_id,
            driver_digest=context.assignment.driver_digest,
            view=InvocationView.EVALUATOR,
            executable=self._executable,
            input_manifest_digest=context.input_manifest_digest,
            outputs=(
                OutputDeclaration(
                    logical_id="report",
                    path=f"{context.stage.stage_id}.report",
                    media_type="application/json",
                    artifact_class=ArtifactClass.EVIDENCE,
                ),
            ),
        )

    def evaluate(
        self,
        context: EvaluationContext,
        execution: ExecutionResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult:
        assert execution.state.state is ExecutorJobStateKind.COMPLETED
        assert set(artifacts) == {"executor.stderr", "executor.stdout", "report"}
        if (
            context.stage.stage_id == "qor"
            and context.candidate.candidate_id in self._failed_candidates
        ):
            return StageResult(
                stage_id=context.stage.stage_id,
                outcome=CandidateFailureOutcome(),
            )
        measurements: tuple[MeasurementEvidence, ...] = ()
        report = artifacts["report"].record
        evidence = (
            ArtifactEvidence(
                kind=EvidenceKind.REPORT,
                artifact_id=report.logical_id,
            ),
        )
        if context.stage.stage_id == "qor":
            tool = next(
                binding
                for binding in context.environment.tool_bindings
                if binding.capability is context.assignment.capability
            )
            measurements = (
                MeasurementEvidence(
                    measurement_id="cell_count",
                    samples=(
                        self._candidate_values.get(
                            context.candidate.candidate_id,
                            Decimal(7),
                        ),
                    ),
                    provenance=MeasurementProvenance(
                        unit=MeasurementUnit.COUNT,
                        tool_id=tool.tool_id,
                        tool_version=tool.tool_version,
                        library_id="not_applicable",
                        library_digest=NOT_APPLICABLE_LIBRARY_DIGEST,
                        corner="not_applicable",
                        mode="not_applicable",
                        task_seed=context.instance.identity.seed,
                        sample_seeds=measurement_sample_seeds(
                            context.instance.identity.seed,
                            "cell_count",
                            1,
                        ),
                        source_artifact_id=report.logical_id,
                        source_digest=report.blob.digest,
                    ),
                ),
            )
        return StageResult(
            stage_id=context.stage.stage_id,
            outcome=PassedOutcome(),
            measurements=measurements,
            evidence=evidence,
        )


class _FixtureExecutor:
    def __init__(
        self,
        environment: EnvironmentSpec,
        store: ContentAddressedStore,
        *,
        licensed_capabilities: frozenset[Capability] = frozenset(),
        report_content: bytes = b'{"accepted":true}\n',
    ) -> None:
        self._environment = environment
        self._store = store
        self._licensed_capabilities = licensed_capabilities
        self._report_content = report_content
        self._plans: dict[str, InvocationPlan] = {}
        self.workspace_designs: list[str] = []
        self.workspaces: list[Path] = []

    def launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: dict[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None = None,
    ) -> JobHandle:
        assert environment == self._environment
        assert workspace.is_dir()
        assert artifact_directory.is_dir()
        assert not asset_paths
        assert scope is FilesystemScope.EVALUATOR
        assert (license_lease is not None) == (plan.capability in self._licensed_capabilities)
        self.workspaces.append(workspace)
        self.workspace_designs.append((workspace / "design.sv").read_text(encoding="ascii"))
        handle = JobHandle(
            job_id=plan.invocation_id,
            invocation_digest=plan.digest,
            executor_id=environment.executor.executor_id,
        )
        self._plans[handle.job_id] = plan
        return handle

    def inspect(self, handle: JobHandle) -> JobState:
        assert handle.job_id in self._plans
        return JobState(
            handle=handle,
            state=ExecutorJobStateKind.COMPLETED,
            exit_code=0,
        )

    def cancel(self, handle: JobHandle) -> JobState:
        return JobState(
            handle=handle,
            state=ExecutorJobStateKind.CANCELLED,
            exit_code=-15,
            failure=ExecutionFailureKind.CANCELLED,
        )

    def collect(self, handle: JobHandle) -> ExecutionResult:
        plan = self._plans[handle.job_id]
        diagnostic = self._environment.artifact_policy.persistent_disclosure(
            ArtifactClass.DIAGNOSTIC
        )
        evidence = self._environment.artifact_policy.persistent_disclosure(ArtifactClass.EVIDENCE)
        assert diagnostic is not None
        assert evidence is not None
        stdout = self._store.put_bytes(
            b"ok\n",
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=diagnostic.sensitivity,
            visibility=diagnostic.visibility,
            redistribution=diagnostic.redistribution,
        )
        stderr = self._store.put_bytes(
            b"",
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=diagnostic.sensitivity,
            visibility=diagnostic.visibility,
            redistribution=diagnostic.redistribution,
        )
        output = self._store.put_bytes(
            self._report_content,
            artifact_class=ArtifactClass.EVIDENCE,
            sensitivity=evidence.sensitivity,
            visibility=evidence.visibility,
            redistribution=evidence.redistribution,
        )
        declaration = plan.outputs[0]
        return ExecutionResult(
            state=self.inspect(handle),
            stdout=stdout,
            stderr=stderr,
            outputs=(
                CollectedOutput(
                    logical_id=declaration.logical_id,
                    blob=output,
                    media_type=declaration.media_type,
                    artifact_class=declaration.artifact_class,
                ),
            ),
        )

    def abandon(self, invocation_id: str) -> None:
        del invocation_id


def _evaluators(
    task_specification: TaskSpec,
    environment: EnvironmentSpec,
    candidate_values: Mapping[str, Decimal] | None = None,
    failed_candidates: frozenset[str] = frozenset(),
) -> tuple[_FixtureEvaluator, ...]:
    tools = {item.capability: item for item in environment.tool_bindings}
    return tuple(
        _FixtureEvaluator(
            evaluator_id=item.evaluator_id,
            evaluator_revision_digest=item.revision_digest,
            driver_digest=tools[item.capability].driver_digest,
            executable=tools[item.capability].locator.executable,
            candidate_values=candidate_values,
            failed_candidates=failed_candidates,
        )
        for item in task_specification.evaluation.evaluators
    )


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def _artifact_environment(visibility: Visibility) -> EnvironmentSpec:
    document = environment_spec().model_dump(mode="python")
    for rule in document["artifact_policy"]["rules"]:
        for disclosure in rule["allowed_disclosures"]:
            disclosure["visibility"] = visibility
            if visibility is Visibility.PUBLIC:
                disclosure["sensitivity"] = Sensitivity.PUBLIC
                disclosure["redistribution"] = Redistribution.ALLOWED
    return EnvironmentSpec.model_validate(document)


def _licensed_environment(
    measurement_visibility: Visibility = Visibility.PARTICIPANT,
) -> EnvironmentSpec:
    environment = environment_spec()
    license_binding_id = "fixture_license_binding"
    tools = tuple(
        tool.model_copy(
            update={
                "license_binding_id": (
                    license_binding_id if tool.capability is Capability.RTL_SIMULATION else None
                )
            }
        )
        for tool in environment.tool_bindings
    )
    protected = ArtifactDisclosure(
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    policy = environment.artifact_policy.model_copy(
        update={
            "encryption": ManagedEncryption(
                provider_id="fixture_encryption",
                policy_digest=digest("fixture-encryption-policy"),
            ),
            "rules": tuple(
                rule.model_copy(update={"allowed_disclosures": (protected,)})
                if rule.artifact_class in {ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE}
                else rule.model_copy(
                    update={
                        "allowed_disclosures": (
                            ArtifactDisclosure(
                                sensitivity=(
                                    Sensitivity.PUBLIC
                                    if measurement_visibility is Visibility.PUBLIC
                                    else Sensitivity.INTERNAL
                                ),
                                visibility=measurement_visibility,
                                redistribution=(
                                    Redistribution.ALLOWED
                                    if measurement_visibility is Visibility.PUBLIC
                                    else Redistribution.RESTRICTED
                                ),
                            ),
                        )
                    }
                )
                if rule.artifact_class is ArtifactClass.MEASUREMENT
                else rule
                for rule in environment.artifact_policy.rules
            ),
        }
    )
    return EnvironmentSpec.model_validate(
        {
            **environment.model_dump(mode="python"),
            "tool_bindings": tools,
            "licenses": (
                LicenseBinding(
                    license_binding_id=license_binding_id,
                    provider_id="fixture_license_provider",
                    provider_digest=digest("fixture-license-provider"),
                    feature_class="rtl_simulation",
                    lease_ttl_seconds=300,
                ),
            ),
            "artifact_policy": policy,
        }
    )


def _licensed_store(path: Path, environment: EnvironmentSpec) -> ContentAddressedStore:
    return ContentAddressedStore(
        _private_directory(path),
        policy=environment.artifact_policy,
        encryption_key=EncryptionKey(key_id="fixture_key", value=b"k" * 32),
    )


def _licensed_session() -> SessionSpec:
    session = session_spec()
    return session.model_copy(
        update={"resources": session.resources.model_copy(update={"max_license_seconds": 1_000})}
    )


def _benchmark_session(*, trial_count: int = 1) -> SessionSpec:
    session = session_spec()
    return SessionSpec.model_validate(
        {
            **session.model_dump(mode="python"),
            "mode": BenchmarkMode(trial_count=trial_count),
            "feedback": FeedbackPolicy.NONE,
            "recovery": RecoveryPolicy.NONE,
        }
    )


def _create_runtime(
    root: Path,
    participant: ParticipantAdapter,
    *,
    task: TaskSpec | None = None,
    environment: EnvironmentSpec | None = None,
    session: SessionSpec | None = None,
    candidate_values: Mapping[str, Decimal] | None = None,
    failed_candidates: frozenset[str] = frozenset(),
    trial_key: str = "runtime_contract",
) -> RunOrchestrator:
    root.mkdir(mode=0o700)
    bound_task = task if task is not None else task_spec()
    bound_environment = environment if environment is not None else environment_spec()
    bound_session = session if session is not None else session_spec()
    instance = task_instance(bound_task)
    release = release_manifest(bound_task, instance, bound_environment)
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=bound_environment.artifact_policy,
    )
    workspace = _private_directory(root / "workspace")
    (workspace / "design.sv").write_text(
        "module design; endmodule\n",
        encoding="ascii",
    )
    return RunOrchestrator.create(
        task=bound_task,
        instance=instance,
        release=release,
        environment=bound_environment,
        session=bound_session,
        trial_key=trial_key,
        state_root=root / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(root / "executor-artifacts"),
        artifact_store=store,
        executor=_FixtureExecutor(bound_environment, store),
        evaluators=_evaluators(
            bound_task,
            bound_environment,
            candidate_values,
            failed_candidates,
        ),
        participant=participant,
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )


def test_workspace_submission_paths_must_not_overlap() -> None:
    with pytest.raises(ValueError):
        WorkspaceInterface(submission_paths=("rtl", "rtl/top.sv"))


def test_runtime_rejects_same_process_checkpoint_recovery(tmp_path: Path) -> None:
    task = task_spec()
    environment = environment_spec()
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(tmp_path / "store"),
        policy=environment.artifact_policy,
    )
    workspace = _private_directory(tmp_path / "workspace")
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="ascii")
    artifact_directory = _private_directory(tmp_path / "executor-artifacts")
    executor = _FixtureExecutor(environment, store)
    evaluators = _evaluators(task, environment)
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="trial_a",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=artifact_directory,
        artifact_store=store,
        executor=executor,
        evaluators=evaluators,
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )

    runtime.advance()
    submission_events = runtime.journal.read_events()
    candidate_event = next(
        event for event in submission_events if isinstance(event, CandidateSubmittedEvent)
    )
    snapshot_event = next(
        event
        for event in submission_events
        if isinstance(event, ArtifactRecordedEvent)
        and event.payload.record.artifact_class is ArtifactClass.CANDIDATE
    )
    assert snapshot_event.sequence < candidate_event.sequence
    assert snapshot_event.payload.record.blob.digest == candidate_event.payload.candidate_digest
    marker, checkpoint_state = runtime.checkpoint("checkpoint_a")
    assert checkpoint_state.checkpoint_ids == ("checkpoint_a",)
    assert marker.checkpoint_id == "checkpoint_a"

    resumed_workspace = tmp_path / "resumed-workspace"
    reopened_store = ContentAddressedStore(
        tmp_path / "store",
        policy=environment.artifact_policy,
    )
    reopened_executor = _FixtureExecutor(environment, reopened_store)
    resumed = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="trial_a",
        state_root=tmp_path / "runs",
        workspace=resumed_workspace,
        artifact_directory=artifact_directory,
        artifact_store=reopened_store,
        executor=reopened_executor,
        evaluators=evaluators,
        participant=_SingleSubmission("candidate_b"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    events_before = resumed.journal.read_events()
    with pytest.raises(OrchestrationError, match="participant incarnation recovery failed"):
        resumed.resume("checkpoint_a")
    assert resumed.journal.read_events() == events_before
    assert not resumed_workspace.exists()


def test_runtime_persists_a_task_derived_pareto_score(tmp_path: Path) -> None:
    environment = _artifact_environment(Visibility.PARTICIPANT)
    runtime = _create_runtime(
        tmp_path / "pareto-score",
        _SingleSubmission("candidate_a"),
        environment=environment,
    )

    state = runtime.run_to_completion()

    assert state.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert len(state.scoring) == 1
    decision = state.scoring[0].decision
    assert decision.eligibility.state is ScorerEligibilityKind.READY
    assert isinstance(decision.score, ParetoVectorScore)
    assert decision.score.measurements[0].measurement_id == "cell_count"
    assert decision.score.measurements[0].value == Decimal(7)
    scoring_events = tuple(
        event
        for event in runtime.journal.record().events
        if isinstance(event, ScoringRecordedEvent)
    )
    assert len(scoring_events) == 1
    assert scoring_events[0].payload.decision == decision


def test_runtime_persists_only_a_bound_scalar_score(tmp_path: Path) -> None:
    task = scalar_task_spec()
    environment = _artifact_environment(Visibility.PARTICIPANT)
    runtime = _create_runtime(
        tmp_path / "scalar-score",
        _SingleSubmission("candidate_a"),
        task=task,
        environment=environment,
    )

    state = runtime.run_to_completion()

    score = state.scoring[0].decision.score
    assert isinstance(score, ScalarScore)
    assert score.value == Decimal(993)
    assert score.direction is MetricDirection.MAXIMIZE
    scorer = task.evaluation.scorer
    assert scorer is not None
    assert score.scorer_revision_digest == scorer.revision_digest


def test_training_scores_an_improved_second_candidate_before_explicit_finish(
    tmp_path: Path,
) -> None:
    session = session_spec().model_copy(update={"feedback": FeedbackPolicy.METRICS})
    runtime = _create_runtime(
        tmp_path / "training-improvement",
        _ImprovingTraining(),
        session=session,
        candidate_values={
            "candidate_a": Decimal(11),
            "candidate_b": Decimal(7),
        },
    )

    state = runtime.run_to_completion()

    assert state.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert state.successful_candidate_id == "candidate_b"
    assert tuple(candidate.parent_candidate_id for candidate in state.candidates) == (
        None,
        "candidate_a",
    )
    scores = {item.candidate_id: item.decision.score for item in state.scoring}
    assert isinstance(scores["candidate_a"], ParetoVectorScore)
    assert isinstance(scores["candidate_b"], ParetoVectorScore)
    assert scores["candidate_a"].measurements[0].value == Decimal(11)
    assert scores["candidate_b"].measurements[0].value == Decimal(7)
    terminal = runtime.journal.read_events()[-1]
    assert isinstance(terminal, RunEndedEvent)
    assert terminal.producer is ProducerKind.PARTICIPANT


def test_scorer_failure_leaves_a_retryable_journal_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = scalar_task_spec()
    environment = _artifact_environment(Visibility.PUBLIC)
    runtime = _create_runtime(
        tmp_path / "scorer-recovery",
        _SingleSubmission("candidate_a"),
        task=task,
        environment=environment,
        session=_benchmark_session(),
    )
    runtime.advance()
    runtime.advance()
    runtime.advance()
    original = build_candidate_score

    def fail_score(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise ArithmeticError("injected scorer failure")

    monkeypatch.setattr(orchestrator_module, "build_candidate_score", fail_score)
    with pytest.raises(OrchestrationError, match="score derivation"):
        runtime.advance()

    failed_prefix = runtime.state
    assert failed_prefix.terminal_reason is None
    assert failed_prefix.scoring == ()
    assert (
        sum(isinstance(event, EvaluationCompletedEvent) for event in runtime.journal.read_events())
        == 2
    )

    monkeypatch.setattr(orchestrator_module, "build_candidate_score", original)
    recovered = runtime.advance()
    assert recovered.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert len(recovered.scoring) == 1


def test_replay_rejects_forged_scalar_and_sample_seed(
    tmp_path: Path,
) -> None:
    task = scalar_task_spec()
    environment = _artifact_environment(Visibility.PUBLIC)
    runtime = _create_runtime(
        tmp_path / "forged-scoring",
        _SingleSubmission("candidate_a"),
        task=task,
        environment=environment,
        session=_benchmark_session(),
    )
    runtime.run_to_completion()
    events = runtime.journal.read_events()
    scoring_index = next(
        index for index, event in enumerate(events) if isinstance(event, ScoringRecordedEvent)
    )
    scoring_event = events[scoring_index]
    assert isinstance(scoring_event, ScoringRecordedEvent)
    score = scoring_event.payload.decision.score
    assert isinstance(score, ScalarScore)
    forged_score = score.model_copy(update={"value": score.value + 1})
    forged_decision = scoring_event.payload.decision.model_copy(update={"score": forged_score})
    forged_scoring = scoring_event.model_copy(
        update={"payload": scoring_event.payload.model_copy(update={"decision": forged_decision})}
    )
    forged_events = (*events[:scoring_index], forged_scoring, *events[scoring_index + 1 :])
    with pytest.raises(InvalidTransition, match="task-bound derivation"):
        replay(runtime.journal.header, task, forged_events)

    measurement_index = next(
        index
        for index, event in enumerate(events)
        if isinstance(event, EvaluationCompletedEvent) and event.payload.result.measurements
    )
    measurement_event = events[measurement_index]
    assert isinstance(measurement_event, EvaluationCompletedEvent)
    measurement = measurement_event.payload.result.measurements[0]
    provenance = measurement.provenance
    assert provenance is not None
    forged_measurement = measurement.model_copy(
        update={"provenance": provenance.model_copy(update={"sample_seeds": ("f" * 32,)})}
    )
    forged_result = measurement_event.payload.result.model_copy(
        update={"measurements": (forged_measurement,)}
    )
    forged_measurement_event = measurement_event.model_copy(
        update={"payload": measurement_event.payload.model_copy(update={"result": forged_result})}
    )
    forged_events = (
        *events[:measurement_index],
        forged_measurement_event,
        *events[measurement_index + 1 :],
    )
    with pytest.raises(InvalidTransition, match="sample seeds"):
        replay(runtime.journal.header, task, forged_events)


def test_leaderboard_ranks_only_public_verifier_success(tmp_path: Path) -> None:
    environment = _artifact_environment(Visibility.PUBLIC)
    base_session = session_spec()
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "mode": BenchmarkMode(),
            "feedback": FeedbackPolicy.NONE,
            "recovery": RecoveryPolicy.NONE,
        }
    )
    runtime = _create_runtime(
        tmp_path / "leaderboard-success",
        _SingleSubmission("candidate_a"),
        environment=environment,
        session=session,
    )

    state = runtime.run_to_completion()
    entry = project_leaderboard_entry(runtime.journal, session)

    assert state.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert entry.rank_eligible
    assert isinstance(entry.score, ParetoVectorScore)
    assert {measurement.candidate_id for measurement in entry.measurements} == {"candidate_a"}


def test_public_calibration_benchmark_run_cannot_enter_sealed_leaderboard(
    tmp_path: Path,
) -> None:
    task = import_public_calibration_task(
        task_spec(),
        PublicCalibrationTaskOrigin(
            source_id="hdlbits",
            source_snapshot_digest=digest("hdlbits-source-snapshot"),
            source_resource_ids=("behavior",),
            license_spdx_expression="MIT",
            redistribution=Redistribution.ALLOWED,
            provenance=("https://hdlbits.01xz.net",),
        ),
    )
    session = _benchmark_session()
    runtime = _create_runtime(
        tmp_path / "public-calibration",
        _SingleSubmission("candidate_a"),
        task=task,
        environment=_artifact_environment(Visibility.PUBLIC),
        session=session,
    )

    state = runtime.run_to_completion()

    assert state.terminal_reason is StopReason.VERIFIER_SUCCESS
    with pytest.raises(ProjectionUnavailable, match="sealed leaderboard"):
        project_leaderboard_entry(runtime.journal, session)


def test_success_without_a_public_score_makes_the_aggregate_ineligible(
    tmp_path: Path,
) -> None:
    session = session_spec()
    benchmark = SessionSpec.model_validate(
        {
            **session.model_dump(mode="python"),
            "mode": BenchmarkMode(),
            "feedback": FeedbackPolicy.SAFE_DIAGNOSTIC,
            "recovery": RecoveryPolicy.NONE,
        }
    )
    runtime = _create_runtime(
        tmp_path / "private-score",
        _SingleSubmission("candidate_a"),
        environment=_artifact_environment(Visibility.PARTICIPANT),
        session=benchmark,
    )
    runtime.run_to_completion()

    entry = project_leaderboard_entry(runtime.journal, benchmark)
    aggregate = aggregate_leaderboard(((runtime.journal, benchmark),))[0]

    assert entry.success
    assert not entry.rank_eligible
    assert entry.score is None
    assert not aggregate.rank_eligible
    assert aggregate.success_numerator == aggregate.success_denominator == 1


def test_failed_measurement_is_an_explicit_unrankable_trial(
    tmp_path: Path,
) -> None:
    environment = _artifact_environment(Visibility.PUBLIC)
    session = _benchmark_session()
    runtime = _create_runtime(
        tmp_path / "unrankable-measurement",
        _SingleSubmission("candidate_a"),
        environment=environment,
        session=session,
        failed_candidates=frozenset({"candidate_a"}),
    )

    state = runtime.run_to_completion()
    entry = project_leaderboard_entry(runtime.journal, session)
    aggregate = aggregate_leaderboard(((runtime.journal, session),))[0]

    assert state.terminal_reason is StopReason.UNRANKABLE
    assert state.successful_candidate_id is None
    assert state.scoring[0].decision.eligibility.state is ScorerEligibilityKind.BLOCKED
    assert state.scoring[0].decision.score is None
    assert not entry.success
    assert not entry.rank_eligible
    assert aggregate.rank_eligible
    assert aggregate.success_numerator == 0


def test_pareto_front_is_derived_only_within_one_exact_partition(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = _artifact_environment(Visibility.PUBLIC)
    session = _benchmark_session()
    slower = _create_runtime(
        tmp_path / "pareto-slower",
        _SingleSubmission("candidate_a"),
        task=task,
        environment=environment,
        session=session,
        candidate_values={"candidate_a": Decimal(11)},
        trial_key="pareto_slow",
    )
    faster = _create_runtime(
        tmp_path / "pareto-faster",
        _SingleSubmission("candidate_a"),
        task=task,
        environment=environment,
        session=session,
        candidate_values={"candidate_a": Decimal(7)},
        trial_key="pareto_fast",
    )
    slower.run_to_completion()
    faster.run_to_completion()
    slower_entry = project_leaderboard_entry(slower.journal, session)
    faster_entry = project_leaderboard_entry(faster.journal, session)

    assert project_pareto_front(task, (slower_entry, faster_entry)) == (faster_entry,)

    scalar_task = scalar_task_spec()
    scalar = _create_runtime(
        tmp_path / "pareto-scalar",
        _SingleSubmission("candidate_a"),
        task=scalar_task,
        environment=environment,
        session=session,
        trial_key="pareto_scalar",
    )
    scalar.run_to_completion()
    scalar_entry = project_leaderboard_entry(scalar.journal, session)
    with pytest.raises(ProjectionUnavailable, match="cannot cross"):
        project_pareto_front(task, (faster_entry, scalar_entry))

    score = faster_entry.score
    assert isinstance(score, ParetoVectorScore)
    forged = faster_entry.model_copy(
        update={
            "run_id": digest("forged-pareto-entry"),
            "score": score.model_copy(
                update={
                    "measurements": (
                        score.measurements[0].model_copy(
                            update={"measurement_id": "forged_metric"}
                        ),
                    )
                }
            ),
        }
    )
    with pytest.raises(ProjectionUnavailable, match="measurement schema"):
        project_pareto_front(task, (forged,))


def test_runtime_rejects_unimplemented_application_checkpoint(tmp_path: Path) -> None:
    application_environment = environment_spec().model_copy(
        update={"checkpoint": CheckpointCapability.APPLICATION}
    )
    runtime = _create_runtime(
        tmp_path / "application-checkpoint",
        _SingleSubmission("candidate_a"),
        environment=application_environment,
    )

    with pytest.raises(OrchestrationError, match="does not implement"):
        runtime.checkpoint("checkpoint_a")


def test_application_checkpoint_restores_only_driver_owned_database(
    tmp_path: Path,
) -> None:
    base = environment_spec()
    environment = EnvironmentSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "checkpoint": CheckpointCapability.APPLICATION,
            "application_checkpoint": ApplicationCheckpointBinding(
                driver_id="synthesis_database",
                driver_digest=digest("synthesis-database-checkpoint"),
                capture_paths=("design.sv",),
                after_stage_ids=("functional",),
            ),
        }
    )
    runtime = _create_runtime(
        tmp_path / "application-checkpoint-supported",
        _SingleSubmission("candidate_a"),
        environment=environment,
    )
    (runtime.workspace / "unmanaged.log").write_text("discarded\n", encoding="ascii")

    runtime.advance()
    runtime.advance()
    marker, _ = runtime.checkpoint("checkpoint_a")

    assert marker.checkpoint_kind is CheckpointCapability.APPLICATION
    application_binding = environment.application_checkpoint
    assert application_binding is not None
    assert marker.driver_digest == application_binding.driver_digest
    destination = tmp_path / "restored-application-workspace"
    restore_application_checkpoint(
        store=runtime.artifact_store,
        journal=runtime.journal,
        environment=environment,
        checkpoint_id="checkpoint_a",
        destination=destination,
    )
    assert (destination / "design.sv").read_text(encoding="ascii") == ("module design; endmodule\n")
    assert not (destination / "unmanaged.log").exists()


@pytest.mark.parametrize(
    ("failure", "reason"),
    (
        (ParticipantFailureKind.RESPONSE_BOUND, StopReason.POLICY_FAILURE),
        (ParticipantFailureKind.INVALID_INTENT, StopReason.POLICY_FAILURE),
        (ParticipantFailureKind.ACTOR_MISMATCH, StopReason.POLICY_FAILURE),
        (ParticipantFailureKind.CHANNEL_FAILURE, StopReason.INFRASTRUCTURE_FAILURE),
        (ParticipantFailureKind.COMMAND_CANCELLED, StopReason.EXPLICIT_CANCEL),
        (ParticipantFailureKind.COMMAND_EXIT, StopReason.INFRASTRUCTURE_FAILURE),
        (ParticipantFailureKind.COMMAND_TIMEOUT, StopReason.INFRASTRUCTURE_FAILURE),
        (ParticipantFailureKind.END_OF_INPUT, StopReason.INFRASTRUCTURE_FAILURE),
        (ParticipantFailureKind.CANDIDATE_SNAPSHOT, StopReason.INFRASTRUCTURE_FAILURE),
    ),
)
def test_runtime_preserves_participant_failure_kind(
    tmp_path: Path,
    failure: ParticipantFailureKind,
    reason: StopReason,
) -> None:
    runtime = _create_runtime(
        tmp_path / failure.value,
        _FailingParticipant(failure),
    )

    state = runtime.advance()

    assert state.terminal_reason is reason


@pytest.mark.parametrize(
    ("left", "right"),
    (
        ("workspace", "state"),
        ("workspace", "artifacts"),
        ("workspace", "store"),
        ("state", "artifacts"),
        ("state", "store"),
        ("artifacts", "store"),
    ),
)
def test_runtime_rejects_overlapping_storage_domains(
    tmp_path: Path,
    left: str,
    right: str,
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
    paths = {
        "workspace": _private_directory(tmp_path / "workspace"),
        "state": _private_directory(tmp_path / "runs"),
        "artifacts": _private_directory(tmp_path / "executor-artifacts"),
        "store": store.root,
    }
    paths[left] = paths[right]

    with pytest.raises(OrchestrationError, match="must use separate paths"):
        RunOrchestrator.create(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key="overlapping_storage",
            state_root=paths["state"],
            workspace=paths["workspace"],
            artifact_directory=paths["artifacts"],
            artifact_store=store,
            executor=_FixtureExecutor(environment, store),
            evaluators=_evaluators(task, environment),
            participant=_SingleSubmission("candidate_a"),
            clock=lambda: _NOW,
            poll_interval_seconds=0,
        )


def test_runtime_accounts_completed_provider_usage_instead_of_reservation(
    tmp_path: Path,
) -> None:
    base_session = session_spec()
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "model_budget": ModelBudget(
                max_requests=2,
                max_input_tokens_per_request=5,
                max_output_tokens_per_request=5,
                max_total_input_tokens=5,
                max_total_output_tokens=5,
                max_total_tokens=10,
            ),
        }
    )
    runtime = _create_runtime(
        tmp_path / "provider-usage",
        _SingleSubmission("candidate_a"),
        session=session,
    )
    exchange = provider_exchange_fixture(
        runtime.journal.header,
        request_id="provider_request_a",
        actor_id="solver",
        requested_model="test-route",
        provider_profile_digest=digest("provider-profile"),
        provider_config_digest=digest("provider-config"),
        budget_binding_digest=digest("provider-budget"),
        reserved_input_tokens=5,
        reserved_output_tokens=5,
        usage=ProviderUsageFact(
            input_tokens=4,
            output_tokens=4,
            total_tokens=8,
        ),
    )

    runtime.journal.transact_events(
        lambda state: exchange.request_events(state, timestamp=_NOW)
    )
    runtime.journal.transact_events(
        lambda state: exchange.response_events(state, timestamp=_NOW)
    )

    state = runtime.advance()

    assert state.terminal_reason is None
    assert tuple(candidate.candidate_id for candidate in state.candidates) == ("candidate_a",)


def test_runtime_journals_secret_free_license_lifecycle(tmp_path: Path) -> None:
    task = task_spec()
    environment = _licensed_environment()
    session = _licensed_session()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = _licensed_store(tmp_path / "store", environment)
    workspace = _private_directory(tmp_path / "workspace")
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="ascii")
    executor = _FixtureExecutor(
        environment,
        store,
        licensed_capabilities=frozenset({Capability.RTL_SIMULATION}),
    )
    provider = FakeLicenseProvider(
        provider_id="fixture_license_provider",
        capacities={"rtl_simulation": 1},
    )
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="licensed_runtime",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=executor,
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        license_providers={"fixture_license_provider": provider},
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )

    state = runtime.run_to_completion()

    assert state.terminal_reason is StopReason.VERIFIER_SUCCESS
    acquired = tuple(
        event
        for event in runtime.journal.read_events()
        if isinstance(event, LicenseLeaseAcquiredEvent)
    )
    released = tuple(
        event
        for event in runtime.journal.read_events()
        if isinstance(event, LicenseLeaseReleasedEvent)
    )
    assert len(acquired) == len(released) == 1
    assert acquired[0].payload.model_dump(mode="json") == {
        "job_id": acquired[0].payload.job_id,
        "license_binding_id": "fixture_license_binding",
        "provider_id": "fixture_license_provider",
        "feature_class": "rtl_simulation",
    }
    assert released[0].payload.model_dump(mode="json") == acquired[0].payload.model_dump(
        mode="json"
    )
    encoded = runtime.journal.record().model_dump_json()
    assert "lease_00000001" not in encoded
    assert "license_environment" not in encoded


def test_runtime_rejects_unencrypted_licensed_environment_copy(tmp_path: Path) -> None:
    task = task_spec()
    licensed = _licensed_environment()
    environment = licensed.model_copy(
        update={"artifact_policy": environment_spec().artifact_policy}
    )
    session = _licensed_session()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = ContentAddressedStore(
        _private_directory(tmp_path / "store"),
        policy=environment.artifact_policy,
    )
    workspace = _private_directory(tmp_path / "workspace")
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="ascii")

    with pytest.raises(OrchestrationError, match="managed artifact encryption"):
        RunOrchestrator.create(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key="unencrypted_licensed_copy",
            state_root=tmp_path / "runs",
            workspace=workspace,
            artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
            artifact_store=store,
            executor=_FixtureExecutor(environment, store),
            evaluators=_evaluators(task, environment),
            participant=_SingleSubmission("candidate_a"),
            clock=lambda: _NOW,
            poll_interval_seconds=0,
        )


def test_licensed_runtime_projects_only_sanitized_measurements(tmp_path: Path) -> None:
    task = task_spec()
    environment = _licensed_environment(Visibility.PUBLIC)
    base_session = _licensed_session()
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "mode": BenchmarkMode(),
            "feedback": FeedbackPolicy.NONE,
            "recovery": RecoveryPolicy.NONE,
        }
    )
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    store = _licensed_store(tmp_path / "store", environment)
    workspace = _private_directory(tmp_path / "workspace")
    (workspace / "design.sv").write_text("module design; endmodule\n", encoding="ascii")
    malicious_report = (
        b'{"accepted":true,"end'
        b'point":"ht'
        b"tps://broker.in"
        b'ternal:8443",'
        b'"lib'
        b'rary":"saed32/'
        b"EDK_08_"
        b'2025",'
        b'"license_'
        b'route":"27'
        b"000"
        b"@license.in"
        b'ternal",'
        b'"pa'
        b'th":"/mnt/na'
        b"s0/eda.libs/saed32/"
        b"EDK_08_"
        b'2025"}\n'
    )
    executor = _FixtureExecutor(
        environment,
        store,
        licensed_capabilities=frozenset({Capability.RTL_SIMULATION}),
        report_content=malicious_report,
    )
    runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="licensed_public_measurement",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=executor,
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        license_providers={
            "fixture_license_provider": FakeLicenseProvider(
                provider_id="fixture_license_provider",
                capacities={"rtl_simulation": 1},
            )
        },
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )

    state = runtime.run_to_completion()

    assert state.terminal_reason is StopReason.VERIFIER_SUCCESS
    raw_reports = tuple(
        artifact
        for artifact in state.artifacts
        if artifact.artifact_class is ArtifactClass.EVIDENCE
        and artifact.media_type == "application/json"
    )
    assert raw_reports
    assert all(
        artifact.sensitivity is Sensitivity.CONFIDENTIAL
        and artifact.visibility is Visibility.AUTHOR
        and artifact.redistribution is Redistribution.FORBIDDEN
        for artifact in raw_reports
    )
    sanitized = next(
        artifact
        for artifact in state.artifacts
        if artifact.media_type == SANITIZED_MEASUREMENTS_MEDIA_TYPE
    )
    assert sanitized.artifact_class is ArtifactClass.MEASUREMENT
    assert sanitized.visibility is Visibility.PUBLIC
    sanitized_document = SanitizedMeasurements.model_validate_json(
        store.read_bytes(sanitized.blob, maximum_bytes=sanitized.blob.size_bytes)
    )
    assert sanitized_document.measurements[0].samples == (Decimal(7),)
    assert len(sanitized_document.measurements[0].sample_seeds) == 1
    raw_links_record = next(
        artifact
        for artifact in state.artifacts
        if artifact.media_type == RAW_MEASUREMENT_LINKS_MEDIA_TYPE
    )
    assert raw_links_record.visibility is Visibility.AUTHOR
    raw_links = RawMeasurementLinks.model_validate_json(
        store.read_bytes(
            raw_links_record.blob,
            maximum_bytes=raw_links_record.blob.size_bytes,
        )
    )
    assert raw_links.sanitized_artifact_id == sanitized.logical_id
    assert raw_links.links[0].source_artifact_id in {
        artifact.logical_id for artifact in raw_reports
    }

    result = next(
        candidate_result.result
        for candidate_result in state.stage_results
        if candidate_result.result.measurements
    )
    provenance = result.measurements[0].provenance
    assert provenance is not None
    assert provenance.source_artifact_id == sanitized.logical_id
    assert provenance.source_digest == sanitized.blob.digest
    assert {evidence.artifact_id for evidence in result.evidence} == {sanitized.logical_id}
    assert all(
        not candidate_result.result.evidence
        for candidate_result in state.stage_results
        if not candidate_result.result.measurements
    )
    private_record = runtime.journal.record().model_dump(mode="python")
    private_provenance = next(
        event["payload"]["result"]["measurements"][0]["provenance"]
        for commit in private_record["commits"]
        for event in commit["events"]
        if event["kind"] == "evaluation_completed" and event["payload"]["result"]["measurements"]
    )
    assert {
        "tool_id",
        "tool_version",
        "library_id",
        "library_digest",
        "corner",
        "mode",
        "task_seed",
        "sample_seeds",
    }.issubset(private_provenance)

    projection = project_leaderboard_entry(runtime.journal, session)
    exported = projection.model_dump_json()
    for private_artifact in (*raw_reports, raw_links_record):
        assert private_artifact.logical_id not in exported
        assert private_artifact.blob.digest not in exported
    for forbidden in (
        "broker.internal",
        "license.internal",
        "".join(("/mnt/", "nas0")),
        "".join(("saed32/EDK_", "08_2025")),
    ):
        assert forbidden not in exported
    assert {
        "tool_id",
        "tool_version",
        "library_id",
        "library_digest",
        "corner",
        "mode",
        "task_seed",
    }.isdisjoint(projection.measurements[0].model_dump())
    assert projection.measurements[0].source_artifact_id == sanitized.logical_id
    assert projection.measurements[0].source_digest == sanitized.blob.digest
    assert "tools" not in projection.partition.model_dump()

    raw_blob = raw_reports[0].blob.digest.removeprefix("sha256:")
    encrypted = (store.blob_root / raw_blob[:2] / raw_blob[2:]).read_bytes()
    assert malicious_report not in encrypted


def test_runtime_journals_typed_license_denial(tmp_path: Path) -> None:
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
        trial_key="license_denial",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=_FixtureExecutor(environment, store),
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    runtime.advance()

    state = runtime.advance()

    denial = next(
        event
        for event in runtime.journal.read_events()
        if isinstance(event, LicenseLeaseDeniedEvent)
    )
    assert denial.payload.reason is LicenseDenialReason.PROVIDER_UNAVAILABLE
    assert state.stage_results[-1].result.outcome.kind is OutcomeKind.LICENSE_UNAVAILABLE
    assert not any(
        isinstance(event, LicenseLeaseAcquiredEvent | LicenseLeaseReleasedEvent)
        for event in runtime.journal.read_events()
    )


def test_license_budget_uses_acquire_and_release_timestamps(tmp_path: Path) -> None:
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
        trial_key="license_accounting",
        state_root=tmp_path / "runs",
        workspace=workspace,
        artifact_directory=_private_directory(tmp_path / "executor-artifacts"),
        artifact_store=store,
        executor=_FixtureExecutor(environment, store),
        evaluators=_evaluators(task, environment),
        participant=_SingleSubmission("candidate_a"),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    runtime.advance()
    acquired_at = _NOW + timedelta(seconds=2)
    released_at = _NOW + timedelta(seconds=7)
    identity = {
        "job_id": "job_accounting",
        "license_binding_id": "fixture_license_binding",
        "provider_id": "fixture_license_provider",
        "feature_class": "rtl_simulation",
    }
    runtime.journal.transact(
        lambda state: EvaluationStartedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW + timedelta(seconds=1),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.PARTICIPANT,
            payload=EvaluationStartedPayload(
                stage_id="functional",
                candidate_id="candidate_a",
                job_id="job_accounting",
            ),
        )
    )
    runtime.journal.transact(
        lambda state: LicenseLeaseAcquiredEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=acquired_at,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.VERIFIER,
            payload=LicenseLeaseAcquiredPayload(**identity),
        )
    )
    runtime.journal.transact(
        lambda state: JobStateChangedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW + timedelta(seconds=3),
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.VERIFIER,
            payload=JobStateChangedPayload(
                job_id="job_accounting",
                state=JobStateKind.RUNNING,
            ),
        )
    )
    runtime.journal.transact(
        lambda state: LicenseLeaseReleasedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=released_at,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.VERIFIER,
            payload=LicenseLeaseReleasedPayload(**identity),
        )
    )
    runtime.journal.transact(
        lambda state: JobStateChangedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=uuid4(),
            timestamp=_NOW + timedelta(seconds=99),
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.VERIFIER,
            payload=JobStateChangedPayload(
                job_id="job_accounting",
                state=JobStateKind.COMPLETED,
            ),
        )
    )

    from edagym.runtime.budget import budget_usage

    usage = budget_usage(
        journal=runtime.journal,
        task=task,
        artifact_store=store,
        now=_NOW + timedelta(seconds=100),
    )

    assert usage.eda_compute_seconds == 96
    assert usage.license_seconds == 5
