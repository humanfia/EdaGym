"""End-to-end evidence for durable campaign trial dispatch."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from io import StringIO
from pathlib import Path

import pytest

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.evaluation.model import PassedOutcome, StageResult
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.licenses import (
    FakeLicenseProvider,
    LeaseState,
    LicenseLease,
)
from edagym.executors.model import (
    CollectedOutput,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
)
from edagym.executors.model import JobStateKind as ExecutorJobStateKind
from edagym.participant_tool_protocol import (
    CHECKPOINT_PARTICIPANT_TOOL_NAME,
    COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
    EXECUTOR_PARTICIPANT_TOOL_NAME,
)
from edagym.participants.adapters import (
    HumanParticipantAdapter,
    HybridParticipantAdapter,
    JsonLineHumanChannel,
    ParticipantAdapterError,
    ParticipantFailureKind,
    json_line_human_adapter_digest,
)
from edagym.participants.evidence import (
    ParticipantActionKind,
    project_participant_session_record,
)
from edagym.participants.model import ParticipantIntent, ParticipantView
from edagym.participants.responses import (
    MeteredResponsesParticipantSender,
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
from edagym.projections.model import ParticipationKind
from edagym.providers.campaign import (
    CampaignExecutionLimits,
    CampaignScope,
    CampaignTokenLimits,
    CappedSpendLimit,
    FeatureSupport,
    ModelCategory,
    ModelReferenceKind,
    ModelRoute,
    ModelSetManifest,
    RetryPolicy,
    RouteQualification,
)
from edagym.providers.campaign_budget import CampaignResources
from edagym.providers.campaign_runner import (
    AttemptDisposition,
    CampaignAccountingError,
    CampaignReservation,
    CampaignRunner,
    KnownSpend,
    ProviderAttemptSettledEvent,
    ReservationCancelledEvent,
)
from edagym.providers.campaign_schedule import (
    CampaignTask,
    CampaignTaskRole,
    MeteredProviderHarnessBinding,
)
from edagym.providers.model import (
    FunctionCall,
    FunctionCallStatus,
    ProviderDefaults,
    ProviderProfile,
    ProviderSecurityBinding,
    ProviderUsage,
    RequestTokenClaim,
    ResolvedProviderConfig,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
)
from edagym.providers.provider_budget import CampaignProviderBudget
from edagym.providers.responses import ResponsesExchangeObserver
from edagym.providers.trial_evidence import (
    TOOL_EXECUTION_MEDIA_TYPE,
    project_campaign_trial_run_evidence,
)
from edagym.providers.trial_runtime import (
    CampaignTrialContinuation,
    CampaignTrialDispatcher,
)
from edagym.providers.trial_security import (
    campaign_trial_run_binding,
    runtime_surface_binding_for_trial,
)
from edagym.providers.trial_workspace import prepare_trial_workspace
from edagym.resolution import resolve_run
from edagym.run.artifacts import ContentAddressedStore, EncryptionKey
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ControlTransferredEvent,
    InteractionDirection,
    InteractionRecordedEvent,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseReleasedEvent,
    ParticipantToolLostEvent,
    ParticipantToolReservedEvent,
    ParticipantToolSettledEvent,
    ProviderRequestState,
    RunHeader,
    RunStartedEvent,
    StopReason,
)
from edagym.runtime.model import EvaluationArtifacts, EvaluationContext
from edagym.runtime.orchestrator import RunOrchestrator
from edagym.security.canary_artifact import ProviderCanaryEvidence
from edagym.specs.budget import EpisodeBudget, ModelBudget, ResourceBudget
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    ProviderResponseStatus,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    EnvironmentSpec,
    FilesystemScope,
    LicenseBinding,
    ManagedEncryption,
)
from edagym.specs.operation import (
    CandidateInputOperationArgument,
    FixedOperationArgument,
    ParticipantOperationBinding,
)
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import (
    ActorKind,
    HandoffWriter,
    HarnessActor,
    HumanActor,
    SessionSpec,
)
from edagym.specs.task import TaskSpec
from tests.campaign_fixtures import campaign_cells, campaign_header
from tests.factories import SYNTHETIC_CREDENTIAL_SOURCE_DIGEST

from .factories import (
    digest,
    environment_spec,
    provider_canary_evidence_for_binding,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)

_NOW = datetime(2026, 9, 4, tzinfo=UTC)
_INSTRUCTION = "Use the bounded workspace, checkpoint, and EDA tools."


class _InjectedControllerRestart(BaseException):
    pass


class _MonotonicTicker:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        value = self.value
        self.value += 0.1
        return value


class _SchemaDispatcher:
    def __init__(self, operation_ids: tuple[str, ...]) -> None:
        self.operation_ids = operation_ids

    def invoke(
        self,
        *,
        operation_id: str,
        view: object,
    ) -> ToolObservation:
        del operation_id, view
        raise AssertionError("schema-only dispatcher cannot execute")


class _SequenceTransport:
    def __init__(self, reported_model: str, *, start_index: int = 0) -> None:
        self.reported_model = reported_model
        self.start_index = start_index
        self.calls = 0
        self.request_bodies: list[bytes] = []

    def respond(
        self,
        *,
        request: ResponsesRequest,
    ) -> tuple[bytes, ResponsesResult]:
        self.request_bodies.append(request._wire_body())
        calls = (
            (
                CHECKPOINT_PARTICIPANT_TOOL_NAME,
                {"checkpoint_id": "before_tool"},
            ),
            (
                EXECUTOR_PARTICIPANT_TOOL_NAME,
                {"operation_id": "check_candidate"},
            ),
            (
                COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
                {
                    "intent": json.dumps(
                        {
                            "kind": "submit_candidate",
                            "candidate_id": "candidate_a",
                            "parent_candidate_id": None,
                        },
                        separators=(",", ":"),
                    )
                },
            ),
            (
                COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
                {
                    "intent": json.dumps(
                        {"kind": "finish_training", "candidate_id": "candidate_a"},
                        separators=(",", ":"),
                    )
                },
            ),
        )
        call_index = self.start_index + self.calls
        if call_index >= len(calls):
            raise AssertionError("provider received an unexpected request")
        name, arguments = calls[call_index]
        self.calls += 1
        usage = ProviderUsage(
            input_tokens=self.calls,
            output_tokens=1,
            total_tokens=self.calls + 1,
            cached_input_tokens=0,
            reasoning_tokens=0,
        )
        result = ResponsesResult(
            response_id=f"response_{self.calls}",
            reported_model=self.reported_model,
            reported_service_tier="default",
            status=ResponseStatus.COMPLETED,
            outputs=(
                FunctionCall(
                    call_id=f"call_{self.calls}",
                    name=name,
                    arguments=json.dumps(arguments, separators=(",", ":")),
                    status=FunctionCallStatus.COMPLETED,
                ),
            ),
            usage=usage,
        )
        response_body = json.dumps(
            {
                "id": f"response_{self.calls}",
                "model": self.reported_model,
                "service_tier": "default",
                "status": "completed",
                "output": [
                    {
                        "type": "function_call",
                        "call_id": f"call_{self.calls}",
                        "name": name,
                        "arguments": json.dumps(arguments, separators=(",", ":")),
                        "status": "completed",
                    }
                ],
                "usage": {
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "total_tokens": usage.total_tokens,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens_details": {"reasoning_tokens": 0},
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return response_body, result


class _MeteredSequenceSender(MeteredResponsesParticipantSender):
    """Exercise trial orchestration above the separately tested credential boundary."""

    def __init__(
        self,
        *,
        runner: CampaignRunner,
        configuration: ResolvedProviderConfig,
        transport: _SequenceTransport,
        canary_evidence: ProviderCanaryEvidence,
    ) -> None:
        self._runner = runner
        self._configuration = configuration
        self._transport = transport
        self._canary_evidence = canary_evidence
        self._budget = CampaignProviderBudget(runner)
        self._trial_id = runner.schedule.trials[0].trial_id
        self._security_binding = ProviderSecurityBinding(
            canary_receipt_digest=canary_evidence.receipt.digest,
            runtime_surface_manifest_digest=canary_evidence.runtime_surface_manifest.digest,
            budget_binding_digest=self._budget.binding_digest,
        )

    @property
    def campaign_digest(self) -> str:
        return self._runner.campaign.digest

    @property
    def campaign_schedule_digest(self) -> str:
        return self._runner.schedule.digest

    @property
    def provider_profile_digest(self) -> str:
        return self._configuration.profile.digest

    @property
    def provider_config_digest(self) -> str:
        return self._configuration.digest

    @property
    def budget_binding_digest(self) -> str:
        return self._budget.binding_digest

    @property
    def bound_trial_id(self) -> str:
        return self._trial_id

    @property
    def provider_security_binding(self) -> ProviderSecurityBinding:
        return self._security_binding

    @property
    def provider_canary_evidence(self) -> ProviderCanaryEvidence:
        return self._canary_evidence

    def request(
        self,
        *,
        trial_id: str,
        request_key: str,
        request: ResponsesRequest,
        observer: ResponsesExchangeObserver | None = None,
    ) -> ResponsesResult:
        assert trial_id == self._trial_id
        assert observer is not None
        reservation = self._budget.reserve_provider_attempt(
            trial_id=trial_id,
            request_key=request_key,
            requested_model=request.model,
            token_claim=request.token_claim,
            security_binding=self._security_binding,
        )
        try:
            observer.request_reserved(
                trial_id=trial_id,
                request_key=request_key,
                provider_profile_digest=self.provider_profile_digest,
                provider_config_digest=self.provider_config_digest,
                security_binding=self._security_binding,
                canary_evidence=self._canary_evidence,
                request_body=request._wire_body(),
                beta_features=(),
            )
        except BaseException:
            reservation.cancel()
            raise
        reservation.mark_dispatched()
        response_body, result = self._transport.respond(request=request)
        try:
            observer.response_received(response_body=response_body, result=result)
        finally:
            reservation.settle_completed(
                usage=result.usage,
                provider_reported_model=result.reported_model,
                provider_reported_service_tier=result.reported_service_tier,
                provider_response_status=result.status,
            )
        return result


class _InactiveHarness:
    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {"solver": ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        del view
        raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)


class _Executor:
    def __init__(self, environment: EnvironmentSpec, store: ContentAddressedStore) -> None:
        self.environment = environment
        self.store = store
        self.plans: dict[str, InvocationPlan] = {}
        self.scopes: list[FilesystemScope] = []

    def launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        workspace: Path,
        artifact_directory: Path,
        asset_paths: Mapping[str, Path],
        scope: FilesystemScope,
        license_lease: LicenseLease | None = None,
    ) -> JobHandle:
        assert environment == self.environment
        assert workspace.is_dir() and artifact_directory.is_dir()
        assert not asset_paths
        if license_lease is not None:
            assert license_lease.state is LeaseState.ACTIVE
        assert scope is (
            FilesystemScope.TOOL if plan.view is InvocationView.TOOL else FilesystemScope.EVALUATOR
        )
        handle = JobHandle(
            job_id=plan.invocation_id,
            invocation_digest=plan.digest,
            executor_id=environment.executor.executor_id,
        )
        self.plans[handle.job_id] = plan
        self.scopes.append(scope)
        return handle

    def inspect(self, handle: JobHandle) -> JobState:
        assert handle.job_id in self.plans
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

    def abandon(self, invocation_id: str) -> None:
        self.plans.pop(invocation_id, None)

    def collect(self, handle: JobHandle) -> ExecutionResult:
        plan = self.plans[handle.job_id]
        diagnostic = self.environment.artifact_policy.persistent_disclosure(
            ArtifactClass.DIAGNOSTIC
        )
        assert diagnostic is not None
        stdout = self.store.put_bytes(
            b"ok\n",
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=diagnostic.sensitivity,
            visibility=diagnostic.visibility,
            redistribution=diagnostic.redistribution,
        )
        stderr = self.store.put_bytes(
            b"",
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=diagnostic.sensitivity,
            visibility=diagnostic.visibility,
            redistribution=diagnostic.redistribution,
        )
        evidence = self.environment.artifact_policy.persistent_disclosure(ArtifactClass.EVIDENCE)
        assert evidence is not None
        outputs = tuple(
            CollectedOutput(
                logical_id=declaration.logical_id,
                blob=self.store.put_bytes(
                    b"{}\n",
                    artifact_class=declaration.artifact_class,
                    sensitivity=evidence.sensitivity,
                    visibility=evidence.visibility,
                    redistribution=evidence.redistribution,
                ),
                media_type=declaration.media_type,
                artifact_class=declaration.artifact_class,
            )
            for declaration in plan.outputs
        )
        return ExecutionResult(
            state=self.inspect(handle),
            stdout=stdout,
            stderr=stderr,
            outputs=outputs,
        )


class _RestartingToolExecutor(_Executor):
    def __init__(self, environment: EnvironmentSpec, store: ContentAddressedStore) -> None:
        super().__init__(environment, store)
        self.abandoned: list[str] = []
        self._restarted = False

    def inspect(self, handle: JobHandle) -> JobState:
        plan = self.plans[handle.job_id]
        if plan.view is InvocationView.TOOL and not self._restarted:
            self._restarted = True
            raise _InjectedControllerRestart
        return super().inspect(handle)

    def abandon(self, invocation_id: str) -> None:
        self.abandoned.append(invocation_id)
        super().abandon(invocation_id)


class _Evaluator:
    def __init__(self, task: TaskSpec, environment: EnvironmentSpec, evaluator_id: str) -> None:
        spec = next(
            item for item in task.evaluation.evaluators if item.evaluator_id == evaluator_id
        )
        tool = next(
            item for item in environment.tool_bindings if item.capability is spec.capability
        )
        self.evaluator_id = evaluator_id
        self.evaluator_revision_digest = spec.revision_digest
        self.driver_digest = tool.driver_digest
        self.executable = tool.locator.executable

    def prepare(self, context: EvaluationContext) -> InvocationPlan:
        return InvocationPlan(
            invocation_id=context.job_id,
            run_id=context.run_id,
            capability=context.assignment.capability,
            tool_id=context.assignment.tool_id,
            driver_digest=context.assignment.driver_digest,
            view=InvocationView.EVALUATOR,
            executable=self.executable,
            input_manifest_digest=context.input_manifest_digest,
        )

    def evaluate(
        self,
        context: EvaluationContext,
        execution: ExecutionResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult:
        del artifacts
        assert execution.state.state is ExecutorJobStateKind.COMPLETED
        return StageResult(stage_id=context.stage.stage_id, outcome=PassedOutcome())



def _encrypted_environment(*, licensed: bool = False) -> EnvironmentSpec:
    base = environment_spec()
    license_binding_id = "verilator_license"
    rules = tuple(
        ArtifactRetentionRule(
            artifact_class=artifact_class,
            retention_seconds=3600,
            allowed_disclosures=(
                ArtifactDisclosure(
                    sensitivity=(
                        Sensitivity.CONFIDENTIAL
                        if artifact_class
                        in {
                            ArtifactClass.DIAGNOSTIC,
                            ArtifactClass.EVIDENCE,
                            ArtifactClass.TRAINING,
                        }
                        else Sensitivity.INTERNAL
                    ),
                    visibility=Visibility.AUTHOR,
                    redistribution=(
                        Redistribution.FORBIDDEN
                        if artifact_class
                        in {
                            ArtifactClass.DIAGNOSTIC,
                            ArtifactClass.EVIDENCE,
                            ArtifactClass.TRAINING,
                        }
                        else Redistribution.RESTRICTED
                    ),
                ),
            ),
        )
        for artifact_class in ArtifactClass
    )
    return EnvironmentSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "participant_operations": (
                ParticipantOperationBinding(
                    operation_id="check_candidate",
                    capability=Capability.RTL_SIMULATION,
                    tool_id="verilator",
                    arguments=(
                        FixedOperationArgument(value="--lint-only"),
                        CandidateInputOperationArgument(path="participant/design.sv"),
                    ),
                ),
            ),
            "tool_bindings": tuple(
                tool.model_copy(
                    update={
                        "license_binding_id": (
                            license_binding_id if licensed and tool.tool_id == "verilator" else None
                        )
                    }
                )
                for tool in base.tool_bindings
            ),
            "licenses": (
                (
                    LicenseBinding(
                        license_binding_id=license_binding_id,
                        provider_id="fake_license",
                        provider_digest=digest("fake-license-provider"),
                        feature_class="rtl_simulation",
                        lease_ttl_seconds=30,
                    ),
                )
                if licensed
                else ()
            ),
            "artifact_policy": ArtifactPolicy(
                quota_bytes=64 * 1024**2,
                encryption=ManagedEncryption(
                    provider_id="test_key_provider",
                    policy_digest=digest("test-key-policy"),
                ),
                rules=rules,
            ),
        }
    )


def _tool_schema_digest(environment: EnvironmentSpec) -> str:
    paths = ("participant/design.sv",)
    dispatcher = _SchemaDispatcher(
        tuple(item.operation_id for item in environment.participant_operations)
    )
    definitions = (
        WorkspaceReadTool(Path("unused"), paths=paths).definition,
        EdaInvocationTool(dispatcher).definition,
        WorkspaceWriteTool(Path("unused"), paths=paths).definition,
        CheckpointParticipantTool(
            lambda _checkpoint_id: ToolObservation(
                outcome=ToolObservationOutcome.PASSED,
                summary="unused",
            )
        ).definition,
    )
    return responses_tool_schema_digest(definitions)


def _campaign_inputs(
    root: Path,
    *,
    licensed: bool = False,
    hybrid: bool = False,
) -> tuple[
    CampaignRunner,
    TaskSpec,
    TaskInstance,
    ReleaseManifest,
    EnvironmentSpec,
    SessionSpec,
    ResolvedProviderConfig,
]:
    task = task_spec().model_copy(update={"measurements": ()})
    environment = _encrypted_environment(licensed=licensed)
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="test_gateway",
        profile=ProviderProfile(
            logical_id="test.gateway", origin="https://gateway.test", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(
            requested_model="route.snapshot",
            reasoning_effort="high",
            service_tier="fast",
        ),
    )
    harness = MeteredProviderHarnessBinding(
        harness_id="responses_harness",
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        instruction_digest=responses_instruction_digest(_INSTRUCTION),
        tool_schema_digest=_tool_schema_digest(environment),
        scaffold_digest=digest("campaign-scaffold"),
        maximum_requests_per_action=4,
    )
    base_session = session_spec()
    harness_actor = HarnessActor(
        actor_id="solver",
        harness_id=harness.harness_id,
        harness_digest=harness.digest,
        scaffold_digest=harness.scaffold_digest,
        requested_model_route="route.snapshot",
    )
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "actors": (
                (
                    HumanActor(
                        actor_id="operator",
                        adapter_id="json_line",
                        adapter_digest=json_line_human_adapter_digest(),
                    ),
                    harness_actor,
                )
                if hybrid
                else (harness_actor,)
            ),
            "writer": (HandoffWriter(initial_writer="operator") if hybrid else base_session.writer),
            "resources": ResourceBudget(
                max_turns=8,
                max_tool_calls=8,
                max_experiments=4,
                max_wall_seconds=300,
                max_eda_compute_seconds=120,
                max_license_seconds=60 if licensed else 0,
                max_artifact_bytes=16 * 1024**2,
            ),
            "model_budget": ModelBudget(
                max_requests=8,
                max_input_tokens_per_request=128,
                max_output_tokens_per_request=64,
                max_input_tokens=1024,
                max_output_tokens=512,
                max_total_tokens=1536,
            ),
        }
    )
    route = ModelRoute(
        route_id="snapshot_route",
        requested_model="route.snapshot",
        provider_reported_model="provider.route.snapshot",
        reference_kind=ModelReferenceKind.SNAPSHOT,
        categories=tuple(ModelCategory),
        qualification=RouteQualification(
            reasoning_control=FeatureSupport.SUPPORTED,
            requested_service_tier="fast",
            canary_tool_schema_digest=digest("route-canary-tools"),
            canary_evidence_digest=digest("route-canary"),
        ),
    )
    model_set = ModelSetManifest(
        provider_config_digest=configuration.digest,
        discovery_digest=digest("model-discovery"),
        resolved_on="2026-09-04",
        routes=(route,),
    )
    campaign_task = CampaignTask(
        task_release_digest=release.digest,
        task_family=task.identity.family,
        task_origin=task.identity.origin,
        role=CampaignTaskRole.RTL_GENERATION,
        device_capability=Capability.RTL_SIMULATION,
        environment_digest=environment.digest,
        evaluator_stage_ids=tuple(stage.stage_id for stage in task.evaluation.stages),
        task_instance_digest=release.task_instance_digest,
    )
    header = campaign_header(
        campaign_id="trial-runtime",
        scope=CampaignScope.EXPANDED_BREADTH,
        schedule_seed="2" * 32,
        retry_policy=RetryPolicy(max_request_attempts=1, backoff_milliseconds=0),
        provider_spend_limit=CappedSpendLimit(currency="USD", amount=Decimal("1")),
        model_set=model_set,
        provider_config=configuration,
        tasks=(campaign_task,),
        repetition_count=1,
        cells=campaign_cells(
            model_set=model_set,
            harnesses=(harness,),
            feedback_policy_digest=canonical_digest(
                session.feedback,
                domain="feedback-policy-v1",
            ),
        ),
        episode_budget=EpisodeBudget(
            max_experiments=session.resources.max_experiments,
            max_requests=8,
            max_input_tokens_per_request=128,
            max_output_tokens_per_request=64,
            max_input_tokens=1024,
            max_output_tokens=512,
            max_total_tokens=1536,
            max_turns=8,
            max_tool_calls=8,
            max_wall_seconds=300,
            max_eda_compute_seconds=120,
            max_license_seconds=session.resources.max_license_seconds,
            max_artifact_bytes=16 * 1024**2,
        ),
        token_limits=CampaignTokenLimits(
            max_requests=8, max_input_tokens=1024, max_output_tokens=512, max_total_tokens=1536
        ),
        execution_limits=CampaignExecutionLimits(
            max_turns=8,
            max_tool_calls=8,
            max_wall_seconds=300,
            max_eda_compute_seconds=120,
            max_license_seconds=60 if licensed else 1,
            max_artifact_bytes=16 * 1024**2,
        ),
    )
    runner = CampaignRunner(header=header, state_root=root / "campaign")
    return runner, task, instance, release, environment, session, configuration


def _sender(
    runner: CampaignRunner,
    configuration: ResolvedProviderConfig,
    transport: _SequenceTransport,
    *,
    task: TaskSpec,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
) -> _MeteredSequenceSender:
    trial = runner.schedule.trials[0]
    binding = runtime_surface_binding_for_trial(
        runner=runner,
        trial=trial,
        task=task,
        release=release,
        environment=environment,
        session=session,
    )
    return _MeteredSequenceSender(
        runner=runner,
        configuration=configuration,
        transport=transport,
        canary_evidence=provider_canary_evidence_for_binding(binding),
    )


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    return path


def _security_binding(runner: CampaignRunner) -> ProviderSecurityBinding:
    return ProviderSecurityBinding(
        canary_receipt_digest=digest("canary-receipt"),
        runtime_surface_manifest_digest=digest("runtime-surface"),
        budget_binding_digest=runner.budget_projection().digest,
    )


def test_campaign_trial_reopens_after_terminal_run_and_replays_both_journals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_directory(tmp_path / "campaign-trial")
    runner, task, instance, release, environment, session, configuration = _campaign_inputs(root)
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=environment.artifact_policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"k" * 32),
    )
    executor = _Executor(environment, store)
    evaluators = tuple(
        _Evaluator(task, environment, spec.evaluator_id) for spec in task.evaluation.evaluators
    )
    source = root / "design.sv"
    source.write_bytes(b"participant-design")
    transport = _SequenceTransport("provider.route.snapshot")
    sender = _sender(
        runner,
        configuration,
        transport,
        task=task,
        release=release,
        environment=environment,
        session=session,
    )
    dispatcher = CampaignTrialDispatcher(runner)
    trial = runner.schedule.trials[0]
    original_finalize = CampaignReservation.finalize_run

    def crash_before_campaign_finalize(
        self: CampaignReservation,
        *,
        actual: object,
        outcome: object,
    ) -> None:
        del self, actual, outcome
        raise RuntimeError("injected controller restart")

    monkeypatch.setattr(CampaignReservation, "finalize_run", crash_before_campaign_finalize)
    with pytest.raises(RuntimeError, match="controller restart"):
        dispatcher.dispatch(
            trial_id=trial.trial_id,
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            sender=sender,
            instruction=_INSTRUCTION,
            asset_source_policy=load_system_asset_source_policy(),
            run_state_root=root / "runs",
            runtime_root=root / "runtime",
            artifact_store=store,
            executor=executor,
            evaluators=evaluators,
            participant_files={"participant/design.sv": source},
            provider_spend=KnownSpend(currency="USD", amount=Decimal("0.01")),
            clock=lambda: _NOW,
            poll_interval_seconds=0,
        )

    assert transport.calls == 4
    assert len(runner.pending_trials()) == 1

    monkeypatch.setattr(CampaignReservation, "finalize_run", original_finalize)
    reopened = CampaignRunner(header=runner.header, state_root=root / "campaign")
    unused_transport = _SequenceTransport("provider.route.snapshot")
    result = CampaignTrialDispatcher(reopened).dispatch(
        trial_id=trial.trial_id,
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        sender=_sender(
            reopened,
            configuration,
            unused_transport,
            task=task,
            release=release,
            environment=environment,
            session=session,
        ),
        instruction=_INSTRUCTION,
        asset_source_policy=load_system_asset_source_policy(),
        run_state_root=root / "runs",
        runtime_root=root / "runtime",
        artifact_store=store,
        executor=executor,
        evaluators=evaluators,
        participant_files={"participant/design.sv": source},
        provider_spend=KnownSpend(currency="USD", amount=Decimal("0.01")),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    assert unused_transport.calls == 0
    assert result.outcome.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert result.outcome.run_binding is not None
    assert result.outcome.run_binding.campaign is not None
    campaign_binding = result.outcome.run_binding.campaign
    assert campaign_binding.campaign_digest == reopened.campaign.digest
    assert campaign_binding.schedule_digest == reopened.schedule.digest
    assert campaign_binding.scheduled_trial_digest == trial.digest
    assert campaign_binding.paired_seed == trial.binding.paired_seed
    assert campaign_binding.repetition_index == 0
    assert campaign_binding.route_id == trial.binding.route_id
    assert campaign_binding.reasoning_effort == trial.binding.reasoning_effort
    assert campaign_binding.service_tier == trial.binding.service_tier
    assert result.run_id == result.outcome.run_binding.digest
    assert len(result.outcome.provider_requests) == 4
    assert all(request.usage is not None for request in result.outcome.provider_requests)
    assert all(
        request.requested_service_tier == "fast"
        and request.provider_reported_service_tier == "default"
        for request in result.outcome.provider_requests
    )
    assert FilesystemScope.TOOL in executor.scopes
    assert executor.scopes.count(FilesystemScope.EVALUATOR) == 2
    tool_plan = next(plan for plan in executor.plans.values() if plan.view is InvocationView.TOOL)
    assert tool_plan.arguments == ("--lint-only", "participant/design.sv")

    run_binding = result.outcome.run_binding
    assert run_binding is not None
    run_journal = TrialJournal.create(root / "runs", RunHeader.from_binding(run_binding), task)
    run_state = run_journal.state()
    assert run_state.checkpoint_ids == ("before_tool",)
    run_evidence = project_campaign_trial_run_evidence(run_journal.record(), task, store)
    assert run_evidence.resources == result.resources
    tool_records = tuple(
        event.payload.record
        for event in run_journal.read_events()
        if isinstance(event, ArtifactRecordedEvent)
        and event.payload.record.media_type == TOOL_EXECUTION_MEDIA_TYPE
    )
    assert len(tool_records) == 1
    assert len(run_evidence.participant_tool_executions) == 1
    tool_evidence = run_evidence.participant_tool_executions[0]
    assert tool_evidence.tool_id == "verilator"
    assert tool_evidence.input_manifest_digest == tool_plan.input_manifest_digest
    assert tool_evidence.outcome is ToolObservationOutcome.PASSED
    tool_results = tuple(
        event
        for event in run_journal.read_events()
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
        and event.artifact_refs == (tool_records[0].logical_id,)
    )
    assert len(tool_results) == 1

    report = reopened.build_report()
    assert report.campaign_record_digest == result.campaign_record_digest
    assert report.resources.requests == 4
    assert report.token_accounting.provider_input_tokens == 10
    assert report.token_accounting.provider_output_tokens == 4
    assert tuple(
        (item.service_tier, item.count)
        for item in report.service_tier_accounting.requested_service_tiers
    ) == (("fast", 4),)
    assert report.service_tier_accounting.reported_tier_mismatches.numerator == 4
    assert report.service_tier_accounting.reported_tier_mismatches.denominator == 4
    assert report.trials[0].outcome == result.outcome
    assert report.trials[0].resources.requests == 4
    assert report.trials[0].resources.tool_calls == result.resources.tool_calls
    assert _INSTRUCTION.encode("utf-8") not in canonical_bytes(run_journal.record())
    assert _INSTRUCTION.encode("utf-8") not in canonical_bytes(reopened.journal.record())

    with pytest.raises(ValueError, match="terminal outcome"):
        CampaignTrialDispatcher(reopened).dispatch(
            trial_id=trial.trial_id,
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            sender=_sender(
                reopened,
                configuration,
                unused_transport,
                task=task,
                release=release,
                environment=environment,
                session=session,
            ),
            instruction=_INSTRUCTION,
            asset_source_policy=load_system_asset_source_policy(),
            run_state_root=root / "runs",
            runtime_root=root / "runtime",
            artifact_store=store,
            executor=executor,
            evaluators=evaluators,
            participant_files={"participant/design.sv": source},
            clock=lambda: _NOW,
            poll_interval_seconds=0,
        )


def test_campaign_trial_restart_charges_unsettled_tool_reservation(
    tmp_path: Path,
) -> None:
    root = _private_directory(tmp_path / "tool-restart")
    runner, task, instance, release, environment, session, configuration = _campaign_inputs(root)
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=environment.artifact_policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"k" * 32),
    )
    executor = _RestartingToolExecutor(environment, store)
    evaluators = tuple(
        _Evaluator(task, environment, spec.evaluator_id) for spec in task.evaluation.evaluators
    )
    source = root / "design.sv"
    source.write_bytes(b"participant-design")
    trial = runner.schedule.trials[0]
    interrupted_transport = _SequenceTransport("provider.route.snapshot")

    with pytest.raises(_InjectedControllerRestart):
        CampaignTrialDispatcher(runner).dispatch(
            trial_id=trial.trial_id,
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            sender=_sender(
                runner,
                configuration,
                interrupted_transport,
                task=task,
                release=release,
                environment=environment,
                session=session,
            ),
            instruction=_INSTRUCTION,
            asset_source_policy=load_system_asset_source_policy(),
            run_state_root=root / "runs",
            runtime_root=root / "runtime",
            artifact_store=store,
            executor=executor,
            evaluators=evaluators,
            participant_files={"participant/design.sv": source},
            clock=lambda: _NOW,
            poll_interval_seconds=0,
        )
    assert interrupted_transport.calls == 2

    reopened = CampaignRunner(header=runner.header, state_root=root / "campaign")
    resumed_transport = _SequenceTransport(
        "provider.route.snapshot",
        start_index=2,
    )
    result = CampaignTrialDispatcher(reopened).dispatch(
        trial_id=trial.trial_id,
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        sender=_sender(
            reopened,
            configuration,
            resumed_transport,
            task=task,
            release=release,
            environment=environment,
            session=session,
        ),
        instruction=_INSTRUCTION,
        asset_source_policy=load_system_asset_source_policy(),
        run_state_root=root / "runs",
        runtime_root=root / "runtime",
        artifact_store=store,
        executor=executor,
        evaluators=evaluators,
        participant_files={"participant/design.sv": source},
        provider_spend=KnownSpend(currency="USD", amount=Decimal("0.01")),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    assert resumed_transport.calls == 0
    assert result.outcome.terminal_reason is StopReason.EDA_COMPUTE_BUDGET
    assert len(result.outcome.provider_requests) == 2

    run_binding = result.outcome.run_binding
    assert run_binding is not None
    journal = TrialJournal.create(root / "runs", RunHeader.from_binding(run_binding), task)
    events = journal.read_events()
    reservations = tuple(
        event for event in events if isinstance(event, ParticipantToolReservedEvent)
    )
    losses = tuple(event for event in events if isinstance(event, ParticipantToolLostEvent))
    settlements = tuple(event for event in events if isinstance(event, ParticipantToolSettledEvent))
    assert len(reservations) == len(losses) == 1
    assert settlements == ()
    reservation = reservations[0]
    loss = losses[0]
    assert executor.abandoned == [reservation.payload.invocation_id]
    result_event = next(
        event
        for event in events
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
        and event.payload.related_interaction_id == reservation.payload.request_interaction_id
    )
    assert journal.events_committed_together((loss.event_id, result_event.event_id))
    assert (
        result.resources.eda_compute_seconds
        >= (reservation.payload.reserved_compute_milliseconds + 999) // 1000
    )
    assert result.resources.eda_compute_seconds > 0


def test_campaign_trial_journals_participant_license_custody(
    tmp_path: Path,
) -> None:
    root = _private_directory(tmp_path / "licensed-tool")
    runner, task, instance, release, environment, session, configuration = _campaign_inputs(
        root,
        licensed=True,
    )
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=environment.artifact_policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"k" * 32),
    )
    executor = _Executor(environment, store)
    evaluators = tuple(
        _Evaluator(task, environment, spec.evaluator_id) for spec in task.evaluation.evaluators
    )
    source = root / "design.sv"
    source.write_bytes(b"participant-design")
    transport = _SequenceTransport("provider.route.snapshot")
    trial = runner.schedule.trials[0]
    result = CampaignTrialDispatcher(runner).dispatch(
        trial_id=trial.trial_id,
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        sender=_sender(
            runner,
            configuration,
            transport,
            task=task,
            release=release,
            environment=environment,
            session=session,
        ),
        instruction=_INSTRUCTION,
        asset_source_policy=load_system_asset_source_policy(),
        run_state_root=root / "runs",
        runtime_root=root / "runtime",
        artifact_store=store,
        executor=executor,
        evaluators=evaluators,
        participant_files={"participant/design.sv": source},
        license_providers={
            "fake_license": FakeLicenseProvider(
                provider_id="fake_license",
                capacities={"rtl_simulation": 1},
            )
        },
        provider_spend=KnownSpend(currency="USD", amount=Decimal("0.01")),
        clock=lambda: _NOW,
        monotonic=_MonotonicTicker(),
        poll_interval_seconds=0,
    )
    assert result.outcome.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert result.resources.license_seconds > 0

    run_binding = result.outcome.run_binding
    assert run_binding is not None
    journal = TrialJournal.create(root / "runs", RunHeader.from_binding(run_binding), task)
    events = journal.read_events()
    reservation = next(
        event
        for event in events
        if isinstance(event, ParticipantToolReservedEvent)
        and event.payload.license_binding_id is not None
    )
    settlement = next(
        event
        for event in events
        if isinstance(event, ParticipantToolSettledEvent)
        and event.payload.request_interaction_id == reservation.payload.request_interaction_id
    )
    acquisition = next(
        event
        for event in events
        if isinstance(event, LicenseLeaseAcquiredEvent)
        and event.payload.job_id == reservation.payload.invocation_id
    )
    release_event = next(
        event
        for event in events
        if isinstance(event, LicenseLeaseReleasedEvent)
        and event.payload.job_id == reservation.payload.invocation_id
    )
    assert (
        reservation.sequence < acquisition.sequence < release_event.sequence < settlement.sequence
    )
    assert settlement.payload.license_milliseconds > 0


def test_campaign_trial_continues_same_run_after_human_handoff(
    tmp_path: Path,
) -> None:
    root = _private_directory(tmp_path / "hybrid-continuation")
    runner, task, instance, release, environment, session, configuration = _campaign_inputs(
        root,
        hybrid=True,
    )
    store = ContentAddressedStore(
        _private_directory(root / "store"),
        policy=environment.artifact_policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"k" * 32),
    )
    executor = _Executor(environment, store)
    evaluators = tuple(
        _Evaluator(task, environment, spec.evaluator_id) for spec in task.evaluation.evaluators
    )
    source = root / "design.sv"
    source.write_bytes(b"participant-design")
    trial = runner.schedule.trials[0]
    campaign_binding = campaign_trial_run_binding(runner, trial)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key=trial.trial_id,
        campaign=campaign_binding,
    )
    journal = TrialJournal.create(root / "runs", RunHeader.from_binding(plan.binding), task)
    prepared = prepare_trial_workspace(
        runtime_root=root / "runtime",
        journal=journal,
        environment=environment,
        session=session,
        release=release,
        participant_files={"participant/design.sv": source},
    )
    resources = session.resources
    work = runner.reserve_work(
        trial_id=trial.trial_id,
        claim=CampaignResources(
            turns=resources.max_turns,
            tool_calls=resources.max_tool_calls,
            wall_seconds=resources.max_wall_seconds,
            eda_compute_seconds=resources.max_eda_compute_seconds,
            license_seconds=resources.max_license_seconds,
            artifact_bytes=resources.max_artifact_bytes,
        ),
    )
    work.mark_dispatched()
    human = HumanParticipantAdapter(
        "operator",
        JsonLineHumanChannel(
            StringIO('{"kind":"transfer_control","next_writer":"solver"}\n'),
            StringIO(),
        ),
    )
    initial_runtime = RunOrchestrator.create(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key=trial.trial_id,
        campaign=campaign_binding,
        state_root=root / "runs",
        workspace=prepared.workspace,
        artifact_directory=prepared.artifact_directory,
        artifact_store=store,
        executor=executor,
        evaluators=evaluators,
        participant=HybridParticipantAdapter((human, _InactiveHarness())),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    handed_off = initial_runtime.advance()
    assert handed_off.current_writer == "solver"

    reopened = CampaignRunner(header=runner.header, state_root=root / "campaign")
    continuation = CampaignTrialContinuation(
        run_binding=plan.binding,
        run_record_digest=journal.integrity_digest(),
        current_harness_actor_id="solver",
        campaign_budget_binding_digest=reopened.budget_projection().digest,
    )
    transport = _SequenceTransport("provider.route.snapshot")
    result = CampaignTrialDispatcher(reopened).dispatch(
        trial_id=trial.trial_id,
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        sender=_sender(
            reopened,
            configuration,
            transport,
            task=task,
            release=release,
            environment=environment,
            session=session,
        ),
        instruction=_INSTRUCTION,
        asset_source_policy=load_system_asset_source_policy(),
        continuation=continuation,
        run_state_root=root / "runs",
        runtime_root=root / "runtime",
        artifact_store=store,
        executor=executor,
        evaluators=evaluators,
        participant_files={"participant/design.sv": source},
        provider_spend=KnownSpend(currency="USD", amount=Decimal("0.01")),
        clock=lambda: _NOW,
        poll_interval_seconds=0,
    )
    assert result.run_id == plan.binding.digest
    assert result.outcome.terminal_reason is StopReason.VERIFIER_SUCCESS
    assert transport.calls == 4
    events = journal.read_events()
    assert sum(isinstance(event, RunStartedEvent) for event in events) == 1
    assert sum(isinstance(event, ControlTransferredEvent) for event in events) == 1
    participant_evidence = project_participant_session_record(
        journal.record(),
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
    )
    assert len(participant_evidence.handoffs) == 1
    assert participant_evidence.participation is ParticipationKind.HYBRID
    transfer_sequence = next(
        action.sequence
        for action in participant_evidence.actions
        if action.kind is ParticipantActionKind.CONTROL_TRANSFER
    )
    provider_sequences = tuple(
        action.sequence
        for action in participant_evidence.actions
        if action.kind is ParticipantActionKind.PROVIDER_REQUEST
    )
    assert provider_sequences and transfer_sequence < min(provider_sequences)
    assert participant_evidence.final_writer == "solver"
    assert reopened.pending_trials() == ()


def test_provider_recovery_replays_exact_response_and_predispatch_cancellation(
    tmp_path: Path,
) -> None:
    root = _private_directory(tmp_path / "provider-recovery")
    runner, _, _, _, _, _, configuration = _campaign_inputs(root)
    trial = runner.schedule.trials[0]
    claim = RequestTokenClaim(input_tokens=8, output_tokens=4)
    completed = runner.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="completed_request",
        requested_model=trial.binding.requested_model,
        token_claim=claim,
        security_binding=_security_binding(runner),
    )
    completed.mark_dispatched()
    runner.reserve_provider_attempt(
        trial_id=trial.trial_id,
        request_key="cancelled_request",
        requested_model=trial.binding.requested_model,
        token_claim=claim,
        security_binding=_security_binding(runner),
    )

    reopened = CampaignRunner(header=runner.header, state_root=root / "campaign")
    requests = (
        ProviderRequestState(
            request_id="completed_request",
            actor_id="solver",
            request_artifact_id="completed_request_artifact",
            security_evidence_artifact_id="provider_canary_evidence",
            provider_profile_digest=configuration.profile.digest,
            provider_config_digest=configuration.digest,
            requested_model=trial.binding.requested_model,
            requested_service_tier=trial.binding.service_tier,
            security_binding=_security_binding(runner),
            reserved_input_tokens=claim.input_tokens,
            reserved_output_tokens=claim.output_tokens,
            provider_reported_model=trial.binding.qualified_provider_reported_model,
            provider_reported_service_tier="default",
            status=ProviderResponseStatus.COMPLETED,
            usage=ProviderUsage(
                input_tokens=3,
                output_tokens=2,
                total_tokens=5,
                cached_input_tokens=1,
                reasoning_tokens=1,
            ),
        ),
        ProviderRequestState(
            request_id="cancelled_request",
            actor_id="solver",
            request_artifact_id="cancelled_request_artifact",
            security_evidence_artifact_id="provider_canary_evidence",
            provider_profile_digest=configuration.profile.digest,
            provider_config_digest=configuration.digest,
            requested_model=trial.binding.requested_model,
            requested_service_tier=trial.binding.service_tier,
            security_binding=_security_binding(runner),
            reserved_input_tokens=claim.input_tokens,
            reserved_output_tokens=claim.output_tokens,
        ),
    )
    before_recovery = reopened.journal.record().integrity_digest
    with pytest.raises(
        CampaignAccountingError,
        match="differs from its campaign reservation",
    ):
        reopened.recover_incomplete_provider_dispatches(
            trial_id=trial.trial_id,
            provider_requests=(
                requests[0].model_copy(
                    update={"provider_config_digest": digest("wrong-provider-config")}
                ),
                requests[1],
            ),
        )
    assert reopened.journal.record().integrity_digest == before_recovery
    recovery = reopened.recover_incomplete_provider_dispatches(
        trial_id=trial.trial_id,
        provider_requests=requests,
    )
    assert recovery is not None
    assert len(recovery.reservation_ids) == 2
    events = reopened.journal.record().events
    settlement = next(
        event
        for event in events
        if isinstance(event, ProviderAttemptSettledEvent)
        and event.payload.attempt.request_key == "completed_request"
    )
    attempt = settlement.payload.attempt
    assert attempt.disposition is AttemptDisposition.COMPLETED
    assert attempt.provider_response_status is ProviderResponseStatus.COMPLETED
    assert attempt.provider_usage is not None
    assert attempt.provider_usage.total_tokens == 5
    assert attempt.charged_resources.input_tokens == 3
    assert any(isinstance(event, ReservationCancelledEvent) for event in events)
    assert (
        reopened.recover_incomplete_provider_dispatches(
            trial_id=trial.trial_id,
            provider_requests=requests,
        )
        is None
    )
