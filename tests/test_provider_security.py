"""Security evidence for credential acquisition and provider dispatch."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import ssl
import threading
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import edagym.security.collector as collector_module
from edagym.benchmark.model import EpisodeBudget
from edagym.executors.isolation_launch import (
    SyntheticPreflightExecutorReceipt,
    SyntheticPreflightParentReceipt,
    SyntheticPreflightProbeLaunchReceipt,
    synthetic_preflight_canary_binding_digest,
)
from edagym.executors.isolation_preflight import (
    ISOLATION_PROBE_IMPLEMENTATION_DIGEST,
    IsolationPreflightReceipt,
    IsolationProbeReceipt,
    IsolationProbeRole,
    isolation_probe_plan,
)
from edagym.executors.model import ExecutionResult, JobHandle, JobState, JobStateKind
from edagym.participants.execution import _issue_synthetic_preflight_execution_grant
from edagym.providers.budget import (
    BudgetExceeded,
    BudgetLedger,
    BudgetLimits,
    BudgetReservation,
    BudgetSnapshot,
)
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
from edagym.providers.campaign_runner import (
    CampaignAccountingError,
    CampaignRunner,
)
from edagym.providers.campaign_schedule import (
    CampaignTask,
    CampaignTaskRole,
    MeteredProviderHarnessBinding,
    ScheduledTrial,
)
from edagym.providers.model import (
    FunctionCall,
    FunctionCallStatus,
    FunctionTool,
    InputMessage,
    InputRole,
    OutputText,
    ProviderDefaults,
    ProviderProfile,
    ProviderSecurityBinding,
    ProviderUsage,
    ProviderWire,
    RequestTokenClaim,
    ResolvedProviderConfig,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
    ResponsesWire,
    ToolParameter,
    ToolValueKind,
)
from edagym.providers.provider_budget import (
    CampaignProviderBudget,
    ProviderBudget,
    StandaloneProviderBudget,
)
from edagym.providers.qualification import RouteCanaryError, run_route_canary
from edagym.providers.responses import (
    DirectHttpsTransport,
    ProviderHttpError,
    ProviderProtocolError,
    ProviderRedirectError,
    ProviderTransportError,
    RawHttpResponse,
    ResponsesBroker,
    ResponsesCampaign,
)
from edagym.providers.trial_security import (
    campaign_trial_run_binding,
    runtime_surface_binding_for_trial,
)
from edagym.resolution import resolve_run
from edagym.run.artifact_model import (
    BlobRef,
)
from edagym.run.artifacts import ContentAddressedStore, EncryptionKey
from edagym.run.trial_model import (
    CampaignTrialRunBinding,
    ParticipantIncarnationBinding,
    ParticipantIncarnationStartedEvent,
    ParticipantIncarnationStartedPayload,
    ParticipantProcessIdentity,
    ProducerKind,
    RunCommit,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunPurpose,
    RunRecord,
    RunStartedEvent,
    RunStartedPayload,
    StopReason,
    run_journal_anchor,
)
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    IsolationSurface,
)
from edagym.security.canary import (
    CanaryAttestation,
    CanaryChallenge,
    CanaryExposure,
    CanaryPolicy,
    CanaryProtocolError,
)
from edagym.security.canary_artifact import (
    ProviderCanaryEvidence,
    store_provider_canary_evidence,
    verify_provider_canary_evidence,
)
from edagym.security.collector import IsolationSurfaceCollector, RuntimeSurfaceIssuer
from edagym.security.credentials import (
    CredentialLease,
    ProviderAccessGrant,
    ProviderAccessLease,
)
from edagym.security.runtime_surface import (
    RuntimeSurfaceBinding,
    runtime_surface_export_policy_digest,
)
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Digest,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import ArtifactPolicy, EnvironmentSpec, ManagedEncryption
from edagym.specs.release import ReleaseManifest
from edagym.specs.session import HarnessActor, SessionSpec
from edagym.specs.task import TaskSpec
from tests.campaign_fixtures import campaign_cells, campaign_header
from tests.factories import (
    SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _seed(value: int) -> str:
    return f"{value:032x}"


def _clean_attestation(
    configuration: ResolvedProviderConfig,
    campaign_digest: str,
    budget: ProviderBudget,
    surface_root: Path,
    *,
    runner: CampaignRunner | None = None,
) -> tuple[CanaryPolicy, CanaryAttestation]:
    policy = CanaryPolicy(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=budget.binding_digest,
    )
    challenge = CanaryChallenge(policy=policy, campaign_digest=campaign_digest)
    controller_environment: dict[str, str] = {}
    challenge.install_controller_environment(controller_environment)
    _install_synthetic_credential(challenge, surface_root / "controller")
    _complete_synthetic_parent_launches(challenge)
    marker = next(iter(controller_environment.values())).encode("ascii")
    assert repr(challenge) == "CanaryChallenge(<redacted>)"
    attestation = challenge.attest(
        _surface_collector(
            surface_root,
            configuration=configuration,
            campaign_digest=campaign_digest,
            budget=budget,
            canary_marker=marker,
            runner=runner,
        )
    )
    assert controller_environment == {}
    return policy, attestation


def _install_synthetic_credential(challenge: CanaryChallenge, root: Path) -> Path:
    root.mkdir(mode=0o700, parents=True)
    path = root / "synthetic-credential"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        challenge._install_credential_descriptor(descriptor)
    finally:
        os.close(descriptor)
    return path


def _complete_synthetic_parent_launches(challenge: CanaryChallenge) -> None:
    """Stand in for the concrete executor that launches every fixed probe once."""

    claim = challenge._issue_launch_capability()._claim()
    try:
        process_environment = claim._parent_environment({})
        for role in IsolationProbeRole:
            container_argv = (
                "run",
                "--network=none",
                "--pid=private",
                "--read-only",
                "--unsetenv-all",
                f"--name=isolation_probe_{role.value}",
                "sh",
            )
            claim._validate_parent_launch(
                process_environment=process_environment,
                parent_argv=("podman", *container_argv),
                container_argv=container_argv,
                pass_fds=(),
            )
    finally:
        claim.close()


def _surface_collector(
    root: Path,
    *,
    configuration: ResolvedProviderConfig,
    campaign_digest: Digest,
    budget: ProviderBudget,
    canary_marker: bytes,
    runner: CampaignRunner | None = None,
) -> IsolationSurfaceCollector:
    return _collector_from_paths(
        _surface_paths(root),
        configuration=configuration,
        campaign_digest=campaign_digest,
        budget=budget,
        canary_marker=canary_marker,
        runner=runner,
    )


def _surface_paths(root: Path) -> dict[IsolationSurface, Path]:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    paths: dict[IsolationSurface, Path] = {}
    for surface in REQUIRED_ISOLATION_SURFACES:
        path = root / surface.value
        path.mkdir(mode=0o700)
        paths[surface] = path
    return paths


def _preflight_bindings(
    *,
    configuration: ResolvedProviderConfig,
    campaign_digest: Digest,
    budget: ProviderBudget,
    task: TaskSpec,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    runner: CampaignRunner | None,
) -> tuple[SessionSpec, CampaignTrialRunBinding, RuntimeSurfaceBinding]:
    """Bind the preflight to the runner's sole scheduled trial or to a standalone probe."""

    if runner is not None:
        (trial,) = runner.schedule.trials
        session = _campaign_trial_session(trial)
        return (
            session,
            campaign_trial_run_binding(runner, trial),
            runtime_surface_binding_for_trial(
                runner=runner,
                trial=trial,
                task=task,
                release=release,
                environment=environment,
                session=session,
            ),
        )
    session = session_spec()
    (harness,) = (actor for actor in session.actors if isinstance(actor, HarnessActor))
    campaign = CampaignTrialRunBinding(
        campaign_digest=campaign_digest,
        schedule_digest=_digest("preflight-schedule"),
        scheduled_trial_digest=_digest("preflight-trial"),
        paired_seed=_seed(1),
        repetition_index=0,
        route_id="preflight_route",
        reasoning_effort="high",
        service_tier="fast",
    )
    binding = RuntimeSurfaceBinding(
        campaign_digest=campaign_digest,
        campaign_schedule_digest=campaign.schedule_digest,
        scheduled_trial_digest=campaign.scheduled_trial_digest,
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=budget.binding_digest,
        task_release_digest=release.digest,
        environment_spec_digest=environment.digest,
        session_spec_digest=session.digest,
        harness_digest=harness.harness_digest,
        harness_schema_digest=_digest("preflight-harness-schema"),
        executor_digest=environment.executor.implementation_digest,
        export_policy_digest=runtime_surface_export_policy_digest(environment),
    )
    return session, campaign, binding


def _campaign_trial_session(trial: ScheduledTrial) -> SessionSpec:
    """Session whose sole harness actor is the one frozen by the scheduled trial."""

    harness = trial.binding.harness
    base = session_spec()
    return SessionSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "actors": (
                HarnessActor(
                    actor_id="solver",
                    harness_id=harness.harness_id,
                    harness_digest=trial.binding.harness_digest,
                    scaffold_digest=harness.scaffold_digest,
                    requested_model_route=trial.binding.requested_model,
                ),
            ),
        }
    )


def _collector_from_paths(
    paths: dict[IsolationSurface, Path],
    *,
    configuration: ResolvedProviderConfig,
    campaign_digest: Digest,
    budget: ProviderBudget,
    canary_marker: bytes,
    artifact_store: ContentAddressedStore | None = None,
    environment: EnvironmentSpec | None = None,
    runner: CampaignRunner | None = None,
) -> IsolationSurfaceCollector:
    resolved_environment = environment or environment_spec()
    resolved_store = artifact_store or ContentAddressedStore(
        paths[IsolationSurface.ARTIFACT_STORE],
        policy=resolved_environment.artifact_policy,
    )
    task = task_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, resolved_environment)
    session, campaign, binding = _preflight_bindings(
        configuration=configuration,
        campaign_digest=campaign_digest,
        budget=budget,
        task=task,
        release=release,
        environment=resolved_environment,
        runner=runner,
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=resolved_environment,
        session=session,
        trial_key="credential-preflight",
        campaign=campaign,
        purpose=RunPurpose.SYNTHETIC_PREFLIGHT,
    )
    header = RunHeader.from_binding(plan.binding)
    events = (
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID(int=1),
            timestamp=datetime(2026, 9, 4, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        ),
        ParticipantIncarnationStartedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID(int=2),
            timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
            payload=ParticipantIncarnationStartedPayload(
                incarnation=ParticipantIncarnationBinding(
                    generation=0,
                    process=ParticipantProcessIdentity(
                        process_id=1,
                        start_time_ticks=1,
                        boot_id_digest=_digest("preflight-boot"),
                    ),
                    workspace_identity_digest=_digest("preflight-workspace"),
                    artifact_directory_identity_digest=_digest("preflight-artifact-directory"),
                )
            ),
        ),
        RunEndedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID(int=3),
            timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
        ),
    )
    record = RunRecord(
        header=header,
        commits=(
            RunCommit.from_events(
                previous_record_digest=run_journal_anchor(header),
                events=events,
            ),
        ),
    )
    descriptors = tuple(
        (
            surface,
            os.open(
                paths[surface],
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            ),
        )
        for surface in REQUIRED_ISOLATION_SURFACES
    )
    grant = _issue_synthetic_preflight_execution_grant(
        surfaces=descriptors,
        artifact_store=resolved_store,
        preflight_run_id=record.header.run_id,
        run_binding_digest=record.header.binding.digest,
        runtime_surface_binding=binding,
        executor_receipt=_synthetic_preflight_executor_receipt(
            resolved_environment,
            artifact_store_policy_digest=resolved_store.policy_digest,
            canary_marker=canary_marker,
        ),
        launcher_receipt_digest=_digest("preflight-launcher-receipt"),
    )
    issuer = RuntimeSurfaceIssuer(
        preflight_record=record,
        task=task,
        environment=resolved_environment,
        session=session,
        execution_grant=grant,
    )
    return IsolationSurfaceCollector(issuer)


def _synthetic_preflight_executor_receipt(
    environment: EnvironmentSpec,
    *,
    artifact_store_policy_digest: Digest,
    canary_marker: bytes,
) -> SyntheticPreflightExecutorReceipt:
    """Fabricate the executor launch receipt of a completed fixed probe set.

    The grant binds only the receipt digests, so probe artifacts are digest-only
    references that never touch the artifact store.
    """

    executor_id = environment.executor.executor_id
    stdout = BlobRef(digest=_digest("preflight-probe-stdout"), size_bytes=0)
    stderr = BlobRef(digest=_digest("preflight-probe-stderr"), size_bytes=0)
    probes: list[IsolationProbeReceipt] = []
    parent_launches: list[SyntheticPreflightProbeLaunchReceipt] = []
    for role in IsolationProbeRole:
        plan = isolation_probe_plan(
            role=role,
            invocation_id=f"isolation_probe_{role.value}",
            environment_spec_digest=environment.digest,
        )
        probes.append(
            IsolationProbeReceipt(
                role=role,
                plan=plan,
                execution=ExecutionResult(
                    state=JobState(
                        handle=JobHandle(
                            job_id=plan.invocation_id,
                            invocation_digest=plan.digest,
                            executor_id=executor_id,
                        ),
                        state=JobStateKind.COMPLETED,
                        exit_code=0,
                    ),
                    stdout=stdout,
                    stderr=stderr,
                ),
            )
        )
        parent_launches.append(
            SyntheticPreflightProbeLaunchReceipt(
                role=role,
                parent_launch_digest=_digest(f"preflight-parent-launch-{role.value}"),
            )
        )
    return SyntheticPreflightExecutorReceipt(
        isolation_preflight=IsolationPreflightReceipt(
            environment_spec_digest=environment.digest,
            executor_id=executor_id,
            executor_implementation_digest=environment.executor.implementation_digest,
            isolation_capability_digest=_digest("preflight-isolation-capability"),
            probe_implementation_digest=ISOLATION_PROBE_IMPLEMENTATION_DIGEST,
            artifact_store_policy_digest=artifact_store_policy_digest,
            probes=tuple(probes),
        ),
        parent_launch=SyntheticPreflightParentReceipt(
            canary_launch_binding_digest=synthetic_preflight_canary_binding_digest(canary_marker),
            controller_boundary_digest=_digest("preflight-controller-boundary"),
            probes=tuple(parent_launches),
        ),
    )


class _StaticCredentialSource:
    def __init__(self, configuration: ResolvedProviderConfig) -> None:
        self.configuration = configuration
        self.calls = 0

    def acquire(self, *, grant: ProviderAccessGrant) -> ProviderAccessLease:
        self.calls += 1
        assert (
            grant._consume(provider_profile_digest=self.configuration.profile.digest)
            == self.configuration.digest
        )
        lease = CredentialLease(
            bytearray(b"stub"),
            profile_digest=self.configuration.profile.digest,
        )
        return ProviderAccessLease(self.configuration, lease)


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def exchange(
        self,
        *,
        profile: ProviderProfile,
        headers: Mapping[str, str],
        body: bytes,
    ) -> RawHttpResponse:
        self.calls += 1
        return RawHttpResponse(status=500, headers={}, body=b"")


class _RecordingExchangeObserver:
    def __init__(self, *, trial_id: str) -> None:
        self.trial_id = trial_id
        self.request_body: bytes | None = None
        self.response_body: bytes | None = None
        self.result: ResponsesResult | None = None

    def request_reserved(
        self,
        *,
        trial_id: str,
        request_key: str,
        provider_profile_digest: str,
        provider_config_digest: str,
        security_binding: ProviderSecurityBinding,
        canary_evidence: ProviderCanaryEvidence,
        request_body: bytes,
        beta_features: tuple[str, ...],
    ) -> None:
        assert beta_features == ()
        assert trial_id == self.trial_id
        assert provider_profile_digest.startswith("sha256:")
        assert provider_config_digest.startswith("sha256:")
        assert security_binding.budget_binding_digest.startswith("sha256:")
        assert canary_evidence.receipt.digest == security_binding.canary_receipt_digest
        self.request_body = request_body

    def response_rejected(self, *, response_body: bytes) -> None:
        self.response_body = response_body

    def response_received(
        self,
        *,
        response_body: bytes,
        result: ResponsesResult,
    ) -> None:
        self.response_body = response_body
        self.result = result


class _RejectingExchangeObserver(_RecordingExchangeObserver):
    def request_reserved(
        self,
        *,
        trial_id: str,
        request_key: str,
        provider_profile_digest: str,
        provider_config_digest: str,
        security_binding: ProviderSecurityBinding,
        canary_evidence: ProviderCanaryEvidence,
        request_body: bytes,
        beta_features: tuple[str, ...],
    ) -> None:
        del trial_id, provider_profile_digest, provider_config_digest
        del security_binding, canary_evidence, request_body, beta_features
        raise RuntimeError("observer rejected request")


def _budget(*, requests: int = 4, tokens: int = 100) -> BudgetLedger:
    return BudgetLedger(
        BudgetLimits(
            max_requests=requests,
            max_input_tokens=tokens,
            max_output_tokens=tokens,
            max_total_tokens=tokens * 2,
            max_requests_per_trial=requests,
            max_input_tokens_per_trial=tokens,
            max_output_tokens_per_trial=tokens,
            max_total_tokens_per_trial=tokens * 2,
        )
    )


def _campaign_runner(
    configuration: ResolvedProviderConfig,
    state_root: Path,
) -> CampaignRunner:
    route = ModelRoute(
        route_id="shared_route",
        requested_model="route.test",
        provider_reported_model="route.test",
        reference_kind=ModelReferenceKind.UNKNOWN,
        categories=(
            ModelCategory.FRONTIER_REASONING,
            ModelCategory.CODING_AGENT,
            ModelCategory.BALANCED,
            ModelCategory.HIGH_THROUGHPUT,
        ),
        qualification=RouteQualification(
            reasoning_control=FeatureSupport.SUPPORTED,
            requested_service_tier="fast",
            canary_tool_schema_digest=_digest("campaign-route-tool-schema"),
            canary_evidence_digest=_digest("campaign-route-canary"),
        ),
    )
    model_set = ModelSetManifest(
        provider_config_digest=configuration.digest,
        discovery_digest=_digest("campaign-model-discovery"),
        resolved_on="2026-09-04",
        routes=(route,),
    )
    task = task_spec()
    environment = environment_spec()
    release = release_manifest(task, task_instance(task), environment)
    harness = MeteredProviderHarnessBinding(
        harness_id="campaign-harness",
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        instruction_digest=_digest("campaign-prompt"),
        tool_schema_digest=_digest("campaign-tools"),
        scaffold_digest=_digest("campaign-scaffold"),
        maximum_requests_per_action=4,
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
        campaign_id="provider-campaign",
        scope=CampaignScope.EXPANDED_BREADTH,
        schedule_seed=_seed(2),
        retry_policy=RetryPolicy(max_request_attempts=1, backoff_milliseconds=0),
        provider_spend_limit=CappedSpendLimit(currency="USD", amount=Decimal("1")),
        model_set=model_set,
        provider_config=configuration,
        tasks=(campaign_task,),
        repetition_count=1,
        cells=campaign_cells(
            model_set=model_set,
            harnesses=(harness,),
            feedback_policy_digest=_digest("campaign-feedback"),
        ),
        episode_budget=EpisodeBudget(
            max_experiments=8,
            max_requests=4,
            max_input_tokens_per_request=100,
            max_output_tokens_per_request=100,
            max_input_tokens=400,
            max_output_tokens=400,
            max_total_tokens=800,
            max_turns=8,
            max_tool_calls=16,
            max_wall_seconds=600,
            max_eda_compute_seconds=300,
            max_license_seconds=120,
            max_artifact_bytes=1 << 20,
        ),
        token_limits=CampaignTokenLimits(
            max_requests=4, max_input_tokens=400, max_output_tokens=400, max_total_tokens=800
        ),
        execution_limits=CampaignExecutionLimits(
            max_turns=8,
            max_tool_calls=16,
            max_wall_seconds=600,
            max_eda_compute_seconds=300,
            max_license_seconds=120,
            max_artifact_bytes=1 << 20,
        ),
    )
    return CampaignRunner(header=header, state_root=state_root)


def _request(
    *,
    input_tokens: int = 10,
    output_tokens: int = 10,
    service_tier: str | None = None,
) -> ResponsesRequest:
    return ResponsesRequest(
        model="route.test",
        inputs=(InputMessage(role=InputRole.USER, content="confidential prompt"),),
        service_tier=service_tier,
        token_claim=RequestTokenClaim(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        ),
    )


def test_required_strict_tool_choice_has_one_wire_contract() -> None:
    with pytest.raises(ValueError):
        FunctionTool(
            name="probe",
            description="Return the protocol probe.",
            parameters=(
                ToolParameter(
                    name="value",
                    kind=ToolValueKind.STRING,
                    description="Probe value.",
                    required=False,
                ),
            ),
        )

    tool = FunctionTool(
        name="probe",
        description="Return the protocol probe.",
        parameters=(
            ToolParameter(
                name="value",
                kind=ToolValueKind.STRING,
                description="Probe value.",
            ),
        ),
    )
    request = ResponsesRequest(
        model="route.test",
        inputs=(InputMessage(role=InputRole.USER, content="Call the probe tool."),),
        tools=(tool,),
        tool_choice_required=True,
        token_claim=RequestTokenClaim(input_tokens=10, output_tokens=10),
    )

    payload = request._wire_payload()
    assert payload["tool_choice"] == "required"
    assert payload["tools"] == [
        {
            "type": "function",
            "name": "probe",
            "description": "Return the protocol probe.",
            "parameters": {
                "type": "object",
                "properties": {"value": {"type": "string", "description": "Probe value."}},
                "required": ["value"],
                "additionalProperties": False,
            },
            "strict": True,
        }
    ]


class _CanarySender:
    def __init__(self, arguments: str) -> None:
        self.arguments = arguments

    def request(
        self,
        *,
        trial_id: str,
        request_key: str,
        request: ResponsesRequest,
    ) -> ResponsesResult:
        assert trial_id == "route_canary"
        assert request_key == "route_canary_request"
        assert request.tool_choice_required
        return ResponsesResult(
            response_id="restricted-response-id",
            reported_model="provider.route.snapshot",
            reported_service_tier="default",
            status=ResponseStatus.COMPLETED,
            outputs=(
                FunctionCall(
                    call_id="restricted-call-id",
                    name="edagym_protocol_canary",
                    arguments=self.arguments,
                    status=FunctionCallStatus.COMPLETED,
                ),
            ),
            usage=ProviderUsage(input_tokens=31, output_tokens=7, total_tokens=38),
        )


def test_paid_route_canary_requires_exact_tool_arguments_and_real_usage() -> None:
    nonce = "0123456789abcdef0123456789abcdef"
    evidence = run_route_canary(
        _CanarySender(json.dumps({"protocol": "responses", "nonce": nonce})),
        trial_id="route_canary",
        requested_model="route.test",
        nonce=nonce,
        token_claim=RequestTokenClaim(input_tokens=128, output_tokens=128),
        reasoning_effort="low",
        service_tier="fast",
    )
    assert evidence.provider_reported_model == "provider.route.snapshot"
    assert evidence.service_tier_requested == "fast"
    assert evidence.provider_reported_service_tier == "default"
    assert evidence.usage.total_tokens == 38
    assert evidence.reasoning_control is FeatureSupport.SUPPORTED
    assert "restricted-response-id" not in evidence.model_dump_json()

    with pytest.raises(RouteCanaryError):
        run_route_canary(
            _CanarySender(json.dumps({"protocol": "responses", "nonce": "0" * 32})),
            trial_id="route_canary",
            requested_model="route.test",
            nonce=nonce,
            token_claim=RequestTokenClaim(input_tokens=128, output_tokens=128),
            reasoning_effort="low",
            service_tier="fast",
        )


def test_canary_receipt_binds_a_path_free_terminal_runtime_manifest(
    tmp_path: Path,
) -> None:
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    campaign_digest = _digest("manifest-campaign")
    budget = StandaloneProviderBudget(
        campaign_digest=campaign_digest,
        ledger=_budget(),
    )
    policy, attestation = _clean_attestation(
        configuration,
        campaign_digest,
        budget,
        tmp_path / "manifest-preflight",
    )

    manifest = attestation.runtime_surface_manifest
    assert manifest.preflight_run_id == manifest.run_binding_digest
    assert manifest.binding.digest.startswith("sha256:")
    assert manifest.artifact_closure_receipt_digest.startswith("sha256:")
    serialized = manifest.model_dump_json()
    assert str(tmp_path) not in serialized
    receipt = attestation.consume(
        policy_digest=policy.digest,
        campaign_digest=campaign_digest,
        provider_profile_digest=configuration.profile.digest,
    )
    assert receipt.manifest_digest == manifest.digest
    assert receipt.digest.startswith("sha256:")
    evidence = ProviderCanaryEvidence(
        policy=policy,
        receipt=receipt,
        runtime_surface_manifest=manifest,
    )
    evidence_store = ContentAddressedStore(
        tmp_path / "canary-evidence-cas",
        policy=environment_spec().artifact_policy,
    )
    evidence_record = store_provider_canary_evidence(evidence, evidence_store)
    assert evidence_record.logical_id == evidence.artifact_id
    assert verify_provider_canary_evidence(evidence_record, evidence_store) == evidence


def test_canary_rejects_a_grant_bound_to_another_marker(tmp_path: Path) -> None:
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    campaign_digest = _digest("marker-binding-campaign")
    budget = StandaloneProviderBudget(
        campaign_digest=campaign_digest,
        ledger=_budget(),
    )
    policy = CanaryPolicy(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=budget.binding_digest,
    )
    challenge = CanaryChallenge(policy=policy, campaign_digest=campaign_digest)
    controller_environment: dict[str, str] = {}
    challenge.install_controller_environment(controller_environment)
    _install_synthetic_credential(challenge, tmp_path / "controller")
    _complete_synthetic_parent_launches(challenge)
    collector = _surface_collector(
        tmp_path / "preflight",
        configuration=configuration,
        campaign_digest=campaign_digest,
        budget=budget,
        canary_marker=b"different-synthetic-marker",
    )

    with pytest.raises(CanaryProtocolError, match="did not bind this canary"):
        challenge.attest(collector)
    assert controller_environment == {}


def test_canary_rejects_and_zeroizes_a_changed_synthetic_credential(
    tmp_path: Path,
) -> None:
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    campaign_digest = _digest("credential-file-campaign")
    budget = StandaloneProviderBudget(
        campaign_digest=campaign_digest,
        ledger=_budget(),
    )
    policy = CanaryPolicy(
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=budget.binding_digest,
    )
    challenge = CanaryChallenge(policy=policy, campaign_digest=campaign_digest)
    controller_environment: dict[str, str] = {}
    challenge.install_controller_environment(controller_environment)
    marker = next(iter(controller_environment.values())).encode("ascii")
    credential_path = _install_synthetic_credential(challenge, tmp_path / "controller")
    credential_path.write_bytes(b"changed")
    credential_path.chmod(0o600)
    collector = _surface_collector(
        tmp_path / "preflight",
        configuration=configuration,
        campaign_digest=campaign_digest,
        budget=budget,
        canary_marker=marker,
    )

    with pytest.raises(CanaryProtocolError, match="credential marker changed"):
        challenge.attest(collector)
    assert controller_environment == {}
    assert credential_path.read_bytes() == b""


def test_canary_binding_and_budget_gate_run_before_network_or_credential_reuse(
    tmp_path: Path,
) -> None:
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    campaign_digest = _digest("campaign")
    credentials = _StaticCredentialSource(configuration)
    transport = _RecordingTransport()
    broker = ResponsesBroker(transport)
    ledger = _budget(tokens=4)
    budget = StandaloneProviderBudget(campaign_digest=campaign_digest, ledger=ledger)
    policy, wrong_attestation = _clean_attestation(
        configuration,
        _digest("other-campaign"),
        StandaloneProviderBudget(
            campaign_digest=_digest("other-campaign"),
            ledger=ledger,
        ),
        tmp_path / "wrong-preflight",
    )

    with pytest.raises(ProviderProtocolError, match="runtime surface manifest"):
        broker.open_probe(
            configuration=configuration,
            campaign_digest=campaign_digest,
            policy=policy,
            attestation=wrong_attestation,
            credentials=credentials,
            budget=budget,
        )
    assert credentials.calls == 0
    assert transport.calls == 0
    assert ledger.snapshot().reserved_requests == 0

    policy, attestation = _clean_attestation(
        configuration,
        campaign_digest,
        budget,
        tmp_path / "preflight",
    )
    mismatched_budget = StandaloneProviderBudget(
        campaign_digest=campaign_digest,
        ledger=_budget(tokens=8),
    )
    with pytest.raises(ProviderProtocolError):
        broker.open_probe(
            configuration=configuration,
            campaign_digest=campaign_digest,
            policy=policy,
            attestation=attestation,
            credentials=credentials,
            budget=mismatched_budget,
        )
    assert credentials.calls == 0

    campaign = broker.open_probe(
        configuration=configuration,
        campaign_digest=campaign_digest,
        policy=policy,
        attestation=attestation,
        credentials=credentials,
        budget=budget,
    )
    assert campaign.canary_receipt.collection_evidence_digest.startswith("sha256:")
    assert campaign.campaign_digest == campaign_digest
    assert campaign.campaign_schedule_digest is None
    assert campaign.provider_profile_digest == configuration.profile.digest
    assert campaign.provider_config_digest == configuration.digest
    assert campaign.budget_binding_digest == budget.binding_digest
    with pytest.raises(CanaryProtocolError):
        broker.open_probe(
            configuration=configuration,
            campaign_digest=campaign_digest,
            policy=policy,
            attestation=attestation,
            credentials=credentials,
            budget=budget,
        )
    assert credentials.calls == 1

    with pytest.raises(BudgetExceeded):
        campaign.request(
            trial_id="budget-gate",
            request_key="budget_gate_request",
            request=_request(input_tokens=5, output_tokens=5),
        )
    assert transport.calls == 0
    campaign.close()


def test_observer_failure_cancels_atomic_reservation_before_dispatch(tmp_path: Path) -> None:
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    campaign_digest = _digest("observer-campaign")
    credentials = _StaticCredentialSource(configuration)
    transport = _RecordingTransport()
    ledger = _budget()
    budget = StandaloneProviderBudget(campaign_digest=campaign_digest, ledger=ledger)
    policy, attestation = _clean_attestation(
        configuration,
        campaign_digest,
        budget,
        tmp_path / "preflight",
    )
    campaign = ResponsesBroker(transport).open_probe(
        configuration=configuration,
        campaign_digest=campaign_digest,
        policy=policy,
        attestation=attestation,
        credentials=credentials,
        budget=budget,
    )

    with campaign, pytest.raises(RuntimeError, match="observer rejected"):
        campaign.request(
            trial_id="direct-probe",
            request_key="observer_request",
            request=_request(),
            observer=_RejectingExchangeObserver(trial_id="direct-probe"),
        )

    assert transport.calls == 0
    assert ledger.snapshot() == BudgetSnapshot(
        committed_requests=0,
        reserved_requests=0,
        committed_input_tokens=0,
        reserved_input_tokens=0,
        committed_output_tokens=0,
        reserved_output_tokens=0,
        violated=False,
    )


def test_scheduled_transport_settles_the_campaign_runner_ledger(tmp_path: Path) -> None:
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    runner = _campaign_runner(configuration, tmp_path / "campaign-state")
    (trial,) = runner.schedule.trials
    budget = CampaignProviderBudget(runner)
    credentials = _StaticCredentialSource(configuration)
    transport = _RecordingTransport()
    policy, attestation = _clean_attestation(
        configuration,
        runner.campaign.digest,
        budget,
        tmp_path / "preflight",
        runner=runner,
    )
    campaign = ResponsesBroker(transport).open_trial_sender(
        configuration=configuration,
        runner=runner,
        trial_id=trial.trial_id,
        policy=policy,
        attestation=attestation,
        credentials=credentials,
    )
    assert campaign.bound_trial_id == trial.trial_id
    assert campaign.campaign_digest == runner.campaign.digest
    assert campaign.campaign_schedule_digest == runner.schedule.digest
    assert campaign.provider_profile_digest == configuration.profile.digest
    assert campaign.provider_config_digest == configuration.digest
    assert campaign.budget_binding_digest == budget.binding_digest

    with campaign, pytest.raises(ProviderHttpError):
        campaign.request(
            trial_id=trial.trial_id,
            request_key="solve",
            request=_request(),
            observer=_RecordingExchangeObserver(trial_id=trial.trial_id),
        )

    assert transport.calls == 1
    with pytest.raises(CampaignAccountingError, match="poisoned"):
        runner.reserve_provider_attempt(
            trial_id=trial.trial_id,
            request_key="solve",
            requested_model=trial.binding.requested_model,
            token_claim=RequestTokenClaim(input_tokens=10, output_tokens=10),
            security_binding=campaign.provider_security_binding,
        )


def test_forged_clean_canary_observations_cannot_issue_an_attestation(tmp_path: Path) -> None:
    profile = ProviderProfile(
        logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
    )
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=profile,
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    ledger = _budget()
    policy = CanaryPolicy(
        provider_profile_digest=profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=ledger.limits_digest,
    )
    challenge = CanaryChallenge(policy=policy, campaign_digest=_digest("campaign"))
    controller_environment: dict[str, str] = {}
    challenge.install_controller_environment(controller_environment)
    _install_synthetic_credential(challenge, tmp_path / "forged-controller")
    marker = next(iter(controller_environment.values())).encode("ascii")

    class ForgedCleanCollector:
        def _collect(self, _marker: memoryview, *, authority: object) -> str:
            del authority
            return _digest("forged-clean-observation")

    forged = ForgedCleanCollector()
    with pytest.raises(CanaryProtocolError, match="trusted surface collector"):
        challenge.attest(forged)  # type: ignore[arg-type]
    assert controller_environment == {}
    with pytest.raises(CanaryProtocolError, match="closed"):
        challenge.attest(
            _surface_collector(
                tmp_path / "unused-preflight",
                configuration=configuration,
                campaign_digest=_digest("campaign"),
                budget=StandaloneProviderBudget(
                    campaign_digest=_digest("campaign"),
                    ledger=ledger,
                ),
                canary_marker=marker,
            )
        )

    cleared = CanaryChallenge(policy=policy, campaign_digest=_digest("campaign"))
    cleared_environment: dict[str, str] = {}
    cleared.install_controller_environment(cleared_environment)
    _install_synthetic_credential(cleared, tmp_path / "cleared-controller")
    cleared_marker = next(iter(cleared_environment.values())).encode("ascii")
    cleared_environment.clear()
    with pytest.raises(CanaryProtocolError, match="environment changed"):
        cleared.attest(
            _surface_collector(
                tmp_path / "cleared-preflight",
                configuration=configuration,
                campaign_digest=_digest("campaign"),
                budget=StandaloneProviderBudget(
                    campaign_digest=_digest("campaign"),
                    ledger=ledger,
                ),
                canary_marker=cleared_marker,
            )
        )


def test_canary_finds_a_real_surface_leak_split_across_read_chunks(tmp_path: Path) -> None:
    profile = ProviderProfile(
        logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
    )
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=profile,
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    ledger = _budget()
    policy = CanaryPolicy(
        provider_profile_digest=profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=ledger.limits_digest,
    )
    challenge = CanaryChallenge(policy=policy, campaign_digest=_digest("campaign"))
    controller_environment: dict[str, str] = {}
    challenge.install_controller_environment(controller_environment)
    _install_synthetic_credential(challenge, tmp_path / "leaking-controller")
    _complete_synthetic_parent_launches(challenge)
    marker = next(iter(controller_environment.values())).encode("ascii")
    collector_root = tmp_path / "leaking-preflight"
    paths = _surface_paths(collector_root)
    split_offset = collector_module._CHUNK_SIZE - 7
    leak = collector_root / IsolationSurface.TOOL_PROCESS.value / "captured-output.bin"
    leak.write_bytes(b"x" * split_offset + marker)
    leak.chmod(0o600)
    collector = _collector_from_paths(
        paths,
        configuration=configuration,
        campaign_digest=_digest("campaign"),
        budget=StandaloneProviderBudget(
            campaign_digest=_digest("campaign"),
            ledger=ledger,
        ),
        canary_marker=marker,
    )

    with pytest.raises(CanaryExposure) as exposure:
        challenge.attest(collector)
    assert controller_environment == {}
    assert marker.decode("ascii") not in repr(challenge)
    assert marker.decode("ascii") not in str(exposure.value)


def test_canary_scans_encrypted_artifact_plaintext(tmp_path: Path) -> None:
    profile = ProviderProfile(
        logical_id="local.stub", origin="https://localhost:4443", request_path="/v1/responses"
    )
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=profile,
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    ledger = _budget()
    policy = CanaryPolicy(
        provider_profile_digest=profile.digest,
        provider_config_digest=configuration.digest,
        budget_binding_digest=ledger.limits_digest,
    )
    challenge = CanaryChallenge(policy=policy, campaign_digest=_digest("campaign"))
    controller_environment: dict[str, str] = {}
    challenge.install_controller_environment(controller_environment)
    _install_synthetic_credential(challenge, tmp_path / "encrypted-controller")
    _complete_synthetic_parent_launches(challenge)
    marker = next(iter(controller_environment.values())).encode("ascii")
    paths = _surface_paths(tmp_path / "encrypted-preflight")
    base_policy = environment_spec().artifact_policy
    artifact_policy = ArtifactPolicy(
        quota_bytes=base_policy.quota_bytes,
        encryption=ManagedEncryption(
            provider_id="preflight_encryption",
            policy_digest=_digest("preflight-encryption-policy"),
        ),
        rules=base_policy.rules,
    )
    store = ContentAddressedStore(
        paths[IsolationSurface.ARTIFACT_STORE],
        policy=artifact_policy,
        encryption_key=EncryptionKey(key_id="preflight_key", value=b"k" * 32),
    )
    store.put_bytes(
        marker,
        artifact_class=ArtifactClass.DIAGNOSTIC,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )

    with pytest.raises(CanaryExposure) as exposure:
        challenge.attest(
            _collector_from_paths(
                paths,
                configuration=configuration,
                campaign_digest=_digest("campaign"),
                budget=StandaloneProviderBudget(
                    campaign_digest=_digest("campaign"),
                    ledger=ledger,
                ),
                canary_marker=marker,
                artifact_store=store,
                environment=EnvironmentSpec.model_validate(
                    {
                        **environment_spec().model_dump(mode="python"),
                        "artifact_policy": artifact_policy,
                    }
                ),
            )
        )
    assert controller_environment == {}
    assert marker.decode("ascii") not in str(exposure.value)


def test_budget_reservations_are_atomic_under_concurrency() -> None:
    ledger = _budget(requests=8, tokens=80)

    def reserve(_index: int) -> BudgetReservation | None:
        try:
            return ledger.reserve(
                trial_id="paired-trial",
                input_tokens=10,
                output_tokens=10,
            )
        except BudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=32) as pool:
        reservations = [item for item in pool.map(reserve, range(32)) if item is not None]

    assert len(reservations) == 8
    snapshot = ledger.snapshot()
    assert snapshot.reserved_requests == 8
    assert snapshot.reserved_input_tokens == 80
    assert snapshot.reserved_output_tokens == 80
    for reservation in reservations:
        reservation.cancel()
    assert ledger.snapshot().reserved_requests == 0


class _HttpsStub:
    def __init__(
        self,
        server_context: ssl.SSLContext,
        *,
        status: int,
        response_body: bytes,
        response_headers: dict[str, str] | None = None,
        declared_response_bytes: int | None = None,
    ) -> None:
        if declared_response_bytes is not None and declared_response_bytes < len(response_body):
            raise ValueError("declared response length cannot truncate the supplied body")
        self.records: list[tuple[str, str | None, bytes]] = []
        self.request_headers: list[dict[str, str]] = []
        records = self.records
        request_headers = self.request_headers
        headers = response_headers or {}
        content_length = (
            len(response_body) if declared_response_bytes is None else declared_response_bytes
        )

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                size = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(size)
                records.append((self.path, self.headers.get("Authorization"), body))
                request_headers.append(
                    {name.casefold(): value for name, value in self.headers.items()}
                )
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(content_length))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, _format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.socket = server_context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"https://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> _HttpsStub:
        self.thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _tls_contexts(root: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local provider stub")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = root / "stub-cert.pem"
    key_path = root / "stub-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=os.fspath(cert_path))
    return server_context, client_context


def _open_local_campaign(
    origin: str,
    client_context: ssl.SSLContext,
    surface_root: Path,
    *,
    wire: ProviderWire | None = None,
) -> tuple[ResponsesCampaign, _StaticCredentialSource, BudgetLedger]:
    wire = wire or ResponsesWire()
    configuration = ResolvedProviderConfig(
        credential_source_digest=SYNTHETIC_CREDENTIAL_SOURCE_DIGEST,
        selected_provider_label="local_stub",
        profile=ProviderProfile(
            logical_id="local.stub",
            origin=origin,
            request_path=f"/v1/{wire.protocol.value}",
            wire=wire,
        ),
        defaults=ProviderDefaults(requested_model="route.test"),
    )
    campaign_digest = _digest("local-campaign")
    source = _StaticCredentialSource(configuration)
    ledger = _budget()
    budget = StandaloneProviderBudget(campaign_digest=campaign_digest, ledger=ledger)
    policy, attestation = _clean_attestation(
        configuration,
        campaign_digest,
        budget,
        surface_root,
    )
    broker = ResponsesBroker(DirectHttpsTransport(ssl_context=client_context))
    campaign = broker.open_probe(
        configuration=configuration,
        campaign_digest=campaign_digest,
        policy=policy,
        attestation=attestation,
        credentials=source,
        budget=budget,
    )
    return campaign, source, ledger


def test_direct_https_ignores_ambient_proxies_and_decodes_typed_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_context, client_context = _tls_contexts(tmp_path)
    response = json.dumps(
        {
            "id": "response-local",
            "model": "route.test",
            "service_tier": "default",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "done"}],
                }
            ],
            "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
        }
    ).encode()
    with _HttpsStub(
        server_context,
        status=200,
        response_body=response,
        response_headers={"Content-Type": "application/json"},
    ) as stub:
        monkeypatch.setenv("HTTPS_PROXY", "https://127.0.0.1:1")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("NO_PROXY", "")
        campaign, source, ledger = _open_local_campaign(
            stub.origin,
            client_context,
            tmp_path / "preflight",
        )
        request = _request(service_tier="fast")
        observer = _RecordingExchangeObserver(trial_id="direct-probe")
        assert "confidential prompt" not in repr(request)
        with pytest.raises(TypeError):
            pickle.dumps(request)
        with campaign:
            result = campaign.request(
                trial_id="direct-probe",
                request_key="direct_probe_request",
                request=request,
                observer=observer,
            )

    assert source.calls == 1
    assert len(result.outputs) == 1
    assert isinstance(result.outputs[0], OutputText)
    assert result.outputs[0].text == "done"
    assert result.usage is not None and result.usage.total_tokens == 5
    assert result.reported_service_tier == "default"
    assert repr(result) == "ResponsesResult(<confidential>)"
    with pytest.raises(TypeError):
        pickle.dumps(result.outputs[0])
    with pytest.raises(TypeError):
        pickle.dumps(result)
    assert len(stub.records) == 1
    path, authorization, body = stub.records[0]
    assert path == "/v1/responses"
    assert authorization == "Bearer stub"
    request_body = json.loads(body)
    assert request_body["store"] is False
    assert request_body["service_tier"] == "fast"
    assert observer.request_body == body
    assert observer.response_body == response
    assert observer.result is result
    snapshot = ledger.snapshot()
    assert snapshot.committed_input_tokens == 3
    assert snapshot.committed_output_tokens == 2
    assert snapshot.reserved_requests == 0


def test_direct_https_connection_loss_settles_dispatched_usage_unknown(
    tmp_path: Path,
) -> None:
    server_context, client_context = _tls_contexts(tmp_path)
    with _HttpsStub(
        server_context,
        status=200,
        response_body=b'{"id":"partial',
        response_headers={"Content-Type": "application/json"},
        declared_response_bytes=1024,
    ) as stub:
        campaign, source, ledger = _open_local_campaign(
            stub.origin,
            client_context,
            tmp_path / "preflight",
        )
        with campaign, pytest.raises(ProviderTransportError):
            campaign.request(
                trial_id="connection-loss-probe",
                request_key="connection_loss_request",
                request=_request(),
            )

    assert source.calls == 1
    assert len(stub.records) == 1
    snapshot = ledger.snapshot()
    assert snapshot.committed_requests == 1
    assert snapshot.committed_input_tokens == 10
    assert snapshot.committed_output_tokens == 10
    assert snapshot.reserved_requests == 0


def test_redirect_is_not_followed_and_authorization_is_not_forwarded(tmp_path: Path) -> None:
    server_context, client_context = _tls_contexts(tmp_path)
    with (
        _HttpsStub(server_context, status=200, response_body=b"{}") as destination,
        _HttpsStub(
            server_context,
            status=307,
            response_body=b"",
            response_headers={"Location": destination.origin + "/capture"},
        ) as redirector,
    ):
        campaign, _source, ledger = _open_local_campaign(
            redirector.origin,
            client_context,
            tmp_path / "preflight",
        )
        with campaign, pytest.raises(ProviderRedirectError):
            campaign.request(
                trial_id="redirect-probe",
                request_key="redirect_probe_request",
                request=_request(),
            )

    assert len(redirector.records) == 1
    assert redirector.records[0][1] == "Bearer stub"
    assert destination.records == []
    snapshot = ledger.snapshot()
    assert snapshot.committed_input_tokens == 10
    assert snapshot.committed_output_tokens == 10
