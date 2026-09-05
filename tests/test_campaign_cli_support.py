"""Semantic evidence for the canonical campaign command boundary."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.cli_support.campaigns import (
    CampaignCliCommand,
    CampaignCliFailure,
    CampaignCliFailureReason,
    ProviderDiscoverRequest,
    execute_campaign_command,
)
from edagym.executors.asset_policy import AssetSourcePolicy, load_system_asset_source_policy
from edagym.participants.responses import responses_instruction_digest
from edagym.providers.campaign import (
    CampaignExecutionLimits,
    CampaignScope,
    CampaignSpec,
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
from edagym.providers.campaign_budget import CampaignBudgetProjection
from edagym.providers.campaign_operation import (
    AdmittedCampaignTrial,
    AuthoringProviderBinding,
    CampaignOperationRefusal,
    CampaignOperationRefusalReason,
    CampaignOperationRequest,
    FrozenCampaignProposal,
    PreparedCampaignTrial,
    RootlessImageToolRecipe,
    execute_campaign_operation,
)
from edagym.providers.campaign_runner import CampaignRunner
from edagym.providers.campaign_schedule import (
    CampaignHeader,
    CampaignTask,
    CampaignTaskRole,
    MeteredProviderHarnessBinding,
    build_campaign_schedule,
)
from edagym.providers.model import (
    ProviderDefaults,
    ProviderProfile,
    ResolvedProviderConfig,
)
from edagym.providers.model_discovery import (
    ModelDiscoverySnapshot,
    ModelDiscoverySource,
    ModelRouteCandidate,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.model import StopReason
from edagym.security.canary import CanaryPolicy
from edagym.security.synthetic_preflight import SyntheticPreflightError
from edagym.specs.common import Capability
from edagym.specs.session import (
    BenchmarkMode,
    HarnessActor,
    ModelBudget,
    RecoveryPolicy,
    ResourceBudget,
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


def test_campaign_discovery_command_requires_one_canonical_document(tmp_path: Path) -> None:
    configuration = ResolvedProviderConfig(
        selected_provider_label="DeclaredGateway",
        profile=ProviderProfile(
            logical_id="declared.gateway",
            origin="https://gateway.test",
            responses_path="/v1/responses",
        ),
        defaults=ProviderDefaults(requested_model="route-frontier"),
    )
    request = ProviderDiscoverRequest(
        configuration=configuration,
        explicit_candidates=(
            ModelRouteCandidate(
                route_id="frontier",
                requested_model="route-frontier",
                reference_kind=ModelReferenceKind.UNKNOWN,
                categories=(ModelCategory.FRONTIER_REASONING,),
            ),
        ),
    )
    request_path = tmp_path / "discover.json"
    request_path.write_bytes(canonical_bytes(request) + b"\n")

    result, status = execute_campaign_command(
        CampaignCliCommand.DISCOVER,
        request_path,
    )

    assert status == 0
    assert isinstance(result, ModelDiscoverySnapshot)
    assert result.source is ModelDiscoverySource.EXPLICIT_CANDIDATES
    assert result.provider_config_digest == configuration.digest

    request_path.write_text(
        json.dumps(request.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    rejected, rejected_status = execute_campaign_command(
        CampaignCliCommand.DISCOVER,
        request_path,
    )
    assert rejected_status == 1
    assert isinstance(rejected, CampaignCliFailure)
    assert rejected.reason is CampaignCliFailureReason.INVALID_REQUEST


_INSTRUCTION = "Solve the task with the workspace tools and submit once the checks pass."
_ROUTE = "route.snapshot"


class _Host:
    """Trial host with a predetermined admission outcome; nothing here reaches a provider."""

    def __init__(
        self,
        configuration: ResolvedProviderConfig,
        *,
        admission_error: Exception | None,
    ) -> None:
        self._configuration = configuration
        self._admission_error = admission_error
        self.admissions = 0

    @property
    def provider_config(self) -> ResolvedProviderConfig:
        return self._configuration

    @property
    def asset_source_policy(self) -> AssetSourcePolicy:
        return load_system_asset_source_policy()

    def admit(
        self,
        prepared: PreparedCampaignTrial,
        *,
        runner: CampaignRunner,
        policy: CanaryPolicy,
        job_state_root: Path,
        preflight_root: Path,
    ) -> AdmittedCampaignTrial:
        del prepared, runner, policy, job_state_root, preflight_root
        self.admissions += 1
        if self._admission_error is None:
            raise AssertionError("terminal trials must not be admitted again")
        raise self._admission_error


def _operation_request(root: Path, *, instruction: str) -> CampaignOperationRequest:
    task = task_spec().model_copy(update={"measurements": ()})
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    configuration = ResolvedProviderConfig(
        selected_provider_label="test_gateway",
        profile=ProviderProfile(logical_id="test.gateway", origin="https://gateway.test"),
        defaults=ProviderDefaults(
            requested_model=_ROUTE,
            reasoning_effort="high",
            service_tier="fast",
        ),
    )
    harness = MeteredProviderHarnessBinding(
        harness_id="responses_harness",
        provider_profile_digest=configuration.profile.digest,
        provider_config_digest=configuration.digest,
        instruction_digest=responses_instruction_digest(_INSTRUCTION),
        tool_schema_digest=digest("campaign-tools"),
        scaffold_digest=digest("campaign-scaffold"),
        maximum_requests_per_action=4,
    )
    base_session = session_spec()
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "mode": BenchmarkMode(),
            "recovery": RecoveryPolicy.NONE,
            "actors": (
                HarnessActor(
                    actor_id="solver",
                    harness_id=harness.harness_id,
                    harness_digest=harness.digest,
                    scaffold_digest=harness.scaffold_digest,
                    requested_model_route=_ROUTE,
                ),
            ),
            "resources": ResourceBudget(
                max_turns=8,
                max_tool_calls=8,
                max_experiments=4,
                max_wall_seconds=300,
                max_eda_compute_seconds=120,
                max_license_seconds=0,
                max_artifact_bytes=16 * 1024**2,
            ),
            "model_budget": ModelBudget(
                max_requests=8,
                max_input_tokens_per_request=128,
                max_output_tokens_per_request=64,
                max_total_input_tokens=1024,
                max_total_output_tokens=512,
                max_total_tokens=1536,
            ),
        }
    )
    route = ModelRoute(
        route_id="snapshot_route",
        requested_model=_ROUTE,
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
        harness=harness,
        evaluator_stage_ids=tuple(stage.stage_id for stage in task.evaluation.stages),
    )
    campaign = CampaignSpec(
        campaign_id="operation-smoke",
        scope=CampaignScope.EXPANDED_BREADTH,
        model_set_digest=model_set.digest,
        route_ids=(route.route_id,),
        task_release_digests=(release.digest,),
        environment_digests=(environment.digest,),
        harness_digests=(harness.digest,),
        prompt_digest=harness.instruction_digest,
        tool_schema_digest=harness.tool_schema_digest,
        feedback_policy_digest=canonical_digest(session.feedback, domain="feedback-policy-v1"),
        reasoning_efforts=("high",),
        service_tier="fast",
        paired_trial_seeds=("1" * 32,),
        task_order_seed="2" * 32,
        retry_policy=RetryPolicy(max_request_attempts=1, backoff_milliseconds=0),
        token_limits=CampaignTokenLimits(
            max_requests=8,
            max_requests_per_trial=8,
            max_input_tokens_per_request=128,
            max_output_tokens_per_request=64,
            max_input_tokens_per_trial=1024,
            max_output_tokens_per_trial=512,
            max_total_tokens_per_trial=1536,
            max_input_tokens=1024,
            max_output_tokens=512,
            max_total_tokens=1536,
        ),
        execution_limits=CampaignExecutionLimits(
            max_turns_per_trial=8,
            max_tool_calls_per_trial=8,
            max_wall_seconds_per_trial=300,
            max_eda_compute_seconds_per_trial=120,
            max_license_seconds_per_trial=1,
            max_artifact_bytes_per_trial=16 * 1024**2,
            max_turns=8,
            max_tool_calls=8,
            max_wall_seconds=300,
            max_eda_compute_seconds=120,
            max_license_seconds=1,
            max_artifact_bytes=16 * 1024**2,
        ),
        provider_spend_limit=CappedSpendLimit(currency="USD", amount=Decimal("1")),
    )
    schedule = build_campaign_schedule(campaign, model_set, (campaign_task,))
    header = CampaignHeader(
        campaign=campaign,
        model_set=model_set,
        provider_config=configuration,
        tasks=(campaign_task,),
        schedule=schedule,
    )
    return CampaignOperationRequest(
        proposal=FrozenCampaignProposal(
            header=header,
            budget=CampaignBudgetProjection.from_campaign(campaign, schedule),
        ),
        instruction=instruction,
        authoring_provider=AuthoringProviderBinding(
            executable="/usr/bin/false",
            executable_digest=digest("provider-executable"),
            implementation_digest=digest("provider-implementation"),
            descriptor_digest=digest("provider-descriptor"),
        ),
        flow_catalog_root=(root / "flow-catalog").as_posix(),
        backend_deployment=(root / "backend-deployment.json").as_posix(),
        executor_deployment=(root / "executor-deployment.json").as_posix(),
        container_engine="/usr/bin/podman",
        rootless_image_tools=(
            RootlessImageToolRecipe(
                tool_id="yosys",
                image_digest=digest("open-image"),
                tool_entrypoint="/usr/bin/yosys",
                package_manifest_path="/usr/share/edagym/dpkg-manifest.tsv",
                package_manifest_digest=digest("package-manifest"),
                package_manifest_checksum_path="/usr/share/edagym/dpkg-manifest.sha256",
            ),
        ),
        artifact_store_root=(root / "artifacts").as_posix(),
        state_root=(root / "state").as_posix(),
        environments=(environment,),
        sessions=(session,),
    )


def _prepared(request: CampaignOperationRequest, root: Path) -> tuple[PreparedCampaignTrial, ...]:
    header = request.header
    (environment,) = request.environments
    (session,) = request.sessions
    task = task_spec().model_copy(update={"measurements": ()})
    instance = task_instance(task)
    store = ContentAddressedStore(root / "store", policy=environment.artifact_policy)
    return tuple(
        PreparedCampaignTrial(
            trial=trial,
            task=task,
            instance=instance,
            release=release_manifest(task, instance, environment),
            environment=environment,
            session=session,
            artifact_store=store,
            evaluators=(),
            participant_files={},
            asset_paths={},
        )
        for trial in header.schedule.trials
    )


def test_campaign_run_refuses_instruction_mismatch_before_touching_state(tmp_path: Path) -> None:
    request = _operation_request(tmp_path, instruction="a different prompt")
    host = _Host(request.header.provider_config, admission_error=None)

    with pytest.raises(CampaignOperationRefusal) as refused:
        execute_campaign_operation(request, _prepared(request, tmp_path), resume=False, host=host)

    assert refused.value.reason is CampaignOperationRefusalReason.INSTRUCTION_MISMATCH
    assert host.admissions == 0
    assert not (tmp_path / "state").exists()


def test_campaign_run_without_attestation_dispatches_nothing(tmp_path: Path) -> None:
    request = _operation_request(tmp_path, instruction=_INSTRUCTION)
    prepared = _prepared(request, tmp_path)
    host = _Host(
        request.header.provider_config,
        admission_error=SyntheticPreflightError("no attestation"),
    )
    (trial,) = request.header.schedule.trials

    with pytest.raises(CampaignOperationRefusal) as refused:
        execute_campaign_operation(request, prepared, resume=False, host=host)

    assert refused.value.reason is CampaignOperationRefusalReason.PREFLIGHT_FAILED
    assert refused.value.trial_id == trial.trial_id
    assert host.admissions == 1
    reopened = CampaignRunner(
        campaign=request.header.campaign,
        model_set=request.header.model_set,
        tasks=request.header.tasks,
        provider_config=request.header.provider_config,
        state_root=tmp_path / "state" / "campaign",
    )
    assert reopened.journal.record().commits == ()
    assert len(reopened.pending_trials()) == 1
    assert not (tmp_path / "state" / "runs").exists()

    with pytest.raises(CampaignOperationRefusal) as not_started:
        execute_campaign_operation(request, prepared, resume=True, host=host)
    assert not_started.value.reason is CampaignOperationRefusalReason.CAMPAIGN_NOT_STARTED
    assert host.admissions == 1


def test_campaign_resume_does_not_redispatch_terminal_trials(tmp_path: Path) -> None:
    request = _operation_request(tmp_path, instruction=_INSTRUCTION)
    prepared = _prepared(request, tmp_path)
    header = request.header
    (tmp_path / "state").mkdir(mode=0o700)
    runner = CampaignRunner(
        campaign=header.campaign,
        model_set=header.model_set,
        tasks=header.tasks,
        provider_config=header.provider_config,
        state_root=tmp_path / "state" / "campaign",
    )
    runner.stop_unfinished(StopReason.EXPLICIT_CANCEL)
    host = _Host(header.provider_config, admission_error=None)

    with pytest.raises(CampaignOperationRefusal) as started:
        execute_campaign_operation(request, prepared, resume=False, host=host)
    assert started.value.reason is CampaignOperationRefusalReason.CAMPAIGN_ALREADY_STARTED

    result = execute_campaign_operation(request, prepared, resume=True, host=host)

    assert host.admissions == 0
    assert result.pending_trial_ids == ()
    assert result.trial_results == ()
    assert result.report is not None
    assert result.report.campaign_digest == header.campaign.digest
    assert result.campaign_record_digest == runner.journal.record().integrity_digest
