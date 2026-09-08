"""Canonical objects shared by tests of semantic joints."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from edagym.canonical import canonical_bytes
from edagym.executors.capabilities import ProviderAvailability, probe_local_containment
from edagym.providers.model import ProviderSecurityBinding, ProviderUsage
from edagym.run.artifact_model import (
    ArtifactRecord,
    BlobRef,
)
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    HarnessRunActor,
    ProducerKind,
    ProviderRequestStartedEvent,
    ProviderRequestStartedPayload,
    ProviderResponseRecordedEvent,
    ProviderResponseRecordedPayload,
    RunEvent,
    RunHeader,
    RunState,
)
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    RuntimeSurfaceBinding,
)
from edagym.security.canary import CanaryPolicy, CanaryReceipt
from edagym.security.canary_artifact import (
    PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE,
    PROVIDER_TRANSCRIPT_MEDIA_TYPE,
    ProviderCanaryEvidence,
    ProviderTranscriptRole,
    provider_transcript_artifact_id,
)
from edagym.security.runtime_surface import (
    RuntimeSurfaceIdentity,
    RuntimeSurfaceManifest,
)
from edagym.specs.budget import ModelBudget, ResourceBudget
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
    CheckpointCapability,
    ContainerRuntime,
    EnvironmentIdentity,
    EnvironmentSpec,
    FilesystemPolicy,
    ImageToolLocator,
    NoEncryption,
    NoNetwork,
    ResourceLimits,
    RootlessLocalExecutor,
    ToolBinding,
)
from edagym.specs.release import (
    GeneratedFile,
    IntegerParameterValue,
    MutantQualification,
    ReleaseManifest,
    ReleaseQualification,
    TaskInstance,
    TaskInstanceIdentity,
)
from edagym.specs.session import (
    FeedbackPolicy,
    FixedWriter,
    HarnessActor,
    RecoveryPolicy,
    SessionSpec,
    TrainingMode,
)
from edagym.specs.task import (
    NOT_APPLICABLE_LIBRARY_DIGEST,
    Aggregation,
    ClockSpec,
    ContractSpec,
    DifficultyAxis,
    EvaluationGraph,
    EvaluatorSpec,
    GeneratorSpec,
    IntegerDomain,
    MeasurementSpec,
    MeasurementUnit,
    MetricDirection,
    NativeSealedTaskOrigin,
    QualificationSpec,
    RequirementKind,
    RequirementSpec,
    ResetKind,
    ResetSpec,
    ResourceLicense,
    ResourceSpec,
    ResourceVisibility,
    ScorerRef,
    ScorerTerm,
    StagePurpose,
    StageSpec,
    StreamInterface,
    TaskIdentity,
    TaskSpec,
)


@dataclass(frozen=True)
class ProviderExchangeFixture:
    """Canonical artifact and event facts for one synthetic provider exchange."""

    request_record: ArtifactRecord
    evidence_record: ArtifactRecord
    response_record: ArtifactRecord
    request_payload: ProviderRequestStartedPayload
    response_payload: ProviderResponseRecordedPayload

    def request_events(
        self,
        state: RunState,
        *,
        timestamp: datetime,
        event_id_factory: Callable[[], UUID] = uuid4,
    ) -> tuple[RunEvent, ...]:
        return (
            ArtifactRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                payload=ArtifactRecordedPayload(record=self.request_record),
            ),
            ArtifactRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence + 1,
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                payload=ArtifactRecordedPayload(record=self.evidence_record),
            ),
            ProviderRequestStartedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence + 2,
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                artifact_refs=(
                    self.request_record.logical_id,
                    self.evidence_record.logical_id,
                ),
                payload=self.request_payload,
            ),
        )

    def response_events(
        self,
        state: RunState,
        *,
        timestamp: datetime,
        event_id_factory: Callable[[], UUID] = uuid4,
    ) -> tuple[RunEvent, ...]:
        return (
            ArtifactRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                payload=ArtifactRecordedPayload(record=self.response_record),
            ),
            ProviderResponseRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence + 1,
                event_id=event_id_factory(),
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                artifact_refs=(self.response_record.logical_id,),
                payload=self.response_payload,
            ),
        )


def provider_canary_evidence_for_binding(
    binding: RuntimeSurfaceBinding,
) -> ProviderCanaryEvidence:
    """Build one internally consistent synthetic canary document for journal tests."""

    preflight_run_id = digest("provider-fixture-preflight")
    manifest = RuntimeSurfaceManifest(
        preflight_run_id=preflight_run_id,
        preflight_record_digest=digest("provider-fixture-preflight-record"),
        run_binding_digest=preflight_run_id,
        binding=binding,
        executor_receipt_digest=digest("provider-fixture-executor"),
        launcher_receipt_digest=digest("provider-fixture-launcher"),
        artifact_closure_receipt_digest=digest("provider-fixture-closure"),
        artifact_store_identity_digest=digest("provider-fixture-store"),
        surfaces=tuple(
            RuntimeSurfaceIdentity(
                surface=surface,
                identity_digest=digest(f"provider-fixture-surface-{surface.value}"),
            )
            for surface in REQUIRED_ISOLATION_SURFACES
        ),
    )
    policy = CanaryPolicy(
        provider_profile_digest=binding.provider_profile_digest,
        provider_config_digest=binding.provider_config_digest,
        budget_binding_digest=binding.budget_binding_digest,
    )
    receipt = CanaryReceipt(
        attestation_id="f" * 32,
        policy_digest=policy.digest,
        campaign_digest=binding.campaign_digest,
        provider_profile_digest=binding.provider_profile_digest,
        manifest_digest=manifest.digest,
        collection_evidence_digest=digest("provider-fixture-collection"),
    )
    return ProviderCanaryEvidence(
        policy=policy,
        receipt=receipt,
        runtime_surface_manifest=manifest,
    )


def provider_canary_evidence_fixture(
    header: RunHeader,
    *,
    actor_id: str,
    provider_profile_digest: str,
    provider_config_digest: str,
    budget_binding_digest: str,
) -> ProviderCanaryEvidence:
    """Derive a journal test's exact surface binding before building canary evidence."""

    return provider_canary_evidence_for_binding(
        _provider_runtime_surface_binding_fixture(
            header,
            actor_id=actor_id,
            provider_profile_digest=provider_profile_digest,
            provider_config_digest=provider_config_digest,
            budget_binding_digest=budget_binding_digest,
        )
    )


def provider_exchange_fixture(
    header: RunHeader,
    *,
    request_id: str,
    actor_id: str,
    requested_model: str,
    provider_profile_digest: str,
    provider_config_digest: str,
    budget_binding_digest: str,
    reserved_input_tokens: int,
    reserved_output_tokens: int,
    usage: ProviderUsage | None,
    requested_service_tier: str | None = None,
    provider_reported_service_tier: str | None = None,
) -> ProviderExchangeFixture:
    """Build exact transcript identities and security evidence through canonical models."""

    evidence = provider_canary_evidence_fixture(
        header,
        actor_id=actor_id,
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        budget_binding_digest=budget_binding_digest,
    )
    disclosure = ArtifactDisclosure(
        sensitivity=Sensitivity.CONFIDENTIAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.FORBIDDEN,
    )
    request_content = canonical_bytes({"input": [], "model": requested_model, "store": False})
    response_content = canonical_bytes(
        {
            "id": "provider-fixture-response",
            "model": requested_model,
            "output": [],
            "status": "completed",
        }
    )
    request_record = _provider_fixture_record(
        provider_transcript_artifact_id(request_id, ProviderTranscriptRole.REQUEST),
        request_content,
        media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
        artifact_class=ArtifactClass.TRAINING,
        disclosure=disclosure,
    )
    evidence_record = _provider_fixture_record(
        evidence.artifact_id,
        canonical_bytes(evidence),
        media_type=PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE,
        artifact_class=ArtifactClass.EVIDENCE,
        disclosure=disclosure,
    )
    response_record = _provider_fixture_record(
        provider_transcript_artifact_id(request_id, ProviderTranscriptRole.RESPONSE),
        response_content,
        media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
        artifact_class=ArtifactClass.TRAINING,
        disclosure=disclosure,
    )
    security = ProviderSecurityBinding(
        canary_receipt_digest=evidence.receipt.digest,
        runtime_surface_manifest_digest=evidence.runtime_surface_manifest.digest,
        budget_binding_digest=budget_binding_digest,
    )
    return ProviderExchangeFixture(
        request_record=request_record,
        evidence_record=evidence_record,
        response_record=response_record,
        request_payload=ProviderRequestStartedPayload(
            request_id=request_id,
            actor_id=actor_id,
            request_artifact_id=request_record.logical_id,
            security_evidence_artifact_id=evidence_record.logical_id,
            provider_profile_digest=provider_profile_digest,
            provider_config_digest=provider_config_digest,
            requested_model=requested_model,
            requested_service_tier=requested_service_tier,
            security_binding=security,
            reserved_input_tokens=reserved_input_tokens,
            reserved_output_tokens=reserved_output_tokens,
        ),
        response_payload=ProviderResponseRecordedPayload(
            request_id=request_id,
            provider_reported_model=requested_model,
            provider_reported_service_tier=provider_reported_service_tier,
            status=ProviderResponseStatus.COMPLETED,
            usage=usage,
        ),
    )


def _provider_runtime_surface_binding_fixture(
    header: RunHeader,
    *,
    actor_id: str,
    provider_profile_digest: str,
    provider_config_digest: str,
    budget_binding_digest: str,
) -> RuntimeSurfaceBinding:
    harness = next(
        actor
        for actor in header.binding.session.actors
        if isinstance(actor, HarnessRunActor) and actor.actor_id == actor_id
    )
    campaign = header.binding.campaign
    return RuntimeSurfaceBinding(
        campaign_digest=(
            campaign.campaign_digest
            if campaign is not None
            else digest("provider-fixture-campaign")
        ),
        campaign_schedule_digest=(
            campaign.schedule_digest
            if campaign is not None
            else digest("provider-fixture-schedule")
        ),
        scheduled_trial_digest=(
            campaign.scheduled_trial_digest
            if campaign is not None
            else digest("provider-fixture-trial")
        ),
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        budget_binding_digest=budget_binding_digest,
        task_release_digest=header.binding.task.release_digest,
        environment_spec_digest=header.binding.environment.environment_spec_digest,
        session_spec_digest=header.binding.session.session_spec_digest,
        harness_digest=harness.harness_digest,
        harness_schema_digest=digest("provider-fixture-harness-schema"),
        executor_digest=header.binding.environment.executor_digest,
        export_policy_digest=digest("provider-fixture-export-policy"),
    )


def _provider_fixture_record(
    logical_id: str,
    content: bytes,
    *,
    media_type: str,
    artifact_class: ArtifactClass,
    disclosure: ArtifactDisclosure,
) -> ArtifactRecord:
    return ArtifactRecord(
        logical_id=logical_id,
        blob=BlobRef(
            digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
            size_bytes=len(content),
        ),
        media_type=media_type,
        artifact_class=artifact_class,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )


def digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


SYNTHETIC_CREDENTIAL_SOURCE_DIGEST = digest("synthetic-credential-source")


def task_spec() -> TaskSpec:
    resource_names = (
        "behavior",
        "generator",
        "sim_evaluator",
        "synth_evaluator",
        "oracle",
        "known_answers",
        "reference",
        "mutant_drop",
        "mutant_stall",
        "mutant_corrupt",
    )
    resources = tuple(
        ResourceSpec(
            resource_id=name,
            content_digest=digest(f"resource-{name}"),
            media_type="application/octet-stream",
            path=f"authoring/{name}.bin",
        )
        for name in resource_names
    )
    public_resources = {"behavior"}
    verifier_resources = {"sim_evaluator", "synth_evaluator", "oracle", "known_answers"}
    visibility = tuple(
        ResourceVisibility(
            resource_id=name,
            visibility=(
                Visibility.PUBLIC
                if name in public_resources
                else Visibility.VERIFIER
                if name in verifier_resources
                else Visibility.AUTHOR
            ),
            sensitivity=(Sensitivity.PUBLIC if name in public_resources else Sensitivity.INTERNAL),
        )
        for name in resource_names
    )
    licensing = tuple(
        ResourceLicense(
            resource_id=name,
            spdx_expression="Apache-2.0",
            redistribution=Redistribution.ALLOWED,
            provenance=(f"clean-room:{name}",),
        )
        for name in resource_names
    )
    return TaskSpec(
        identity=TaskIdentity(
            family="stream_guard",
            authoring_revision=1,
            origin=NativeSealedTaskOrigin(provenance=("clean-room",)),
        ),
        interface=StreamInterface(
            top_module="stream_guard",
            clock=ClockSpec(clock_id="core", period_fs=10_000_000),
            reset=ResetSpec(
                reset_id="reset_n",
                clock_id="core",
                kind=ResetKind.SYNC_ACTIVE_LOW,
            ),
            data_width=8,
        ),
        generator=GeneratorSpec(
            implementation_resource="generator",
            implementation_digest=digest("generator-implementation"),
            parameters=(
                IntegerDomain(
                    parameter_id="data_width",
                    default=8,
                    minimum=8,
                    maximum=64,
                    step=8,
                ),
            ),
        ),
        contract=ContractSpec(
            public_behavior_resource="behavior",
            requirements=(
                RequirementSpec(
                    requirement_id="preserves_payload",
                    kind=RequirementKind.BEHAVIORAL,
                    description="Every accepted input is emitted once without modification.",
                ),
                RequirementSpec(
                    requirement_id="respects_backpressure",
                    kind=RequirementKind.TEMPORAL,
                    description="Output remains stable while valid data is stalled.",
                ),
            ),
        ),
        resources=resources,
        visibility=visibility,
        evaluation=EvaluationGraph(
            evaluators=(
                EvaluatorSpec(
                    evaluator_id="simulate",
                    capability=Capability.RTL_SIMULATION,
                    implementation_resource="sim_evaluator",
                    revision_digest=digest("sim-evaluator-v1"),
                ),
                EvaluatorSpec(
                    evaluator_id="synthesize",
                    capability=Capability.ASIC_SYNTHESIS,
                    implementation_resource="synth_evaluator",
                    revision_digest=digest("synth-evaluator-v1"),
                ),
            ),
            stages=(
                StageSpec(
                    stage_id="functional",
                    evaluator_id="simulate",
                    purpose=StagePurpose.HARD_GATE,
                    requirement_ids=("preserves_payload", "respects_backpressure"),
                ),
                StageSpec(
                    stage_id="qor",
                    evaluator_id="synthesize",
                    depends_on=("functional",),
                    purpose=StagePurpose.OBSERVATION,
                ),
            ),
        ),
        measurements=(
            MeasurementSpec(
                measurement_id="cell_count",
                producer_stage_id="qor",
                unit=MeasurementUnit.COUNT,
                library_id="not_applicable",
                library_digest=NOT_APPLICABLE_LIBRARY_DIGEST,
                corner="not_applicable",
                mode="not_applicable",
                direction=MetricDirection.MINIMIZE,
                repetitions=1,
                aggregation=Aggregation.MEDIAN,
                valid_minimum=Decimal(0),
            ),
        ),
        difficulty_axes=(DifficultyAxis(axis_id="width", parameter_id="data_width"),),
        qualification=QualificationSpec(
            sail_oracle_resource="oracle",
            known_answer_resources=("known_answers",),
            reference_candidate_resource="reference",
            mutant_resources=("mutant_corrupt", "mutant_drop", "mutant_stall"),
            require_formal=False,
            temporal_rule_ids=("response_backpressure_hold",),
            structural_rule_ids=("exact_profile_ports",),
        ),
        licensing=licensing,
    )


def scalar_task_spec() -> TaskSpec:
    task = task_spec()
    scorer = ScorerRef(
        implementation_resource="weighted_scorer",
        direction=MetricDirection.MAXIMIZE,
        intercept=Decimal(1000),
        terms=(
            ScorerTerm(
                measurement_id="cell_count",
                coefficient=Decimal(-1),
            ),
        ),
    )
    return TaskSpec.model_validate(
        {
            **task.model_dump(mode="python"),
            "resources": (
                *task.resources,
                ResourceSpec(
                    resource_id=scorer.implementation_resource,
                    content_digest=scorer.implementation_digest,
                    media_type="application/json",
                    path="authoring/weighted_scorer.json",
                ),
            ),
            "visibility": (
                *task.visibility,
                ResourceVisibility(
                    resource_id=scorer.implementation_resource,
                    visibility=Visibility.AUTHOR,
                    sensitivity=Sensitivity.INTERNAL,
                ),
            ),
            "evaluation": task.evaluation.model_copy(update={"scorer": scorer}),
            "licensing": (
                *task.licensing,
                ResourceLicense(
                    resource_id=scorer.implementation_resource,
                    spdx_expression="Apache-2.0",
                    redistribution=Redistribution.ALLOWED,
                    provenance=("clean-room:weighted_scorer",),
                ),
            ),
        }
    )


def environment_spec() -> EnvironmentSpec:
    tools = tuple(
        ToolBinding(
            capability=capability,
            tool_id=tool_id,
            tool_version=version,
            driver_id=f"{tool_id}_driver",
            driver_digest=digest(f"driver-{tool_id}"),
            locator=ImageToolLocator(
                image_digest=digest("open-image"),
                executable=executable,
                deployment_attestation_digest=digest(f"deployment-{tool_id}"),
            ),
        )
        for capability, tool_id, version, executable in (
            (Capability.RTL_SIMULATION, "verilator", "5.040", "verilator"),
            (Capability.ASIC_SYNTHESIS, "yosys", "0.60", "yosys"),
        )
    )
    rules = tuple(
        ArtifactRetentionRule(
            artifact_class=artifact_class,
            retention_seconds=(3600 if artifact_class is ArtifactClass.CHECKPOINT else 60),
            allowed_disclosures=(
                ArtifactDisclosure(
                    sensitivity=Sensitivity.INTERNAL,
                    visibility=(
                        Visibility.PARTICIPANT
                        if artifact_class is ArtifactClass.MEASUREMENT
                        else Visibility.AUTHOR
                    ),
                    redistribution=Redistribution.RESTRICTED,
                ),
            ),
        )
        for artifact_class in ArtifactClass
    )
    return EnvironmentSpec(
        identity=EnvironmentIdentity(
            environment_id="open_local",
            authoring_revision=1,
        ),
        executor=RootlessLocalExecutor(
            executor_id="podman_rootless",
            implementation_digest=digest("podman-executor"),
            runtime=ContainerRuntime.PODMAN,
            runtime_version="5.8.2",
            runtime_probe_digest=digest("podman-probe"),
            image_digest=digest("open-image"),
        ),
        tool_bindings=tools,
        filesystem=FilesystemPolicy(
            workspace_target="/workspace",
            artifact_target="/artifacts",
        ),
        network=NoNetwork(),
        resources=ResourceLimits(
            cpu_millicores=4000,
            memory_bytes=8 * 1024**3,
            pids=512,
            disk_bytes=16 * 1024**3,
            wall_seconds=3600,
        ),
        checkpoint=CheckpointCapability.FILESYSTEM,
        artifact_policy=ArtifactPolicy(
            quota_bytes=64 * 1024**2,
            encryption=NoEncryption(),
            rules=rules,
        ),
    )


def session_spec() -> SessionSpec:
    return SessionSpec(
        session_id="agent_training",
        mode=TrainingMode(),
        actors=(
            HarnessActor(
                actor_id="solver",
                harness_id="responses_harness",
                harness_digest=digest("responses-harness"),
                scaffold_digest=digest("training-scaffold"),
                requested_model_route="test-route",
            ),
        ),
        writer=FixedWriter(writer="solver"),
        feedback=FeedbackPolicy.SAFE_DIAGNOSTIC,
        recovery=RecoveryPolicy.REQUIRED,
        resources=ResourceBudget(
            max_turns=16,
            max_tool_calls=32,
            max_experiments=8,
            max_wall_seconds=1800,
            max_eda_compute_seconds=1200,
            max_license_seconds=0,
            max_artifact_bytes=16 * 1024**2,
        ),
        model_budget=ModelBudget(
            max_requests=16,
            max_input_tokens_per_request=4096,
            max_output_tokens_per_request=2048,
            max_input_tokens=65_536,
            max_output_tokens=32_768,
            max_total_tokens=98_304,
        ),
    )


def task_instance(task: TaskSpec) -> TaskInstance:
    generated_files = (
        GeneratedFile(
            path="participant/design.sv",
            content_digest=digest("participant-design"),
            media_type="text/x-systemverilog",
            source_resource_ids=("behavior",),
            visibility=Visibility.PARTICIPANT,
            sensitivity=Sensitivity.INTERNAL,
            redistribution=Redistribution.ALLOWED,
        ),
        GeneratedFile(
            path="verifier/checks.bin",
            content_digest=digest("verifier-checks"),
            media_type="application/octet-stream",
            source_resource_ids=("oracle",),
            visibility=Visibility.VERIFIER,
            sensitivity=Sensitivity.INTERNAL,
            redistribution=Redistribution.ALLOWED,
        ),
    )
    return TaskInstance(
        identity=TaskInstanceIdentity(
            task_family=task.identity.family,
            authoring_revision=task.identity.authoring_revision,
            task_spec_digest=task.digest,
            generator_digest=task.generator.implementation_digest,
            seed="00000000000000000000000000000007",
            parameters=(IntegerParameterValue(parameter_id="data_width", value=8),),
        ),
        generated_files=generated_files,
    )


def release_manifest(
    task: TaskSpec,
    instance: TaskInstance,
    environment: EnvironmentSpec,
) -> ReleaseManifest:
    if not isinstance(task.qualification, QualificationSpec):
        raise TypeError("the RTL fixture requires Sail qualification semantics")
    return ReleaseManifest(
        task_spec_digest=task.digest,
        task_instance_digest=instance.digest,
        participant_bundle_digest=digest("participant-bundle"),
        verifier_bundle_digest=digest("verifier-bundle"),
        environment_digests=(environment.digest,),
        files=instance.generated_files,
        qualification=ReleaseQualification(
            reference_evidence_digest=digest("reference-evidence"),
            known_answer_evidence_digests=(digest("known-evidence"),),
            simulator_evidence_digests=(
                digest("simulator-evidence-primary"),
                digest("simulator-evidence-secondary"),
            ),
            synthesis_evidence_digest=digest("synthesis-evidence"),
            temporal_evidence_digest=digest("temporal-evidence"),
            structural_evidence_digest=digest("structural-evidence"),
            mutant_results=tuple(
                MutantQualification(
                    mutant_resource_id=mutant,
                    evidence_digest=digest(f"evidence-{mutant}"),
                )
                for mutant in task.qualification.mutant_resources
            ),
        ),
    )


def require_local_containment() -> None:
    """Skip evidence that needs the user systemd boundary when the host lacks it."""

    capability = probe_local_containment()
    if capability.availability is not ProviderAvailability.AVAILABLE:
        pytest.skip(f"local containment is unavailable: {capability.reason}")
