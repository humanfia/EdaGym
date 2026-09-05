"""Release readiness evidence at the immutable-source boundary."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from edagym.authoring.provider import FlowCandidateAttestation, FlowCandidateRole
from edagym.canonical import canonical_bytes
from edagym.drivers.catalog import BACKEND_CATALOG
from edagym.drivers.qualification import QualificationDisposition
from edagym.drivers.qualification_verification import QualificationSourceKind
from edagym.drivers.semantic_claims import semantic_contract
from edagym.evaluation import CandidateFailureOutcome, StageResult
from edagym.executors.capabilities import ProviderUnavailableReason
from edagym.participants import (
    ParticipantActionEvidence,
    ParticipantActionKind,
    ParticipantHandoffEvidence,
    ParticipantSessionEvidence,
)
from edagym.policy.private_roots import (
    REQUIRED_RELEASE_PRIVATE_ROOT_ROLES,
    PrivateRootAuditReport,
    PrivateRootAuditStatus,
    PrivateRootKind,
    PrivateRootSummary,
)
from edagym.policy.repository import (
    AuditMode,
    AuditStatus,
    CoverageScope,
    CoverageStatus,
    GitObjectFormat,
    RepositorySnapshot,
)
from edagym.projections.model import ParticipationKind
from edagym.providers.campaign import (
    REQUIRED_MODEL_CATEGORIES,
    CampaignScope,
    CategoryExclusionReason,
    FeatureSupport,
    ModelCategory,
    ModelReferenceKind,
    ModelRoute,
    ModelSetManifest,
    RouteQualification,
    UncoveredCategory,
)
from edagym.providers.campaign_runner import (
    CountRatio,
    ReportedServiceTierCount,
    ServiceTierAccounting,
)
from edagym.providers.campaign_schedule import CampaignTaskRole
from edagym.providers.model import (
    RUST_CAT_PROFILE,
    ProviderDefaults,
    ResolvedProviderConfig,
)
from edagym.providers.model_discovery import (
    ModelDiscoverySnapshot,
    ModelDiscoverySource,
)
from edagym.providers.qualification import RouteCanaryEvidence, RouteCanaryUsage
from edagym.release_authoring import AuthoringCatalogEvidence
from edagym.release_backends import (
    BackendCapabilityEvidence,
    BackendQualificationEvidence,
    project_backend_coverage,
)
from edagym.release_commands import (
    CommandFailure,
    CommandUnavailable,
    ReleaseCommandEvidence,
    ReleaseCommandPlan,
    ReleaseCommandPurpose,
    ReleaseCommandReceipt,
    ReleaseEvidenceStatus,
    ReleaseInvocationEvidence,
    ReleaseInvocationReceipt,
    release_command_plan,
    release_command_requires_installation,
)
from edagym.release_e2e import (
    ArtifactClassCount,
    EndToEndRequirement,
    EndToEndSmokeEvidence,
    EndToEndTrialEvidence,
    ParticipantRecoveryEvidence,
    _hidden_verifier_sources_are_disjoint,
)
from edagym.release_evidence import EvidenceCounts
from edagym.release_reporting import (
    CampaignEvidence,
    CampaignTaskBindingEvidence,
    DurableExecutorEvidence,
    FlowReleaseEvidence,
    FlowRunEvidence,
    FlowRunRole,
    ReleaseDecision,
    ReleaseReport,
    RepositoryAuditEvidence,
    RepositoryCoverageEvidence,
    _flow_record_status,
    _model_discovery_source,
    _route_canary_sources,
)
from edagym.release_sessions import (
    ParticipantModeRunEvidence,
    ParticipantModeSuiteEvidence,
    ReleaseProjectionKind,
)
from edagym.resolution import resolve_run
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.model import (
    CandidateSubmittedEvent,
    CandidateSubmittedPayload,
    EvaluationCompletedEvent,
    EvaluationCompletedPayload,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    HarnessRunActor,
    HumanRunActor,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    ProducerKind,
    RunCommit,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunRecord,
    RunStartedEvent,
    RunStartedPayload,
    StopReason,
    run_journal_anchor,
)
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.session import CandidateAuthority, ModeKind
from edagym.specs.task import TaskSpec
from edagym.task_families.catalog import (
    EDA_FLOW_FAMILIES,
    PUBLIC_TASK_CATALOG,
    SAIL_RTL_FAMILIES,
)
from tests.factories import (
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _repository_identity() -> RepositorySnapshot:
    return RepositorySnapshot(
        object_format=GitObjectFormat.SHA1,
        commit_id="1" * 40,
        tree_id="2" * 40,
        index_tree_id="2" * 40,
        worktree_tree_id="2" * 40,
        index_state_digest=_digest("repository-index"),
        worktree_state_digest=_digest(""),
        ref_set_digest=_digest("repository-refs"),
        reflog_record_digest=_digest("repository-reflogs"),
        lfs_object_inventory_digest=_digest("repository-lfs"),
        scan_scope_digest=_digest("repository-scan-scope"),
    )


def _authoring() -> AuthoringCatalogEvidence:
    families = tuple(item.family for item in SAIL_RTL_FAMILIES)
    instances = tuple(
        (family, name) for family in families for name in ("base", "advanced")
    )
    return AuthoringCatalogEvidence(
        public_catalog_digest=PUBLIC_TASK_CATALOG.digest,
        catalog_attestation_digest=_digest("sail-catalog-attestation"),
        catalog_reference_digest=_digest("sail-catalog-reference"),
        member_manifest_digest=_digest("sail-member-manifest"),
        provider_descriptor_digest=_digest("sail-provider-descriptor"),
        provider_implementation_digest=_digest("sail-provider-implementation"),
        provider_security_qualification_digest=_digest("sail-provider-security"),
        clean_room_attestation_digest=_digest("clean-room-attestation"),
        clean_room_auditor_descriptor_digest=_digest("clean-room-auditor-descriptor"),
        clean_room_auditor_implementation_digest=_digest(
            "clean-room-auditor-implementation"
        ),
        reference_tree_snapshot_digest=_digest("clean-room-reference-tree"),
        reference_inventory_digest=_digest("clean-room-reference-inventory"),
        human_review_aggregate_digest=_digest("clean-room-human-review"),
        clean_room_family_projection_digests=tuple(
            _digest(f"clean-room-family-{family}") for family in families
        ),
        families=families,
        task_spec_digests=tuple(_digest(f"task-{family}") for family in families),
        instance_digests=tuple(
            _digest(f"instance-{family}-{name}") for family, name in instances
        ),
        release_digests=tuple(
            _digest(f"release-{family}-{name}") for family, name in instances
        ),
        release_environment_digests=(_digest("sail-release-environment"),),
        qualification_digests=tuple(
            _digest(f"qualification-{family}-{name}") for family, name in instances
        ),
        qualification_request_digests=tuple(
            _digest(f"qualification-request-{family}-{name}")
            for family, name in instances
        ),
        counts=EvidenceCounts(passed=40, failed=0, unavailable=0, total=40),
        status=ReleaseEvidenceStatus.PASSED,
    )


def _backends() -> tuple[BackendQualificationEvidence, ...]:
    return tuple(
        BackendQualificationEvidence(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            driver_digest=definition.driver_digest,
            tool_version=f"{definition.tool_id}-release-version",
            deployment_attestation_digest=_digest(
                f"deployment-{definition.tool_id}"
            ),
            qualification_digest=_digest(f"qualification-{definition.tool_id}"),
            disposition=QualificationDisposition.CONFORMANT,
            capabilities=tuple(
                BackendCapabilityEvidence(
                    capability=capability,
                    status=ReleaseEvidenceStatus.PASSED,
                    source_kind=QualificationSourceKind.EVIDENCE_PAIR,
                    verified_source_digest=_digest(
                        f"verified-source-{definition.tool_id}-{capability.value}"
                    ),
                    artifact_closure_digest=_digest(
                        f"artifact-closure-{definition.tool_id}-{capability.value}"
                    ),
                    evidence_digest=_digest(f"evidence-{definition.tool_id}-{capability.value}"),
                    semantic_claim_id=semantic_contract(capability).comprehensive_claim_id,
                    semantic_joints=semantic_contract(capability).required_joints,
                    implementation_family=next(
                        (
                            fixture.implementation_family
                            for fixture in definition.fixtures
                            if fixture.capability is capability
                        ),
                        definition.tool_id,
                    ),
                )
                for capability in definition.capabilities
            ),
            counts=EvidenceCounts(
                passed=len(definition.capabilities),
                failed=0,
                unavailable=0,
                total=len(definition.capabilities),
            ),
            status=ReleaseEvidenceStatus.PASSED,
        )
        for definition in BACKEND_CATALOG.backends
    )


def _flows() -> tuple[FlowReleaseEvidence, ...]:
    return tuple(
        FlowReleaseEvidence(
            family=family.family,
            public_metadata_digest=family.digest,
            catalog_attestation_digest=_digest("flow-catalog-attestation"),
            family_attestation_digest=_digest(f"flow-attestation-{family.family}"),
            instance_reference_digest=_digest(f"flow-reference-{family.family}"),
            task_spec_digest=_digest(f"flow-task-{family.family}"),
            task_instance_digest=_digest(f"flow-instance-{family.family}"),
            release_digest=_digest(f"flow-release-{family.family}"),
            qualification_digest=_digest(f"flow-qualification-{family.family}"),
            runs=(
                FlowRunEvidence(
                    resource_id="witness.reference",
                    role=FlowRunRole.WITNESS,
                    record_digest=_digest(f"flow-witness-{family.family}"),
                    status=ReleaseEvidenceStatus.PASSED,
                ),
                FlowRunEvidence(
                    resource_id="negative.semantic_mutant",
                    role=FlowRunRole.NEGATIVE,
                    record_digest=_digest(f"flow-negative-{family.family}"),
                    status=ReleaseEvidenceStatus.PASSED,
                ),
            ),
            counts=EvidenceCounts(passed=2, failed=0, unavailable=0, total=2),
            status=ReleaseEvidenceStatus.PASSED,
        )
        for family in EDA_FLOW_FAMILIES
    )


def _campaign(scope: CampaignScope) -> CampaignEvidence:
    smoke = scope is CampaignScope.END_TO_END_SMOKE
    route_ids = ("frontier",) if smoke else ("frontier", "coding", "balanced", "throughput")
    common_tasks = tuple(_digest(f"comparison-task-{index}") for index in range(8))
    task_releases = (
        tuple(_digest(f"smoke-release-{index}") for index in range(3))
        if smoke
        else common_tasks[:6]
        if scope is CampaignScope.REASONING_EFFORT_SENSITIVITY
        else common_tasks
    )
    reasoning_efforts = (
        ("low", "medium")
        if scope is CampaignScope.REASONING_EFFORT_SENSITIVITY
        else ("medium",)
    )
    paired_trial_seeds = (
        ("1" * 32, "2" * 32, "3" * 32)
        if scope is CampaignScope.COMMON_CORE
        else ("1" * 32,)
    )
    trial_count = (
        len(task_releases)
        * len(route_ids)
        * len(reasoning_efforts)
        * len(paired_trial_seeds)
    )
    smoke_families = (
        SAIL_RTL_FAMILIES[0].family,
        "synthesis_qor_tuning",
        "physical_design_closure",
    )
    smoke_roles = (
        CampaignTaskRole.RTL_GENERATION,
        CampaignTaskRole.SYNTHESIS_QOR,
        CampaignTaskRole.PHYSICAL_ANALOG,
    )
    smoke_capabilities = (
        Capability.RTL_SIMULATION,
        Capability.ASIC_SYNTHESIS,
        Capability.DIGITAL_IMPLEMENTATION,
    )
    end_to_end = (
        EndToEndSmokeEvidence(
            trials=tuple(
                EndToEndTrialEvidence(
                    trial_id=f"smoke_trial_{index}",
                    run_id=_digest(f"smoke-run-{index}"),
                    run_record_digest=_digest(f"smoke-record-{index}"),
                    campaign_trial_result_digest=_digest(f"smoke-trial-result-{index}"),
                    task_family=smoke_families[index],
                    task_role=smoke_roles[index],
                    device_capability=smoke_capabilities[index],
                    task_spec_digest=_digest(f"smoke-task-{index}"),
                    task_instance_digest=_digest(f"smoke-instance-{index}"),
                    release_digest=_digest(f"smoke-release-{index}"),
                    session_spec_digest=_digest("smoke-session"),
                    environment_spec_digest=_digest(f"smoke-environment-{index}"),
                    participant_actor_id="smoke_agent",
                    is_training=index == 0,
                    artifact_closure_receipt_digest=_digest(
                        f"smoke-artifact-closure-{index}"
                    ),
                    recovery=(
                        ParticipantRecoveryEvidence(
                            run_record_digest=_digest("smoke-record-0"),
                            artifact_closure_receipt_digest=_digest(
                                "smoke-artifact-closure-0"
                            ),
                            lifecycle_digest=_digest("smoke-recovery-lifecycle"),
                            checkpoint_id="checkpoint_after_feedback_0",
                            checkpoint_manifest_digest=_digest(
                                "smoke-checkpoint-manifest"
                            ),
                            terminated_sequence=20,
                            restored_sequence=21,
                            restored_incarnation_digest=_digest(
                                "smoke-restored-incarnation"
                            ),
                            restored_manifest_digest=_digest(
                                "smoke-checkpoint-manifest"
                            ),
                            post_restore_provider_request_id="smoke_resume_request",
                            post_restore_tool_invocation_id="smoke_resume_tool",
                            post_restore_candidate_id="candidate_improved_0",
                        )
                        if index == 0
                        else None
                    ),
                    candidate_ids=(
                        f"candidate_initial_{index}",
                        f"candidate_improved_{index}",
                    ),
                    eda_tool_ids=("iverilog", "vcs"),
                    checkpoint_ids=(f"checkpoint_after_feedback_{index}",),
                    artifact_counts=tuple(
                        ArtifactClassCount(
                            artifact_class=artifact_class,
                            count=1,
                        )
                        for artifact_class in (
                            ArtifactClass.CANDIDATE,
                            ArtifactClass.CHECKPOINT,
                            ArtifactClass.EVIDENCE,
                        )
                    ),
                    atif_projection_digest=_digest(f"atif-{index}"),
                    report_projection_digest=_digest(f"harbor-{index}"),
                    failed_requirements=(),
                    unavailable_requirements=(
                        ()
                        if index == 0
                        else (
                            EndToEndRequirement.CANDIDATE_CHANGE,
                            EndToEndRequirement.CONTROLLED_FEEDBACK,
                            EndToEndRequirement.CHECKPOINT,
                            EndToEndRequirement.PARTICIPANT_RECOVERY,
                        )
                    ),
                    status=(
                        ReleaseEvidenceStatus.PASSED
                        if index == 0
                        else ReleaseEvidenceStatus.UNAVAILABLE
                    ),
                )
                for index in range(3)
            ),
            training_run_id=_digest("smoke-run-0"),
            eda_tool_ids=("iverilog", "vcs"),
            failed_requirements=(),
            unavailable_requirements=(),
            status=ReleaseEvidenceStatus.PASSED,
        )
        if smoke
        else None
    )
    return CampaignEvidence(
        campaign_digest=_digest(f"campaign-{scope.value}"),
        campaign_scope=scope,
        campaign_header_digest=_digest(f"campaign-header-{scope.value}"),
        schedule_digest=_digest(f"campaign-schedule-{scope.value}"),
        campaign_record_digest=_digest(f"campaign-record-{scope.value}"),
        report_digest=_digest(f"campaign-report-{scope.value}"),
        model_set_digest=_digest("model-set"),
        model_discovery_digest=_digest("model-discovery"),
        comparison_digest=_digest("comparison"),
        controlled_variables_digest=_digest("controlled-variables"),
        provider_logical_id=RUST_CAT_PROFILE.logical_id,
        provider_profile_digest=RUST_CAT_PROFILE.digest,
        provider_config_digest=_digest("provider-config"),
        route_ids=route_ids,
        route_canary_evidence_digests=tuple(
            _digest(f"canary-{route_id}") for route_id in route_ids
        ),
        task_bindings=tuple(
            CampaignTaskBindingEvidence(
                task_release_digest=task_release_digest,
                binding_digest=_digest(f"task-binding-{task_release_digest}"),
            )
            for task_release_digest in task_releases
        ),
        reasoning_efforts=reasoning_efforts,
        paired_trial_seeds=paired_trial_seeds,
        covered_model_categories=tuple(REQUIRED_MODEL_CATEGORIES),
        uncovered_categories=(),
        positive_usage_trial_count=trial_count,
        unknown_usage_attempt_count=0,
        service_tier_accounting=ServiceTierAccounting(
            requested_service_tier="default",
            provider_reported_service_tiers=(
                ReportedServiceTierCount(
                    provider_reported_service_tier="default",
                    count=trial_count,
                ),
            ),
            unknown_attempts=0,
            reported_tier_mismatches=CountRatio(numerator=0, denominator=trial_count),
        ),
        counts=EvidenceCounts(
            passed=trial_count,
            failed=0,
            unavailable=0,
            total=trial_count,
        ),
        budget_violation=False,
        end_to_end=end_to_end,
        status=ReleaseEvidenceStatus.PASSED,
    )


def _participant_modes() -> ParticipantModeSuiteEvidence:
    mode_specs = (
        (ParticipationKind.HUMAN, ModeKind.COURSE),
        (ParticipationKind.AGENT, ModeKind.BENCHMARK),
        (ParticipationKind.HYBRID, ModeKind.TRAINING),
    )
    runs: list[ParticipantModeRunEvidence] = []
    for index, (participation, mode) in enumerate(mode_specs):
        human = HumanRunActor(
            actor_id=f"human_{index}",
            adapter_digest=_digest(f"human-adapter-{index}"),
        )
        harness = HarnessRunActor(
            actor_id=f"agent_{index}",
            harness_digest=_digest(f"harness-{index}"),
            scaffold_digest=_digest(f"scaffold-{index}"),
            requested_model_route="qualified-route",
        )
        actors = (
            (human,)
            if participation is ParticipationKind.HUMAN
            else (harness,)
            if participation is ParticipationKind.AGENT
            else (human, harness)
        )
        initial_writer = actors[0].actor_id
        actions: tuple[ParticipantActionEvidence, ...]
        handoffs: tuple[ParticipantHandoffEvidence, ...]
        if participation is ParticipationKind.HYBRID:
            actions = (
                ParticipantActionEvidence(
                    sequence=1,
                    event_id=UUID(int=100 + index * 10),
                    actor_id=human.actor_id,
                    kind=ParticipantActionKind.CANDIDATE_SUBMISSION,
                ),
                ParticipantActionEvidence(
                    sequence=2,
                    event_id=UUID(int=101 + index * 10),
                    actor_id=human.actor_id,
                    kind=ParticipantActionKind.CONTROL_TRANSFER,
                ),
                ParticipantActionEvidence(
                    sequence=3,
                    event_id=UUID(int=102 + index * 10),
                    actor_id=harness.actor_id,
                    kind=ParticipantActionKind.CANDIDATE_SUBMISSION,
                ),
            )
            handoffs = (
                ParticipantHandoffEvidence(
                    sequence=2,
                    event_id=UUID(int=101 + index * 10),
                    previous_writer=human.actor_id,
                    next_writer=harness.actor_id,
                ),
            )
            final_writer = harness.actor_id
        else:
            actions = (
                ParticipantActionEvidence(
                    sequence=1,
                    event_id=UUID(int=100 + index * 10),
                    actor_id=initial_writer,
                    kind=ParticipantActionKind.CANDIDATE_SUBMISSION,
                ),
            )
            handoffs = ()
            final_writer = initial_writer
        session_evidence = ParticipantSessionEvidence(
            run_id=_digest(f"participant-run-{index}"),
            run_record_integrity_digest=_digest(f"participant-record-{index}"),
            task_spec_digest=_digest(f"participant-task-{index}"),
            instance_digest=_digest(f"participant-instance-{index}"),
            release_digest=_digest(f"participant-release-{index}"),
            environment_spec_digest=_digest(f"participant-environment-{index}"),
            session_spec_digest=_digest(f"participant-session-{index}"),
            participation=participation,
            actors=actors,
            initial_writer=initial_writer,
            final_writer=final_writer,
            handoff_enabled=participation is ParticipationKind.HYBRID,
            actions=actions,
            handoffs=handoffs,
            terminal_reason=StopReason.VERIFIER_SUCCESS,
        )
        runs.append(
            ParticipantModeRunEvidence(
                session=session_evidence,
                mode=mode,
                candidate_authority=CandidateAuthority.PARTICIPANT,
                artifact_closure_receipt_digest=_digest(
                    f"participant-artifact-closure-{index}"
                ),
                artifact_counts=(
                    ArtifactClassCount(artifact_class=ArtifactClass.CANDIDATE, count=1),
                    ArtifactClassCount(artifact_class=ArtifactClass.EVIDENCE, count=1),
                ),
                atif_projection_digest=_digest(f"participant-atif-{index}"),
                harbor_projection_digest=_digest(f"participant-harbor-{index}"),
                nemo_projection_digest=_digest(f"participant-nemo-{index}"),
                course_projection_digest=(
                    _digest("participant-course") if mode is ModeKind.COURSE else None
                ),
                leaderboard_projection_digest=(
                    _digest("participant-leaderboard")
                    if mode is ModeKind.BENCHMARK
                    else None
                ),
            )
        )
    return ParticipantModeSuiteEvidence(
        runs=tuple(runs),
        missing_participation=(),
        projection_coverage=tuple(ReleaseProjectionKind),
        status=ReleaseEvidenceStatus.PASSED,
    )


def _repository() -> RepositoryAuditEvidence:
    coverage = tuple(
        RepositoryCoverageEvidence(
            scope=scope,
            status=(
                CoverageStatus.NOT_USED
                if scope is CoverageScope.GIT_LFS
                else CoverageStatus.COMPLETE
            ),
        )
        for scope in CoverageScope
    )
    return RepositoryAuditEvidence(
        audit_digest=_digest("repository-audit"),
        snapshot=_repository_identity(),
        mode=AuditMode.RELEASE,
        audit_status=AuditStatus.PASS,
        coverage=coverage,
        complete_coverage_count=len(CoverageScope),
        incomplete_coverage_count=0,
        finding_count=0,
        issue_count=0,
        status=ReleaseEvidenceStatus.PASSED,
    )


def _private_roots() -> PrivateRootAuditReport:
    return PrivateRootAuditReport(
        repository_snapshot_digest=_repository_identity().digest,
        policy_digest=_digest("private-root-policy"),
        roots=(
            PrivateRootSummary(
                roles=tuple(REQUIRED_RELEASE_PRIVATE_ROOT_ROLES),
                root_kind=PrivateRootKind.DIRECTORY,
                source_identity_digests=tuple(
                    _digest(f"private-root-source-{role.value}")
                    for role in REQUIRED_RELEASE_PRIVATE_ROOT_ROLES
                ),
                tree_identity_digest=_digest("private-root-tree"),
                directory_count=1,
                regular_file_count=1,
                symlink_count=0,
                other_count=0,
                owner_mismatch_count=0,
                hardlink_ambiguity_count=0,
                unstable_entry_count=0,
                exposed_modes=(),
            ),
        ),
        missing_roles=(),
        status=PrivateRootAuditStatus.PASS,
    )


def _durable_executor() -> DurableExecutorEvidence:
    return DurableExecutorEvidence(
        capability_digest=_digest("local-containment"),
        available_runtime_commands=("systemd-run", "systemctl", "env"),
        control_plane_probe_digest=_digest("user-systemd-manager"),
        status=ReleaseEvidenceStatus.PASSED,
    )


def _retained_invocation(
    store: ContentAddressedStore,
    invocation_digest: str,
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int | None = 0,
    failure: CommandFailure | None = None,
) -> ReleaseInvocationReceipt:
    disclosure = {
        "artifact_class": ArtifactClass.EVIDENCE,
        "sensitivity": Sensitivity.INTERNAL,
        "visibility": Visibility.AUTHOR,
        "redistribution": Redistribution.RESTRICTED,
    }
    stdout_blob = store.put_bytes(stdout, **disclosure)  # type: ignore[arg-type]
    stderr_blob = store.put_bytes(stderr, **disclosure)  # type: ignore[arg-type]
    timestamp = datetime(2026, 9, 4, tzinfo=UTC)
    evidence = ReleaseInvocationEvidence(
        invocation_digest=invocation_digest,
        started_at=timestamp,
        finished_at=timestamp,
        exit_code=exit_code,
        stdout_blob=stdout_blob,
        stderr_blob=stderr_blob,
        failure=failure,
    )
    evidence_blob = store.put_bytes(canonical_bytes(evidence), **disclosure)  # type: ignore[arg-type]
    return ReleaseInvocationReceipt(
        invocation_digest=invocation_digest,
        evidence=evidence,
        evidence_blob=evidence_blob,
    )


def _command(
    purpose: ReleaseCommandPurpose,
    store: ContentAddressedStore,
    *,
    installation_receipt_digest: str | None = None,
) -> ReleaseCommandEvidence:
    repository = _repository_identity()
    subject = (
        PUBLIC_TASK_CATALOG.digest
        if purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT
        else repository.digest
    )
    tool_ids = (
        {"go"}
        if purpose is ReleaseCommandPurpose.VM_GUEST
        else {"git"}
        if purpose is ReleaseCommandPurpose.FINAL_GIT_STATE
        else {"python"}
    )
    plan = release_command_plan(
        purpose=purpose,
        repository=repository,
        input_subject_digest=subject,
        executable_digests={tool_id: _digest(f"executable-{tool_id}") for tool_id in tool_ids},
        installation_receipt_digest=installation_receipt_digest,
    )
    receipts = tuple(
        _retained_invocation(store, invocation.digest)
        for invocation in plan.invocations
    )
    receipt = ReleaseCommandReceipt(
        plan=plan,
        invocations=receipts,
        verified_public_catalog_digest=(
            PUBLIC_TASK_CATALOG.digest
            if purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT
            else None
        ),
        installed_environment_digest=(
            _digest("installed-environment")
            if purpose is ReleaseCommandPurpose.CLEAN_INSTALLATION
            else None
        ),
    )
    return _command_evidence(receipt, store)


def _command_evidence(
    receipt: ReleaseCommandReceipt,
    store: ContentAddressedStore,
) -> ReleaseCommandEvidence:
    return ReleaseCommandEvidence(
        purpose=receipt.plan.purpose,
        plan_digest=receipt.plan.digest,
        receipt_digest=receipt.digest,
        repository_identity_digest=receipt.plan.repository.digest,
        artifact_policy_digest=store.policy_digest,
        input_subject_digest=receipt.plan.input_subject_digest,
        installation_receipt_digest=receipt.plan.installation_receipt_digest,
        verified_public_catalog_digest=receipt.verified_public_catalog_digest,
        invocation_receipts=receipt.invocations,
        status=receipt.status,
    )


def _ready_report(tmp_path: Path, *, reverse_commands: bool = False) -> ReleaseReport:
    backends = _backends()
    store = ContentAddressedStore(
        tmp_path / "release-command-store",
        policy=environment_spec().artifact_policy,
    )
    installation = _command(ReleaseCommandPurpose.CLEAN_INSTALLATION, store)
    commands = (
        installation,
        *(
            _command(
                purpose,
                store,
                installation_receipt_digest=(
                    installation.receipt_digest
                    if release_command_requires_installation(purpose)
                    else None
                ),
            )
            for purpose in tuple(ReleaseCommandPurpose)[1:]
        ),
    )
    if reverse_commands:
        commands = tuple(reversed(commands))
    return ReleaseReport(
        public_task_catalog_digest=PUBLIC_TASK_CATALOG.digest,
        flow_catalog_attestation_digest=_digest("flow-catalog-attestation"),
        backend_catalog_digest=BACKEND_CATALOG.digest,
        authoring=_authoring(),
        backends=backends,
        backend_coverage=project_backend_coverage(backends),
        flows=_flows(),
        campaigns=(
            _campaign(CampaignScope.END_TO_END_SMOKE),
            _campaign(CampaignScope.MODEL_COMPARISON_PILOT),
            _campaign(CampaignScope.COMMON_CORE),
            _campaign(CampaignScope.REASONING_EFFORT_SENSITIVITY),
        ),
        participant_modes=_participant_modes(),
        repository=_repository(),
        private_roots=_private_roots(),
        durable_executor=_durable_executor(),
        commands=commands,
        source_counts=EvidenceCounts(passed=9, failed=0, unavailable=0, total=9),
        decision=ReleaseDecision.READY,
    )


def test_ready_report_requires_complete_derived_release_gates(tmp_path: Path) -> None:
    first = _ready_report(tmp_path)
    second = _ready_report(tmp_path, reverse_commands=True)
    assert first == second
    assert first.digest == second.digest
    assert first.decision is ReleaseDecision.READY

    missing_flow = first.model_dump(mode="json")
    missing_flow["flows"].pop()
    with pytest.raises(ValidationError, match="exactly twelve flow families"):
        ReleaseReport.model_validate(missing_flow)

    forged_coverage = first.model_dump(mode="json")
    synthesis = next(
        item
        for item in forged_coverage["backend_coverage"]
        if item["capability"] == Capability.ASIC_SYNTHESIS.value
    )
    synthesis["independent_implementations"] = synthesis[
        "independent_implementations"
    ][:1]
    synthesis["status"] = ReleaseEvidenceStatus.UNAVAILABLE.value
    with pytest.raises(ValidationError, match="derived from qualifications"):
        ReleaseReport.model_validate(forged_coverage)

    mismatched_campaign = first.model_dump(mode="json")
    pilot = next(
        item
        for item in mismatched_campaign["campaigns"]
        if item["campaign_scope"] == CampaignScope.MODEL_COMPARISON_PILOT.value
    )
    pilot["comparison_digest"] = _digest("changed")
    with pytest.raises(ValidationError, match="source counts"):
        ReleaseReport.model_validate(mismatched_campaign)

    missing_smoke = first.model_dump(mode="json")
    missing_smoke["campaigns"] = [
        item
        for item in missing_smoke["campaigns"]
        if item["campaign_scope"] != CampaignScope.END_TO_END_SMOKE.value
    ]
    with pytest.raises(ValidationError, match="source counts"):
        ReleaseReport.model_validate(missing_smoke)

    missing_effort = first.model_dump(mode="json")
    missing_effort["campaigns"] = [
        item
        for item in missing_effort["campaigns"]
        if item["campaign_scope"]
        != CampaignScope.REASONING_EFFORT_SENSITIVITY.value
    ]
    with pytest.raises(ValidationError, match="source counts"):
        ReleaseReport.model_validate(missing_effort)

    mismatched_effort = first.model_dump(mode="json")
    effort = next(
        item
        for item in mismatched_effort["campaigns"]
        if item["campaign_scope"]
        == CampaignScope.REASONING_EFFORT_SENSITIVITY.value
    )
    effort["controlled_variables_digest"] = _digest("different-controlled-variables")
    with pytest.raises(ValidationError, match="source counts"):
        ReleaseReport.model_validate(mismatched_effort)

    incomplete_smoke = first.model_dump(mode="json")
    smoke = next(
        item
        for item in incomplete_smoke["campaigns"]
        if item["campaign_scope"] == CampaignScope.END_TO_END_SMOKE.value
    )
    smoke["end_to_end"]["trials"].pop()
    with pytest.raises(ValidationError, match="at least 3 items"):
        ReleaseReport.model_validate(incomplete_smoke)

    mislabeled_actual_trial = first.model_dump(mode="json")
    smoke = next(
        item
        for item in mislabeled_actual_trial["campaigns"]
        if item["campaign_scope"] == CampaignScope.END_TO_END_SMOKE.value
    )
    smoke["end_to_end"]["trials"][2]["task_role"] = (
        CampaignTaskRole.TOOL_FAILURE_RECOVERY.value
    )
    with pytest.raises(ValidationError, match="summary must derive"):
        ReleaseReport.model_validate(mislabeled_actual_trial)

    duplicate_training = first.model_dump(mode="json")
    smoke = next(
        item
        for item in duplicate_training["campaigns"]
        if item["campaign_scope"] == CampaignScope.END_TO_END_SMOKE.value
    )
    smoke["end_to_end"]["trials"][1]["is_training"] = True
    with pytest.raises(ValidationError, match="summary must derive"):
        ReleaseReport.model_validate(duplicate_training)

    stale_recovery = first.model_dump(mode="json")
    smoke = next(
        item
        for item in stale_recovery["campaigns"]
        if item["campaign_scope"] == CampaignScope.END_TO_END_SMOKE.value
    )
    smoke["end_to_end"]["trials"][0]["recovery"]["restored_manifest_digest"] = (
        _digest("different-restored-manifest")
    )
    with pytest.raises(ValidationError, match="committed checkpoint manifest"):
        ReleaseReport.model_validate(stale_recovery)

    spoofed_capability = first.model_dump(mode="json")
    smoke = next(
        item
        for item in spoofed_capability["campaigns"]
        if item["campaign_scope"] == CampaignScope.END_TO_END_SMOKE.value
    )
    smoke["end_to_end"]["trials"][2]["device_capability"] = (
        Capability.RTL_SIMULATION.value
    )
    with pytest.raises(ValidationError, match="does not admit"):
        ReleaseReport.model_validate(spoofed_capability)

    unknown_paid_usage = first.model_dump(mode="json")
    smoke = next(
        item
        for item in unknown_paid_usage["campaigns"]
        if item["campaign_scope"] == CampaignScope.END_TO_END_SMOKE.value
    )
    smoke["unknown_usage_attempt_count"] = 1
    with pytest.raises(ValidationError, match="complete positive usage"):
        ReleaseReport.model_validate(unknown_paid_usage)

    honest_unavailable_category = _campaign(
        CampaignScope.MODEL_COMPARISON_PILOT
    ).model_dump(mode="json")
    honest_unavailable_category["covered_model_categories"].remove(
        ModelCategory.HIGH_THROUGHPUT.value
    )
    honest_unavailable_category["uncovered_categories"] = [
        UncoveredCategory(
            category=ModelCategory.HIGH_THROUGHPUT,
            reason=CategoryExclusionReason.NO_QUALIFIED_ROUTE,
            evidence_digest=_digest("unavailable-high-throughput-route"),
        ).model_dump(mode="json")
    ]
    assert (
        CampaignEvidence.model_validate(honest_unavailable_category).status
        is ReleaseEvidenceStatus.PASSED
    )

    incomplete_authoring = first.model_dump(mode="json")
    incomplete_authoring["authoring"]["qualification_digests"].pop()
    with pytest.raises(ValidationError, match="every Sail base and advanced"):
        ReleaseReport.model_validate(incomplete_authoring)

    unavailable_executor = first.model_dump(mode="json")
    unavailable_executor["durable_executor"] = {
        "capability_digest": _digest("local-containment-unavailable"),
        "available_runtime_commands": ["env", "systemctl", "systemd-run"],
        "control_plane_probe_digest": None,
        "unavailable": ProviderUnavailableReason.CONTROL_PLANE_UNAVAILABLE.value,
        "status": ReleaseEvidenceStatus.UNAVAILABLE.value,
    }
    unavailable_executor["source_counts"] = {
        "passed": 8,
        "failed": 0,
        "unavailable": 1,
        "total": 9,
    }
    unavailable_executor["decision"] = ReleaseDecision.INCOMPLETE.value
    assert ReleaseReport.model_validate(unavailable_executor).decision is ReleaseDecision.INCOMPLETE

    wrong_catalog = first.model_dump(mode="json")
    catalog_check = next(
        item
        for item in wrong_catalog["commands"]
        if item["purpose"] == ReleaseCommandPurpose.AUTHORING_CONTRACT.value
    )
    catalog_check["input_subject_digest"] = _digest("different-catalog")
    with pytest.raises(ValidationError, match="different catalog"):
        ReleaseReport.model_validate(wrong_catalog)

    wrong_verified_catalog = first.model_dump(mode="json")
    catalog_check = next(
        item
        for item in wrong_verified_catalog["commands"]
        if item["purpose"] == ReleaseCommandPurpose.AUTHORING_CONTRACT.value
    )
    catalog_check["verified_public_catalog_digest"] = _digest("different-catalog")
    with pytest.raises(ValidationError, match="different public catalog"):
        ReleaseReport.model_validate(wrong_verified_catalog)


def test_command_failures_and_unavailability_remain_distinct(tmp_path: Path) -> None:
    repository = _repository_identity()
    store = ContentAddressedStore(
        tmp_path / "release-command-store",
        policy=environment_spec().artifact_policy,
    )
    installation_receipt_digest = _digest("installation-receipt")
    failed_plan = release_command_plan(
        purpose=ReleaseCommandPurpose.TEST_SUITE,
        repository=repository,
        input_subject_digest=repository.digest,
        executable_digests={"python": _digest("python")},
        installation_receipt_digest=installation_receipt_digest,
    )
    invocation = failed_plan.invocations[0]
    failed_invocation = _retained_invocation(
        store,
        invocation.digest,
        stdout=b"failed-stdout",
        stderr=b"failed-stderr",
        exit_code=2,
        failure=CommandFailure.NONZERO_EXIT,
    )
    failed = _command_evidence(
        ReleaseCommandReceipt(plan=failed_plan, invocations=(failed_invocation,)),
        store,
    )
    unavailable_plan = release_command_plan(
        purpose=ReleaseCommandPurpose.SCHEMA_EXPORTS,
        repository=repository,
        input_subject_digest=repository.digest,
        executable_digests={"python": _digest("python")},
        installation_receipt_digest=installation_receipt_digest,
    )
    unavailable = _command_evidence(
        ReleaseCommandReceipt(
            plan=unavailable_plan,
            invocations=(
                ReleaseInvocationReceipt(
                    invocation_digest=unavailable_plan.invocations[0].digest,
                    unavailable=CommandUnavailable.AUTHORIZATION_REQUIRED,
                ),
            ),
        ),
        store,
    )
    assert failed.receipt_digest != unavailable.receipt_digest
    assert failed.status is ReleaseEvidenceStatus.FAILED
    assert unavailable.status is ReleaseEvidenceStatus.UNAVAILABLE

    with pytest.raises(ValidationError, match="cannot claim execution evidence"):
        ReleaseInvocationReceipt(
            invocation_digest=unavailable_plan.invocations[0].digest,
            evidence=failed_invocation.evidence,
            unavailable=CommandUnavailable.AUTHORIZATION_REQUIRED,
        )

    payload = failed.model_dump(mode="json")
    payload["status"] = ReleaseEvidenceStatus.PASSED.value
    with pytest.raises(ValidationError, match="derived from invocation receipts"):
        ReleaseCommandEvidence.model_validate(payload)

    arbitrary_argv = failed_plan.model_dump(mode="json")
    arbitrary_argv["invocations"][0]["argv"] = ["python", "-c", "true"]
    with pytest.raises(ValidationError, match="canonical purpose"):
        ReleaseCommandPlan.model_validate(arbitrary_argv)

    catalog_plan = release_command_plan(
        purpose=ReleaseCommandPurpose.AUTHORING_CONTRACT,
        repository=repository,
        input_subject_digest=PUBLIC_TASK_CATALOG.digest,
        executable_digests={"python": _digest("python")},
        installation_receipt_digest=installation_receipt_digest,
    )
    catalog_invocation = _retained_invocation(
        store,
        catalog_plan.invocations[0].digest,
    )
    with pytest.raises(ValidationError, match="public catalog digest"):
        ReleaseCommandReceipt(
            plan=catalog_plan,
            invocations=(catalog_invocation,),
        )
    assert (
        ReleaseCommandReceipt(
            plan=catalog_plan,
            invocations=(
                ReleaseInvocationReceipt(
                    invocation_digest=catalog_plan.invocations[0].digest,
                    unavailable=CommandUnavailable.NOT_RUN,
                ),
            ),
        ).status
        is ReleaseEvidenceStatus.UNAVAILABLE
    )
    with pytest.raises(ValidationError, match="only the authoring contract"):
        ReleaseCommandReceipt(
            plan=unavailable_plan,
            invocations=unavailable.invocation_receipts,
            verified_public_catalog_digest=_digest("catalog"),
        )


def test_route_canary_source_cannot_be_relabelled_by_a_model_set() -> None:
    provider = ResolvedProviderConfig(
        selected_provider_label="rust_cat",
        profile=RUST_CAT_PROFILE,
        defaults=ProviderDefaults(requested_model="gpt-route"),
    )
    discovery = ModelDiscoverySnapshot(
        provider_profile_digest=provider.profile.digest,
        provider_config_digest=provider.digest,
        selected_provider_label=provider.selected_provider_label,
        source=ModelDiscoverySource.EXPLICIT_CANDIDATES,
        model_labels=("gpt-route",),
        source_evidence_digest=_digest("model-discovery-source"),
    )
    canary = RouteCanaryEvidence(
        requested_model="gpt-route",
        provider_reported_model="provider-route",
        reasoning_control=FeatureSupport.SUPPORTED,
        service_tier_requested="default",
        provider_reported_service_tier="default",
        request_body_bytes=10,
        tool_schema_digest=_digest("canary-tool-schema"),
        usage=RouteCanaryUsage(input_tokens=20, output_tokens=5, total_tokens=25),
    )
    qualification = RouteQualification(
        authentication=True,
        responses_protocol=True,
        usage_reporting=True,
        structured_output=True,
        typed_tool_call=True,
        reasoning_control=canary.reasoning_control,
        canary_tool_schema_digest=canary.tool_schema_digest,
        requested_service_tier=canary.service_tier_requested,
        provider_reported_service_tier=canary.provider_reported_service_tier,
        observed_input_token_floor=canary.observed_input_token_floor,
        canary_evidence_digest=canary.digest,
    )
    route = ModelRoute(
        route_id="qualified_route",
        requested_model=canary.requested_model,
        provider_reported_model=canary.provider_reported_model,
        reference_kind=ModelReferenceKind.SNAPSHOT,
        categories=tuple(REQUIRED_MODEL_CATEGORIES),
        qualification=qualification,
    )
    model_set = ModelSetManifest(
        provider_config_digest=provider.digest,
        discovery_digest=discovery.digest,
        resolved_on="2026-09-04",
        routes=(route,),
    )
    assert _model_discovery_source(
        provider,
        model_set,
        {discovery.digest: discovery},
    ) == discovery.digest
    assert _route_canary_sources(model_set, {canary.digest: canary}) == (canary.digest,)

    relabelled_discovery = discovery.model_copy(
        update={"model_labels": ("different-route",)}
    )
    wrong_discovery_set = model_set.model_copy(
        update={"discovery_digest": relabelled_discovery.digest}
    )
    with pytest.raises(ValueError, match="exact discovery source"):
        _model_discovery_source(
            provider,
            wrong_discovery_set,
            {relabelled_discovery.digest: relabelled_discovery},
        )

    relabelled = canary.model_copy(update={"requested_model": "different-route"})
    forged_route = route.model_copy(
        update={
            "qualification": qualification.model_copy(
                update={"canary_evidence_digest": relabelled.digest}
            )
        }
    )
    forged_set = model_set.model_copy(update={"routes": (forged_route,)})
    with pytest.raises(ValueError, match="paid canary source"):
        _route_canary_sources(forged_set, {relabelled.digest: relabelled})

    stale_usage_route = route.model_copy(
        update={
            "qualification": qualification.model_copy(
                update={"observed_input_token_floor": canary.observed_input_token_floor - 1}
            )
        }
    )
    stale_usage_set = model_set.model_copy(update={"routes": (stale_usage_route,)})
    with pytest.raises(ValueError, match="paid canary source"):
        _route_canary_sources(stale_usage_set, {canary.digest: canary})

    stale_tool_route = route.model_copy(
        update={
            "qualification": qualification.model_copy(
                update={"canary_tool_schema_digest": _digest("different-canary-tool")}
            )
        }
    )
    stale_tool_set = model_set.model_copy(update={"routes": (stale_tool_route,)})
    with pytest.raises(ValueError, match="paid canary source"):
        _route_canary_sources(stale_tool_set, {canary.digest: canary})


def test_flow_release_replay_rejects_budget_exhaustion_as_negative_evidence() -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session_spec(),
        trial_key="release-negative-terminal",
    )
    header = RunHeader.from_binding(plan.binding)
    candidate_resource = next(
        item for item in task.resources if item.resource_id == "mutant_corrupt"
    )
    resource_id = f"negative.{candidate_resource.resource_id}"
    timestamp = datetime(2026, 9, 4, tzinfo=UTC)
    events = (
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID(int=1),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        ),
        CandidateSubmittedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID(int=2),
            timestamp=timestamp,
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.AUTHOR,
            payload=CandidateSubmittedPayload(
                candidate_id=candidate_resource.resource_id,
                candidate_digest=candidate_resource.content_digest,
            ),
        ),
        EvaluationStartedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID(int=3),
            timestamp=timestamp,
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationStartedPayload(
                stage_id="functional",
                candidate_id=candidate_resource.resource_id,
                job_id="functional_job",
            ),
        ),
        JobStateChangedEvent(
            run_id=header.run_id,
            sequence=3,
            event_id=UUID(int=4),
            timestamp=timestamp,
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.AUTHOR,
            payload=JobStateChangedPayload(
                job_id="functional_job",
                state=JobStateKind.RUNNING,
            ),
        ),
        JobStateChangedEvent(
            run_id=header.run_id,
            sequence=4,
            event_id=UUID(int=5),
            timestamp=timestamp,
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.AUTHOR,
            payload=JobStateChangedPayload(
                job_id="functional_job",
                state=JobStateKind.COMPLETED,
            ),
        ),
        EvaluationCompletedEvent(
            run_id=header.run_id,
            sequence=5,
            event_id=UUID(int=6),
            timestamp=timestamp,
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationCompletedPayload(
                candidate_id=candidate_resource.resource_id,
                job_id="functional_job",
                result=StageResult(
                    stage_id="functional",
                    outcome=CandidateFailureOutcome(),
                ),
            ),
        ),
        RunEndedEvent(
            run_id=header.run_id,
            sequence=6,
            event_id=UUID(int=7),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunEndedPayload(reason=StopReason.UNRANKABLE),
        ),
    )
    negative = RunRecord(
        header=header,
        commits=(
            RunCommit.from_events(
                previous_record_digest=run_journal_anchor(header),
                events=events,
            ),
        ),
    )
    candidate_attestation = FlowCandidateAttestation(
        candidate_id=candidate_resource.resource_id,
        candidate_resource_id=resource_id,
        role=FlowCandidateRole.SEMANTIC_NEGATIVE,
        content_manifest_digest=candidate_resource.content_digest,
        environment_spec_digest=environment.digest,
        expected_candidate_manifest_digest=candidate_resource.content_digest,
        qualification_evidence_digest=negative.integrity_digest,
    )
    assert (
        _flow_record_status(
            negative,
            task,
            release,
            release.digest,
            candidate_attestation,
            FlowRunRole.NEGATIVE,
        )
        is ReleaseEvidenceStatus.PASSED
    )

    forged_candidate = list(negative.events)
    submitted = forged_candidate[1]
    assert isinstance(submitted, CandidateSubmittedEvent)
    forged_candidate[1] = submitted.model_copy(
        update={
            "payload": submitted.payload.model_copy(
                update={"candidate_digest": _digest("different-candidate")}
            )
        }
    )
    forged_record = RunRecord(
        header=header,
        commits=(
            RunCommit.from_events(
                previous_record_digest=run_journal_anchor(header),
                events=tuple(forged_candidate),
            ),
        ),
    )
    assert (
        _flow_record_status(
            forged_record,
            task,
            release,
            release.digest,
            candidate_attestation,
            FlowRunRole.NEGATIVE,
        )
        is ReleaseEvidenceStatus.FAILED
    )

    budget_events = list(negative.events)
    ended = budget_events[-1]
    assert isinstance(ended, RunEndedEvent)
    budget_events[-1] = ended.model_copy(
        update={
            "payload": ended.payload.model_copy(update={"reason": StopReason.INTERACTION_BUDGET})
        }
    )
    budget_stopped = RunRecord(
        header=negative.header,
        commits=(
            RunCommit.from_events(
                previous_record_digest=run_journal_anchor(header),
                events=tuple(budget_events),
            ),
        ),
    )
    assert (
        _flow_record_status(
            budget_stopped,
            task,
            release,
            release.digest,
            candidate_attestation,
            FlowRunRole.NEGATIVE,
        )
        is ReleaseEvidenceStatus.FAILED
    )


def test_hidden_verifier_resources_cannot_be_participant_visible() -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    assert _hidden_verifier_sources_are_disjoint(task, release, environment)

    exposed_task = TaskSpec.model_validate(
        {
            **task.model_dump(mode="python"),
            "visibility": tuple(
                item.model_copy(update={"visibility": Visibility.PARTICIPANT})
                if item.resource_id == "sim_evaluator"
                else item
                for item in task.visibility
            ),
        }
    )
    assert not _hidden_verifier_sources_are_disjoint(
        exposed_task,
        release,
        environment,
    )

def test_repository_release_audit_requires_every_named_surface() -> None:
    payload = _repository().model_dump(mode="json")
    payload["coverage"].pop()
    payload["complete_coverage_count"] -= 1
    with pytest.raises(ValidationError, match="every repository surface"):
        RepositoryAuditEvidence.model_validate(payload)

    misclassified = _repository().model_dump(mode="json")
    non_lfs = next(
        item for item in misclassified["coverage"] if item["scope"] != CoverageScope.GIT_LFS.value
    )
    non_lfs["status"] = CoverageStatus.NOT_USED.value
    with pytest.raises(ValidationError, match="only an unused Git LFS"):
        RepositoryAuditEvidence.model_validate(misclassified)
