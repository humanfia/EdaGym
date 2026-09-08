"""Mechanical end-to-end release evidence from a frozen paid smoke campaign."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.drivers.model import Vendor
from edagym.drivers.qualification import QualificationDisposition
from edagym.drivers.qualification_verification import (
    VerifiedBackendQualificationSource,
)
from edagym.evaluation.model import HardGateState, OutcomeKind
from edagym.evaluation.promotion import hard_gate_status
from edagym.participant_tool_protocol import (
    CHECKPOINT_PARTICIPANT_TOOL_NAME,
    WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
)
from edagym.projections import project_atif_record, project_harbor_record
from edagym.projections.errors import ProjectionUnavailable
from edagym.providers.campaign import CampaignScope
from edagym.providers.campaign_runner import (
    CampaignRecord,
    CampaignReport,
    CampaignResources,
    TrialDisposition,
    TrialOutcomeRecordedEvent,
    TrialReport,
    WorkSettledEvent,
)
from edagym.providers.campaign_schedule import (
    CampaignTaskRole,
    campaign_role_allows_capability,
)
from edagym.providers.trial_evidence import CampaignTrialResult
from edagym.release_commands import ReleaseEvidenceStatus
from edagym.resolution import ResolutionError, resolve_run
from edagym.run.artifacts import ContentAddressedStore, artifact_policy_digest
from edagym.run.journal_storage import JournalError
from edagym.run.trial_journal import (
    participant_incarnation_lifecycle,
    participant_tool_dispatches,
    replay,
)
from edagym.run.trial_model import (
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    EvaluationCompletedEvent,
    HarnessRunActor,
    InteractionDirection,
    InteractionRecordedEvent,
    ParticipantToolSettledEvent,
    ProviderRequestStartedEvent,
    ProviderResponseRecordedEvent,
    RunRecord,
    StopReason,
)
from edagym.security.artifact_closure import ArtifactClosureError, verify_run_artifact_closure
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    ProviderResponseStatus,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import (
    BrokeredHostToolExecutor,
    EnvironmentSpec,
    FilesystemScope,
)
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import FeedbackPolicy, RecoveryPolicy, SessionSpec, TrainingMode
from edagym.specs.task import FlowQualificationSpec, QualificationSpec, TaskSpec
from edagym.task_families.catalog import EDA_FLOW_FAMILIES, SAIL_RTL_FAMILIES

_SAIL_FAMILIES = frozenset(item.family for item in SAIL_RTL_FAMILIES)
_SYNTHESIS_TIMING_FAMILIES = frozenset(
    item.family
    for item in EDA_FLOW_FAMILIES
    if set(item.required_capabilities) & {Capability.ASIC_SYNTHESIS, Capability.STATIC_TIMING}
)
_LONG_FLOW_FAMILIES = frozenset(
    item.family
    for item in EDA_FLOW_FAMILIES
    if set(item.required_capabilities)
    & {
        Capability.DIGITAL_IMPLEMENTATION,
        Capability.CIRCUIT_SIMULATION,
        Capability.FPGA_IMPLEMENTATION,
    }
)


class EndToEndRequirement(StrEnum):
    TASK_BREADTH = "task_breadth"
    CANDIDATE_CHANGE = "candidate_change"
    OPEN_SOURCE_EDA = "open_source_eda"
    COMMERCIAL_EDA = "commercial_eda"
    EDA_INPUT_ISOLATION = "eda_input_isolation"
    CONTROLLED_FEEDBACK = "controlled_feedback"
    CHECKPOINT = "checkpoint"
    PARTICIPANT_RECOVERY = "participant_recovery"
    HIDDEN_VERIFIER = "hidden_verifier"
    ARTIFACT_COMMIT = "artifact_commit"
    ATIF_PROJECTION = "atif_projection"
    REPORT_PROJECTION = "report_projection"


class ArtifactClassCount(StrictModel):
    """Public-safe count of verified retained artifacts by semantic class."""

    artifact_class: ArtifactClass
    count: JcsPositiveInt


class ParticipantRecoveryEvidence(StrictModel):
    """Path-free release projection of one journal-owned participant restart."""

    run_record_digest: Digest
    artifact_closure_receipt_digest: Digest
    lifecycle_digest: Digest
    checkpoint_id: Identifier
    checkpoint_manifest_digest: Digest
    terminated_sequence: JcsNonNegativeInt
    restored_sequence: JcsNonNegativeInt
    restored_incarnation_digest: Digest
    restored_manifest_digest: Digest
    post_restore_provider_request_id: Identifier
    post_restore_tool_invocation_id: Identifier
    post_restore_candidate_id: Identifier

    @model_validator(mode="after")
    def validate_recovery(self) -> Self:
        if self.restored_sequence <= self.terminated_sequence:
            raise ValueError("participant restore must follow termination")
        if self.restored_manifest_digest != self.checkpoint_manifest_digest:
            raise ValueError("participant restore must use the committed checkpoint manifest")
        return self


class EndToEndTrialEvidence(StrictModel):
    """Compact projection of one replayed smoke trial."""

    trial_id: Identifier
    run_id: Digest
    run_record_digest: Digest
    campaign_trial_result_digest: Digest
    task_family: Identifier
    task_role: CampaignTaskRole
    device_capability: Capability
    task_spec_digest: Digest
    task_instance_digest: Digest
    release_digest: Digest
    session_spec_digest: Digest
    environment_spec_digest: Digest
    participant_actor_id: Identifier
    is_training: bool
    artifact_closure_receipt_digest: Digest
    recovery: ParticipantRecoveryEvidence | None = None
    candidate_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    eda_tool_ids: tuple[Identifier, ...]
    checkpoint_ids: tuple[Identifier, ...]
    artifact_counts: tuple[ArtifactClassCount, ...]
    atif_projection_digest: Digest | None = None
    report_projection_digest: Digest | None = None
    failed_requirements: tuple[EndToEndRequirement, ...]
    unavailable_requirements: tuple[EndToEndRequirement, ...]
    status: ReleaseEvidenceStatus

    @field_validator("candidate_ids", "eda_tool_ids", "checkpoint_ids")
    @classmethod
    def normalize_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("end-to-end evidence identities must be unique")
        return tuple(sorted(value))

    @field_validator("artifact_counts")
    @classmethod
    def normalize_artifact_counts(
        cls,
        value: tuple[ArtifactClassCount, ...],
    ) -> tuple[ArtifactClassCount, ...]:
        classes = [item.artifact_class for item in value]
        if len(classes) != len(set(classes)):
            raise ValueError("end-to-end artifact classes must be unique")
        return tuple(sorted(value, key=lambda item: item.artifact_class.value))

    @field_validator("failed_requirements", "unavailable_requirements")
    @classmethod
    def normalize_requirements(
        cls,
        value: tuple[EndToEndRequirement, ...],
    ) -> tuple[EndToEndRequirement, ...]:
        if len(value) != len(set(value)):
            raise ValueError("end-to-end requirements must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if not campaign_role_allows_capability(self.task_role, self.device_capability):
            raise ValueError("end-to-end task role does not admit its device capability")
        failed = set(self.failed_requirements)
        unavailable = set(self.unavailable_requirements)
        if failed & unavailable:
            raise ValueError("end-to-end failed and unavailable requirements must be disjoint")
        passed = set(EndToEndRequirement) - failed - unavailable
        if (self.atif_projection_digest is not None) != (
            EndToEndRequirement.ATIF_PROJECTION in passed
        ):
            raise ValueError("ATIF identity must exist exactly when its projection passed")
        if (self.report_projection_digest is not None) != (
            EndToEndRequirement.REPORT_PROJECTION in passed
        ):
            raise ValueError("report identity must exist exactly when its projection passed")
        if EndToEndRequirement.CANDIDATE_CHANGE in passed and len(self.candidate_ids) < 2:
            raise ValueError("candidate-change evidence requires parent and child candidates")
        if EndToEndRequirement.CHECKPOINT in passed and not self.checkpoint_ids:
            raise ValueError("passing checkpoint evidence requires a checkpoint identity")
        if EndToEndRequirement.ARTIFACT_COMMIT in passed and not {
            ArtifactClass.CANDIDATE,
            ArtifactClass.CHECKPOINT,
            ArtifactClass.EVIDENCE,
        }.issubset({item.artifact_class for item in self.artifact_counts}):
            raise ValueError("passing artifact evidence requires every retained state class")
        training_requirements = {
            EndToEndRequirement.CANDIDATE_CHANGE,
            EndToEndRequirement.CONTROLLED_FEEDBACK,
            EndToEndRequirement.CHECKPOINT,
            EndToEndRequirement.PARTICIPANT_RECOVERY,
        }
        if not self.is_training and not training_requirements.issubset(unavailable):
            raise ValueError("fresh smoke trials cannot claim stateful training evidence")
        if (self.recovery is not None) != (
            self.is_training and EndToEndRequirement.PARTICIPANT_RECOVERY in passed
        ):
            raise ValueError("participant recovery evidence must exist exactly when it passed")
        if self.recovery is not None and (
            self.recovery.run_record_digest != self.run_record_digest
            or self.recovery.artifact_closure_receipt_digest
            != self.artifact_closure_receipt_digest
            or self.recovery.post_restore_candidate_id not in self.candidate_ids
            or self.recovery.checkpoint_id not in self.checkpoint_ids
        ):
            raise ValueError("participant recovery evidence differs from its trial")
        if (
            passed
            & {
                EndToEndRequirement.OPEN_SOURCE_EDA,
                EndToEndRequirement.COMMERCIAL_EDA,
                EndToEndRequirement.EDA_INPUT_ISOLATION,
            }
            and not self.eda_tool_ids
        ):
            raise ValueError("passing EDA evidence requires a settled tool identity")
        expected = (
            ReleaseEvidenceStatus.FAILED
            if failed
            else ReleaseEvidenceStatus.UNAVAILABLE
            if unavailable
            else ReleaseEvidenceStatus.PASSED
        )
        if self.status is not expected:
            raise ValueError("end-to-end trial status must derive from requirement evidence")
        return self


class EndToEndSmokeEvidence(StrictModel):
    """Aggregate proof over the complete frozen smoke campaign."""

    trials: Annotated[tuple[EndToEndTrialEvidence, ...], Field(min_length=1)]
    training_run_id: Digest | None = None
    eda_tool_ids: tuple[Identifier, ...]
    failed_requirements: tuple[EndToEndRequirement, ...]
    unavailable_requirements: tuple[EndToEndRequirement, ...]
    status: ReleaseEvidenceStatus

    @field_validator("trials")
    @classmethod
    def normalize_trials(
        cls,
        value: tuple[EndToEndTrialEvidence, ...],
    ) -> tuple[EndToEndTrialEvidence, ...]:
        trial_ids = [item.trial_id for item in value]
        run_ids = [item.run_id for item in value]
        record_digests = [item.run_record_digest for item in value]
        result_digests = [item.campaign_trial_result_digest for item in value]
        if any(
            len(items) != len(set(items))
            for items in (trial_ids, run_ids, record_digests, result_digests)
        ):
            raise ValueError("end-to-end smoke trials require unique immutable identities")
        return tuple(sorted(value, key=lambda item: item.trial_id))

    @field_validator("eda_tool_ids")
    @classmethod
    def normalize_tools(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("end-to-end smoke tool identities must be unique")
        return tuple(sorted(value))

    @field_validator("failed_requirements", "unavailable_requirements")
    @classmethod
    def normalize_requirements(
        cls,
        value: tuple[EndToEndRequirement, ...],
    ) -> tuple[EndToEndRequirement, ...]:
        if len(value) != len(set(value)):
            raise ValueError("end-to-end smoke requirements must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        training, tools, failed, unavailable, status = _aggregate_trial_evidence(self.trials)
        if (
            self.training_run_id != training
            or self.eda_tool_ids != tools
            or self.failed_requirements != failed
            or self.unavailable_requirements != unavailable
            or self.status is not status
        ):
            raise ValueError("end-to-end smoke summary must derive from its trial evidence")
        if sum(item.is_training for item in self.trials) != 1:
            raise ValueError("end-to-end smoke requires exactly one stateful training trial")
        return self


def project_end_to_end_smoke(
    *,
    campaign_record: CampaignRecord,
    campaign_report: CampaignReport,
    trial_results: tuple[CampaignTrialResult, ...],
    run_records: tuple[RunRecord, ...],
    task_specs: tuple[TaskSpec, ...],
    task_instances: tuple[TaskInstance, ...],
    releases: tuple[ReleaseManifest, ...],
    environments: tuple[EnvironmentSpec, ...],
    sessions: tuple[SessionSpec, ...],
    backend_qualification_sources: tuple[VerifiedBackendQualificationSource, ...],
    artifact_stores: Mapping[Digest, ContentAddressedStore],
) -> EndToEndSmokeEvidence:
    """Replay and bind every frozen smoke trial into one release attestation."""

    if (
        campaign_record.header.campaign.scope is not CampaignScope.END_TO_END_SMOKE
        or campaign_report.campaign_scope is not CampaignScope.END_TO_END_SMOKE
    ):
        raise ValueError("end-to-end evidence requires a frozen smoke campaign")
    scheduled = {trial.trial_id for trial in campaign_record.header.schedule.trials}
    if (
        {report.trial.trial_id for report in campaign_report.trials} != scheduled
        or len(campaign_report.trials) != len(scheduled)
        or len(run_records) != len(scheduled)
        or len(trial_results) != len(scheduled)
    ):
        raise ValueError("end-to-end evidence must cover every frozen trial")
    runs = {item.header.run_id: item for item in run_records}
    results = {item.run_id: item for item in trial_results}
    tasks = {item.digest: item for item in task_specs}
    instances = {item.digest: item for item in task_instances}
    release_map = {item.digest: item for item in releases}
    environment_map = {item.digest: item for item in environments}
    session_map = {item.digest: item for item in sessions}
    if (
        len(runs) != len(run_records)
        or len(results) != len(trial_results)
        or len(tasks) != len(task_specs)
        or len(instances) != len(task_instances)
        or len(release_map) != len(releases)
        or len(environment_map) != len(environments)
        or len(session_map) != len(sessions)
    ):
        raise ValueError("end-to-end sources require unique content identities")
    if set(artifact_stores) != set(runs):
        raise ValueError("end-to-end smoke requires one live artifact store per run")

    projected: list[EndToEndTrialEvidence] = []
    used_tasks: set[str] = set()
    used_instances: set[str] = set()
    used_releases: set[str] = set()
    used_environments: set[str] = set()
    used_sessions: set[str] = set()
    for report in campaign_report.trials:
        run_id = report.outcome.run_id
        if run_id is None:
            raise ValueError("every end-to-end smoke trial must have a completed run")
        run = runs.get(run_id)
        result = results.get(run_id)
        if run is None or result is None:
            raise ValueError("end-to-end smoke trial is missing its run or terminal receipt")
        binding = run.header.binding
        task = tasks.get(binding.task.task_spec_digest)
        instance = instances.get(binding.task.instance_digest)
        release = release_map.get(binding.task.release_digest)
        environment = environment_map.get(binding.environment.environment_spec_digest)
        session = session_map.get(binding.session.session_spec_digest)
        if any(item is None for item in (task, instance, release, environment, session)):
            raise ValueError("end-to-end smoke trial is missing a bound specification")
        assert task is not None
        assert instance is not None
        assert release is not None
        assert environment is not None
        assert session is not None
        used_tasks.add(task.digest)
        used_instances.add(instance.digest)
        used_releases.add(release.digest)
        used_environments.add(environment.digest)
        used_sessions.add(session.digest)
        projected.append(
            _project_end_to_end_trial(
                campaign_record=campaign_record,
                campaign_report=campaign_report,
                trial_result=result,
                run_record=run,
                task=task,
                instance=instance,
                release=release,
                environment=environment,
                session=session,
                backend_qualification_sources=backend_qualification_sources,
                artifact_store=artifact_stores[run_id],
            )
        )
    if set(runs) != {item.run_id for item in projected} or set(results) != set(runs):
        raise ValueError("end-to-end smoke sources contain an unreferenced trial")
    if (
        used_tasks != set(tasks)
        or used_instances != set(instances)
        or used_releases != set(release_map)
        or used_environments != set(environment_map)
        or used_sessions != set(session_map)
    ):
        raise ValueError("end-to-end specification source is unreferenced")

    training_run_id, tools, failed, unavailable, status = _aggregate_trial_evidence(
        tuple(projected)
    )
    return EndToEndSmokeEvidence(
        trials=tuple(projected),
        training_run_id=training_run_id,
        eda_tool_ids=tools,
        failed_requirements=failed,
        unavailable_requirements=unavailable,
        status=status,
    )


def _project_end_to_end_trial(
    *,
    campaign_record: CampaignRecord,
    campaign_report: CampaignReport,
    trial_result: CampaignTrialResult,
    run_record: RunRecord,
    task: TaskSpec,
    instance: TaskInstance,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
    backend_qualification_sources: tuple[VerifiedBackendQualificationSource, ...],
    artifact_store: ContentAddressedStore,
) -> EndToEndTrialEvidence:
    """Replay one exact smoke trial; absent runtime proofs stay unavailable."""

    trial_report = _validate_trial_sources(
        campaign_record,
        campaign_report,
        trial_result,
        run_record,
    )
    binding = run_record.header.binding
    try:
        expected = resolve_run(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=trial_report.trial.trial_id,
            campaign=binding.campaign,
            lineage=binding.lineage,
        )
    except (ResolutionError, ValueError) as error:
        raise ValueError("end-to-end specifications do not resolve") from error
    if expected.binding != binding:
        raise ValueError("end-to-end specifications differ from the run binding")
    try:
        state = replay(run_record.header, task, run_record.events)
    except (JournalError, ValueError) as error:
        raise ValueError("end-to-end RunRecord semantic replay failed") from error
    if (
        tuple(state.provider_requests) != trial_report.outcome.provider_requests
        or state.stage_results != trial_report.outcome.stage_results
        or state.terminal_reason != trial_report.outcome.terminal_reason
    ):
        raise ValueError("end-to-end campaign outcome differs from replayed run facts")
    try:
        artifact_closure = verify_run_artifact_closure(run_record, task, artifact_store)
    except ArtifactClosureError as error:
        raise ValueError("end-to-end run artifact closure is invalid") from error
    if artifact_closure.artifact_policy_digest != artifact_policy_digest(
        environment.artifact_policy
    ):
        raise ValueError("end-to-end artifact store uses a different environment policy")

    harnesses = tuple(
        actor
        for actor in binding.session.actors
        if isinstance(actor, HarnessRunActor)
        and actor.harness_digest == trial_report.trial.binding.harness.digest
        and actor.scaffold_digest == trial_report.trial.binding.harness.scaffold_digest
        and actor.requested_model_route == trial_report.trial.binding.requested_model
    )
    if len(harnesses) != 1:
        raise ValueError("end-to-end run does not contain its scheduled provider harness")
    participant_actor_id = harnesses[0].actor_id

    failed: set[EndToEndRequirement] = set()
    training = isinstance(session.mode, TrainingMode)
    unavailable: set[EndToEndRequirement] = {
        EndToEndRequirement.ARTIFACT_COMMIT,
        EndToEndRequirement.HIDDEN_VERIFIER,
    }
    if not training:
        unavailable.update(
            {
                EndToEndRequirement.CANDIDATE_CHANGE,
                EndToEndRequirement.CONTROLLED_FEEDBACK,
                EndToEndRequirement.CHECKPOINT,
                EndToEndRequirement.PARTICIPANT_RECOVERY,
            }
        )

    events = run_record.events
    candidates = tuple(event for event in events if isinstance(event, CandidateSubmittedEvent))
    candidates_by_id = {item.payload.candidate_id: item for item in candidates}
    successful = (
        None
        if state.successful_candidate_id is None
        else candidates_by_id.get(state.successful_candidate_id)
    )
    parent = (
        None
        if successful is None or successful.payload.parent_candidate_id is None
        else candidates_by_id.get(successful.payload.parent_candidate_id)
    )
    writes = tuple(
        event
        for event in events
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_REQUEST
        and event.payload.tool_name == WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME
    )
    completed_writes = tuple(
        (request, result)
        for request in writes
        for result in events
        if isinstance(result, InteractionRecordedEvent)
        and result.payload.direction is InteractionDirection.TOOL_RESULT
        and result.payload.related_interaction_id == request.payload.interaction_id
        and result.payload.tool_name == request.payload.tool_name
    )
    candidate_changed = (
        successful is not None
        and parent is not None
        and successful.payload.candidate_digest != parent.payload.candidate_digest
        and any(
            parent.sequence < request.sequence < result.sequence < successful.sequence
            for request, result in completed_writes
        )
    )
    if training and not candidate_changed:
        failed.add(EndToEndRequirement.CANDIDATE_CHANGE)

    feedback = tuple(
        event
        for event in events
        if isinstance(event, EvaluationCompletedEvent)
        and parent is not None
        and event.payload.candidate_id == parent.payload.candidate_id
        and event.visibility in {Visibility.PUBLIC, Visibility.PARTICIPANT}
        and event.payload.result.outcome.kind
        in {OutcomeKind.CANDIDATE_FAILURE, OutcomeKind.COUNTEREXAMPLE}
    )
    provider_requests = tuple(
        event
        for event in events
        if isinstance(event, ProviderRequestStartedEvent)
        and event.payload.actor_id == participant_actor_id
    )
    completed_provider_exchanges = tuple(
        (request, response)
        for request in provider_requests
        for response in events
        if isinstance(response, ProviderResponseRecordedEvent)
        and response.payload.request_id == request.payload.request_id
        and response.payload.status is ProviderResponseStatus.COMPLETED
        and response.payload.usage is not None
        and response.payload.usage.total_tokens > 0
    )
    completed_feedback_exchanges = tuple(
        (request, response)
        for request, response in completed_provider_exchanges
        if any(
            observation.sequence < request.sequence
            and (successful is None or request.sequence < successful.sequence)
            for observation in feedback
        )
    )
    if training and not (
        session.feedback is not FeedbackPolicy.NONE
        and session.recovery is RecoveryPolicy.REQUIRED
        and completed_feedback_exchanges
        and any(
            request.sequence < response.sequence < write.sequence < result.sequence
            and (successful is None or result.sequence < successful.sequence)
            for request, response in completed_feedback_exchanges
            for write, result in completed_writes
        )
    ):
        failed.add(EndToEndRequirement.CONTROLLED_FEEDBACK)

    dispatches = participant_tool_dispatches(events)
    settled_bindings = tuple(
        (
            dispatch.reservation.payload.capability,
            dispatch.reservation.payload.tool_id,
        )
        for dispatch in dispatches.values()
        if isinstance(dispatch.terminal, ParticipantToolSettledEvent)
    )
    settled_tools = tuple(tool_id for _, tool_id in settled_bindings)
    selected_operations = tuple(
        operation
        for capability, tool_id in settled_bindings
        for operation in environment.participant_operations
        if operation.capability is capability and operation.tool_id == tool_id
    )
    isolated_operation = not (
        not selected_operations
        or len(selected_operations) != len(settled_bindings)
        or isinstance(environment.executor, BrokeredHostToolExecutor)
        or not state.provider_requests
        or any(request.security_binding is None for request in state.provider_requests)
    )
    if not isolated_operation:
        failed.add(EndToEndRequirement.EDA_INPUT_ISOLATION)
    else:
        unavailable.add(EndToEndRequirement.EDA_INPUT_ISOLATION)
    conformant = {
        (
            item.qualification.probe.tool_id,
            item.qualification.requested_capabilities[0],
        ): item.qualification.probe.vendor
        for item in backend_qualification_sources
        if item.qualification.disposition is QualificationDisposition.CONFORMANT
    }
    if not any(
        conformant.get((tool, capability)) is Vendor.OPEN_SOURCE
        for capability, tool in settled_bindings
    ):
        failed.add(EndToEndRequirement.OPEN_SOURCE_EDA)
    else:
        unavailable.add(EndToEndRequirement.OPEN_SOURCE_EDA)
    if not any(
        (tool, capability) in conformant
        and conformant[(tool, capability)] is not Vendor.OPEN_SOURCE
        for capability, tool in settled_bindings
    ):
        failed.add(EndToEndRequirement.COMMERCIAL_EDA)
    else:
        unavailable.add(EndToEndRequirement.COMMERCIAL_EDA)

    checkpoints = tuple(event for event in events if isinstance(event, CheckpointCommittedEvent))
    checkpoint_requests = tuple(
        event
        for event in events
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_REQUEST
        and event.payload.tool_name == CHECKPOINT_PARTICIPANT_TOOL_NAME
    )
    checkpoint_results = tuple(
        (request, result)
        for request in checkpoint_requests
        for result in events
        if isinstance(result, InteractionRecordedEvent)
        and result.payload.direction is InteractionDirection.TOOL_RESULT
        and result.payload.related_interaction_id == request.payload.interaction_id
        and result.payload.tool_name == request.payload.tool_name
    )
    checkpoint_recorded = any(
        request.sequence < checkpoint.sequence < result.sequence
        and (successful is None or result.sequence < successful.sequence)
        for request, result in checkpoint_results
        for checkpoint in checkpoints
    )
    if training and not checkpoint_recorded:
        failed.add(EndToEndRequirement.CHECKPOINT)

    lifecycle = participant_incarnation_lifecycle(events)
    recovery_evidence: ParticipantRecoveryEvidence | None = None
    if training:
        lifecycle_digest = canonical_digest(
            lifecycle,
            domain="release-participant-recovery-projection-v1",
        )
        for recovery in lifecycle.recoveries:
            checkpoint_pair = next(
                (
                    (checkpoint, request, result)
                    for request, result in checkpoint_results
                    for checkpoint in checkpoints
                    if request.sequence
                    < checkpoint.sequence
                    < result.sequence
                    < recovery.terminated_sequence
                    < recovery.restored_sequence
                    and checkpoint.payload.checkpoint_id
                    == recovery.termination.checkpoint_id
                    and checkpoint.payload.manifest_digest
                    == recovery.termination.checkpoint_manifest_digest
                ),
                None,
            )
            provider_exchange = next(
                (
                    (request, response)
                    for request, response in completed_provider_exchanges
                    if recovery.restored_sequence < request.sequence < response.sequence
                ),
                None,
            )
            post_restore_write = next(
                (
                    (write, result)
                    for write, result in completed_writes
                    if recovery.restored_sequence < write.sequence < result.sequence
                ),
                None,
            )
            post_restore_dispatch = next(
                (
                    dispatch
                    for dispatch in dispatches.values()
                    if isinstance(dispatch.terminal, ParticipantToolSettledEvent)
                    and recovery.restored_sequence < dispatch.terminal.sequence
                ),
                None,
            )
            successful_evaluation = next(
                (
                    event
                    for event in events
                    if isinstance(event, EvaluationCompletedEvent)
                    and successful is not None
                    and event.payload.candidate_id == successful.payload.candidate_id
                    and recovery.restored_sequence < successful.sequence < event.sequence
                ),
                None,
            )
            if (
                checkpoint_pair is None
                or provider_exchange is None
                or post_restore_write is None
                or post_restore_dispatch is None
                or successful is None
                or successful_evaluation is None
            ):
                continue
            checkpoint = checkpoint_pair[0]
            recovery_evidence = ParticipantRecoveryEvidence(
                run_record_digest=run_record.integrity_digest,
                artifact_closure_receipt_digest=artifact_closure.digest,
                lifecycle_digest=lifecycle_digest,
                checkpoint_id=checkpoint.payload.checkpoint_id,
                checkpoint_manifest_digest=checkpoint.payload.manifest_digest,
                terminated_sequence=recovery.terminated_sequence,
                restored_sequence=recovery.restored_sequence,
                restored_incarnation_digest=recovery.restored_incarnation_digest,
                restored_manifest_digest=recovery.restored_manifest_digest,
                post_restore_provider_request_id=provider_exchange[0].payload.request_id,
                post_restore_tool_invocation_id=(
                    post_restore_dispatch.reservation.payload.invocation_id
                ),
                post_restore_candidate_id=successful.payload.candidate_id,
            )
            break
        if (
            recovery_evidence is None
            or lifecycle.active_incarnation is None
            or lifecycle.pending_termination is not None
        ):
            failed.add(EndToEndRequirement.PARTICIPANT_RECOVERY)
            recovery_evidence = None

    results = tuple(
        item.result
        for item in state.stage_results
        if item.candidate_id == state.successful_candidate_id
    )
    if not (
        successful is not None
        and state.terminal_reason is StopReason.VERIFIER_SUCCESS
        and hard_gate_status(task, results).state is HardGateState.SUCCEEDED
        and _hidden_verifier_sources_are_disjoint(task, release, environment)
    ):
        failed.add(EndToEndRequirement.HIDDEN_VERIFIER)
        unavailable.discard(EndToEndRequirement.HIDDEN_VERIFIER)

    artifact_classes = {item.artifact_class for item in artifact_closure.artifacts}
    if not {
        ArtifactClass.CANDIDATE,
        ArtifactClass.CHECKPOINT,
        ArtifactClass.EVIDENCE,
    }.issubset(artifact_classes):
        failed.add(EndToEndRequirement.ARTIFACT_COMMIT)
        unavailable.discard(EndToEndRequirement.ARTIFACT_COMMIT)
    else:
        unavailable.discard(EndToEndRequirement.ARTIFACT_COMMIT)

    atif_digest = _projection_digest(
        lambda: project_atif_record(run_record, task),
        domain="release-atif-projection-v1",
        requirement=EndToEndRequirement.ATIF_PROJECTION,
        failed=failed,
    )
    report_digest = _projection_digest(
        lambda: project_harbor_record(run_record, task),
        domain="release-harbor-projection-v1",
        requirement=EndToEndRequirement.REPORT_PROJECTION,
        failed=failed,
    )
    status = (
        ReleaseEvidenceStatus.FAILED
        if failed
        else ReleaseEvidenceStatus.UNAVAILABLE
        if unavailable
        else ReleaseEvidenceStatus.PASSED
    )
    return EndToEndTrialEvidence(
        trial_id=trial_report.trial.trial_id,
        run_id=run_record.header.run_id,
        run_record_digest=run_record.integrity_digest,
        campaign_trial_result_digest=trial_result.digest,
        task_family=trial_report.trial.binding.task_family,
        task_role=trial_report.trial.binding.task_role,
        device_capability=trial_report.trial.binding.device_capability,
        task_spec_digest=task.digest,
        task_instance_digest=instance.digest,
        release_digest=release.digest,
        session_spec_digest=session.digest,
        environment_spec_digest=environment.digest,
        participant_actor_id=participant_actor_id,
        is_training=training,
        artifact_closure_receipt_digest=artifact_closure.digest,
        recovery=recovery_evidence,
        candidate_ids=tuple(item.payload.candidate_id for item in candidates),
        eda_tool_ids=settled_tools,
        checkpoint_ids=tuple(item.payload.checkpoint_id for item in checkpoints),
        artifact_counts=tuple(
            ArtifactClassCount(
                artifact_class=artifact_class,
                count=sum(
                    item.artifact_class is artifact_class
                    for item in artifact_closure.artifacts
                ),
            )
            for artifact_class in sorted(artifact_classes, key=lambda item: item.value)
        ),
        atif_projection_digest=atif_digest,
        report_projection_digest=report_digest,
        failed_requirements=tuple(failed),
        unavailable_requirements=tuple(unavailable),
        status=status,
    )


def _validate_trial_sources(
    campaign_record: CampaignRecord,
    campaign_report: CampaignReport,
    trial_result: CampaignTrialResult,
    run_record: RunRecord,
) -> TrialReport:
    binding = run_record.header.binding
    campaign_binding = binding.campaign
    matches = tuple(
        item for item in campaign_report.trials if item.outcome.run_id == run_record.header.run_id
    )
    matching_commits = tuple(
        commit
        for commit in campaign_record.commits
        if commit.record_digest == trial_result.campaign_record_digest
    )
    if (
        campaign_record.header.campaign.scope is not CampaignScope.END_TO_END_SMOKE
        or campaign_binding is None
        or campaign_binding.campaign_digest != campaign_record.header.campaign.digest
        or campaign_binding.schedule_digest != campaign_record.header.schedule.digest
        or len(matches) != 1
        or matches[0].outcome.disposition is not TrialDisposition.COMPLETED_RUN
        or matches[0].outcome.run_binding != binding
        or matches[0].trial.trial_id != binding.trial_key
        or trial_result.trial_id != matches[0].trial.trial_id
        or trial_result.run_id != run_record.header.run_id
        or trial_result.run_record_digest != run_record.integrity_digest
        or trial_result.outcome != matches[0].outcome
        or len(matching_commits) != 1
    ):
        raise ValueError("end-to-end trial receipt differs from its immutable journals")
    commit = matching_commits[0]
    if (
        len(commit.events) != 2
        or not isinstance(commit.events[0], WorkSettledEvent)
        or not isinstance(commit.events[1], TrialOutcomeRecordedEvent)
        or commit.events[0].payload.actual != trial_result.resources
        or commit.events[1].payload.trial_id != trial_result.trial_id
        or commit.events[1].payload.outcome != trial_result.outcome
    ):
        raise ValueError("end-to-end trial receipt does not name its atomic terminal commit")
    provider = CampaignResources(
        requests=sum(item.charged_resources.requests for item in matches[0].provider_attempts),
        input_tokens=sum(
            item.charged_resources.input_tokens for item in matches[0].provider_attempts
        ),
        output_tokens=sum(
            item.charged_resources.output_tokens for item in matches[0].provider_attempts
        ),
    )
    expected_resources = CampaignResources.model_validate(
        {
            name: getattr(trial_result.resources, name) + getattr(provider, name)
            for name in CampaignResources.model_fields
        }
    )
    if matches[0].resources != expected_resources:
        raise ValueError("end-to-end trial resources differ from its run and provider journals")
    return matches[0]


def _aggregate_trial_evidence(
    trials: tuple[EndToEndTrialEvidence, ...],
) -> tuple[
    Digest | None,
    tuple[Identifier, ...],
    tuple[EndToEndRequirement, ...],
    tuple[EndToEndRequirement, ...],
    ReleaseEvidenceStatus,
]:
    failed: set[EndToEndRequirement] = set()
    unavailable: set[EndToEndRequirement] = set()
    training_requirements = {
        EndToEndRequirement.CANDIDATE_CHANGE,
        EndToEndRequirement.CONTROLLED_FEEDBACK,
        EndToEndRequirement.CHECKPOINT,
    }
    stateful = tuple(item for item in trials if item.is_training)
    training = stateful[0] if len(stateful) == 1 else None
    any_trial_requirements = {
        EndToEndRequirement.OPEN_SOURCE_EDA,
        EndToEndRequirement.COMMERCIAL_EDA,
    }
    for requirement in EndToEndRequirement:
        if requirement is EndToEndRequirement.TASK_BREADTH:
            if training is None or not _has_smoke_task_breadth(trials):
                failed.add(requirement)
            continue
        if (
            requirement in training_requirements
            or requirement is EndToEndRequirement.PARTICIPANT_RECOVERY
        ):
            if training is None:
                failed.add(requirement)
            else:
                _merge_requirement(training, requirement, failed, unavailable)
            continue
        statuses = tuple(_requirement_status(item, requirement) for item in trials)
        if requirement in any_trial_requirements:
            if ReleaseEvidenceStatus.PASSED in statuses:
                continue
            if ReleaseEvidenceStatus.UNAVAILABLE in statuses:
                unavailable.add(requirement)
            else:
                failed.add(requirement)
        elif ReleaseEvidenceStatus.FAILED in statuses:
            failed.add(requirement)
        elif ReleaseEvidenceStatus.UNAVAILABLE in statuses:
            unavailable.add(requirement)
    status = (
        ReleaseEvidenceStatus.FAILED
        if failed
        else ReleaseEvidenceStatus.UNAVAILABLE
        if unavailable
        else ReleaseEvidenceStatus.PASSED
    )
    return (
        None if training is None else training.run_id,
        tuple(sorted({tool for item in trials for tool in item.eda_tool_ids})),
        tuple(sorted(failed, key=lambda item: item.value)),
        tuple(sorted(unavailable, key=lambda item: item.value)),
        status,
    )


def _requirement_status(
    evidence: EndToEndTrialEvidence,
    requirement: EndToEndRequirement,
) -> ReleaseEvidenceStatus:
    if requirement in evidence.failed_requirements:
        return ReleaseEvidenceStatus.FAILED
    if requirement in evidence.unavailable_requirements:
        return ReleaseEvidenceStatus.UNAVAILABLE
    return ReleaseEvidenceStatus.PASSED


def _merge_requirement(
    evidence: EndToEndTrialEvidence,
    requirement: EndToEndRequirement,
    failed: set[EndToEndRequirement],
    unavailable: set[EndToEndRequirement],
) -> None:
    status = _requirement_status(evidence, requirement)
    if status is ReleaseEvidenceStatus.FAILED:
        failed.add(requirement)
    elif status is ReleaseEvidenceStatus.UNAVAILABLE:
        unavailable.add(requirement)


def _has_smoke_task_breadth(trials: tuple[EndToEndTrialEvidence, ...]) -> bool:
    tasks = trials
    rtl = any(
        item.task_family in _SAIL_FAMILIES
        and item.task_role is CampaignTaskRole.RTL_GENERATION
        and campaign_role_allows_capability(item.task_role, item.device_capability)
        for item in tasks
    )
    synthesis_timing = any(
        item.task_family in _SYNTHESIS_TIMING_FAMILIES
        and item.task_role in {CampaignTaskRole.SYNTHESIS_QOR, CampaignTaskRole.STA_CLOSURE}
        and campaign_role_allows_capability(item.task_role, item.device_capability)
        for item in tasks
    )
    long_flow = any(
        item.task_family in _LONG_FLOW_FAMILIES
        and item.task_role
        in {CampaignTaskRole.PHYSICAL_ANALOG, CampaignTaskRole.FPGA_IMPLEMENTATION}
        and campaign_role_allows_capability(item.task_role, item.device_capability)
        for item in tasks
    )
    return rtl and synthesis_timing and long_flow


def _hidden_verifier_sources_are_disjoint(
    task: TaskSpec,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
) -> bool:
    visibility = {item.resource_id: item.visibility for item in task.visibility}
    evaluator_resources = {item.implementation_resource for item in task.evaluation.evaluators}
    if task.evaluation.scorer is not None:
        evaluator_resources.add(task.evaluation.scorer.implementation_resource)
    qualification = task.qualification
    if isinstance(qualification, QualificationSpec):
        hidden_resources = {
            qualification.sail_oracle_resource,
            *qualification.known_answer_resources,
            qualification.reference_candidate_resource,
            *qualification.mutant_resources,
        }
    elif isinstance(qualification, FlowQualificationSpec):
        hidden_resources = {
            qualification.authoring_source_resource,
            qualification.feasibility_witness_resource,
            *qualification.negative_candidate_resources,
        }
    else:
        return False
    hidden_resources.update(evaluator_resources)
    if any(
        visibility.get(resource_id) in {Visibility.PUBLIC, Visibility.PARTICIPANT}
        for resource_id in hidden_resources
    ):
        return False
    participant_sources = {
        source_id
        for item in release.files
        if item.visibility in {Visibility.PUBLIC, Visibility.PARTICIPANT}
        for source_id in item.source_resource_ids
    }
    if hidden_resources & participant_sources:
        return False
    participant_assets = {
        item.asset_id
        for item in environment.filesystem.readonly_assets
        if item.scope is FilesystemScope.PARTICIPANT
    }
    evaluator_assets = {
        item.asset_id
        for item in environment.filesystem.readonly_assets
        if item.scope in {FilesystemScope.EVALUATOR, FilesystemScope.TOOL}
    }
    return not participant_assets & evaluator_assets


def _projection_digest(
    project: Callable[[], StrictModel],
    *,
    domain: str,
    requirement: EndToEndRequirement,
    failed: set[EndToEndRequirement],
) -> Digest | None:
    try:
        return canonical_digest(project(), domain=domain)
    except (JournalError, ProjectionUnavailable, ValueError):
        failed.add(requirement)
        return None
