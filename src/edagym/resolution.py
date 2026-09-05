"""Fail-closed composition of task, environment, session, and release truth."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Self

from pydantic import field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.run.model import (
    CampaignTrialRunBinding,
    EnvironmentRunBinding,
    EvaluatorRunBinding,
    HarnessRunActor,
    HumanRunActor,
    ResolvedAssetBinding,
    ResolvedParticipantOperationBinding,
    ResolvedToolBinding,
    RunActor,
    RunBinding,
    RunLineage,
    RunPurpose,
    SessionRunBinding,
    TaskRunBinding,
)
from edagym.specs.common import (
    Capability,
    Digest,
    Identifier,
    Redistribution,
    Sensitivity,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import (
    CheckpointCapability,
    EnvironmentSpec,
    executor_is_participant_isolation,
)
from edagym.specs.release import (
    BooleanParameterValue,
    ChoiceParameterValue,
    FlowReleaseCandidateQualification,
    FlowReleaseQualification,
    IntegerParameterValue,
    ReleaseManifest,
    ReleaseQualification,
    TaskInstance,
)
from edagym.specs.session import (
    CandidateAuthority,
    FixedWriter,
    HarnessActor,
    HumanActor,
    RecoveryPolicy,
    SessionSpec,
)
from edagym.specs.task import (
    BooleanDomain,
    ChoiceDomain,
    FlowQualificationSpec,
    IntegerDomain,
    QualificationSpec,
    TaskSpec,
)


class ResolutionError(ValueError):
    """The canonical inputs cannot form one executable run."""


class StageDriverAssignment(StrictModel):
    stage_id: Identifier
    evaluator_id: Identifier
    capability: Capability
    tool_id: Identifier
    driver_id: Identifier
    driver_digest: Digest


class ResolvedRunPlan(StrictModel):
    """A derived execution view; its binding remains the persistent identity owner."""

    binding: RunBinding
    stage_drivers: tuple[StageDriverAssignment, ...]

    @field_validator("stage_drivers")
    @classmethod
    def normalize_assignments(
        cls, value: tuple[StageDriverAssignment, ...]
    ) -> tuple[StageDriverAssignment, ...]:
        return tuple(sorted(value, key=lambda item: item.stage_id))

    @model_validator(mode="after")
    def validate_assignments(self) -> Self:
        stage_ids = [item.stage_id for item in self.stage_drivers]
        if not stage_ids or len(stage_ids) != len(set(stage_ids)):
            raise ValueError("resolved stages must be unique and non-empty")
        return self


def resolve_run(
    *,
    task: TaskSpec,
    instance: TaskInstance,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
    session: SessionSpec,
    trial_key: str,
    campaign: CampaignTrialRunBinding | None = None,
    purpose: RunPurpose | None = None,
    lineage: RunLineage | None = None,
) -> ResolvedRunPlan:
    """Resolve all logical capabilities and reject any cross-spec inconsistency."""

    _validate_instance(task, instance)
    _validate_release(task, instance, release, environment)
    _validate_session_environment(session, environment)
    _validate_candidate_execution(task, environment, session, campaign)
    _validate_participant_operations(release, environment)

    tools_by_capability = {binding.capability: binding for binding in environment.tool_bindings}
    evaluators = {item.evaluator_id: item for item in task.evaluation.evaluators}
    required_capabilities = {
        capability
        for evaluator in evaluators.values()
        for capability in (evaluator.capability, *evaluator.supporting_capabilities)
    }
    required_capabilities.update(
        operation.capability for operation in environment.participant_operations
    )
    missing = required_capabilities - tools_by_capability.keys()
    if missing:
        names = ", ".join(sorted(item.value for item in missing))
        raise ResolutionError(f"environment does not resolve required capabilities: {names}")

    assignments: list[StageDriverAssignment] = []
    for stage in task.evaluation.stages:
        evaluator = evaluators[stage.evaluator_id]
        tool = tools_by_capability[evaluator.capability]
        assignments.append(
            StageDriverAssignment(
                stage_id=stage.stage_id,
                evaluator_id=evaluator.evaluator_id,
                capability=evaluator.capability,
                tool_id=tool.tool_id,
                driver_id=tool.driver_id,
                driver_digest=tool.driver_digest,
            )
        )

    run_actors: list[RunActor] = []
    for actor in session.actors:
        if isinstance(actor, HumanActor):
            run_actors.append(
                HumanRunActor(
                    actor_id=actor.actor_id,
                    adapter_digest=actor.adapter_digest,
                )
            )
        elif isinstance(actor, HarnessActor):
            run_actors.append(
                HarnessRunActor(
                    actor_id=actor.actor_id,
                    harness_digest=actor.harness_digest,
                    scaffold_digest=actor.scaffold_digest,
                    requested_model_route=actor.requested_model_route,
                )
            )

    initial_writer = (
        session.writer.writer
        if isinstance(session.writer, FixedWriter)
        else session.writer.initial_writer
    )
    session_binding = SessionRunBinding(
        session_spec_digest=session.digest,
        actors=tuple(run_actors),
        initial_writer=initial_writer,
        handoff_enabled=not isinstance(session.writer, FixedWriter),
        feedback_policy_digest=canonical_digest(
            session.feedback,
            domain="feedback-policy-v1",
        ),
        budget_digest=canonical_digest(
            {"resources": session.resources, "model": session.model_budget},
            domain="session-budget-v1",
        ),
    )

    resolved_tools = tuple(
        ResolvedToolBinding(
            capability=tool.capability,
            tool_id=tool.tool_id,
            tool_version=tool.tool_version,
            driver_digest=tool.driver_digest,
            deployment_attestation_digest=tool.locator.deployment_attestation_digest,
        )
        for tool in environment.tool_bindings
        if tool.capability in required_capabilities
    )
    resolved_assets = tuple(
        ResolvedAssetBinding(
            asset_id=asset.asset_id,
            restricted_digest=asset.restricted_digest,
        )
        for asset in environment.assets
    )
    resolved_operations = tuple(
        ResolvedParticipantOperationBinding(
            operation_id=operation.operation_id,
            operation_digest=operation.digest,
            capability=operation.capability,
            tool_id=operation.tool_id,
        )
        for operation in environment.participant_operations
    )
    policy_digest = canonical_digest(
        {
            "filesystem": environment.filesystem,
            "network": environment.network,
            "resources": environment.resources,
            "licenses": environment.licenses,
            "participant_operations": environment.participant_operations,
            "checkpoint": environment.checkpoint,
            "artifact_policy": environment.artifact_policy,
        },
        domain="resolved-environment-policy-v1",
    )
    resolved_purpose = (
        RunPurpose.STANDARD
        if campaign is None
        else RunPurpose.CAMPAIGN_TRIAL
        if purpose is None
        else purpose
    )
    if purpose is not None and campaign is None and purpose is not RunPurpose.STANDARD:
        raise ResolutionError("campaign execution purposes require a campaign binding")
    binding = RunBinding(
        purpose=resolved_purpose,
        task=TaskRunBinding(
            family=task.identity.family,
            authoring_revision=task.identity.authoring_revision,
            task_spec_digest=task.digest,
            instance_seed=instance.identity.seed,
            instance_digest=instance.digest,
            release_digest=release.digest,
        ),
        environment=EnvironmentRunBinding(
            environment_spec_digest=environment.digest,
            executor_id=environment.executor.executor_id,
            executor_digest=environment.executor.implementation_digest,
            policy_digest=policy_digest,
            tools=resolved_tools,
            participant_operations=resolved_operations,
            assets=resolved_assets,
        ),
        session=session_binding,
        evaluators=tuple(
            EvaluatorRunBinding(
                evaluator_id=evaluator.evaluator_id,
                revision_digest=evaluator.revision_digest,
            )
            for evaluator in task.evaluation.evaluators
        ),
        measurement_schema_digest=canonical_digest(
            task.measurements,
            domain="measurement-schema-v1",
        ),
        scorer_revision_digest=(
            None if task.evaluation.scorer is None else task.evaluation.scorer.revision_digest
        ),
        trial_key=trial_key,
        campaign=campaign,
        lineage=RunLineage() if lineage is None else lineage,
    )
    return ResolvedRunPlan(binding=binding, stage_drivers=tuple(assignments))


def _validate_candidate_execution(
    task: TaskSpec,
    environment: EnvironmentSpec,
    session: SessionSpec,
    campaign: CampaignTrialRunBinding | None,
) -> None:
    if campaign is not None and session.candidate_authority is not CandidateAuthority.PARTICIPANT:
        raise ResolutionError("campaign runs cannot claim task-author candidate authority")
    if session.candidate_authority is CandidateAuthority.PARTICIPANT and not (
        executor_is_participant_isolation(environment.executor)
    ):
        raise ResolutionError(
            "participant candidates require a rootless or virtual-machine executor"
        )


def _validate_participant_operations(
    release: ReleaseManifest,
    environment: EnvironmentSpec,
) -> None:
    visible_files = {
        item.path: item
        for item in release.files
        if item.visibility in {Visibility.PUBLIC, Visibility.PARTICIPANT}
    }
    visible_paths = tuple(PurePosixPath(path) for path in visible_files)
    for operation in environment.participant_operations:
        missing = set(operation.candidate_input_paths) - visible_files.keys()
        if missing:
            raise ResolutionError(
                "participant operation inputs must be participant-visible release files"
            )
        if any(
            output == visible or output in visible.parents or visible in output.parents
            for output in (PurePosixPath(path) for path in operation.output_paths)
            for visible in visible_paths
        ):
            raise ResolutionError("participant operation outputs cannot overwrite release files")


def _validate_instance(task: TaskSpec, instance: TaskInstance) -> None:
    identity = instance.identity
    if (
        identity.task_family != task.identity.family
        or identity.authoring_revision != task.identity.authoring_revision
        or identity.task_spec_digest != task.digest
        or identity.generator_digest != task.generator.implementation_digest
    ):
        raise ResolutionError("task instance identity does not match its TaskSpec")
    if int(identity.seed, 16) >= 2**task.generator.seed_bits:
        raise ResolutionError("task instance seed exceeds the generator seed domain")

    domains = {item.parameter_id: item for item in task.generator.parameters}
    values = {item.parameter_id: item for item in identity.parameters}
    if set(values) != set(domains):
        raise ResolutionError("task instance must bind every generator parameter exactly once")
    for parameter_id, domain in domains.items():
        value = values[parameter_id]
        if isinstance(domain, IntegerDomain):
            if not isinstance(value, IntegerParameterValue):
                raise ResolutionError("integer parameter has a non-integer binding")
            if not domain.minimum <= value.value <= domain.maximum:
                raise ResolutionError("integer parameter lies outside its declared domain")
            if (value.value - domain.minimum) % domain.step:
                raise ResolutionError("integer parameter is not on its declared step")
        elif isinstance(domain, BooleanDomain):
            if not isinstance(value, BooleanParameterValue):
                raise ResolutionError("boolean parameter has a non-boolean binding")
        elif isinstance(domain, ChoiceDomain):
            if not isinstance(value, ChoiceParameterValue) or value.value not in domain.choices:
                raise ResolutionError("choice parameter lies outside its declared domain")


def _validate_release(
    task: TaskSpec,
    instance: TaskInstance,
    release: ReleaseManifest,
    environment: EnvironmentSpec,
) -> None:
    if release.task_spec_digest != task.digest or release.task_instance_digest != instance.digest:
        raise ResolutionError("release does not bind the supplied task and instance")
    if environment.digest not in release.environment_digests:
        raise ResolutionError("release was not qualified for the supplied environment")
    if release.files != instance.generated_files:
        raise ResolutionError("release files diverge from the generated task instance")
    resources = {item.resource_id: item for item in task.resources}
    if isinstance(task.qualification, QualificationSpec):
        if not isinstance(release.qualification, ReleaseQualification):
            raise ResolutionError("Sail tasks require Sail release qualification")
        expected_mutants = set(task.qualification.mutant_resources)
        actual_mutants = {
            result.mutant_resource_id for result in release.qualification.mutant_results
        }
        if actual_mutants != expected_mutants:
            raise ResolutionError("release qualification does not cover every declared mutant")
        if (
            len(release.qualification.simulator_evidence_digests)
            < task.qualification.required_simulators
        ):
            raise ResolutionError("release qualification lacks the required simulator evidence")
        if task.qualification.require_formal and (
            release.qualification.formal_evidence_digest is None
        ):
            raise ResolutionError("release qualification lacks required formal evidence")
    elif isinstance(task.qualification, FlowQualificationSpec):
        if isinstance(release.qualification, FlowReleaseCandidateQualification):
            if (
                release.qualification.authoring_source_digest
                != resources[task.qualification.authoring_source_resource].content_digest
            ):
                raise ResolutionError("flow release candidate has a stale authoring source")
        elif not isinstance(release.qualification, FlowReleaseQualification):
            raise ResolutionError("flow tasks require flow release qualification")
        else:
            expected_negatives = set(task.qualification.negative_candidate_resources)
            actual_negatives = {
                result.candidate_resource_id for result in release.qualification.negative_results
            }
            if (
                actual_negatives != expected_negatives
                or release.qualification.witness_resource_id
                != task.qualification.feasibility_witness_resource
            ):
                raise ResolutionError(
                    "flow release qualification does not cover its witness and negatives"
                )
    else:
        raise TypeError("unsupported task qualification type")

    visibility = {item.resource_id: item for item in task.visibility}
    licensing = {item.resource_id: item for item in task.licensing}
    sensitivity_rank = {
        Sensitivity.PUBLIC: 0,
        Sensitivity.INTERNAL: 1,
        Sensitivity.CONFIDENTIAL: 2,
        Sensitivity.SECRET: 3,
    }
    visible_sources = {
        Visibility.PUBLIC: {Visibility.PUBLIC},
        Visibility.PARTICIPANT: {Visibility.PUBLIC, Visibility.PARTICIPANT},
        Visibility.REVIEWER: {
            Visibility.PUBLIC,
            Visibility.PARTICIPANT,
            Visibility.REVIEWER,
        },
        Visibility.VERIFIER: {
            Visibility.PUBLIC,
            Visibility.PARTICIPANT,
            Visibility.VERIFIER,
        },
        Visibility.AUTHOR: set(Visibility),
    }
    for generated in release.files:
        if set(generated.source_resource_ids) - resources.keys():
            raise ResolutionError("generated file references an unknown authoring resource")
        for source_id in generated.source_resource_ids:
            if visibility[source_id].visibility not in visible_sources[generated.visibility]:
                raise ResolutionError("generated file weakens source visibility")
            if (
                sensitivity_rank[generated.sensitivity]
                < sensitivity_rank[visibility[source_id].sensitivity]
            ):
                raise ResolutionError("generated file weakens source sensitivity")
            if (
                generated.redistribution is Redistribution.ALLOWED
                and licensing[source_id].redistribution is not Redistribution.ALLOWED
            ):
                raise ResolutionError("generated file weakens source redistribution policy")


def _validate_session_environment(session: SessionSpec, environment: EnvironmentSpec) -> None:
    if (
        session.recovery is RecoveryPolicy.REQUIRED
        and environment.checkpoint is CheckpointCapability.NONE
    ):
        raise ResolutionError("required recovery needs a checkpoint-capable environment")
    if session.resources.max_artifact_bytes > environment.artifact_policy.quota_bytes:
        raise ResolutionError("session artifact budget exceeds the environment quota")
