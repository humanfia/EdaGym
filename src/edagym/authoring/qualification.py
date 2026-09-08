"""TaskSpec-owned qualification from private, trusted verifier receipts."""

from __future__ import annotations

from collections.abc import Sequence

from edagym.canonical import canonical_digest
from edagym.config.view_qualification import ViewQualificationReceipt
from edagym.evaluation.model import OutcomeKind
from edagym.evaluation.rtl_queue import QueueOracleEvidence
from edagym.run.journal import replay
from edagym.run.manifest import QualificationBinding, RunPurpose
from edagym.run.model import (
    EnginePhase,
    OperationPreparedEvent,
    OperationRunningEvent,
    OperationTerminalEvent,
    RunRecord,
)
from edagym.specs.common import Digest, Identifier, StrictModel
from edagym.specs.release import (
    QualificationStatus,
    TaskCanaryObservation,
    TaskInstance,
    TaskQualificationEvidence,
)
from edagym.specs.task import FlowQualificationSpec, TaskSpec


def qualify_from_canaries(
    instance: TaskInstance,
    task: TaskSpec,
    observations: Sequence[TaskCanaryObservation],
    *,
    tool_visibility_digest: Digest,
    independent_evidence_digests: tuple[Digest, ...],
    reference_evidence_digest: Digest,
    verifier_evidence_digest: Digest,
) -> TaskQualificationEvidence:
    """Check every declared candidate, retaining unsuccessful execution evidence.

    The trusted executor supplies receipts and separate independent-oracle checks.
    Different run digests alone do not establish oracle independence. This flow
    protocol cannot satisfy Sail's additional simulator/synthesis/formal contract.
    """

    if instance.identity.task_spec_digest != task.digest:
        raise ValueError("qualification task and instance identities disagree")
    resources = {item.resource_id: item for item in task.resources}
    candidates = {item.candidate_resource_id: item for item in observations}
    if len(candidates) != len(observations):
        raise ValueError("qualification candidates must have unique receipts")
    for resource_id, observation in candidates.items():
        resource = resources.get(resource_id)
        if resource is None or resource.content_digest != observation.candidate_content_digest:
            raise ValueError("qualification receipt does not bind the declared candidate content")
        if not any(
            resource_id in file.source_resource_ids
            and file.content_digest == observation.candidate_content_digest
            for file in instance.generated_files
        ):
            raise ValueError("qualification candidate is absent from the generated instance")

    status = QualificationStatus.UNAVAILABLE
    reason: str | None = "qualification_protocol_unavailable"
    contract = task.qualification
    if isinstance(contract, FlowQualificationSpec):
        required = {contract.feasibility_witness_resource, *contract.negative_candidate_resources}
        if set(candidates) - required:
            raise ValueError("qualification receipt names an undeclared candidate")
        if set(candidates) != required:
            reason = "qualification_receipts_incomplete"
        elif any(
            item.outcome
            in {
                OutcomeKind.INFRASTRUCTURE_FAILURE,
                OutcomeKind.LICENSE_UNAVAILABLE,
                OutcomeKind.UNKNOWN,
                OutcomeKind.TIMEOUT,
                OutcomeKind.SECURITY_VIOLATION,
            }
            for item in observations
        ):
            reason = "qualification_execution_unavailable"
        else:
            reference = candidates[contract.feasibility_witness_resource]
            negatives = [candidates[item] for item in contract.negative_candidate_resources]
            if not reference.runnable or reference.outcome not in {
                OutcomeKind.PASSED,
                OutcomeKind.PROVED,
            }:
                status, reason = QualificationStatus.REJECTED, "reference_canary_failed"
            elif any(
                not item.runnable or item.outcome is not OutcomeKind.COUNTEREXAMPLE
                for item in negatives
            ):
                status, reason = QualificationStatus.REJECTED, "semantic_mutant_not_rejected"
            elif not independent_evidence_digests:
                reason = "independent_oracle_evidence_required"
            else:
                status, reason = QualificationStatus.QUALIFIED, None

    return TaskQualificationEvidence(
        status=status,
        task_spec_digest=task.digest,
        observations=tuple(observations),
        independent_evidence_digests=independent_evidence_digests,
        tool_visibility_digest=tool_visibility_digest,
        reference_evidence_digest=reference_evidence_digest,
        verifier_evidence_digest=verifier_evidence_digest,
        reason=reason,
    )


def validate_qualification(instance: TaskInstance, task: TaskSpec) -> None:
    """Recheck admission at materialization/load boundaries against the task owner."""

    if instance.identity.task_spec_digest != task.digest:
        raise ValueError("task instance disagrees with its frozen specification")
    evidence = instance.qualification
    if evidence is None:
        return
    if evidence.task_spec_digest is not None and evidence.task_spec_digest != task.digest:
        raise ValueError("qualification evidence belongs to another task")
    if evidence.status is not QualificationStatus.QUALIFIED:
        return
    if (
        evidence.tool_visibility_digest is None
        or evidence.reference_evidence_digest is None
        or evidence.verifier_evidence_digest is None
    ):
        raise ValueError("qualified instance lacks verifier evidence")
    expected = qualify_from_canaries(
        instance,
        task,
        evidence.observations,
        tool_visibility_digest=evidence.tool_visibility_digest,
        independent_evidence_digests=evidence.independent_evidence_digests,
        reference_evidence_digest=evidence.reference_evidence_digest,
        verifier_evidence_digest=evidence.verifier_evidence_digest,
    )
    if evidence != expected:
        raise ValueError("qualification evidence does not satisfy the task contract")


class QualificationRunEvidence(StrictModel):
    """Task admission binds its actual run, views, and independent oracle check."""

    run_id: Identifier
    journal_head_digest: Digest
    snapshot_digest: Digest
    views: tuple[ViewQualificationReceipt, ...]
    oracle: QueueOracleEvidence
    qualification: TaskQualificationEvidence

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="task-qualification-run-evidence-v2")


def qualification_from_run(
    instance: TaskInstance,
    task: TaskSpec,
    record: RunRecord,
    views: tuple[ViewQualificationReceipt, ...],
    oracle: QueueOracleEvidence,
) -> QualificationRunEvidence:
    if record.manifest.task_instance_digest != instance.digest:
        raise ValueError("qualification run binds another task instance")
    if (
        record.manifest.purpose is not RunPurpose.QUALIFICATION
        or len(views) != 2
        or record.manifest.qualification
        != QualificationBinding(
            participant_view_digest=views[0].digest,
            evaluator_view_digest=views[1].digest,
            independent_evidence_digest=oracle.digest,
        )
    ):
        raise ValueError("qualification inputs differ from the frozen run binding")
    projection = replay(record.manifest, record.events).projection
    if projection.phase is not EnginePhase.RUNNING or projection.cancel_requested:
        raise ValueError(
            "qualification evidence requires the completed canary prefix before publication"
        )
    resources = {item.resource_id: item for item in task.resources}
    observations = tuple(
        TaskCanaryObservation(
            candidate_resource_id=item.candidate_id,
            candidate_content_digest=resources[item.candidate_id].content_digest,
            outcome=item.outcome,
            runnable=item.runnable,
            evidence_digest=canonical_digest(
                {
                    "run_manifest": record.manifest.digest,
                    "evaluation": item,
                    "operations": tuple(
                        event
                        for event in record.events
                        if (
                            isinstance(event, OperationPreparedEvent)
                            and event.payload.plan.invocation_id in item.operation_ids
                        )
                        or (
                            isinstance(event, OperationRunningEvent | OperationTerminalEvent)
                            and event.payload.operation_id in item.operation_ids
                        )
                    ),
                },
                domain="task-canary-run-evidence-v1",
            ),
        )
        for item in projection.evaluations
    )
    if not isinstance(task.qualification, FlowQualificationSpec):
        raise ValueError("runtime qualification requires the flow task contract")
    reference = next(
        item
        for item in observations
        if item.candidate_resource_id == task.qualification.feasibility_witness_resource
    )
    head = record.integrity_digest
    qualification = qualify_from_canaries(
        instance,
        task,
        observations,
        tool_visibility_digest=canonical_digest(views, domain="task-view-evidence-v1"),
        independent_evidence_digests=(oracle.digest,),
        reference_evidence_digest=reference.evidence_digest,
        verifier_evidence_digest=canonical_digest(
            {"verifier": instance.verifier_bundle_digest, "journal_head": head},
            domain="task-verifier-run-evidence-v1",
        ),
    )
    return QualificationRunEvidence(
        run_id=record.manifest.run_id,
        journal_head_digest=head,
        snapshot_digest=record.manifest.private_config_snapshot_digest,
        views=views,
        oracle=oracle,
        qualification=qualification,
    )
