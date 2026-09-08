"""TaskSpec-owned qualification from private, trusted verifier receipts."""

from __future__ import annotations

from collections.abc import Sequence

from edagym.evaluation.model import OutcomeKind
from edagym.specs.common import Digest
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
            item.outcome in {
                OutcomeKind.INFRASTRUCTURE_FAILURE,
                OutcomeKind.LICENSE_UNAVAILABLE,
                OutcomeKind.UNKNOWN,
            }
            for item in observations
        ):
            reason = "qualification_execution_unavailable"
        else:
            reference = candidates[contract.feasibility_witness_resource]
            negatives = [candidates[item] for item in contract.negative_candidate_resources]
            if not reference.runnable or reference.outcome not in {
                OutcomeKind.PASSED, OutcomeKind.PROVED
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
