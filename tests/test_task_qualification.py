"""Qualification admission binds every required candidate to its actual content."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from edagym.authoring.factory import GenerationRequest, TaskFactory
from edagym.authoring.qualification import qualify_from_canaries
from edagym.evaluation.model import OutcomeKind
from edagym.specs.release import QualificationStatus, TaskCanaryObservation
from edagym.specs.task import FlowQualificationSpec


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


@pytest.mark.parametrize("failure", ("missing_flush", "compile_failure", "license_failure", None))
def test_qualification_requires_every_semantic_mutant(
    tmp_path: Path, failure: str | None
) -> None:
    factory = TaskFactory()
    generated = factory.generate(GenerationRequest(
        family="rtl_verification_repair", difficulty="flush_recovery", seed="0" * 32, count=1
    ))[0]
    resources = {item.resource_id: item for item in generated.task.resources}
    contract = generated.task.qualification
    assert isinstance(contract, FlowQualificationSpec)
    observations = []
    candidates = (
        contract.feasibility_witness_resource,
        *contract.negative_candidate_resources,
    )
    for candidate in candidates:
        if failure == "missing_flush" and candidate == "ignored_flush":
            continue
        outcome = (
            OutcomeKind.PASSED if candidate == contract.feasibility_witness_resource
            else OutcomeKind.COUNTEREXAMPLE
        )
        runnable = True
        if candidate == "ignored_flush":
            if failure == "compile_failure":
                outcome, runnable = OutcomeKind.CANDIDATE_FAILURE, False
            elif failure == "license_failure":
                outcome, runnable = OutcomeKind.LICENSE_UNAVAILABLE, False
        observations.append(TaskCanaryObservation(
            candidate_resource_id=candidate,
            candidate_content_digest=resources[candidate].content_digest,
            outcome=outcome,
            runnable=runnable,
            evidence_digest=_digest(f"execution:{candidate}"),
        ))
    evidence = qualify_from_canaries(
        generated.instance,
        generated.task,
        observations,
        tool_visibility_digest=_digest("visibility"),
        independent_evidence_digests=(_digest("independent_known_answers"),),
        reference_evidence_digest=_digest("reference"),
        verifier_evidence_digest=_digest("verifier"),
    )
    if failure is None:
        assert evidence.status is QualificationStatus.QUALIFIED
        qualified = replace(generated, instance=generated.instance.model_copy(
            update={"qualification": evidence}
        ))
        factory.persist(qualified, tmp_path)
        assert factory.load(tmp_path, qualified.instance_id).instance == qualified.instance
    else:
        assert evidence.status is (
            QualificationStatus.REJECTED if failure == "compile_failure"
            else QualificationStatus.UNAVAILABLE
        )
        # A caller-controlled status cannot turn incomplete or nonsemantic
        # execution receipts into an admitted task at the persistence boundary.
        forged = replace(generated, instance=generated.instance.model_copy(update={
            "qualification": evidence.model_copy(update={"status": QualificationStatus.QUALIFIED})
        }))
        with pytest.raises(ValueError):
            factory.persist(forged, tmp_path)


def test_qualification_rejects_receipts_from_a_different_candidate() -> None:
    generated = TaskFactory().generate(GenerationRequest(
        family="rtl_verification_repair", difficulty="single_transaction", seed="0" * 32, count=1
    ))[0]
    with pytest.raises(ValueError):
        qualify_from_canaries(
            generated.instance,
            generated.task,
            (TaskCanaryObservation(
                candidate_resource_id="reference",
                candidate_content_digest=_digest("unrelated_design"),
                outcome=OutcomeKind.PASSED,
                runnable=True,
                evidence_digest=_digest("execution"),
            ),),
            tool_visibility_digest=_digest("visibility"),
            independent_evidence_digests=(_digest("independent_known_answers"),),
            reference_evidence_digest=_digest("reference"),
            verifier_evidence_digest=_digest("verifier"),
        )
