"""Evidence for evaluator promotion and cross-spec fail-closed resolution."""

from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import ValidationError

from edagym.evaluation import (
    CandidateFailureOutcome,
    HardGateState,
    PassedOutcome,
    ScorerEligibilityKind,
    StageEligibilityKind,
    StageResult,
    UnknownOutcome,
    hard_gate_status,
    scorer_eligibility,
    stage_eligibility,
    topological_stage_ids,
)
from edagym.evaluation.model import MeasurementEvidence
from edagym.resolution import ResolutionError, resolve_run
from edagym.specs.environment import (
    BrokeredHostToolExecutor,
    CheckpointCapability,
    EnvironmentSpec,
)
from edagym.specs.task import TaskSpec
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def test_environment_binds_tool_locators_to_the_executor_boundary() -> None:
    image_document = environment_spec().model_dump(mode="json")
    image_document["tool_bindings"][0]["locator"] = {
        "kind": "attested_host",
        "executable": "verilator",
        "deployment_attestation_digest": digest("host-deployment"),
    }
    with pytest.raises(ValidationError, match="image-backed executors"):
        EnvironmentSpec.model_validate(image_document)

    image_document = environment_spec().model_dump(mode="json")
    image_document["tool_bindings"][0]["locator"]["image_digest"] = digest(
        "different-image"
    )
    with pytest.raises(ValidationError, match="exact image"):
        EnvironmentSpec.model_validate(image_document)

    brokered_document = environment_spec().model_dump(mode="json")
    brokered_document["executor"] = BrokeredHostToolExecutor(
        executor_id="host_broker",
        implementation_digest=digest("host-broker-implementation"),
        broker_id="host_broker",
        broker_digest=digest("host-broker"),
        participant_image_digest=digest("participant-image"),
    ).model_dump(mode="json")
    with pytest.raises(ValidationError, match="attested host locators"):
        EnvironmentSpec.model_validate(brokered_document)


def test_hard_gate_promotion_cannot_be_replaced_by_observations() -> None:
    task = task_spec()
    assert topological_stage_ids(task) == ("functional", "qor")
    assert stage_eligibility(task, (), "functional").state is StageEligibilityKind.READY
    assert stage_eligibility(task, (), "qor").state is StageEligibilityKind.WAITING

    unknown = (StageResult(stage_id="functional", outcome=UnknownOutcome()),)
    assert hard_gate_status(task, unknown).state is HardGateState.FAILED
    assert stage_eligibility(task, unknown, "qor").state is StageEligibilityKind.BLOCKED
    assert scorer_eligibility(task, unknown).state is ScorerEligibilityKind.BLOCKED

    failed = (StageResult(stage_id="functional", outcome=CandidateFailureOutcome()),)
    assert hard_gate_status(task, failed).state is HardGateState.FAILED

    passed = (StageResult(stage_id="functional", outcome=PassedOutcome()),)
    assert hard_gate_status(task, passed).state is HardGateState.SUCCEEDED
    assert stage_eligibility(task, passed, "qor").state is StageEligibilityKind.READY
    complete = (
        *passed,
        StageResult(
            stage_id="qor",
            outcome=PassedOutcome(),
            measurements=(
                MeasurementEvidence(
                    measurement_id="cell_count",
                    samples=(Decimal(42),),
                ),
            ),
        ),
    )
    assert hard_gate_status(task, complete).state is HardGateState.SUCCEEDED


def test_task_rejects_cycles_orphan_requirements_and_visibility_leaks() -> None:
    task = task_spec()
    document = task.model_dump(mode="python")
    document["evaluation"]["stages"][0]["depends_on"] = ("qor",)
    with pytest.raises(ValidationError, match="acyclic"):
        TaskSpec.model_validate(document)

    document = task.model_dump(mode="python")
    document["evaluation"]["stages"][0]["requirement_ids"] = ("preserves_payload",)
    with pytest.raises(ValidationError, match="every hard requirement"):
        TaskSpec.model_validate(document)

    document = task.model_dump(mode="python")
    for item in document["visibility"]:
        if item["resource_id"] == "oracle":
            item["visibility"] = "participant"
    with pytest.raises(ValidationError, match="qualification resources"):
        TaskSpec.model_validate(document)


def test_resolution_binds_all_sources_of_truth_and_fails_closed() -> None:
    task = task_spec()
    environment = environment_spec()
    session = session_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    first = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="paired-0001",
    )
    second = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="paired-0001",
    )
    assert first == second
    assert first.binding.digest == second.binding.digest

    environment_document = environment.model_dump(mode="python")
    environment_document["tool_bindings"] = environment_document["tool_bindings"][:1]
    missing_tool_environment = EnvironmentSpec.model_validate(environment_document)
    missing_tool_release = release.model_copy(
        update={"environment_digests": (missing_tool_environment.digest,)}
    )
    with pytest.raises(ResolutionError, match="required capabilities"):
        resolve_run(
            task=task,
            instance=instance,
            release=missing_tool_release,
            environment=missing_tool_environment,
            session=session,
            trial_key="paired-0001",
        )

    no_checkpoint_environment = environment.model_copy(
        update={"checkpoint": CheckpointCapability.NONE}
    )
    no_checkpoint_release = release.model_copy(
        update={"environment_digests": (no_checkpoint_environment.digest,)}
    )
    with pytest.raises(ResolutionError, match="checkpoint-capable"):
        resolve_run(
            task=task,
            instance=instance,
            release=no_checkpoint_release,
            environment=no_checkpoint_environment,
            session=session,
            trial_key="paired-0001",
        )


def test_licensed_environment_cannot_publish_native_tool_output() -> None:
    document = environment_spec().model_dump(mode="json")
    document["tool_bindings"][0]["license_binding_id"] = "commercial_tool"
    document["licenses"] = [
        {
            "license_binding_id": "commercial_tool",
            "provider_id": "site_broker",
            "provider_digest": "sha256:" + "a" * 64,
            "feature_class": "rtl_simulation",
            "max_checkouts": 1,
            "acquire_timeout_seconds": 0,
            "lease_ttl_seconds": 300,
        }
    ]

    with pytest.raises(ValidationError, match="managed artifact encryption"):
        EnvironmentSpec.model_validate(document)

    document["artifact_policy"]["encryption"] = {
        "kind": "managed",
        "provider_id": "site_keys",
        "policy_digest": "sha256:" + "b" * 64,
    }
    with pytest.raises(ValidationError, match="confidential author artifacts"):
        EnvironmentSpec.model_validate(document)
