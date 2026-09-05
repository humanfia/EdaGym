"""Security evidence for finite participant EDA operations."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from edagym.resolution import ResolutionError, resolve_run
from edagym.specs.common import ArtifactClass, Capability
from edagym.specs.environment import (
    AttestedHostToolLocator,
    BrokeredHostToolExecutor,
    EnvironmentSpec,
    ImageToolLocator,
)
from edagym.specs.operation import (
    CandidateInputOperationArgument,
    FixedOperationArgument,
    OutputOperationArgument,
    ParticipantOperationBinding,
    ParticipantOperationOutput,
)
from edagym.specs.release import FlowReleaseCandidateQualification, ReleaseManifest
from edagym.specs.task import FlowQualificationSpec, TaskSpec, WorkspaceInterface

from .factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def _operation(flag: str = "--lint-only") -> ParticipantOperationBinding:
    return ParticipantOperationBinding(
        operation_id="lint_candidate",
        capability=Capability.RTL_SIMULATION,
        tool_id="verilator",
        arguments=(
            FixedOperationArgument(value=flag),
            CandidateInputOperationArgument(path="participant/design.sv"),
            OutputOperationArgument(path="operation/lint.txt"),
        ),
        outputs=(
            ParticipantOperationOutput(
                logical_id="lint_report",
                path="operation/lint.txt",
                media_type="text/plain",
                artifact_class=ArtifactClass.DIAGNOSTIC,
            ),
        ),
    )


def _environment(operation: ParticipantOperationBinding) -> EnvironmentSpec:
    base = environment_spec()
    return EnvironmentSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "participant_operations": (operation,),
        }
    )


def _brokered_environment_document(base: EnvironmentSpec) -> dict[str, object]:
    return {
        **base.model_dump(mode="python"),
        "executor": BrokeredHostToolExecutor(
            executor_id="site_broker",
            implementation_digest=digest("site-broker-implementation"),
            broker_id="site_broker",
            broker_digest=digest("site-broker-policy"),
            participant_image_digest=digest("site-broker-participant-image"),
        ),
        "tool_bindings": tuple(
            binding.model_copy(
                update={
                    "locator": AttestedHostToolLocator(
                        executable=binding.locator.executable,
                        deployment_attestation_digest=(
                            binding.locator.deployment_attestation_digest
                        ),
                    )
                }
            )
            for binding in base.tool_bindings
        ),
    }


def test_operation_recipe_changes_environment_and_resolved_run_identity() -> None:
    task = task_spec()
    instance = task_instance(task)
    first_environment = _environment(_operation())
    second_environment = _environment(_operation("--Wall"))
    first_release = release_manifest(task, instance, first_environment)
    second_release = release_manifest(task, instance, second_environment)

    first = resolve_run(
        task=task,
        instance=instance,
        release=first_release,
        environment=first_environment,
        session=session_spec(),
        trial_key="finite_operation",
    )
    second = resolve_run(
        task=task,
        instance=instance,
        release=second_release,
        environment=second_environment,
        session=session_spec(),
        trial_key="finite_operation",
    )

    resolved = first.binding.environment.participant_operations
    assert len(resolved) == 1
    assert resolved[0].operation_digest == _operation().digest
    assert first_environment.digest != second_environment.digest
    assert first.binding.digest != second.binding.digest


def test_brokered_operations_reject_candidate_inputs_and_path_literals() -> None:
    with pytest.raises(ValidationError):
        FixedOperationArgument(value="../../host.tcl")

    base = environment_spec()
    unsafe = ParticipantOperationBinding(
        operation_id="source_candidate_script",
        capability=Capability.RTL_SIMULATION,
        tool_id="verilator",
        arguments=(CandidateInputOperationArgument(path="participant/run.tcl"),),
    )
    with pytest.raises(ValidationError, match="cannot expose participant operations"):
        EnvironmentSpec.model_validate(
            {
                **_brokered_environment_document(base),
                "participant_operations": (unsafe,),
            }
        )

    simulation = next(
        binding
        for binding in base.tool_bindings
        if binding.capability is Capability.RTL_SIMULATION
    )
    assert isinstance(simulation.locator, ImageToolLocator)
    interpreter = simulation.model_copy(
        update={
            "locator": ImageToolLocator(
                image_digest=simulation.locator.image_digest,
                executable="tclsh",
                deployment_attestation_digest=digest("tclsh-deployment"),
            )
        }
    )
    with pytest.raises(ValidationError, match="command interpreter"):
        EnvironmentSpec.model_validate(
            {
                **base.model_dump(mode="python"),
                "tool_bindings": tuple(
                    interpreter if binding is simulation else binding
                    for binding in base.tool_bindings
                ),
                "participant_operations": (unsafe,),
            }
        )


def test_every_participant_candidate_requires_an_isolation_executor() -> None:
    base_task = task_spec()
    isolated_environment = environment_spec()
    brokered_environment = EnvironmentSpec.model_validate(
        _brokered_environment_document(isolated_environment)
    )
    base_instance = task_instance(base_task)
    with pytest.raises(ResolutionError, match="rootless or virtual-machine"):
        resolve_run(
            task=base_task,
            instance=base_instance,
            release=release_manifest(base_task, base_instance, brokered_environment),
            environment=brokered_environment,
            session=session_spec(),
            trial_key="host_rtl_participant",
        )

    task = TaskSpec.model_validate(
        {
            **base_task.model_dump(mode="python"),
            "interface": WorkspaceInterface(submission_paths=("participant/design.sv",)),
            "qualification": FlowQualificationSpec(
                authoring_source_resource="generator",
                feasibility_witness_resource="reference",
                negative_candidate_resources=(
                    "mutant_corrupt",
                    "mutant_drop",
                    "mutant_stall",
                ),
            ),
        }
    )
    instance = task_instance(task)

    def release(environment: EnvironmentSpec) -> ReleaseManifest:
        generator = next(item for item in task.resources if item.resource_id == "generator")
        return ReleaseManifest(
            task_spec_digest=task.digest,
            task_instance_digest=instance.digest,
            participant_bundle_digest=digest("participant-bundle"),
            verifier_bundle_digest=digest("verifier-bundle"),
            environment_digests=(environment.digest,),
            files=instance.generated_files,
            qualification=FlowReleaseCandidateQualification(
                authoring_source_digest=generator.content_digest,
            ),
        )

    resolve_run(
        task=task,
        instance=instance,
        release=release(isolated_environment),
        environment=isolated_environment,
        session=session_spec(),
        trial_key="isolated_participant",
    )
    with pytest.raises(ResolutionError, match="rootless or virtual-machine"):
        resolve_run(
            task=task,
            instance=instance,
            release=release(brokered_environment),
            environment=brokered_environment,
            session=session_spec(),
            trial_key="host_participant",
        )
