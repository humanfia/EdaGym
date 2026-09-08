"""Semantic evidence for durable executor qualification receipts."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from edagym.executors.capabilities import (
    ExecutorCapability,
    ExecutorProviderKind,
    ProviderAvailability,
    ProviderFeature,
    ProviderTrustBoundary,
    RuntimeEvidence,
)
from edagym.executors.model import (
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobState,
    JobStateKind,
)
from edagym.executors.qualification import (
    VmExecutorQualificationReceipt,
    VmLifecycleQualification,
    VmQualificationScenario,
    commit_vm_executor_qualification,
    verify_vm_executor_qualification,
)
from edagym.executors.vm import VmIsolationCleanup
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass
from edagym.specs.environment import (
    CheckpointCapability,
    EnvironmentSpec,
    VmPerRunExecutor,
)
from tests.factories import digest, environment_spec


def _qualification(
    tmp_path: Path,
) -> tuple[
    VmExecutorQualificationReceipt,
    EnvironmentSpec,
    ContentAddressedStore,
    dict[VmQualificationScenario, InvocationPlan],
]:
    baseline = environment_spec()
    image_digest = digest("vm-image")
    environment = EnvironmentSpec.model_validate(
        {
            **baseline.model_dump(mode="python"),
            "executor": VmPerRunExecutor(
                executor_id="libvirt_vm",
                implementation_digest=digest("libvirt-executor"),
                provider_id="local_libvirt",
                provider_digest=digest("libvirt-provider"),
                image_digest=image_digest,
            ),
            "tool_bindings": tuple(
                binding.model_copy(
                    update={
                        "locator": binding.locator.model_copy(
                            update={"image_digest": image_digest}
                        )
                    }
                )
                for binding in baseline.tool_bindings
            ),
            "checkpoint": CheckpointCapability.NONE,
        }
    )
    runtime = RuntimeEvidence(
        command="virsh",
        version="11.10.0",
        executable_digest=digest("virsh-executable"),
        version_output_digest=digest("virsh-version-output"),
    )
    capability = ExecutorCapability(
        provider_id="local_libvirt",
        provider_digest=digest("libvirt-provider"),
        kind=ExecutorProviderKind.LIBVIRT_KVM,
        availability=ProviderAvailability.AVAILABLE,
        trust_boundary=ProviderTrustBoundary.HARDWARE_VM,
        features=(
            ProviderFeature.HARDWARE_VIRTUALIZATION,
            ProviderFeature.PER_RUN_MACHINE,
            ProviderFeature.IMMUTABLE_BASE_IMAGE,
            ProviderFeature.GUEST_CONTROL_CHANNEL,
        ),
        runtimes=(runtime,),
        control_plane_probe_digest=digest("libvirt-control-plane"),
    )
    store = ContentAddressedStore(tmp_path / "cas", policy=environment.artifact_policy)
    disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.DIAGNOSTIC)
    assert disclosure is not None
    empty = store.put_bytes(
        b"",
        artifact_class=ArtifactClass.DIAGNOSTIC,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )
    tool = environment.tool_bindings[0]
    scenarios = (
        (
            VmQualificationScenario.COMPLETION,
            JobStateKind.COMPLETED,
            0,
            None,
        ),
        (
            VmQualificationScenario.DEADLINE,
            JobStateKind.TIMED_OUT,
            124,
            ExecutionFailureKind.TIMEOUT,
        ),
        (
            VmQualificationScenario.CANCELLATION,
            JobStateKind.CANCELLED,
            143,
            ExecutionFailureKind.CANCELLED,
        ),
    )
    cases: list[VmLifecycleQualification] = []
    plans: dict[VmQualificationScenario, InvocationPlan] = {}
    for scenario, state_kind, exit_code, failure in scenarios:
        plan = InvocationPlan(
            invocation_id=f"vm_{scenario.value}",
            run_id=digest("vm-lifecycle-qualification"),
            capability=tool.capability,
            tool_id=tool.tool_id,
            driver_digest=tool.driver_digest,
            view=InvocationView.PARTICIPANT,
            executable=tool.locator.executable,
            input_manifest_digest=digest(f"{scenario.value}-input"),
        )
        result = ExecutionResult(
            state=JobState(
                handle=JobHandle(
                    job_id=plan.invocation_id,
                    invocation_digest=plan.digest,
                    executor_id="libvirt_vm",
                ),
                state=state_kind,
                exit_code=exit_code,
                failure=failure,
            ),
            stdout=empty,
            stderr=empty,
        )
        fence = digest(f"{scenario.value}-lifecycle-fence")
        plans[scenario] = plan
        cases.append(
            VmLifecycleQualification.from_execution(
                scenario=scenario,
                plan=plan,
                execution=result,
                cleanup=VmIsolationCleanup(
                    invocation_id=plan.invocation_id,
                    lifecycle_fence_digest=fence,
                ),
                reconstructed_cleanup=VmIsolationCleanup(
                    invocation_id=plan.invocation_id,
                    lifecycle_fence_digest=fence,
                ),
            )
        )
    return (
        VmExecutorQualificationReceipt.from_environment(
            environment=environment,
            capability=capability,
            cases=tuple(reversed(cases)),
        ),
        environment,
        store,
        plans,
    )


def test_vm_qualification_commits_the_complete_cas_and_recovery_closure(
    tmp_path: Path,
) -> None:
    receipt, environment, store, plans = _qualification(tmp_path)
    commitment = commit_vm_executor_qualification(receipt, environment, plans, store)

    assert (
        verify_vm_executor_qualification(
            receipt,
            commitment,
            environment,
            plans,
            store,
        )
        == receipt.digest
    )
    assert tuple(case.scenario for case in receipt.cases) == tuple(VmQualificationScenario)

    stale = receipt.cases[0]
    with pytest.raises(ValidationError, match="reconstructed absence"):
        VmLifecycleQualification(
            scenario=stale.scenario,
            invocation_id=stale.invocation_id,
            invocation_digest=stale.invocation_digest,
            execution=stale.execution,
            cleanup_fence_digest=stale.cleanup_fence_digest,
            reconstructed_cleanup_fence_digest=digest("stale-fence"),
        )
