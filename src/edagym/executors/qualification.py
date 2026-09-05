"""Canonical execution and cleanup evidence for concrete executor qualification."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Self

from pydantic import field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.capabilities import (
    ExecutorCapability,
    ExecutorProviderKind,
    ProviderAvailability,
)
from edagym.executors.model import (
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobStateKind,
)
from edagym.executors.vm import VmIsolationCleanup
from edagym.run.artifacts import ContentAddressedStore, artifact_policy_digest
from edagym.run.model import BlobRef
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
)
from edagym.specs.environment import EnvironmentSpec, NoNetwork, VmPerRunExecutor

EXECUTOR_QUALIFICATION_MEDIA_TYPE = "application/vnd.edagym.executor-qualification+json"


class VmQualificationScenario(StrEnum):
    COMPLETION = "completion"
    DEADLINE = "deadline"
    CANCELLATION = "cancellation"


_VM_EXPECTED_OUTCOMES = {
    VmQualificationScenario.COMPLETION: (
        JobStateKind.COMPLETED,
        None,
    ),
    VmQualificationScenario.DEADLINE: (
        JobStateKind.TIMED_OUT,
        ExecutionFailureKind.TIMEOUT,
    ),
    VmQualificationScenario.CANCELLATION: (
        JobStateKind.CANCELLED,
        ExecutionFailureKind.CANCELLED,
    ),
}


class VmLifecycleQualification(StrictModel):
    """One real invocation plus original and reconstructed cleanup observations."""

    scenario: VmQualificationScenario
    invocation_id: Identifier
    invocation_digest: Digest
    execution: ExecutionResult
    cleanup_fence_digest: Digest
    reconstructed_cleanup_fence_digest: Digest

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        expected_state, expected_failure = _VM_EXPECTED_OUTCOMES[self.scenario]
        state = self.execution.state
        if (
            state.handle.job_id != self.invocation_id
            or state.handle.invocation_digest != self.invocation_digest
            or state.state is not expected_state
            or state.failure is not expected_failure
        ):
            raise ValueError("VM qualification execution differs from its scenario")
        if self.scenario is VmQualificationScenario.COMPLETION:
            if state.exit_code != 0:
                raise ValueError("completed VM qualification requires a zero exit code")
        elif state.exit_code is None:
            raise ValueError("terminated VM qualification requires an exit code")
        if self.cleanup_fence_digest != self.reconstructed_cleanup_fence_digest:
            raise ValueError("VM qualification did not prove durable reconstructed absence")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="vm-lifecycle-qualification-v1")

    @classmethod
    def from_execution(
        cls,
        *,
        scenario: VmQualificationScenario,
        plan: InvocationPlan,
        execution: ExecutionResult,
        cleanup: VmIsolationCleanup,
        reconstructed_cleanup: VmIsolationCleanup,
    ) -> VmLifecycleQualification:
        cleanups = (cleanup, reconstructed_cleanup)
        if any(
            item.invocation_id != plan.invocation_id or item.remaining_resources
            for item in cleanups
        ):
            raise ValueError("VM qualification cleanup did not prove resource absence")
        return cls(
            scenario=scenario,
            invocation_id=plan.invocation_id,
            invocation_digest=plan.digest,
            execution=execution,
            cleanup_fence_digest=cleanup.lifecycle_fence_digest,
            reconstructed_cleanup_fence_digest=(reconstructed_cleanup.lifecycle_fence_digest),
        )


class VmExecutorQualificationReceipt(StrictModel):
    """Portable evidence for the complete disposable-VM lifecycle contract."""

    schema_version: SchemaVersion = 1
    environment_spec_digest: Digest
    executor_id: Identifier
    executor_implementation_digest: Digest
    executor_image_digest: Digest
    artifact_store_policy_digest: Digest
    capability: ExecutorCapability
    cases: tuple[VmLifecycleQualification, ...]

    @field_validator("cases")
    @classmethod
    def normalize_cases(
        cls,
        cases: tuple[VmLifecycleQualification, ...],
    ) -> tuple[VmLifecycleQualification, ...]:
        by_scenario = {case.scenario: case for case in cases}
        if len(by_scenario) != len(cases) or set(by_scenario) != set(VmQualificationScenario):
            raise ValueError("VM qualification requires every lifecycle scenario exactly once")
        return tuple(by_scenario[scenario] for scenario in VmQualificationScenario)

    @model_validator(mode="after")
    def validate_executor_closure(self) -> Self:
        if (
            self.capability.kind is not ExecutorProviderKind.LIBVIRT_KVM
            or self.capability.availability is not ProviderAvailability.AVAILABLE
        ):
            raise ValueError("VM qualification requires an available libvirt capability")
        invocation_ids = tuple(case.invocation_id for case in self.cases)
        invocation_digests = tuple(case.invocation_digest for case in self.cases)
        if (
            len(invocation_ids) != len(set(invocation_ids))
            or len(invocation_digests) != len(set(invocation_digests))
            or any(
                case.execution.state.handle.executor_id != self.executor_id for case in self.cases
            )
        ):
            raise ValueError("VM qualification invocations differ from the executor closure")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="vm-executor-qualification-v1")

    @classmethod
    def from_environment(
        cls,
        *,
        environment: EnvironmentSpec,
        capability: ExecutorCapability,
        cases: tuple[VmLifecycleQualification, ...],
    ) -> VmExecutorQualificationReceipt:
        executor = environment.executor
        if (
            not isinstance(executor, VmPerRunExecutor)
            or not isinstance(environment.network, NoNetwork)
            or capability.provider_id != executor.provider_id
            or capability.provider_digest != executor.provider_digest
        ):
            raise ValueError("VM qualification environment and capability disagree")
        return cls(
            environment_spec_digest=environment.digest,
            executor_id=executor.executor_id,
            executor_implementation_digest=executor.implementation_digest,
            executor_image_digest=executor.image_digest,
            artifact_store_policy_digest=artifact_policy_digest(environment.artifact_policy),
            capability=capability,
            cases=cases,
        )


class CommittedExecutorQualification(StrictModel):
    """CAS commitment for one canonical executor qualification receipt."""

    receipt_digest: Digest
    receipt_blob: BlobRef


def commit_vm_executor_qualification(
    receipt: VmExecutorQualificationReceipt,
    environment: EnvironmentSpec,
    plans: Mapping[VmQualificationScenario, InvocationPlan],
    artifact_store: ContentAddressedStore,
) -> CommittedExecutorQualification:
    """Verify the full CAS closure, then commit the canonical receipt itself."""

    _verify_vm_qualification_inputs(receipt, environment, plans, artifact_store)
    disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.EVIDENCE)
    if disclosure is None:
        raise ValueError("executor qualification policy does not retain evidence")
    blob = artifact_store.put_bytes(
        canonical_bytes(receipt),
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
    )
    return CommittedExecutorQualification(
        receipt_digest=receipt.digest,
        receipt_blob=blob,
    )


def verify_vm_executor_qualification(
    receipt: VmExecutorQualificationReceipt,
    commitment: CommittedExecutorQualification,
    environment: EnvironmentSpec,
    plans: Mapping[VmQualificationScenario, InvocationPlan],
    artifact_store: ContentAddressedStore,
) -> Digest:
    """Reopen every referenced blob and the committed receipt bytes."""

    _verify_vm_qualification_inputs(receipt, environment, plans, artifact_store)
    if commitment.receipt_digest != receipt.digest:
        raise ValueError("executor qualification commitment has a stale receipt identity")
    artifact_store.verify(commitment.receipt_blob)
    if artifact_store.read_bytes(
        commitment.receipt_blob,
        maximum_bytes=commitment.receipt_blob.size_bytes,
    ) != canonical_bytes(receipt):
        raise ValueError("executor qualification commitment has different receipt bytes")
    return receipt.digest


def _verify_vm_qualification_inputs(
    receipt: VmExecutorQualificationReceipt,
    environment: EnvironmentSpec,
    plans: Mapping[VmQualificationScenario, InvocationPlan],
    artifact_store: ContentAddressedStore,
) -> None:
    if type(receipt) is not VmExecutorQualificationReceipt:
        raise TypeError("VM qualification requires its canonical receipt")
    if type(artifact_store) is not ContentAddressedStore:
        raise TypeError("VM qualification requires the concrete artifact store")
    executor = environment.executor
    if (
        not isinstance(executor, VmPerRunExecutor)
        or not isinstance(environment.network, NoNetwork)
        or environment.digest != receipt.environment_spec_digest
        or executor.executor_id != receipt.executor_id
        or executor.implementation_digest != receipt.executor_implementation_digest
        or executor.image_digest != receipt.executor_image_digest
        or receipt.capability.provider_id != executor.provider_id
        or receipt.capability.provider_digest != executor.provider_digest
        or artifact_store.policy != environment.artifact_policy
        or artifact_store.policy_digest != receipt.artifact_store_policy_digest
    ):
        raise ValueError("VM qualification closure differs from its receipt")
    if set(plans) != set(VmQualificationScenario):
        raise ValueError("VM qualification plans do not cover every scenario")
    for case in receipt.cases:
        plan = plans[case.scenario]
        if (
            plan.view is not InvocationView.PARTICIPANT
            or plan.recipe
            or plan.invocation_id != case.invocation_id
            or plan.digest != case.invocation_digest
            or not _plan_matches_environment(plan, environment)
        ):
            raise ValueError("VM qualification plan differs from its receipt")
        artifact_store.verify(case.execution.stdout)
        artifact_store.verify(case.execution.stderr)
        for output in case.execution.outputs:
            artifact_store.verify(output.blob)


def _plan_matches_environment(plan: InvocationPlan, environment: EnvironmentSpec) -> bool:
    matches = tuple(
        binding
        for binding in environment.tool_bindings
        if binding.capability is plan.capability and binding.tool_id == plan.tool_id
    )
    return len(matches) == 1 and (
        matches[0].driver_digest == plan.driver_digest
        and matches[0].locator.executable == plan.executable
    )
