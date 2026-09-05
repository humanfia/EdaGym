"""Release-owned replay of the committed disposable-VM executor qualification."""

from __future__ import annotations

from typing import Never, Self

from pydantic import model_validator

from edagym.executors.model import InvocationPlan
from edagym.executors.qualification import (
    CommittedExecutorQualification,
    VmExecutorQualificationReceipt,
    VmQualificationScenario,
    verify_vm_executor_qualification,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import Digest, SchemaVersion, StrictModel
from edagym.specs.environment import EnvironmentSpec

_VERIFIED_QUALIFICATION_TOKEN = object()


class VmExecutorQualificationSource(StrictModel):
    """Portable closure naming one committed receipt and its exact replay inputs."""

    schema_version: SchemaVersion = 1
    receipt: VmExecutorQualificationReceipt
    commitment: CommittedExecutorQualification
    environment: EnvironmentSpec
    plans: tuple[InvocationPlan, ...]

    @model_validator(mode="after")
    def validate_plan_coverage(self) -> Self:
        expected = {case.invocation_id for case in self.receipt.cases}
        actual = [plan.invocation_id for plan in self.plans]
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise ValueError("executor qualification plans must cover each receipt case once")
        return self

    def scenario_plans(self) -> dict[VmQualificationScenario, InvocationPlan]:
        by_invocation = {plan.invocation_id: plan for plan in self.plans}
        return {case.scenario: by_invocation[case.invocation_id] for case in self.receipt.cases}


class VerifiedExecutorQualification:
    """Nonserializable proof that one live store replayed its committed receipt."""

    __slots__ = ("receipt_digest", "store")

    def __init__(
        self,
        token: object,
        *,
        receipt_digest: Digest,
        store: ContentAddressedStore,
    ) -> None:
        if token is not _VERIFIED_QUALIFICATION_TOKEN:
            raise TypeError("verified executor qualifications require the canonical replay")
        self.receipt_digest = receipt_digest
        self.store = store

    def __reduce__(self) -> Never:
        raise TypeError("verified executor qualifications cannot be serialized")


def verify_executor_qualification_source(
    source: VmExecutorQualificationSource,
    artifact_store: ContentAddressedStore,
) -> VerifiedExecutorQualification:
    """Reopen the committed receipt closure before the store may claim a release role."""

    if type(source) is not VmExecutorQualificationSource:
        raise TypeError("executor qualification replay requires its canonical source")
    if type(artifact_store) is not ContentAddressedStore:
        raise TypeError("executor qualification replay requires the concrete artifact store")
    receipt_digest = verify_vm_executor_qualification(
        source.receipt,
        source.commitment,
        source.environment,
        source.scenario_plans(),
        artifact_store,
    )
    return VerifiedExecutorQualification(
        _VERIFIED_QUALIFICATION_TOKEN,
        receipt_digest=receipt_digest,
        store=artifact_store,
    )
