"""Concrete-executor receipts for credential-isolation preflight probes."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import suppress
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Self, SupportsIndex

from pydantic import field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.executors.model import (
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    JobStateKind,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.runtime_surface_protocol import CANARY_ENVIRONMENT_NAME, IsolationSurface
from edagym.specs.common import (
    Capability,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
)

_PREFLIGHT_PROCESS_SURFACES = (
    IsolationSurface.CONSOLE,
    IsolationSurface.TOOL_PROCESS,
    IsolationSurface.EDA_PROCESS,
    IsolationSurface.VERIFIER,
)
_ISOLATION_PREFLIGHT_AUTHORITY = object()
SYNTHETIC_CREDENTIAL_PROBE_TARGET = "/edagym-preflight/controller-credential"


class IsolationProbeRole(StrEnum):
    PARTICIPANT = "participant"
    TOOL = "tool"
    EDA = "eda"
    VERIFIER = "verifier"


ISOLATION_PROBE_SURFACE = MappingProxyType(
    {
        IsolationProbeRole.PARTICIPANT: IsolationSurface.CONSOLE,
        IsolationProbeRole.TOOL: IsolationSurface.TOOL_PROCESS,
        IsolationProbeRole.EDA: IsolationSurface.EDA_PROCESS,
        IsolationProbeRole.VERIFIER: IsolationSurface.VERIFIER,
    }
)
ISOLATION_PROBE_VIEW = MappingProxyType(
    {
        IsolationProbeRole.PARTICIPANT: InvocationView.PARTICIPANT,
        IsolationProbeRole.TOOL: InvocationView.TOOL,
        IsolationProbeRole.EDA: InvocationView.EVALUATOR,
        IsolationProbeRole.VERIFIER: InvocationView.EVALUATOR,
    }
)
_ISOLATION_PROBE_PROGRAM = (
    "set -eu; "
    f'if [ "${{{CANARY_ENVIRONMENT_NAME}+x}}" = x ]; then '
    "printf 'controller-environment-present\\n'; "
    "exit 97; fi; "
    f"if [ -e {SYNTHETIC_CREDENTIAL_PROBE_TARGET} ] || "
    f"[ -L {SYNTHETIC_CREDENTIAL_PROBE_TARGET} ]; then "
    "printf 'controller-credential-present\\n'; "
    "exit 98; fi; "
    "printf 'credential-boundary-absent\\n'"
)
ISOLATION_PROBE_IMPLEMENTATION_DIGEST = canonical_digest(
    {"executable": "sh", "program": _ISOLATION_PROBE_PROGRAM},
    domain="executor-isolation-probe-implementation-v1",
)
_ISOLATION_PROBE_SUCCESS = b"credential-boundary-absent\n"


class IsolationProbeReceipt(StrictModel):
    """Path-free result of one fixed probe in a real execution boundary."""

    role: IsolationProbeRole
    plan: InvocationPlan
    execution: ExecutionResult

    @model_validator(mode="after")
    def validate_execution(self) -> Self:
        state = self.execution.state
        if (
            self.plan.view is not ISOLATION_PROBE_VIEW[self.role]
            or any(entry.name == CANARY_ENVIRONMENT_NAME for entry in self.plan.environment)
            or state.handle.job_id != self.plan.invocation_id
            or state.handle.invocation_digest != self.plan.digest
            or state.state is not JobStateKind.COMPLETED
        ):
            raise ValueError("isolation preflight probe did not complete its fixed invocation")
        return self

    @property
    def recipe_digest(self) -> Digest:
        return canonical_digest(
            {"role": self.role, "plan": self.plan},
            domain="isolation-preflight-probe-recipe-v1",
        )

    @property
    def execution_digest(self) -> Digest:
        return canonical_digest(
            self.execution,
            domain="isolation-preflight-probe-execution-v1",
        )


def isolation_probe_plan(
    *,
    role: IsolationProbeRole,
    invocation_id: str,
    environment_spec_digest: Digest,
) -> InvocationPlan:
    """Build the sole implementation-owned credential-absence invocation."""

    return InvocationPlan(
        invocation_id=invocation_id,
        capability=Capability.RTL_LINT,
        tool_id="edagym_isolation_probe",
        driver_digest=ISOLATION_PROBE_IMPLEMENTATION_DIGEST,
        view=ISOLATION_PROBE_VIEW[role],
        executable="sh",
        arguments=("-c", _ISOLATION_PROBE_PROGRAM),
        input_manifest_digest=canonical_digest(
            {
                "environment_spec_digest": environment_spec_digest,
                "role": role,
            },
            domain="executor-isolation-probe-input-v1",
        ),
    )


def validate_isolation_probe_execution(
    *,
    role: IsolationProbeRole,
    plan: InvocationPlan,
    execution: ExecutionResult,
    artifact_store: ContentAddressedStore,
) -> IsolationProbeReceipt:
    """Reopen fixed probe artifacts and admit only the exact absence result."""

    receipt = IsolationProbeReceipt(role=role, plan=plan, execution=execution)
    artifact_store.verify(execution.stdout)
    artifact_store.verify(execution.stderr)
    if (
        artifact_store.read_bytes(
            execution.stdout,
            maximum_bytes=execution.stdout.size_bytes,
        )
        != _ISOLATION_PROBE_SUCCESS
        or artifact_store.read_bytes(
            execution.stderr,
            maximum_bytes=execution.stderr.size_bytes,
        )
        or execution.outputs
    ):
        raise ValueError("isolation probe did not return the fixed absence evidence")
    return receipt


class IsolationPreflightReceipt(StrictModel):
    """Exact capability and four process probes owned by one concrete executor."""

    schema_version: SchemaVersion = 1
    environment_spec_digest: Digest
    executor_id: Identifier
    executor_implementation_digest: Digest
    isolation_capability_digest: Digest
    probe_implementation_digest: Digest
    artifact_store_policy_digest: Digest
    probes: tuple[IsolationProbeReceipt, ...]

    @field_validator("probes")
    @classmethod
    def normalize_probes(
        cls,
        probes: tuple[IsolationProbeReceipt, ...],
    ) -> tuple[IsolationProbeReceipt, ...]:
        by_role = {probe.role: probe for probe in probes}
        if len(by_role) != len(probes) or set(by_role) != set(IsolationProbeRole):
            raise ValueError("isolation preflight must probe every process role exactly once")
        return tuple(by_role[role] for role in IsolationProbeRole)

    @model_validator(mode="after")
    def validate_invocation_identities(self) -> Self:
        invocation_ids = tuple(probe.plan.invocation_id for probe in self.probes)
        invocation_digests = tuple(probe.plan.digest for probe in self.probes)
        if len(invocation_ids) != len(set(invocation_ids)) or len(invocation_digests) != len(
            set(invocation_digests)
        ):
            raise ValueError("isolation preflight probe invocations must be distinct")
        if any(
            probe.plan.driver_digest != self.probe_implementation_digest
            or probe.execution.state.handle.executor_id != self.executor_id
            for probe in self.probes
        ):
            raise ValueError("isolation preflight probe differs from its executor closure")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="executor-isolation-preflight-v1")


class IsolationPreflightExecution:
    """One-shot executor-owned process surfaces from fixed absence probes."""

    __slots__ = ("_artifact_store", "_closed", "_receipt", "_surfaces")

    def __init__(
        self,
        *,
        receipt: IsolationPreflightReceipt,
        surfaces: tuple[tuple[IsolationSurface, int], ...],
        artifact_store: ContentAddressedStore,
        authority: object,
    ) -> None:
        if authority is not _ISOLATION_PREFLIGHT_AUTHORITY:
            raise TypeError("isolation preflight execution is issued only by an executor")
        self._receipt = receipt
        self._surfaces = surfaces
        self._artifact_store = artifact_store
        self._closed = False
        try:
            if type(receipt) is not IsolationPreflightReceipt:
                raise TypeError("isolation preflight requires its canonical receipt")
            if type(artifact_store) is not ContentAddressedStore:
                raise TypeError("isolation preflight requires the concrete artifact store")
            if receipt.artifact_store_policy_digest != artifact_store.policy_digest:
                raise ValueError("isolation preflight receipt differs from its artifact store")
            for probe in receipt.probes:
                artifact_store.verify(probe.execution.stdout)
                artifact_store.verify(probe.execution.stderr)
                for output in probe.execution.outputs:
                    artifact_store.verify(output.blob)
            _validate_process_surface_descriptors(surfaces)
        except BaseException:
            self.close()
            raise

    @property
    def receipt(self) -> IsolationPreflightReceipt:
        return self._receipt

    @property
    def artifact_store(self) -> ContentAddressedStore:
        return self._artifact_store

    def _claim(
        self,
    ) -> tuple[
        IsolationPreflightReceipt,
        tuple[tuple[IsolationSurface, int], ...],
    ]:
        if self._closed:
            raise RuntimeError("isolation preflight execution is no longer available")
        surfaces = self._surfaces
        self._surfaces = ()
        self._closed = True
        return self._receipt, surfaces

    def close(self) -> None:
        if self._closed:
            return
        surfaces = self._surfaces
        self._surfaces = ()
        self._closed = True
        for _, descriptor in surfaces:
            with suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> IsolationPreflightExecution:
        if self._closed:
            raise RuntimeError("isolation preflight execution is no longer available")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "IsolationPreflightExecution(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("isolation preflight executions cannot be serialized")


def _issue_isolation_preflight_execution(
    *,
    receipt: IsolationPreflightReceipt,
    surfaces: tuple[tuple[IsolationSurface, int], ...],
    artifact_store: ContentAddressedStore,
) -> IsolationPreflightExecution:
    """Private issuance seam for isolation-capable concrete executors."""

    return IsolationPreflightExecution(
        receipt=receipt,
        surfaces=surfaces,
        artifact_store=artifact_store,
        authority=_ISOLATION_PREFLIGHT_AUTHORITY,
    )


def _validate_process_surface_descriptors(
    surfaces: tuple[tuple[IsolationSurface, int], ...],
) -> None:
    if tuple(surface for surface, _ in surfaces) != _PREFLIGHT_PROCESS_SURFACES:
        raise ValueError("executor preflight requires every process surface exactly once")
    descriptors = tuple(descriptor for _, descriptor in surfaces)
    if len(descriptors) != len(set(descriptors)) or any(
        type(descriptor) is not int or descriptor < 0 for descriptor in descriptors
    ):
        raise ValueError("executor preflight surface descriptors must be distinct")
    identities: set[tuple[int, int]] = set()
    for _, descriptor in surfaces:
        metadata = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or os.get_inheritable(descriptor)
            or flags & os.O_ACCMODE != os.O_RDONLY
        ):
            raise ValueError("executor preflight surfaces must be private read-only descriptors")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            raise ValueError("executor preflight surfaces cannot alias one object")
        identities.add(identity)
