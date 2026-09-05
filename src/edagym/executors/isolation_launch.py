"""One-shot controller authority for a real isolation-preflight launch."""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, SupportsIndex

from pydantic import TypeAdapter, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.executors.isolation_preflight import (
    IsolationPreflightExecution,
    IsolationPreflightReceipt,
    IsolationProbeRole,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.runtime_surface_protocol import CANARY_ENVIRONMENT_NAME, IsolationSurface
from edagym.specs.common import Digest, SchemaVersion, StrictModel

_DIGEST_ADAPTER = TypeAdapter(Digest)
_LAUNCH_CAPABILITY_AUTHORITY = object()
_MAXIMUM_MARKER_BYTES = 4096
_REQUIRED_PARENT_LAUNCHES = len(IsolationProbeRole)
_PODMAN_NAMESPACE_ARGUMENT_PREFIXES = (
    "--cap-drop=",
    "--cgroupns=",
    "--image-volume=",
    "--ipc=",
    "--network=",
    "--pid=",
    "--read-only-tmpfs=",
    "--security-opt=",
    "--tmpfs=",
    "--userns=",
    "--uts=",
    "--volume=",
)
_PODMAN_NAMESPACE_ARGUMENTS = frozenset({"--read-only"})
_SYNTHETIC_EXECUTION_AUTHORITY = object()


@dataclass(slots=True)
class _SyntheticPreflightLaunchState:
    completed: bool = False


class SyntheticPreflightProbeLaunchReceipt(StrictModel):
    """Path-free parent launch evidence for one fixed process role."""

    role: IsolationProbeRole
    parent_launch_digest: Digest


class SyntheticPreflightParentReceipt(StrictModel):
    """One challenge bound to the exact parent launch of all fixed probes."""

    schema_version: SchemaVersion = 1
    canary_launch_binding_digest: Digest
    controller_boundary_digest: Digest
    probes: tuple[SyntheticPreflightProbeLaunchReceipt, ...]

    @field_validator("probes")
    @classmethod
    def normalize_probes(
        cls,
        probes: tuple[SyntheticPreflightProbeLaunchReceipt, ...],
    ) -> tuple[SyntheticPreflightProbeLaunchReceipt, ...]:
        by_role = {probe.role: probe for probe in probes}
        if len(by_role) != len(probes) or set(by_role) != set(IsolationProbeRole):
            raise ValueError("synthetic parent receipt must bind every probe role exactly once")
        normalized = tuple(by_role[role] for role in IsolationProbeRole)
        if len({probe.parent_launch_digest for probe in normalized}) != len(normalized):
            raise ValueError("synthetic parent probe launches must be distinct")
        return normalized

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="synthetic-preflight-parent-receipt-v1")


class SyntheticPreflightExecutorReceipt(StrictModel):
    """A fixed executor probe set bound to one real controller challenge."""

    schema_version: SchemaVersion = 1
    isolation_preflight: IsolationPreflightReceipt
    parent_launch: SyntheticPreflightParentReceipt

    @model_validator(mode="after")
    def validate_probe_roles(self) -> SyntheticPreflightExecutorReceipt:
        if tuple(probe.role for probe in self.isolation_preflight.probes) != tuple(
            probe.role for probe in self.parent_launch.probes
        ):
            raise ValueError("synthetic parent launches differ from fixed probe roles")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="synthetic-preflight-executor-receipt-v1")


class SyntheticIsolationPreflightExecution:
    """One-shot fixed probe surfaces with real parent challenge evidence."""

    __slots__ = ("_closed", "_execution", "_receipt")

    def __init__(
        self,
        *,
        execution: IsolationPreflightExecution,
        parent_receipt: SyntheticPreflightParentReceipt,
        authority: object,
    ) -> None:
        if authority is not _SYNTHETIC_EXECUTION_AUTHORITY:
            raise TypeError("synthetic isolation executions require executor authority")
        if type(execution) is not IsolationPreflightExecution:
            raise TypeError("synthetic isolation execution requires fixed executor probes")
        if type(parent_receipt) is not SyntheticPreflightParentReceipt:
            raise TypeError("synthetic isolation execution requires its parent receipt")
        self._execution = execution
        try:
            self._receipt = SyntheticPreflightExecutorReceipt(
                isolation_preflight=execution.receipt,
                parent_launch=parent_receipt,
            )
        except BaseException:
            execution.close()
            raise
        self._closed = False

    @property
    def receipt(self) -> SyntheticPreflightExecutorReceipt:
        return self._receipt

    @property
    def artifact_store(self) -> ContentAddressedStore:
        return self._execution.artifact_store

    def _claim(
        self,
    ) -> tuple[
        SyntheticPreflightExecutorReceipt,
        tuple[tuple[IsolationSurface, int], ...],
    ]:
        if self._closed:
            raise RuntimeError("synthetic isolation execution is no longer available")
        _, surfaces = self._execution._claim()
        self._closed = True
        return self._receipt, surfaces

    def close(self) -> None:
        if self._closed:
            return
        self._execution.close()
        self._closed = True

    def __enter__(self) -> SyntheticIsolationPreflightExecution:
        if self._closed:
            raise RuntimeError("synthetic isolation execution is no longer available")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SyntheticIsolationPreflightExecution(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("synthetic isolation executions cannot be serialized")


def _issue_synthetic_isolation_preflight_execution(
    *,
    execution: IsolationPreflightExecution,
    parent_receipt: SyntheticPreflightParentReceipt,
) -> SyntheticIsolationPreflightExecution:
    """Bind concrete fixed probes to an executor-observed parent challenge."""

    return SyntheticIsolationPreflightExecution(
        execution=execution,
        parent_receipt=parent_receipt,
        authority=_SYNTHETIC_EXECUTION_AUTHORITY,
    )


def synthetic_preflight_canary_binding_digest(marker: bytes) -> Digest:
    """Bind the exact high-entropy marker retained by the controller."""

    if type(marker) is not bytes or not marker or len(marker) > _MAXIMUM_MARKER_BYTES:
        raise ValueError("synthetic preflight marker must be bounded non-empty bytes")
    try:
        value = marker.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("synthetic preflight marker must be ASCII") from None
    return canonical_digest(
        {"environment_name": CANARY_ENVIRONMENT_NAME, "marker": value},
        domain="synthetic-preflight-canary-binding-v1",
    )


class _SyntheticPreflightLaunchClaim:
    """Live marker and credential authority consumed only by a concrete executor."""

    __slots__ = (
        "_canary_launch_binding_digest",
        "_closed",
        "_controller_boundary_digest",
        "_credential_descriptor",
        "_credential_identity",
        "_marker",
        "_parent_launch_digests",
        "_state",
    )

    def __init__(
        self,
        *,
        marker: bytearray,
        credential_descriptor: int,
        credential_identity: tuple[int, ...],
        state: _SyntheticPreflightLaunchState,
        authority: object,
    ) -> None:
        if authority is not _LAUNCH_CAPABILITY_AUTHORITY:
            raise TypeError("synthetic preflight launch claims require controller authority")
        self._marker = marker
        self._credential_descriptor = credential_descriptor
        self._credential_identity = credential_identity
        self._state = state
        self._parent_launch_digests: list[Digest] = []
        self._canary_launch_binding_digest = synthetic_preflight_canary_binding_digest(
            bytes(marker)
        )
        self._controller_boundary_digest = canonical_digest(
            {
                "canary_launch_binding_digest": self._canary_launch_binding_digest,
                "credential_identity_digest": canonical_digest(
                    tuple(str(value) for value in credential_identity),
                    domain="synthetic-preflight-credential-identity-v1",
                ),
            },
            domain="synthetic-preflight-controller-boundary-v1",
        )
        self._closed = False

    @property
    def canary_launch_binding_digest(self) -> Digest:
        return self._canary_launch_binding_digest

    @property
    def controller_boundary_digest(self) -> Digest:
        return self._controller_boundary_digest

    def _parent_environment(self, base: Mapping[str, str]) -> dict[str, str]:
        """Return the sole parent-only mapping containing the live marker."""

        self._require_live_credential()
        if CANARY_ENVIRONMENT_NAME in base:
            raise ValueError("preflight parent environment already contains the canary name")
        marker = bytes(self._marker).decode("ascii")
        if any(marker in value for value in base.values()):
            raise ValueError("preflight parent environment already contains the canary value")
        environment = dict(base)
        environment[CANARY_ENVIRONMENT_NAME] = marker
        return environment

    def _validate_parent_launch(
        self,
        *,
        process_environment: Mapping[str, str],
        parent_argv: Sequence[str],
        container_argv: Sequence[str],
        pass_fds: Sequence[int],
    ) -> Digest:
        """Bind the exact parent environment, argv, mounts, and inherited descriptors."""

        self._require_live_credential()
        installed = process_environment.get(CANARY_ENVIRONMENT_NAME)
        try:
            environment_matches = installed is not None and secrets.compare_digest(
                installed.encode("ascii", errors="strict"),
                self._marker,
            )
        except UnicodeEncodeError:
            environment_matches = False
        if not environment_matches:
            raise ValueError("Podman parent environment does not contain the bound canary")
        marker = bytes(self._marker)
        marker_text = marker.decode("ascii")
        if any(
            name != CANARY_ENVIRONMENT_NAME and marker_text in value
            for name, value in process_environment.items()
        ):
            raise ValueError("synthetic marker must have one parent environment owner")

        parent = tuple(parent_argv)
        container = tuple(container_argv)
        inherited = tuple(pass_fds)
        if not parent or not container or parent[-len(container) :] != container:
            raise ValueError("Podman parent argv does not contain the exact container command")
        if any(marker_text in argument for argument in parent):
            raise ValueError("synthetic marker cannot enter Podman argv")
        if any(
            argument == f"--env={CANARY_ENVIRONMENT_NAME}"
            or argument.startswith(f"--env={CANARY_ENVIRONMENT_NAME}=")
            or argument.startswith("--env-file=")
            for argument in container
        ):
            raise ValueError("synthetic marker cannot enter the container environment")
        required_isolation_arguments = {
            "--network=none",
            "--pid=private",
            "--read-only",
            "--unsetenv-all",
        }
        if not required_isolation_arguments.issubset(container):
            raise ValueError("synthetic preflight container isolation was weakened")
        if self._credential_descriptor in inherited or any(
            f"/proc/self/fd/{self._credential_descriptor}" in argument for argument in parent
        ):
            raise ValueError("synthetic credential descriptor cannot enter Podman")
        namespace_arguments = tuple(
            argument
            for argument in container
            if argument in _PODMAN_NAMESPACE_ARGUMENTS
            or argument.startswith(_PODMAN_NAMESPACE_ARGUMENT_PREFIXES)
        )
        if not namespace_arguments:
            raise ValueError("Podman isolation namespace arguments are unavailable")
        digest = _DIGEST_ADAPTER.validate_python(
            canonical_digest(
                {
                    "canary_launch_binding_digest": self._canary_launch_binding_digest,
                    "controller_boundary_digest": self._controller_boundary_digest,
                    "parent_argv_digest": canonical_digest(
                        parent,
                        domain="synthetic-preflight-parent-argv-v1",
                    ),
                    "container_argv_digest": canonical_digest(
                        container,
                        domain="synthetic-preflight-container-argv-v1",
                    ),
                    "mount_namespace_digest": canonical_digest(
                        namespace_arguments,
                        domain="synthetic-preflight-mount-namespace-v1",
                    ),
                    "parent_environment_digest": canonical_digest(
                        tuple(sorted(process_environment.items())),
                        domain="synthetic-preflight-parent-environment-v1",
                    ),
                    "inherited_descriptor_digest": canonical_digest(
                        inherited,
                        domain="synthetic-preflight-inherited-descriptors-v1",
                    ),
                },
                domain="synthetic-preflight-parent-launch-v1",
            )
        )
        if digest in self._parent_launch_digests:
            raise ValueError("synthetic preflight parent launches must be distinct")
        if len(self._parent_launch_digests) >= _REQUIRED_PARENT_LAUNCHES:
            raise ValueError("synthetic preflight parent launch set is already complete")
        self._parent_launch_digests.append(digest)
        return digest

    def close(self) -> None:
        if self._closed:
            return
        completion_error: BaseException | None = None
        if len(self._parent_launch_digests) == _REQUIRED_PARENT_LAUNCHES:
            try:
                self._require_live_credential()
            except BaseException as error:
                completion_error = error
        descriptor = self._credential_descriptor
        self._credential_descriptor = -1
        with suppress(OSError):
            os.close(descriptor)
        for index in range(len(self._marker)):
            self._marker[index] = 0
        self._state.completed = (
            completion_error is None
            and len(self._parent_launch_digests) == _REQUIRED_PARENT_LAUNCHES
        )
        self._closed = True
        if completion_error is not None:
            raise completion_error

    def _require_live_credential(self) -> None:
        if self._closed:
            raise RuntimeError("synthetic preflight launch claim is no longer available")
        try:
            metadata = os.fstat(self._credential_descriptor)
            os.lseek(self._credential_descriptor, 0, os.SEEK_SET)
            content = bytearray()
            while len(content) <= len(self._marker):
                chunk = os.read(
                    self._credential_descriptor,
                    len(self._marker) + 1 - len(content),
                )
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(self._credential_descriptor)
        except OSError:
            raise RuntimeError("synthetic credential authority is unavailable") from None
        if (
            _credential_identity(metadata) != self._credential_identity
            or _credential_identity(after) != self._credential_identity
            or len(content) != len(self._marker)
            or not secrets.compare_digest(content, self._marker)
        ):
            raise RuntimeError("synthetic credential authority changed before launch")

    def __repr__(self) -> str:
        return "_SyntheticPreflightLaunchClaim(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("synthetic preflight launch claims cannot be serialized")


class SyntheticPreflightLaunchCapability:
    """One-shot nonserializable authority for a concrete preflight executor."""

    __slots__ = (
        "_closed",
        "_credential_descriptor",
        "_credential_identity",
        "_marker",
        "_state",
    )

    def __init__(
        self,
        *,
        marker: bytes,
        credential_descriptor: int,
        authority: object,
    ) -> None:
        if authority is not _LAUNCH_CAPABILITY_AUTHORITY:
            raise TypeError("synthetic preflight launch capabilities require a challenge")
        self._marker = bytearray(marker)
        self._credential_descriptor = credential_descriptor
        self._credential_identity = _credential_identity(os.fstat(credential_descriptor))
        self._state = _SyntheticPreflightLaunchState()
        self._closed = False
        try:
            _validate_credential_descriptor(
                credential_descriptor,
                self._credential_identity,
                self._marker,
            )
        except BaseException:
            self.close()
            raise

    def _claim(self) -> _SyntheticPreflightLaunchClaim:
        if self._closed:
            raise RuntimeError("synthetic preflight launch capability is no longer available")
        marker = self._marker
        descriptor = self._credential_descriptor
        identity = self._credential_identity
        self._marker = bytearray()
        self._credential_descriptor = -1
        self._closed = True
        return _SyntheticPreflightLaunchClaim(
            marker=marker,
            credential_descriptor=descriptor,
            credential_identity=identity,
            state=self._state,
            authority=_LAUNCH_CAPABILITY_AUTHORITY,
        )

    def _completed(self) -> bool:
        return self._state.completed

    def close(self) -> None:
        if self._closed:
            return
        descriptor = self._credential_descriptor
        self._credential_descriptor = -1
        with suppress(OSError):
            os.close(descriptor)
        for index in range(len(self._marker)):
            self._marker[index] = 0
        self._closed = True

    def __enter__(self) -> SyntheticPreflightLaunchCapability:
        if self._closed:
            raise RuntimeError("synthetic preflight launch capability is no longer available")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SyntheticPreflightLaunchCapability(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("synthetic preflight launch capabilities cannot be serialized")


def _issue_synthetic_preflight_launch_capability(
    *,
    marker: bytes,
    controller_environment: dict[str, str],
    credential_descriptor: int,
) -> SyntheticPreflightLaunchCapability:
    """Issue from one installed challenge while retaining no caller path."""

    if type(controller_environment) is not dict:
        raise TypeError("controller canary environment must be a plain mapping")
    installed = controller_environment.get(CANARY_ENVIRONMENT_NAME)
    try:
        matches = installed is not None and secrets.compare_digest(
            installed.encode("ascii", errors="strict"),
            marker,
        )
    except UnicodeEncodeError:
        matches = False
    if not matches:
        raise ValueError("controller environment does not contain the installed marker")
    owned = os.dup(credential_descriptor)
    try:
        os.set_inheritable(owned, False)
        return SyntheticPreflightLaunchCapability(
            marker=marker,
            credential_descriptor=owned,
            authority=_LAUNCH_CAPABILITY_AUTHORITY,
        )
    except BaseException:
        with suppress(OSError):
            os.close(owned)
        raise


def _validate_credential_descriptor(
    descriptor: int,
    identity: tuple[int, ...],
    marker: bytes | bytearray,
) -> None:
    metadata = os.fstat(descriptor)
    access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    if (
        _credential_identity(metadata) != identity
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or os.get_inheritable(descriptor)
        or access_mode != os.O_RDWR
    ):
        raise ValueError("synthetic credential descriptor is not private controller state")
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= len(marker):
        chunk = os.read(descriptor, len(marker) + 1 - len(content))
        if not chunk:
            break
        content.extend(chunk)
    if len(content) != len(marker) or not secrets.compare_digest(content, marker):
        raise ValueError("synthetic credential descriptor does not contain the marker")


def _credential_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
