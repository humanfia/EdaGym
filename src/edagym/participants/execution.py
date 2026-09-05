"""Journal-backed locking and crash recovery for participant tools."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from typing import Any, Literal, SupportsIndex, cast
from uuid import UUID

from pydantic import TypeAdapter

import edagym.participant_tool_protocol as tool_protocol
from edagym.canonical import canonical_digest
from edagym.executors.isolation_launch import SyntheticPreflightExecutorReceipt
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.journal import (
    EventConflict,
    InvalidTransition,
    RunJournal,
    active_license_leases,
    participant_tool_dispatches,
    unresolved_tool_requests,
)
from edagym.run.model import (
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    LicenseLeaseLostEvent,
    LicenseLeaseLostPayload,
    ParticipantToolLostEvent,
    ParticipantToolLostPayload,
    ProducerKind,
    RunEvent,
    RunState,
)
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    IsolationSurface,
    RuntimeSurfaceBinding,
)
from edagym.specs.common import Digest, Identifier, Visibility

_SYNTHETIC_PREFLIGHT_GRANT_AUTHORITY = object()
_DIGEST_ADAPTER = TypeAdapter(Digest)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class _SyntheticPreflightExecutionClaim:
    """One-shot descriptor ownership transferred from the trusted launcher."""

    __slots__ = (
        "_artifact_store",
        "_canary_launch_binding_digest",
        "_executor_receipt_digest",
        "_launcher_receipt_digest",
        "_preflight_run_id",
        "_run_binding_digest",
        "_runtime_surface_binding",
        "_surfaces",
    )

    def __init__(
        self,
        *,
        surfaces: tuple[tuple[IsolationSurface, int], ...],
        artifact_store: ContentAddressedStore,
        preflight_run_id: Digest,
        run_binding_digest: Digest,
        runtime_surface_binding: RuntimeSurfaceBinding,
        executor_receipt_digest: Digest,
        launcher_receipt_digest: Digest,
        canary_launch_binding_digest: Digest,
        authority: object,
    ) -> None:
        if authority is not _SYNTHETIC_PREFLIGHT_GRANT_AUTHORITY:
            raise TypeError("synthetic preflight claims are issued only by the launcher grant")
        self._surfaces = surfaces
        self._artifact_store = artifact_store
        self._preflight_run_id = preflight_run_id
        self._run_binding_digest = run_binding_digest
        self._runtime_surface_binding = runtime_surface_binding
        self._executor_receipt_digest = executor_receipt_digest
        self._launcher_receipt_digest = launcher_receipt_digest
        self._canary_launch_binding_digest = canary_launch_binding_digest

    @property
    def artifact_store(self) -> ContentAddressedStore:
        return self._artifact_store

    @property
    def preflight_run_id(self) -> Digest:
        return self._preflight_run_id

    @property
    def run_binding_digest(self) -> Digest:
        return self._run_binding_digest

    @property
    def executor_receipt_digest(self) -> Digest:
        return self._executor_receipt_digest

    @property
    def runtime_surface_binding(self) -> RuntimeSurfaceBinding:
        return self._runtime_surface_binding

    @property
    def launcher_receipt_digest(self) -> Digest:
        return self._launcher_receipt_digest

    @property
    def canary_launch_binding_digest(self) -> Digest:
        return self._canary_launch_binding_digest

    def _take_surfaces(self) -> tuple[tuple[IsolationSurface, int], ...]:
        if not self._surfaces:
            raise RuntimeError("synthetic preflight surface ownership was already transferred")
        surfaces = self._surfaces
        self._surfaces = ()
        return surfaces

    def close(self) -> None:
        surfaces = self._surfaces
        self._surfaces = ()
        for _, descriptor in surfaces:
            with suppress(OSError):
                os.close(descriptor)

    def __repr__(self) -> str:
        return "_SyntheticPreflightExecutionClaim(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("synthetic preflight execution claims cannot be serialized")


class SyntheticPreflightExecutionGrant:
    """Nonserializable ownership of one real preflight's live surface descriptors."""

    __slots__ = (
        "_artifact_store",
        "_canary_launch_binding_digest",
        "_closed",
        "_executor_receipt_digest",
        "_launcher_receipt_digest",
        "_preflight_run_id",
        "_run_binding_digest",
        "_runtime_surface_binding",
        "_surfaces",
    )

    def __init__(
        self,
        *,
        surfaces: tuple[tuple[IsolationSurface, int], ...],
        artifact_store: ContentAddressedStore,
        preflight_run_id: Digest,
        run_binding_digest: Digest,
        runtime_surface_binding: RuntimeSurfaceBinding,
        executor_receipt: SyntheticPreflightExecutorReceipt,
        launcher_receipt_digest: Digest,
        authority: object,
    ) -> None:
        if authority is not _SYNTHETIC_PREFLIGHT_GRANT_AUTHORITY:
            raise TypeError("synthetic preflight grants are issued only by the trusted launcher")
        self._surfaces = surfaces
        self._artifact_store = artifact_store
        self._closed = False
        try:
            self._preflight_run_id = _DIGEST_ADAPTER.validate_python(preflight_run_id)
            self._run_binding_digest = _DIGEST_ADAPTER.validate_python(run_binding_digest)
            if type(runtime_surface_binding) is not RuntimeSurfaceBinding:
                raise TypeError("synthetic preflight grants require the exact surface binding")
            self._runtime_surface_binding = runtime_surface_binding
            if type(executor_receipt) is not SyntheticPreflightExecutorReceipt:
                raise TypeError("synthetic preflight grants require the executor launch receipt")
            self._executor_receipt_digest = executor_receipt.digest
            self._launcher_receipt_digest = _DIGEST_ADAPTER.validate_python(launcher_receipt_digest)
            self._canary_launch_binding_digest = (
                executor_receipt.parent_launch.canary_launch_binding_digest
            )
            if self._preflight_run_id != self._run_binding_digest:
                raise ValueError("synthetic preflight run identity differs from its binding")
            _validate_synthetic_preflight_descriptors(surfaces, artifact_store)
        except BaseException:
            self.close()
            raise

    def _claim(self) -> _SyntheticPreflightExecutionClaim:
        if self._closed:
            raise RuntimeError("synthetic preflight execution grant is no longer available")
        surfaces = self._surfaces
        self._surfaces = ()
        self._closed = True
        return _SyntheticPreflightExecutionClaim(
            surfaces=surfaces,
            artifact_store=self._artifact_store,
            preflight_run_id=self._preflight_run_id,
            run_binding_digest=self._run_binding_digest,
            runtime_surface_binding=self._runtime_surface_binding,
            executor_receipt_digest=self._executor_receipt_digest,
            launcher_receipt_digest=self._launcher_receipt_digest,
            canary_launch_binding_digest=self._canary_launch_binding_digest,
            authority=_SYNTHETIC_PREFLIGHT_GRANT_AUTHORITY,
        )

    def close(self) -> None:
        if self._closed:
            return
        surfaces = self._surfaces
        self._surfaces = ()
        self._closed = True
        for _, descriptor in surfaces:
            with suppress(OSError):
                os.close(descriptor)

    def __enter__(self) -> SyntheticPreflightExecutionGrant:
        if self._closed:
            raise RuntimeError("synthetic preflight execution grant is no longer available")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SyntheticPreflightExecutionGrant(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("synthetic preflight execution grants cannot be serialized")


def _issue_synthetic_preflight_execution_grant(
    *,
    surfaces: tuple[tuple[IsolationSurface, int], ...],
    artifact_store: ContentAddressedStore,
    preflight_run_id: Digest,
    run_binding_digest: Digest,
    runtime_surface_binding: RuntimeSurfaceBinding,
    executor_receipt: SyntheticPreflightExecutorReceipt,
    launcher_receipt_digest: Digest,
) -> SyntheticPreflightExecutionGrant:
    """Private issuance seam used only after the trusted launcher settles a real run."""

    return SyntheticPreflightExecutionGrant(
        surfaces=surfaces,
        artifact_store=artifact_store,
        preflight_run_id=preflight_run_id,
        run_binding_digest=run_binding_digest,
        runtime_surface_binding=runtime_surface_binding,
        executor_receipt=executor_receipt,
        launcher_receipt_digest=launcher_receipt_digest,
        authority=_SYNTHETIC_PREFLIGHT_GRANT_AUTHORITY,
    )


def _validate_synthetic_preflight_descriptors(
    surfaces: tuple[tuple[IsolationSurface, int], ...],
    artifact_store: ContentAddressedStore,
) -> None:
    if type(artifact_store) is not ContentAddressedStore:
        raise TypeError("synthetic preflight grants require the concrete artifact store")
    if tuple(surface for surface, _ in surfaces) != REQUIRED_ISOLATION_SURFACES:
        raise ValueError("synthetic preflight grants require every surface exactly once")
    descriptors = tuple(descriptor for _, descriptor in surfaces)
    if len(descriptors) != len(set(descriptors)) or any(
        type(descriptor) is not int or descriptor < 0 for descriptor in descriptors
    ):
        raise ValueError("synthetic preflight surface descriptors must be distinct")
    identities: set[tuple[int, int]] = set()
    ancestors: list[frozenset[tuple[int, int]]] = []
    for _, descriptor in surfaces:
        metadata = os.fstat(descriptor)
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or os.get_inheritable(descriptor)
            or descriptor_flags & os.O_ACCMODE != os.O_RDONLY
        ):
            raise ValueError(
                "synthetic preflight surfaces must be private owned read-only descriptors"
            )
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in identities:
            raise ValueError("synthetic preflight surfaces cannot alias one object")
        identities.add(identity)
        ancestors.append(_directory_ancestor_identities(descriptor))
    ordered_identities = tuple(
        (metadata.st_dev, metadata.st_ino)
        for _, descriptor in surfaces
        for metadata in (os.fstat(descriptor),)
    )
    if any(
        left in ancestors[right_index] or right in ancestors[left_index]
        for left_index, left in enumerate(ordered_identities)
        for right_index, right in enumerate(ordered_identities[left_index + 1 :], left_index + 1)
    ):
        raise ValueError("synthetic preflight surfaces must be pairwise disjoint")
    artifact_descriptor = dict(surfaces)[IsolationSurface.ARTIFACT_STORE]
    artifact_metadata = os.stat(artifact_store.root, follow_symlinks=False)
    bound_metadata = os.fstat(artifact_descriptor)
    if not stat.S_ISDIR(artifact_metadata.st_mode) or (
        artifact_metadata.st_dev,
        artifact_metadata.st_ino,
    ) != (bound_metadata.st_dev, bound_metadata.st_ino):
        raise ValueError("synthetic preflight artifact descriptor differs from its store")


def _directory_ancestor_identities(descriptor: int) -> frozenset[tuple[int, int]]:
    current = os.dup(descriptor)
    ancestors: set[tuple[int, int]] = set()
    try:
        current_metadata = os.fstat(current)
        current_identity = (current_metadata.st_dev, current_metadata.st_ino)
        while True:
            parent = os.open("..", _DIRECTORY_FLAGS, dir_fd=current)
            parent_metadata = os.fstat(parent)
            parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
            os.close(current)
            current = parent
            if parent_identity == current_identity:
                return frozenset(ancestors)
            if parent_identity in ancestors:
                raise ValueError("synthetic preflight surface ancestry is cyclic")
            ancestors.add(parent_identity)
            current_identity = parent_identity
    finally:
        os.close(current)


@contextmanager
def participant_dispatch_lock(directory: os.PathLike[str]) -> Iterator[None]:
    """Serialize participant dispatch and explicit recovery across processes."""

    directory_descriptor = os.open(
        directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        directory_metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.getuid()
            or stat.S_IMODE(directory_metadata.st_mode) & 0o077
        ):
            raise RuntimeError("participant journal directory is not private")
        lock_descriptor = os.open(
            ".participant-dispatch.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            lock_metadata = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_uid != os.getuid()
                or stat.S_IMODE(lock_metadata.st_mode) & 0o077
            ):
                raise RuntimeError("participant dispatch lock is not private")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock_descriptor)
    finally:
        os.close(directory_descriptor)


def participant_tool_interaction_id(
    owner: Identifier,
    tool_name: Identifier,
    role: Literal["request", "result"],
) -> Identifier:
    """Derive one stable journal interaction identifier."""

    identity = canonical_digest(
        {"owner": owner, "role": role, "tool_name": tool_name},
        domain="participant-tool-interaction-id-v1",
    ).removeprefix("sha256:")
    return f"tool_{role}_{identity[:32]}"


def recover_interrupted_executor_tools(
    *,
    journal: RunJournal,
    fence: Callable[[str], object],
    timestamp: datetime,
    event_id_factory: Callable[[], UUID],
) -> RunState:
    """Fence and close unresolved participant executor requests.

    ``fence`` receives one invocation identity and returns only once that
    invocation's isolation domain is provably empty; raising leaves the request
    open so a later recovery retries it.
    """

    while True:
        pending = unresolved_tool_requests(
            journal.read_events(),
            tool_name=tool_protocol.EXECUTOR_PARTICIPANT_TOOL_NAME,
        )
        if not pending:
            return journal.state()
        request = pending[0]
        invocation_id = tool_protocol.participant_tool_invocation_id(
            journal.header.run_id,
            request.payload.interaction_id,
        )
        dispatch = participant_tool_dispatches(journal.read_events()).get(
            request.payload.interaction_id
        )
        if dispatch is not None and dispatch.reservation.payload.invocation_id != invocation_id:
            raise InvalidTransition(
                "participant tool reservation has the wrong invocation identity"
            )
        if dispatch is None or dispatch.terminal is None:
            fence(invocation_id)
        _close_interrupted_request(
            journal=journal,
            request=request,
            tool_name=tool_protocol.EXECUTOR_PARTICIPANT_TOOL_NAME,
            close_active_dispatch=True,
            timestamp=timestamp,
            event_id_factory=event_id_factory,
        )


def close_interrupted_controller_tools(
    *,
    journal: RunJournal,
    timestamp: datetime,
    event_id_factory: Callable[[], UUID],
) -> RunState:
    """Close unresolved built-in controller tool requests during recovery."""

    while True:
        pending = tuple(
            request
            for request in unresolved_tool_requests(journal.read_events())
            if request.payload.tool_name in tool_protocol.CONTROLLER_PARTICIPANT_TOOL_NAMES
        )
        if not pending:
            return journal.state()
        request = pending[0]
        tool_name = cast(Identifier, request.payload.tool_name)
        _close_interrupted_request(
            journal=journal,
            request=request,
            tool_name=tool_name,
            close_active_dispatch=False,
            timestamp=timestamp,
            event_id_factory=event_id_factory,
        )


def _close_interrupted_request(
    *,
    journal: RunJournal,
    request: InteractionRecordedEvent,
    tool_name: Identifier,
    close_active_dispatch: bool,
    timestamp: datetime,
    event_id_factory: Callable[[], UUID],
) -> None:
    result_interaction_id = participant_tool_interaction_id(
        request.payload.interaction_id,
        tool_name,
        "result",
    )
    while True:
        events = journal.read_events()
        pending_ids = {
            event.payload.interaction_id
            for event in unresolved_tool_requests(
                events,
                tool_name=tool_name,
            )
        }
        if request.payload.interaction_id not in pending_ids:
            return
        prefix: tuple[RunEvent, ...] = ()
        if close_active_dispatch:
            dispatch = participant_tool_dispatches(events).get(request.payload.interaction_id)
            if dispatch is not None and dispatch.terminal is None:
                reservation = dispatch.reservation.payload
                expected_invocation_id = tool_protocol.participant_tool_invocation_id(
                    journal.header.run_id,
                    request.payload.interaction_id,
                )
                if reservation.invocation_id != expected_invocation_id:
                    raise InvalidTransition(
                        "participant tool reservation has the wrong invocation identity"
                    )
                lease = active_license_leases(events).get(reservation.invocation_id)
                license_events: tuple[RunEvent, ...] = ()
                if lease is not None:
                    license_events = (
                        LicenseLeaseLostEvent(
                            run_id=journal.header.run_id,
                            sequence=len(events),
                            event_id=event_id_factory(),
                            timestamp=timestamp,
                            producer=ProducerKind.CONTROLLER,
                            visibility=Visibility.VERIFIER,
                            payload=LicenseLeaseLostPayload(
                                **lease.payload.model_dump(mode="python")
                            ),
                        ),
                    )
                prefix = (
                    *license_events,
                    ParticipantToolLostEvent(
                        run_id=journal.header.run_id,
                        sequence=len(events) + len(license_events),
                        event_id=event_id_factory(),
                        timestamp=timestamp,
                        producer=ProducerKind.CONTROLLER,
                        visibility=Visibility.VERIFIER,
                        payload=ParticipantToolLostPayload(
                            request_interaction_id=reservation.request_interaction_id,
                            invocation_id=reservation.invocation_id,
                            invocation_digest=reservation.invocation_digest,
                        ),
                    ),
                )
        event = InteractionRecordedEvent(
            run_id=journal.header.run_id,
            sequence=len(events) + len(prefix),
            event_id=event_id_factory(),
            timestamp=timestamp,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PARTICIPANT,
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.TOOL_RESULT,
                interaction_id=result_interaction_id,
                related_interaction_id=request.payload.interaction_id,
                tool_name=tool_name,
            ),
        )
        try:
            journal.append_events((*prefix, event))
        except (EventConflict, InvalidTransition) as error:
            if request.payload.interaction_id not in {
                item.payload.interaction_id
                for item in unresolved_tool_requests(
                    journal.read_events(),
                    tool_name=tool_name,
                )
            }:
                return
            if isinstance(error, InvalidTransition):
                raise
        else:
            return
