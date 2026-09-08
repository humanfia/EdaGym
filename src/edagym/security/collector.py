"""Descriptor-bound collection of credential-isolation surfaces."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import IO, TYPE_CHECKING, Any, Protocol, SupportsIndex

from pydantic import TypeAdapter

from edagym.run.artifacts import ContentAddressedStore
from edagym.run.trial_model import (
    HarnessRunActor,
    ProviderRequestStartedEvent,
    ProviderResponseRecordedEvent,
    RunPurpose,
    RunRecord,
)
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    IsolationSurface,
    RuntimeSurfaceBinding,
)
from edagym.security.artifact_closure import (
    ArtifactClosureError,
    RunArtifactClosureReceipt,
    verify_run_artifact_closure,
)
from edagym.security.canary import CanaryExposure, CanaryProtocolError
from edagym.security.runtime_surface import (
    RuntimeSurfaceIdentity,
    RuntimeSurfaceManifest,
    runtime_surface_export_policy_digest,
)
from edagym.specs.common import Digest
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.session import SessionSpec
from edagym.specs.task import TaskSpec

if TYPE_CHECKING:
    from edagym.participants.execution import SyntheticPreflightExecutionGrant

_CHUNK_SIZE = 64 * 1024
_MAX_COLLECTED_BYTES = 4 * 1024 * 1024 * 1024
_MAX_COLLECTED_ENTRIES = 1_000_000
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_COLLECTION_AUTHORITY = object()
_ISSUER_AUTHORITY = object()
_DIGEST_ADAPTER = TypeAdapter(Digest)


class _DigestSink(Protocol):
    def update(self, content: bytes) -> None: ...

    def hexdigest(self) -> str: ...


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    links: int
    owner: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(slots=True)
class _OpenedSurface:
    surface: IsolationSurface
    descriptor: int
    identity: _FileIdentity
    artifact_store: ContentAddressedStore | None = None


@dataclass(slots=True)
class _CollectionBudget:
    bytes_read: int = 0
    entries: int = 0

    def add_entry(self, size: int) -> None:
        self.entries += 1
        self.bytes_read += size
        if self.entries > _MAX_COLLECTED_ENTRIES:
            raise CanaryProtocolError("isolation surface entry limit exceeded")
        if self.bytes_read > _MAX_COLLECTED_BYTES:
            raise CanaryProtocolError("isolation surface byte limit exceeded")


class _MarkerMatcher:
    __slots__ = ("_marker", "_matched", "_prefix")

    def __init__(self, marker: memoryview) -> None:
        if not marker or marker.format != "B" or marker.ndim != 1:
            raise CanaryProtocolError("synthetic marker has an invalid representation")
        self._marker = marker
        self._prefix = self._prefix_table(marker)
        self._matched = 0

    def feed(self, chunk: bytes) -> bool:
        for byte in chunk:
            while self._matched and byte != self._marker[self._matched]:
                self._matched = self._prefix[self._matched - 1]
            if byte == self._marker[self._matched]:
                self._matched += 1
                if self._matched == len(self._marker):
                    return True
        return False

    @staticmethod
    def _prefix_table(marker: memoryview) -> tuple[int, ...]:
        table = [0] * len(marker)
        matched = 0
        for index in range(1, len(marker)):
            while matched and marker[index] != marker[matched]:
                matched = table[matched - 1]
            if marker[index] == marker[matched]:
                matched += 1
            table[index] = matched
        return tuple(table)


class RuntimeSurfaceIssuer:
    """Own a validated preflight record and its already-open surface descriptors."""

    __slots__ = ("_canary_launch_binding_digest", "_closed", "_manifest", "_sources")

    def __init__(
        self,
        *,
        preflight_record: RunRecord,
        task: TaskSpec,
        environment: EnvironmentSpec,
        session: SessionSpec,
        execution_grant: SyntheticPreflightExecutionGrant,
    ) -> None:
        from edagym.participants.execution import (
            SyntheticPreflightExecutionGrant,
            _SyntheticPreflightExecutionClaim,
        )

        if type(execution_grant) is not SyntheticPreflightExecutionGrant:
            raise TypeError("runtime surfaces require the trusted preflight execution grant")
        claim = execution_grant._claim()
        if type(claim) is not _SyntheticPreflightExecutionClaim:
            claim.close()
            raise TypeError("runtime surfaces require the trusted preflight execution claim")
        artifact_store = claim.artifact_store
        binding = claim.runtime_surface_binding
        opened: list[_OpenedSurface] = []
        try:
            artifact_closure = _validate_preflight(
                preflight_record=preflight_record,
                task=task,
                environment=environment,
                session=session,
                binding=binding,
                artifact_store=artifact_store,
            )
            if (
                claim.preflight_run_id != preflight_record.header.run_id
                or claim.run_binding_digest != preflight_record.header.binding.digest
            ):
                raise CanaryProtocolError("preflight execution grant does not match its run record")
            executor_receipt_digest = claim.executor_receipt_digest
            launcher_receipt_digest = claim.launcher_receipt_digest
            canary_launch_binding_digest = claim.canary_launch_binding_digest
            opened = list(_adopt_surface_descriptors(claim._take_surfaces(), artifact_store))
            surface_identities = tuple(_surface_identity(source) for source in opened)
            self._manifest = RuntimeSurfaceManifest(
                preflight_run_id=preflight_record.header.run_id,
                preflight_record_digest=preflight_record.integrity_digest,
                run_binding_digest=preflight_record.header.binding.digest,
                binding=binding,
                executor_receipt_digest=executor_receipt_digest,
                launcher_receipt_digest=launcher_receipt_digest,
                artifact_closure_receipt_digest=artifact_closure.digest,
                artifact_store_identity_digest=(artifact_closure.artifact_store_identity_digest),
                surfaces=surface_identities,
            )
        except BaseException:
            for source in opened:
                _close_surface(source)
            claim.close()
            raise
        claim.close()
        self._sources = tuple(opened)
        self._canary_launch_binding_digest = canary_launch_binding_digest
        self._closed = False

    @property
    def manifest(self) -> RuntimeSurfaceManifest:
        return self._manifest

    def _claim(
        self,
        *,
        authority: object,
    ) -> tuple[RuntimeSurfaceManifest, Digest, tuple[_OpenedSurface, ...]]:
        if authority is not _ISSUER_AUTHORITY:
            raise CanaryProtocolError("runtime surfaces require the trusted collector")
        if self._closed:
            raise CanaryProtocolError("runtime surface issuer is no longer available")
        sources = self._sources
        self._sources = ()
        self._closed = True
        return self._manifest, self._canary_launch_binding_digest, sources

    def close(self) -> None:
        if self._closed:
            return
        for source in self._sources:
            _close_surface(source)
        self._sources = ()
        self._closed = True

    def __enter__(self) -> RuntimeSurfaceIssuer:
        if self._closed:
            raise CanaryProtocolError("runtime surface issuer is no longer available")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "RuntimeSurfaceIssuer(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("runtime surface issuers cannot be serialized")


class IsolationSurfaceCollector:
    """Scan the descriptors owned by one settled preflight issuer exactly once."""

    __slots__ = (
        "_canary_launch_binding_digest",
        "_closed",
        "_manifest",
        "_sources",
        "_used",
    )

    def __init__(self, issuer: RuntimeSurfaceIssuer) -> None:
        if type(issuer) is not RuntimeSurfaceIssuer:
            raise TypeError("isolation collection requires the concrete runtime surface issuer")
        (
            self._manifest,
            self._canary_launch_binding_digest,
            self._sources,
        ) = issuer._claim(authority=_ISSUER_AUTHORITY)
        self._used = False
        self._closed = False

    @property
    def manifest(self) -> RuntimeSurfaceManifest:
        return self._manifest

    def _collect(self, marker: memoryview, *, authority: object) -> Digest:
        if authority is not _COLLECTION_AUTHORITY:
            raise CanaryProtocolError("only a canary challenge can invoke the collector")
        if self._closed or self._used:
            raise CanaryProtocolError("isolation surface collector is no longer available")
        from edagym.executors.isolation_launch import (
            synthetic_preflight_canary_binding_digest,
        )

        if (
            synthetic_preflight_canary_binding_digest(bytes(marker))
            != self._canary_launch_binding_digest
        ):
            raise CanaryProtocolError("preflight launcher did not bind this canary challenge")
        self._used = True
        evidence = hashlib.sha256(b"edagym\x00credential-isolation-collection-v2\x00")
        _evidence_field(evidence, self._manifest.digest.encode("ascii"))
        manifest_identities = {
            identity.surface: identity.identity_digest for identity in self._manifest.surfaces
        }
        budget = _CollectionBudget()
        try:
            for source in self._sources:
                _require_source_binding(source)
                _evidence_field(evidence, source.surface.value.encode("ascii"))
                actual_identity = _surface_identity(source).identity_digest
                if actual_identity != manifest_identities[source.surface]:
                    raise CanaryProtocolError("runtime surface identity differs from its manifest")
                _evidence_field(evidence, actual_identity.encode("ascii"))
                matcher = _MarkerMatcher(marker)
                _scan_opened_source(source, matcher, evidence, budget)
                if source.artifact_store is not None:
                    _scan_artifact_plaintext(
                        source.artifact_store,
                        _MarkerMatcher(marker),
                        evidence,
                        budget,
                    )
                _require_source_binding(source)
            return _DIGEST_ADAPTER.validate_python(f"sha256:{evidence.hexdigest()}")
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        for source in self._sources:
            _close_surface(source)
        self._closed = True

    def __enter__(self) -> IsolationSurfaceCollector:
        if self._closed or self._used:
            raise CanaryProtocolError("isolation surface collector is no longer available")
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "IsolationSurfaceCollector(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("isolation surface collectors cannot be serialized")


def _validate_preflight(
    *,
    preflight_record: RunRecord,
    task: TaskSpec,
    environment: EnvironmentSpec,
    session: SessionSpec,
    binding: RuntimeSurfaceBinding,
    artifact_store: ContentAddressedStore,
) -> RunArtifactClosureReceipt:
    if type(preflight_record) is not RunRecord:
        raise TypeError("runtime surfaces require the concrete preflight run record")
    if type(task) is not TaskSpec:
        raise TypeError("runtime surfaces require the concrete task specification")
    if type(environment) is not EnvironmentSpec:
        raise TypeError("runtime surfaces require the concrete environment specification")
    if type(session) is not SessionSpec:
        raise TypeError("runtime surfaces require the concrete session specification")
    if type(binding) is not RuntimeSurfaceBinding:
        raise TypeError("runtime surfaces require the concrete semantic binding")
    if type(artifact_store) is not ContentAddressedStore:
        raise TypeError("artifact isolation requires the concrete content-addressed store")

    header = preflight_record.header
    campaign = header.binding.campaign
    harness_digests = tuple(
        actor.harness_digest
        for actor in header.binding.session.actors
        if isinstance(actor, HarnessRunActor)
    )
    if campaign is None:
        raise CanaryProtocolError("credential preflight must be bound to one campaign trial")
    if (
        header.binding.purpose is not RunPurpose.SYNTHETIC_PREFLIGHT
        or binding.campaign_digest != campaign.campaign_digest
        or binding.campaign_schedule_digest != campaign.schedule_digest
        or binding.scheduled_trial_digest != campaign.scheduled_trial_digest
        or binding.task_release_digest != header.binding.task.release_digest
        or binding.environment_spec_digest != environment.digest
        or binding.environment_spec_digest != header.binding.environment.environment_spec_digest
        or binding.session_spec_digest != session.digest
        or binding.session_spec_digest != header.binding.session.session_spec_digest
        or binding.executor_digest != environment.executor.implementation_digest
        or binding.executor_digest != header.binding.environment.executor_digest
        or binding.export_policy_digest != runtime_surface_export_policy_digest(environment)
        or harness_digests != (binding.harness_digest,)
    ):
        raise CanaryProtocolError("credential preflight semantics do not match its run record")
    if artifact_store.policy != environment.artifact_policy:
        raise CanaryProtocolError("credential preflight artifact policy does not match its store")

    if any(
        isinstance(event, ProviderRequestStartedEvent | ProviderResponseRecordedEvent)
        for event in preflight_record.events
    ):
        raise CanaryProtocolError("credential preflight cannot contain provider exchanges")
    try:
        return verify_run_artifact_closure(preflight_record, task, artifact_store)
    except ArtifactClosureError as error:
        raise CanaryProtocolError("credential preflight artifact closure is invalid") from error


def _surface_identity(source: _OpenedSurface) -> RuntimeSurfaceIdentity:
    digest = hashlib.sha256(b"edagym\x00runtime-surface-descriptor-identity-v1\x00")
    _evidence_field(digest, source.surface.value.encode("ascii"))
    _evidence_field(digest, _identity_bytes(source.identity))
    return RuntimeSurfaceIdentity(
        surface=source.surface,
        identity_digest=_DIGEST_ADAPTER.validate_python(f"sha256:{digest.hexdigest()}"),
    )


def _adopt_surface_descriptors(
    surfaces: tuple[tuple[IsolationSurface, int], ...],
    artifact_store: ContentAddressedStore,
) -> tuple[_OpenedSurface, ...]:
    opened: list[_OpenedSurface] = []
    try:
        if tuple(surface for surface, _ in surfaces) != REQUIRED_ISOLATION_SURFACES:
            raise CanaryProtocolError("preflight grant does not cover every isolation surface")
        for surface, descriptor in surfaces:
            if type(descriptor) is not int or descriptor < 0:
                raise CanaryProtocolError("preflight grant contains an invalid descriptor")
            metadata = os.fstat(descriptor)
            _require_private_source(metadata)
            if (
                os.get_inheritable(descriptor)
                or (fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE) != os.O_RDONLY
            ):
                raise CanaryProtocolError(
                    "preflight surfaces require non-inheritable read descriptors"
                )
            opened.append(
                _OpenedSurface(
                    surface=surface,
                    descriptor=descriptor,
                    identity=_file_identity(metadata),
                    artifact_store=(
                        artifact_store if surface is IsolationSurface.ARTIFACT_STORE else None
                    ),
                )
            )
        identities = {(source.identity.device, source.identity.inode) for source in opened}
        if len(identities) != len(opened):
            raise CanaryProtocolError("isolation surfaces cannot alias the same object")
        artifact_source = next(
            source for source in opened if source.surface is IsolationSurface.ARTIFACT_STORE
        )
        _require_source_binding(artifact_source)
        return tuple(opened)
    except BaseException:
        for _, descriptor in surfaces:
            with suppress(OSError):
                os.close(descriptor)
        raise


def _close_surface(source: _OpenedSurface) -> None:
    with suppress(OSError):
        os.close(source.descriptor)


def _require_source_binding(source: _OpenedSurface) -> None:
    try:
        current = os.fstat(source.descriptor)
    except OSError as error:
        raise CanaryProtocolError("isolation surface binding is no longer valid") from error
    if _file_identity(current) != source.identity:
        raise CanaryProtocolError("isolation surface binding changed before collection")
    if source.artifact_store is not None:
        try:
            linked = os.stat(source.artifact_store.root, follow_symlinks=False)
        except OSError as error:
            raise CanaryProtocolError("artifact store binding is no longer valid") from error
        if _file_identity(linked) != source.identity:
            raise CanaryProtocolError("artifact store path changed before collection")


def _scan_opened_source(
    source: _OpenedSurface,
    matcher: _MarkerMatcher,
    evidence: _DigestSink,
    budget: _CollectionBudget,
) -> None:
    metadata = os.fstat(source.descriptor)
    if _file_identity(metadata) != source.identity:
        raise CanaryProtocolError("isolation surface changed before collection")
    if stat.S_ISDIR(metadata.st_mode):
        _scan_directory(
            source.descriptor,
            prefix=PurePosixPath(),
            matcher=matcher,
            evidence=evidence,
            budget=budget,
        )
    else:
        _evidence_field(evidence, b"file")
        _scan_file(source.descriptor, metadata, matcher, evidence, budget)
    if _file_identity(os.fstat(source.descriptor)) != source.identity:
        raise CanaryProtocolError("isolation surface changed during collection")


def _scan_directory(
    descriptor: int,
    *,
    prefix: PurePosixPath,
    matcher: _MarkerMatcher,
    evidence: _DigestSink,
    budget: _CollectionBudget,
) -> None:
    before = _file_identity(os.fstat(descriptor))
    names = _directory_names(descriptor)
    for name in names:
        relative = prefix / name
        try:
            encoded_path = relative.as_posix().encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CanaryProtocolError("isolation surface contains an invalid path") from error
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise CanaryProtocolError("isolation surface entry cannot be inspected") from error
        _require_private_source(metadata)
        _evidence_field(evidence, encoded_path)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                if _file_identity(os.fstat(child)) != _file_identity(metadata):
                    raise CanaryProtocolError("isolation surface directory changed while opened")
                budget.add_entry(0)
                _evidence_field(evidence, b"directory")
                _scan_directory(
                    child,
                    prefix=relative,
                    matcher=matcher,
                    evidence=evidence,
                    budget=budget,
                )
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode):
            child = os.open(name, _FILE_FLAGS, dir_fd=descriptor)
            try:
                if _file_identity(os.fstat(child)) != _file_identity(metadata):
                    raise CanaryProtocolError("isolation surface file changed while opened")
                _evidence_field(evidence, b"file")
                _scan_file(child, metadata, matcher, evidence, budget)
            finally:
                os.close(child)
        else:
            raise CanaryProtocolError("isolation surfaces may contain only files and directories")
    if names != _directory_names(descriptor) or before != _file_identity(os.fstat(descriptor)):
        raise CanaryProtocolError("isolation surface directory changed during collection")


def _scan_file(
    descriptor: int,
    metadata: os.stat_result,
    matcher: _MarkerMatcher,
    evidence: _DigestSink,
    budget: _CollectionBudget,
) -> None:
    before = _file_identity(metadata)
    if metadata.st_nlink != 1:
        raise CanaryProtocolError("isolation surface files cannot have multiple links")
    budget.add_entry(metadata.st_size)
    evidence.update(metadata.st_size.to_bytes(8, byteorder="big"))
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = metadata.st_size
    while remaining:
        chunk = os.read(descriptor, min(_CHUNK_SIZE, remaining))
        if not chunk:
            raise CanaryProtocolError("isolation surface file ended during collection")
        remaining -= len(chunk)
        if matcher.feed(chunk):
            raise CanaryExposure("synthetic credential marker escaped isolation")
        evidence.update(chunk)
    if os.read(descriptor, 1):
        raise CanaryProtocolError("isolation surface file grew during collection")
    if before != _file_identity(os.fstat(descriptor)):
        raise CanaryProtocolError("isolation surface file changed during collection")


def _scan_artifact_plaintext(
    store: ContentAddressedStore,
    matcher: _MarkerMatcher,
    evidence: _DigestSink,
    budget: _CollectionBudget,
) -> None:
    _evidence_field(evidence, b"verified-artifact-plaintext")
    with store.stable_plaintext_blobs() as blobs:
        for reference, stream in blobs:
            _evidence_field(evidence, reference.digest.encode("ascii"))
            _scan_artifact_reader(stream, reference.size_bytes, matcher, evidence, budget)


def _scan_artifact_reader(
    stream: IO[bytes],
    size: int,
    matcher: _MarkerMatcher,
    evidence: _DigestSink,
    budget: _CollectionBudget,
) -> None:
    budget.add_entry(size)
    evidence.update(size.to_bytes(8, byteorder="big"))
    remaining = size
    while remaining:
        chunk = stream.read(min(_CHUNK_SIZE, remaining))
        if not chunk:
            raise CanaryProtocolError("verified artifact ended during collection")
        remaining -= len(chunk)
        if matcher.feed(chunk):
            raise CanaryExposure("synthetic credential marker escaped isolation")
        evidence.update(chunk)
    if stream.read(1):
        raise CanaryProtocolError("verified artifact exceeded its bound")


def _evidence_field(evidence: _DigestSink, content: bytes) -> None:
    evidence.update(len(content).to_bytes(8, byteorder="big"))
    evidence.update(content)


def _directory_names(descriptor: int) -> tuple[str, ...]:
    try:
        names = os.listdir(descriptor)
    except OSError as error:
        raise CanaryProtocolError("isolation surface directory cannot be listed") from error
    if any(name in {"", ".", ".."} or "/" in name for name in names):
        raise CanaryProtocolError("isolation surface contains an invalid entry name")
    return tuple(sorted(names))


def _require_private_source(metadata: os.stat_result) -> None:
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise CanaryProtocolError("isolation sources must be files or directories")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CanaryProtocolError("isolation sources must be private and owned")


def _file_identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        owner=metadata.st_uid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _identity_bytes(identity: _FileIdentity) -> bytes:
    try:
        return b"".join(
            value.to_bytes(8, byteorder="big")
            for value in (
                identity.device,
                identity.inode,
                identity.mode,
                identity.links,
                identity.owner,
                identity.size,
                identity.modified_ns,
                identity.changed_ns,
            )
        )
    except OverflowError as error:
        raise CanaryProtocolError("isolation source identity is outside its domain") from error
