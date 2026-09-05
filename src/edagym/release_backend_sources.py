"""Descriptor-stable private source registry for backend release qualification."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Never, Self, SupportsIndex

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers.deployment import BackendDeploymentRegistry
from edagym.drivers.model import BackendCatalog
from edagym.drivers.qualification import BackendQualification
from edagym.drivers.qualification_verification import (
    QualificationSourceKind,
    VerifiedBackendQualificationSource,
    verify_backend_qualification_source,
)
from edagym.policy.private_roots import (
    PrivateRootRegistration,
    PrivateRootRole,
    _bind_private_root_from_descriptor,
)
from edagym.run.artifacts import (
    ContentAddressedStore,
    EncryptionKey,
    encryption_key_from_file_descriptor,
)
from edagym.specs.common import (
    Capability,
    Digest,
    Identifier,
    SchemaVersion,
    StrictModel,
    validate_relative_path,
)
from edagym.specs.environment import EnvironmentSpec, ManagedEncryption

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
_MAXIMUM_REGISTRY_BYTES = 4 << 20
_MAXIMUM_DOCUMENT_BYTES = 64 << 20
_SOURCE_ISSUER = object()


class BackendQualificationSourceEntry(StrictModel):
    """One exact capability partition and its root-relative private sources."""

    tool_id: Identifier
    capability: Capability
    source_kind: QualificationSourceKind
    qualification_path: str
    qualification_digest: Digest
    environment_path: str | None = None
    environment_digest: Digest | None = None
    artifact_store_path: str | None = None
    artifact_key_path: str | None = None

    @field_validator(
        "qualification_path",
        "environment_path",
        "artifact_store_path",
        "artifact_key_path",
    )
    @classmethod
    def normalize_relative_paths(cls, value: str | None) -> str | None:
        return None if value is None else validate_relative_path(value)

    @model_validator(mode="after")
    def validate_source_shape(self) -> Self:
        evidence_source = self.source_kind is QualificationSourceKind.EVIDENCE_PAIR
        evidence_fields = (
            self.environment_path,
            self.environment_digest,
            self.artifact_store_path,
        )
        if (
            evidence_source and any(value is None for value in evidence_fields)
        ) or (
            not evidence_source and any(value is not None for value in evidence_fields)
        ):
            raise ValueError("backend evidence sources require environment and CAS locators")
        if not evidence_source and self.artifact_key_path is not None:
            raise ValueError("backend gap sources cannot carry an artifact key")
        return self


class BackendQualificationSourceRegistryDocument(StrictModel):
    """Private, path-bearing inventory; never part of the public release report."""

    schema_version: SchemaVersion = 1
    backend_catalog_digest: Digest
    backend_deployment_source_digest: Digest
    entries: Annotated[tuple[BackendQualificationSourceEntry, ...], Field(min_length=1)]

    @field_validator("entries")
    @classmethod
    def normalize_entries(
        cls,
        value: tuple[BackendQualificationSourceEntry, ...],
    ) -> tuple[BackendQualificationSourceEntry, ...]:
        identities = [(item.tool_id, item.capability) for item in value]
        qualification_paths = [item.qualification_path for item in value]
        evidence = tuple(
            item for item in value if item.source_kind is QualificationSourceKind.EVIDENCE_PAIR
        )
        environment_paths = [item.environment_path for item in evidence]
        store_paths = [item.artifact_store_path for item in evidence]
        if (
            len(identities) != len(set(identities))
            or len(qualification_paths) != len(set(qualification_paths))
            or len(environment_paths) != len(set(environment_paths))
            or len(store_paths) != len(set(store_paths))
        ):
            raise ValueError("backend source registry entries require unique source identities")
        return tuple(sorted(value, key=lambda item: (item.tool_id, item.capability.value)))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="backend-qualification-source-registry-v1")


class VerifiedBackendQualificationSources:
    """Process-local verified sources plus their one-shot private-root authorities."""

    __slots__ = (
        "_private_root_registrations",
        "deployment_source_digest",
        "registry_digest",
        "sources",
    )

    def __init__(
        self,
        token: object,
        *,
        sources: tuple[VerifiedBackendQualificationSource, ...],
        registry_digest: Digest,
        deployment_source_digest: Digest,
        private_root_registrations: tuple[PrivateRootRegistration, ...],
    ) -> None:
        if token is not _SOURCE_ISSUER:
            raise TypeError("backend source authorities require the canonical live loader")
        self.sources = sources
        self.registry_digest = registry_digest
        self.deployment_source_digest = deployment_source_digest
        self._private_root_registrations = private_root_registrations

    @property
    def private_root_registrations(self) -> tuple[PrivateRootRegistration, ...]:
        return self._private_root_registrations

    def close(self) -> None:
        for registration in self._private_root_registrations:
            registration.close()

    def __del__(self) -> None:
        self.close()

    def __reduce__(self) -> Never:
        raise TypeError("verified backend source authorities cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified backend source authorities cannot be serialized")


def load_backend_qualification_sources(
    registry_path: Path,
    *,
    catalog: BackendCatalog,
    deployment_registry: BackendDeploymentRegistry,
) -> VerifiedBackendQualificationSources:
    """Load and live-verify every exact backend capability source once."""

    if type(catalog) is not BackendCatalog:
        raise TypeError("backend source loading requires the concrete public catalog")
    root_path = registry_path.absolute().parent
    root_descriptor = os.open(root_path, _DIRECTORY_FLAGS)
    registrations: list[PrivateRootRegistration] = []
    try:
        _require_private_node(os.fstat(root_descriptor), directory=True)
        registry_descriptor = _open_relative(
            root_descriptor,
            registry_path.name,
            directory=False,
        )
        try:
            registry_content = _read_stable_file(
                registry_descriptor,
                maximum_bytes=_MAXIMUM_REGISTRY_BYTES,
            )
        finally:
            os.close(registry_descriptor)
        document = _decode_registry(registry_content)
        deployment_registration = deployment_registry.source_registration()
        registrations.append(deployment_registration)
        expected_pairs = {
            (definition.tool_id, capability)
            for definition in catalog.backends
            for capability in definition.capabilities
        }
        if (
            document.backend_catalog_digest != catalog.digest
            or document.backend_deployment_source_digest
            != deployment_registration.source_identity_digest
            or {(item.tool_id, item.capability) for item in document.entries}
            != expected_pairs
        ):
            raise ValueError("backend source registry differs from its live authorities")
        registrations.append(
            _bind_private_root_from_descriptor(
                PrivateRootRole.BACKEND_QUALIFICATION_SOURCE_REGISTRY,
                root_descriptor,
                document.digest,
            )
        )
        definitions = {item.tool_id: item for item in catalog.backends}
        verified: list[VerifiedBackendQualificationSource] = []
        for entry in document.entries:
            definition = definitions[entry.tool_id]
            qualification = _read_model(
                root_descriptor,
                entry.qualification_path,
                BackendQualification,
            )
            if (
                qualification.digest != entry.qualification_digest
                or qualification.requested_capabilities != (entry.capability,)
            ):
                raise ValueError("backend qualification differs from its registry entry")
            deployment = deployment_registry.configuration_for(entry.tool_id)
            if entry.source_kind is QualificationSourceKind.LIVE_PROBE_GAP:
                source = verify_backend_qualification_source(
                    qualification,
                    definition=definition,
                    deployment_configuration=deployment,
                )
            else:
                assert entry.environment_path is not None
                assert entry.environment_digest is not None
                assert entry.artifact_store_path is not None
                environment = _read_model(
                    root_descriptor,
                    entry.environment_path,
                    EnvironmentSpec,
                )
                if environment.digest != entry.environment_digest:
                    raise ValueError("backend environment differs from its registry entry")
                store_descriptor = _open_relative(
                    root_descriptor,
                    entry.artifact_store_path,
                    directory=True,
                )
                try:
                    store_path = root_path / entry.artifact_store_path
                    _require_same_node(store_descriptor, store_path)
                    key = _artifact_key(root_descriptor, entry, environment)
                    store = ContentAddressedStore(
                        store_path,
                        policy=environment.artifact_policy,
                        encryption_key=key,
                    )
                    source = verify_backend_qualification_source(
                        qualification,
                        definition=definition,
                        environment=environment,
                        artifact_store=store,
                        deployment_configuration=deployment,
                    )
                    _require_same_node(store_descriptor, store_path)
                    registrations.append(
                        _bind_private_root_from_descriptor(
                            PrivateRootRole.BACKEND_QUALIFICATION_STORE,
                            store_descriptor,
                            source.source_digest,
                        )
                    )
                finally:
                    os.close(store_descriptor)
            if source.source_kind is not entry.source_kind:
                raise ValueError("backend source kind differs from live verification")
            verified.append(source)
        if not deployment_registry.revalidate():
            raise ValueError("backend deployment registry changed during source verification")
        current_registry = _read_relative_file(
            root_descriptor,
            registry_path.name,
            maximum_bytes=_MAXIMUM_REGISTRY_BYTES,
        )
        if current_registry != registry_content:
            raise ValueError("backend source registry changed during verification")
        return VerifiedBackendQualificationSources(
            _SOURCE_ISSUER,
            sources=tuple(verified),
            registry_digest=document.digest,
            deployment_source_digest=deployment_registration.source_identity_digest,
            private_root_registrations=tuple(registrations),
        )
    except BaseException:
        for registration in registrations:
            registration.close()
        raise
    finally:
        os.close(root_descriptor)


def _decode_registry(content: bytes) -> BackendQualificationSourceRegistryDocument:
    try:
        decoded = json.loads(content, object_pairs_hook=_unique_object)
        document = BackendQualificationSourceRegistryDocument.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("backend source registry is not canonical JSON") from None
    if canonical_bytes(document) != content:
        raise ValueError("backend source registry bytes are not canonical")
    return document


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("backend source registry contains a duplicate key")
        result[key] = value
    return result


def _read_model[T: StrictModel](
    root_descriptor: int,
    relative_path: str,
    expected: type[T],
) -> T:
    content = _read_relative_file(
        root_descriptor,
        relative_path,
        maximum_bytes=_MAXIMUM_DOCUMENT_BYTES,
    )
    try:
        decoded = json.loads(content, object_pairs_hook=_unique_object)
        return expected.model_validate(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("backend source document is not valid JSON") from None


def _read_relative_file(
    root_descriptor: int,
    relative_path: str,
    *,
    maximum_bytes: int,
) -> bytes:
    descriptor = _open_relative(root_descriptor, relative_path, directory=False)
    try:
        return _read_stable_file(descriptor, maximum_bytes=maximum_bytes)
    finally:
        os.close(descriptor)


def _read_stable_file(descriptor: int, *, maximum_bytes: int) -> bytes:
    metadata = os.fstat(descriptor)
    _require_private_node(metadata, directory=False)
    if metadata.st_size > maximum_bytes:
        raise ValueError("backend source document exceeds its bounded size")
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = bytearray()
    while len(content) <= maximum_bytes:
        chunk = os.read(descriptor, min(1 << 20, maximum_bytes + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if len(content) != metadata.st_size or _file_identity(os.fstat(descriptor)) != _file_identity(
        metadata
    ):
        raise ValueError("backend source document changed while reading")
    return bytes(content)


def _open_relative(
    root_descriptor: int,
    relative_path: str,
    *,
    directory: bool,
) -> int:
    parts = PurePosixPath(validate_relative_path(relative_path)).parts
    descriptor = os.dup(root_descriptor)
    try:
        for component in parts[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                _require_private_node(os.fstat(child), directory=True)
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        flags = _DIRECTORY_FLAGS if directory else _FILE_FLAGS
        result = os.open(parts[-1], flags, dir_fd=descriptor)
        try:
            _require_private_node(os.fstat(result), directory=directory)
        except BaseException:
            os.close(result)
            raise
        return result
    finally:
        os.close(descriptor)


def _artifact_key(
    root_descriptor: int,
    entry: BackendQualificationSourceEntry,
    environment: EnvironmentSpec,
) -> EncryptionKey | None:
    encryption = environment.artifact_policy.encryption
    if isinstance(encryption, ManagedEncryption):
        if entry.artifact_key_path is None:
            raise ValueError("managed backend qualification store requires its key locator")
        descriptor = _open_relative(
            root_descriptor,
            entry.artifact_key_path,
            directory=False,
        )
        try:
            return encryption_key_from_file_descriptor(
                key_id=encryption.provider_id,
                descriptor=descriptor,
            )
        finally:
            os.close(descriptor)
    if entry.artifact_key_path is not None:
        raise ValueError("unencrypted backend qualification store cannot carry a key")
    return None


def _require_private_node(metadata: os.stat_result, *, directory: bool) -> None:
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    required_mode = 0o700 if directory else 0o600
    if (
        not expected
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != required_mode
        or (not directory and metadata.st_nlink != 1)
    ):
        raise ValueError("backend source registry contains an unsafe private node")


def _require_same_node(descriptor: int, path: Path) -> None:
    opened = os.fstat(descriptor)
    linked = os.stat(path, follow_symlinks=False)
    if _file_identity(opened) != _file_identity(linked):
        raise ValueError("backend artifact store path changed during verification")


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
