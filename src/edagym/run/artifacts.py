"""Policy-bound content-addressed artifacts and committed checkpoints."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Generator, Iterable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import IO, Literal, Never, Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import AEADEncryptionContext
from pydantic import ValidationError, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.policy.runtime_storage import (
    PrivateStorageError,
    private_directory,
    read_private,
    write_private,
)
from edagym.policy.secrets import (
    CONTENT_RULES,
    RESTRICTED_CONTENT_RULES,
    ContentRuleScanner,
)
from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
    BlobRef,
    CommittedManifest,
    ManifestEntry,
)
from edagym.specs.common import (
    ArtifactClass,
    CanonicalDecimal,
    Digest,
    Identifier,
    Redistribution,
    SchemaVersion,
    Seed128Hex,
    Sensitivity,
    StrictModel,
    Visibility,
    validate_relative_path,
)
from edagym.specs.environment import (
    PROTECTED_RAW_DISCLOSURE,
    RAW_EDA_ARTIFACT_CLASSES,
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    CheckpointCapability,
    EncryptionKind,
    ManagedEncryption,
)
from edagym.specs.task import MeasurementUnit

_CHUNK_SIZE = 1024 * 1024
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_ENVELOPE_MAGIC = b"EDAGYMB1"
_MODE_PLAINTEXT = b"P"
_MODE_ENCRYPTED = b"E"
_NONCE_SIZE = 12
_TAG_SIZE = 16
_HEADER_SIZE = len(_ENVELOPE_MAGIC) + 1 + _NONCE_SIZE + _TAG_SIZE
_ENCRYPTION_KEY_BYTES = 32
PRIVATE_ARTIFACT_KEY_PROVIDER_ID: Identifier = "edagym_private_cas"
ARTIFACT_MANIFEST_MEDIA_TYPE = "application/vnd.edagym.artifact-manifest+json"
SANITIZED_MEASUREMENTS_MEDIA_TYPE = "application/vnd.edagym.measurements+json"
RAW_MEASUREMENT_LINKS_MEDIA_TYPE = "application/vnd.edagym.raw-measurement-links+json"


def candidate_snapshot_artifact_id(run_id: Digest, candidate_id: Identifier) -> Identifier:
    """Derive the sole artifact identifier for one immutable candidate snapshot."""

    identity = canonical_digest(
        {"candidate_id": candidate_id, "run_id": run_id},
        domain="candidate-snapshot-artifact-id-v1",
    )
    return f"candidate_snapshot_{identity.removeprefix('sha256:')}"


class ArtifactStoreError(RuntimeError):
    """Base class for artifact integrity and policy failures."""


class ArtifactIntegrityError(ArtifactStoreError):
    """Stored bytes do not match their immutable content identity."""


class ArtifactQuotaExceeded(ArtifactStoreError):
    """A write would exceed the resolved artifact policy quota."""


class ArtifactPolicyViolation(ArtifactStoreError):
    """An artifact is not persistable under the resolved environment policy."""


def artifact_policy_digest(policy: ArtifactPolicy) -> Digest:
    """Return the canonical identity of one exact artifact policy."""

    if type(policy) is not ArtifactPolicy:
        raise TypeError("artifact policy identity requires a concrete ArtifactPolicy")
    return canonical_digest(policy, domain="artifact-policy-v1")


class EncryptionKey:
    """Process-local AES-256 material identified only by a non-secret key ID."""

    __slots__ = ("_value", "key_id")

    def __init__(self, *, key_id: str, value: bytes) -> None:
        if len(value) != _ENCRYPTION_KEY_BYTES:
            raise ValueError("artifact encryption requires a 32-byte key")
        if not key_id or not key_id[0].isalpha() or not key_id.replace("_", "").isalnum():
            raise ValueError("artifact key ID must be a normalized identifier")
        self.key_id = key_id
        self._value = bytes(value)

    def __repr__(self) -> str:
        return f"EncryptionKey(key_id={self.key_id!r}, value=<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("encryption keys cannot be serialized")

    def _cipher_bytes(self) -> bytes:
        return self._value


def encryption_key_from_file_descriptor(
    *,
    key_id: Identifier,
    descriptor: int,
) -> EncryptionKey:
    """Read one stable owner-only AES-256 key from an already-open file."""

    owned_descriptor = os.dup(descriptor)
    try:
        metadata = os.fstat(owned_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != _FILE_MODE
            or metadata.st_size != _ENCRYPTION_KEY_BYTES
        ):
            raise ArtifactPolicyViolation(
                "artifact encryption key must be one owner-only regular file"
            )
        os.lseek(owned_descriptor, 0, os.SEEK_SET)
        value = _read_exact_fd(owned_descriptor, _ENCRYPTION_KEY_BYTES)
        if os.read(owned_descriptor, 1) or _private_key_identity(
            os.fstat(owned_descriptor)
        ) != _private_key_identity(metadata):
            raise ArtifactIntegrityError("artifact encryption key changed while reading")
        return EncryptionKey(key_id=key_id, value=value)
    finally:
        os.close(owned_descriptor)


class StoreMetadata(StrictModel):
    schema_version: SchemaVersion = 1
    format: Literal["envelope-v1"] = "envelope-v1"
    policy_digest: Digest
    encryption: EncryptionKind
    key_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_key_identity(self) -> Self:
        requires_key = self.encryption is EncryptionKind.MANAGED
        if requires_key != (self.key_id is not None):
            raise ValueError("managed store encryption requires exactly one key ID")
        return self


class CheckpointMarker(StrictModel):
    schema_version: SchemaVersion = 1
    checkpoint_kind: Literal[
        CheckpointCapability.APPLICATION,
        CheckpointCapability.FILESYSTEM,
    ]
    checkpoint_id: Identifier
    manifest_digest: Digest
    manifest_blob: BlobRef
    driver_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_driver_binding(self) -> Self:
        if (self.checkpoint_kind is CheckpointCapability.APPLICATION) != (
            self.driver_digest is not None
        ):
            raise ValueError("application checkpoints require exactly one driver identity")
        return self


class RetainedArtifact(StrictModel):
    record: ArtifactRecord
    recorded_at: datetime
    checkpoint_pinned: bool = False

    @field_validator("recorded_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("artifact retention timestamps must be timezone-aware")
        return value.astimezone(UTC)


class SanitizedMeasurement(StrictModel):
    """One typed numeric result with no raw report or commercial-library content."""

    measurement_id: Identifier
    unit: MeasurementUnit
    samples: tuple[CanonicalDecimal, ...]
    sample_seeds: tuple[Seed128Hex, ...]

    @field_validator("samples")
    @classmethod
    def require_samples(
        cls,
        value: tuple[CanonicalDecimal, ...],
    ) -> tuple[CanonicalDecimal, ...]:
        if not value:
            raise ValueError("sanitized measurements require at least one sample")
        return value

    @model_validator(mode="after")
    def validate_sample_seeds(self) -> Self:
        if len(self.sample_seeds) != len(self.samples) or len(self.sample_seeds) != len(
            set(self.sample_seeds)
        ):
            raise ValueError("sanitized samples require unique one-to-one seeds")
        return self


class SanitizedMeasurements(StrictModel):
    """Canonical artifact safe for policy-controlled participant or public disclosure."""

    schema_version: SchemaVersion = 1
    stage_id: Identifier
    measurements: tuple[SanitizedMeasurement, ...]

    @field_validator("measurements")
    @classmethod
    def normalize_measurements(
        cls,
        value: tuple[SanitizedMeasurement, ...],
    ) -> tuple[SanitizedMeasurement, ...]:
        identifiers = [measurement.measurement_id for measurement in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("sanitized measurement identifiers must be unique and non-empty")
        return tuple(sorted(value, key=lambda measurement: measurement.measurement_id))


class RawMeasurementLink(StrictModel):
    measurement_id: Identifier
    source_artifact_id: Identifier
    source_digest: Digest


class RawMeasurementLinks(StrictModel):
    """Author-only mapping from sanitized measurements back to native evidence."""

    schema_version: SchemaVersion = 1
    sanitized_artifact_id: Identifier
    sanitized_digest: Digest
    links: tuple[RawMeasurementLink, ...]

    @field_validator("links")
    @classmethod
    def normalize_links(
        cls,
        value: tuple[RawMeasurementLink, ...],
    ) -> tuple[RawMeasurementLink, ...]:
        identifiers = [link.measurement_id for link in value]
        if not value or len(identifiers) != len(set(identifiers)):
            raise ValueError("raw measurement links must be unique and non-empty")
        return tuple(sorted(value, key=lambda link: link.measurement_id))


class ContentAddressedStore:
    """Owner-only CAS whose format, encryption, quota, and disclosure are immutable."""

    @classmethod
    def open_private(cls, root: Path, *, policy: ArtifactPolicy) -> Self:
        """Create or reopen a local encrypted store with a durable owner-only key.

        The key is a sibling of the CAS, never an artifact. Reopening a store
        requires its existing key; losing one must not silently rotate it.
        """

        encryption = policy.encryption
        if (
            not isinstance(encryption, ManagedEncryption)
            or encryption.provider_id != PRIVATE_ARTIFACT_KEY_PROVIDER_ID
        ):
            raise ArtifactPolicyViolation("private CAS requires its local key provider")
        parent = private_directory(root.parent, create=True)
        root = parent / root.name
        key_path = parent / f"{root.name}.key"
        if not key_path.exists():
            if root.exists() and any(private_directory(root).iterdir()) and not key_path.exists():
                raise ArtifactPolicyViolation("an existing private CAS cannot replace its key")
            try:
                write_private(key_path, os.urandom(_ENCRYPTION_KEY_BYTES))
            except PrivateStorageError:
                # Another opener may have atomically published the key first.
                if not key_path.exists():
                    raise
        key = EncryptionKey(
            key_id=encryption.provider_id,
            value=read_private(key_path, max_bytes=_ENCRYPTION_KEY_BYTES),
        )
        return cls(root, policy=policy, encryption_key=key)

    def __init__(
        self,
        root: Path,
        *,
        policy: ArtifactPolicy,
        encryption_key: EncryptionKey | None = None,
    ) -> None:
        self.root = root
        self.policy = policy
        self.policy_digest = artifact_policy_digest(policy)
        self.blob_root = root / "blobs"
        self.checkpoint_root = root / "checkpoints"
        self.lock_path = root / "store.lock"
        self.metadata_path = root / "store.json"
        self._encryption_key = encryption_key
        if isinstance(policy.encryption, ManagedEncryption):
            if encryption_key is None:
                raise ArtifactPolicyViolation("managed encryption requires a process-local key")
            key_id = encryption_key.key_id
        else:
            if encryption_key is not None:
                raise ArtifactPolicyViolation(
                    "an unencrypted policy cannot accept an encryption key"
                )
            key_id = None
        self.metadata = StoreMetadata(
            policy_digest=self.policy_digest,
            encryption=policy.encryption.kind,
            key_id=key_id,
        )
        self._initialize()

    @property
    def encrypted(self) -> bool:
        return self.metadata.encryption is EncryptionKind.MANAGED

    def put_bytes(
        self,
        content: bytes,
        *,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> BlobRef:
        return self.put_chunks(
            (content,),
            artifact_class=artifact_class,
            sensitivity=sensitivity,
            visibility=visibility,
            redistribution=redistribution,
        )

    def put_file(
        self,
        path: Path,
        *,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> BlobRef:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            return self.put_file_descriptor(
                descriptor,
                artifact_class=artifact_class,
                sensitivity=sensitivity,
                visibility=visibility,
                redistribution=redistribution,
            )
        finally:
            os.close(descriptor)

    def put_file_descriptor(
        self,
        descriptor: int,
        *,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> BlobRef:
        """Store one already-open regular file without resolving another path."""

        owned_descriptor = os.dup(descriptor)
        try:
            metadata = os.fstat(owned_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ArtifactStoreError("only regular files can become artifacts")
            os.lseek(owned_descriptor, 0, os.SEEK_SET)

            def chunks() -> Iterator[bytes]:
                while chunk := os.read(owned_descriptor, _CHUNK_SIZE):
                    yield chunk
                if _file_identity(os.fstat(owned_descriptor)) != _file_identity(metadata):
                    raise ArtifactIntegrityError("artifact source changed while it was read")

            return self.put_chunks(
                chunks(),
                artifact_class=artifact_class,
                sensitivity=sensitivity,
                visibility=visibility,
                redistribution=redistribution,
            )
        finally:
            os.close(owned_descriptor)

    def put_chunks(
        self,
        chunks: Iterable[bytes],
        *,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> BlobRef:
        self._require_disclosure(
            artifact_class,
            sensitivity,
            visibility,
            redistribution,
        )
        credential_scanner = ContentRuleScanner(CONTENT_RULES)
        restricted_scanner = ContentRuleScanner(RESTRICTED_CONTENT_RULES)
        restricted_content_allowed = self._restricted_content_allowed(
            artifact_class,
            sensitivity,
            visibility,
            redistribution,
        )
        with self._exclusive_lock():
            used = self._stored_bytes_unlocked()
            descriptor, temporary_name = tempfile.mkstemp(prefix="incoming-", dir=self.root)
            temporary = Path(temporary_name)
            os.chmod(temporary, _FILE_MODE)
            digest = hashlib.sha256()
            size = 0
            try:
                with os.fdopen(descriptor, "w+b") as stream:
                    encryptor = self._start_envelope(stream)
                    for chunk in chunks:
                        if not isinstance(chunk, bytes):
                            raise TypeError("artifact chunks must be bytes")
                        self._scan_disclosure_chunk(
                            chunk,
                            credential_scanner=credential_scanner,
                            restricted_scanner=restricted_scanner,
                            restricted_content_allowed=restricted_content_allowed,
                        )
                        digest.update(chunk)
                        size += len(chunk)
                        encoded = chunk if encryptor is None else encryptor.update(chunk)
                        _write_all(stream, encoded)
                        if used + stream.tell() > self.policy.quota_bytes:
                            raise ArtifactQuotaExceeded("artifact store quota would be exceeded")
                    if encryptor is not None:
                        _write_all(stream, encryptor.finalize())
                        stream.seek(len(_ENVELOPE_MAGIC) + 1 + _NONCE_SIZE)
                        _write_all(stream, encryptor.tag)
                    stream.flush()
                    if used + os.fstat(stream.fileno()).st_size > self.policy.quota_bytes:
                        raise ArtifactQuotaExceeded("artifact store quota would be exceeded")
                    os.fsync(stream.fileno())

                blob = BlobRef(
                    digest=f"sha256:{digest.hexdigest()}",
                    size_bytes=size,
                )
                destination = self._blob_path(blob.digest, create_shard=True)
                try:
                    os.link(temporary, destination, follow_symlinks=False)
                    _fsync_directory(destination.parent)
                except FileExistsError:
                    self.verify(blob)
                temporary.unlink()
                _fsync_directory(self.root)
                return blob
            finally:
                with suppress(FileNotFoundError):
                    temporary.unlink()

    def read_bytes(self, reference: BlobRef, *, maximum_bytes: int) -> bytes:
        if maximum_bytes < 0:
            raise ValueError("maximum_bytes cannot be negative")
        with self._verified_plaintext(reference, maximum_bytes=maximum_bytes) as stream:
            return stream.read()

    def read_manifest(self, reference: BlobRef) -> ArtifactManifest:
        """Reopen and verify one canonical manifest and all of its entry blobs."""

        return self._load_manifest_blob(reference)

    def verify(self, reference: BlobRef) -> None:
        with self._verified_plaintext(
            reference,
            maximum_bytes=reference.size_bytes,
        ):
            return

    def verify_disclosure(
        self,
        reference: BlobRef,
        *,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> None:
        """Verify immutable content again at the disclosure registration boundary."""

        self._require_disclosure(
            artifact_class,
            sensitivity,
            visibility,
            redistribution,
        )
        credential_scanner = ContentRuleScanner(CONTENT_RULES)
        restricted_scanner = ContentRuleScanner(RESTRICTED_CONTENT_RULES)
        restricted_content_allowed = self._restricted_content_allowed(
            artifact_class,
            sensitivity,
            visibility,
            redistribution,
        )
        with self.verified_reader(
            reference,
            maximum_bytes=reference.size_bytes,
        ) as stream:
            while chunk := stream.read(_CHUNK_SIZE):
                self._scan_disclosure_chunk(
                    chunk,
                    credential_scanner=credential_scanner,
                    restricted_scanner=restricted_scanner,
                    restricted_content_allowed=restricted_content_allowed,
                )

    @contextmanager
    def verified_reader(
        self,
        reference: BlobRef,
        *,
        maximum_bytes: int,
    ) -> Iterator[IO[bytes]]:
        with self._verified_plaintext(reference, maximum_bytes=maximum_bytes) as stream:
            yield stream

    @contextmanager
    def stable_plaintext_blobs(
        self,
    ) -> Iterator[Iterator[tuple[BlobRef, IO[bytes]]]]:
        """Hold the store lock while yielding every verified plaintext blob once."""

        with self._exclusive_lock():
            references = self._blob_references_unlocked()

            def readers() -> Generator[tuple[BlobRef, IO[bytes]], None, None]:
                for reference in references:
                    with self._verified_plaintext(
                        reference,
                        maximum_bytes=reference.size_bytes,
                    ) as stream:
                        yield reference, stream

            opened = readers()
            try:
                yield opened
            finally:
                opened.close()

    def put_manifest(self, manifest: ArtifactManifest) -> CommittedManifest:
        blob = self.put_bytes(
            canonical_bytes(manifest),
            artifact_class=manifest.artifact_class,
            sensitivity=manifest.sensitivity,
            visibility=manifest.visibility,
            redistribution=manifest.redistribution,
        )
        return CommittedManifest(semantic_digest=manifest.digest, blob=blob)

    def commit_filesystem_checkpoint(
        self,
        checkpoint_id: str,
        committed: CommittedManifest,
    ) -> CheckpointMarker:
        return self._commit_checkpoint(
            checkpoint_id,
            committed,
            kind=CheckpointCapability.FILESYSTEM,
            driver_digest=None,
        )

    def commit_application_checkpoint(
        self,
        checkpoint_id: str,
        committed: CommittedManifest,
        *,
        driver_digest: Digest,
    ) -> CheckpointMarker:
        return self._commit_checkpoint(
            checkpoint_id,
            committed,
            kind=CheckpointCapability.APPLICATION,
            driver_digest=driver_digest,
        )

    def _commit_checkpoint(
        self,
        checkpoint_id: str,
        committed: CommittedManifest,
        *,
        kind: Literal[
            CheckpointCapability.APPLICATION,
            CheckpointCapability.FILESYSTEM,
        ],
        driver_digest: Digest | None,
    ) -> CheckpointMarker:
        with self._exclusive_lock():
            manifest = self._load_committed_manifest(committed)
            if manifest.artifact_class is not ArtifactClass.CHECKPOINT:
                raise ArtifactPolicyViolation("checkpoint markers require checkpoint manifests")
            marker = CheckpointMarker(
                checkpoint_kind=kind,
                checkpoint_id=checkpoint_id,
                manifest_digest=committed.semantic_digest,
                manifest_blob=committed.blob,
                driver_digest=driver_digest,
            )
            encoded = canonical_bytes(marker) + b"\n"
            target = self.checkpoint_root / f"{marker.checkpoint_id}.json"
            _require_secure_directory(self.checkpoint_root)
            _publish_bytes_no_replace(target, encoded, directory=self.checkpoint_root)
        return marker

    def load_filesystem_checkpoint(
        self,
        checkpoint_id: str,
    ) -> tuple[CheckpointMarker, ArtifactManifest]:
        return self._load_checkpoint(
            checkpoint_id,
            kind=CheckpointCapability.FILESYSTEM,
            driver_digest=None,
        )

    def load_application_checkpoint(
        self,
        checkpoint_id: str,
        *,
        driver_digest: Digest,
    ) -> tuple[CheckpointMarker, ArtifactManifest]:
        return self._load_checkpoint(
            checkpoint_id,
            kind=CheckpointCapability.APPLICATION,
            driver_digest=driver_digest,
        )

    def _load_checkpoint(
        self,
        checkpoint_id: str,
        *,
        kind: Literal[
            CheckpointCapability.APPLICATION,
            CheckpointCapability.FILESYSTEM,
        ],
        driver_digest: Digest | None,
    ) -> tuple[CheckpointMarker, ArtifactManifest]:
        validated_id = CheckpointMarker(
            checkpoint_kind=kind,
            checkpoint_id=checkpoint_id,
            manifest_digest="sha256:" + "0" * 64,
            manifest_blob=BlobRef(digest="sha256:" + "0" * 64, size_bytes=0),
            driver_digest=driver_digest,
        ).checkpoint_id
        with self._exclusive_lock():
            marker = self._load_checkpoint_marker_unlocked(validated_id)
            if marker.checkpoint_kind is not kind or marker.driver_digest != driver_digest:
                raise ArtifactIntegrityError(
                    "checkpoint marker differs from the requested recovery implementation"
                )
            manifest = self._load_committed_manifest(
                CommittedManifest(
                    semantic_digest=marker.manifest_digest,
                    blob=marker.manifest_blob,
                )
            )
            if manifest.artifact_class is not ArtifactClass.CHECKPOINT:
                raise ArtifactIntegrityError(
                    "checkpoint marker references a non-checkpoint manifest"
                )
            return marker, manifest

    def garbage_collect(
        self,
        retained: Iterable[RetainedArtifact],
        *,
        now: datetime,
    ) -> tuple[str, ...]:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("garbage collection time must be timezone-aware")
        current = now.astimezone(UTC)
        retained_records: list[ArtifactRecord] = []
        for retained_artifact in retained:
            rule = self._retention_rule(retained_artifact.record.artifact_class)
            expires = retained_artifact.recorded_at + timedelta(seconds=rule.retention_seconds)
            if retained_artifact.checkpoint_pinned or current < expires:
                retained_records.append(retained_artifact.record)

        removed: list[str] = []
        with self._exclusive_lock():
            live: set[str] = set()
            live_checkpoint_manifests: set[tuple[str, int, str]] = set()
            for record in retained_records:
                live.add(record.blob.digest)
                if record.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE:
                    continue
                manifest = self._load_manifest_blob(record.blob)
                if (
                    manifest.artifact_class is not record.artifact_class
                    or manifest.sensitivity is not record.sensitivity
                    or manifest.visibility is not record.visibility
                    or manifest.redistribution is not record.redistribution
                ):
                    raise ArtifactIntegrityError(
                        "retained manifest disclosure disagrees with its artifact record"
                    )
                live.update(entry.blob.digest for entry in manifest.entries)
                if record.artifact_class is ArtifactClass.CHECKPOINT:
                    live_checkpoint_manifests.add(
                        (record.blob.digest, record.blob.size_bytes, manifest.digest)
                    )

            for marker_path in tuple(sorted(self.checkpoint_root.iterdir())):
                if marker_path.suffix != ".json":
                    raise ArtifactStoreError("checkpoint root contains an invalid marker name")
                marker = self._load_checkpoint_marker_unlocked(marker_path.stem)
                marker_reference = (
                    marker.manifest_blob.digest,
                    marker.manifest_blob.size_bytes,
                    marker.manifest_digest,
                )
                if marker_reference in live_checkpoint_manifests:
                    continue
                marker_path.unlink()
            _fsync_directory(self.checkpoint_root)

            for shard in self._validated_shards():
                for path in tuple(shard.iterdir()):
                    _require_blob_name(path.name)
                    digest = f"sha256:{shard.name}{path.name}"
                    if digest in live:
                        continue
                    _require_secure_regular_file(path)
                    path.unlink()
                    removed.append(digest)
                _fsync_directory(shard)
                if not any(shard.iterdir()):
                    shard.rmdir()
                    _fsync_directory(self.blob_root)
        return tuple(sorted(removed))

    def stored_bytes(self) -> int:
        with self._exclusive_lock():
            return self._stored_bytes_unlocked()

    def _initialize(self) -> None:
        self.root.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
        _require_secure_directory(self.root)
        for directory in (self.blob_root, self.checkpoint_root):
            created = False
            try:
                directory.mkdir(mode=_DIRECTORY_MODE)
                created = True
            except FileExistsError:
                pass
            _require_secure_directory(directory)
            if created:
                _fsync_directory(self.root)
        if not self.lock_path.exists():
            try:
                _write_exclusive(self.lock_path, b"")
                _fsync_directory(self.root)
            except FileExistsError:
                pass
        _require_secure_regular_file(self.lock_path)
        encoded = canonical_bytes(self.metadata) + b"\n"
        try:
            _write_exclusive(self.metadata_path, encoded)
            _fsync_directory(self.root)
        except FileExistsError:
            existing = _read_secure_file(self.metadata_path, maximum_bytes=64 * 1024)
            if existing != encoded:
                raise ArtifactPolicyViolation(
                    "artifact store metadata does not match the resolved policy and key ID"
                ) from None

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        _require_secure_directory(self.root)
        descriptor = os.open(
            self.lock_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._discard_stale_temporary_files_unlocked()
            yield
        finally:
            os.close(descriptor)

    def _require_disclosure(
        self,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> None:
        if sensitivity is Sensitivity.SECRET:
            raise ArtifactPolicyViolation("secret data cannot enter persistent artifact storage")
        rule = self._retention_rule(artifact_class)
        if rule.retention_seconds == 0:
            raise ArtifactPolicyViolation("ephemeral policy forbids persistent storage")
        requested = ArtifactDisclosure(
            sensitivity=sensitivity,
            visibility=visibility,
            redistribution=redistribution,
        )
        if requested not in rule.allowed_disclosures:
            raise ArtifactPolicyViolation("artifact disclosure is not allowed by its class policy")
        if sensitivity is Sensitivity.CONFIDENTIAL and not self.encrypted:
            raise ArtifactPolicyViolation("confidential artifacts require managed encryption")

    def _restricted_content_allowed(
        self,
        artifact_class: ArtifactClass,
        sensitivity: Sensitivity,
        visibility: Visibility,
        redistribution: Redistribution,
    ) -> bool:
        return (
            self.encrypted
            and artifact_class in RAW_EDA_ARTIFACT_CLASSES
            and ArtifactDisclosure(
                sensitivity=sensitivity,
                visibility=visibility,
                redistribution=redistribution,
            )
            == PROTECTED_RAW_DISCLOSURE
        )

    @staticmethod
    def _scan_disclosure_chunk(
        chunk: bytes,
        *,
        credential_scanner: ContentRuleScanner,
        restricted_scanner: ContentRuleScanner,
        restricted_content_allowed: bool,
    ) -> None:
        credential_scanner.update(chunk)
        if credential_scanner.matched_rule_ids:
            raise ArtifactPolicyViolation("artifact content violates the credential policy")
        restricted_scanner.update(chunk)
        if restricted_scanner.matched_rule_ids and not restricted_content_allowed:
            raise ArtifactPolicyViolation(
                "artifact content violates the restricted disclosure policy"
            )

    def _retention_rule(self, artifact_class: ArtifactClass) -> ArtifactRetentionRule:
        return next(rule for rule in self.policy.rules if rule.artifact_class is artifact_class)

    def _start_envelope(self, stream: IO[bytes]) -> AEADEncryptionContext | None:
        if self._encryption_key is None:
            _write_all(
                stream,
                _ENVELOPE_MAGIC + _MODE_PLAINTEXT + bytes(_NONCE_SIZE + _TAG_SIZE),
            )
            return None
        nonce = os.urandom(_NONCE_SIZE)
        prefix = _ENVELOPE_MAGIC + _MODE_ENCRYPTED + nonce
        _write_all(stream, prefix + bytes(_TAG_SIZE))
        encryptor = Cipher(
            algorithms.AES(self._encryption_key._cipher_bytes()),
            modes.GCM(nonce),
        ).encryptor()
        encryptor.authenticate_additional_data(self._aad(prefix))
        return encryptor

    def _aad(self, prefix: bytes) -> bytes:
        key_id = "" if self.metadata.key_id is None else self.metadata.key_id
        return prefix + b"\x00" + self.policy_digest.encode() + b"\x00" + key_id.encode()

    @contextmanager
    def _verified_plaintext(
        self,
        reference: BlobRef,
        *,
        maximum_bytes: int,
    ) -> Iterator[IO[bytes]]:
        if maximum_bytes < 0:
            raise ValueError("maximum_bytes cannot be negative")
        path = self._blob_path(reference.digest, create_shard=False)
        try:
            source_descriptor = os.open(
                path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as error:
            raise ArtifactIntegrityError("artifact object cannot be opened safely") from error
        memory_descriptor = os.memfd_create(
            "edagym-verified-artifact",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        try:
            source_metadata = _require_secure_fd(source_descriptor, regular=True)
            with os.fdopen(memory_descriptor, "w+b", closefd=False) as verified:
                header = _read_exact_fd(source_descriptor, _HEADER_SIZE)
                prefix = header[: len(_ENVELOPE_MAGIC) + 1 + _NONCE_SIZE]
                if not prefix.startswith(_ENVELOPE_MAGIC):
                    raise ArtifactIntegrityError("artifact envelope has an invalid format")
                mode = prefix[len(_ENVELOPE_MAGIC) : len(_ENVELOPE_MAGIC) + 1]
                nonce = prefix[-_NONCE_SIZE:]
                tag = header[-_TAG_SIZE:]
                decryptor = None
                if mode == _MODE_ENCRYPTED:
                    if self._encryption_key is None:
                        raise ArtifactPolicyViolation("encrypted artifact requires its bound key")
                    decryptor = Cipher(
                        algorithms.AES(self._encryption_key._cipher_bytes()),
                        modes.GCM(nonce, tag),
                    ).decryptor()
                    decryptor.authenticate_additional_data(self._aad(prefix))
                elif (
                    mode != _MODE_PLAINTEXT
                    or self._encryption_key is not None
                    or any(nonce)
                    or any(tag)
                ):
                    raise ArtifactPolicyViolation(
                        "artifact envelope encryption mode is inconsistent"
                    )

                actual = hashlib.sha256()
                size = 0
                while chunk := os.read(source_descriptor, _CHUNK_SIZE):
                    plaintext = chunk if decryptor is None else decryptor.update(chunk)
                    size += len(plaintext)
                    if size > maximum_bytes or size > reference.size_bytes:
                        raise ArtifactIntegrityError("artifact exceeds its declared read bound")
                    actual.update(plaintext)
                    _write_all(verified, plaintext)
                if decryptor is not None:
                    try:
                        tail = decryptor.finalize()
                    except InvalidTag as error:
                        raise ArtifactIntegrityError("artifact authentication failed") from error
                    size += len(tail)
                    if size > maximum_bytes or size > reference.size_bytes:
                        raise ArtifactIntegrityError("artifact exceeds its declared read bound")
                    actual.update(tail)
                    _write_all(verified, tail)
                after = os.fstat(source_descriptor)
                if (
                    after.st_dev != source_metadata.st_dev
                    or after.st_ino != source_metadata.st_ino
                    or after.st_size != source_metadata.st_size
                    or after.st_mtime_ns != source_metadata.st_mtime_ns
                ):
                    raise ArtifactIntegrityError("artifact changed during verification")
                actual_digest = f"sha256:{actual.hexdigest()}"
                if size != reference.size_bytes or actual_digest != reference.digest:
                    raise ArtifactIntegrityError("artifact content does not match its reference")
                verified.flush()
                os.fsync(memory_descriptor)
                fcntl.fcntl(
                    memory_descriptor,
                    fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_WRITE
                    | fcntl.F_SEAL_SEAL,
                )
                verified.seek(0)
                yield verified
        finally:
            os.close(source_descriptor)
            os.close(memory_descriptor)

    def _load_committed_manifest(self, committed: CommittedManifest) -> ArtifactManifest:
        return self._load_manifest_blob(
            committed.blob,
            expected_semantic_digest=committed.semantic_digest,
        )

    def _load_manifest_blob(
        self,
        blob: BlobRef,
        *,
        expected_semantic_digest: str | None = None,
    ) -> ArtifactManifest:
        content = self.read_bytes(blob, maximum_bytes=16 * 1024 * 1024)
        try:
            raw = json.loads(content)
            manifest = ArtifactManifest.model_validate(raw)
        except (json.JSONDecodeError, ValidationError) as error:
            raise ArtifactIntegrityError("committed manifest is invalid") from error
        if canonical_bytes(manifest) != content or (
            expected_semantic_digest is not None and manifest.digest != expected_semantic_digest
        ):
            raise ArtifactIntegrityError("committed manifest identity is inconsistent")
        for entry in manifest.entries:
            self.verify(entry.blob)
        return manifest

    def _load_checkpoint_marker_unlocked(self, checkpoint_id: str) -> CheckpointMarker:
        target = self.checkpoint_root / f"{checkpoint_id}.json"
        _require_secure_directory(self.checkpoint_root)
        content = _read_secure_file(target, maximum_bytes=64 * 1024)
        try:
            marker = CheckpointMarker.model_validate_json(content)
        except ValidationError as error:
            raise ArtifactIntegrityError("checkpoint marker is invalid") from error
        if canonical_bytes(marker) + b"\n" != content:
            raise ArtifactIntegrityError("checkpoint marker is not canonically encoded")
        if marker.checkpoint_id != checkpoint_id:
            raise ArtifactIntegrityError("checkpoint marker identity disagrees with its name")
        return marker

    def _blob_path(self, digest: str, *, create_shard: bool) -> Path:
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("artifact digest is not a canonical SHA-256 identity")
        hexadecimal = digest.removeprefix("sha256:")
        if any(character not in "0123456789abcdef" for character in hexadecimal):
            raise ValueError("artifact digest is not lowercase hexadecimal")
        shard = self.blob_root / hexadecimal[:2]
        if create_shard:
            created = False
            try:
                shard.mkdir(mode=_DIRECTORY_MODE)
                created = True
            except FileExistsError:
                pass
            _require_secure_directory(shard)
            if created:
                _fsync_directory(self.blob_root)
        else:
            _require_secure_directory(shard)
        return shard / hexadecimal[2:]

    def _validated_shards(self) -> tuple[Path, ...]:
        shards = []
        for path in self.blob_root.iterdir():
            if len(path.name) != 2 or any(
                character not in "0123456789abcdef" for character in path.name
            ):
                raise ArtifactStoreError("artifact blob root contains an invalid shard")
            _require_secure_directory(path)
            shards.append(path)
        return tuple(sorted(shards))

    def _stored_bytes_unlocked(self) -> int:
        total = 0
        for shard in self._validated_shards():
            for blob in shard.iterdir():
                _require_blob_name(blob.name)
                total += _require_secure_regular_file(blob).st_size
        for incoming in self.root.glob("incoming-*"):
            total += _require_secure_regular_file(incoming).st_size
        return total

    def _blob_references_unlocked(self) -> tuple[BlobRef, ...]:
        references: list[BlobRef] = []
        for shard in self._validated_shards():
            for path in sorted(shard.iterdir()):
                _require_blob_name(path.name)
                metadata = _require_secure_regular_file(path)
                if metadata.st_size < _HEADER_SIZE:
                    raise ArtifactIntegrityError("artifact envelope is truncated")
                references.append(
                    BlobRef(
                        digest=f"sha256:{shard.name}{path.name}",
                        size_bytes=metadata.st_size - _HEADER_SIZE,
                    )
                )
        return tuple(references)

    def _discard_stale_temporary_files_unlocked(self) -> None:
        removed = False
        for path in self.root.iterdir():
            if not path.name.startswith("incoming-"):
                continue
            _require_secure_regular_file(path)
            path.unlink()
            removed = True
        for path in self.checkpoint_root.iterdir():
            if not path.name.startswith("publish-"):
                continue
            _require_secure_regular_file(path)
            path.unlink()
            removed = True
        if removed:
            _fsync_directory(self.root)
            _fsync_directory(self.checkpoint_root)


def manifest_tree(
    store: ContentAddressedStore,
    source: Path,
    *,
    artifact_class: ArtifactClass,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> ArtifactManifest:
    """Store a stable regular-file tree and return its deterministic manifest."""

    source_descriptor = _open_owned_directory_path(source)
    try:
        before = _source_tree_identity(source_descriptor, prefix=PurePosixPath())
        entries = _manifest_entries_from_directory(
            store,
            source_descriptor,
            prefix=PurePosixPath(),
            artifact_class=artifact_class,
            sensitivity=sensitivity,
            visibility=visibility,
            redistribution=redistribution,
        )
        after = _source_tree_identity(source_descriptor, prefix=PurePosixPath())
        if before != after:
            raise ArtifactIntegrityError("artifact tree changed while it was captured")
    finally:
        os.close(source_descriptor)
    return ArtifactManifest(
        artifact_class=artifact_class,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
        entries=tuple(entries),
    )


def manifest_paths(
    store: ContentAddressedStore,
    source: Path,
    paths: Iterable[str],
    *,
    artifact_class: ArtifactClass,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> ArtifactManifest:
    """Store selected stable paths while preserving their workspace-relative names."""

    normalized = tuple(sorted(validate_relative_path(path) for path in paths))
    path_objects = tuple(PurePosixPath(path) for path in normalized)
    if (
        not normalized
        or len(normalized) != len(set(normalized))
        or any(
            left in right.parents or right in left.parents
            for position, left in enumerate(path_objects)
            for right in path_objects[position + 1 :]
        )
    ):
        raise ValueError("selected artifact paths must be unique and non-overlapping")
    source_descriptor = _open_owned_directory_path(source)
    try:
        before = tuple(
            identity
            for path in path_objects
            for identity in _selected_source_identity(source_descriptor, path)
        )
        entries = tuple(
            entry
            for path in path_objects
            for entry in _manifest_entries_from_selected_path(
                store,
                source_descriptor,
                path,
                artifact_class=artifact_class,
                sensitivity=sensitivity,
                visibility=visibility,
                redistribution=redistribution,
            )
        )
        after = tuple(
            identity
            for path in path_objects
            for identity in _selected_source_identity(source_descriptor, path)
        )
        if before != after:
            raise ArtifactIntegrityError("selected artifact paths changed while captured")
    finally:
        os.close(source_descriptor)
    return ArtifactManifest(
        artifact_class=artifact_class,
        sensitivity=sensitivity,
        visibility=visibility,
        redistribution=redistribution,
        entries=entries,
    )


def _selected_source_identity(
    root_descriptor: int,
    path: PurePosixPath,
) -> tuple[tuple[str, tuple[int, int, int, int, int, int]], ...]:
    parent_descriptor, metadata = _open_selected_parent(root_descriptor, path)
    try:
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_descriptor,
            )
            try:
                if _file_identity(os.fstat(child)) != _file_identity(metadata):
                    raise ArtifactIntegrityError("selected directory changed while opened")
                return _source_tree_identity(child, prefix=path)
            finally:
                os.close(child)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactStoreError("selected artifact paths must be regular files or trees")
        return ((path.as_posix(), _file_identity(metadata)),)
    finally:
        os.close(parent_descriptor)


def _manifest_entries_from_selected_path(
    store: ContentAddressedStore,
    root_descriptor: int,
    path: PurePosixPath,
    *,
    artifact_class: ArtifactClass,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> tuple[ManifestEntry, ...]:
    parent_descriptor, metadata = _open_selected_parent(root_descriptor, path)
    try:
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_descriptor,
            )
            try:
                if _file_identity(os.fstat(child)) != _file_identity(metadata):
                    raise ArtifactIntegrityError("selected directory changed while opened")
                return tuple(
                    _manifest_entries_from_directory(
                        store,
                        child,
                        prefix=path,
                        artifact_class=artifact_class,
                        sensitivity=sensitivity,
                        visibility=visibility,
                        redistribution=redistribution,
                    )
                )
            finally:
                os.close(child)
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactStoreError("selected artifact paths must be regular files or trees")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        try:
            if _file_identity(os.fstat(descriptor)) != _file_identity(metadata):
                raise ArtifactIntegrityError("selected file changed while opened")
            blob = store.put_file_descriptor(
                descriptor,
                artifact_class=artifact_class,
                sensitivity=sensitivity,
                visibility=visibility,
                redistribution=redistribution,
            )
        finally:
            os.close(descriptor)
        mode: Literal[0o644, 0o755] = 0o755 if metadata.st_mode & 0o111 else 0o644
        return (ManifestEntry(path=path.as_posix(), blob=blob, mode=mode),)
    finally:
        os.close(parent_descriptor)


def _open_selected_parent(
    root_descriptor: int,
    path: PurePosixPath,
) -> tuple[int, os.stat_result]:
    descriptor = os.dup(root_descriptor)
    try:
        for part in path.parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        metadata = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def _source_tree_identity(
    directory_descriptor: int,
    *,
    prefix: PurePosixPath,
) -> tuple[tuple[str, tuple[int, int, int, int, int, int]], ...]:
    """Describe a tree without following links and reject an unstable traversal."""

    directory_before = _file_identity(os.fstat(directory_descriptor))
    names = sorted(os.listdir(directory_descriptor))
    identities = [(prefix.as_posix(), directory_before)]
    for name in names:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        relative = prefix / name
        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_descriptor,
            )
            try:
                if _file_identity(os.fstat(child_descriptor)) != _file_identity(metadata):
                    raise ArtifactIntegrityError("artifact tree entry changed while it was opened")
                identities.extend(_source_tree_identity(child_descriptor, prefix=relative))
            finally:
                os.close(child_descriptor)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactStoreError("artifact trees cannot contain links or special files")
        identities.append((relative.as_posix(), _file_identity(metadata)))
    if (
        names != sorted(os.listdir(directory_descriptor))
        or _file_identity(os.fstat(directory_descriptor)) != directory_before
    ):
        raise ArtifactIntegrityError("artifact tree changed while it was inspected")
    return tuple(identities)


def _manifest_entries_from_directory(
    store: ContentAddressedStore,
    directory_descriptor: int,
    *,
    prefix: PurePosixPath,
    artifact_class: ArtifactClass,
    sensitivity: Sensitivity,
    visibility: Visibility,
    redistribution: Redistribution,
) -> list[ManifestEntry]:
    directory_identity = _file_identity(os.fstat(directory_descriptor))
    names = sorted(os.listdir(directory_descriptor))
    entries: list[ManifestEntry] = []
    for name in names:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        relative = prefix / name
        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_descriptor,
            )
            try:
                if _file_identity(os.fstat(child_descriptor)) != _file_identity(metadata):
                    raise ArtifactIntegrityError("artifact tree entry changed while it was opened")
                entries.extend(
                    _manifest_entries_from_directory(
                        store,
                        child_descriptor,
                        prefix=relative,
                        artifact_class=artifact_class,
                        sensitivity=sensitivity,
                        visibility=visibility,
                        redistribution=redistribution,
                    )
                )
            finally:
                os.close(child_descriptor)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ArtifactStoreError("artifact trees cannot contain links or special files")
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_descriptor,
        )
        try:
            if _file_identity(os.fstat(descriptor)) != _file_identity(metadata):
                raise ArtifactIntegrityError("artifact tree entry changed while it was opened")
            blob = store.put_file_descriptor(
                descriptor,
                artifact_class=artifact_class,
                sensitivity=sensitivity,
                visibility=visibility,
                redistribution=redistribution,
            )
        finally:
            os.close(descriptor)
        mode: Literal[0o644, 0o755] = 0o755 if metadata.st_mode & 0o111 else 0o644
        entries.append(
            ManifestEntry(
                path=relative.as_posix(),
                blob=blob,
                mode=mode,
            )
        )
    if (
        names != sorted(os.listdir(directory_descriptor))
        or _file_identity(os.fstat(directory_descriptor)) != directory_identity
    ):
        raise ArtifactIntegrityError("artifact tree changed while it was captured")
    return entries


def restore_manifest(
    store: ContentAddressedStore,
    manifest: ArtifactManifest,
    destination: Path,
) -> None:
    """Materialize and atomically publish a verified tree at a new path."""

    from edagym.run.materialization import restore_manifest as materialize_manifest

    materialize_manifest(store, manifest, destination)


def _publish_bytes_no_replace(target: Path, content: bytes, *, directory: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix="publish-", dir=directory)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, _FILE_MODE)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            _write_all(stream, content)
            stream.flush()
            os.fsync(descriptor)
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            existing = _read_secure_file(target, maximum_bytes=len(content) + 1)
            if existing != content:
                raise ArtifactStoreError(
                    "immutable marker identity already has other content"
                ) from None
        _fsync_directory(directory)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _read_secure_file(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ArtifactIntegrityError("artifact metadata cannot be opened safely") from error
    try:
        metadata = _require_secure_fd(descriptor, regular=True)
        if metadata.st_size > maximum_bytes:
            raise ArtifactIntegrityError("artifact metadata file exceeds its bound")
        content = bytearray()
        while chunk := os.read(
            descriptor,
            min(_CHUNK_SIZE, maximum_bytes + 1 - len(content)),
        ):
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise ArtifactIntegrityError("artifact metadata file exceeds its bound")
        return bytes(content)
    finally:
        os.close(descriptor)


def _write_all(stream: IO[bytes], content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = stream.write(view)
        if written is None or written == 0:
            raise OSError("short artifact-store write")
        view = view[written:]


def _require_blob_name(name: str) -> None:
    if len(name) != 62 or any(character not in "0123456789abcdef" for character in name):
        raise ArtifactStoreError("artifact shard contains an invalid blob name")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_key_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _read_exact_fd(descriptor: int, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        chunk = os.read(descriptor, count - len(result))
        if not chunk:
            raise ArtifactIntegrityError("artifact envelope is truncated")
        result.extend(chunk)
    return bytes(result)


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        _FILE_MODE,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            _write_all(stream, content)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_secure_fd(descriptor: int, *, regular: bool) -> os.stat_result:
    metadata = os.fstat(descriptor)
    expected = stat.S_ISREG(metadata.st_mode) if regular else stat.S_ISDIR(metadata.st_mode)
    if not expected or metadata.st_uid != os.getuid():
        raise ArtifactStoreError("artifact storage objects must be owned and correctly typed")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ArtifactStoreError("artifact storage objects cannot grant group or other access")
    return metadata


def _require_secure_directory(path: Path) -> os.stat_result:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise ArtifactStoreError("artifact directory cannot be opened safely") from error
    try:
        return _require_secure_fd(descriptor, regular=False)
    finally:
        os.close(descriptor)


def _open_owned_directory_path(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = -1
    try:
        descriptor = os.open(
            "/",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        for part in absolute.parts[1:]:
            child_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child_descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactStoreError("owned directory path cannot be opened safely") from error
    try:
        _require_owned_nonwritable_directory_fd(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_owned_nonwritable_directory_fd(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ArtifactStoreError("directory must be owned and not broadly writable")


def _require_secure_regular_file(path: Path) -> os.stat_result:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ArtifactStoreError("artifact file cannot be opened safely") from error
    try:
        return _require_secure_fd(descriptor, regular=True)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
