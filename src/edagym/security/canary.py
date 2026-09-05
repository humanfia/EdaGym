"""Single-use synthetic-secret isolation attestations."""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
from contextlib import suppress
from threading import Lock
from typing import TYPE_CHECKING, Annotated, Any, Literal, SupportsIndex

from pydantic import StringConstraints, TypeAdapter, model_validator

from edagym.canonical import canonical_digest
from edagym.runtime_surface_protocol import (
    CANARY_ENVIRONMENT_NAME,
    REQUIRED_ISOLATION_SURFACES,
    IsolationSurface,
)
from edagym.specs.common import Digest, SchemaVersion, StrictModel

if TYPE_CHECKING:
    from edagym.executors.isolation_launch import SyntheticPreflightLaunchCapability
    from edagym.security.collector import IsolationSurfaceCollector
    from edagym.security.runtime_surface import RuntimeSurfaceManifest


CANARY_COLLECTOR_RULE: Literal["descriptor-bound-runtime-manifest-scan-v2"] = (
    "descriptor-bound-runtime-manifest-scan-v2"
)
_CANARY_PREFIX = b"edagym-canary-"
_CANARY_RANDOM_LENGTH = 48
_CANARY_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
_DIGEST_ADAPTER = TypeAdapter(Digest)
_ATTESTATION_ISSUER = object()


class CanaryExposure(RuntimeError):
    """Raised when the synthetic marker reaches any protected surface."""


class CanaryProtocolError(RuntimeError):
    """Raised when isolation evidence is incomplete, duplicated, or reused."""


class CanaryPolicy(StrictModel):
    """Exact fail-closed credential and isolation policy for a provider profile."""

    schema_version: SchemaVersion = 1
    provider_profile_digest: Digest
    provider_config_digest: Digest
    budget_binding_digest: Digest
    credential_rule: Literal["passwd-home-owned-private-v1"] = "passwd-home-owned-private-v1"
    synthetic_credential_rule: Literal["controller-file-and-environment-v1"] = (
        "controller-file-and-environment-v1"
    )
    collector_rule: Literal["descriptor-bound-runtime-manifest-scan-v2"] = CANARY_COLLECTOR_RULE
    required_surfaces: tuple[IsolationSurface, ...] = REQUIRED_ISOLATION_SURFACES

    @model_validator(mode="after")
    def require_complete_surface_set(self) -> CanaryPolicy:
        if self.required_surfaces != REQUIRED_ISOLATION_SURFACES:
            raise ValueError("the credential preflight surface set cannot be weakened")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-canary-policy-v1")


AttestationId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class CanaryReceipt(StrictModel):
    """Non-secret record emitted when a matching attestation is consumed."""

    schema_version: SchemaVersion = 1
    attestation_id: AttestationId
    policy_digest: Digest
    campaign_digest: Digest
    provider_profile_digest: Digest
    manifest_digest: Digest
    collection_evidence_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="provider-canary-receipt-v1")


class CanaryAttestation:
    """Opaque, process-local capability that can authorize exactly one provider request."""

    __slots__ = (
        "_attestation_id",
        "_campaign_digest",
        "_collection_evidence_digest",
        "_consumed",
        "_lock",
        "_manifest",
        "_policy_digest",
        "_profile_digest",
    )

    def __init__(
        self,
        *,
        attestation_id: str,
        policy_digest: Digest,
        campaign_digest: Digest,
        provider_profile_digest: Digest,
        runtime_surface_manifest: RuntimeSurfaceManifest,
        collection_evidence_digest: Digest,
        _issuer: object,
    ) -> None:
        from edagym.security.runtime_surface import RuntimeSurfaceManifest

        if _issuer is not _ATTESTATION_ISSUER:
            raise CanaryProtocolError("canary attestations can only be issued by a challenge")
        if type(runtime_surface_manifest) is not RuntimeSurfaceManifest:
            raise CanaryProtocolError("canary attestation requires a runtime surface manifest")
        self._attestation_id = attestation_id
        self._policy_digest = _DIGEST_ADAPTER.validate_python(policy_digest)
        self._campaign_digest = _DIGEST_ADAPTER.validate_python(campaign_digest)
        self._profile_digest = _DIGEST_ADAPTER.validate_python(provider_profile_digest)
        self._manifest = runtime_surface_manifest
        self._collection_evidence_digest = _DIGEST_ADAPTER.validate_python(
            collection_evidence_digest
        )
        self._lock = Lock()
        self._consumed = False

    @property
    def runtime_surface_manifest(self) -> RuntimeSurfaceManifest:
        return self._manifest

    def consume(
        self,
        *,
        policy_digest: Digest,
        campaign_digest: Digest,
        provider_profile_digest: Digest,
    ) -> CanaryReceipt:
        with self._lock:
            if self._consumed:
                raise CanaryProtocolError("canary attestation has already been consumed")
            if (
                policy_digest != self._policy_digest
                or campaign_digest != self._campaign_digest
                or provider_profile_digest != self._profile_digest
            ):
                raise CanaryProtocolError("canary attestation binding does not match")
            self._consumed = True
            return CanaryReceipt(
                attestation_id=self._attestation_id,
                policy_digest=self._policy_digest,
                campaign_digest=self._campaign_digest,
                provider_profile_digest=self._profile_digest,
                manifest_digest=self._manifest.digest,
                collection_evidence_digest=self._collection_evidence_digest,
            )

    def __repr__(self) -> str:
        return "CanaryAttestation(<opaque>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("canary attestations cannot be serialized")


class CanaryChallenge:
    """Own a synthetic marker while all required isolation surfaces are inspected."""

    __slots__ = (
        "_campaign_digest",
        "_closed",
        "_controller_environment",
        "_credential_descriptor",
        "_credential_identity",
        "_launch_capability",
        "_policy",
        "_token",
    )

    def __init__(self, *, policy: CanaryPolicy, campaign_digest: Digest) -> None:
        self._policy = policy
        self._campaign_digest = _DIGEST_ADAPTER.validate_python(campaign_digest)
        self._token = bytearray(_CANARY_PREFIX)
        self._token.extend(
            _CANARY_ALPHABET[secrets.randbelow(len(_CANARY_ALPHABET))]
            for _ in range(_CANARY_RANDOM_LENGTH)
        )
        self._controller_environment: dict[str, str] | None = None
        self._credential_descriptor: int | None = None
        self._credential_identity: tuple[int, ...] | None = None
        self._launch_capability: SyntheticPreflightLaunchCapability | None = None
        self._closed = False

    def install_controller_environment(self, environment: dict[str, str]) -> None:
        """Install the marker only in a controller-owned simulated credential surface."""

        self._require_open()
        if self._controller_environment is not None:
            raise CanaryProtocolError("controller canary environment is already installed")
        if type(environment) is not dict:
            raise CanaryProtocolError("controller canary environment must be a plain mapping")
        if CANARY_ENVIRONMENT_NAME in environment:
            raise CanaryProtocolError("controller canary variable already exists")
        environment[CANARY_ENVIRONMENT_NAME] = bytes(self._token).decode("ascii")
        self._controller_environment = environment

    def _install_credential_descriptor(self, descriptor: int) -> None:
        """Write the marker through a launcher-owned private credential descriptor."""

        self._require_open()
        if self._credential_descriptor is not None:
            raise CanaryProtocolError("synthetic credential descriptor is already installed")
        if type(descriptor) is not int or descriptor < 0:
            raise CanaryProtocolError("synthetic credential descriptor is invalid")
        try:
            metadata = os.fstat(descriptor)
            access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        except OSError as error:
            raise CanaryProtocolError("synthetic credential descriptor is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or os.get_inheritable(descriptor)
            or access_mode != os.O_RDWR
        ):
            raise CanaryProtocolError(
                "synthetic credential descriptor must be private, owned, and writable"
            )

        owned = os.dup(descriptor)
        try:
            os.ftruncate(owned, 0)
            os.lseek(owned, 0, os.SEEK_SET)
            _write_all(owned, self._token)
            os.fsync(owned)
            installed = os.fstat(owned)
            if installed.st_size != len(self._token):
                raise CanaryProtocolError("synthetic credential marker was not fully installed")
            self._credential_descriptor = owned
            self._credential_identity = _credential_identity(installed)
        except BaseException:
            os.close(owned)
            raise

    def _issue_launch_capability(self) -> SyntheticPreflightLaunchCapability:
        """Bind the installed marker to one concrete executor launch."""

        from edagym.executors.isolation_launch import (
            _issue_synthetic_preflight_launch_capability,
        )

        self._require_open()
        if self._launch_capability is not None:
            raise CanaryProtocolError("synthetic preflight launch was already authorized")
        environment = self._controller_environment
        descriptor = self._credential_descriptor
        if environment is None or descriptor is None or not self._credential_marker_matches():
            raise CanaryProtocolError(
                "synthetic preflight launch requires both controller canary surfaces"
            )
        try:
            capability = _issue_synthetic_preflight_launch_capability(
                marker=bytes(self._token),
                controller_environment=environment,
                credential_descriptor=descriptor,
            )
        except (OSError, TypeError, ValueError) as error:
            raise CanaryProtocolError("synthetic preflight launch cannot be authorized") from error
        self._launch_capability = capability
        return capability

    def attest(self, collector: IsolationSurfaceCollector) -> CanaryAttestation:
        """Issue once after the trusted collector scans every descriptor-bound surface."""

        from edagym.security.collector import (
            _COLLECTION_AUTHORITY,
            IsolationSurfaceCollector,
        )

        self._require_open()
        environment = self._controller_environment
        try:
            if environment is None:
                raise CanaryProtocolError("controller canary environment was not installed")
            if not self._credential_marker_matches():
                raise CanaryProtocolError("synthetic credential marker changed before collection")
            installed = environment.get(CANARY_ENVIRONMENT_NAME)
            try:
                matches = installed is not None and secrets.compare_digest(
                    installed.encode("ascii", errors="strict"),
                    self._token,
                )
            except UnicodeEncodeError:
                matches = False
            if not matches:
                raise CanaryProtocolError("controller canary environment changed before collection")
            if type(collector) is not IsolationSurfaceCollector:
                raise CanaryProtocolError("canary evidence requires the trusted surface collector")
            if self._launch_capability is None or not self._launch_capability._completed():
                raise CanaryProtocolError("synthetic preflight parent launch did not complete")
            manifest = collector.manifest
            binding = manifest.binding
            if (
                binding.campaign_digest != self._campaign_digest
                or binding.provider_profile_digest != self._policy.provider_profile_digest
                or binding.provider_config_digest != self._policy.provider_config_digest
                or binding.budget_binding_digest != self._policy.budget_binding_digest
            ):
                raise CanaryProtocolError("runtime surface manifest does not match the challenge")
            collection_evidence_digest = collector._collect(
                memoryview(self._token),
                authority=_COLLECTION_AUTHORITY,
            )
            return CanaryAttestation(
                attestation_id=secrets.token_hex(16),
                policy_digest=self._policy.digest,
                campaign_digest=self._campaign_digest,
                provider_profile_digest=self._policy.provider_profile_digest,
                runtime_surface_manifest=manifest,
                collection_evidence_digest=collection_evidence_digest,
                _issuer=_ATTESTATION_ISSUER,
            )
        finally:
            if type(collector) is IsolationSurfaceCollector:
                collector.close()
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        if self._launch_capability is not None:
            self._launch_capability.close()
            self._launch_capability = None
        if self._controller_environment is not None:
            self._controller_environment.pop(CANARY_ENVIRONMENT_NAME, None)
            self._controller_environment = None
        descriptor = self._credential_descriptor
        if descriptor is not None:
            with suppress(OSError):
                os.lseek(descriptor, 0, os.SEEK_SET)
                _write_all(descriptor, bytearray(len(self._token)))
            with suppress(OSError):
                os.fsync(descriptor)
            with suppress(OSError):
                os.ftruncate(descriptor, 0)
            with suppress(OSError):
                os.fsync(descriptor)
            with suppress(OSError):
                os.close(descriptor)
            self._credential_descriptor = None
            self._credential_identity = None
        for index in range(len(self._token)):
            self._token[index] = 0
        self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise CanaryProtocolError("canary challenge is closed")

    def _credential_marker_matches(self) -> bool:
        descriptor = self._credential_descriptor
        identity = self._credential_identity
        if descriptor is None or identity is None:
            return False
        try:
            before = os.fstat(descriptor)
            if _credential_identity(before) != identity:
                return False
            os.lseek(descriptor, 0, os.SEEK_SET)
            content = bytearray()
            while len(content) <= len(self._token):
                chunk = os.read(descriptor, len(self._token) + 1 - len(content))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
        except OSError:
            return False
        return (
            _credential_identity(after) == identity
            and len(content) == len(self._token)
            and secrets.compare_digest(content, self._token)
        )

    def __enter__(self) -> CanaryChallenge:
        self._require_open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "CanaryChallenge(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("canary challenges cannot be serialized")


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


def _write_all(descriptor: int, content: bytes | bytearray) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("synthetic credential write made no progress")
        offset += written
