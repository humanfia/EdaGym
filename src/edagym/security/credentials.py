"""Descriptor-bound acquisition of controller-only provider credentials."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import MutableMapping
from pathlib import Path
from threading import Lock
from typing import Any, Protocol, SupportsIndex

from edagym.config.model import CredentialConfig, CredentialDecoder
from edagym.providers.model import (
    MessagesWire,
    ProviderAuthorization,
    ProviderProfile,
    ResolvedProviderConfig,
)
from edagym.security.canary import (
    CanaryAttestation,
    CanaryPolicy,
    CanaryReceipt,
)
from edagym.specs.common import Digest

_MAX_CONFIG_BYTES = 1 << 20
_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_DIRECTORY_FLAGS = _OPEN_FLAGS | os.O_DIRECTORY
_MAX_CREDENTIAL_BYTES = 8192
_PROVIDER_ACCESS_GRANT_ISSUER = object()


class CredentialSecurityError(RuntimeError):
    """A local credential object failed ownership, mode, or stability checks."""


class CredentialFormatError(RuntimeError):
    """A trusted local configuration does not match a supported narrow decoder."""


class ProviderAccessGrant:
    """Opaque one-shot authority issued only by consuming a canary attestation."""

    __slots__ = (
        "_budget_binding_digest",
        "_campaign_digest",
        "_consumed",
        "_lock",
        "_manifest_digest",
        "_provider_config_digest",
        "_provider_profile_digest",
        "_receipt_digest",
    )

    def __init__(
        self,
        *,
        provider_profile_digest: Digest,
        provider_config_digest: Digest,
        campaign_digest: Digest,
        budget_binding_digest: Digest,
        receipt_digest: Digest,
        manifest_digest: Digest,
        _issuer: object,
    ) -> None:
        if _issuer is not _PROVIDER_ACCESS_GRANT_ISSUER:
            raise CredentialSecurityError(
                "provider access grants require a consumed canary attestation"
            )
        self._provider_profile_digest = provider_profile_digest
        self._provider_config_digest = provider_config_digest
        self._campaign_digest = campaign_digest
        self._budget_binding_digest = budget_binding_digest
        self._receipt_digest = receipt_digest
        self._manifest_digest = manifest_digest
        self._lock = Lock()
        self._consumed = False

    def _consume(self, *, provider_profile_digest: Digest) -> Digest:
        with self._lock:
            if self._consumed:
                raise CredentialSecurityError("provider access grant has already been consumed")
            self._consumed = True
            if provider_profile_digest != self._provider_profile_digest:
                raise CredentialSecurityError(
                    "provider access grant belongs to another provider profile"
                )
            return self._provider_config_digest

    def __repr__(self) -> str:
        return "ProviderAccessGrant(<opaque>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("provider access grants cannot be serialized")

    def __copy__(self) -> Any:
        raise TypeError("provider access grants cannot be copied")

    def __deepcopy__(self, _memo: object) -> Any:
        raise TypeError("provider access grants cannot be copied")


def _consume_attestation_for_provider_access(
    *,
    policy: CanaryPolicy,
    attestation: CanaryAttestation,
) -> tuple[ProviderAccessGrant, CanaryReceipt]:
    """Consume one concrete preflight attestation into one credential authority."""

    if type(policy) is not CanaryPolicy or type(attestation) is not CanaryAttestation:
        raise TypeError("provider access requires exact canary policy and attestation types")
    manifest = attestation.runtime_surface_manifest
    binding = manifest.binding
    if (
        policy.provider_profile_digest != binding.provider_profile_digest
        or policy.provider_config_digest != binding.provider_config_digest
        or policy.budget_binding_digest != binding.budget_binding_digest
    ):
        raise CredentialSecurityError(
            "provider access policy differs from the runtime surface manifest"
        )
    receipt = attestation.consume(
        policy_digest=policy.digest,
        campaign_digest=binding.campaign_digest,
        provider_profile_digest=binding.provider_profile_digest,
    )
    if receipt.manifest_digest != manifest.digest:
        raise CredentialSecurityError(
            "provider access receipt differs from the runtime surface manifest"
        )
    return (
        ProviderAccessGrant(
            provider_profile_digest=binding.provider_profile_digest,
            provider_config_digest=binding.provider_config_digest,
            campaign_digest=binding.campaign_digest,
            budget_binding_digest=binding.budget_binding_digest,
            receipt_digest=receipt.digest,
            manifest_digest=manifest.digest,
            _issuer=_PROVIDER_ACCESS_GRANT_ISSUER,
        ),
        receipt,
    )


class CredentialLease:
    """Opaque in-memory credential that zeroizes its mutable storage on close."""

    __slots__ = ("_closed", "_lock", "_profile_digest", "_value")

    def __init__(self, value: bytearray, *, profile_digest: Digest) -> None:
        if not value:
            raise CredentialFormatError("credential value cannot be empty")
        self._value = value
        self._profile_digest = profile_digest
        self._lock = Lock()
        self._closed = False

    def authorize(
        self,
        headers: MutableMapping[str, str],
        *,
        profile: ProviderProfile,
        beta_features: tuple[str, ...] = (),
    ) -> None:
        """Project protocol and credential headers from the bound provider identity."""

        with self._lock:
            if self._closed:
                raise CredentialSecurityError("credential lease is closed")
            if profile.digest != self._profile_digest:
                raise CredentialSecurityError("credential lease profile binding does not match")
            if any(
                name.casefold()
                in {"authorization", "x-api-key", "anthropic-version", "anthropic-beta"}
                for name in headers
            ):
                raise CredentialSecurityError("provider identity header is already present")
            if isinstance(profile.wire, MessagesWire):
                try:
                    beta_features = profile.wire.admit_features(beta_features)
                except ValueError:
                    raise CredentialSecurityError(
                        "provider beta feature grant does not match"
                    ) from None
            elif beta_features:
                raise CredentialSecurityError("Responses requests do not accept Messages features")
            value = self._value.decode("utf-8")
            if profile.wire.authorization is ProviderAuthorization.BEARER:
                headers["Authorization"] = "Bearer " + value
            else:
                headers["x-api-key"] = value
            if isinstance(profile.wire, MessagesWire):
                headers["anthropic-version"] = profile.wire.api_version
                if beta_features:
                    headers["anthropic-beta"] = ",".join(beta_features)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            for index in range(len(self._value)):
                self._value[index] = 0
            self._closed = True

    def __enter__(self) -> CredentialLease:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "CredentialLease(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("credential leases cannot be serialized")

    def __copy__(self) -> Any:
        raise TypeError("credential leases cannot be copied")

    def __deepcopy__(self, _memo: object) -> Any:
        raise TypeError("credential leases cannot be copied")


class ProviderAccessLease:
    """Bind an opaque credential to the exact non-secret provider projection."""

    __slots__ = ("credential", "resolved")

    def __init__(self, resolved: ResolvedProviderConfig, credential: CredentialLease) -> None:
        self.resolved = resolved
        self.credential = credential

    def close(self) -> None:
        self.credential.close()

    def __enter__(self) -> ProviderAccessLease:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "ProviderAccessLease(<redacted>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("provider access leases cannot be serialized")


class CredentialSource(Protocol):
    def acquire(self, *, grant: ProviderAccessGrant) -> ProviderAccessLease:
        """Consume preflight authority and revalidate config before opening auth."""


class ConfiguredCredentialSource:
    """Acquire only the file and decoder frozen in the provider's configuration."""

    def __init__(
        self, *, configuration: ResolvedProviderConfig, credential: CredentialConfig
    ) -> None:
        if (
            not credential.file_path.is_absolute()
            or credential.file_path != Path(os.path.abspath(credential.file_path))
            or configuration.credential_source_digest != credential.digest
        ):
            raise CredentialSecurityError(
                "credential locator differs from the frozen provider binding"
            )
        self._configuration = configuration
        self._credential = credential

    def acquire(self, *, grant: ProviderAccessGrant) -> ProviderAccessLease:
        if type(grant) is not ProviderAccessGrant:
            raise TypeError("credential acquisition requires an exact provider access grant")
        expected_config_digest = grant._consume(
            provider_profile_digest=self._configuration.profile.digest
        )
        if expected_config_digest != self._configuration.digest:
            raise CredentialSecurityError("provider configuration differs from its preflight grant")
        parent = _open_credential_directory(self._credential.file_path.parent)
        try:
            raw = _read_owned_private_file(
                parent, self._credential.file_path.name, uid=os.geteuid()
            )
            try:
                credential = _decode_credential(
                    raw,
                    decoder=self._credential.decoder,
                    profile_digest=self._configuration.profile.digest,
                )
            finally:
                _zeroize(raw)
        finally:
            os.close(parent)
        return ProviderAccessLease(self._configuration, credential)

    def __repr__(self) -> str:
        return "ConfiguredCredentialSource(<controller-only>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("credential sources cannot be serialized")


def _open_credential_directory(path: Path) -> int:
    descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        _validate_directory(descriptor, uid=os.geteuid(), name="credential directory")
        return descriptor
    except BaseException as error:
        os.close(descriptor)
        if isinstance(error, OSError):
            raise CredentialSecurityError("credential directory is not trusted") from None
        raise


def _validate_directory(fd: int, *, uid: int, name: str) -> None:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
        raise CredentialSecurityError(f"{name} has an unsafe owner or type")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise CredentialSecurityError(f"{name} is writable by another account")


def _read_owned_private_file(directory_fd: int, name: str, *, uid: int) -> bytearray:
    try:
        fd = os.open(name, _OPEN_FLAGS, dir_fd=directory_fd)
    except OSError:
        raise CredentialSecurityError("credential file is not a non-symlink regular file") from None
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_nlink != 1
            or not mode & stat.S_IRUSR
            or mode & 0o7177
        ):
            raise CredentialSecurityError("credential file owner, type, links, or mode is unsafe")
        if before.st_size > _MAX_CONFIG_BYTES:
            raise CredentialSecurityError("credential file exceeds the size bound")
        content = _read_stable_bytes(fd)
        after = os.fstat(fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            _zeroize(content)
            raise CredentialSecurityError("credential file changed while it was read")
        return content
    finally:
        os.close(fd)


def _read_stable_bytes(fd: int) -> bytearray:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(65536, _MAX_CONFIG_BYTES + 1 - total))
        if not chunk:
            return bytearray(b"".join(chunks))
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_CONFIG_BYTES:
            raise CredentialSecurityError("credential file exceeds the size bound")


def _decode_credential(
    raw: bytes | bytearray, *, decoder: CredentialDecoder, profile_digest: Digest
) -> CredentialLease:
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, CredentialFormatError):
        raise CredentialFormatError("auth file is not valid UTF-8 JSON") from None
    if not isinstance(decoded, dict):
        raise CredentialFormatError("auth file must be a top-level object")
    fields = {
        CredentialDecoder.CODEX_API_KEY_JSON: ("OPENAI_API_KEY",),
        CredentialDecoder.CLAUDE_SETTINGS_API_KEY: ("env", "ANTHROPIC_API_KEY"),
        CredentialDecoder.CLAUDE_SETTINGS_AUTH_TOKEN: ("env", "ANTHROPIC_AUTH_TOKEN"),
    }
    value: object = decoded
    for name in fields[decoder]:
        value = value.get(name) if isinstance(value, dict) else None
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or len(value) > _MAX_CREDENTIAL_BYTES
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise CredentialFormatError("auth file lacks the configured credential field")
    try:
        encoded = bytearray(value, "utf-8")
    except UnicodeEncodeError:
        raise CredentialFormatError("credential value is not valid UTF-8") from None
    return CredentialLease(encoded, profile_digest=profile_digest)


def _zeroize(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CredentialFormatError("auth file contains a duplicate object key")
        value[key] = item
    return value
