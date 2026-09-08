"""Descriptor-bound acquisition of controller-only provider credentials."""

from __future__ import annotations

import json
import os
import pwd as pwd
import stat
import tomllib
from collections.abc import Mapping, MutableMapping
from enum import StrEnum
from threading import Lock
from typing import Any, Protocol, SupportsIndex
from urllib.parse import urlsplit

from edagym.providers.model import (
    MessagesWire,
    ProviderAuthorization,
    ProviderDefaults,
    ProviderProfile,
    ResolvedProviderConfig,
    WireProtocol,
)
from edagym.security.canary import (
    CanaryAttestation,
    CanaryPolicy,
    CanaryReceipt,
)
from edagym.specs.common import Digest

_MAX_CONFIG_BYTES = 1 << 20
_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
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


class AuthDecoderVersion(StrEnum):
    TOP_LEVEL_OPENAI_API_KEY_V1 = "top-level-openai-api-key-v1"


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

    def authorize(self, headers: MutableMapping[str, str], *, profile: ProviderProfile) -> None:
        """Project protocol and credential headers from the bound provider identity."""

        with self._lock:
            if self._closed:
                raise CredentialSecurityError("credential lease is closed")
            if profile.digest != self._profile_digest:
                raise CredentialSecurityError("credential lease profile binding does not match")
            if any(
                name.casefold() in {"authorization", "x-api-key", "anthropic-version"}
                for name in headers
            ):
                raise CredentialSecurityError("provider identity header is already present")
            value = self._value.decode("utf-8")
            if profile.wire.authorization is ProviderAuthorization.BEARER:
                headers["Authorization"] = "Bearer " + value
            else:
                headers["x-api-key"] = value
            if isinstance(profile.wire, MessagesWire):
                headers["anthropic-version"] = profile.wire.api_version

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


class CodexCredentialSource:
    """Read the current account's local CLI files through directory descriptors."""

    decoder_version = AuthDecoderVersion.TOP_LEVEL_OPENAI_API_KEY_V1

    def __init__(self, *, trusted_profile: ProviderProfile) -> None:
        if type(trusted_profile) is not ProviderProfile:
            raise TypeError("credential sources require one explicit trusted provider profile")
        if trusted_profile.wire_protocol is not WireProtocol.RESPONSES:
            raise CredentialFormatError("Codex credentials require a Responses provider profile")
        self._trusted_profile = trusted_profile

    def inspect_profile(self) -> ResolvedProviderConfig:
        """Read only the non-secret config projection; never open the auth file."""

        uid, home_fd, codex_fd = _open_current_codex_directory()
        try:
            raw_config = _read_owned_private_file(codex_fd, "config.toml", uid=uid)
            try:
                return _decode_config_v1(
                    raw_config,
                    trusted_profile=self._trusted_profile,
                )
            finally:
                _zeroize(raw_config)
        finally:
            os.close(codex_fd)
            os.close(home_fd)

    def acquire(self, *, grant: ProviderAccessGrant) -> ProviderAccessLease:
        """Revalidate the config before opening and decoding the credential file."""

        if type(grant) is not ProviderAccessGrant:
            raise TypeError("credential acquisition requires an exact provider access grant")
        expected_config_digest = grant._consume(
            provider_profile_digest=self._trusted_profile.digest
        )
        uid, home_fd, codex_fd = _open_current_codex_directory()
        try:
            raw_config = _read_owned_private_file(codex_fd, "config.toml", uid=uid)
            try:
                resolved = _decode_config_v1(
                    raw_config,
                    trusted_profile=self._trusted_profile,
                )
            finally:
                _zeroize(raw_config)
            if resolved.digest != expected_config_digest:
                raise CredentialSecurityError("provider config changed after preflight")
            raw_auth = _read_owned_private_file(codex_fd, "auth.json", uid=uid)
            try:
                credential = _decode_auth_v1(raw_auth, profile_digest=resolved.profile.digest)
            finally:
                _zeroize(raw_auth)
            return ProviderAccessLease(resolved, credential)
        finally:
            os.close(codex_fd)
            os.close(home_fd)


def _open_current_codex_directory() -> tuple[int, int, int]:
    uid = os.geteuid()
    account = pwd.getpwuid(uid)
    if not os.path.isabs(account.pw_dir):
        raise CredentialSecurityError("passwd home must be absolute")
    try:
        home_fd = os.open(account.pw_dir, _DIRECTORY_FLAGS)
    except OSError:
        raise CredentialSecurityError("passwd home is not a trusted directory") from None
    try:
        _validate_directory(home_fd, uid=uid, name="passwd home")
        try:
            codex_fd = os.open(".codex", _DIRECTORY_FLAGS, dir_fd=home_fd)
        except OSError:
            raise CredentialSecurityError("credential directory is not trusted") from None
        try:
            _validate_directory(codex_fd, uid=uid, name="credential directory")
        except BaseException:
            os.close(codex_fd)
            raise
    except BaseException:
        os.close(home_fd)
        raise
    return uid, home_fd, codex_fd


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


def _decode_config_v1(
    raw: bytes | bytearray,
    *,
    trusted_profile: ProviderProfile,
) -> ResolvedProviderConfig:
    if type(trusted_profile) is not ProviderProfile:
        raise TypeError("config projection requires one explicit trusted provider profile")
    try:
        decoded = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise CredentialFormatError("provider config is not valid UTF-8 TOML") from None
    selected = decoded.get("model_provider")
    providers = decoded.get("model_providers")
    if not isinstance(selected, str) or not isinstance(providers, Mapping):
        raise CredentialFormatError("provider config has no selected provider table")
    provider = providers.get(selected)
    if not isinstance(provider, Mapping):
        raise CredentialFormatError("selected provider table is missing")
    base_url = provider.get("base_url")
    wire_api = provider.get("wire_api")
    requires_auth = provider.get("requires_openai_auth")
    supports_websockets = provider.get("supports_websockets")
    if (
        (base_url is not None and not isinstance(base_url, str))
        or wire_api != "responses"
        or requires_auth is not True
        or supports_websockets is not False
    ):
        raise CredentialFormatError("selected provider does not match the supported wire contract")
    if base_url is not None and _responses_api_base(base_url) != _trusted_api_base(trusted_profile):
        raise CredentialFormatError("selected provider base does not match its trusted identity")
    model = decoded.get("model")
    reasoning = decoded.get("model_reasoning_effort")
    service_tier = decoded.get("service_tier")
    if not isinstance(model, str):
        raise CredentialFormatError("provider config has no default model")
    if reasoning is not None and not isinstance(reasoning, str):
        raise CredentialFormatError("reasoning effort must be a string")
    if service_tier is not None and not isinstance(service_tier, str):
        raise CredentialFormatError("service tier must be a string")
    try:
        defaults = ProviderDefaults(
            requested_model=model,
            reasoning_effort=reasoning,
            service_tier=service_tier,
        )
    except ValueError:
        raise CredentialFormatError("provider request defaults are invalid") from None
    return ResolvedProviderConfig(
        selected_provider_label=selected,
        profile=trusted_profile,
        defaults=defaults,
    )


def _responses_api_base(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CredentialFormatError("selected provider base is invalid")
    path = parsed.path.rstrip("/")
    try:
        profile = ProviderProfile(
            logical_id="config_probe",
            origin=f"{parsed.scheme}://{parsed.netloc}",
            request_path=f"{path}/responses",
        )
    except ValueError:
        raise CredentialFormatError("selected provider base is invalid") from None
    return f"{profile.origin}{path}"


def _trusted_api_base(profile: ProviderProfile) -> str:
    suffix = "/responses"
    if not profile.request_path.endswith(suffix):
        raise CredentialFormatError("trusted provider does not expose a Responses API base")
    return f"{profile.origin}{profile.request_path.removesuffix(suffix)}"


def _decode_auth_v1(raw: bytes | bytearray, *, profile_digest: Digest) -> CredentialLease:
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, CredentialFormatError):
        raise CredentialFormatError("auth file is not valid UTF-8 JSON") from None
    if not isinstance(decoded, dict):
        raise CredentialFormatError("auth file must be a top-level object")
    value = decoded.get("OPENAI_API_KEY")
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or len(value) > _MAX_CREDENTIAL_BYTES
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise CredentialFormatError("auth file lacks the supported top-level credential field")
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
