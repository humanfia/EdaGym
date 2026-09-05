"""Explicit, opaque authorization for commercial qualification workloads."""

from __future__ import annotations

import secrets
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, SupportsIndex

from pydantic import Field, TypeAdapter, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.drivers.deployment import BackendDeploymentConfiguration
from edagym.drivers.fixtures.model import FixtureRole, QualificationFixture
from edagym.drivers.model import BackendDefinition, BackendProbe, QualificationState, Vendor
from edagym.drivers.probe import (
    VERSION_PROBE_TIMEOUT_SECONDS,
    _module_environment,
    probe_backend,
)
from edagym.executors.licenses import LeaseState, LicenseLease, LicenseProvider, LicenseUnavailable
from edagym.specs.common import Capability, Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.environment import LicenseBinding

_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)
_PROVIDER_RUN_ID_ADAPTER: TypeAdapter[str] = TypeAdapter(Identifier | Digest)
_AUTHORIZATION_ISSUER = object()
_LEASE_COMPLETION_GUARD_SECONDS = 1


class CommercialQualificationAuthorizationError(RuntimeError):
    """A commercial qualification grant is invalid, closed, or already consumed."""


class CommercialQualificationReceipt(StrictModel):
    """Secret-free identity of one explicit commercial workload authorization."""

    schema_version: SchemaVersion = 1
    authorization_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: Identifier
    tool_id: Identifier
    vendor: Vendor
    capability: Capability
    driver_digest: Digest
    metadata_probe_digest: Digest
    fixture_digest: Digest
    license_binding_id: Identifier
    license_binding_digest: Digest
    provider_id: Identifier
    provider_digest: Digest
    feature_class: Identifier
    max_execution_seconds: int = Field(gt=0, le=3600)
    authorized_at: datetime
    expires_at: datetime

    @field_validator("authorized_at", "expires_at")
    @classmethod
    def normalize_authorized_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("commercial authorization time must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_commercial_authorization(self) -> CommercialQualificationReceipt:
        if self.vendor is Vendor.OPEN_SOURCE:
            raise ValueError("commercial authorization cannot target an open-source backend")
        if self.expires_at <= self.authorized_at:
            raise ValueError("commercial authorization must expire after it is issued")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="commercial-qualification-authorization-v1")


class CommercialLicenseProvider(LicenseProvider, Protocol):
    """License provider whose non-secret route is bound before authorization."""

    provider_id: Identifier
    provider_digest: Digest
    feature_class: Identifier
    tool_id: Identifier
    deployment_digest: Digest
    max_checkouts: int


class HostModuleLicenseProvider:
    """Load one trusted module environment into bounded, opaque leases."""

    def __init__(
        self,
        *,
        provider_id: str,
        feature_class: str,
        deployment_configuration: BackendDeploymentConfiguration,
        max_checkouts: int,
    ) -> None:
        self.provider_id = _IDENTIFIER_ADAPTER.validate_python(provider_id)
        self.feature_class = _IDENTIFIER_ADAPTER.validate_python(feature_class)
        if not deployment_configuration.revalidate():
            raise ValueError("deployment configuration is no longer valid")
        if max_checkouts <= 0:
            raise ValueError("license checkout capacity must be positive")
        self.tool_id = _IDENTIFIER_ADAPTER.validate_python(deployment_configuration.tool_id)
        self.deployment_digest = deployment_configuration.deployment_digest
        self._deployment_configuration = deployment_configuration
        self.max_checkouts = max_checkouts
        self.provider_digest = canonical_digest(
            {
                "protocol_revision": 1,
                "provider_id": self.provider_id,
                "feature_class": self.feature_class,
                "tool_id": self.tool_id,
                "deployment_digest": self.deployment_digest,
                "max_checkouts": self.max_checkouts,
            },
            domain="host-module-license-provider-v1",
        )
        self._active: dict[str, LicenseLease] = {}
        self._counter = 0
        self._lock = threading.Lock()

    def acquire(
        self,
        *,
        feature_class: Identifier,
        run_id: str,
        ttl_seconds: int,
    ) -> LicenseLease:
        _PROVIDER_RUN_ID_ADAPTER.validate_python(run_id)
        if feature_class != self.feature_class:
            raise LicenseUnavailable("license feature is unavailable")
        if ttl_seconds <= 0:
            raise ValueError("license TTL must be positive")
        with self._lock:
            self._discard_inactive()
            if len(self._active) >= self.max_checkouts:
                raise LicenseUnavailable("license feature is unavailable")
            try:
                if not self._deployment_configuration.revalidate():
                    raise OSError("deployment configuration changed")
                environment = _module_environment(
                    self._deployment_configuration.module_name
                )
            except (OSError, subprocess.SubprocessError, UnicodeError):
                raise LicenseUnavailable("license environment is unavailable") from None
            self._counter += 1
            lease = LicenseLease(
                lease_id=f"commercial_{self._counter:08x}_{secrets.token_hex(8)}",
                provider_id=self.provider_id,
                feature_class=self.feature_class,
                expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
                environment=environment,
            )
            self._active[lease.lease_id] = lease
            return lease

    def renew(self, lease: LicenseLease, *, ttl_seconds: int) -> LeaseState:
        if ttl_seconds <= 0:
            raise ValueError("license TTL must be positive")
        with self._lock:
            if (
                self._active.get(lease.lease_id) is not lease
                or lease.state is not LeaseState.ACTIVE
            ):
                return lease.state
            lease._expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
            return lease.state

    def release(self, lease: LicenseLease) -> LeaseState:
        with self._lock:
            owned = self._active.pop(lease.lease_id, None)
            if owned is lease:
                lease._release()
            return lease.state

    def _discard_inactive(self) -> None:
        stale = [
            lease_id
            for lease_id, lease in self._active.items()
            if lease.state is not LeaseState.ACTIVE
        ]
        for lease_id in stale:
            self._active.pop(lease_id)._release()


class CommercialQualificationAuthorization:
    """Single-use, process-local authority for one canonical commercial fixture."""

    __slots__ = ("_closed", "_consumed", "_lease", "_lock", "_provider", "_receipt")

    def __init__(
        self,
        *,
        receipt: CommercialQualificationReceipt,
        lease: LicenseLease,
        provider: CommercialLicenseProvider,
        _issuer: object,
    ) -> None:
        if _issuer is not _AUTHORIZATION_ISSUER:
            raise CommercialQualificationAuthorizationError(
                "commercial authorizations can only be issued by a license broker"
            )
        self._receipt = receipt
        self._lease = lease
        self._provider = provider
        self._lock = threading.Lock()
        self._consumed = False
        self._closed = False

    @property
    def receipt(self) -> CommercialQualificationReceipt:
        return self._receipt

    def _consume(
        self,
        *,
        definition: BackendDefinition,
        metadata_probe: BackendProbe,
        fixture: QualificationFixture,
        timeout_seconds: int,
    ) -> tuple[CommercialQualificationReceipt, LicenseLease]:
        with self._lock:
            if self._closed:
                raise CommercialQualificationAuthorizationError(
                    "commercial qualification authorization is closed"
                )
            if self._consumed:
                raise CommercialQualificationAuthorizationError(
                    "commercial qualification authorization was already consumed"
                )
            receipt = self._receipt
            if (
                receipt.tool_id != definition.tool_id
                or receipt.vendor is not definition.vendor
                or receipt.capability is not fixture.capability
                or receipt.driver_digest != definition.driver_digest
                or receipt.metadata_probe_digest
                != canonical_digest(metadata_probe, domain="backend-probe-v1")
                or receipt.fixture_digest != fixture.digest
            ):
                raise CommercialQualificationAuthorizationError(
                    "commercial qualification authorization binding does not match"
                )
            workload_seconds = timeout_seconds * len(fixture.invocations) * len(FixtureRole)
            if workload_seconds > receipt.max_execution_seconds:
                raise CommercialQualificationAuthorizationError(
                    "commercial workload exceeds its authorized execution time"
                )
            required_seconds = (
                VERSION_PROBE_TIMEOUT_SECONDS + workload_seconds + _LEASE_COMPLETION_GUARD_SECONDS
            )
            required_until = datetime.now(UTC) + timedelta(seconds=required_seconds)
            if required_until > receipt.expires_at:
                raise CommercialQualificationAuthorizationError(
                    "commercial qualification lease cannot cover the workload"
                )
            if self._lease.state is not LeaseState.ACTIVE:
                raise CommercialQualificationAuthorizationError(
                    "commercial qualification license lease is not active"
                )
            self._consumed = True
            return receipt, self._lease

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._provider.release(self._lease)
            finally:
                self._closed = True

    def __enter__(self) -> CommercialQualificationAuthorization:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "CommercialQualificationAuthorization(<opaque>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("commercial qualification authorizations cannot be serialized")

    def __copy__(self) -> Any:
        raise TypeError("commercial qualification authorizations cannot be copied")

    def __deepcopy__(self, _memo: object) -> Any:
        raise TypeError("commercial qualification authorizations cannot be copied")


class CommercialQualificationLicenseBroker:
    """Issue an exact commercial fixture grant from one canonical license binding."""

    def __init__(
        self,
        *,
        binding: LicenseBinding,
        provider: CommercialLicenseProvider,
        deployment_configuration: BackendDeploymentConfiguration,
    ) -> None:
        if (
            binding.provider_id != provider.provider_id
            or binding.provider_digest != provider.provider_digest
            or binding.feature_class != provider.feature_class
            or binding.max_checkouts != provider.max_checkouts
            or provider.tool_id != deployment_configuration.tool_id
            or provider.deployment_digest != deployment_configuration.deployment_digest
            or not deployment_configuration.revalidate()
        ):
            raise ValueError("license binding does not match its provider")
        self._binding = binding
        self._provider = provider
        self._deployment_configuration = deployment_configuration

    def authorize(
        self,
        *,
        definition: BackendDefinition,
        metadata_probe: BackendProbe,
        fixture: QualificationFixture,
        run_id: str,
        max_execution_seconds: int,
    ) -> CommercialQualificationAuthorization:
        from edagym.drivers.catalog import backend_by_id
        from edagym.drivers.fixtures import fixture_for

        if definition.workload_use_requires_eula_acceptance:
            raise CommercialQualificationAuthorizationError(
                "commercial workload use requires explicit EULA acceptance"
            )
        canonical_definition = backend_by_id(definition.tool_id)
        canonical_fixture = fixture_for(definition.tool_id, fixture.capability)
        if (
            canonical_definition.driver_digest != definition.driver_digest
            or canonical_fixture is None
            or canonical_fixture.digest != fixture.digest
            or fixture.log_projection is None
            or not fixture.rejection_inputs
        ):
            raise CommercialQualificationAuthorizationError(
                "commercial authorization requires a canonical backend fixture"
            )
        if (
            definition.vendor is Vendor.OPEN_SOURCE
            or metadata_probe.state is not QualificationState.DETECTED
            or metadata_probe.tool_id != definition.tool_id
            or metadata_probe.vendor is not definition.vendor
            or metadata_probe.capabilities != definition.capabilities
            or metadata_probe.host_support_mode is not definition.host_support_mode
            or metadata_probe.driver_digest != definition.driver_digest
            or self._deployment_configuration.tool_id != definition.tool_id
            or not self._deployment_configuration.revalidate()
            or fixture.capability not in definition.capabilities
        ):
            raise CommercialQualificationAuthorizationError(
                "commercial authorization target does not match detected metadata"
            )
        current_probe, installation = probe_backend(
            definition,
            deployment_configuration=self._deployment_configuration,
        )
        if installation is not None or canonical_digest(
            current_probe,
            domain="backend-probe-v1",
        ) != canonical_digest(metadata_probe, domain="backend-probe-v1"):
            raise CommercialQualificationAuthorizationError(
                "commercial deployment metadata changed before authorization"
            )
        if max_execution_seconds <= 0 or max_execution_seconds > 3600:
            raise ValueError("commercial execution time must be between one second and one hour")
        required_seconds = (
            max_execution_seconds + VERSION_PROBE_TIMEOUT_SECONDS + _LEASE_COMPLETION_GUARD_SECONDS
        )
        if required_seconds > self._binding.lease_ttl_seconds:
            raise CommercialQualificationAuthorizationError(
                "commercial execution and resolution time exceed the license lease TTL"
            )
        validated_run_id = _IDENTIFIER_ADAPTER.validate_python(run_id)
        lease_deadline = datetime.now(UTC) + timedelta(seconds=self._binding.lease_ttl_seconds)
        lease = self._provider.acquire(
            feature_class=self._binding.feature_class,
            run_id=validated_run_id,
            ttl_seconds=self._binding.lease_ttl_seconds,
        )
        if (
            lease.state is not LeaseState.ACTIVE
            or lease.provider_id != self._binding.provider_id
            or lease.feature_class != self._binding.feature_class
        ):
            self._provider.release(lease)
            raise CommercialQualificationAuthorizationError(
                "license provider returned a mismatched lease"
            )
        try:
            authorized_at = datetime.now(UTC)
            if authorized_at + timedelta(seconds=required_seconds) > lease_deadline:
                raise CommercialQualificationAuthorizationError(
                    "license provider returned an insufficient lease lifetime"
                )
            receipt = CommercialQualificationReceipt(
                authorization_id=secrets.token_hex(16),
                run_id=validated_run_id,
                tool_id=definition.tool_id,
                vendor=definition.vendor,
                capability=fixture.capability,
                driver_digest=definition.driver_digest,
                metadata_probe_digest=canonical_digest(
                    metadata_probe,
                    domain="backend-probe-v1",
                ),
                fixture_digest=fixture.digest,
                license_binding_id=self._binding.license_binding_id,
                license_binding_digest=canonical_digest(
                    self._binding,
                    domain="license-binding-v1",
                ),
                provider_id=self._binding.provider_id,
                provider_digest=self._binding.provider_digest,
                feature_class=self._binding.feature_class,
                max_execution_seconds=max_execution_seconds,
                authorized_at=authorized_at,
                expires_at=lease_deadline,
            )
            return CommercialQualificationAuthorization(
                receipt=receipt,
                lease=lease,
                provider=self._provider,
                _issuer=_AUTHORIZATION_ISSUER,
            )
        except BaseException:
            self._provider.release(lease)
            raise
