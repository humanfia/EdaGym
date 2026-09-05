"""Opaque, bounded license leases for trusted tool processes."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Never, Protocol

from edagym.specs.common import Identifier


class LeaseState(StrEnum):
    ACTIVE = "active"
    DENIED = "denied"
    EXPIRED = "expired"
    RELEASED = "released"


class LicenseUnavailable(RuntimeError):
    """A bounded license lease could not be acquired or retained."""


class LicenseLease:
    """Non-serializable lease whose process environment remains private."""

    __slots__ = (
        "_environment",
        "_expires_at",
        "_feature_class",
        "_lease_id",
        "_provider_id",
        "_state",
    )

    def __init__(
        self,
        *,
        lease_id: str,
        provider_id: str,
        feature_class: str,
        expires_at: datetime,
        environment: Mapping[str, str],
    ) -> None:
        self._lease_id = lease_id
        self._provider_id = provider_id
        self._feature_class = feature_class
        self._expires_at = expires_at
        self._environment = dict(environment)
        self._state = LeaseState.ACTIVE

    def __repr__(self) -> str:
        return "LicenseLease(<opaque>)"

    def __reduce__(self) -> Never:
        raise TypeError("license leases cannot be serialized")

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def feature_class(self) -> str:
        return self._feature_class

    @property
    def state(self) -> LeaseState:
        if self._state is LeaseState.ACTIVE and datetime.now(UTC) >= self._expires_at:
            self._state = LeaseState.EXPIRED
        return self._state

    def _process_environment(self) -> dict[str, str]:
        if self.state is not LeaseState.ACTIVE:
            raise LicenseUnavailable("license lease is no longer active")
        return dict(self._environment)

    def _release(self) -> None:
        if self._state is not LeaseState.RELEASED:
            self._environment.clear()
            self._state = LeaseState.RELEASED


class LicenseProvider(Protocol):
    def acquire(
        self,
        *,
        feature_class: Identifier,
        run_id: str,
        ttl_seconds: int,
    ) -> LicenseLease: ...

    def renew(self, lease: LicenseLease, *, ttl_seconds: int) -> LeaseState: ...

    def release(self, lease: LicenseLease) -> LeaseState: ...


class FakeLicenseProvider:
    """Real concurrency and cleanup semantics without a vendor secret."""

    def __init__(
        self,
        *,
        provider_id: str = "fake_license",
        capacities: Mapping[str, int],
    ) -> None:
        if not capacities or any(value <= 0 for value in capacities.values()):
            raise ValueError("fake license capacities must be positive")
        self.provider_id = provider_id
        self._capacities = dict(capacities)
        self._active: dict[str, LicenseLease] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def acquire(
        self,
        *,
        feature_class: Identifier,
        run_id: str,
        ttl_seconds: int,
    ) -> LicenseLease:
        if ttl_seconds <= 0:
            raise ValueError("license TTL must be positive")
        with self._lock:
            self._discard_inactive()
            capacity = self._capacities.get(feature_class)
            active = sum(
                lease.feature_class == feature_class and lease.state is LeaseState.ACTIVE
                for lease in self._active.values()
            )
            if capacity is None or active >= capacity:
                raise LicenseUnavailable("license feature is unavailable")
            self._counter += 1
            lease_id = f"lease_{self._counter:08x}"
            lease = LicenseLease(
                lease_id=lease_id,
                provider_id=self.provider_id,
                feature_class=feature_class,
                expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
                environment={},
            )
            self._active[lease_id] = lease
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
        stale = [key for key, lease in self._active.items() if lease.state is not LeaseState.ACTIVE]
        for key in stale:
            self._active.pop(key)._release()
