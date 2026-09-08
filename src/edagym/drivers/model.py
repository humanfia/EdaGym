"""Backend inventory and qualification evidence contracts."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Capability, Digest, Identifier, SchemaVersion, StrictModel

_EXECUTABLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_DRIVER_PROTOCOL_REVISION = 4


class Vendor(StrEnum):
    OPEN_SOURCE = "open_source"
    CADENCE = "cadence"
    SYNOPSYS = "synopsys"
    AMD = "amd"
    ALTERA = "altera"
    ACHRONIX = "achronix"


def qualification_fixture_id(tool_id: str, capability: Capability) -> str:
    """Derive the only fixture identity for a backend capability."""

    return f"{tool_id}_{capability.value.replace('.', '_')}"


class QualificationState(StrEnum):
    DETECTED = "detected"
    INVOCABLE = "invocable"
    UNAVAILABLE = "unavailable"


class ExecutableInvocationMode(StrEnum):
    DESCRIPTOR_BOUND = "descriptor_bound"
    ROOTLESS_IMAGE = "rootless_image"
    TRUSTED_PATH = "trusted_path"
    SITE_CONTAINER = "site_container"


class HostSupportMode(StrEnum):
    DEFAULT = "default"
    VENDOR_UNSUPPORTED = "vendor_unsupported"
    VENDOR_UNSUPPORTED_OVERRIDE = "vendor_unsupported_override"


class UnavailableReason(StrEnum):
    MODULE_UNAVAILABLE = "module_unavailable"
    MODULE_LOAD_FAILED = "module_load_failed"
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    VERSION_PROBE_FAILED = "version_probe_failed"
    LICENSE_UNAVAILABLE = "license_unavailable"
    FIXTURE_FAILED = "fixture_failed"
    POLICY_UNAVAILABLE = "policy_unavailable"


class CapabilityFixture(StrictModel):
    capability: Capability
    fixture_id: Identifier
    implementation_family: Identifier


class BackendDefinition(StrictModel):
    tool_id: Identifier
    vendor: Vendor
    capabilities: tuple[Capability, ...]
    executable_candidates: tuple[Annotated[str, Field(max_length=128)], ...]
    supporting_executables: tuple[Annotated[str, Field(max_length=128)], ...] = Field(
        default=(), exclude_if=lambda value: not value,
    )
    version_arguments: tuple[Annotated[str, Field(max_length=128)], ...]
    accepted_version_exit_codes: tuple[int, ...] = (0,)
    version_identity_pattern: str | None = Field(
        default=None,
        max_length=512,
        exclude_if=lambda value: value is None,
    )
    workload_use_requires_eula_acceptance: bool = Field(
        default=False,
        exclude_if=lambda value: not value,
    )
    fixtures: tuple[CapabilityFixture, ...] = ()
    host_support_mode: HostSupportMode = HostSupportMode.DEFAULT

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("backend capabilities must be unique and non-empty")
        return tuple(sorted(value, key=lambda item: item.value))

    @field_validator("executable_candidates")
    @classmethod
    def validate_executables(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not value
            or len(value) != len(set(value))
            or any(not _EXECUTABLE.fullmatch(item) for item in value)
        ):
            raise ValueError("backend executable candidates must be unique command names")
        return value

    @field_validator("supporting_executables")
    @classmethod
    def validate_supporting_executables(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not _EXECUTABLE.fullmatch(item) for item in value):
            raise ValueError("supporting executables must be unique command names")
        return tuple(sorted(value))

    @field_validator("version_arguments")
    @classmethod
    def validate_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in item or "\n" in item or "\r" in item for item in value):
            raise ValueError("version arguments cannot contain control boundaries")
        return value

    @field_validator("accepted_version_exit_codes")
    @classmethod
    def validate_version_exit_codes(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if (
            not value
            or 0 not in value
            or len(value) != len(set(value))
            or tuple(sorted(value)) != value
            or any(
                isinstance(code, bool) or not isinstance(code, int) or code < 0 or code > 255
                for code in value
            )
        ):
            raise ValueError(
                "accepted version exit codes must be unique ordered process statuses including zero"
            )
        return value

    @field_validator("version_identity_pattern")
    @classmethod
    def validate_version_identity_pattern(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            encoded = value.encode("ascii")
            pattern = re.compile(encoded, flags=re.MULTILINE)
        except (UnicodeEncodeError, re.error) as error:
            raise ValueError("version identity patterns must be valid ASCII regexes") from error
        if pattern.groups or pattern.search(b"") is not None:
            raise ValueError("version identity patterns must be nonempty and capture-free")
        return value

    @field_validator("fixtures")
    @classmethod
    def normalize_fixtures(
        cls, value: tuple[CapabilityFixture, ...]
    ) -> tuple[CapabilityFixture, ...]:
        capabilities = [item.capability for item in value]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("a backend may own one fixture per capability")
        return tuple(sorted(value, key=lambda item: item.capability.value))

    @model_validator(mode="after")
    def validate_fixture_capabilities(self) -> Self:
        if set(self.supporting_executables) & set(self.executable_candidates):
            raise ValueError("supporting executables must differ from primary candidates")
        if any(item.capability not in self.capabilities for item in self.fixtures):
            raise ValueError("backend fixture references an undeclared capability")
        if self.vendor is Vendor.OPEN_SOURCE and self.workload_use_requires_eula_acceptance:
            raise ValueError("open-source backends cannot require commercial EULA acceptance")
        return self

    @property
    def driver_digest(self) -> str:
        return canonical_digest(
            {"protocol_revision": _DRIVER_PROTOCOL_REVISION, "definition": self},
            domain="tool-driver-v1",
        )


class BackendProbe(StrictModel):
    """Public, path-free resolution result with one opaque deployment attestation."""

    tool_id: Identifier
    vendor: Vendor
    capabilities: tuple[Capability, ...]
    state: QualificationState
    tool_version: str | None = None
    deployment_attestation_digest: Digest | None = None
    host_support_mode: HostSupportMode = HostSupportMode.DEFAULT
    driver_digest: Digest
    reason: UnavailableReason | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.state is QualificationState.INVOCABLE and (
            self.tool_version is None or self.deployment_attestation_digest is None
        ):
            raise ValueError("invocable backends require versioned deployment attestation")
        if self.state is QualificationState.DETECTED and (
            self.tool_version is not None or self.deployment_attestation_digest is None
        ):
            raise ValueError("detected backends require metadata-only deployment attestation")
        if self.state is QualificationState.UNAVAILABLE and self.reason is None:
            raise ValueError("unavailable backends require a typed reason")
        if self.state is not QualificationState.UNAVAILABLE and self.reason is not None:
            raise ValueError("only unavailable backends may carry an unavailable reason")
        if self.state is QualificationState.UNAVAILABLE and (
            self.tool_version is not None or self.deployment_attestation_digest is not None
        ):
            raise ValueError("unavailable backends cannot carry resolution evidence")
        return self


class BackendCatalog(StrictModel):
    """Canonical public backend inventory, independent of local deployment."""

    schema_version: SchemaVersion = 1
    backends: tuple[BackendDefinition, ...]

    @field_validator("backends")
    @classmethod
    def normalize_backends(
        cls,
        value: tuple[BackendDefinition, ...],
    ) -> tuple[BackendDefinition, ...]:
        identities = [item.tool_id for item in value]
        if not value or len(identities) != len(set(identities)):
            raise ValueError("backend catalog must contain unique tool identities")
        return tuple(sorted(value, key=lambda item: item.tool_id))

    @model_validator(mode="after")
    def validate_capability_coverage(self) -> Self:
        covered = {capability for backend in self.backends for capability in backend.capabilities}
        if covered != set(Capability):
            raise ValueError("backend catalog must cover every capability")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="public-backend-catalog-v1")
