"""The sole typed owner of a user's private EdaGym configuration."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, ValidationInfo, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import (
    Capability,
    Digest,
    Identifier,
    JcsNonNegativeInt,
    SchemaVersion,
    StrictModel,
)
from edagym.specs.environment import ExecutorKind, NetworkKind


class ToolSourceKind(StrEnum):
    """Where an externally supplied tool is made available."""

    USER_IMAGE = "user_image"
    INSTALLED_TREE = "installed_tree"


class ToolVisibility(StrEnum):
    EXACT_TOOLSET = "exact_toolset"
    DECLARED_BUNDLE = "declared_bundle"


class ConfigView(StrEnum):
    PARTICIPANT = "participant"
    EVALUATOR = "evaluator"


class HarnessKind(StrEnum):
    HUMAN = "human"
    CONTROLLED_AGENT = "controlled_agent"
    NATIVE_CLI = "native_cli"


class SessionKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    HYBRID = "hybrid"


class WebExposure(StrEnum):
    LOOPBACK = "loopback"
    EXTERNAL = "external"


class VerifierTrust(StrEnum):
    SAME_ACCOUNT = "same_account"
    SEPARATE_ACCOUNT = "separate_account"
    REMOTE_WORKER = "remote_worker"


class RuntimeBaseSpec(StrictModel):
    """One user-owned immutable root filesystem usable by a profile view."""

    runtime_id: Identifier
    image_reference: Annotated[str, Field(min_length=1, max_length=512)]
    image_digest: Digest
    architecture: Annotated[str, Field(min_length=1, max_length=64)]
    launcher_executable: Annotated[str, Field(min_length=1, max_length=128)] = "python3"

    @field_validator("image_reference", "architecture", "launcher_executable")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("runtime identifiers cannot contain whitespace boundaries or controls")
        return value


class UserImageToolSource(StrictModel):
    kind: Literal[ToolSourceKind.USER_IMAGE] = ToolSourceKind.USER_IMAGE
    runtime_id: Identifier
    executable: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")]
    image_digest: Digest


class InstalledTreeToolSource(StrictModel):
    """Phase-four external tool tree binding; paths stay in private snapshots."""

    kind: Literal[ToolSourceKind.INSTALLED_TREE] = ToolSourceKind.INSTALLED_TREE
    root_path: Path
    entrypoint_relative_path: Annotated[str, Field(min_length=1, max_length=512)]
    closure_evidence_digest: Digest

    @field_validator("entrypoint_relative_path")
    @classmethod
    def validate_entrypoint_path(cls, value: str) -> str:
        parts = Path(value).parts
        if Path(value).is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
            raise ValueError("installed tool entrypoint must be a normalized relative path")
        return Path(*parts).as_posix()


ToolSource = Annotated[
    UserImageToolSource | InstalledTreeToolSource,
    Field(discriminator="kind"),
]


class ToolConfig(StrictModel):
    tool_id: Identifier
    adapter_id: Identifier
    source: ToolSource
    version_label: Annotated[str, Field(min_length=1, max_length=160)]
    capabilities: Annotated[tuple[Capability, ...], Field(min_length=1)]
    visibility: ToolVisibility = ToolVisibility.EXACT_TOOLSET
    environment_reference_ids: tuple[Identifier, ...] = ()

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if len(value) != len(set(value)):
            raise ValueError("tool capabilities must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @field_validator("environment_reference_ids")
    @classmethod
    def normalize_environment_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("tool environment references must be unique")
        return tuple(sorted(value))


class LibraryConfig(StrictModel):
    library_id: Identifier
    source_path: Path
    content_digest: Digest
    allowed_views: Annotated[tuple[ConfigView, ...], Field(min_length=1)]

    @field_validator("allowed_views")
    @classmethod
    def normalize_views(cls, value: tuple[ConfigView, ...]) -> tuple[ConfigView, ...]:
        if len(value) != len(set(value)):
            raise ValueError("library views must be unique")
        return tuple(sorted(value, key=lambda item: item.value))


class ProviderConfig(StrictModel):
    provider_id: Identifier
    protocol: Annotated[str, Field(min_length=1, max_length=64)]
    endpoint: Annotated[str, Field(min_length=1, max_length=512)]
    model_id: Annotated[str, Field(min_length=1, max_length=160)]
    credential_reference: Identifier

    @field_validator("protocol", "endpoint", "model_id")
    @classmethod
    def reject_controls(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("provider values cannot contain whitespace boundaries or controls")
        return value


class HarnessConfig(StrictModel):
    harness_id: Identifier
    kind: HarnessKind
    executable_path: Path | None = None
    provider_id: Identifier | None = None
    version_label: Annotated[str, Field(min_length=1, max_length=160)]
    tool_permissions: tuple[Capability, ...] = ()

    @field_validator("tool_permissions")
    @classmethod
    def normalize_permissions(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if len(value) != len(set(value)):
            raise ValueError("harness tool permissions must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.kind is HarnessKind.HUMAN:
            if self.executable_path is not None or self.provider_id is not None:
                raise ValueError("human harnesses do not bind executables or providers")
        elif self.kind is HarnessKind.CONTROLLED_AGENT:
            if self.provider_id is None:
                raise ValueError("controlled harnesses require one provider reference")
        elif self.executable_path is None:
            raise ValueError("native CLI harnesses require an explicit executable path")
        return self


class SiteConfig(StrictModel):
    site_id: Identifier
    state_root: Path
    executor_kind: ExecutorKind = ExecutorKind.ROOTLESS_LOCAL
    max_concurrency: Annotated[int, Field(ge=1, le=65536)] = 1


class ResourceLimits(StrictModel):
    cpu_millicores: JcsNonNegativeInt = 0
    cpu_seconds: JcsNonNegativeInt = 0
    memory_bytes: JcsNonNegativeInt = 0
    process_count: Annotated[int, Field(strict=True, ge=0)] = 0
    wall_seconds: JcsNonNegativeInt = 0


class StoragePolicy(StrictModel):
    root: Path | None = None
    max_bytes: JcsNonNegativeInt = 0
    max_inodes: JcsNonNegativeInt = 0
    output_max_bytes: JcsNonNegativeInt = 0
    retention_seconds: JcsNonNegativeInt = 30 * 24 * 60 * 60

    @model_validator(mode="after")
    def validate_limits(self) -> Self:
        if self.max_bytes and self.output_max_bytes > self.max_bytes:
            raise ValueError("output storage limit cannot exceed storage limit")
        return self


class ProfileViewConfig(StrictModel):
    runtime_id: Identifier | None = None
    tool_ids: tuple[Identifier, ...] = ()
    library_ids: tuple[Identifier, ...] = ()
    network: NetworkKind = NetworkKind.NONE

    @field_validator("tool_ids", "library_ids")
    @classmethod
    def normalize_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("profile view references must be unique")
        return tuple(sorted(value))


class ProfileConfig(StrictModel):
    profile_id: Identifier
    site_id: Identifier
    participant: ProfileViewConfig
    evaluator: ProfileViewConfig
    verifier_trust: VerifierTrust = VerifierTrust.SAME_ACCOUNT
    resources: ResourceLimits = ResourceLimits()
    storage: StoragePolicy = StoragePolicy()


class SessionConfig(StrictModel):
    session_id: Identifier
    kind: SessionKind
    harness_id: Identifier | None = None
    max_requests: Annotated[int, Field(strict=True, ge=1)] = 1
    max_wall_seconds: Annotated[int, Field(strict=True, ge=1)] = 3600

    @model_validator(mode="after")
    def validate_harness(self) -> Self:
        if (self.kind is SessionKind.HUMAN) != (self.harness_id is None):
            raise ValueError("human sessions omit a harness and agent sessions require one")
        return self


class BenchmarkConfig(StrictModel):
    benchmark_id: Identifier
    benchmark_spec_digest: Digest
    roster_id: Identifier
    max_requests: Annotated[int, Field(ge=1)]
    max_wall_seconds: Annotated[int, Field(ge=1)]


class WebConfig(StrictModel):
    exposure: WebExposure = WebExposure.LOOPBACK
    host: Annotated[str, Field(min_length=1, max_length=255)] = "127.0.0.1"
    port: Annotated[int, Field(ge=0, le=65535)] = 0
    principal_id: Identifier = "local_user"
    principal_source: Identifier | None = None
    tls_termination_reference: Identifier | None = None
    token_file: Path | None = None

    @model_validator(mode="after")
    def validate_exposure(self) -> Self:
        loopback_hosts = {"127.0.0.1", "::1", "localhost"}
        if self.exposure is WebExposure.LOOPBACK:
            if self.host not in loopback_hosts:
                raise ValueError("loopback web exposure requires a loopback host")
            if self.principal_source is not None or self.tls_termination_reference is not None:
                raise ValueError(
                    "loopback web exposure does not use external authentication fields"
                )
        elif self.principal_source is None or self.tls_termination_reference is None:
            raise ValueError("external web exposure requires authentication and TLS references")
        return self


class SnapshotView(StrictModel):
    runtime_id: Identifier | None = None
    runtime_digest: Digest | None = None
    tool_ids: tuple[Identifier, ...]
    library_ids: tuple[Identifier, ...]
    network: NetworkKind
    resource_digest: Digest | None = None
    storage_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_runtime_identity(self) -> Self:
        if (self.runtime_id is None) != (self.runtime_digest is None):
            raise ValueError("a snapshot runtime requires both ID and digest")
        return self


class EdaGymConfig(StrictModel):
    """One private TOML document with no include, merge, or environment overlay layer."""

    schema_version: SchemaVersion = 1
    sites: tuple[SiteConfig, ...]
    runtimes: tuple[RuntimeBaseSpec, ...] = ()
    tools: tuple[ToolConfig, ...] = ()
    libraries: tuple[LibraryConfig, ...] = ()
    providers: tuple[ProviderConfig, ...] = ()
    harnesses: tuple[HarnessConfig, ...] = ()
    profiles: tuple[ProfileConfig, ...] = ()
    sessions: tuple[SessionConfig, ...] = ()
    benchmarks: tuple[BenchmarkConfig, ...] = ()
    web: WebConfig = WebConfig()
    source_path: Path | None = Field(default=None, exclude=True)

    @field_validator(
        "sites",
        "runtimes",
        "tools",
        "libraries",
        "providers",
        "harnesses",
        "profiles",
        "sessions",
        "benchmarks",
    )
    @classmethod
    def normalize_collections(
        cls, value: tuple[StrictModel, ...], info: ValidationInfo
    ) -> tuple[StrictModel, ...]:
        identifier_field = {
            "sites": "site_id",
            "runtimes": "runtime_id",
            "tools": "tool_id",
            "libraries": "library_id",
            "providers": "provider_id",
            "harnesses": "harness_id",
            "profiles": "profile_id",
            "sessions": "session_id",
            "benchmarks": "benchmark_id",
        }[str(info.field_name)]
        identifiers = [getattr(item, identifier_field) for item in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("configuration identifiers must be globally unique per section")
        return tuple(sorted(value, key=lambda item: getattr(item, identifier_field)))

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if not self.sites:
            raise ValueError("configuration requires at least one site")
        sites = {item.site_id for item in self.sites}
        runtimes = {item.runtime_id: item for item in self.runtimes}
        tools = {item.tool_id: item for item in self.tools}
        libraries = {item.library_id: item for item in self.libraries}
        providers = {item.provider_id for item in self.providers}
        harnesses = {item.harness_id for item in self.harnesses}

        for tool in self.tools:
            if isinstance(tool.source, UserImageToolSource):
                runtime = runtimes.get(tool.source.runtime_id)
                if runtime is None or runtime.image_digest != tool.source.image_digest:
                    raise ValueError("user-image tools must bind one declared runtime digest")
        for harness in self.harnesses:
            if harness.provider_id is not None and harness.provider_id not in providers:
                raise ValueError("harness references an unknown provider")
        for session in self.sessions:
            if session.harness_id is not None and session.harness_id not in harnesses:
                raise ValueError("session references an unknown harness")
        for profile in self.profiles:
            if profile.site_id not in sites:
                raise ValueError("profile references an unknown site")
            for view_name, view in (
                ("participant", profile.participant),
                ("evaluator", profile.evaluator),
            ):
                if view.runtime_id is not None and view.runtime_id not in runtimes:
                    raise ValueError("profile view references an unknown runtime")
                if set(view.tool_ids) - tools.keys():
                    raise ValueError("profile view references an unknown tool")
                if set(view.library_ids) - libraries.keys():
                    raise ValueError("profile view references an unknown library")
                expected_view = ConfigView(view_name)
                if any(
                    expected_view not in libraries[library_id].allowed_views
                    for library_id in view.library_ids
                ):
                    raise ValueError("profile view exceeds a library visibility policy")
                for tool_id in view.tool_ids:
                    tool = tools[tool_id]
                    if isinstance(tool.source, UserImageToolSource) and (
                        view.runtime_id != tool.source.runtime_id
                    ):
                        raise ValueError("user-image tool and profile view use different runtimes")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            self.model_dump(mode="json", exclude={"source_path"}),
            domain="edagym-private-config-v1",
        )

    def redacted_view(self) -> dict[str, object]:
        """Return an intentionally non-replayable configuration projection for CLI output."""

        return {
            "schema_version": self.schema_version,
            "sites": tuple(
                {
                    "site_id": site.site_id,
                    "executor_kind": site.executor_kind,
                    "max_concurrency": site.max_concurrency,
                    "state_root": "<private>",
                }
                for site in self.sites
            ),
            "runtimes": {"count": len(self.runtimes)},
            "tools": {"count": len(self.tools)},
            "libraries": {"count": len(self.libraries)},
            "providers": {"count": len(self.providers)},
            "harnesses": tuple(
                {
                    "harness_id": harness.harness_id,
                    "kind": harness.kind,
                }
                for harness in self.harnesses
            ),
            "profiles": tuple(
                {
                    "profile_id": profile.profile_id,
                    "site_id": profile.site_id,
                    "participant": {
                        "tool_count": len(profile.participant.tool_ids),
                        "library_count": len(profile.participant.library_ids),
                        "network": profile.participant.network,
                    },
                    "evaluator": {
                        "tool_count": len(profile.evaluator.tool_ids),
                        "library_count": len(profile.evaluator.library_ids),
                        "network": profile.evaluator.network,
                    },
                    "verifier_trust": profile.verifier_trust,
                }
                for profile in self.profiles
            ),
            "sessions": tuple(
                {
                    "session_id": session.session_id,
                    "kind": session.kind,
                    "harness_id": session.harness_id,
                }
                for session in self.sessions
            ),
            "web": {
                "exposure": self.web.exposure,
                "host": self.web.host,
                "port": self.web.port,
                "principal_id": self.web.principal_id,
            },
        }


class PrivateConfigSnapshot(StrictModel):
    """A selected, absolute-path configuration frozen for replay.

    The original document digest records provenance. Execution projections are
    derived from the frozen configuration, never from the current TOML file.
    """

    schema_version: SchemaVersion = 1
    config_digest: Digest
    configuration: EdaGymConfig

    @model_validator(mode="after")
    def validate_selection(self) -> Self:
        config = self.configuration
        if len(config.sites) != 1 or len(config.profiles) != 1:
            raise ValueError("a snapshot binds exactly one site and profile")
        paths = [config.sites[0].state_root]
        paths.extend(library.source_path for library in config.libraries)
        paths.extend(
            tool.source.root_path
            for tool in config.tools
            if isinstance(tool.source, InstalledTreeToolSource)
        )
        paths.extend(
            harness.executable_path
            for harness in config.harnesses
            if harness.executable_path is not None
        )
        storage = config.profiles[0].storage.root
        if storage is not None:
            paths.append(storage)
        if any(not path.is_absolute() for path in paths):
            raise ValueError("snapshot paths must already be absolute")
        return self

    @property
    def profile_id(self) -> str:
        return self.configuration.profiles[0].profile_id

    @property
    def site_id(self) -> str:
        return self.configuration.sites[0].site_id

    @property
    def verifier_trust(self) -> VerifierTrust:
        return self.configuration.profiles[0].verifier_trust

    @property
    def participant(self) -> SnapshotView:
        return self._view(self.configuration.profiles[0].participant)

    @property
    def evaluator(self) -> SnapshotView:
        return self._view(self.configuration.profiles[0].evaluator)

    def _view(self, view: ProfileViewConfig) -> SnapshotView:
        profile = self.configuration.profiles[0]
        runtime = next(
            (item for item in self.configuration.runtimes if item.runtime_id == view.runtime_id),
            None,
        )
        return SnapshotView(
            runtime_id=view.runtime_id,
            runtime_digest=None if runtime is None else runtime.image_digest,
            tool_ids=view.tool_ids,
            library_ids=view.library_ids,
            network=view.network,
            resource_digest=canonical_digest(
                profile.resources, domain="profile-resource-limits-v1"
            ),
            storage_digest=canonical_digest(profile.storage, domain="profile-storage-policy-v1"),
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="private-config-snapshot-v1")
