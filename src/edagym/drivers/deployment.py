"""Owner-only host deployment selection for backend resolution."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, SupportsIndex

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.drivers.closure import (
    ClosureEnvironmentBinding,
    ClosureRecipeComponent,
    ExecutionClosureRequirementRef,
    SiteContainerExecutionRecipe,
    SiteContainerLauncherKind,
    SiteContainerOperatingSystem,
)
from edagym.executors.asset_policy import AssetSourcePolicy, _issue_asset_source_policy
from edagym.policy.private_roots import (
    PrivateRootRegistration,
    PrivateRootRole,
    _bind_private_root_from_descriptor,
)
from edagym.specs.common import Digest, Identifier, StrictModel

_MODULE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/@:-]{0,159}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOST_ENVIRONMENT_NAMES = frozenset(
    {"HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "USER", "XDG_RUNTIME_DIR"}
)
_MAX_DEPLOYMENT_BYTES = 1024 * 1024
_MAX_MOUNTS = 32
_MAX_COMPONENTS = 128
_MAX_ENVIRONMENT_BINDINGS = 32
_MAX_PATH_BYTES = 4096
_BROAD_MOUNT_ROOTS = frozenset(
    Path(path)
    for path in (
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/mnt",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
        "/var",
    )
)
_RESERVED_TARGET_TREES = tuple(
    PurePosixPath(path)
    for path in (
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
        "/var/lib/containers",
        "/var/lib/docker",
        "/var/run",
    )
)


class DeploymentBindingKind(StrEnum):
    """Private runtime substrate selected for one catalog tool."""

    HOST_MODULE = "host_module"
    SITE_CONTAINER = "site_container"


class _DeploymentComponent(StrictModel):
    role: Identifier
    relative_path: str


class _DeploymentEnvironmentBinding(StrictModel):
    variable_name: str
    component_role: Identifier


class _DeploymentMount(StrictModel):
    source: Annotated[str, Field(min_length=2, max_length=_MAX_PATH_BYTES)]
    target: Annotated[str, Field(min_length=2, max_length=_MAX_PATH_BYTES)]

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        source = Path(self.source)
        target = PurePosixPath(self.target)
        if (
            not source.is_absolute()
            or not target.is_absolute()
            or source.as_posix() != self.source
            or target.as_posix() != self.target
            or source in _BROAD_MOUNT_ROOTS
            or target == PurePosixPath("/")
            or any(target == item or item in target.parents for item in _RESERVED_TARGET_TREES)
            or "\x00" in self.source
            or "\x00" in self.target
            or ":" in self.source
            or ":" in self.target
        ):
            raise ValueError("deployment mounts require absolute path pairs")
        return self


class _HostModuleDeploymentBinding(StrictModel):
    kind: Literal[DeploymentBindingKind.HOST_MODULE] = DeploymentBindingKind.HOST_MODULE
    tool_id: Identifier
    module_name: str

    @field_validator("module_name")
    @classmethod
    def validate_module_name(cls, value: str) -> str:
        if _MODULE.fullmatch(value) is None:
            raise ValueError("deployment module names must be normalized identities")
        return value


class _SiteContainerDeploymentBinding(StrictModel):
    kind: Literal[DeploymentBindingKind.SITE_CONTAINER] = DeploymentBindingKind.SITE_CONTAINER
    tool_id: Identifier
    module_name: str
    requirement_id: Identifier
    operating_system: SiteContainerOperatingSystem
    launcher_kind: SiteContainerLauncherKind
    launcher: str
    image_inspector: str
    image_reference: str
    image_digest: Digest
    container_user: str
    trusted_owner_uid: int
    readonly_mounts: tuple[_DeploymentMount, ...]
    root_environment_variable: str
    entrypoint_relative_path: str
    components: tuple[_DeploymentComponent, ...]
    tool_environment_names: tuple[str, ...]
    environment_bindings: tuple[_DeploymentEnvironmentBinding, ...] = ()

    @field_validator("module_name")
    @classmethod
    def validate_module_name(cls, value: str) -> str:
        if _MODULE.fullmatch(value) is None:
            raise ValueError("deployment module names must be normalized identities")
        return value

    @field_validator("launcher", "image_inspector")
    @classmethod
    def validate_absolute_executable(cls, value: str) -> str:
        if not Path(value).is_absolute() or "\x00" in value:
            raise ValueError("deployment executables must be absolute")
        return value

    @model_validator(mode="after")
    def validate_private_closure_bounds(self) -> Self:
        if (
            not 0 < len(self.readonly_mounts) <= _MAX_MOUNTS
            or not 0 < len(self.components) <= _MAX_COMPONENTS
            or len(self.environment_bindings) > _MAX_ENVIRONMENT_BINDINGS
            or len(self.tool_environment_names) > _MAX_ENVIRONMENT_BINDINGS
            or self.trusted_owner_uid <= 0
            or self.trusted_owner_uid == os.getuid()
            or self.trusted_owner_uid > 2**31 - 1
            or not _mount_set_is_bounded(
                tuple((Path(item.source), item.target) for item in self.readonly_mounts),
                self.trusted_owner_uid,
            )
        ):
            raise ValueError("site-container deployment closure is not bounded")
        return self


_DeploymentBinding = Annotated[
    _HostModuleDeploymentBinding | _SiteContainerDeploymentBinding,
    Field(discriminator="kind"),
]


class _DeploymentDocument(StrictModel):
    schema_version: Literal[2]
    deployment_id: Identifier
    bindings: tuple[_DeploymentBinding, ...]

    @field_validator("bindings")
    @classmethod
    def validate_bindings(
        cls,
        value: tuple[_DeploymentBinding, ...],
    ) -> tuple[_DeploymentBinding, ...]:
        identities = [item.tool_id for item in value]
        if not value or len(identities) != len(set(identities)):
            raise ValueError("deployment bindings must have unique tool identities")
        return tuple(sorted(value, key=lambda item: item.tool_id))

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="backend-deployment-v2")


@dataclass(frozen=True, slots=True, repr=False)
class DeploymentRegistrySnapshot:
    """Private descriptor identity for one deployment registry read."""

    path: Path
    file_identity: tuple[int, int, int, int, int, int, int, int, int]
    content_digest: str

    def __repr__(self) -> str:
        return "DeploymentRegistrySnapshot(<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("deployment registry snapshots cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class MountRootSnapshot:
    """Private identity of one exact readonly deployment mount root."""

    path: Path
    chain_identities: tuple[
        tuple[str, tuple[int, int, int, int, int, int, int, int, int]], ...
    ]

    def revalidate(self) -> bool:
        try:
            return _mount_chain_identity(self.path) == self.chain_identities
        except OSError:
            return False

    def __repr__(self) -> str:
        return "MountRootSnapshot(<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("deployment mount snapshots cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class HostModuleConfiguration:
    """Private selection of one module-backed host installation."""

    tool_id: str
    module_name: str
    deployment_id: str
    deployment_digest: str
    _registry_digest: str
    _deployment_snapshot: DeploymentRegistrySnapshot

    def __repr__(self) -> str:
        return f"HostModuleConfiguration(tool_id={self.tool_id!r}, selection=<restricted>)"

    def revalidate(self) -> bool:
        return _configuration_snapshot_matches(
            self._deployment_snapshot,
            self.deployment_id,
            self._registry_digest,
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("deployment configurations cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class SiteContainerBroker:
    """Private broker inputs; serialized evidence contains only their digests."""

    operating_system: SiteContainerOperatingSystem
    deployment_id: str
    deployment_digest: str
    launcher_kind: SiteContainerLauncherKind
    launcher: Path
    image_inspector: Path
    image_reference: str
    image_digest: str
    host_environment: Mapping[str, str]
    container_user: str
    trusted_owner_uid: int
    readonly_mounts: tuple[tuple[Path, str], ...]
    mount_snapshots: tuple[MountRootSnapshot, ...]

    def __post_init__(self) -> None:
        mount_sources = [source for source, _ in self.readonly_mounts]
        mount_targets = [target for _, target in self.readonly_mounts]
        if (
            not self.launcher.is_absolute()
            or not self.image_inspector.is_absolute()
            or len(self.deployment_id) > 96
            or _IDENTIFIER.fullmatch(self.deployment_id) is None
            or _DIGEST.fullmatch(self.deployment_digest) is None
            or not self.image_reference
            or _DIGEST.fullmatch(self.image_digest) is None
            or not set(self.host_environment).issubset(_HOST_ENVIRONMENT_NAMES)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,95}", self.container_user) is None
            or len(mount_sources) != len(set(mount_sources))
            or len(mount_targets) != len(set(mount_targets))
            or not _mount_set_is_bounded(self.readonly_mounts, self.trusted_owner_uid)
            or tuple(item.path for item in self.mount_snapshots) != tuple(mount_sources)
            or (
                self.launcher_kind is SiteContainerLauncherKind.PODMAN
                and (
                    not self.image_reference.endswith(f"@{self.image_digest}")
                    or not self.readonly_mounts
                )
            )
        ):
            raise ValueError("site-container broker inputs are not bounded")
        object.__setattr__(
            self,
            "host_environment",
            MappingProxyType(dict(self.host_environment)),
        )

    def __repr__(self) -> str:
        return (
            "SiteContainerBroker(operating_system="
            f"{self.operating_system.value!r}, paths=<restricted>, environment=<restricted>)"
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("site-container brokers cannot be serialized")

    def revalidate_mounts(self) -> bool:
        return _root_owned_immutable_executable(
            self.launcher
        ) and _root_owned_immutable_executable(self.image_inspector) and all(
            item.revalidate() for item in self.mount_snapshots
        )

    def path_has_trusted_owner(self, path: Path) -> bool:
        try:
            original = Path(os.path.normpath(path))
            resolved = original.resolve(strict=True)
            if not original.is_absolute():
                return False
            components = {*original.parents, resolved, *resolved.parents}
            return all(
                _owned_nonwritable_path(component, {0, self.trusted_owner_uid})
                for component in components
            ) and _symlink_chain_has_trusted_owner(original, self.trusted_owner_uid)
        except OSError:
            return False


@dataclass(frozen=True, slots=True, repr=False)
class SiteContainerConfiguration:
    """Private container recipe selected for one catalog tool."""

    tool_id: str
    module_name: str
    requirement: ExecutionClosureRequirementRef
    recipe: SiteContainerExecutionRecipe
    broker: SiteContainerBroker
    _registry_digest: str
    _deployment_snapshot: DeploymentRegistrySnapshot

    @property
    def deployment_id(self) -> str:
        return self.broker.deployment_id

    @property
    def deployment_digest(self) -> str:
        return self.broker.deployment_digest

    def __repr__(self) -> str:
        return f"SiteContainerConfiguration(tool_id={self.tool_id!r}, selection=<restricted>)"

    def revalidate(self) -> bool:
        return (
            _configuration_snapshot_matches(
                self._deployment_snapshot,
                self.deployment_id,
                self._registry_digest,
            )
            and self.broker.revalidate_mounts()
        )

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("deployment configurations cannot be serialized")

    def open_mount_descriptors(self) -> tuple[int, ...]:
        """Hold exact mount-root inodes across one broker invocation."""

        if not self.revalidate():
            raise OSError("deployment configuration changed")
        descriptors: list[int] = []
        try:
            for snapshot in self.broker.mount_snapshots:
                descriptor = os.open(
                    snapshot.path,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                descriptors.append(descriptor)
                if _file_identity(os.fstat(descriptor)) != snapshot.chain_identities[-1][1]:
                    raise OSError("deployment mount root changed")
        except BaseException:
            for descriptor in descriptors:
                os.close(descriptor)
            raise
        return tuple(descriptors)


BackendDeploymentConfiguration = HostModuleConfiguration | SiteContainerConfiguration


@dataclass(frozen=True, slots=True, repr=False)
class BackendDeploymentRegistry:
    """One descriptor-stable private deployment document and its exact snapshot."""

    _document: _DeploymentDocument
    _deployment_snapshot: DeploymentRegistrySnapshot

    @property
    def tool_ids(self) -> tuple[str, ...]:
        return tuple(binding.tool_id for binding in self._document.bindings)

    def configuration_for(self, tool_id: str) -> BackendDeploymentConfiguration | None:
        if _IDENTIFIER.fullmatch(tool_id) is None:
            raise ValueError("backend tool identity is invalid")
        binding = next(
            (item for item in self._document.bindings if item.tool_id == tool_id),
            None,
        )
        if binding is None:
            return None
        return _configuration_from_binding(
            self._document,
            self._deployment_snapshot,
            binding,
        )

    def asset_source_policy(self) -> AssetSourcePolicy:
        """Bind asset selection to the exact private deployment source roots."""

        restricted_roots = tuple(
            Path(mount.source)
            for binding in self._document.bindings
            if isinstance(binding, _SiteContainerDeploymentBinding)
            for mount in binding.readonly_mounts
        )
        return _issue_asset_source_policy(
            additional_broad_roots=restricted_roots,
            authority_identity_digest=self._document.digest,
            authority_revalidator=self.revalidate,
        )

    def source_registration(self) -> PrivateRootRegistration:
        """Register the exact owner-only deployment source for release audit."""

        if not self.revalidate():
            raise ValueError("deployment registry changed before source registration")
        snapshot = self._deployment_snapshot
        descriptor = os.open(
            snapshot.path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            if _file_identity(os.fstat(descriptor)) != snapshot.file_identity:
                raise ValueError("deployment registry changed before source registration")
            source_identity = canonical_digest(
                {
                    "content_digest": snapshot.content_digest,
                    "document_digest": self._document.digest,
                },
                domain="backend-deployment-registry-source-v1",
            )
            return _bind_private_root_from_descriptor(
                PrivateRootRole.BACKEND_DEPLOYMENT_REGISTRY,
                descriptor,
                source_identity,
            )
        finally:
            os.close(descriptor)

    def revalidate(self) -> bool:
        return _configuration_snapshot_matches(
            self._deployment_snapshot,
            self._document.deployment_id,
            self._document.digest,
        )

    def __repr__(self) -> str:
        return "BackendDeploymentRegistry(<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("deployment registries cannot be serialized")


def load_backend_deployment_registry(deployment_path: Path) -> BackendDeploymentRegistry:
    """Load one owner-only deployment document without exposing its selections."""

    document, deployment_snapshot = _read_deployment_document(deployment_path)
    return BackendDeploymentRegistry(document, deployment_snapshot)


def load_backend_deployment_configuration(
    deployment_path: Path,
    tool_id: str,
) -> BackendDeploymentConfiguration:
    """Load one catalog tool from an owner-only deployment registry."""

    registry = load_backend_deployment_registry(deployment_path)
    if not registry.revalidate():
        raise ValueError("deployment registry changed after loading")
    configuration = registry.configuration_for(tool_id)
    if configuration is None or not configuration.revalidate():
        raise ValueError("deployment registry lacks one exact backend selection")
    return configuration


def load_backend_asset_source_policy(deployment_path: Path) -> AssetSourcePolicy:
    """Issue source authority from one exact owner-only deployment registry."""

    registry = load_backend_deployment_registry(deployment_path)
    if not registry.revalidate():
        raise ValueError("deployment registry changed after loading")
    policy = registry.asset_source_policy()
    if not policy.revalidate():
        raise ValueError("deployment registry asset authority is unavailable")
    return policy


def _configuration_from_binding(
    document: _DeploymentDocument,
    deployment_snapshot: DeploymentRegistrySnapshot,
    binding: _DeploymentBinding,
) -> BackendDeploymentConfiguration:
    binding_digest = canonical_digest(binding, domain="backend-deployment-binding-v2")
    if isinstance(binding, _HostModuleDeploymentBinding):
        configuration: BackendDeploymentConfiguration = HostModuleConfiguration(
            tool_id=binding.tool_id,
            module_name=binding.module_name,
            deployment_id=document.deployment_id,
            deployment_digest=binding_digest,
            _registry_digest=document.digest,
            _deployment_snapshot=deployment_snapshot,
        )
    else:
        recipe = SiteContainerExecutionRecipe(
            operating_system=binding.operating_system,
            root_environment_variable=binding.root_environment_variable,
            entrypoint_relative_path=binding.entrypoint_relative_path,
            components=tuple(
                ClosureRecipeComponent(item.role, item.relative_path)
                for item in binding.components
            ),
            tool_environment_names=binding.tool_environment_names,
            environment_bindings=tuple(
                ClosureEnvironmentBinding(item.variable_name, item.component_role)
                for item in binding.environment_bindings
            ),
        )
        requirement = ExecutionClosureRequirementRef(
            requirement_id=binding.requirement_id,
            requirement_digest=recipe.requirement_digest,
        )
        broker = SiteContainerBroker(
            operating_system=binding.operating_system,
            deployment_id=document.deployment_id,
            deployment_digest=binding_digest,
            launcher_kind=binding.launcher_kind,
            launcher=Path(binding.launcher),
            image_inspector=Path(binding.image_inspector),
            image_reference=binding.image_reference,
            image_digest=binding.image_digest,
            host_environment=private_container_host_environment(),
            container_user=binding.container_user,
            trusted_owner_uid=binding.trusted_owner_uid,
            readonly_mounts=tuple(
                (Path(item.source), item.target) for item in binding.readonly_mounts
            ),
            mount_snapshots=tuple(
                _snapshot_mount_root(Path(item.source), binding.trusted_owner_uid)
                for item in binding.readonly_mounts
            ),
        )
        configuration = SiteContainerConfiguration(
            tool_id=binding.tool_id,
            module_name=binding.module_name,
            requirement=requirement,
            recipe=recipe,
            broker=broker,
            _registry_digest=document.digest,
            _deployment_snapshot=deployment_snapshot,
        )
    return configuration


def private_container_host_environment() -> dict[str, str]:
    """Derive the only non-ambient host identity used by container brokers."""

    account = pwd.getpwuid(os.getuid())
    user = account.pw_name
    home = account.pw_dir
    try:
        home_metadata = Path(home).stat()
    except OSError:
        home_metadata = None
    if (
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,95}", user) is None
        or not Path(home).is_absolute()
        or home_metadata is None
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
    ):
        raise ValueError("site-container host identity is unavailable")
    environment = {
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": user,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "USER": user,
    }
    runtime = Path("/run/user") / str(os.getuid())
    try:
        runtime_metadata = runtime.stat()
    except OSError:
        runtime_metadata = None
    if (
        runtime_metadata is not None
        and stat.S_ISDIR(runtime_metadata.st_mode)
        and runtime_metadata.st_uid == os.getuid()
        and not runtime_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        environment["XDG_RUNTIME_DIR"] = os.fspath(runtime)
    return environment


def broker_image_identity_matches(broker: SiteContainerBroker) -> bool:
    """Revalidate the immutable image selected by a private broker."""

    try:
        completed = subprocess.run(
            (
                os.fspath(broker.image_inspector),
                "image",
                "inspect",
                "--format",
                "{{.Digest}}",
                broker.image_reference,
            ),
            env=broker.host_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd="/",
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and completed.stdout.strip() == broker.image_digest.encode(
        "ascii"
    )


def _configuration_snapshot_matches(
    snapshot: DeploymentRegistrySnapshot,
    deployment_id: str,
    deployment_digest: str,
) -> bool:
    try:
        document, current = _read_deployment_document(snapshot.path)
    except (OSError, ValueError):
        return False
    return (
        current == snapshot
        and document.deployment_id == deployment_id
        and document.digest == deployment_digest
    )


def _read_deployment_document(
    path: Path,
) -> tuple[_DeploymentDocument, DeploymentRegistrySnapshot]:
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("deployment registry must be an absolute non-symlink path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > _MAX_DEPLOYMENT_BYTES
        ):
            raise ValueError("deployment registry must be one owner-only regular file")
        identity = _file_identity(before)
        payload = _read_exact_payload(descriptor, before.st_size)
        changed = _file_identity(os.fstat(descriptor)) != identity
        if len(payload) != before.st_size or changed:
            raise ValueError("deployment registry changed while read")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload, object_pairs_hook=_unique_json_object)
        document = _DeploymentDocument.model_validate(value)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("deployment registry is not canonical JSON") from error
    if payload != canonical_bytes(document):
        raise ValueError("deployment registry bytes are not canonical")
    return (
        document,
        DeploymentRegistrySnapshot(
            path=path,
            file_identity=identity,
            content_digest=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        ),
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("deployment registry contains a duplicate field")
        value[name] = item
    return value


def _trusted_readonly_mount(path: Path, trusted_owner_uid: int) -> bool:
    try:
        if (
            trusted_owner_uid <= 0
            or trusted_owner_uid == os.getuid()
            or not path.is_absolute()
            or path in _BROAD_MOUNT_ROOTS
            or len(path.parts) < 4
            or path.resolve(strict=True) != path
        ):
            return False
        components = (path, *path.parents)
        if path.stat().st_uid != trusted_owner_uid:
            return False
        if not all(
            _owned_nonwritable_path(component, {0, trusted_owner_uid})
            for component in components
        ):
            return False
        return stat.S_ISDIR(path.stat().st_mode)
    except OSError:
        return False


def _snapshot_mount_root(
    path: Path,
    trusted_owner_uid: int,
) -> MountRootSnapshot:
    if not _trusted_readonly_mount(path, trusted_owner_uid):
        raise ValueError("deployment mount root is not trusted and immutable")
    return MountRootSnapshot(path=path, chain_identities=_mount_chain_identity(path))


def _mount_chain_identity(
    path: Path,
) -> tuple[tuple[str, tuple[int, int, int, int, int, int, int, int, int]], ...]:
    return tuple(
        (component.as_posix(), _file_identity(component.stat()))
        for component in reversed((path, *path.parents))
    )


def _mount_set_is_bounded(
    mounts: tuple[tuple[Path, str], ...],
    trusted_owner_uid: int,
) -> bool:
    if not mounts or len(mounts) > _MAX_MOUNTS:
        return False
    sources = tuple(source for source, _ in mounts)
    targets = tuple(PurePosixPath(target) for _, target in mounts)
    if (
        len(sources) != len(set(sources))
        or len(targets) != len(set(targets))
        or any(
            not _trusted_readonly_mount(source, trusted_owner_uid) for source in sources
        )
        or any(
            source.as_posix() != target.as_posix()
            for source, target in zip(sources, targets, strict=True)
        )
        or any(
            target == PurePosixPath("/")
            or target.as_posix() != raw_target
            or any(
                target == reserved or reserved in target.parents
                for reserved in _RESERVED_TARGET_TREES
            )
            for (_, raw_target), target in zip(mounts, targets, strict=True)
        )
    ):
        return False
    return not any(
        left in right.parents or right in left.parents
        for position, left in enumerate(sources)
        for right in sources[position + 1 :]
    ) and not any(
        left in right.parents or right in left.parents
        for position, left in enumerate(targets)
        for right in targets[position + 1 :]
    )


def _owned_nonwritable_path(path: Path, allowed_owners: set[int]) -> bool:
    metadata = path.stat()
    return metadata.st_uid in allowed_owners and not metadata.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    )


def _symlink_chain_has_trusted_owner(path: Path, trusted_owner_uid: int) -> bool:
    current = path
    for _ in range(32):
        metadata = current.lstat()
        if metadata.st_uid not in {0, trusted_owner_uid}:
            return False
        if not stat.S_ISLNK(metadata.st_mode):
            return not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        target = Path(os.readlink(current))
        current = target if target.is_absolute() else current.parent / target
        current = Path(os.path.normpath(current))
    return False


def _root_owned_immutable_executable(path: Path) -> bool:
    try:
        original = Path(os.path.normpath(path))
        resolved = original.resolve(strict=True)
        metadata = resolved.stat()
        if (
            not original.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or not os.access(original, os.X_OK)
            or not all(
                _owned_nonwritable_path(component, {0})
                for component in {resolved, *resolved.parents, *original.parents}
            )
        ):
            return False
        return _symlink_chain_has_trusted_owner(original, 0)
    except OSError:
        return False


def _read_exact_payload(descriptor: int, expected_size: int) -> bytes:
    remaining = expected_size
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ValueError("deployment registry grew while read")
    return b"".join(chunks)


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
