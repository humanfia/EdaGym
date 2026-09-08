"""Path resolution and private snapshot derivation for one EdaGym profile."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from edagym.config.model import (
    ConfigView,
    EdaGymConfig,
    InstalledTreeToolSource,
    LibraryConfig,
    NativeCliHarnessConfig,
    PrivateConfigSnapshot,
    ProfileConfig,
    ProfileViewConfig,
    ResourceLimits,
    RuntimeBaseSpec,
    StoragePolicy,
    ToolConfig,
    ToolVisibility,
)
from edagym.specs.environment import ExecutorKind, NetworkKind


class ResolutionError(ValueError):
    """A selected private configuration reference cannot form a runnable view."""


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedSite:
    site_id: str
    state_root: Path
    executor_kind: ExecutorKind
    max_concurrency: int
    available: bool = True
    unavailable_reason: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedTool:
    tool: ToolConfig
    installed_root: Path | None
    available: bool = True
    unavailable_reason: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedEnvironmentView:
    view: ConfigView
    tool_visibility: ToolVisibility
    runtime: RuntimeBaseSpec | None
    tools: tuple[ResolvedTool, ...]
    library_paths: tuple[tuple[str, Path], ...]
    library_ids: tuple[str, ...]
    network: NetworkKind
    available: bool = True
    unavailable_reasons: tuple[str, ...] = ()
    resources: ResourceLimits = field(default_factory=ResourceLimits)
    storage: StoragePolicy = field(default_factory=StoragePolicy)


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedEnvironmentPair:
    """Derived participant/evaluator bindings; it is never another editable configuration."""

    site: ResolvedSite
    profile_id: str
    participant: ResolvedEnvironmentView
    evaluator: ResolvedEnvironmentView
    snapshot: PrivateConfigSnapshot

    @property
    def available(self) -> bool:
        return self.site.available and self.participant.available and self.evaluator.available

    @property
    def unavailable_reasons(self) -> tuple[str, ...]:
        reasons = [
            reason
            for reason in (
                self.site.unavailable_reason,
                *self.participant.unavailable_reasons,
                *self.evaluator.unavailable_reasons,
            )
            if reason is not None
        ]
        return tuple(sorted(set(reasons)))


def resolve_site(config: EdaGymConfig, site_id: str) -> ResolvedSite:
    """Resolve one configured site root relative only to the configuration document."""

    site = _one(config.sites, "site_id", site_id, "site")
    root = _resolve_private_path(config, site.state_root)
    site_available, reason = _directory_status(root)
    return ResolvedSite(
        site_id=site.site_id,
        state_root=root,
        executor_kind=site.executor_kind,
        max_concurrency=site.max_concurrency,
        available=site_available,
        unavailable_reason=reason,
    )


def resolve_profile(config: EdaGymConfig, profile_id: str) -> ResolvedEnvironmentPair:
    """Resolve a profile into one private participant/evaluator pair and frozen snapshot."""

    profile = _one(config.profiles, "profile_id", profile_id, "profile")
    return resolve_snapshot(freeze_profile(config, profile))


def resolve_snapshot(snapshot: PrivateConfigSnapshot) -> ResolvedEnvironmentPair:
    """Recheck the frozen selection without creating a new configuration identity."""

    config = snapshot.configuration
    profile = config.profiles[0]
    site = resolve_site(config, profile.site_id)
    runtimes = {item.runtime_id: item for item in config.runtimes}
    tools = {item.tool_id: item for item in config.tools}
    libraries = {item.library_id: item for item in config.libraries}
    participant = _resolve_view(
        config,
        ConfigView.PARTICIPANT,
        profile.participant,
        runtimes,
        tools,
        libraries,
        profile.resources,
        profile.storage,
    )
    evaluator = _resolve_view(
        config,
        ConfigView.EVALUATOR,
        profile.evaluator,
        runtimes,
        tools,
        libraries,
        profile.resources,
        profile.storage,
    )
    return ResolvedEnvironmentPair(
        site=site,
        profile_id=profile.profile_id,
        participant=participant,
        evaluator=evaluator,
        snapshot=snapshot,
    )


def _resolve_view(
    config: EdaGymConfig,
    view: ConfigView,
    declared: ProfileViewConfig,
    runtimes: dict[str, RuntimeBaseSpec],
    tools: dict[str, ToolConfig],
    libraries: Mapping[str, LibraryConfig],
    resources: ResourceLimits,
    storage: StoragePolicy,
) -> ResolvedEnvironmentView:
    runtime = None if declared.runtime_id is None else runtimes[declared.runtime_id]
    resolved_tools: list[ResolvedTool] = []
    unavailable: list[str] = []
    for tool_id in declared.tool_ids:
        tool = tools[tool_id]
        installed_root = None
        tool_available = True
        tool_reason = None
        if isinstance(tool.source, InstalledTreeToolSource):
            installed_root = _resolve_private_path(config, tool.source.root_path)
            if not installed_root.is_dir() or installed_root.is_symlink():
                tool_available = False
                tool_reason = f"tool_unavailable:{tool.tool_id}"
                unavailable.append(tool_reason)
        resolved_tools.append(
            ResolvedTool(
                tool=tool,
                installed_root=installed_root,
                available=tool_available,
                unavailable_reason=tool_reason,
            )
        )
    resolved_libraries: list[tuple[str, Path]] = []
    library_ids = tuple(declared.library_ids)
    for library_id in declared.library_ids:
        library = libraries[library_id]
        source = _resolve_private_path(config, library.source_path)
        if source.is_symlink() or not source.exists():
            unavailable.append(f"library_unavailable:{library.library_id}")
        else:
            resolved_libraries.append((library.library_id, source))
    return ResolvedEnvironmentView(
        view=view,
        tool_visibility=declared.tool_visibility,
        runtime=runtime,
        tools=tuple(resolved_tools),
        library_paths=tuple(resolved_libraries),
        library_ids=library_ids,
        network=declared.network,
        available=not unavailable,
        unavailable_reasons=tuple(sorted(set(unavailable))),
        resources=resources,
        storage=storage,
    )


def freeze_profile(config: EdaGymConfig, profile: ProfileConfig) -> PrivateConfigSnapshot:
    """Freeze selected configuration values with paths resolved exactly once."""

    site = _one(config.sites, "site_id", profile.site_id, "site")
    runtime_ids = {profile.participant.runtime_id, profile.evaluator.runtime_id}
    tool_ids = set(profile.participant.tool_ids) | set(profile.evaluator.tool_ids)
    library_ids = set(profile.participant.library_ids) | set(profile.evaluator.library_ids)
    storage = profile.storage
    if storage.root is not None:
        storage = storage.model_copy(update={"root": _resolve_private_path(config, storage.root)})
    selected_tools = []
    for tool in config.tools:
        if tool.tool_id not in tool_ids:
            continue
        source = tool.source
        if isinstance(source, InstalledTreeToolSource):
            source = source.model_copy(
                update={
                    "root_path": _resolve_private_path(config, source.root_path),
                }
            )
        selected_tools.append(tool.model_copy(update={"source": source}))
    selected = EdaGymConfig(
        sites=(
            site.model_copy(
                update={
                    "state_root": _resolve_private_path(config, site.state_root),
                }
            ),
        ),
        profiles=(profile.model_copy(update={"storage": storage}),),
        runtimes=tuple(item for item in config.runtimes if item.runtime_id in runtime_ids),
        tools=tuple(selected_tools),
        libraries=tuple(
            item.model_copy(update={"source_path": _resolve_private_path(config, item.source_path)})
            for item in config.libraries
            if item.library_id in library_ids
        ),
        harnesses=tuple(
            item
            if not isinstance(item, NativeCliHarnessConfig)
            else item.model_copy(
                update={
                    "executable_path": _resolve_private_path(config, item.executable_path),
                }
            )
            for item in config.harnesses
        ),
        providers=config.providers,
        sessions=config.sessions,
    )
    return PrivateConfigSnapshot(config_digest=config.digest, configuration=selected)


def _resolve_private_path(config: EdaGymConfig, path: Path) -> Path:
    if path.is_absolute():
        return Path(os.path.abspath(path))
    source = config.source_path
    if source is None:
        raise ResolutionError("configuration has no source location")
    return Path(os.path.abspath(source.parent / path))


def _directory_status(path: Path) -> tuple[bool, str | None]:
    try:
        metadata = path.lstat()
    except OSError:
        return False, "site_state_root_unavailable"
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        return False, "site_state_root_not_private"
    return True, None


def _one[T](items: tuple[T, ...], field_name: str, value: str, label: str) -> T:
    matches = [item for item in items if getattr(item, field_name) == value]
    if len(matches) != 1:
        raise ResolutionError(f"unknown {label} identifier")
    return matches[0]
