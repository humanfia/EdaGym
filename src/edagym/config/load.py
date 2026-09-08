"""Strict private TOML loading and secure first-run initialization."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path

from pydantic import ValidationError

from edagym.config.model import EdaGymConfig, ToolVisibility
from edagym.policy.runtime_storage import private_directory, read_private, write_private


class ConfigError(ValueError):
    """A private configuration document is absent, unsafe, or structurally invalid."""


def load_config(path: Path) -> EdaGymConfig:
    """Load exactly one private TOML document without include or environment expansion."""

    source = path.expanduser().absolute()
    try:
        raw = tomllib.loads(read_private(source).decode("utf-8"))
    except (OSError, ValueError):
        raise ConfigError("configuration cannot be parsed") from None
    if not isinstance(raw, dict) or _contains_placeholder(raw):
        raise ConfigError("configuration contains unresolved placeholders")
    if "source_path" in raw:
        raise ConfigError("configuration cannot set its own source location")
    try:
        return EdaGymConfig.model_validate(raw).model_copy(update={"source_path": source})
    except ValidationError:
        raise ConfigError("configuration schema is invalid") from None


def import_legacy_config(source_path: Path, output_path: Path) -> EdaGymConfig:
    """Explicitly migrate a legacy TOML/JSON document into the private schema.

    The operation is opt-in and validates every field against the current typed
    schema before publishing the converted configuration.
    """

    source = source_path.expanduser().absolute()
    destination = output_path.expanduser().absolute()
    try:
        raw_bytes = read_private(source)
        raw: object
        try:
            raw = json.loads(raw_bytes)
        except json.JSONDecodeError:
            raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigError("legacy configuration cannot be parsed") from error
    if not isinstance(raw, dict):
        raise ConfigError("legacy configuration must be an object")
    if "source_path" in raw:
        raise ConfigError("legacy configuration cannot set its own source location")
    if raw.get("schema_version") == 1:
        _migrate_visibility(raw)
    try:
        config = EdaGymConfig.model_validate(raw)
    except ValidationError as error:
        raise ConfigError("legacy configuration cannot satisfy the new schema") from error
    private_directory(destination.parent, create=True)
    if destination.exists() or destination.is_symlink():
        raise ConfigError("configuration destination already exists")
    write_private(destination, _toml_bytes(config))
    return load_config(destination)


def initialize_config(config_path: Path, private_root: Path) -> EdaGymConfig:
    """Create one owner-only state root and a usable tool-free configuration skeleton."""

    root = private_root.expanduser().absolute()
    source = config_path.expanduser().absolute()
    if source.exists() or source.is_symlink():
        raise ConfigError("configuration destination already exists")
    private_directory(root, create=True)
    private_directory(source.parent, create=True)
    payload = _template(root)
    write_private(source, payload)
    return load_config(source)


def _template(root: Path) -> bytes:
    root_value = json.dumps(os.fspath(root), ensure_ascii=True)
    return (
        f"schema_version = {EdaGymConfig.model_fields['schema_version'].default}\n\n"
        "[[sites]]\n"
        'site_id = "local"\n'
        f"state_root = {root_value}\n"
        'executor_kind = "rootless_local"\n'
        "max_concurrency = 1\n\n"
        "[[profiles]]\n"
        'profile_id = "default"\n'
        'site_id = "local"\n'
        "[profiles.participant]\n"
        "[profiles.evaluator]\n\n"
        "[[sessions]]\n"
        'session_id = "human"\n'
        'kind = "human"\n\n'
        "[web]\n"
        'exposure = "loopback"\n'
        'host = "127.0.0.1"\n'
        "port = 0\n"
        'principal_id = "local_user"\n'
    ).encode()


def _contains_placeholder(value: object) -> bool:
    if isinstance(value, str):
        return "${" in value
    if isinstance(value, dict):
        return any(
            _contains_placeholder(key) or _contains_placeholder(item) for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    return False


def _migrate_visibility(document: dict[str, object]) -> None:
    """Offline v1 conversion; immutable run snapshots are never upgraded."""

    tools = document.get("tools", [])
    profiles = document.get("profiles", [])
    if not isinstance(tools, list) or not isinstance(profiles, list):
        raise ConfigError("legacy configuration collections are invalid")
    modes = {}
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("tool_id"), str):
            raise ConfigError("legacy configuration tool is invalid")
        modes[tool["tool_id"]] = ToolVisibility(
            tool.pop("visibility", ToolVisibility.EXACT_TOOLSET)
        )
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ConfigError("legacy configuration profile is invalid")
        for name in ("participant", "evaluator"):
            view = profile.get(name, {})
            if not isinstance(view, dict) or not isinstance(view.get("tool_ids", []), list):
                raise ConfigError("legacy configuration view is invalid")
            references = view.get("tool_ids", [])
            if any(not isinstance(tool_id, str) for tool_id in references):
                raise ConfigError("legacy configuration tool reference is invalid")
            selected = {modes.get(tool_id) for tool_id in references}
            if None in selected or len(selected) > 1 or "tool_visibility" in view:
                raise ConfigError("legacy tool visibility cannot define one unambiguous view")
            view["tool_visibility"] = next(iter(selected), ToolVisibility.EXACT_TOOLSET)
            profile[name] = view
    document["schema_version"] = EdaGymConfig.model_fields["schema_version"].default


def _toml_bytes(config: EdaGymConfig) -> bytes:
    value = config.model_dump(mode="json", exclude={"source_path"})
    lines = _toml_table_lines(value)
    return ("\n".join(lines) + "\n").encode()


def _toml_table_lines(value: Mapping[str, object], prefix: str = "") -> list[str]:
    lines: list[str] = []
    scalar_items = [
        (key, item)
        for key, item in value.items()
        if item is not None
        if not isinstance(item, (dict, list))
        or (isinstance(item, list) and not any(isinstance(child, dict) for child in item))
    ]
    for key, item in scalar_items:
        lines.append(f"{key} = {_toml_scalar(item)}")
    for key, item in value.items():
        if item is None:
            continue
        if isinstance(item, dict):
            header = f"[{prefix + '.' if prefix else ''}{key}]"
            lines.extend(("", header))
            lines.extend(_toml_table_lines(item, f"{prefix + '.' if prefix else ''}{key}"))
        elif isinstance(item, list) and any(isinstance(child, dict) for child in item):
            table_name = f"{prefix + '.' if prefix else ''}{key}"
            for child in item:
                if not isinstance(child, dict):
                    raise ConfigError("legacy configuration contains a mixed TOML array")
                lines.extend(("", f"[[{table_name}]]"))
                lines.extend(_toml_table_lines(child, table_name))
    return lines


def _toml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_scalar(item) for item in value) + "]"
    if value is None:
        raise ConfigError("legacy configuration cannot encode null values")
    raise ConfigError("legacy configuration contains an unsupported value")
