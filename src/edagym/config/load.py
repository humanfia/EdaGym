"""Strict private TOML loading and secure first-run initialization."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Mapping
from pathlib import Path

from pydantic import ValidationError

from edagym.config.model import EdaGymConfig
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

    The operation is deliberately opt-in and rejects unknown or secret-bearing
    fields instead of silently carrying them into the new configuration.
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
    _reject_secret_fields(raw)
    allowed = set(EdaGymConfig.model_fields) - {"source_path"}
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError("legacy configuration contains unsupported fields")
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
        "schema_version = 1\n\n"
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


def _reject_secret_fields(value: object) -> None:
    secret_markers = ("secret", "token", "password", "api_key", "private_key")
    if isinstance(value, dict):
        for key, item in value.items():
            if any(marker in str(key).casefold() for marker in secret_markers):
                raise ConfigError("legacy configuration contains a secret field")
            _reject_secret_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_fields(item)


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
