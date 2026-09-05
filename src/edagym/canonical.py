"""Canonical JSON encoding used for every persistent identity."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

import rfc8785
from pydantic import BaseModel


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _json_value(
            value.model_dump(
                mode="json",
                exclude_defaults=False,
                exclude_none=False,
                exclude_unset=False,
            )
        )
    if isinstance(value, Enum):
        return _json_value(value.value)
    if isinstance(value, Decimal):
        return canonical_decimal_string(value)
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical mappings require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_json_value(item) for item in value]
        return sorted(items, key=lambda item: canonical_bytes(item))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if isinstance(value, float):
        raise TypeError("canonical values must use Decimal instead of float")
    if value is not None and not isinstance(value, (str, int, bool)):
        raise TypeError(f"unsupported canonical value type: {type(value).__name__}")
    return value


def canonical_decimal_string(value: Decimal) -> str:
    """Render one finite decimal without exponent or redundant fractional zeros."""

    if not value.is_finite():
        raise ValueError("canonical decimals must be finite")
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise ValueError("finite decimal has a non-integer exponent")
    significant = list(digits)
    while significant and significant[-1] == 0:
        significant.pop()
        exponent += 1
    if not significant:
        return "0"
    coefficient = "".join(str(digit) for digit in significant)
    if exponent >= 0:
        rendered = coefficient + "0" * exponent
    else:
        point = len(coefficient) + exponent
        rendered = (
            coefficient[:point] + "." + coefficient[point:]
            if point > 0
            else "0." + "0" * -point + coefficient
        )
    return f"-{rendered}" if sign else rendered


def canonical_bytes(value: Any) -> bytes:
    """Encode a JSON-compatible value without representation-dependent whitespace."""

    return rfc8785.dumps(_json_value(value))


def canonical_digest(value: Any, *, domain: str) -> str:
    """Return a domain-separated SHA-256 identity of a canonical value."""

    if not domain or "\x00" in domain:
        raise ValueError("digest domain must be non-empty and cannot contain NUL")
    payload = b"edagym\x00" + domain.encode("utf-8") + b"\x00" + canonical_bytes(value)
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
