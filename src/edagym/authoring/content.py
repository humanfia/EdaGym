"""Raw content identity for the public private-authoring boundary."""

from __future__ import annotations

import hashlib


def content_digest(content: bytes) -> str:
    """Return the raw SHA-256 identity of an opaque byte string."""

    return f"sha256:{hashlib.sha256(content).hexdigest()}"


__all__ = ["content_digest"]
