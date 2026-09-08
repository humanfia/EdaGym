"""Content identity of the framework code used by a frozen execution binding."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from edagym.canonical import canonical_digest


def framework_implementation_digest() -> str:
    """Bind the installed Python source tree without relying on a Git checkout.

    The complete package is the implementation unit: policy, serialization, and
    executor changes all invalidate an earlier execution binding. Relative
    module names and contents give editable installs and wheels the same
    identity, independent of their installation path.
    """

    root = Path(__file__).resolve().parent
    modules = {
        path.relative_to(root).as_posix(): f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        for path in sorted(root.rglob("*.py"))
    }
    return canonical_digest(
        {"modules": modules, "python_version": tuple(sys.version_info[:3])},
        domain="framework-implementation-v1",
    )
