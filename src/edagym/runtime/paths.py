"""Private controller path invariants shared by runtime components."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from edagym.runtime.errors import OrchestrationError


def require_private_runtime_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise OrchestrationError("runtime directories must be private real directories")


def require_separate_runtime_paths(*paths: Path) -> None:
    normalized = tuple(path.resolve(strict=False) for path in paths)
    for position, left in enumerate(normalized):
        if any(
            left == right or left in right.parents or right in left.parents
            for right in normalized[position + 1 :]
        ):
            raise OrchestrationError(
                "workspace, runtime state, executor artifacts, and artifact store "
                "must use separate paths"
            )
