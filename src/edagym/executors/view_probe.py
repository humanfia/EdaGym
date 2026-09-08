"""Standalone file-view inventory and mount canary inside a configured executor."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

_MAX_FILES = 250_000
_MAX_REQUEST_BYTES = 1024 * 1024
_NAMESPACE_MOUNTS = ("/dev", "/proc", "/sys")


def _readonly(path: str) -> bool:
    return bool(os.statvfs(path).f_flag & os.ST_RDONLY)


def _inventory(
    excluded: tuple[str, ...],
) -> tuple[list[str], list[str], dict[str, str], list[str]]:
    """Inventory every visible immutable image file, including non-executable data.

    A declared bundle grants this complete image payload. The executable bit or
    PATH alone cannot identify all invocable scripts, libraries, and EDA data.
    Runtime mounts and profile attachments have separate owners and receipts.
    """

    files: list[str] = []
    programs: list[str] = []
    symlinks: dict[str, str] = {}
    search_denied: list[str] = []
    pending = [Path("/")]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir())
        except PermissionError:
            if os.access(directory, os.X_OK):
                # Searchable but unlistable directories could conceal invocable
                # programs. This probe cannot certify their complete inventory.
                raise
            search_denied.append(directory.as_posix())
            continue
        for path in children:
            name = path.as_posix()
            if name in excluded:
                continue
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            else:
                files.append(name)
                if stat.S_ISLNK(metadata.st_mode):
                    symlinks[name] = os.readlink(path)
                if stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111:
                    programs.append(name)
            if len(files) > _MAX_FILES:
                raise ValueError("image inventory exceeds the bounded qualification size")
    return sorted(files), sorted(programs), dict(sorted(symlinks.items())), sorted(search_denied)


def main() -> None:
    request_path, output_path = sys.argv[1:]
    with open(request_path, "rb") as stream:
        raw = stream.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        raise ValueError("view probe request exceeds its bound")
    request = json.loads(raw)
    libraries = request["libraries"]
    mounts = {
        re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), line.split()[4])
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
    }
    excluded = (
        *_NAMESPACE_MOUNTS, *request["temporary_targets"],
        request["workspace"], request["artifacts"], request["empty_secret_target"],
        *(item["target"] for item in libraries),
    )
    if not set(excluded) <= mounts:
        raise ValueError(f"declared mounts are absent: {sorted(set(excluded) - mounts)}")
    excluded += tuple(path for path in ("/run", *request["runtime_files"]) if path in mounts)
    excluded += tuple(request["control_files"])
    allowed_mounts = {"/", *excluded, *request["control_files"]}
    unexpected_mounts = sorted(
        path for path in mounts if path not in allowed_mounts
        and not path.startswith(("/dev/", "/proc/", "/sys/"))
    )
    files, programs, symlinks, search_denied = _inventory(excluded)
    controls = Path(request["control_root"])
    control_files = sorted(
        str(path) for path in controls.rglob("*") if not path.is_dir()
    )
    matching_entrypoints = True
    for path, expected in request["entrypoints"].items():
        with open(path, "rb") as stream:
            observed = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        matching_entrypoints &= observed == expected and os.access(path, os.X_OK)
    readable_libraries = []
    for item in libraries:
        path = Path(item["target"])
        readable = os.access(path, os.R_OK)
        if path.is_dir():
            next(iter(path.iterdir()), None)
        else:
            with path.open("rb") as stream:
                stream.read(1)
        if readable and _readonly(str(path)):
            readable_libraries.append(item["asset_id"])
    result = {
        "rootfs_readonly": _readonly("/"),
        "entrypoints_match": matching_entrypoints,
        "framework_absent": (
            importlib.util.find_spec("edagym") is None
            and control_files == sorted(request["control_files"])
        ),
        "private_sources_absent": all(
            not os.path.lexists(path) for path in request["private_paths"]
        ),
        "readonly_library_ids": sorted(readable_libraries),
        "rootfs_paths": files,
        "program_paths": programs,
        "symlinks": symlinks,
        "search_denied_directories": search_denied,
        "unexpected_mounts": unexpected_mounts,
        "default_secrets_empty": (
            _readonly(request["empty_secret_target"])
            and not tuple(Path(request["empty_secret_target"]).iterdir())
        ),
    }
    Path(output_path).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
