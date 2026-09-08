#!/usr/bin/env python3
"""Build a wheel and install it with dependencies into a fresh virtual environment."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

_EXPECTED_DISTRIBUTION = "edagym"
_EXPECTED_STATIC_MEMBERS = {
    "edagym/web/static/index.html",
    "edagym/web/static/app.js",
    "edagym/web/static/style.css",
}
_FORBIDDEN_RELEASE_PARTS = (
    "containerfile",
    "bootstrap_sail",
    "install_eda",
    "openroad/",
    "klayout/",
    ".lef",
    ".lib",
    ".sp",
    ".sdc",
)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _run(arguments: list[str], *, cwd: Path) -> None:
    subprocess.run(
        arguments,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        env={
            **os.environ,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "TMPDIR": os.fspath(cwd),
        },
        check=True,
        shell=False,
    )


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    state_root = repository / ".edagym-state"
    state_root.mkdir(mode=0o700, exist_ok=True)
    state_metadata = state_root.lstat()
    if (
        state_root.is_symlink()
        or not stat.S_ISDIR(state_metadata.st_mode)
        or state_metadata.st_uid != os.getuid()
        or stat.S_IMODE(state_metadata.st_mode) != 0o700
    ):
        return 1
    installed_environment = state_root / "release-environment"
    if installed_environment.exists() or installed_environment.is_symlink():
        installed_metadata = installed_environment.lstat()
        if (
            installed_environment.is_symlink()
            or not stat.S_ISDIR(installed_metadata.st_mode)
            or installed_metadata.st_uid != os.getuid()
        ):
            return 1
        shutil.rmtree(installed_environment)
    with tempfile.TemporaryDirectory(prefix="clean-install-", dir=state_root) as temporary:
        scratch = Path(temporary)
        wheelhouse = scratch / "wheelhouse"
        wheelhouse.mkdir(mode=0o700)
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--wheel-dir",
                os.fspath(wheelhouse),
                f"{repository}[dev]",
            ],
            cwd=scratch,
        )
        _run(
            [sys.executable, "-m", "venv", os.fspath(installed_environment)],
            cwd=scratch,
        )
        installed_python = installed_environment / "bin" / "python"
        _run(
            [
                os.fspath(installed_python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--find-links",
                os.fspath(wheelhouse),
                f"{_EXPECTED_DISTRIBUTION}[dev]",
            ],
            cwd=scratch,
        )
        probe = subprocess.run(
            [
                os.fspath(installed_python),
                "-I",
                "-c",
                (
                    "import importlib.metadata as m; "
                    "import edagym; "
                    "print(m.version('edagym'))"
                ),
            ],
            cwd=scratch,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "TMPDIR": os.fspath(scratch)},
            stdout=subprocess.PIPE,
            stderr=None,
            check=True,
            shell=False,
            text=True,
        )
        version = probe.stdout.strip()
        if not version:
            return 1
        console = subprocess.run(
            [os.fspath(installed_environment / "bin" / "edagym"), "--version"],
            cwd=scratch,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "TMPDIR": os.fspath(scratch)},
            stdout=subprocess.PIPE,
            stderr=None,
            check=True,
            shell=False,
            text=True,
        )
        if console.stdout.strip() != f"edagym {version}":
            return 1
        schema_probe = subprocess.run(
            [
                os.fspath(installed_python),
                "-I",
                "-c",
                (
                    "from edagym.schemas import schema_index; "
                    "print(len(schema_index()['schemas']))"
                ),
            ],
            cwd=scratch,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "TMPDIR": os.fspath(scratch)},
            stdout=subprocess.PIPE,
            stderr=None,
            check=True,
            shell=False,
            text=True,
        )
        try:
            schema_count = int(schema_probe.stdout.strip())
        except ValueError:
            return 1
        if schema_count <= 0:
            return 1
        wheels = tuple(
            {
                "digest": _file_digest(path),
                "name": path.name,
                "size_bytes": path.stat().st_size,
            }
            for path in sorted(wheelhouse.iterdir())
            if path.is_file() and not path.is_symlink()
        )
        if not wheels:
            return 1
        package_wheels = [
            path for path in wheelhouse.iterdir()
            if path.name.startswith(f"{_EXPECTED_DISTRIBUTION}-") and path.suffix == ".whl"
        ]
        if len(package_wheels) != 1:
            return 1
        with zipfile.ZipFile(package_wheels[0]) as archive:
            members = set(archive.namelist())
            if not members >= _EXPECTED_STATIC_MEMBERS:
                return 1
            if any(
                any(part in name.casefold() for part in _FORBIDDEN_RELEASE_PARTS)
                for name in archive.namelist()
            ):
                return 1
        print(
            json.dumps(
                {
                    "distribution": _EXPECTED_DISTRIBUTION,
                    "schema_count": schema_count,
                    "version": version,
                    "wheels": wheels,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
