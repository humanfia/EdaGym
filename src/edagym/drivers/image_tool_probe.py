"""Standalone metadata probe executed inside a user's immutable image."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

_MAX_VERSION_BYTES = 256 * 1024
_VERSION_TIMEOUT_SECONDS = 20


def main() -> None:
    executable = shutil.which(sys.argv[1])
    digest = None
    exit_code = None
    output = b""
    if executable is not None:
        metadata = os.stat(executable)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("image executable is not immutable")
        with open(executable, "rb") as stream:
            digest = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
        with tempfile.TemporaryFile() as log:
            result = subprocess.run(
                (executable, *sys.argv[2:]),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=_VERSION_TIMEOUT_SECONDS,
                check=False,
            )
            exit_code = result.returncode
            log.seek(0)
            output = log.read(_MAX_VERSION_BYTES + 1)
            if len(output) > _MAX_VERSION_BYTES:
                raise ValueError("image version output exceeds its bound")
    print(
        json.dumps(
            {
                "entrypoint": executable,
                "entrypoint_digest": digest,
                "exit_code": exit_code,
                "version_output_base64": base64.b64encode(output).decode("ascii"),
            "launcher_version": sys.version,
            "launcher_entrypoint": sys.executable,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
