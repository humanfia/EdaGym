"""Secret-safe failures returned by the command-line boundary."""

from __future__ import annotations


class CliFailure(RuntimeError):
    """A stable public error code and process status."""

    def __init__(self, code: str, *, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
