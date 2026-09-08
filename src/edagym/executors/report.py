"""Canonical command evidence emitted by the trusted composite supervisor."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from edagym.canonical import canonical_digest
from edagym.executors.model import RecipeCommand
from edagym.specs.common import Digest, SchemaVersion, StrictModel


class CommandFailure(StrEnum):
    SPAWN_FAILED = "spawn_failed"


class ReportStatus(StrEnum):
    COMPLETED = "completed"
    DRIVER_ERROR = "driver_error"


class CommandReportEntry(StrictModel):
    identity_digest: Digest
    exit_code: int | None
    failure: CommandFailure | None
    stdout_digest: Digest
    stdout_size_bytes: int = Field(ge=0)
    stderr_digest: Digest
    stderr_size_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        if (self.exit_code is None) != (self.failure is not None):
            raise ValueError("command failure requires exactly one missing exit code")
        return self


class CompositeCommandReport(StrictModel):
    schema_version: SchemaVersion = 1
    status: ReportStatus
    commands: tuple[CommandReportEntry, ...]

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status is ReportStatus.DRIVER_ERROR and self.commands:
            raise ValueError("driver errors cannot claim completed commands")
        if self.status is ReportStatus.COMPLETED and not self.commands:
            raise ValueError("completed composite reports require command evidence")
        return self

    def verify(self, recipe: Sequence[RecipeCommand], stdout: bytes, stderr: bytes) -> None:
        expected = tuple(
            canonical_digest(command, domain="composite-recipe-command-v1") for command in recipe
        )
        actual = tuple(command.identity_digest for command in self.commands)
        if actual != expected[: len(actual)]:
            raise ValueError("composite report command identity diverges from its recipe")
        if self.status is ReportStatus.DRIVER_ERROR:
            return
        if any(
            command.failure is not None or command.exit_code != 0 for command in self.commands[:-1]
        ):
            raise ValueError("composite report continued after a terminal command")
        terminal = self.commands[-1]
        if terminal.failure is None and terminal.exit_code == 0 and len(actual) != len(expected):
            raise ValueError("a successful composite report omitted recipe commands")
        for name, content in (("stdout", stdout), ("stderr", stderr)):
            offset = 0
            for command in self.commands:
                size = command.stdout_size_bytes if name == "stdout" else command.stderr_size_bytes
                digest = command.stdout_digest if name == "stdout" else command.stderr_digest
                chunk = content[offset : offset + size]
                if len(chunk) != size or "sha256:" + hashlib.sha256(chunk).hexdigest() != digest:
                    raise ValueError(f"composite {name} disagrees with its command report")
                offset += size
            if offset != len(content):
                raise ValueError(f"composite {name} has unreported bytes")
