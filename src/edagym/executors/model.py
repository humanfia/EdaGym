"""Typed command plans and executor results."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.run.model import BlobRef
from edagym.specs.common import ArtifactClass, Capability, Digest, Identifier, StrictModel

_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_FORBIDDEN_ENVIRONMENT_MARKERS = (
    "AUTH",
    "CREDENTIAL",
    "KEY",
    "LICENSE",
    "PASS",
    "SECRET",
    "TOKEN",
)
COMPOSITE_REPORT_LOGICAL_ID = "command_report"
COMPOSITE_REPORT_PATH = ".edagym-evaluator/command-report.json"


class InvocationView(StrEnum):
    PARTICIPANT = "participant"
    EVALUATOR = "evaluator"
    TOOL = "tool"


class JobStateKind(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    LOST = "lost"


class ExecutionFailureKind(StrEnum):
    CANDIDATE = "candidate"
    TOOL = "tool"
    INFRASTRUCTURE = "infrastructure"
    LICENSE_UNAVAILABLE = "license_unavailable"
    SECURITY_VIOLATION = "security_violation"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class EnvironmentEntry(StrictModel):
    name: str
    value: Annotated[str, Field(max_length=4096)]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _ENVIRONMENT_NAME.fullmatch(value):
            raise ValueError("command environment names must be normalized uppercase names")
        if any(marker in value for marker in _FORBIDDEN_ENVIRONMENT_MARKERS):
            raise ValueError("credential and license values cannot enter invocation plans")
        return value

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if any(character in value for character in ("\x00", "\n", "\r")):
            raise ValueError("command environment values cannot contain record boundaries")
        return value


class OutputDeclaration(StrictModel):
    logical_id: Identifier
    path: str
    media_type: Annotated[str, Field(min_length=1, max_length=127)]
    artifact_class: Literal[ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE]
    required: bool = True

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        from edagym.specs.common import validate_relative_path

        return validate_relative_path(value)


class ToolRecipeCommand(StrictModel):
    kind: Literal["tool"] = "tool"
    tool_id: Identifier
    capability: Capability
    driver_digest: Digest
    executable: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")]
    arguments: tuple[Annotated[str, Field(max_length=16_384)], ...] = ()

    @field_validator("arguments")
    @classmethod
    def validate_argument_count(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 4096:
            raise ValueError("recipe command argument count exceeds its bound")
        return value

    @model_validator(mode="after")
    def reject_control_characters(self) -> Self:
        if any(
            "\x00" in value or "\n" in value or "\r" in value
            for value in (self.executable, *self.arguments)
        ):
            raise ValueError("recipe command tokens cannot contain record boundaries")
        return self


class WorkspaceRecipeCommand(StrictModel):
    kind: Literal["workspace"] = "workspace"
    executable: str
    arguments: tuple[Annotated[str, Field(max_length=16_384)], ...] = ()

    @field_validator("arguments")
    @classmethod
    def validate_argument_count(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 4096:
            raise ValueError("recipe command argument count exceeds its bound")
        return value

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        from edagym.specs.common import validate_relative_path

        return validate_relative_path(value)

    @model_validator(mode="after")
    def reject_control_characters(self) -> Self:
        if any("\x00" in value or "\n" in value or "\r" in value for value in self.arguments):
            raise ValueError("recipe command tokens cannot contain record boundaries")
        return self


RecipeCommand = Annotated[
    ToolRecipeCommand | WorkspaceRecipeCommand,
    Field(discriminator="kind"),
]


class InvocationPlan(StrictModel):
    invocation_id: Identifier
    capability: Capability
    tool_id: Identifier
    driver_digest: Digest
    view: InvocationView
    executable: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")]
    arguments: tuple[Annotated[str, Field(max_length=16_384)], ...] = ()
    working_directory: str = "."
    environment: Annotated[tuple[EnvironmentEntry, ...], Field(max_length=64)] = ()
    input_manifest_digest: Digest
    recipe: Annotated[tuple[RecipeCommand, ...], Field(max_length=256)] = ()
    outputs: tuple[OutputDeclaration, ...] = ()

    @field_validator("working_directory")
    @classmethod
    def validate_working_directory(cls, value: str) -> str:
        if value == ".":
            return value
        from edagym.specs.common import validate_relative_path

        return validate_relative_path(value)

    @field_validator("environment")
    @classmethod
    def normalize_environment(
        cls, value: tuple[EnvironmentEntry, ...]
    ) -> tuple[EnvironmentEntry, ...]:
        names = [entry.name for entry in value]
        if len(names) != len(set(names)):
            raise ValueError("an invocation environment may define each name only once")
        return tuple(sorted(value, key=lambda entry: entry.name))

    @field_validator("outputs")
    @classmethod
    def normalize_outputs(
        cls, value: tuple[OutputDeclaration, ...]
    ) -> tuple[OutputDeclaration, ...]:
        identities = [(entry.logical_id, entry.path) for entry in value]
        if len(identities) != len(set(identities)):
            raise ValueError("invocation output identities and paths must be unique")
        return tuple(sorted(value, key=lambda entry: entry.logical_id))

    @model_validator(mode="after")
    def reject_control_characters(self) -> Self:
        values = (self.executable, *self.arguments)
        if any("\x00" in value or "\n" in value or "\r" in value for value in values):
            raise ValueError("command tokens cannot contain NUL or line boundaries")
        if self.recipe:
            first = self.recipe[0]
            if not isinstance(first, ToolRecipeCommand) or (
                first.capability is not self.capability
                or first.tool_id != self.tool_id
                or first.driver_digest != self.driver_digest
                or first.executable != self.executable
            ):
                raise ValueError("a composite recipe must begin with its primary tool binding")
            reports = [
                output
                for output in self.outputs
                if output.logical_id == COMPOSITE_REPORT_LOGICAL_ID
            ]
            if len(reports) != 1 or (
                reports[0].path != COMPOSITE_REPORT_PATH
                or reports[0].media_type != "application/json"
                or reports[0].artifact_class is not ArtifactClass.EVIDENCE
                or not reports[0].required
            ):
                raise ValueError("a composite recipe requires its canonical command report")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="invocation-plan-v1")


class JobHandle(StrictModel):
    job_id: Identifier
    invocation_digest: Digest
    executor_id: Identifier


class JobState(StrictModel):
    handle: JobHandle
    state: JobStateKind
    exit_code: int | None = None
    failure: ExecutionFailureKind | None = None

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        terminal = self.state not in {JobStateKind.QUEUED, JobStateKind.RUNNING}
        if terminal != (self.exit_code is not None or self.failure is not None):
            raise ValueError("only terminal job states may carry an exit code or failure")
        if self.state is JobStateKind.COMPLETED and (self.exit_code != 0 or self.failure):
            raise ValueError("completed jobs require a zero exit code and no failure")
        if self.state in {JobStateKind.QUEUED, JobStateKind.RUNNING} and self.failure is not None:
            raise ValueError("active jobs cannot carry a failure classification")
        return self


class CollectedOutput(StrictModel):
    logical_id: Identifier
    blob: BlobRef
    media_type: Annotated[str, Field(min_length=1, max_length=127)]
    artifact_class: ArtifactClass


class ExecutionResult(StrictModel):
    state: JobState
    stdout: BlobRef
    stderr: BlobRef
    outputs: tuple[CollectedOutput, ...] = ()
