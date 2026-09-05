"""Finite participant operations bound by an execution environment."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import ArtifactClass, Capability, Digest, Identifier, StrictModel
from edagym.specs.common import validate_relative_path as _validate_relative_path

_LITERAL_PATTERN = re.compile(r"^(?:--?|\+)?[A-Za-z0-9][A-Za-z0-9._:+,@%-]{0,1023}$")
_SHELL_EXECUTABLES = frozenset(
    {
        "bash",
        "csh",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "tclsh",
        "tcsh",
        "wish",
        "zsh",
    }
)


def _normalized_operation_path(value: str) -> str:
    return _validate_relative_path(value)


OperationPath = Annotated[
    str,
    Field(max_length=1024),
    AfterValidator(_normalized_operation_path),
]


class ParticipantOperationArgumentKind(StrEnum):
    FIXED = "fixed"
    CANDIDATE_INPUT = "candidate_input"
    OUTPUT = "output"


class FixedOperationArgument(StrictModel):
    kind: Literal[ParticipantOperationArgumentKind.FIXED] = ParticipantOperationArgumentKind.FIXED
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        if not _LITERAL_PATTERN.fullmatch(value):
            raise ValueError("fixed operation arguments must be opaque non-path atoms")
        return value


class CandidateInputOperationArgument(StrictModel):
    kind: Literal[ParticipantOperationArgumentKind.CANDIDATE_INPUT] = (
        ParticipantOperationArgumentKind.CANDIDATE_INPUT
    )
    path: OperationPath


class OutputOperationArgument(StrictModel):
    kind: Literal[ParticipantOperationArgumentKind.OUTPUT] = ParticipantOperationArgumentKind.OUTPUT
    path: OperationPath


ParticipantOperationArgument = Annotated[
    FixedOperationArgument | CandidateInputOperationArgument | OutputOperationArgument,
    Field(discriminator="kind"),
]


class ParticipantOperationOutput(StrictModel):
    logical_id: Identifier
    path: OperationPath
    media_type: Annotated[str, Field(min_length=1, max_length=127)]
    artifact_class: Literal[ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE]
    required: bool = True


class ParticipantOperationBinding(StrictModel):
    """One immutable operation selectable by its identifier and nothing else."""

    operation_id: Identifier
    capability: Capability
    tool_id: Identifier
    arguments: Annotated[tuple[ParticipantOperationArgument, ...], Field(max_length=256)] = ()
    outputs: tuple[ParticipantOperationOutput, ...] = ()

    @field_validator("outputs")
    @classmethod
    def normalize_outputs(
        cls,
        value: tuple[ParticipantOperationOutput, ...],
    ) -> tuple[ParticipantOperationOutput, ...]:
        identities = [(item.logical_id, item.path) for item in value]
        if len(identities) != len(set(identities)):
            raise ValueError("participant operation output identities and paths must be unique")
        return tuple(sorted(value, key=lambda item: item.logical_id))

    @model_validator(mode="after")
    def validate_path_roles(self) -> Self:
        input_paths = tuple(
            PurePosixPath(item.path)
            for item in self.arguments
            if isinstance(item, CandidateInputOperationArgument)
        )
        output_arguments = {
            item.path for item in self.arguments if isinstance(item, OutputOperationArgument)
        }
        declared_outputs = {item.path for item in self.outputs}
        if output_arguments - declared_outputs:
            raise ValueError("operation output arguments require matching output declarations")
        output_paths = tuple(PurePosixPath(path) for path in declared_outputs)
        if any(
            left == right or left in right.parents or right in left.parents
            for left in input_paths
            for right in output_paths
        ):
            raise ValueError("participant operation inputs and outputs must not overlap")
        path_tokens = {path.as_posix() for path in (*input_paths, *output_paths)}
        if any(
            isinstance(item, FixedOperationArgument) and item.value in path_tokens
            for item in self.arguments
        ):
            raise ValueError("operation paths must use typed path arguments")
        return self

    @property
    def candidate_input_paths(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    item.path
                    for item in self.arguments
                    if isinstance(item, CandidateInputOperationArgument)
                }
            )
        )

    @property
    def output_paths(self) -> tuple[str, ...]:
        return tuple(sorted(item.path for item in self.outputs))

    @property
    def argv(self) -> tuple[str, ...]:
        return tuple(
            item.value if isinstance(item, FixedOperationArgument) else item.path
            for item in self.arguments
        )

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="participant-operation-v1")


def executable_is_shell(executable: str) -> bool:
    return executable.casefold() in _SHELL_EXECUTABLES
