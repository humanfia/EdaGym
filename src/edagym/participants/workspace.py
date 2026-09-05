"""Bounded participant tools for an isolated run workspace."""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol

from edagym.participant_tool_protocol import (
    CHECKPOINT_PARTICIPANT_TOOL_NAME,
    EXECUTOR_PARTICIPANT_TOOL_NAME,
    WORKSPACE_READ_PARTICIPANT_TOOL_NAME,
    WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
)
from edagym.participants.adapters import ParticipantAdapterError, ParticipantFailureKind
from edagym.participants.model import ParticipantView
from edagym.participants.responses import ParticipantToolResult, ResponsesParticipantTool
from edagym.providers.model import FunctionTool, ToolParameter, ToolValueKind

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_FILE_BYTES = 1024 * 1024
_MAX_ARGUMENT_BYTES = 256 * 1024
_MAX_RESULT_BYTES = 1024 * 1024


class ToolObservationOutcome(StrEnum):
    PASSED = "passed"
    CANDIDATE_FAILURE = "candidate_failure"
    TIMEOUT = "timeout"
    LICENSE_UNAVAILABLE = "license_unavailable"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    SECURITY_VIOLATION = "security_violation"


@dataclass(frozen=True, slots=True)
class ToolObservation:
    """A trusted, secret-safe observation returned to the participant."""

    outcome: ToolObservationOutcome
    summary: str
    artifact_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.summary or len(self.summary.encode("utf-8")) > _MAX_RESULT_BYTES:
            raise ValueError("tool observation summaries must be bounded and non-empty")
        if len(self.artifact_refs) != len(set(self.artifact_refs)):
            raise ValueError("tool observation artifact references must be unique")

    def participant_text(self) -> str:
        return json.dumps(
            {
                "artifact_refs": list(self.artifact_refs),
                "outcome": self.outcome.value,
                "summary": self.summary,
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )


class ParticipantToolDispatcher(Protocol):
    """Trusted bridge from a logical tool request to the EdaGym executor."""

    @property
    def operation_ids(self) -> tuple[str, ...]: ...

    def invoke(
        self,
        *,
        operation_id: str,
        view: ParticipantView,
    ) -> ToolObservation: ...


class WorkspaceReadTool(ResponsesParticipantTool):
    """Read one explicitly allowlisted UTF-8 workspace file."""

    def __init__(self, workspace: Path, *, paths: Sequence[str]) -> None:
        self._workspace = workspace
        self._paths = _normalize_paths(paths)
        self._definition = FunctionTool(
            name=WORKSPACE_READ_PARTICIPANT_TOOL_NAME,
            description="Read one allowlisted text file from the isolated task workspace.",
            parameters=(
                ToolParameter(
                    name="path",
                    kind=ToolValueKind.STRING,
                    description="The workspace-relative file name.",
                    choices=self._paths,
                ),
            ),
        )

    @property
    def definition(self) -> FunctionTool:
        return self._definition

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult:
        del view
        value = _decode_exact_object(arguments, {"path"})
        path = value.get("path")
        if not isinstance(path, str) or path not in self._paths:
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        try:
            content = _read_workspace_file(self._workspace, path)
            text = content.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        return ParticipantToolResult(output=text if text else "<empty>")


class WorkspaceWriteTool(ResponsesParticipantTool):
    """Atomically replace one explicitly allowlisted UTF-8 workspace file."""

    def __init__(self, workspace: Path, *, paths: Sequence[str]) -> None:
        self._workspace = workspace
        self._paths = _normalize_paths(paths)
        self._definition = FunctionTool(
            name=WORKSPACE_WRITE_PARTICIPANT_TOOL_NAME,
            description="Atomically write one allowlisted text file in the isolated workspace.",
            parameters=(
                ToolParameter(
                    name="path",
                    kind=ToolValueKind.STRING,
                    description="The workspace-relative file name.",
                    choices=self._paths,
                ),
                ToolParameter(
                    name="content",
                    kind=ToolValueKind.STRING,
                    description="The complete UTF-8 replacement content.",
                ),
            ),
        )

    @property
    def definition(self) -> FunctionTool:
        return self._definition

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult:
        del view
        value = _decode_exact_object(arguments, {"content", "path"})
        path = value.get("path")
        content = value.get("content")
        if (
            not isinstance(path, str)
            or path not in self._paths
            or not isinstance(content, str)
            or len(content.encode("utf-8")) > _MAX_FILE_BYTES
        ):
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        try:
            encoded = content.encode("utf-8")
            _replace_workspace_file(self._workspace, path, encoded)
        except (OSError, ValueError):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        return ParticipantToolResult(output=f"wrote {len(encoded)} bytes")


class EdaInvocationTool(ResponsesParticipantTool):
    """Dispatch one immutable EDA operation through a trusted bridge."""

    def __init__(self, dispatcher: ParticipantToolDispatcher) -> None:
        operation_ids = tuple(sorted(dispatcher.operation_ids))
        if not operation_ids or len(operation_ids) != len(set(operation_ids)):
            raise ValueError("participant operation identifiers must be unique and non-empty")
        self._dispatcher = dispatcher
        self._operation_ids = operation_ids
        self._definition = FunctionTool(
            name=EXECUTOR_PARTICIPANT_TOOL_NAME,
            description=(
                "Run one immutable task operation through the isolated EdaGym executor. "
                "The operation owns its tool, arguments, inputs, and outputs."
            ),
            parameters=(
                ToolParameter(
                    name="operation_id",
                    kind=ToolValueKind.STRING,
                    description="The immutable task operation identifier.",
                    choices=operation_ids,
                ),
            ),
        )

    @property
    def definition(self) -> FunctionTool:
        return self._definition

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult:
        value = _decode_exact_object(arguments, {"operation_id"})
        operation_id = value.get("operation_id")
        if not isinstance(operation_id, str) or operation_id not in self._operation_ids:
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        try:
            observation = self._dispatcher.invoke(
                operation_id=operation_id,
                view=view,
            )
        except ParticipantAdapterError:
            raise
        except Exception:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        if not isinstance(observation, ToolObservation):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        return ParticipantToolResult(
            output=observation.participant_text(),
            artifact_refs=observation.artifact_refs,
        )


class CheckpointParticipantTool(ResponsesParticipantTool):
    """Request the environment's checkpoint through a controller-owned callback."""

    def __init__(self, checkpoint: Callable[[str], ToolObservation]) -> None:
        self._checkpoint = checkpoint
        self._definition = FunctionTool(
            name=CHECKPOINT_PARTICIPANT_TOOL_NAME,
            description="Commit the current task workspace as a named durable checkpoint.",
            parameters=(
                ToolParameter(
                    name="checkpoint_id",
                    kind=ToolValueKind.STRING,
                    description="A stable lower-case checkpoint identifier.",
                ),
            ),
        )

    @property
    def definition(self) -> FunctionTool:
        return self._definition

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult:
        del view
        value = _decode_exact_object(arguments, {"checkpoint_id"})
        checkpoint_id = value.get("checkpoint_id")
        if (
            not isinstance(checkpoint_id, str)
            or not checkpoint_id
            or len(checkpoint_id) > 64
            or not checkpoint_id.replace("_", "").isalnum()
            or not checkpoint_id.isascii()
            or checkpoint_id.casefold() != checkpoint_id
        ):
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
        try:
            observation = self._checkpoint(checkpoint_id)
        except ParticipantAdapterError:
            raise
        except Exception:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
        if not isinstance(observation, ToolObservation):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        return ParticipantToolResult(
            output=observation.participant_text(),
            artifact_refs=observation.artifact_refs,
        )


def _normalize_paths(paths: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(sorted(_relative_path(path) for path in paths))
    if not normalized or len(normalized) != len(set(normalized)):
        raise ValueError("workspace tool paths must be unique and non-empty")
    return normalized


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\x00" in value
        or len(value.encode("utf-8")) > 1024
    ):
        raise ValueError("workspace paths must be normalized relative POSIX paths")
    return path.as_posix()


def _decode_exact_object(arguments: str, keys: set[str]) -> Mapping[str, object]:
    if not arguments or len(arguments.encode("utf-8")) > _MAX_ARGUMENT_BYTES:
        raise ParticipantAdapterError(ParticipantFailureKind.RESPONSE_BOUND)
    try:
        value = json.loads(arguments)
    except json.JSONDecodeError:
        raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT) from None
    if not isinstance(value, dict) or set(value) != keys:
        raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
    return value


def _open_workspace(workspace: Path) -> int:
    descriptor = os.open(workspace, _DIRECTORY_FLAGS)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise OSError("participant workspace is not private")
    return descriptor


def _open_parent(workspace_descriptor: int, path: str, *, create: bool) -> tuple[int, str]:
    parts = PurePosixPath(_relative_path(path)).parts
    descriptor = os.dup(workspace_descriptor)
    try:
        for part in parts[:-1]:
            if create:
                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            metadata = os.fstat(child)
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                os.close(child)
                raise OSError("participant workspace subtree is not private")
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _read_workspace_file(workspace: Path, path: str) -> bytes:
    workspace_descriptor = _open_workspace(workspace)
    try:
        parent_descriptor, name = _open_parent(workspace_descriptor, path, create=False)
        try:
            descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_descriptor)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or metadata.st_size > _MAX_FILE_BYTES
                ):
                    raise OSError("workspace file is not a bounded private regular file")
                chunks: list[bytes] = []
                remaining = _MAX_FILE_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
                if len(content) > _MAX_FILE_BYTES:
                    raise OSError("workspace file exceeds the read bound")
                return content
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(workspace_descriptor)


def _replace_workspace_file(workspace: Path, path: str, content: bytes) -> None:
    if len(content) > _MAX_FILE_BYTES:
        raise ValueError("workspace file exceeds the write bound")
    workspace_descriptor = _open_workspace(workspace)
    try:
        parent_descriptor, name = _open_parent(workspace_descriptor, path, create=True)
        temporary_name = f".edagym-write-{secrets.token_hex(16)}"
        descriptor = -1
        try:
            try:
                target = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                target = None
            if target is not None and (
                not stat.S_ISREG(target.st_mode)
                or target.st_uid != os.getuid()
                or target.st_nlink != 1
            ):
                raise OSError("workspace write target is not a private regular file")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=parent_descriptor,
            )
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("workspace file write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
    finally:
        os.close(workspace_descriptor)
