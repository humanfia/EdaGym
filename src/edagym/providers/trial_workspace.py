"""Private workspace materialization for one campaign trial runtime."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from edagym.run.trial_journal import TrialJournal, participant_incarnation_lifecycle
from edagym.runtime.participant_recovery import (
    current_participant_process_identity,
    participant_process_is_alive,
    require_current_participant_incarnation,
)
from edagym.specs.common import (
    Visibility,
    validate_relative_path,
)
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import GeneratedFile, ReleaseManifest
from edagym.specs.session import SessionSpec

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class PreparedTrialWorkspace:
    """Private paths selected from the journal-owned participant generation."""

    workspace: Path
    artifact_directory: Path
    resume_checkpoint_id: str | None


def prepare_trial_workspace(
    *,
    runtime_root: Path,
    journal: TrialJournal,
    environment: EnvironmentSpec,
    session: SessionSpec,
    release: ReleaseManifest,
    participant_files: Mapping[str, Path],
) -> PreparedTrialWorkspace:
    """Create or reopen the exact private workspace bound to a run journal."""

    if (
        environment.digest
        != journal.header.binding.environment.environment_spec_digest
        or session.digest != journal.header.binding.session.session_spec_digest
        or release.digest != journal.header.binding.task.release_digest
    ):
        raise ValueError("campaign workspace inputs differ from the run binding")
    _make_private_directory(runtime_root)
    workspace_root = runtime_root / "workspaces"
    artifact_root = runtime_root / "executor-artifacts"
    for path in (workspace_root, artifact_root):
        _make_private_directory(path)
    run_name = journal.header.run_id.removeprefix("sha256:")
    workspace_run_root = workspace_root / run_name
    artifact_run_root = artifact_root / run_name
    events = journal.read_events()
    if not events:
        if workspace_run_root.exists() or artifact_run_root.exists():
            raise ValueError("fresh campaign run paths already contain state")
        workspace_run_root.mkdir(mode=_DIRECTORY_MODE)
        artifact_run_root.mkdir(mode=_DIRECTORY_MODE)
        workspace = workspace_run_root / _generation_name(0)
        artifact_directory = artifact_run_root / _generation_name(0)
        workspace.mkdir(mode=_DIRECTORY_MODE)
        artifact_directory.mkdir(mode=_DIRECTORY_MODE)
        _materialize_participant_release(
            release,
            participant_files,
            workspace,
            maximum_bytes=environment.resources.disk_bytes,
        )
        return PreparedTrialWorkspace(
            workspace=workspace,
            artifact_directory=artifact_directory,
            resume_checkpoint_id=None,
        )
    require_private_directory(workspace_run_root)
    require_private_directory(artifact_run_root)
    lifecycle = participant_incarnation_lifecycle(events)
    if not lifecycle.incarnations:
        raise ValueError("campaign journal has no participant incarnation")
    active = lifecycle.active_incarnation
    if journal.state().terminal_reason is not None:
        generation = lifecycle.incarnations[-1].generation
        workspace = workspace_run_root / _generation_name(generation)
        artifact_directory = artifact_run_root / _generation_name(generation)
        require_private_directory(workspace)
        require_private_directory(artifact_directory)
        return PreparedTrialWorkspace(
            workspace=workspace,
            artifact_directory=artifact_directory,
            resume_checkpoint_id=None,
        )
    if active is not None and active.process == current_participant_process_identity():
        generation = active.generation
        workspace = workspace_run_root / _generation_name(generation)
        artifact_directory = artifact_run_root / _generation_name(generation)
        require_current_participant_incarnation(
            journal,
            workspace=workspace,
            artifact_directory=artifact_directory,
        )
        return PreparedTrialWorkspace(
            workspace=workspace,
            artifact_directory=artifact_directory,
            resume_checkpoint_id=None,
        )
    if active is not None and participant_process_is_alive(active.process):
        raise ValueError("campaign participant incarnation is still active")
    checkpoints = journal.state().checkpoint_ids
    if not checkpoints:
        raise ValueError("campaign participant recovery requires a committed checkpoint")
    generation = lifecycle.incarnations[-1].generation + 1
    return PreparedTrialWorkspace(
        workspace=workspace_run_root / _generation_name(generation),
        artifact_directory=artifact_run_root / _generation_name(generation),
        resume_checkpoint_id=checkpoints[-1],
    )


def _generation_name(generation: int) -> str:
    return f"generation-{generation:08d}"


def participant_release_paths(release: ReleaseManifest) -> tuple[str, ...]:
    """Return the exact participant-visible release paths."""

    return tuple(
        file.path
        for file in release.files
        if file.visibility in {Visibility.PUBLIC, Visibility.PARTICIPANT}
    )


def require_private_directory(path: Path) -> None:
    """Reject mutable runtime directories outside the controller's private custody."""

    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("campaign runtime directories must be private and owner-controlled")


def _materialize_participant_release(
    release: ReleaseManifest,
    sources: Mapping[str, Path],
    workspace: Path,
    *,
    maximum_bytes: int,
) -> None:
    visible = {
        file.path: file
        for file in release.files
        if file.visibility in {Visibility.PUBLIC, Visibility.PARTICIPANT}
    }
    if set(sources) != set(visible):
        raise ValueError("participant release sources do not match the visible bundle")
    descriptor = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        total = 0
        for path, generated in sorted(visible.items()):
            content = _read_generated_source(
                sources[path],
                generated,
                maximum_bytes=maximum_bytes - total,
            )
            total += len(content)
            _write_relative_file(descriptor, path, content)
    finally:
        os.close(descriptor)


def _read_generated_source(
    path: Path,
    generated: GeneratedFile,
    *,
    maximum_bytes: int,
) -> bytes:
    if maximum_bytes < 0:
        raise ValueError("participant release exceeds the environment disk bound")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise ValueError("participant release source is not a bounded regular file")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError("participant release exceeds the environment disk bound")
            digest.update(chunk)
            chunks.append(chunk)
        if _file_identity(os.fstat(descriptor)) != _file_identity(metadata):
            raise ValueError("participant release source changed while it was read")
        content = b"".join(chunks)
    finally:
        os.close(descriptor)
    if f"sha256:{digest.hexdigest()}" != generated.content_digest:
        raise ValueError("participant release source has the wrong content digest")
    return content


def _write_relative_file(root_descriptor: int, relative: str, content: bytes) -> None:
    parts = PurePosixPath(validate_relative_path(relative)).parts
    parent = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            with suppress(FileExistsError):
                os.mkdir(part, mode=_DIRECTORY_MODE, dir_fd=parent)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            _FILE_MODE,
            dir_fd=parent,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("participant release write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def _file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _make_private_directory(path: Path) -> None:
    path.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
    require_private_directory(path)
