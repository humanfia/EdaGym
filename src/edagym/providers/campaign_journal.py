"""Crash-safe storage for canonical paid-campaign accounting records."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path

from pydantic import ValidationError

from edagym.canonical import canonical_bytes
from edagym.providers.campaign_runner import (
    CampaignCommit,
    CampaignEvent,
    CampaignRecord,
)
from edagym.providers.campaign_schedule import CampaignHeader

_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700


class CampaignJournalError(RuntimeError):
    """Base class for campaign journal failures."""


class CampaignJournalCorruption(CampaignJournalError):
    """A durable campaign record is malformed or discontinuous."""


class CampaignJournalConflict(CampaignJournalError):
    """A campaign journal already owns incompatible immutable content."""


class CampaignJournal:
    """Own one immutable campaign header and append-only hash-chained event stream."""

    def __init__(self, directory: Path, header: CampaignHeader) -> None:
        self.directory = directory
        self.header = header
        self.header_path = directory / "campaign.json"
        self.events_path = directory / "events.jsonl"

    @classmethod
    def create(cls, state_root: Path, header: CampaignHeader) -> CampaignJournal:
        created_root = False
        try:
            state_root.mkdir(mode=_DIRECTORY_MODE, parents=True)
            created_root = True
        except FileExistsError:
            pass
        _require_secure_directory(state_root)
        if created_root:
            _fsync_directory(state_root.parent)
        lock_path = state_root / ".campaign-create.lock"
        try:
            _write_exclusive(lock_path, b"")
            _fsync_directory(state_root)
        except FileExistsError:
            pass

        with _locked_file(lock_path, exclusive=True):
            final_directory = state_root / header.digest.removeprefix("sha256:")
            if final_directory.exists():
                existing = cls.open(final_directory)
                if existing.header != header:
                    raise CampaignJournalConflict(
                        "existing campaign directory has a conflicting header"
                    )
                return existing

            staging = Path(tempfile.mkdtemp(prefix=".campaign-incoming-", dir=state_root))
            os.chmod(staging, _DIRECTORY_MODE)
            try:
                _write_exclusive(staging / "campaign.json", canonical_bytes(header) + b"\n")
                _write_exclusive(staging / "events.jsonl", b"")
                _fsync_directory(staging)
                os.rename(staging, final_directory)
                _fsync_directory(state_root)
            except BaseException:
                _remove_staging_directory(staging)
                raise
        return cls.open(final_directory)

    @classmethod
    def open(cls, directory: Path) -> CampaignJournal:
        _require_secure_directory(directory)
        content = _read_secure_file(directory / "campaign.json", maximum_bytes=16 * 1024 * 1024)
        try:
            header = CampaignHeader.model_validate_json(content)
        except ValidationError as error:
            raise CampaignJournalCorruption("campaign header is invalid") from error
        if content != canonical_bytes(header) + b"\n":
            raise CampaignJournalCorruption("campaign header is not canonically encoded")
        if directory.name != header.digest.removeprefix("sha256:"):
            raise CampaignJournalCorruption("campaign directory name does not match its header")
        _require_secure_regular_file(directory / "events.jsonl")
        return cls(directory, header)

    def record(self) -> CampaignRecord:
        descriptor = os.open(self.events_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            data = _read_all(descriptor)
        finally:
            os.close(descriptor)
        _, _, commits = _decode_durable_prefix(data, self.header)
        return CampaignRecord(header=self.header, commits=commits)

    def transact(
        self,
        factory: Callable[[CampaignRecord], Sequence[CampaignEvent]],
    ) -> CampaignRecord:
        """Build, validate, and commit one event group against the latest durable record."""

        descriptor = os.open(self.events_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            data = _read_all(descriptor)
            durable_length, head_digest, commits = _decode_durable_prefix(data, self.header)
            if durable_length != len(data):
                os.ftruncate(descriptor, durable_length)
                os.fsync(descriptor)
            record = CampaignRecord(header=self.header, commits=commits)
            requested = tuple(factory(record))
            if not requested:
                raise ValueError("a campaign transaction must contain at least one event")
            for offset, event in enumerate(requested):
                if event.sequence != len(record.events) + offset:
                    raise CampaignJournalConflict(
                        "campaign transaction does not own its event positions"
                    )
            committed_ids = {event.event_id for event in record.events}
            requested_ids = [event.event_id for event in requested]
            if len(requested_ids) != len(set(requested_ids)) or committed_ids.intersection(
                requested_ids
            ):
                raise CampaignJournalConflict("campaign event identifier is already owned")
            commit = CampaignCommit.from_events(
                previous_record_digest=head_digest,
                events=requested,
            )
            prospective = CampaignRecord(header=self.header, commits=(*commits, commit))
            from edagym.providers.campaign_replay import replay_campaign_record

            replay_campaign_record(prospective)
            os.lseek(descriptor, 0, os.SEEK_END)
            _write_all_fd(descriptor, canonical_bytes(commit) + b"\n")
            os.fsync(descriptor)
            return prospective
        finally:
            os.close(descriptor)


def _decode_durable_prefix(
    data: bytes,
    header: CampaignHeader,
) -> tuple[int, str, tuple[CampaignCommit, ...]]:
    head_digest = header.digest
    if not data:
        return 0, head_digest, ()
    durable_length = len(data)
    if not data.endswith(b"\n"):
        boundary = data.rfind(b"\n")
        durable_length = boundary + 1 if boundary >= 0 else 0
    commits: list[CampaignCommit] = []
    for line in data[:durable_length].splitlines():
        if not line:
            raise CampaignJournalCorruption("campaign journal contains an empty record")
        try:
            commit = CampaignCommit.model_validate_json(line)
        except ValidationError as error:
            raise CampaignJournalCorruption(
                "campaign journal contains an invalid record"
            ) from error
        if canonical_bytes(commit) != line:
            raise CampaignJournalCorruption("campaign journal record is not canonical")
        if commit.previous_record_digest != head_digest:
            raise CampaignJournalCorruption("campaign journal hash chain is discontinuous")
        commits.append(commit)
        head_digest = commit.record_digest
    CampaignRecord(header=header, commits=tuple(commits))
    return durable_length, head_digest, tuple(commits)


@contextmanager
def _locked_file(path: Path, *, exclusive: bool) -> Iterator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _require_secure_fd(descriptor, regular=True)
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield descriptor
    finally:
        os.close(descriptor)


def _read_secure_file(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = _require_secure_fd(descriptor, regular=True)
        if metadata.st_size > maximum_bytes:
            raise CampaignJournalCorruption("campaign metadata exceeds its read bound")
        return _read_all(descriptor)
    finally:
        os.close(descriptor)


def _read_all(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        _FILE_MODE,
    )
    try:
        _write_all_fd(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all_fd(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("short write while committing campaign journal data")
        view = view[written:]


def _require_secure_fd(descriptor: int, *, regular: bool) -> os.stat_result:
    metadata = os.fstat(descriptor)
    expected = stat.S_ISREG(metadata.st_mode) if regular else stat.S_ISDIR(metadata.st_mode)
    if not expected or metadata.st_uid != os.getuid():
        raise CampaignJournalError("campaign journal paths must be owned and correctly typed")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CampaignJournalError("campaign journal paths cannot grant group or other access")
    return metadata


def _require_secure_directory(path: Path) -> os.stat_result:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _require_secure_fd(descriptor, regular=False)
    finally:
        os.close(descriptor)


def _require_secure_regular_file(path: Path) -> os.stat_result:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _require_secure_fd(descriptor, regular=True)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_staging_directory(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_file() and not child.is_symlink():
            child.unlink()
    with suppress(FileNotFoundError):
        path.rmdir()
