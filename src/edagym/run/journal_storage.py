"""Owner-only atomic journal publication and hash-chained durable records."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Annotated, Self, TypeVar

from pydantic import BaseModel, Field, ValidationError, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.specs.common import Digest, SchemaVersion, StrictModel

_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
Result = TypeVar("Result")


class JournalError(RuntimeError):
    """A journal cannot be accessed or committed safely."""


class JournalCorruption(JournalError):
    """A durable journal prefix is malformed or internally inconsistent."""


class EventConflict(JournalError):
    """A requested fact conflicts with a durable identity."""


class InvalidTransition(JournalError):
    """A fact is invalid in the current replayed state."""


def commit_digest(previous_record_digest: Digest, events: tuple[BaseModel, ...]) -> Digest:
    return canonical_digest(
        {"events": events, "previous_record_digest": previous_record_digest},
        domain="run-journal-record-v1",
    )


class JournalCommit[Event: BaseModel](StrictModel):
    """One crash-atomic group; the event schema belongs to the consuming domain."""

    schema_version: SchemaVersion = 1
    previous_record_digest: Digest
    events: Annotated[tuple[Event, ...], Field(min_length=1)]
    record_digest: Digest

    @classmethod
    def from_events(cls, *, previous_record_digest: Digest, events: tuple[Event, ...]) -> Self:
        return cls(
            previous_record_digest=previous_record_digest,
            events=events,
            record_digest=commit_digest(previous_record_digest, events),
        )

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        if self.record_digest != commit_digest(self.previous_record_digest, self.events):
            raise ValueError("run commit digest does not match its content")
        return self


class JournalStorage[Event: BaseModel]:
    """The physical record codec and commit lock shared by journal consumers."""

    def __init__(
        self, directory: Path, anchor: Digest, commit_type: type[JournalCommit[Event]]
    ) -> None:
        require_directory(directory)
        self.directory = directory
        self.events_path = directory / "events.jsonl"
        self.anchor = anchor
        self.commit_type = commit_type
        with locked_file(self.events_path, exclusive=False):
            pass

    @staticmethod
    def create(root: Path, name: str, documents: Mapping[str, bytes]) -> Path:
        """Publish all immutable inputs together, or verify their exact prior binding."""

        if not name or name in {".", ".."} or Path(name).name != name:
            raise ValueError("journal directory requires one path component")
        if "events.jsonl" in documents or any(
            key in {"", ".", ".."} or Path(key).name != key for key in documents
        ):
            raise ValueError("journal documents require distinct flat metadata paths")
        created_root = False
        try:
            root.mkdir(mode=_DIRECTORY_MODE, parents=True)
            created_root = True
        except FileExistsError:
            pass
        require_directory(root)
        if created_root:
            fsync_directory(root.parent)
        lock_path = root / ".journal-create.lock"
        try:
            write_exclusive(lock_path, b"")
            fsync_directory(root)
        except FileExistsError:
            pass
        with locked_file(lock_path, exclusive=True):
            directory = root / name
            if directory.exists() or directory.is_symlink():
                require_directory(directory)
                for filename, content in documents.items():
                    if read_file(directory / filename, maximum_bytes=len(content)) != content:
                        raise EventConflict("existing journal has conflicting frozen inputs")
                return directory
            staging = Path(tempfile.mkdtemp(prefix=".run-incoming-", dir=root))
            try:
                for filename, content in documents.items():
                    write_exclusive(staging / filename, content)
                write_exclusive(staging / "events.jsonl", b"")
                fsync_directory(staging)
                os.rename(staging, directory)
                fsync_directory(root)
            except BaseException:
                if staging.exists():
                    for child in staging.iterdir():
                        if child.is_file() and not child.is_symlink():
                            child.unlink()
                    with suppress(FileNotFoundError):
                        staging.rmdir()
                raise
        return directory

    def records(self) -> tuple[JournalCommit[Event], ...]:
        with locked_file(self.events_path, exclusive=False) as descriptor:
            records, _ = self._decode(read_all(descriptor))
        return records

    def transact(
        self,
        factory: Callable[[tuple[JournalCommit[Event], ...]], tuple[tuple[Event, ...], Result]],
    ) -> Result:
        """Validate against the latest prefix, then publish one complete group."""

        with locked_file(self.events_path, exclusive=True, writable=True) as descriptor:
            data = read_all(descriptor)
            records, durable_length = self._decode(data)
            if durable_length != len(data):
                os.ftruncate(descriptor, durable_length)
                os.fsync(descriptor)
            requested, result = factory(records)
            if requested:
                record = self.commit_type.from_events(
                    previous_record_digest=records[-1].record_digest if records else self.anchor,
                    events=requested,
                )
                os.lseek(descriptor, 0, os.SEEK_END)
                write_all(descriptor, canonical_bytes(record) + b"\n")
                os.fsync(descriptor)
            return result

    def _decode(self, data: bytes) -> tuple[tuple[JournalCommit[Event], ...], int]:
        durable_length = len(data) if data.endswith(b"\n") else data.rfind(b"\n") + 1
        records = []
        head = self.anchor
        for line in data[:durable_length].splitlines():
            try:
                record = self.commit_type.model_validate_json(line)
            except ValidationError as error:
                raise JournalCorruption("journal contains an invalid durable record") from error
            if canonical_bytes(record) != line:
                raise JournalCorruption("journal record is not canonically encoded")
            if record.previous_record_digest != head:
                raise JournalCorruption("journal record hash chain is discontinuous")
            records.append(record)
            head = record.record_digest
        return tuple(records), durable_length


@contextmanager
def locked_file(path: Path, *, exclusive: bool, writable: bool = False) -> Iterator[int]:
    flags = os.O_RDWR if writable else os.O_RDONLY
    descriptor = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require_fd(descriptor, regular=True)
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield descriptor
    finally:
        os.close(descriptor)


def read_file(path: Path, *, maximum_bytes: int) -> bytes:
    with locked_file(path, exclusive=False) as descriptor:
        if os.fstat(descriptor).st_size > maximum_bytes:
            raise JournalCorruption("journal metadata exceeds its read bound")
        return read_all(descriptor)


def read_all(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, _FILE_MODE
    )
    try:
        write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("short write while committing journal data")
        view = view[written:]


def require_fd(descriptor: int, *, regular: bool) -> os.stat_result:
    metadata = os.fstat(descriptor)
    expected = stat.S_ISREG(metadata.st_mode) if regular else stat.S_ISDIR(metadata.st_mode)
    if not expected or metadata.st_uid != os.getuid():
        raise JournalError("journal paths must be owned and correctly typed")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise JournalError("journal paths cannot grant group or other access")
    return metadata


def require_directory(path: Path) -> os.stat_result:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return require_fd(descriptor, regular=False)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
