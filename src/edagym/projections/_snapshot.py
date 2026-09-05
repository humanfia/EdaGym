"""Validated, in-memory projection input derived from one run journal."""

from __future__ import annotations

from dataclasses import dataclass

from edagym.run.journal import RunJournal, replay
from edagym.run.model import RunEvent, RunHeader, RunRecord, RunState
from edagym.specs.task import TaskSpec


@dataclass(frozen=True, slots=True)
class ProjectionSnapshot:
    header: RunHeader
    task: TaskSpec
    events: tuple[RunEvent, ...]
    state: RunState

    @classmethod
    def from_journal(cls, journal: RunJournal) -> ProjectionSnapshot:
        events = journal.read_events()
        return cls(
            header=journal.header,
            task=journal.task,
            events=events,
            state=replay(journal.header, journal.task, events),
        )

    @classmethod
    def from_record(cls, record: RunRecord, task: TaskSpec) -> ProjectionSnapshot:
        """Replay one portable record into the shared projection boundary."""

        return cls(
            header=record.header,
            task=task,
            events=record.events,
            state=replay(record.header, task, record.events),
        )
