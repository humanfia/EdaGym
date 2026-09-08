"""Harbor trial documents derived from the run journal."""

from __future__ import annotations

from edagym.projections._facts import visible_run_end
from edagym.projections._snapshot import ProjectionSnapshot
from edagym.projections.atif import _project_atif_snapshot
from edagym.projections.errors import ProjectionUnavailable
from edagym.projections.model import HarborReward, HarborTrialProjection
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import RunRecord, StopReason
from edagym.specs.common import Visibility
from edagym.specs.task import TaskSpec


def project_harbor(journal: TrialJournal) -> HarborTrialProjection:
    return _project_harbor_snapshot(ProjectionSnapshot.from_journal(journal))


def project_harbor_record(record: RunRecord, task: TaskSpec) -> HarborTrialProjection:
    """Derive a Harbor trial from a portable record after semantic replay."""

    return _project_harbor_snapshot(ProjectionSnapshot.from_record(record, task))


def _project_harbor_snapshot(snapshot: ProjectionSnapshot) -> HarborTrialProjection:
    if snapshot.state.terminal_reason is None:
        raise ProjectionUnavailable("Harbor reward requires a terminated run")
    terminal = visible_run_end(snapshot, {Visibility.PUBLIC, Visibility.PARTICIPANT})
    if terminal is None:
        raise ProjectionUnavailable("Harbor reward requires a participant-visible outcome")
    return HarborTrialProjection(
        trajectory=_project_atif_snapshot(snapshot),
        reward=HarborReward(
            reward=1 if terminal.payload.reason is StopReason.VERIFIER_SUCCESS else 0
        ),
    )
