"""NeMo Gym pre-collation dataset projection for EdaGym tasks."""

from __future__ import annotations

from edagym.projections._snapshot import ProjectionSnapshot
from edagym.projections.model import (
    NemoDatasetProjection,
    NemoInputMessage,
    NemoResponsesCreateParams,
)
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import RunRecord
from edagym.specs.task import TaskSpec, WorkspaceInterface


def project_nemo(journal: TrialJournal) -> NemoDatasetProjection:
    """Derive an input row whose agent_ref will be added by NeMo dataset collation."""

    return _project_nemo_snapshot(ProjectionSnapshot.from_journal(journal))


def project_nemo_record(record: RunRecord, task: TaskSpec) -> NemoDatasetProjection:
    """Derive a NeMo row from a portable record after semantic replay."""

    return _project_nemo_snapshot(ProjectionSnapshot.from_record(record, task))


def _project_nemo_snapshot(snapshot: ProjectionSnapshot) -> NemoDatasetProjection:
    requirements = "\n".join(
        f"- {requirement.requirement_id}: {requirement.description}"
        for requirement in snapshot.task.contract.requirements
    )
    subject = (
        "workspace submission"
        if isinstance(snapshot.task.interface, WorkspaceInterface)
        else f"top module {snapshot.task.interface.top_module}"
    )
    instruction = (
        f"Solve EdaGym task {snapshot.task.identity.family} for {subject}.\n"
        f"Instance: {snapshot.header.binding.task.instance_digest}\n"
        f"Release: {snapshot.header.binding.task.release_digest}\n"
        f"Requirements:\n{requirements}"
    )
    return NemoDatasetProjection(
        responses_create_params=NemoResponsesCreateParams(
            input=(NemoInputMessage(content=instruction),),
        ),
        id=snapshot.header.run_id,
    )
