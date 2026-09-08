"""Release evidence for real human, agent, and hybrid participant sessions."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.participants import (
    ParticipantActionKind,
    ParticipantSessionEvidence,
    project_participant_session_record,
)
from edagym.projections import (
    project_atif_record,
    project_course_report_record,
    project_harbor_record,
    project_leaderboard_entry_record,
    project_nemo_record,
)
from edagym.projections.errors import ProjectionUnavailable
from edagym.projections.model import ParticipationKind
from edagym.release_commands import ReleaseEvidenceStatus
from edagym.release_e2e import ArtifactClassCount
from edagym.resolution import ResolutionError, resolve_run
from edagym.run.artifacts import ContentAddressedStore, artifact_policy_digest
from edagym.run.journal_storage import JournalError
from edagym.run.trial_model import HarnessRunActor, HumanRunActor, RunRecord
from edagym.security.artifact_closure import (
    ArtifactClosureError,
    RunArtifactClosureReceipt,
    verify_run_artifact_closure,
)
from edagym.specs.common import ArtifactClass, Digest, StrictModel
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import (
    BenchmarkMode,
    CandidateAuthority,
    CourseMode,
    ModeKind,
    SessionSpec,
)
from edagym.specs.task import TaskSpec


class ReleaseProjectionKind(StrEnum):
    ATIF = "atif"
    HARBOR = "harbor"
    NEMO = "nemo"
    COURSE = "course"
    LEADERBOARD = "leaderboard"


_REQUIRED_PROJECTIONS = frozenset(ReleaseProjectionKind)
_MEANINGFUL_ACTIONS = frozenset(
    {
        ParticipantActionKind.OUTPUT,
        ParticipantActionKind.TOOL_REQUEST,
        ParticipantActionKind.PROVIDER_REQUEST,
        ParticipantActionKind.CANDIDATE_SUBMISSION,
    }
)


class ParticipantModeRunEvidence(StrictModel):
    """One replayed session and its public-safe, journal-derived projections."""

    session: ParticipantSessionEvidence
    mode: ModeKind
    candidate_authority: CandidateAuthority
    artifact_closure_receipt_digest: Digest
    artifact_counts: tuple[ArtifactClassCount, ...]
    atif_projection_digest: Digest
    harbor_projection_digest: Digest
    nemo_projection_digest: Digest
    course_projection_digest: Digest | None = None
    leaderboard_projection_digest: Digest | None = None

    @field_validator("artifact_counts")
    @classmethod
    def normalize_artifact_counts(
        cls,
        value: tuple[ArtifactClassCount, ...],
    ) -> tuple[ArtifactClassCount, ...]:
        classes = [item.artifact_class for item in value]
        if len(classes) != len(set(classes)):
            raise ValueError("participant session artifact classes must be unique")
        return tuple(sorted(value, key=lambda item: item.artifact_class.value))

    @model_validator(mode="after")
    def validate_real_session(self) -> Self:
        if self.candidate_authority is not CandidateAuthority.PARTICIPANT:
            raise ValueError("release participant sessions require participant candidate authority")
        if self.session.terminal_reason is None:
            raise ValueError("release participant sessions must be terminal")
        if not any(
            item.kind is ParticipantActionKind.CANDIDATE_SUBMISSION
            for item in self.session.actions
        ):
            raise ValueError("release participant sessions require an attributed submission")
        if not {ArtifactClass.CANDIDATE, ArtifactClass.EVIDENCE}.issubset(
            {item.artifact_class for item in self.artifact_counts}
        ):
            raise ValueError("release participant sessions require candidate and evidence closure")
        if (self.course_projection_digest is not None) != (self.mode is ModeKind.COURSE):
            raise ValueError("course projection identity must match the session mode")
        if (self.leaderboard_projection_digest is not None) != (
            self.mode is ModeKind.BENCHMARK
        ):
            raise ValueError("leaderboard projection identity must match the session mode")
        if self.session.participation is ParticipationKind.HYBRID:
            _validate_hybrid_activity(self.session)
        return self

    @property
    def projections(self) -> frozenset[ReleaseProjectionKind]:
        projected = {
            ReleaseProjectionKind.ATIF,
            ReleaseProjectionKind.HARBOR,
            ReleaseProjectionKind.NEMO,
        }
        if self.course_projection_digest is not None:
            projected.add(ReleaseProjectionKind.COURSE)
        if self.leaderboard_projection_digest is not None:
            projected.add(ReleaseProjectionKind.LEADERBOARD)
        return frozenset(projected)


class ParticipantModeSuiteEvidence(StrictModel):
    """Complete live participant-mode and projection coverage for release."""

    runs: Annotated[tuple[ParticipantModeRunEvidence, ...], Field(max_length=3)]
    missing_participation: tuple[ParticipationKind, ...]
    projection_coverage: tuple[ReleaseProjectionKind, ...]
    status: ReleaseEvidenceStatus

    @field_validator("runs")
    @classmethod
    def normalize_runs(
        cls,
        value: tuple[ParticipantModeRunEvidence, ...],
    ) -> tuple[ParticipantModeRunEvidence, ...]:
        run_ids = [item.session.run_id for item in value]
        record_digests = [item.session.run_record_integrity_digest for item in value]
        participations = [item.session.participation for item in value]
        if (
            len(run_ids) != len(set(run_ids))
            or len(record_digests) != len(set(record_digests))
            or len(participations) != len(set(participations))
        ):
            raise ValueError("participant-mode runs require unique immutable identities")
        return tuple(sorted(value, key=lambda item: item.session.participation.value))

    @field_validator("missing_participation", "projection_coverage")
    @classmethod
    def normalize_enums(cls, value: tuple[StrEnum, ...]) -> tuple[StrEnum, ...]:
        if len(value) != len(set(value)):
            raise ValueError("participant-mode summary values must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        present = {item.session.participation for item in self.runs}
        missing = tuple(sorted(set(ParticipationKind) - present, key=lambda item: item.value))
        projections = tuple(
            sorted(
                {projection for item in self.runs for projection in item.projections},
                key=lambda item: item.value,
            )
        )
        expected_status = (
            ReleaseEvidenceStatus.PASSED
            if not missing and set(projections) == _REQUIRED_PROJECTIONS
            else ReleaseEvidenceStatus.UNAVAILABLE
        )
        if (
            self.missing_participation != missing
            or self.projection_coverage != projections
            or self.status is not expected_status
        ):
            raise ValueError("participant-mode suite must derive from its exact run evidence")
        return self


def project_participant_mode_suite(
    *,
    run_records: tuple[RunRecord, ...],
    task_specs: tuple[TaskSpec, ...],
    task_instances: tuple[TaskInstance, ...],
    releases: tuple[ReleaseManifest, ...],
    environments: tuple[EnvironmentSpec, ...],
    sessions: tuple[SessionSpec, ...],
    artifact_stores: Mapping[Digest, ContentAddressedStore],
) -> ParticipantModeSuiteEvidence:
    """Replay exact live sources; an absent suite remains explicitly unavailable."""

    sources = (task_specs, task_instances, releases, environments, sessions)
    if not run_records:
        if any(sources) or artifact_stores:
            raise ValueError("participant-mode evidence cannot contain a partial source bundle")
        return ParticipantModeSuiteEvidence(
            runs=(),
            missing_participation=tuple(ParticipationKind),
            projection_coverage=(),
            status=ReleaseEvidenceStatus.UNAVAILABLE,
        )
    if len(run_records) > 3:
        raise ValueError("participant-mode release evidence accepts one run per mode")
    records = _unique_by(run_records, lambda item: item.header.run_id, "run")
    tasks = _unique_by(task_specs, lambda item: item.digest, "TaskSpec")
    instances = _unique_by(task_instances, lambda item: item.digest, "TaskInstance")
    release_map = _unique_by(releases, lambda item: item.digest, "release")
    environment_map = _unique_by(environments, lambda item: item.digest, "environment")
    session_map = _unique_by(sessions, lambda item: item.digest, "session")
    if set(artifact_stores) != set(records):
        raise ValueError("participant-mode evidence requires one live CAS per run")

    used_tasks: set[str] = set()
    used_instances: set[str] = set()
    used_releases: set[str] = set()
    used_environments: set[str] = set()
    used_sessions: set[str] = set()
    evidence: list[ParticipantModeRunEvidence] = []
    for run_id, record in records.items():
        binding = record.header.binding
        try:
            task = tasks[binding.task.task_spec_digest]
            instance = instances[binding.task.instance_digest]
            release = release_map[binding.task.release_digest]
            environment = environment_map[binding.environment.environment_spec_digest]
            session = session_map[binding.session.session_spec_digest]
        except KeyError as error:
            raise ValueError("participant-mode run is missing an exact specification") from error
        try:
            resolved = resolve_run(
                task=task,
                instance=instance,
                release=release,
                environment=environment,
                session=session,
                trial_key=binding.trial_key,
                campaign=binding.campaign,
                lineage=binding.lineage,
            )
            participant = project_participant_session_record(
                record,
                task=task,
                instance=instance,
                release=release,
                environment=environment,
                session=session,
            )
            closure = verify_run_artifact_closure(record, task, artifact_stores[run_id])
        except (ArtifactClosureError, JournalError, ResolutionError, ValueError) as error:
            raise ValueError("participant-mode run failed semantic replay") from error
        if resolved.binding != binding or closure.artifact_policy_digest != artifact_policy_digest(
            environment.artifact_policy
        ):
            raise ValueError("participant-mode run differs from its resolved source closure")
        used_tasks.add(task.digest)
        used_instances.add(instance.digest)
        used_releases.add(release.digest)
        used_environments.add(environment.digest)
        used_sessions.add(session.digest)
        evidence.append(
            _mode_run_evidence(
                record=record,
                task=task,
                session=session,
                participant=participant,
                closure=closure,
            )
        )
    if (
        used_tasks != set(tasks)
        or used_instances != set(instances)
        or used_releases != set(release_map)
        or used_environments != set(environment_map)
        or used_sessions != set(session_map)
    ):
        raise ValueError("participant-mode source bundle contains unreferenced specifications")
    runs = tuple(evidence)
    present = {item.session.participation for item in runs}
    missing = tuple(sorted(set(ParticipationKind) - present, key=lambda item: item.value))
    projections = tuple(
        sorted(
            {projection for item in runs for projection in item.projections},
            key=lambda item: item.value,
        )
    )
    return ParticipantModeSuiteEvidence(
        runs=runs,
        missing_participation=missing,
        projection_coverage=projections,
        status=(
            ReleaseEvidenceStatus.PASSED
            if not missing and set(projections) == _REQUIRED_PROJECTIONS
            else ReleaseEvidenceStatus.UNAVAILABLE
        ),
    )


def _mode_run_evidence(
    *,
    record: RunRecord,
    task: TaskSpec,
    session: SessionSpec,
    participant: ParticipantSessionEvidence,
    closure: RunArtifactClosureReceipt,
) -> ParticipantModeRunEvidence:
    try:
        atif = canonical_digest(
            project_atif_record(record, task),
            domain="release-session-atif-projection-v1",
        )
        harbor = canonical_digest(
            project_harbor_record(record, task),
            domain="release-session-harbor-projection-v1",
        )
        nemo = canonical_digest(
            project_nemo_record(record, task),
            domain="release-session-nemo-projection-v1",
        )
        course = (
            canonical_digest(
                project_course_report_record(record, task, session),
                domain="release-session-course-projection-v1",
            )
            if isinstance(session.mode, CourseMode)
            else None
        )
        leaderboard = (
            canonical_digest(
                project_leaderboard_entry_record(record, task, session),
                domain="release-session-leaderboard-projection-v1",
            )
            if isinstance(session.mode, BenchmarkMode)
            else None
        )
    except (JournalError, ProjectionUnavailable, ValueError) as error:
        raise ValueError("participant-mode output projection failed") from error
    artifact_classes = {item.artifact_class for item in closure.artifacts}
    return ParticipantModeRunEvidence(
        session=participant,
        mode=session.mode.kind,
        candidate_authority=session.candidate_authority,
        artifact_closure_receipt_digest=closure.digest,
        artifact_counts=tuple(
            ArtifactClassCount(
                artifact_class=artifact_class,
                count=sum(
                    item.artifact_class is artifact_class for item in closure.artifacts
                ),
            )
            for artifact_class in sorted(artifact_classes, key=lambda item: item.value)
        ),
        atif_projection_digest=atif,
        harbor_projection_digest=harbor,
        nemo_projection_digest=nemo,
        course_projection_digest=course,
        leaderboard_projection_digest=leaderboard,
    )


def _validate_hybrid_activity(evidence: ParticipantSessionEvidence) -> None:
    actor_kinds = {
        actor.actor_id: (
            ParticipationKind.HUMAN
            if isinstance(actor, HumanRunActor)
            else ParticipationKind.AGENT
            if isinstance(actor, HarnessRunActor)
            else None
        )
        for actor in evidence.actors
    }
    active_kinds = {
        actor_kinds[action.actor_id]
        for action in evidence.actions
        if action.kind in _MEANINGFUL_ACTIONS
    }
    if (
        not evidence.handoffs
        or active_kinds != {ParticipationKind.HUMAN, ParticipationKind.AGENT}
        or not any(
            actor_kinds[item.previous_writer] != actor_kinds[item.next_writer]
            for item in evidence.handoffs
        )
    ):
        raise ValueError("hybrid release evidence requires an attributed cross-kind handoff")


def _unique_by[T, K](
    values: tuple[T, ...],
    key: Callable[[T], K],
    label: str,
) -> dict[K, T]:
    result = {key(item): item for item in values}
    if len(result) != len(values):
        raise ValueError(f"participant-mode {label} identities must be unique")
    return result
