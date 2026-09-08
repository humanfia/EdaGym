"""Evidence for journal-only projections and public artifact allowlisting."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from edagym.evaluation.model import PassedOutcome, StageResult
from edagym.projections import (
    ProjectionUnavailable,
    aggregate_leaderboard,
    project_atif,
    project_course_report,
    project_course_report_record,
    project_harbor,
    project_leaderboard_entry,
    project_leaderboard_entry_record,
    project_nemo,
    project_nemo_record,
)
from edagym.resolution import resolve_run
from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
    BlobRef,
    ManifestEntry,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ContentAddressedStore,
)
from edagym.run.journal import RunJournal
from edagym.run.model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    CandidateSubmittedEvent,
    CandidateSubmittedPayload,
    CheckpointCommittedEvent,
    CheckpointCommittedPayload,
    EvaluationCompletedEvent,
    EvaluationCompletedPayload,
    EvaluationStartedEvent,
    EvaluationStartedPayload,
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    JobStateChangedEvent,
    JobStateChangedPayload,
    JobStateKind,
    ProducerKind,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunStartedEvent,
    RunStartedPayload,
    StopReason,
)
from edagym.specs.common import (
    ArtifactClass,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.session import (
    BenchmarkMode,
    CourseMode,
    FeedbackPolicy,
    FixedWriter,
    HandoffWriter,
    HarnessActor,
    HumanActor,
    RecoveryPolicy,
    SessionSpec,
)
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)


def test_ecosystem_projections_allowlist_public_references_from_journal(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    base_session = session_spec()
    session = SessionSpec(
        session_id="projection_benchmark",
        mode=BenchmarkMode(),
        actors=base_session.actors,
        writer=base_session.writer,
        feedback=FeedbackPolicy.SAFE_DIAGNOSTIC,
        recovery=RecoveryPolicy.NONE,
        resources=base_session.resources,
        model_budget=base_session.model_budget,
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="projection-0001",
    )
    header = RunHeader.from_binding(plan.binding)
    journal = RunJournal.create(tmp_path / "journal", header, task)
    store = ContentAddressedStore(
        tmp_path / "store",
        policy=environment.artifact_policy,
    )
    checkpoint_blob = store.put_bytes(
        b"checkpoint-state",
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    checkpoint_manifest = ArtifactManifest(
        artifact_class=ArtifactClass.CHECKPOINT,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
        entries=(
            ManifestEntry(
                path="state.bin",
                blob=checkpoint_blob,
                mode=0o644,
            ),
        ),
    )
    committed_checkpoint = store.put_manifest(checkpoint_manifest)
    with pytest.raises(ProjectionUnavailable):
        project_atif(journal)
    events = (
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID("00000000-0000-0000-0000-000000000201"),
            timestamp=datetime(2026, 9, 4, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID("00000000-0000-0000-0000-000000000202"),
            timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(
                record=ArtifactRecord(
                    logical_id="canary_secret",
                    blob=committed_checkpoint.blob,
                    media_type=ARTIFACT_MANIFEST_MEDIA_TYPE,
                    artifact_class=ArtifactClass.CHECKPOINT,
                    sensitivity=Sensitivity.INTERNAL,
                    visibility=Visibility.AUTHOR,
                    redistribution=Redistribution.RESTRICTED,
                )
            ),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID("00000000-0000-0000-0000-000000000203"),
            timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=ArtifactRecordedPayload(
                record=ArtifactRecord(
                    logical_id="public_signal",
                    blob=BlobRef(digest=digest("public-artifact"), size_bytes=8),
                    media_type="text/plain",
                    artifact_class=ArtifactClass.DIAGNOSTIC,
                    sensitivity=Sensitivity.PUBLIC,
                    visibility=Visibility.PUBLIC,
                    redistribution=Redistribution.ALLOWED,
                )
            ),
        ),
        InteractionRecordedEvent(
            run_id=header.run_id,
            sequence=3,
            event_id=UUID("00000000-0000-0000-0000-000000000204"),
            timestamp=datetime(2026, 9, 4, 0, 0, 3, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.AUTHOR,
            artifact_refs=("canary_secret",),
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.PARTICIPANT_OUTPUT,
                interaction_id="private_turn",
            ),
        ),
        InteractionRecordedEvent(
            run_id=header.run_id,
            sequence=4,
            event_id=UUID("00000000-0000-0000-0000-000000000205"),
            timestamp=datetime(2026, 9, 4, 0, 0, 4, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.PARTICIPANT,
            artifact_refs=("public_signal",),
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.PARTICIPANT_OUTPUT,
                interaction_id="public_turn",
            ),
        ),
        CandidateSubmittedEvent(
            run_id=header.run_id,
            sequence=5,
            event_id=UUID("00000000-0000-0000-0000-000000000206"),
            timestamp=datetime(2026, 9, 4, 0, 0, 5, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="solver",
            visibility=Visibility.PARTICIPANT,
            payload=CandidateSubmittedPayload(
                candidate_id="candidate_a",
                candidate_digest=digest("projection-candidate"),
            ),
        ),
        EvaluationStartedEvent(
            run_id=header.run_id,
            sequence=6,
            event_id=UUID("00000000-0000-0000-0000-000000000207"),
            timestamp=datetime(2026, 9, 4, 0, 0, 6, tzinfo=UTC),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.AUTHOR,
            payload=EvaluationStartedPayload(
                stage_id="functional",
                candidate_id="candidate_a",
                job_id="hidden_functional_job",
            ),
        ),
        JobStateChangedEvent(
            run_id=header.run_id,
            sequence=7,
            event_id=UUID("00000000-0000-0000-0000-000000000208"),
            timestamp=datetime(2026, 9, 4, 0, 0, 7, tzinfo=UTC),
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.AUTHOR,
            payload=JobStateChangedPayload(
                job_id="hidden_functional_job",
                state=JobStateKind.RUNNING,
            ),
        ),
        JobStateChangedEvent(
            run_id=header.run_id,
            sequence=8,
            event_id=UUID("00000000-0000-0000-0000-000000000209"),
            timestamp=datetime(2026, 9, 4, 0, 0, 8, tzinfo=UTC),
            producer=ProducerKind.EXECUTOR,
            visibility=Visibility.AUTHOR,
            payload=JobStateChangedPayload(
                job_id="hidden_functional_job",
                state=JobStateKind.COMPLETED,
            ),
        ),
        EvaluationCompletedEvent(
            run_id=header.run_id,
            sequence=9,
            event_id=UUID("00000000-0000-0000-0000-000000000210"),
            timestamp=datetime(2026, 9, 4, 0, 0, 9, tzinfo=UTC),
            producer=ProducerKind.EVALUATOR,
            visibility=Visibility.PUBLIC,
            payload=EvaluationCompletedPayload(
                candidate_id="candidate_a",
                job_id="hidden_functional_job",
                result=StageResult(
                    stage_id="functional",
                    outcome=PassedOutcome(),
                ),
            ),
        ),
        CheckpointCommittedEvent(
            run_id=header.run_id,
            sequence=10,
            event_id=UUID("00000000-0000-0000-0000-000000000211"),
            timestamp=datetime(2026, 9, 4, 0, 0, 10, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            artifact_refs=("canary_secret",),
            payload=CheckpointCommittedPayload(
                checkpoint_id="canary_secret_checkpoint",
                manifest_digest=checkpoint_manifest.digest,
            ),
        ),
        RunEndedEvent(
            run_id=header.run_id,
            sequence=11,
            event_id=UUID("00000000-0000-0000-0000-000000000212"),
            timestamp=datetime(2026, 9, 4, 0, 0, 11, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
        ),
    )
    journal.append(events[0])
    with pytest.raises(ProjectionUnavailable):
        project_harbor(journal)
    assert project_nemo(journal).id == header.run_id
    with pytest.raises(ProjectionUnavailable):
        project_leaderboard_entry(journal, session)
    for event in events[1:]:
        journal.append(event)

    atif = project_atif(journal)
    harbor = project_harbor(journal)
    nemo = project_nemo(journal)
    with pytest.raises(ProjectionUnavailable, match="course session"):
        project_course_report(journal, session)
    leaderboard = project_leaderboard_entry(journal, session)
    assert project_nemo_record(journal.record(), task) == nemo
    assert project_leaderboard_entry_record(journal.record(), task, session) == leaderboard
    aggregates = aggregate_leaderboard(((journal, session),))
    exported = "\n".join(
        projection.model_dump_json()
        for projection in (atif, harbor, nemo, leaderboard, *aggregates)
    )

    assert "public_signal" in exported
    assert "canary_secret" not in exported
    assert instance.identity.seed not in exported
    assert harbor.reward.reward == 0
    assert atif.session_id == header.run_id
    assert atif.agent.name == "edagym-harness"
    assert nemo.responses_create_params.input[0].role == "user"
    assert instance.digest in nemo.responses_create_params.input[0].content
    assert release.digest in nemo.responses_create_params.input[0].content
    nemo_document = nemo.model_dump()
    assert "agent_ref" not in nemo_document
    assert "response" not in nemo_document
    assert "reward" not in nemo_document
    assert not leaderboard.rank_eligible
    assert leaderboard.stage_outcomes == ()
    assert leaderboard.measurements == ()
    assert aggregates[0].success_denominator == 1
    assert not aggregates[0].rank_eligible
    with pytest.raises(ProjectionUnavailable, match="same run twice"):
        aggregate_leaderboard(((journal, session), (journal, session)))


def test_course_report_excludes_author_only_activity_and_artifacts(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    base_session = session_spec()
    session = SessionSpec(
        session_id="projection_course",
        mode=CourseMode(rubric_digest=digest("course-rubric")),
        actors=(
            HumanActor(
                actor_id="student",
                adapter_id="json_line",
                adapter_digest=digest("course-human-adapter"),
            ),
        ),
        writer=FixedWriter(writer="student"),
        feedback=FeedbackPolicy.COURSE,
        recovery=RecoveryPolicy.REQUIRED,
        resources=base_session.resources,
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=session,
        trial_key="course-projection-0001",
    )
    header = RunHeader.from_binding(plan.binding)
    journal = RunJournal.create(tmp_path / "course-journal", header, task)
    events = (
        RunStartedEvent(
            run_id=header.run_id,
            sequence=0,
            event_id=UUID("00000000-0000-0000-0000-000000000221"),
            timestamp=datetime(2026, 9, 4, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunStartedPayload(binding_digest=header.binding.digest),
        ),
        ArtifactRecordedEvent(
            run_id=header.run_id,
            sequence=1,
            event_id=UUID("00000000-0000-0000-0000-000000000222"),
            timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(
                record=ArtifactRecord(
                    logical_id="canary_hidden_artifact",
                    blob=BlobRef(digest=digest("course-secret"), size_bytes=12),
                    media_type="text/plain",
                    artifact_class=ArtifactClass.DIAGNOSTIC,
                    sensitivity=Sensitivity.PUBLIC,
                    visibility=Visibility.PUBLIC,
                    redistribution=Redistribution.ALLOWED,
                )
            ),
        ),
        InteractionRecordedEvent(
            run_id=header.run_id,
            sequence=2,
            event_id=UUID("00000000-0000-0000-0000-000000000223"),
            timestamp=datetime(2026, 9, 4, 0, 0, 2, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="student",
            visibility=Visibility.AUTHOR,
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.PARTICIPANT_OUTPUT,
                interaction_id="canary_hidden_interaction",
            ),
        ),
        CandidateSubmittedEvent(
            run_id=header.run_id,
            sequence=3,
            event_id=UUID("00000000-0000-0000-0000-000000000224"),
            timestamp=datetime(2026, 9, 4, 0, 0, 3, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="student",
            visibility=Visibility.AUTHOR,
            payload=CandidateSubmittedPayload(
                candidate_id="canary_hidden_candidate",
                candidate_digest=digest("course-hidden-candidate"),
            ),
        ),
        InteractionRecordedEvent(
            run_id=header.run_id,
            sequence=4,
            event_id=UUID("00000000-0000-0000-0000-000000000225"),
            timestamp=datetime(2026, 9, 4, 0, 0, 4, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="student",
            visibility=Visibility.PARTICIPANT,
            payload=InteractionRecordedPayload(
                direction=InteractionDirection.PARTICIPANT_OUTPUT,
                interaction_id="visible_interaction",
            ),
        ),
        CandidateSubmittedEvent(
            run_id=header.run_id,
            sequence=5,
            event_id=UUID("00000000-0000-0000-0000-000000000226"),
            timestamp=datetime(2026, 9, 4, 0, 0, 5, tzinfo=UTC),
            producer=ProducerKind.PARTICIPANT,
            actor="student",
            visibility=Visibility.PARTICIPANT,
            payload=CandidateSubmittedPayload(
                candidate_id="visible_candidate",
                candidate_digest=digest("course-visible-candidate"),
                parent_candidate_id="canary_hidden_candidate",
            ),
        ),
        RunEndedEvent(
            run_id=header.run_id,
            sequence=6,
            event_id=UUID("00000000-0000-0000-0000-000000000227"),
            timestamp=datetime(2026, 9, 4, 0, 0, 6, tzinfo=UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
        ),
    )
    for event in events:
        journal.append(event)

    assert isinstance(session.mode, CourseMode)
    report = project_course_report(journal, session)
    assert project_course_report_record(journal.record(), task, session) == report
    with pytest.raises(ProjectionUnavailable, match="benchmark session"):
        project_leaderboard_entry(journal, session)
    atif = project_atif(journal)
    serialized = "\n".join((report.model_dump_json(), atif.model_dump_json()))

    assert report.actors[0].interaction_count == 1
    assert report.actors[0].candidate_count == 0
    assert report.candidates == ()
    assert report.rubric_digest == session.mode.rubric_digest
    assert report.terminal_reason is None
    assert len(atif.steps) == 1
    assert atif.agent.name == "edagym-human-adapter"
    diagnostic_count = next(
        count.count
        for count in report.artifact_counts
        if count.artifact_class is ArtifactClass.DIAGNOSTIC
    )
    assert diagnostic_count == 0
    assert "canary_hidden" not in serialized
    assert "visible_candidate" not in serialized


def test_leaderboard_partition_preserves_harness_route_association(
    tmp_path: Path,
) -> None:
    task = task_spec()
    environment = environment_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    base_session = session_spec()

    def project(
        routes: tuple[str, str],
        label: str,
    ) -> tuple[str, RunJournal, SessionSpec]:
        session = SessionSpec(
            session_id=f"association_{label}",
            mode=BenchmarkMode(trial_count=2),
            actors=(
                HarnessActor(
                    actor_id="alpha",
                    harness_id="command_agent",
                    harness_digest=digest("harness-alpha"),
                    scaffold_digest=digest("scaffold-alpha"),
                    requested_model_route=routes[0],
                ),
                HarnessActor(
                    actor_id="beta",
                    harness_id="command_agent",
                    harness_digest=digest("harness-beta"),
                    scaffold_digest=digest("scaffold-beta"),
                    requested_model_route=routes[1],
                ),
            ),
            writer=HandoffWriter(initial_writer="alpha"),
            feedback=FeedbackPolicy.SAFE_DIAGNOSTIC,
            recovery=RecoveryPolicy.NONE,
            resources=base_session.resources,
            model_budget=base_session.model_budget,
        )
        plan = resolve_run(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=f"association-{label}",
        )
        header = RunHeader.from_binding(plan.binding)
        journal = RunJournal.create(tmp_path / label, header, task)
        journal.append(
            RunStartedEvent(
                run_id=header.run_id,
                sequence=0,
                event_id=UUID(f"00000000-0000-0000-0000-0000000003{label}"),
                timestamp=datetime(2026, 9, 4, tzinfo=UTC),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.PUBLIC,
                payload=RunStartedPayload(binding_digest=header.binding.digest),
            )
        )
        journal.append(
            RunEndedEvent(
                run_id=header.run_id,
                sequence=1,
                event_id=UUID(f"00000000-0000-0000-0000-0000000004{label}"),
                timestamp=datetime(2026, 9, 4, 0, 0, 1, tzinfo=UTC),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.PUBLIC,
                payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
            )
        )
        entry = project_leaderboard_entry(journal, session)
        return entry.partition_id, journal, session

    direct, direct_journal, direct_session = project(("route-a", "route-b"), "01")
    swapped, _, _ = project(("route-b", "route-a"), "02")

    assert direct != swapped
    assert {
        route.actor_id: route.route
        for route in project_atif(direct_journal).extra.requested_model_routes
    } == {"alpha": "route-a", "beta": "route-b"}
    with pytest.raises(ProjectionUnavailable, match="declared trial count"):
        aggregate_leaderboard(((direct_journal, direct_session),))
