"""Journaled pre-release qualification for canonical EDA-flow tasks."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from edagym.canonical import canonical_digest
from edagym.executors.licenses import LicenseProvider
from edagym.executors.protocol import Executor
from edagym.flow_tasks.canonical import (
    CanonicalFlowTask,
    derive_flow_release,
    derive_flow_release_candidate,
    flow_candidate_manifest_digest,
)
from edagym.flow_tasks.model import CandidateVariant, FlowTaskPack
from edagym.flow_tasks.runtime import flow_evaluator_runtimes
from edagym.participants.adapters import ParticipantAdapterError, ParticipantFailureKind
from edagym.participants.model import ParticipantView, SubmitCandidateIntent
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.model import RunRecord
from edagym.runtime.orchestrator import RunOrchestrator
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest
from edagym.specs.session import (
    ActorKind,
    BenchmarkMode,
    CandidateAuthority,
    FeedbackPolicy,
    FixedWriter,
    HumanActor,
    RecoveryPolicy,
    ResourceBudget,
    SessionSpec,
)


@dataclass(frozen=True, slots=True)
class QualifiedFlowRelease:
    release: ReleaseManifest
    records: Mapping[str, RunRecord]


class _AuthorCandidateAdapter:
    def __init__(self, candidate_id: str) -> None:
        self._candidate_id = candidate_id
        self._submitted = False

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {"flow_author": ActorKind.HUMAN}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> SubmitCandidateIntent:
        if view.actor_id != "flow_author":
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        if self._submitted:
            raise ParticipantAdapterError(ParticipantFailureKind.END_OF_INPUT)
        self._submitted = True
        return SubmitCandidateIntent(candidate_id=self._candidate_id)


def qualify_flow_release(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
    *,
    runtime_root: Path,
    artifact_store: ContentAddressedStore,
    executor: Executor,
    license_providers: Mapping[str, LicenseProvider] | None = None,
    asset_paths: Mapping[str, Path] | None = None,
    timeout_seconds: int | None = None,
    poll_interval_seconds: float = 0.25,
) -> QualifiedFlowRelease:
    """Run every author candidate through the canonical runtime, then admit a release."""

    if artifact_store.policy != environment.artifact_policy:
        raise ValueError("qualification artifact store does not match the environment")
    release_candidate = derive_flow_release_candidate(pack, canonical, environment)
    _create_private_directory(runtime_root)
    workspaces = _create_private_directory(runtime_root / "workspaces")
    records_root = _create_private_directory(runtime_root / "records")
    executor_artifacts = _create_private_directory(runtime_root / "executor-artifacts")
    records: dict[str, RunRecord] = {}
    for candidate in pack.candidates:
        workspace = _create_private_directory(workspaces / candidate.candidate_id)
        artifact_directory = _create_private_directory(executor_artifacts / candidate.candidate_id)
        _write_candidate(workspace, candidate)
        session = _qualification_session(
            pack,
            candidate,
            environment,
            timeout_seconds=timeout_seconds,
        )
        runtime = RunOrchestrator.create(
            task=canonical.task,
            instance=canonical.instance,
            release=release_candidate,
            environment=environment,
            session=session,
            trial_key=f"author_qualification_{candidate.candidate_id}",
            state_root=records_root / candidate.candidate_id,
            workspace=workspace,
            artifact_directory=artifact_directory,
            artifact_store=artifact_store,
            executor=executor,
            license_providers=({} if license_providers is None else license_providers),
            evaluators=flow_evaluator_runtimes(
                pack,
                canonical,
                environment,
                artifact_store,
            ),
            participant=_AuthorCandidateAdapter(candidate.candidate_id),
            asset_paths={} if asset_paths is None else asset_paths,
            poll_interval_seconds=poll_interval_seconds,
        )
        runtime.run_to_completion()
        records[candidate.candidate_id] = runtime.journal.record()
    release = derive_flow_release(
        pack,
        canonical,
        environment,
        records,
        artifact_store,
    )
    return QualifiedFlowRelease(
        release=release,
        records=MappingProxyType(dict(records)),
    )


def _qualification_session(
    pack: FlowTaskPack,
    candidate: CandidateVariant,
    environment: EnvironmentSpec,
    *,
    timeout_seconds: int | None,
) -> SessionSpec:
    stage_count = len(pack.stages)
    default_wall_budget = environment.resources.wall_seconds * max(stage_count, 1) + 60
    if timeout_seconds is not None and timeout_seconds < 1:
        raise ValueError("qualification timeout must be positive")
    wall_budget = default_wall_budget if timeout_seconds is None else timeout_seconds
    licensed = any(binding.license_binding_id is not None for binding in environment.tool_bindings)
    return SessionSpec(
        session_id=f"qualify_{pack.family}_{candidate.candidate_id}",
        mode=BenchmarkMode(),
        actors=(
            HumanActor(
                actor_id="flow_author",
                adapter_id="flow_author_candidate",
                adapter_digest=canonical_digest(
                    {
                        "candidate_id": candidate.candidate_id,
                        "pack_digest": pack.digest,
                    },
                    domain="flow-author-adapter-v1",
                ),
            ),
        ),
        writer=FixedWriter(writer="flow_author"),
        candidate_authority=CandidateAuthority.TASK_AUTHOR,
        author_candidate_digest=flow_candidate_manifest_digest(candidate, environment),
        feedback=FeedbackPolicy.STAGE,
        recovery=RecoveryPolicy.NONE,
        resources=ResourceBudget(
            max_turns=1,
            max_tool_calls=max(
                1,
                sum(len(stage.commands) for stage in pack.stages),
            ),
            max_experiments=max(stage_count, 1),
            max_wall_seconds=wall_budget,
            max_eda_compute_seconds=wall_budget,
            max_license_seconds=wall_budget if licensed else 0,
            max_artifact_bytes=environment.artifact_policy.quota_bytes,
        ),
    )


def _write_candidate(workspace: Path, candidate: CandidateVariant) -> None:
    root = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for asset in candidate.assets:
            parts = PurePosixPath(asset.path).parts
            parent = os.dup(root)
            try:
                for part in parts[:-1]:
                    with suppress(FileExistsError):
                        os.mkdir(part, mode=0o700, dir_fd=parent)
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
                    0o600,
                    dir_fd=parent,
                )
                try:
                    content = asset.content.encode("utf-8")
                    view = memoryview(content)
                    while view:
                        written = os.write(descriptor, view)
                        if not written:
                            raise OSError("short write while preparing an author candidate")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            finally:
                os.close(parent)
    finally:
        os.close(root)


def _create_private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("qualification directories must be private and owner-controlled")
    return path
