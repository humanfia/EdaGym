"""Production composition for canonical non-Sail flow runs."""

from __future__ import annotations

import os
import pwd
import stat
import subprocess
from collections.abc import Mapping
from pathlib import Path

from edagym.canonical import canonical_digest
from edagym.cli_support.backends import resolve_flow_host_bindings
from edagym.cli_support.documents import open_artifact_store
from edagym.cli_support.errors import CliFailure
from edagym.executors.licenses import LicenseProvider
from edagym.executors.local import BrokeredHostExecutor, ExecutorUnavailable
from edagym.flow_tasks import (
    CanonicalFlowTask,
    FlowTaskCatalog,
    flow_candidate_manifest_digest,
    join_flow_candidate_attestations,
)
from edagym.flow_tasks.model import FlowTaskPack, ToolCommand
from edagym.flow_tasks.qualification import qualify_flow_release
from edagym.flow_tasks.runtime import flow_evaluator_runtimes
from edagym.participants.adapters import ParticipantAdapterError, ParticipantFailureKind
from edagym.participants.model import ParticipantView, SubmitCandidateIntent
from edagym.run.artifacts import (
    ArtifactStoreError,
    ContentAddressedStore,
    manifest_paths,
)
from edagym.run.trial_model import RunState, StopReason
from edagym.runtime.errors import OrchestrationError
from edagym.runtime.orchestrator import RunOrchestrator
from edagym.specs.common import ArtifactClass
from edagym.specs.environment import BrokeredHostToolExecutor, EnvironmentSpec
from edagym.specs.release import FlowReleaseQualification, ReleaseManifest
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
from edagym.specs.task import WorkspaceInterface

_SUCCESS = 0
_UNSATISFIED = 1
_INCOMPLETE = 3
_MAXIMUM_TIMEOUT_SECONDS = 24 * 60 * 60
_FLOW_ACTOR_ID = "flow_submitter"


class _CandidateAdapter:
    def __init__(self, candidate_id: str) -> None:
        self._candidate_id = candidate_id
        self._submitted = False

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {_FLOW_ACTOR_ID: ActorKind.HUMAN}

    @property
    def campaign_admission(self) -> None:
        return None

    def next_intent(self, view: ParticipantView) -> SubmitCandidateIntent:
        if view.actor_id != _FLOW_ACTOR_ID:
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        if self._submitted:
            raise ParticipantAdapterError(ParticipantFailureKind.END_OF_INPUT)
        self._submitted = True
        return SubmitCandidateIntent(candidate_id=self._candidate_id)


def load_flow_pack(family: str, catalog: FlowTaskCatalog) -> FlowTaskPack:
    try:
        return catalog.task_pack(family)
    except KeyError:
        raise CliFailure("unknown-flow-task", status=_UNSATISFIED) from None


def evaluate_flow_candidate(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    candidate_id: str,
    environment: EnvironmentSpec,
    release: ReleaseManifest,
    *,
    workspace: Path,
    runtime_root: Path,
    store_root: Path,
    key_file: Path | None,
    asset_paths: Mapping[str, Path],
    timeout_seconds: int,
    authorize_commercial: bool,
    backend_deployment: Path | None = None,
    author_calibration: bool = False,
) -> tuple[dict[str, object], int]:
    """Run one candidate through the canonical journal and return its portable record."""

    _validate_timeout(timeout_seconds)
    if not isinstance(release.qualification, FlowReleaseQualification):
        raise CliFailure("flow-qualified-release-required", status=_UNSATISFIED)
    if not author_calibration:
        raise CliFailure("flow-participant-isolation-required", status=_UNSATISFIED)
    workspace = _absolute_path(workspace)
    runtime_root = _absolute_path(runtime_root)
    store_root = _absolute_path(store_root)
    if key_file is not None:
        key_file = _absolute_path(key_file)
        _require_safe_runtime_path(key_file)
    if backend_deployment is not None:
        backend_deployment = _absolute_path(backend_deployment)
        _require_safe_runtime_path(backend_deployment)
    _require_private_workspace(workspace)
    _require_safe_runtime_path(runtime_root)
    _require_safe_runtime_path(store_root)
    _require_disjoint_paths(
        workspace,
        runtime_root,
        store_root,
        *((backend_deployment,) if backend_deployment is not None else ()),
    )
    store = open_artifact_store(store_root, environment, key_file)
    if not isinstance(canonical.task.interface, WorkspaceInterface):
        raise CliFailure("flow-workspace-interface-required", status=_UNSATISFIED)
    disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.CANDIDATE)
    if disclosure is None:
        raise CliFailure("flow-candidate-retention-disabled", status=_UNSATISFIED)
    try:
        submitted_manifest = manifest_paths(
            store,
            workspace,
            canonical.task.interface.submission_paths,
            artifact_class=ArtifactClass.CANDIDATE,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
        submitted_digest = store.put_manifest(submitted_manifest).blob.digest
    except (ArtifactStoreError, OSError, ValueError):
        raise CliFailure("flow-author-candidate-invalid", status=_UNSATISFIED) from None
    author_candidates = tuple(
        candidate
        for candidate in pack.candidates
        if flow_candidate_manifest_digest(candidate, environment) == submitted_digest
    )
    if len(author_candidates) != 1:
        raise CliFailure("flow-candidate-not-author-owned", status=_UNSATISFIED)
    _create_private_runtime_root(runtime_root)
    artifact_directory = _create_private_child(runtime_root, "executor-artifacts")
    job_state_root = _create_private_child(runtime_root, "executor-jobs")
    records_root = runtime_root / "records"
    executor, license_providers = _flow_executor(
        pack,
        environment,
        store,
        job_state_root=job_state_root,
        authorize_commercial=authorize_commercial,
        backend_deployment=backend_deployment,
    )
    session = _evaluation_session(
        pack,
        candidate_id,
        environment,
        timeout_seconds,
        author_candidate_digest=submitted_digest,
    )
    try:
        runtime = RunOrchestrator.create(
            task=canonical.task,
            instance=canonical.instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=_trial_key(pack, candidate_id),
            state_root=records_root,
            workspace=workspace,
            artifact_directory=artifact_directory,
            artifact_store=store,
            executor=executor,
            evaluators=flow_evaluator_runtimes(pack, canonical, environment, store),
            participant=_CandidateAdapter(candidate_id),
            asset_paths=asset_paths,
            license_providers=license_providers,
        )
        state = runtime.run_to_completion()
        record = runtime.journal.record()
    except (ExecutorUnavailable, OrchestrationError, ArtifactStoreError, OSError, RuntimeError):
        raise CliFailure("flow-runtime-failed", status=_INCOMPLETE) from None
    except ValueError:
        raise CliFailure("flow-run-resolution-failed", status=_UNSATISFIED) from None
    return (
        {
            "admission": "canonical_author_calibration",
            "candidate_id": candidate_id,
            "canonical_candidate_id": author_candidates[0].candidate_id,
            "record": record,
        },
        _evaluation_status(state),
    )


def qualify_flow_pack(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
    *,
    catalog: FlowTaskCatalog,
    scratch_root: Path,
    store_root: Path,
    key_file: Path | None,
    asset_paths: Mapping[str, Path],
    timeout_seconds: int,
    authorize_commercial: bool,
    backend_deployment: Path | None = None,
) -> dict[str, object]:
    """Run the witness and negatives through the canonical qualification journal."""

    _validate_timeout(timeout_seconds)
    scratch_root = _absolute_path(scratch_root)
    store_root = _absolute_path(store_root)
    if key_file is not None:
        key_file = _absolute_path(key_file)
        _require_safe_runtime_path(key_file)
    if backend_deployment is not None:
        backend_deployment = _absolute_path(backend_deployment)
        _require_safe_runtime_path(backend_deployment)
    _require_safe_runtime_path(scratch_root)
    _require_safe_runtime_path(store_root)
    _require_disjoint_paths(
        scratch_root,
        store_root,
        *((backend_deployment,) if backend_deployment is not None else ()),
    )
    _create_private_runtime_root(scratch_root)
    job_state_root = _create_private_child(scratch_root, "executor-jobs")
    store = open_artifact_store(store_root, environment, key_file)
    executor, license_providers = _flow_executor(
        pack,
        environment,
        store,
        job_state_root=job_state_root,
        authorize_commercial=authorize_commercial,
        backend_deployment=backend_deployment,
    )
    try:
        qualified = qualify_flow_release(
            pack,
            canonical,
            environment,
            runtime_root=scratch_root / "qualification",
            artifact_store=store,
            executor=executor,
            license_providers=license_providers,
            asset_paths=asset_paths,
            timeout_seconds=timeout_seconds,
        )
        candidate_attestations = join_flow_candidate_attestations(
            catalog,
            pack.family,
            environment,
            qualified.release,
            qualified.records,
            store,
        )
    except (ExecutorUnavailable, OrchestrationError, ArtifactStoreError, OSError, RuntimeError):
        raise CliFailure("flow-qualification-runtime-failed", status=_INCOMPLETE) from None
    except ValueError:
        raise CliFailure("flow-qualification-rejected", status=_UNSATISFIED) from None
    return {
        "release": qualified.release,
        "records": dict(qualified.records),
        "candidate_attestations": candidate_attestations,
    }


def _flow_executor(
    pack: FlowTaskPack,
    environment: EnvironmentSpec,
    store: ContentAddressedStore,
    *,
    job_state_root: Path,
    authorize_commercial: bool,
    backend_deployment: Path | None,
) -> tuple[BrokeredHostExecutor, Mapping[str, LicenseProvider]]:
    if not isinstance(environment.executor, BrokeredHostToolExecutor):
        raise CliFailure("flow-brokered-executor-required", status=_UNSATISFIED)
    tool_ids = frozenset(
        command.tool_id
        for stage in pack.stages
        for command in stage.commands
        if isinstance(command, ToolCommand)
    )
    bindings = resolve_flow_host_bindings(
        environment,
        tool_ids,
        authorize_commercial=authorize_commercial,
        backend_deployment=backend_deployment,
    )
    try:
        executor = BrokeredHostExecutor(
            executor_id=environment.executor.executor_id,
            tool_paths=bindings.tool_paths,
            tool_environments=bindings.tool_environments,
            tool_closures=bindings.tool_closures,
            site_container_configurations=bindings.site_container_configurations,
            asset_source_policy=bindings.asset_source_policy,
            artifact_store=store,
            job_state_root=job_state_root,
        )
    except (OSError, ValueError, ExecutorUnavailable):
        raise CliFailure("flow-executor-unavailable", status=_INCOMPLETE) from None
    return executor, bindings.license_providers


def _evaluation_session(
    pack: FlowTaskPack,
    candidate_id: str,
    environment: EnvironmentSpec,
    timeout_seconds: int,
    *,
    author_candidate_digest: str,
) -> SessionSpec:
    licensed = any(
        binding.license_binding_id is not None for binding in environment.tool_bindings
    )
    adapter_digest = canonical_digest(
        {
            "candidate_id": candidate_id,
            "pack_digest": pack.digest,
        },
        domain="flow-cli-candidate-adapter-v1",
    )
    return SessionSpec(
        session_id=f"flow_{adapter_digest.removeprefix('sha256:')[:24]}",
        mode=BenchmarkMode(),
        actors=(
            HumanActor(
                actor_id=_FLOW_ACTOR_ID,
                adapter_id="flow_cli_candidate",
                adapter_digest=adapter_digest,
            ),
        ),
        writer=FixedWriter(writer=_FLOW_ACTOR_ID),
        candidate_authority=CandidateAuthority.TASK_AUTHOR,
        author_candidate_digest=author_candidate_digest,
        feedback=FeedbackPolicy.STAGE,
        recovery=RecoveryPolicy.NONE,
        resources=ResourceBudget(
            max_turns=1,
            max_tool_calls=max(1, len(pack.stages)),
            max_experiments=1,
            max_wall_seconds=timeout_seconds,
            max_eda_compute_seconds=timeout_seconds,
            max_license_seconds=timeout_seconds if licensed else 0,
            max_artifact_bytes=environment.artifact_policy.quota_bytes,
        ),
    )


def _trial_key(pack: FlowTaskPack, candidate_id: str) -> str:
    digest = canonical_digest(
        {"candidate_id": candidate_id, "pack_digest": pack.digest},
        domain="flow-cli-trial-key-v1",
    )
    return f"flow_{digest.removeprefix('sha256:')[:24]}"


def _evaluation_status(state: RunState) -> int:
    if state.terminal_reason is StopReason.VERIFIER_SUCCESS:
        return _SUCCESS
    if state.terminal_reason in {
        StopReason.UNRANKABLE,
        StopReason.POLICY_FAILURE,
        StopReason.SECURITY_FAILURE,
    }:
        return _UNSATISFIED
    return _INCOMPLETE


def _validate_timeout(timeout_seconds: int) -> None:
    if timeout_seconds < 1 or timeout_seconds > _MAXIMUM_TIMEOUT_SECONDS:
        raise CliFailure("invalid-flow-timeout", status=_UNSATISFIED)


def _create_private_runtime_root(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        raise CliFailure("flow-runtime-root-exists", status=_UNSATISFIED) from None
    except OSError:
        raise CliFailure("flow-runtime-root-unavailable", status=_INCOMPLETE) from None
    _require_private_directory(path, "flow-runtime-root-insecure")


def _create_private_child(parent: Path, name: str) -> Path:
    child = parent / name
    try:
        child.mkdir(mode=0o700)
    except OSError:
        raise CliFailure("flow-runtime-root-unavailable", status=_INCOMPLETE) from None
    _require_private_directory(child, "flow-runtime-root-insecure")
    return child


def _require_private_workspace(path: Path) -> None:
    _require_unprotected_path(path)
    _require_private_directory(path, "flow-workspace-insecure")


def _require_private_directory(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise CliFailure(code, status=_UNSATISFIED) from None
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise CliFailure(code, status=_UNSATISFIED)


def _require_disjoint_paths(*paths: Path) -> None:
    resolved = tuple(path.resolve(strict=False) for path in paths)
    if any(
        left == right or left in right.parents or right in left.parents
        for position, left in enumerate(resolved)
        for right in resolved[position + 1 :]
    ):
        raise CliFailure("flow-runtime-path-overlap", status=_UNSATISFIED)


def _require_safe_runtime_path(path: Path) -> None:
    resolved = path.resolve(strict=False)
    _require_unprotected_path(resolved)
    existing = resolved
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    try:
        repository = _git(existing, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError):
        if _has_git_marker(existing):
            raise CliFailure("flow-runtime-ignore-unverified", status=_INCOMPLETE) from None
        return
    if repository.returncode != 0:
        return
    try:
        root = Path(repository.stdout.decode("utf-8", errors="strict").strip()).resolve(
            strict=True
        )
        relative = resolved.relative_to(root).as_posix()
    except (OSError, UnicodeError, ValueError):
        raise CliFailure("flow-runtime-ignore-unverified", status=_INCOMPLETE) from None
    try:
        tracked = _git(root, "ls-files", "--", relative)
        ignored = _git(root, "check-ignore", "--no-index", "--quiet", "--", relative)
    except (OSError, subprocess.SubprocessError):
        raise CliFailure("flow-runtime-ignore-unverified", status=_INCOMPLETE) from None
    if tracked.returncode != 0 or tracked.stdout or ignored.returncode != 0:
        raise CliFailure("flow-runtime-path-not-ignored", status=_UNSATISFIED)


def _require_unprotected_path(resolved: Path) -> None:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError, RuntimeError):
        raise CliFailure("flow-runtime-path-unsafe", status=_INCOMPLETE) from None
    if resolved in {Path("/"), home} or _paths_overlap(resolved, home / ".codex"):
        raise CliFailure("flow-runtime-path-unsafe", status=_UNSATISFIED)


def _git(directory: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("git", "-C", os.fspath(directory), *arguments),
        env={
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )


def _has_git_marker(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _absolute_path(path: Path) -> Path:
    try:
        return Path(os.path.abspath(path)).resolve(strict=False)
    except (OSError, RuntimeError):
        raise CliFailure("flow-runtime-path-unsafe", status=_UNSATISFIED) from None
