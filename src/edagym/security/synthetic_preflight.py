"""Trusted credential-free campaign preflight launcher."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, SupportsIndex
from uuid import UUID, uuid4

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.isolation_launch import (
    SyntheticIsolationPreflightExecution,
    SyntheticPreflightLaunchCapability,
)
from edagym.executors.licenses import LicenseProvider
from edagym.executors.rootless import RootlessContainerExecutor
from edagym.participants.adapters import ParticipantAdapter
from edagym.participants.admission import SyntheticPreflightParticipantAdmission
from edagym.participants.execution import (
    SyntheticPreflightExecutionGrant,
    _issue_synthetic_preflight_execution_grant,
)
from edagym.participants.model import ParticipantIntent, ParticipantView, SubmitCandidateIntent
from edagym.projections.atif import project_atif
from edagym.providers.campaign_runner import CampaignRunner
from edagym.providers.campaign_schedule import ScheduledTrial
from edagym.providers.trial_security import (
    campaign_trial_run_binding,
    runtime_surface_binding_for_trial,
)
from edagym.providers.trial_workspace import prepare_trial_workspace
from edagym.resolution import resolve_run
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.journal import RunJournal
from edagym.run.model import RunHeader, RunPurpose, RunRecord
from edagym.runtime.model import EvaluatorRuntime
from edagym.runtime.orchestrator import RunOrchestrator
from edagym.runtime_surface_protocol import (
    REQUIRED_ISOLATION_SURFACES,
    IsolationSurface,
    RuntimeSurfaceBinding,
)
from edagym.security.canary import CanaryAttestation, CanaryChallenge, CanaryPolicy
from edagym.security.collector import IsolationSurfaceCollector, RuntimeSurfaceIssuer
from edagym.specs.environment import EnvironmentSpec, FilesystemScope
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import ActorKind, BenchmarkMode, HarnessActor, SessionSpec
from edagym.specs.task import TaskSpec

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_EXPORT_FILE_NAME = "participant-trajectory.json"


class SyntheticPreflightError(RuntimeError):
    """A real credential-free preflight could not produce admissible evidence."""


class SyntheticPreflightResult:
    """One provider-free run and the opaque attestation issued from its surfaces."""

    __slots__ = ("attestation", "run_record")

    def __init__(
        self,
        *,
        run_record: RunRecord,
        attestation: CanaryAttestation,
    ) -> None:
        if type(run_record) is not RunRecord or type(attestation) is not CanaryAttestation:
            raise TypeError("synthetic preflight results require canonical run evidence")
        self.run_record = run_record
        self.attestation = attestation

    def __repr__(self) -> str:
        return "SyntheticPreflightResult(<bound>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("synthetic preflight results cannot be serialized")


class _SyntheticParticipant(ParticipantAdapter):
    """Submit the exact materialized release once without contacting a provider."""

    def __init__(
        self,
        *,
        actor_id: str,
        candidate_id: str,
        admission: SyntheticPreflightParticipantAdmission,
    ) -> None:
        self._actor_id = actor_id
        self._candidate_id = candidate_id
        self._admission = admission
        self._used = False

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return MappingProxyType({self._actor_id: ActorKind.HARNESS})

    @property
    def campaign_admission(self) -> None:
        return None

    @property
    def synthetic_preflight_admission(self) -> SyntheticPreflightParticipantAdmission:
        return self._admission

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if self._used or view.actor_id != self._actor_id:
            raise SyntheticPreflightError("synthetic participant received an unexpected turn")
        self._used = True
        return SubmitCandidateIntent(candidate_id=self._candidate_id)


class SyntheticPreflightLauncher:
    """Run and attest one exact campaign trial without provider credentials."""

    def __init__(
        self,
        *,
        runner: CampaignRunner,
        trial: ScheduledTrial,
        task: TaskSpec,
        instance: TaskInstance,
        release: ReleaseManifest,
        environment: EnvironmentSpec,
        session: SessionSpec,
        state_root: Path,
        runtime_root: Path,
        artifact_store: ContentAddressedStore,
        executor: RootlessContainerExecutor,
        evaluators: Sequence[EvaluatorRuntime],
        participant_files: Mapping[str, Path],
        asset_paths: Mapping[str, Path],
        license_providers: Mapping[str, LicenseProvider] | None = None,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], UUID] = uuid4,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if type(executor) is not RootlessContainerExecutor:
            raise SyntheticPreflightError(
                "synthetic preflight requires the sealed rootless executor"
            )
        if not isinstance(session.mode, BenchmarkMode):
            raise SyntheticPreflightError(
                "synthetic preflight requires the frozen benchmark session"
            )
        expected_assets = {asset.asset_id for asset in environment.assets}
        if set(asset_paths) != expected_assets:
            raise SyntheticPreflightError(
                "synthetic preflight assets must exactly cover the environment"
            )
        self._runner = runner
        self._trial = trial
        self._task = task
        self._instance = instance
        self._release = release
        self._environment = environment
        self._session = session
        self._state_root = state_root
        self._runtime_root = runtime_root
        self._store = artifact_store
        self._executor = executor
        self._evaluators = tuple(evaluators)
        self._participant_files = MappingProxyType(dict(participant_files))
        self._asset_paths = MappingProxyType(dict(asset_paths))
        self._license_providers = {} if license_providers is None else dict(license_providers)
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)
        self._event_id_factory = event_id_factory
        self._poll_interval_seconds = poll_interval_seconds
        self._used = False
        self._binding = runtime_surface_binding_for_trial(
            runner=runner,
            trial=trial,
            task=task,
            release=release,
            environment=environment,
            session=session,
        )

    def launch(self, policy: CanaryPolicy) -> SyntheticPreflightResult:
        """Execute fixed absence probes and one real provider-free trial exactly once."""

        if self._used:
            raise SyntheticPreflightError("synthetic preflight launcher was already used")
        self._used = True
        if (
            policy.provider_profile_digest != self._binding.provider_profile_digest
            or policy.provider_config_digest != self._binding.provider_config_digest
            or policy.budget_binding_digest != self._binding.budget_binding_digest
        ):
            raise SyntheticPreflightError("canary policy differs from the frozen trial")
        runtime_descriptor = _open_private_directory(self._runtime_root)
        os.close(runtime_descriptor)
        credential_root = self._runtime_root / "controller-synthetic-credential"
        export_root = self._runtime_root / "participant-export"
        isolation_root = self._runtime_root / "isolation-probes"
        for path in (credential_root, export_root, isolation_root):
            if path.exists():
                raise SyntheticPreflightError("synthetic preflight runtime state already exists")
        try:
            credential_root.mkdir(mode=_DIRECTORY_MODE)
            isolation_root.mkdir(mode=_DIRECTORY_MODE)
        except BaseException:
            if isolation_root.exists():
                _remove_private_empty_directory(isolation_root)
            if credential_root.exists():
                _remove_private_empty_directory(credential_root)
            raise
        challenge = CanaryChallenge(
            policy=policy,
            campaign_digest=self._runner.campaign.digest,
        )
        controller_environment: dict[str, str] = {}
        challenge.install_controller_environment(controller_environment)
        credential_path = credential_root / "credential"
        try:
            credential_descriptor = os.open(
                credential_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                _FILE_MODE,
            )
        except BaseException:
            challenge.close()
            _remove_private_empty_directory(credential_root)
            _remove_private_empty_directory(isolation_root)
            raise
        isolation_execution: SyntheticIsolationPreflightExecution | None = None
        try:
            challenge._install_credential_descriptor(credential_descriptor)
            launch_capability = challenge._issue_launch_capability()
            isolation_execution = _execute_isolation_preflight(
                self._executor,
                environment=self._environment,
                runtime_root=isolation_root,
                asset_paths=self._asset_paths,
                artifact_store=self._store,
                launch_capability=launch_capability,
            )
            record, workspace, journal_directory = self._run_provider_free_trial()
            export_root.mkdir(mode=_DIRECTORY_MODE)
            _write_private_file(
                export_root,
                _EXPORT_FILE_NAME,
                canonical_bytes(project_atif(RunJournal.open(journal_directory, self._task))),
            )
            execution_grant = _assemble_execution_grant(
                execution=isolation_execution,
                artifact_store=self._store,
                record=record,
                workspace=workspace,
                journal_directory=journal_directory,
                participant_export=export_root,
                runtime_surface_binding=self._binding,
            )
            issuer = RuntimeSurfaceIssuer(
                preflight_record=record,
                task=self._task,
                environment=self._environment,
                session=self._session,
                execution_grant=execution_grant,
            )
            attestation = challenge.attest(IsolationSurfaceCollector(issuer))
            return SyntheticPreflightResult(
                run_record=record,
                attestation=attestation,
            )
        except BaseException:
            raise
        finally:
            challenge.close()
            if isolation_execution is not None:
                isolation_execution.close()
            os.close(credential_descriptor)
            _unlink_private_file(credential_root, credential_path.name)
            _remove_private_empty_directory(credential_root)

    def _run_provider_free_trial(self) -> tuple[RunRecord, Path, Path]:
        campaign = campaign_trial_run_binding(self._runner, self._trial)
        plan = resolve_run(
            task=self._task,
            instance=self._instance,
            release=self._release,
            environment=self._environment,
            session=self._session,
            trial_key=self._trial.trial_id,
            campaign=campaign,
            purpose=RunPurpose.SYNTHETIC_PREFLIGHT,
        )
        journal = RunJournal.create(
            self._state_root,
            RunHeader.from_binding(plan.binding),
            self._task,
        )
        prepared = prepare_trial_workspace(
            runtime_root=self._runtime_root / "trial-runtime",
            journal=journal,
            environment=self._environment,
            session=self._session,
            release=self._release,
            participant_files=self._participant_files,
        )
        if prepared.resume_checkpoint_id is not None:
            raise SyntheticPreflightError("synthetic preflights cannot resume prior state")
        actor = next(actor for actor in self._session.actors if isinstance(actor, HarnessActor))
        admission = SyntheticPreflightParticipantAdmission(
            run_id=plan.binding.digest,
            actor_id=actor.actor_id,
            runtime_surface_binding=self._binding,
        )
        candidate_digest = canonical_digest(
            {"run_id": plan.binding.digest},
            domain="synthetic-preflight-candidate-id-v1",
        ).removeprefix("sha256:")
        participant = _SyntheticParticipant(
            actor_id=actor.actor_id,
            candidate_id=f"preflight_{candidate_digest[:48]}",
            admission=admission,
        )
        evaluator_assets = _scoped_assets(
            self._environment,
            self._asset_paths,
            FilesystemScope.EVALUATOR,
        )
        runtime = RunOrchestrator.create(
            task=self._task,
            instance=self._instance,
            release=self._release,
            environment=self._environment,
            session=self._session,
            trial_key=self._trial.trial_id,
            campaign=campaign,
            purpose=RunPurpose.SYNTHETIC_PREFLIGHT,
            state_root=self._state_root,
            workspace=prepared.workspace,
            artifact_directory=prepared.artifact_directory,
            artifact_store=self._store,
            executor=self._executor,
            evaluators=self._evaluators,
            participant=participant,
            asset_paths=evaluator_assets,
            license_providers=self._license_providers,
            clock=self._clock,
            event_id_factory=self._event_id_factory,
            poll_interval_seconds=self._poll_interval_seconds,
        )
        if runtime.plan != plan:
            raise SyntheticPreflightError("synthetic preflight resolution changed at launch")
        state = runtime.run_to_completion()
        if state.terminal_reason is None or state.successful_candidate_id is None:
            raise SyntheticPreflightError("synthetic preflight did not pass the real verifier")
        return runtime.journal.record(), prepared.workspace, runtime.journal.directory


def _execute_isolation_preflight(
    executor: RootlessContainerExecutor,
    *,
    environment: EnvironmentSpec,
    runtime_root: Path,
    asset_paths: Mapping[str, Path],
    artifact_store: ContentAddressedStore,
    launch_capability: SyntheticPreflightLaunchCapability,
) -> SyntheticIsolationPreflightExecution:
    if type(executor) is not RootlessContainerExecutor:
        raise SyntheticPreflightError("executor has no trusted isolation preflight")
    method = getattr(executor, "execute_isolation_preflight", None)
    if not callable(method):
        raise SyntheticPreflightError("executor isolation preflight is unavailable")
    execution = method(
        environment=environment,
        runtime_root=runtime_root,
        asset_paths=asset_paths,
        artifact_store=artifact_store,
        launch_capability=launch_capability,
    )
    if type(execution) is not SyntheticIsolationPreflightExecution:
        raise SyntheticPreflightError("executor returned no canonical isolation preflight")
    return execution


def _assemble_execution_grant(
    *,
    execution: SyntheticIsolationPreflightExecution,
    artifact_store: ContentAddressedStore,
    record: RunRecord,
    workspace: Path,
    journal_directory: Path,
    participant_export: Path,
    runtime_surface_binding: RuntimeSurfaceBinding,
) -> SyntheticPreflightExecutionGrant:
    if type(runtime_surface_binding) is not RuntimeSurfaceBinding:
        raise TypeError("synthetic preflight requires its canonical surface binding")
    receipt, process_surfaces = execution._claim()
    opened: list[tuple[IsolationSurface, int]] = list(process_surfaces)
    try:
        extras = {
            IsolationSurface.PARTICIPANT_WORKSPACE: _open_private_directory(workspace),
            IsolationSurface.JOURNAL: _open_private_directory(journal_directory),
            IsolationSurface.ARTIFACT_STORE: _open_private_directory(artifact_store.root),
            IsolationSurface.PARTICIPANT_EXPORT: _open_private_directory(participant_export),
        }
        opened.extend(extras.items())
        by_surface = dict(opened)
        surfaces = tuple((surface, by_surface[surface]) for surface in REQUIRED_ISOLATION_SURFACES)
        launcher_receipt_digest = canonical_digest(
            {
                "executor_receipt_digest": receipt.digest,
                "preflight_record_digest": record.integrity_digest,
                "run_binding_digest": record.header.binding.digest,
                "runtime_surface_binding_digest": runtime_surface_binding.digest,
                "surface_identity_digests": tuple(
                    _surface_descriptor_digest(surface, descriptor)
                    for surface, descriptor in surfaces
                ),
            },
            domain="synthetic-preflight-launcher-receipt-v1",
        )
        grant = _issue_synthetic_preflight_execution_grant(
            surfaces=surfaces,
            artifact_store=artifact_store,
            preflight_run_id=record.header.run_id,
            run_binding_digest=record.header.binding.digest,
            runtime_surface_binding=runtime_surface_binding,
            executor_receipt=receipt,
            launcher_receipt_digest=launcher_receipt_digest,
        )
    except BaseException:
        for _, descriptor in opened:
            with suppress(OSError):
                os.close(descriptor)
        raise
    return grant


def _scoped_assets(
    environment: EnvironmentSpec,
    asset_paths: Mapping[str, Path],
    scope: FilesystemScope,
) -> dict[str, Path]:
    expected = {
        mount.asset_id for mount in environment.filesystem.readonly_assets if mount.scope is scope
    }
    return {asset_id: asset_paths[asset_id] for asset_id in expected}


def _open_private_directory(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise SyntheticPreflightError("preflight directory is not private and owner-controlled")
    return descriptor


def _write_private_file(directory: Path, name: str, content: bytes) -> None:
    root = _open_private_directory(directory)
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            _FILE_MODE,
            dir_fd=root,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("participant export write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(root)
    finally:
        os.close(root)


def _unlink_private_file(directory: Path, name: str) -> None:
    root = _open_private_directory(directory)
    try:
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=root)
        os.fsync(root)
    finally:
        os.close(root)


def _remove_private_empty_directory(directory: Path) -> None:
    parent = _open_private_directory(directory.parent)
    try:
        with suppress(FileNotFoundError):
            os.rmdir(directory.name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _surface_descriptor_digest(surface: IsolationSurface, descriptor: int) -> str:
    metadata = os.fstat(descriptor)
    return canonical_digest(
        {
            "device": str(metadata.st_dev),
            "inode": str(metadata.st_ino),
            "mode": stat.S_IMODE(metadata.st_mode),
            "owner": metadata.st_uid,
            "surface": surface,
        },
        domain="synthetic-preflight-surface-receipt-v1",
    )
