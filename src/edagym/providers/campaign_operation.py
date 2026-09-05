"""Composition owner for executing and resuming one frozen paid campaign."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Protocol, Self
from uuid import uuid4

from pydantic import AfterValidator, Field, model_validator

from edagym.authoring.materialization import (
    CatalogMaterializationReceipt,
    _materialized_path,
    verify_materialized_catalog,
)
from edagym.authoring.provider import (
    AuthoringProviderError,
    ExportMemberRole,
    ExternalAuthoringProvider,
    OpaqueTaskInstanceReference,
    PrivateAuthoringCapability,
)
from edagym.canonical import canonical_digest
from edagym.drivers.catalog import backend_by_id
from edagym.drivers.deployment import load_backend_deployment_registry
from edagym.drivers.probe import ResolvedInstallation, probe_backend
from edagym.drivers.rootless_image import (
    RootlessImageConfiguration,
    RootlessImageExecutionRecipe,
)
from edagym.executors.asset_policy import AssetSourcePolicy
from edagym.executors.deployment import (
    ExecutorDeploymentRegistry,
    RootlessExecutorDeployment,
    load_executor_deployment_registry,
)
from edagym.executors.local import ExecutorUnavailable
from edagym.executors.protocol import Executor
from edagym.flow_tasks import (
    CanonicalFlowTask,
    FlowTaskCatalog,
    flow_evaluator_runtimes,
    load_private_flow_catalog,
)
from edagym.flow_tasks.runtime import validate_runtime_inputs
from edagym.participants.responses import (
    MeteredResponsesParticipantSender,
    responses_instruction_digest,
)
from edagym.providers.campaign_budget import (
    CampaignAccountingError,
    CampaignBudgetExceeded,
    CampaignBudgetProjection,
)
from edagym.providers.campaign_journal import CampaignJournalError
from edagym.providers.campaign_runner import (
    CampaignRecord,
    CampaignReport,
    CampaignRunner,
    TrialOutcomeRecordedEvent,
)
from edagym.providers.campaign_schedule import CampaignHeader, ScheduledTrial
from edagym.providers.model import ProviderProfile, ResolvedProviderConfig
from edagym.providers.provider_budget import CampaignProviderBudget
from edagym.providers.responses import ProviderProtocolError, ResponsesBroker
from edagym.providers.trial_evidence import (
    CampaignTrialResult,
    project_campaign_trial_run_evidence,
)
from edagym.providers.trial_runtime import CampaignTrialDispatcher
from edagym.providers.trial_security import campaign_trial_harness_actor
from edagym.providers.trial_workspace import participant_release_paths
from edagym.run.artifacts import ArtifactStoreError, ContentAddressedStore
from edagym.run.journal import JournalError, RunJournal
from edagym.runtime.errors import OrchestrationError
from edagym.runtime.model import EvaluatorRuntime
from edagym.security.canary import CanaryExposure, CanaryPolicy, CanaryProtocolError
from edagym.security.credentials import (
    CodexCredentialSource,
    CredentialFormatError,
    CredentialSecurityError,
)
from edagym.security.synthetic_preflight import (
    SyntheticPreflightError,
    SyntheticPreflightLauncher,
)
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.environment import EnvironmentSpec, FilesystemScope
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import SessionSpec
from edagym.specs.task import TaskSpec
from edagym.task_families.catalog import PUBLIC_TASK_CATALOG

_DIRECTORY_MODE = 0o700
_LOCK_FILE_MODE = 0o600
_OPERATION_LOCK_NAME = ".campaign-operation.lock"
_CAMPAIGN_JOURNAL_DIRECTORY = "campaign"
_RUN_JOURNAL_DIRECTORY = "runs"
_TRIAL_RUNTIME_DIRECTORY = "runtime"
_EXECUTOR_JOB_DIRECTORY = "executor-jobs"
_PREFLIGHT_DIRECTORY = "preflight"
_PREFLIGHT_STATE_DIRECTORY = "state"
_PREFLIGHT_RUNTIME_DIRECTORY = "runtime"
_PARTICIPANT_MEMBER_ROLES = frozenset(
    {ExportMemberRole.PUBLIC_FILE, ExportMemberRole.PARTICIPANT_FILE}
)


def _require_absolute_path_text(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts[1:])
        or any(character in value for character in "\x00\r\n")
    ):
        raise ValueError("path must be a normalized absolute POSIX path")
    return path.as_posix()


AbsolutePathText = Annotated[str, AfterValidator(_require_absolute_path_text)]


class FrozenCampaignProposal(StrictModel):
    """Complete portable campaign identity and numeric approval envelope."""

    schema_version: SchemaVersion = 1
    header: CampaignHeader
    budget: CampaignBudgetProjection

    @model_validator(mode="after")
    def validate_budget(self) -> Self:
        expected = CampaignBudgetProjection.from_campaign(
            self.header.campaign,
            self.header.schedule,
        )
        if self.budget != expected:
            raise ValueError("campaign proposal budget is not derived from its header")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="frozen-provider-campaign-proposal-v1")


class AuthoringProviderBinding(StrictModel):
    """Restricted authoring provider locator with its three trusted digests."""

    executable: AbsolutePathText
    executable_digest: Digest
    implementation_digest: Digest
    descriptor_digest: Digest


class RootlessImageToolRecipe(StrictModel):
    """Portable in-image entrypoint selection for one catalog backend."""

    tool_id: Identifier
    image_digest: Digest
    tool_entrypoint: AbsolutePathText
    package_manifest_path: AbsolutePathText
    package_manifest_digest: Digest
    package_manifest_checksum_path: AbsolutePathText


class AssetPathBinding(StrictModel):
    """Host locator for one environment asset; content is verified by digest."""

    asset_id: Identifier
    path: AbsolutePathText


class CampaignOperationRequest(StrictModel):
    """Everything a run or resume needs beyond the local credential files."""

    schema_version: SchemaVersion = 1
    proposal: FrozenCampaignProposal
    instruction: Annotated[str, Field(min_length=1)]
    authoring_provider: AuthoringProviderBinding
    flow_catalog_root: AbsolutePathText
    backend_deployment: AbsolutePathText
    executor_deployment: AbsolutePathText
    container_engine: AbsolutePathText
    rootless_image_tools: Annotated[tuple[RootlessImageToolRecipe, ...], Field(min_length=1)]
    assets: tuple[AssetPathBinding, ...] = ()
    artifact_store_root: AbsolutePathText
    artifact_key_file: AbsolutePathText | None = None
    state_root: AbsolutePathText
    environments: Annotated[tuple[EnvironmentSpec, ...], Field(min_length=1)]
    sessions: Annotated[tuple[SessionSpec, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        campaign = self.proposal.header.campaign
        environment_digests = [item.digest for item in self.environments]
        session_digests = [item.digest for item in self.sessions]
        tool_ids = [item.tool_id for item in self.rootless_image_tools]
        asset_ids = [item.asset_id for item in self.assets]
        if len(environment_digests) != len(set(environment_digests)) or set(
            environment_digests
        ) != set(campaign.environment_digests):
            raise ValueError("request environments must exactly cover the frozen campaign")
        if len(session_digests) != len(set(session_digests)):
            raise ValueError("request sessions must be unique")
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("rootless image tool recipes must name unique tools")
        required_assets = {
            asset.asset_id for environment in self.environments for asset in environment.assets
        }
        if len(asset_ids) != len(set(asset_ids)) or set(asset_ids) != required_assets:
            raise ValueError("asset path bindings must exactly cover the environment assets")
        return self

    @property
    def header(self) -> CampaignHeader:
        return self.proposal.header

    @property
    def credential_profile(self) -> ProviderProfile:
        """The frozen provider profile is the only trusted credential profile."""

        return self.proposal.header.provider_config.profile


class CampaignOperationRefusalReason(StrEnum):
    INSTRUCTION_MISMATCH = "instruction_mismatch"
    PROVIDER_CONFIG_MISMATCH = "provider_config_mismatch"
    AUTHORING_CATALOG_UNAVAILABLE = "authoring_catalog_unavailable"
    TASK_RELEASE_UNAVAILABLE = "task_release_unavailable"
    EVALUATOR_RUNTIME_UNAVAILABLE = "evaluator_runtime_unavailable"
    SESSION_UNAVAILABLE = "session_unavailable"
    DEPLOYMENT_REGISTRY_UNAVAILABLE = "deployment_registry_unavailable"
    EXECUTOR_UNAVAILABLE = "executor_unavailable"
    STATE_ROOT_UNAVAILABLE = "state_root_unavailable"
    OPERATION_IN_PROGRESS = "operation_in_progress"
    CAMPAIGN_JOURNAL_CONFLICT = "campaign_journal_conflict"
    CAMPAIGN_ALREADY_STARTED = "campaign_already_started"
    CAMPAIGN_NOT_STARTED = "campaign_not_started"
    PREFLIGHT_FAILED = "preflight_failed"
    PROVIDER_ACCESS_REFUSED = "provider_access_refused"
    TRIAL_RUNTIME_FAILED = "trial_runtime_failed"
    TRIAL_EVIDENCE_UNAVAILABLE = "trial_evidence_unavailable"


class CampaignOperationRefusal(RuntimeError):
    """A typed reason why no further trial was dispatched."""

    def __init__(
        self,
        reason: CampaignOperationRefusalReason,
        *,
        trial_id: str | None = None,
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.trial_id = trial_id


class CampaignOperationResult(StrictModel):
    """Durable-journal projection of one run or resume invocation."""

    schema_version: SchemaVersion = 1
    campaign_digest: Digest
    schedule_digest: Digest
    campaign_record_digest: Digest
    trial_results: tuple[CampaignTrialResult, ...]
    pending_trial_ids: tuple[Identifier, ...]
    report: CampaignReport | None

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if (self.report is None) != bool(self.pending_trial_ids):
            raise ValueError("a campaign report exists exactly when no trial is pending")
        return self


@dataclass(frozen=True, slots=True)
class PreparedCampaignTrial:
    """Every frozen document and store one scheduled trial dispatches with."""

    trial: ScheduledTrial
    task: TaskSpec
    instance: TaskInstance
    release: ReleaseManifest
    environment: EnvironmentSpec
    session: SessionSpec
    artifact_store: ContentAddressedStore
    evaluators: tuple[EvaluatorRuntime, ...]
    participant_files: Mapping[str, Path]
    asset_paths: Mapping[str, Path]

    def scoped_asset_paths(self, scope: FilesystemScope) -> dict[str, Path]:
        expected = {
            mount.asset_id
            for mount in self.environment.filesystem.readonly_assets
            if mount.scope is scope
        }
        return {asset_id: self.asset_paths[asset_id] for asset_id in expected}


@dataclass(frozen=True, slots=True)
class AdmittedCampaignTrial:
    """Executor and attested metered sender for exactly one trial dispatch."""

    executor: Executor
    sender: MeteredResponsesParticipantSender
    close: Callable[[], None]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


class CampaignTrialHost(Protocol):
    """Host-bound executor, preflight, and provider boundary for prepared trials."""

    @property
    def provider_config(self) -> ResolvedProviderConfig: ...

    @property
    def asset_source_policy(self) -> AssetSourcePolicy: ...

    def admit(
        self,
        prepared: PreparedCampaignTrial,
        *,
        runner: CampaignRunner,
        policy: CanaryPolicy,
        job_state_root: Path,
        preflight_root: Path,
    ) -> AdmittedCampaignTrial: ...


class RootlessCampaignTrialHost:
    """Rootless-container executors, synthetic preflight, and Codex credentials."""

    def __init__(
        self,
        *,
        credentials: CodexCredentialSource,
        provider_config: ResolvedProviderConfig,
        asset_source_policy: AssetSourcePolicy,
        executor_registry: ExecutorDeploymentRegistry,
        rootless: RootlessExecutorDeployment,
        installations: Mapping[str, ResolvedInstallation],
    ) -> None:
        self._credentials = credentials
        self._provider_config = provider_config
        self._asset_source_policy = asset_source_policy
        self._executor_registry = executor_registry
        self._rootless = rootless
        self._installations = dict(installations)

    @property
    def provider_config(self) -> ResolvedProviderConfig:
        return self._provider_config

    @property
    def asset_source_policy(self) -> AssetSourcePolicy:
        return self._asset_source_policy

    def admit(
        self,
        prepared: PreparedCampaignTrial,
        *,
        runner: CampaignRunner,
        policy: CanaryPolicy,
        job_state_root: Path,
        preflight_root: Path,
    ) -> AdmittedCampaignTrial:
        executor = self._rootless.create_executor(
            environment=prepared.environment,
            tool_installations=self._installations,
            asset_source_policy=self._asset_source_policy,
            artifact_store=prepared.artifact_store,
            job_state_root=job_state_root,
        )
        runtime_root = preflight_root / _PREFLIGHT_RUNTIME_DIRECTORY
        runtime_root.mkdir(mode=_DIRECTORY_MODE)
        preflight = SyntheticPreflightLauncher(
            runner=runner,
            trial=prepared.trial,
            task=prepared.task,
            instance=prepared.instance,
            release=prepared.release,
            environment=prepared.environment,
            session=prepared.session,
            state_root=preflight_root / _PREFLIGHT_STATE_DIRECTORY,
            runtime_root=runtime_root,
            artifact_store=prepared.artifact_store,
            executor=executor,
            evaluators=prepared.evaluators,
            participant_files=prepared.participant_files,
            asset_paths=prepared.asset_paths,
        ).launch(policy)
        sender = ResponsesBroker().open_trial_sender(
            configuration=self._provider_config,
            runner=runner,
            trial_id=prepared.trial.trial_id,
            policy=policy,
            attestation=preflight.attestation,
            credentials=self._credentials,
        )
        return AdmittedCampaignTrial(executor=executor, sender=sender, close=sender.close)

    def close(self) -> None:
        self._executor_registry.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def open_rootless_campaign_host(request: CampaignOperationRequest) -> RootlessCampaignTrialHost:
    """Bind credentials, deployment registries, and image tools named by the request."""

    credentials = CodexCredentialSource(trusted_profile=request.credential_profile)
    try:
        provider_config = credentials.inspect_profile()
    except (CredentialFormatError, CredentialSecurityError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.PROVIDER_ACCESS_REFUSED
        ) from None
    try:
        backend_registry = load_backend_deployment_registry(Path(request.backend_deployment))
        asset_source_policy = backend_registry.asset_source_policy()
        executor_registry = load_executor_deployment_registry(Path(request.executor_deployment))
    except (OSError, RuntimeError, ValueError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.DEPLOYMENT_REGISTRY_UNAVAILABLE
        ) from None
    try:
        rootless = executor_registry.rootless_configuration()
        installations = _rootless_installations(request, rootless)
    except (ExecutorUnavailable, KeyError, OSError, ValueError):
        executor_registry.close()
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.EXECUTOR_UNAVAILABLE
        ) from None
    return RootlessCampaignTrialHost(
        credentials=credentials,
        provider_config=provider_config,
        asset_source_policy=asset_source_policy,
        executor_registry=executor_registry,
        rootless=rootless,
        installations=installations,
    )


def _rootless_installations(
    request: CampaignOperationRequest,
    rootless: RootlessExecutorDeployment,
) -> dict[str, ResolvedInstallation]:
    engine_path = Path(request.container_engine)
    runtime = rootless.capability.runtime
    if runtime is None or _executable_digest(engine_path) != runtime.executable_digest:
        raise ExecutorUnavailable("container engine differs from the deployed rootless runtime")
    installations: dict[str, ResolvedInstallation] = {}
    for recipe in request.rootless_image_tools:
        configuration = RootlessImageConfiguration(
            recipe=RootlessImageExecutionRecipe(
                image_digest=recipe.image_digest,
                tool_entrypoint=recipe.tool_entrypoint,
                package_manifest_path=recipe.package_manifest_path,
                package_manifest_digest=recipe.package_manifest_digest,
                package_manifest_checksum_path=recipe.package_manifest_checksum_path,
            ),
            engine_path=engine_path,
            image_reference=rootless.image_references[recipe.image_digest],
        )
        _, installation = probe_backend(
            backend_by_id(recipe.tool_id),
            rootless_image_configuration=configuration,
        )
        if installation is None:
            raise ExecutorUnavailable("rootless image tool could not be resolved")
        installations[recipe.tool_id] = installation
    return installations


def _executable_digest(path: Path) -> Digest:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
    finally:
        os.close(descriptor)
    return f"sha256:{digest.hexdigest()}"


def prepare_campaign_trials(
    request: CampaignOperationRequest,
    *,
    artifact_stores: Mapping[Digest, ContentAddressedStore],
) -> tuple[PreparedCampaignTrial, ...]:
    """Resolve every scheduled trial to exact provider-derived documents and evaluators."""

    header = request.header
    environments = {item.digest: item for item in request.environments}
    if set(artifact_stores) != set(environments):
        raise ValueError("campaign artifact stores must exactly cover the request environments")
    provider = ExternalAuthoringProvider(
        Path(request.authoring_provider.executable),
        expected_executable_digest=request.authoring_provider.executable_digest,
        expected_implementation_digest=request.authoring_provider.implementation_digest,
        expected_descriptor_digest=request.authoring_provider.descriptor_digest,
    )
    try:
        receipt = verify_materialized_catalog(Path(request.flow_catalog_root), PUBLIC_TASK_CATALOG)
        catalog = load_private_flow_catalog(provider, PUBLIC_TASK_CATALOG)
        if catalog.attestation != receipt.attestation:
            raise AuthoringProviderError("live flow catalog differs from materialized catalog")
    except (AuthoringProviderError, OSError, RuntimeError, ValueError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.AUTHORING_CATALOG_UNAVAILABLE
        ) from None
    asset_paths = {item.asset_id: Path(item.path) for item in request.assets}
    prepared_tasks: dict[Digest, _PreparedFlowTask] = {}
    for campaign_task in header.tasks:
        if campaign_task.task_family not in catalog.families:
            raise CampaignOperationRefusal(
                CampaignOperationRefusalReason.EVALUATOR_RUNTIME_UNAVAILABLE
            )
        environment = environments[campaign_task.environment_digest]
        canonical, release = _qualified_flow_release(
            provider,
            catalog,
            campaign_task.task_family,
            campaign_task.task_release_digest,
            environment,
        )
        pack = catalog.task_pack(campaign_task.task_family)
        try:
            validate_runtime_inputs(pack, canonical, environment)
            evaluators = flow_evaluator_runtimes(
                pack,
                canonical,
                environment,
                artifact_stores[environment.digest],
            )
        except ValueError:
            raise CampaignOperationRefusal(
                CampaignOperationRefusalReason.EVALUATOR_RUNTIME_UNAVAILABLE
            ) from None
        prepared_tasks[release.digest] = _PreparedFlowTask(
            canonical=canonical,
            release=release,
            evaluators=tuple(evaluators),
            participant_files=_participant_files(
                Path(request.flow_catalog_root),
                receipt,
                canonical.instance_reference,
                release,
            ),
        )
    prepared: list[PreparedCampaignTrial] = []
    for trial in header.schedule.trials:
        prepared_task = prepared_tasks[trial.binding.task_release_digest]
        environment = environments[trial.binding.environment_digest]
        prepared.append(
            PreparedCampaignTrial(
                trial=trial,
                task=prepared_task.canonical.task,
                instance=prepared_task.canonical.instance,
                release=prepared_task.release,
                environment=environment,
                session=_unique_session(trial, request.sessions),
                artifact_store=artifact_stores[environment.digest],
                evaluators=prepared_task.evaluators,
                participant_files=prepared_task.participant_files,
                asset_paths={
                    asset.asset_id: asset_paths[asset.asset_id] for asset in environment.assets
                },
            )
        )
    return tuple(prepared)


@dataclass(frozen=True, slots=True)
class _PreparedFlowTask:
    canonical: CanonicalFlowTask
    release: ReleaseManifest
    evaluators: tuple[EvaluatorRuntime, ...]
    participant_files: Mapping[str, Path]


def _qualified_flow_release(
    provider: ExternalAuthoringProvider,
    catalog: FlowTaskCatalog,
    family: str,
    release_digest: Digest,
    environment: EnvironmentSpec,
) -> tuple[CanonicalFlowTask, ReleaseManifest]:
    try:
        for qualified in catalog.family_attestation(family).instances:
            canonical = catalog.canonical_task(family, qualified.instance_name)
            response = provider.qualify(
                PrivateAuthoringCapability.EDA_FLOW_CATALOG,
                canonical.instance_reference,
                environment=environment,
            )
            if response.release.digest == release_digest:
                return canonical, response.release
    except (AuthoringProviderError, KeyError, OSError, RuntimeError, ValueError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.TASK_RELEASE_UNAVAILABLE
        ) from None
    raise CampaignOperationRefusal(CampaignOperationRefusalReason.TASK_RELEASE_UNAVAILABLE)


def _participant_files(
    catalog_root: Path,
    receipt: CatalogMaterializationReceipt,
    reference: OpaqueTaskInstanceReference,
    release: ReleaseManifest,
) -> dict[str, Path]:
    members = {
        member.content_digest: member
        for member in receipt.members
        if member.instance_reference_id == reference.reference_id
        and member.role in _PARTICIPANT_MEMBER_ROLES
    }
    by_path = {file.path: file for file in release.files}
    files: dict[str, Path] = {}
    for path in participant_release_paths(release):
        member = members.get(by_path[path].content_digest)
        if member is None:
            raise CampaignOperationRefusal(CampaignOperationRefusalReason.TASK_RELEASE_UNAVAILABLE)
        files[path] = catalog_root / _materialized_path(member)
    return files


def _unique_session(trial: ScheduledTrial, sessions: tuple[SessionSpec, ...]) -> SessionSpec:
    matches = []
    for session in sessions:
        try:
            campaign_trial_harness_actor(trial, session)
        except ValueError:
            continue
        matches.append(session)
    if len(matches) != 1:
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.SESSION_UNAVAILABLE,
            trial_id=trial.trial_id,
        )
    return matches[0]


def execute_campaign_operation(
    request: CampaignOperationRequest,
    prepared: tuple[PreparedCampaignTrial, ...],
    *,
    resume: bool,
    host: CampaignTrialHost,
) -> CampaignOperationResult:
    """Dispatch every pending trial of the frozen schedule from its durable journal."""

    header = request.header
    if responses_instruction_digest(request.instruction) != header.campaign.prompt_digest:
        raise CampaignOperationRefusal(CampaignOperationRefusalReason.INSTRUCTION_MISMATCH)
    if host.provider_config != header.provider_config:
        raise CampaignOperationRefusal(CampaignOperationRefusalReason.PROVIDER_CONFIG_MISMATCH)
    by_trial = {item.trial.trial_id: item for item in prepared}
    scheduled = {trial.trial_id: trial for trial in header.schedule.trials}
    if (
        len(by_trial) != len(prepared)
        or {trial_id: item.trial for trial_id, item in by_trial.items()} != scheduled
    ):
        raise ValueError("prepared trials must exactly cover the frozen schedule")
    state_root = Path(request.state_root)
    try:
        _ensure_private_directory(state_root)
        job_state_root = _ensure_private_directory(state_root / _EXECUTOR_JOB_DIRECTORY)
        preflight_parent = _ensure_private_directory(state_root / _PREFLIGHT_DIRECTORY)
    except (OSError, ValueError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.STATE_ROOT_UNAVAILABLE
        ) from None
    with _operation_lock(state_root):
        try:
            runner = CampaignRunner(
                campaign=header.campaign,
                model_set=header.model_set,
                tasks=header.tasks,
                provider_config=header.provider_config,
                state_root=state_root / _CAMPAIGN_JOURNAL_DIRECTORY,
            )
        except (CampaignJournalError, OSError, ValueError):
            raise CampaignOperationRefusal(
                CampaignOperationRefusalReason.CAMPAIGN_JOURNAL_CONFLICT
            ) from None
        if runner.header != header:
            raise CampaignOperationRefusal(CampaignOperationRefusalReason.CAMPAIGN_JOURNAL_CONFLICT)
        started = bool(runner.journal.record().commits)
        if started and not resume:
            raise CampaignOperationRefusal(CampaignOperationRefusalReason.CAMPAIGN_ALREADY_STARTED)
        if resume and not started:
            raise CampaignOperationRefusal(CampaignOperationRefusalReason.CAMPAIGN_NOT_STARTED)
        policy = CanaryPolicy(
            provider_profile_digest=header.provider_config.profile.digest,
            provider_config_digest=header.provider_config.digest,
            budget_binding_digest=CampaignProviderBudget(runner).binding_digest,
        )
        run_state_root = state_root / _RUN_JOURNAL_DIRECTORY
        runtime_root = state_root / _TRIAL_RUNTIME_DIRECTORY
        dispatcher = CampaignTrialDispatcher(runner)
        for trial in runner.pending_trials():
            item = by_trial[trial.trial_id]
            try:
                preflight_root = _ensure_private_directory(
                    preflight_parent / trial.trial_id / uuid4().hex
                )
            except (OSError, ValueError):
                raise CampaignOperationRefusal(
                    CampaignOperationRefusalReason.STATE_ROOT_UNAVAILABLE,
                    trial_id=trial.trial_id,
                ) from None
            admitted = _admit(
                host,
                item,
                runner=runner,
                policy=policy,
                job_state_root=job_state_root,
                preflight_root=preflight_root,
            )
            try:
                with admitted:
                    dispatcher.dispatch(
                        trial_id=trial.trial_id,
                        task=item.task,
                        instance=item.instance,
                        release=item.release,
                        environment=item.environment,
                        session=item.session,
                        sender=admitted.sender,
                        instruction=request.instruction,
                        run_state_root=run_state_root,
                        runtime_root=runtime_root,
                        artifact_store=item.artifact_store,
                        executor=admitted.executor,
                        evaluators=item.evaluators,
                        participant_files=item.participant_files,
                        asset_source_policy=host.asset_source_policy,
                        evaluator_asset_paths=item.scoped_asset_paths(FilesystemScope.EVALUATOR),
                        tool_asset_paths=item.scoped_asset_paths(FilesystemScope.TOOL),
                    )
            except CampaignBudgetExceeded as exceeded:
                _stop_unfinished(runner, exceeded, trial_id=trial.trial_id)
                break
            except (
                ArtifactStoreError,
                CampaignAccountingError,
                ExecutorUnavailable,
                JournalError,
                OrchestrationError,
                OSError,
                RuntimeError,
                ValueError,
            ):
                raise CampaignOperationRefusal(
                    CampaignOperationRefusalReason.TRIAL_RUNTIME_FAILED,
                    trial_id=trial.trial_id,
                ) from None
        record = runner.journal.record()
        pending = tuple(trial.trial_id for trial in runner.pending_trials())
        return CampaignOperationResult(
            campaign_digest=header.campaign.digest,
            schedule_digest=header.schedule.digest,
            campaign_record_digest=record.integrity_digest,
            trial_results=_trial_results(record, by_trial, run_state_root),
            pending_trial_ids=pending,
            report=None if pending else runner.build_report(),
        )


def _stop_unfinished(
    runner: CampaignRunner,
    exceeded: CampaignBudgetExceeded,
    *,
    trial_id: str,
) -> None:
    """A cap reached before dispatch ends every unfinished trial with that typed reason."""

    try:
        runner.stop_unfinished(exceeded.stop_reason)
    except (CampaignAccountingError, CampaignJournalError, OSError, ValueError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.TRIAL_RUNTIME_FAILED,
            trial_id=trial_id,
        ) from None


def _admit(
    host: CampaignTrialHost,
    item: PreparedCampaignTrial,
    *,
    runner: CampaignRunner,
    policy: CanaryPolicy,
    job_state_root: Path,
    preflight_root: Path,
) -> AdmittedCampaignTrial:
    trial_id = item.trial.trial_id
    try:
        return host.admit(
            item,
            runner=runner,
            policy=policy,
            job_state_root=job_state_root,
            preflight_root=preflight_root,
        )
    except ExecutorUnavailable:
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.EXECUTOR_UNAVAILABLE,
            trial_id=trial_id,
        ) from None
    except (CanaryExposure, CanaryProtocolError, SyntheticPreflightError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.PREFLIGHT_FAILED,
            trial_id=trial_id,
        ) from None
    except (CredentialFormatError, CredentialSecurityError, ProviderProtocolError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.PROVIDER_ACCESS_REFUSED,
            trial_id=trial_id,
        ) from None
    except (OSError, RuntimeError, ValueError):
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.TRIAL_RUNTIME_FAILED,
            trial_id=trial_id,
        ) from None


def _trial_results(
    record: CampaignRecord,
    by_trial: Mapping[str, PreparedCampaignTrial],
    run_state_root: Path,
) -> tuple[CampaignTrialResult, ...]:
    """Rebuild every completed-run receipt from the two durable journals."""

    results: list[CampaignTrialResult] = []
    for commit in record.commits:
        for event in commit.events:
            if not isinstance(event, TrialOutcomeRecordedEvent):
                continue
            outcome = event.payload.outcome
            if outcome.run_id is None:
                continue
            item = by_trial[event.payload.trial_id]
            try:
                journal = RunJournal.open(
                    run_state_root / outcome.run_id.removeprefix("sha256:"),
                    item.task,
                )
                resources = project_campaign_trial_run_evidence(
                    journal.record(),
                    item.task,
                    item.artifact_store,
                ).resources
                results.append(
                    CampaignTrialResult(
                        trial_id=event.payload.trial_id,
                        run_id=outcome.run_id,
                        run_record_digest=journal.integrity_digest(),
                        campaign_record_digest=commit.record_digest,
                        resources=resources,
                        outcome=outcome,
                    )
                )
            except (ArtifactStoreError, JournalError, OSError, TypeError, ValueError):
                raise CampaignOperationRefusal(
                    CampaignOperationRefusalReason.TRIAL_EVIDENCE_UNAVAILABLE,
                    trial_id=event.payload.trial_id,
                ) from None
    return tuple(results)


def _ensure_private_directory(path: Path) -> Path:
    path.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("campaign state directories must be private and owner-controlled")
    return path


@contextmanager
def _operation_lock(state_root: Path) -> Iterator[None]:
    """Hold the exclusive per-state-root lock; a concurrent operation is refused, not queued."""

    try:
        descriptor = os.open(
            state_root / _OPERATION_LOCK_NAME,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            _LOCK_FILE_MODE,
        )
    except OSError:
        raise CampaignOperationRefusal(
            CampaignOperationRefusalReason.STATE_ROOT_UNAVAILABLE
        ) from None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise CampaignOperationRefusal(CampaignOperationRefusalReason.STATE_ROOT_UNAVAILABLE)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CampaignOperationRefusal(
                CampaignOperationRefusalReason.OPERATION_IN_PROGRESS
            ) from None
        yield
    finally:
        os.close(descriptor)
