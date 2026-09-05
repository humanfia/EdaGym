"""Release readiness projected from complete immutable evidence owners."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.authoring.provider import (
    DerivedTaskDocument,
    FlowCandidateAttestation,
    FlowCandidateRole,
    PrivateAuthoringCapability,
    QualificationProviderResponse,
    SealedCatalogAttestation,
)
from edagym.canonical import canonical_digest
from edagym.drivers.model import BackendCatalog
from edagym.drivers.qualification_verification import (
    VerifiedBackendQualificationSource,
)
from edagym.evaluation.model import HardGateState, OutcomeKind
from edagym.evaluation.promotion import hard_gate_status
from edagym.executors.capabilities import (
    LocalContainmentCapability,
    ProviderAvailability,
    ProviderUnavailableReason,
)
from edagym.flow_tasks.catalog import FlowTaskCatalog, join_flow_candidate_attestations
from edagym.policy.private_roots import (
    PrivateRootAuditReport,
    PrivateRootAuditStatus,
    PrivateRootRegistration,
)
from edagym.policy.repository import (
    AuditMode,
    AuditReport,
    AuditStatus,
    CoverageScope,
    CoverageStatus,
    RepositorySnapshot,
)
from edagym.providers.campaign import (
    REQUIRED_MODEL_CATEGORIES,
    CampaignScope,
    ModelCategory,
    ModelSetManifest,
    UncoveredCategory,
)
from edagym.providers.campaign_reporting import project_campaign_report
from edagym.providers.campaign_runner import (
    AttemptDisposition,
    CampaignRecord,
    CampaignReport,
    ServiceTierAccounting,
    TrialDisposition,
)
from edagym.providers.campaign_schedule import CampaignHeader, CampaignTask
from edagym.providers.model import RUST_CAT_PROFILE, ResolvedProviderConfig
from edagym.providers.model_discovery import ModelDiscoverySnapshot
from edagym.providers.qualification import RouteCanaryEvidence
from edagym.providers.trial_evidence import CampaignTrialResult
from edagym.release_authoring import (
    AuthoringCatalogEvidence,
    project_authoring_catalog,
)
from edagym.release_backend_sources import VerifiedBackendQualificationSources
from edagym.release_backends import (
    BackendCapabilityCoverage,
    BackendQualificationEvidence,
)
from edagym.release_backends import (
    project_backend_coverage as _backend_coverage,
)
from edagym.release_backends import (
    project_backend_qualification as _backend_evidence,
)
from edagym.release_commands import (
    ReleaseCommandEvidence,
    ReleaseCommandPurpose,
    ReleaseEvidenceStatus,
    VerifiedReleaseCommandReceipt,
    project_release_command,
    release_command_requires_installation,
)
from edagym.release_e2e import EndToEndSmokeEvidence, project_end_to_end_smoke
from edagym.release_evidence import (
    EvidenceCounts,
)
from edagym.release_evidence import (
    evidence_counts as _counts,
)
from edagym.release_evidence import (
    evidence_status as _status_for_counts,
)
from edagym.release_private_roots import project_release_private_root_audit
from edagym.release_sessions import (
    ParticipantModeSuiteEvidence,
    project_participant_mode_suite,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.journal import JournalError, replay
from edagym.run.model import (
    COMPARABLE_TRIAL_STOP_REASONS,
    RunRecord,
    StopReason,
)
from edagym.specs.common import (
    Digest,
    Identifier,
    JcsNonNegativeInt,
    SchemaVersion,
    Seed128Hex,
    StrictModel,
)
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import (
    FlowReleaseCandidateQualification,
    FlowReleaseQualification,
    ReleaseManifest,
    TaskInstance,
)
from edagym.specs.session import SessionSpec
from edagym.specs.task import FlowQualificationSpec, TaskSpec
from edagym.task_families.catalog import PublicTaskCatalog, TaskRoot

_LOCAL_CONTAINMENT_RUNTIME_COMMANDS = frozenset({"env", "systemctl", "systemd-run"})


class ReleaseDecision(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


class DurableExecutorEvidence(StrictModel):
    """Derived availability of the trusted local process boundary."""

    capability_digest: Digest
    available_runtime_commands: tuple[Identifier, ...]
    control_plane_probe_digest: Digest | None = None
    unavailable: ProviderUnavailableReason | None = None
    status: ReleaseEvidenceStatus

    @field_validator("available_runtime_commands")
    @classmethod
    def normalize_runtime_commands(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("durable executor runtime identities must be unique")
        if not set(value) <= _LOCAL_CONTAINMENT_RUNTIME_COMMANDS:
            raise ValueError("durable executor evidence contains an unknown supervisor")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.status is ReleaseEvidenceStatus.PASSED:
            if (
                set(self.available_runtime_commands) != _LOCAL_CONTAINMENT_RUNTIME_COMMANDS
                or self.control_plane_probe_digest is None
                or self.unavailable is not None
            ):
                raise ValueError(
                    "available durable execution requires every supervisor and user manager"
                )
        elif self.status is ReleaseEvidenceStatus.UNAVAILABLE:
            if self.control_plane_probe_digest is not None or self.unavailable is None:
                raise ValueError("unavailable durable execution requires only a typed reason")
        else:
            raise ValueError("durable executor prerequisites are availability evidence")
        return self


class FlowRunRole(StrEnum):
    WITNESS = "witness"
    NEGATIVE = "negative"


class FlowRunEvidence(StrictModel):
    resource_id: Identifier
    role: FlowRunRole
    record_digest: Digest
    status: ReleaseEvidenceStatus


class FlowReleaseEvidence(StrictModel):
    family: Identifier
    public_metadata_digest: Digest
    catalog_attestation_digest: Digest
    family_attestation_digest: Digest
    instance_reference_digest: Digest
    task_spec_digest: Digest
    task_instance_digest: Digest
    release_digest: Digest
    qualification_digest: Digest
    runs: Annotated[tuple[FlowRunEvidence, ...], Field(min_length=1)]
    counts: EvidenceCounts
    status: ReleaseEvidenceStatus

    @field_validator("runs")
    @classmethod
    def normalize_runs(cls, value: tuple[FlowRunEvidence, ...]) -> tuple[FlowRunEvidence, ...]:
        resources = [item.resource_id for item in value]
        digests = [item.record_digest for item in value]
        if len(resources) != len(set(resources)) or len(digests) != len(set(digests)):
            raise ValueError("flow qualification runs require unique resources and records")
        if sum(item.role is FlowRunRole.WITNESS for item in value) != 1:
            raise ValueError("flow qualification requires exactly one witness run")
        return tuple(sorted(value, key=lambda item: (item.role.value, item.resource_id)))

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        expected = _counts(item.status for item in self.runs)
        if self.counts != expected:
            raise ValueError("flow counts must be derived from qualification runs")
        if self.status is not _status_for_counts(expected):
            raise ValueError("flow status must be derived from qualification runs")
        return self


class CampaignTaskBindingEvidence(StrictModel):
    """Public identity of one exact frozen task, environment, and harness binding."""

    task_release_digest: Digest
    binding_digest: Digest


class CampaignEvidence(StrictModel):
    campaign_digest: Digest
    campaign_scope: CampaignScope
    campaign_header_digest: Digest
    schedule_digest: Digest
    campaign_record_digest: Digest
    report_digest: Digest
    model_set_digest: Digest
    model_discovery_digest: Digest
    comparison_digest: Digest
    controlled_variables_digest: Digest
    provider_logical_id: Identifier
    provider_profile_digest: Digest
    provider_config_digest: Digest
    route_ids: tuple[Identifier, ...]
    route_canary_evidence_digests: tuple[Digest, ...]
    task_bindings: tuple[CampaignTaskBindingEvidence, ...]
    reasoning_efforts: tuple[str, ...]
    paired_trial_seeds: tuple[Seed128Hex, ...]
    covered_model_categories: tuple[ModelCategory, ...]
    uncovered_categories: tuple[UncoveredCategory, ...]
    positive_usage_trial_count: JcsNonNegativeInt
    unknown_usage_attempt_count: JcsNonNegativeInt
    service_tier_accounting: ServiceTierAccounting
    counts: EvidenceCounts
    budget_violation: bool
    end_to_end: EndToEndSmokeEvidence | None = None
    status: ReleaseEvidenceStatus

    @field_validator(
        "route_ids",
        "route_canary_evidence_digests",
        "reasoning_efforts",
        "paired_trial_seeds",
        "covered_model_categories",
    )
    @classmethod
    def normalize_routes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("campaign route identities must be unique")
        return tuple(sorted(value))

    @field_validator("task_bindings")
    @classmethod
    def normalize_task_bindings(
        cls,
        value: tuple[CampaignTaskBindingEvidence, ...],
    ) -> tuple[CampaignTaskBindingEvidence, ...]:
        releases = [item.task_release_digest for item in value]
        bindings = [item.binding_digest for item in value]
        if (
            not value
            or len(releases) != len(set(releases))
            or len(bindings) != len(set(bindings))
        ):
            raise ValueError("campaign task bindings must have unique immutable identities")
        return tuple(sorted(value, key=lambda item: item.task_release_digest))

    @field_validator("uncovered_categories")
    @classmethod
    def normalize_uncovered_categories(
        cls,
        value: tuple[UncoveredCategory, ...],
    ) -> tuple[UncoveredCategory, ...]:
        categories = [item.category for item in value]
        if len(categories) != len(set(categories)):
            raise ValueError("campaign model category exclusions must be unique")
        return tuple(sorted(value, key=lambda item: item.category.value))

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if not self.counts.total:
            raise ValueError("campaign evidence must contain at least one scheduled trial")
        if not self.route_ids or len(self.route_ids) != len(set(self.route_ids)):
            raise ValueError("campaign evidence requires unique model routes")
        if len(self.route_canary_evidence_digests) != len(self.route_ids):
            raise ValueError("campaign evidence requires one canary source per model route")
        expected_trial_count = (
            len(self.task_bindings)
            * len(self.route_ids)
            * len(self.reasoning_efforts)
            * len(self.paired_trial_seeds)
        )
        if self.counts.total != expected_trial_count:
            raise ValueError("campaign counts must match the selected scope and route set")
        covered = set(self.covered_model_categories) & REQUIRED_MODEL_CATEGORIES
        uncovered = {item.category for item in self.uncovered_categories}
        if covered & uncovered or covered | uncovered != REQUIRED_MODEL_CATEGORIES:
            raise ValueError("campaign model category evidence must be disjoint")
        if self.positive_usage_trial_count > self.counts.total:
            raise ValueError("positive campaign usage cannot exceed scheduled trials")
        if self.budget_violation and not self.counts.failed:
            raise ValueError("campaign budget violations require failed trial evidence")
        if self.status is not _status_for_counts(self.counts):
            raise ValueError("campaign status must be derived from its trial evidence")
        if self.status is ReleaseEvidenceStatus.PASSED and (
            self.positive_usage_trial_count != self.counts.total or self.unknown_usage_attempt_count
        ):
            raise ValueError("passing paid campaigns require complete positive usage evidence")
        if self.campaign_scope is not CampaignScope.END_TO_END_SMOKE and (
            self.end_to_end is not None
        ):
            raise ValueError("only the end-to-end smoke campaign may carry run evidence")
        return self


class RepositoryCoverageEvidence(StrictModel):
    scope: CoverageScope
    status: CoverageStatus


class RepositoryAuditEvidence(StrictModel):
    audit_digest: Digest
    snapshot: RepositorySnapshot
    mode: AuditMode
    audit_status: AuditStatus
    coverage: tuple[RepositoryCoverageEvidence, ...]
    complete_coverage_count: JcsNonNegativeInt
    incomplete_coverage_count: JcsNonNegativeInt
    finding_count: JcsNonNegativeInt
    issue_count: JcsNonNegativeInt
    status: ReleaseEvidenceStatus

    @field_validator("coverage")
    @classmethod
    def normalize_coverage(
        cls, value: tuple[RepositoryCoverageEvidence, ...]
    ) -> tuple[RepositoryCoverageEvidence, ...]:
        scopes = [item.scope for item in value]
        if len(scopes) != len(set(scopes)):
            raise ValueError("repository audit coverage scopes must be unique")
        return tuple(sorted(value, key=lambda item: item.scope.value))

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if self.mode is not AuditMode.RELEASE:
            raise ValueError("release readiness requires a release-mode repository audit")
        if {item.scope for item in self.coverage} != set(CoverageScope):
            raise ValueError("release audit must cover every repository surface")
        complete = sum(
            item.status
            in {
                CoverageStatus.COMPLETE,
                CoverageStatus.NOT_REQUIRED,
                CoverageStatus.NOT_USED,
            }
            for item in self.coverage
        )
        incomplete = sum(item.status is CoverageStatus.INCOMPLETE for item in self.coverage)
        if self.complete_coverage_count != complete or self.incomplete_coverage_count != incomplete:
            raise ValueError("repository coverage counts must be derived from every scope")
        expected = {
            AuditStatus.PASS: ReleaseEvidenceStatus.PASSED,
            AuditStatus.VIOLATION: ReleaseEvidenceStatus.FAILED,
            AuditStatus.ERROR: ReleaseEvidenceStatus.FAILED,
            AuditStatus.INCOMPLETE: ReleaseEvidenceStatus.UNAVAILABLE,
        }[self.audit_status]
        if self.status is not expected:
            raise ValueError("repository status must be derived from its audit")
        if self.audit_status is AuditStatus.PASS and (
            self.finding_count
            or self.issue_count
            or self.incomplete_coverage_count
            or any(item.status is CoverageStatus.NOT_REQUIRED for item in self.coverage)
            or not self.snapshot.is_clean
        ):
            raise ValueError("a passing repository audit cannot contain unresolved evidence")
        if any(
            item.status is CoverageStatus.NOT_USED and item.scope is not CoverageScope.GIT_LFS
            for item in self.coverage
        ):
            raise ValueError("only an unused Git LFS store may satisfy release coverage")
        return self


class ReleaseReport(StrictModel):
    """Deterministic release decision containing references, never raw evidence."""

    schema_version: SchemaVersion = 1
    public_task_catalog_digest: Digest
    flow_catalog_attestation_digest: Digest
    backend_catalog_digest: Digest
    authoring: AuthoringCatalogEvidence
    backends: Annotated[tuple[BackendQualificationEvidence, ...], Field(min_length=1)]
    backend_coverage: Annotated[tuple[BackendCapabilityCoverage, ...], Field(min_length=1)]
    flows: Annotated[tuple[FlowReleaseEvidence, ...], Field(min_length=1)]
    campaigns: Annotated[tuple[CampaignEvidence, ...], Field(min_length=1)]
    participant_modes: ParticipantModeSuiteEvidence
    repository: RepositoryAuditEvidence
    private_roots: PrivateRootAuditReport
    durable_executor: DurableExecutorEvidence
    commands: Annotated[tuple[ReleaseCommandEvidence, ...], Field(min_length=1)]
    source_counts: EvidenceCounts
    decision: ReleaseDecision

    @field_validator("backends")
    @classmethod
    def normalize_backends(
        cls, value: tuple[BackendQualificationEvidence, ...]
    ) -> tuple[BackendQualificationEvidence, ...]:
        tool_ids = [item.tool_id for item in value]
        digests = [item.qualification_digest for item in value]
        if len(tool_ids) != len(set(tool_ids)) or len(digests) != len(set(digests)):
            raise ValueError("backend qualification identities and references must be unique")
        return tuple(sorted(value, key=lambda item: (item.tool_id, item.qualification_digest)))

    @field_validator("backend_coverage")
    @classmethod
    def normalize_backend_coverage(
        cls, value: tuple[BackendCapabilityCoverage, ...]
    ) -> tuple[BackendCapabilityCoverage, ...]:
        capabilities = [item.capability for item in value]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("backend release coverage capabilities must be unique")
        return tuple(sorted(value, key=lambda item: item.capability.value))

    @field_validator("flows")
    @classmethod
    def normalize_flows(
        cls, value: tuple[FlowReleaseEvidence, ...]
    ) -> tuple[FlowReleaseEvidence, ...]:
        families = [item.family for item in value]
        task_digests = [item.task_spec_digest for item in value]
        release_digests = [item.release_digest for item in value]
        if (
            len(families) != len(set(families))
            or len(task_digests) != len(set(task_digests))
            or len(release_digests) != len(set(release_digests))
        ):
            raise ValueError("flow release references must be unique")
        return tuple(sorted(value, key=lambda item: item.family))

    @field_validator("campaigns")
    @classmethod
    def normalize_campaigns(
        cls, value: tuple[CampaignEvidence, ...]
    ) -> tuple[CampaignEvidence, ...]:
        campaigns = [item.campaign_digest for item in value]
        scopes = [item.campaign_scope for item in value]
        reports = [item.report_digest for item in value]
        records = [item.campaign_record_digest for item in value]
        if (
            len(campaigns) != len(set(campaigns))
            or len(scopes) != len(set(scopes))
            or len(reports) != len(set(reports))
            or len(records) != len(set(records))
        ):
            raise ValueError("campaign scopes and report references must be unique")
        return tuple(sorted(value, key=lambda item: item.campaign_scope.value))

    @field_validator("commands")
    @classmethod
    def normalize_commands(
        cls, value: tuple[ReleaseCommandEvidence, ...]
    ) -> tuple[ReleaseCommandEvidence, ...]:
        plans = [item.plan_digest for item in value]
        receipts = [item.receipt_digest for item in value]
        purposes = [item.purpose for item in value]
        if (
            len(plans) != len(set(plans))
            or len(receipts) != len(set(receipts))
            or len(purposes) != len(set(purposes))
        ):
            raise ValueError("release command plans, receipts, and purposes must be unique")
        return tuple(sorted(value, key=lambda item: item.purpose.value))

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.authoring.public_catalog_digest != self.public_task_catalog_digest:
            raise ValueError("authoring evidence targets a different public task catalog")
        expected_coverage = _backend_coverage(self.backends)
        if self.backend_coverage != expected_coverage:
            raise ValueError("backend release coverage must be derived from qualifications")
        if len(self.flows) != 12:
            raise ValueError("release report requires exactly twelve flow families")
        if any(
            item.catalog_attestation_digest != self.flow_catalog_attestation_digest
            for item in self.flows
        ):
            raise ValueError("flow evidence targets a different sealed catalog attestation")
        if {item.purpose for item in self.commands} != set(ReleaseCommandPurpose):
            raise ValueError("release report requires every release command purpose")
        if len({item.artifact_policy_digest for item in self.commands}) != 1:
            raise ValueError("release command evidence must share one artifact policy")
        repository_digest = self.repository.snapshot.digest
        if self.private_roots.repository_snapshot_digest != repository_digest:
            raise ValueError("private-root audit targets a different repository snapshot")
        installation = next(
            item
            for item in self.commands
            if item.purpose is ReleaseCommandPurpose.CLEAN_INSTALLATION
        )
        for command in self.commands:
            if command.repository_identity_digest != repository_digest:
                raise ValueError("release command evidence targets a different repository")
            if command.purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT:
                if command.input_subject_digest != self.public_task_catalog_digest:
                    raise ValueError("authoring contract evidence targets a different catalog")
                if (
                    command.status is ReleaseEvidenceStatus.PASSED
                    and command.verified_public_catalog_digest
                    != self.public_task_catalog_digest
                ):
                    raise ValueError(
                        "authoring contract verified a different public catalog"
                    )
            elif command.input_subject_digest != repository_digest:
                raise ValueError("release command evidence targets a different input subject")
            if release_command_requires_installation(command.purpose):
                if command.installation_receipt_digest != installation.receipt_digest:
                    raise ValueError(
                        "release command evidence targets a different installation"
                    )
            elif command.installation_receipt_digest is not None:
                raise ValueError(
                    "release command evidence has an unexpected installation prerequisite"
                )
        statuses = (
            self.authoring.status,
            _status_for_counts(_counts(item.status for item in self.backend_coverage)),
            _status_for_counts(_counts(item.status for item in self.flows)),
            _campaign_suite_status(self.campaigns),
            self.participant_modes.status,
            self.repository.status,
            _private_root_status(self.private_roots.status),
            self.durable_executor.status,
            _status_for_counts(_counts(item.status for item in self.commands)),
        )
        expected_counts = _counts(statuses)
        if self.source_counts != expected_counts:
            raise ValueError("release source counts must be derived from every source")
        if self.decision is not _decision_for_counts(expected_counts):
            raise ValueError("release decision must be derived from source evidence")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="release-report-v1")


def build_release_report(
    *,
    public_task_catalog: PublicTaskCatalog,
    sail_catalog_attestation: SealedCatalogAttestation,
    sail_task_documents: tuple[DerivedTaskDocument, ...],
    sail_qualification_responses: tuple[QualificationProviderResponse, ...],
    backend_catalog: BackendCatalog,
    backend_sources: VerifiedBackendQualificationSources,
    flow_catalog: FlowTaskCatalog,
    flow_catalog_attestation: SealedCatalogAttestation,
    flow_task_documents: tuple[DerivedTaskDocument, ...],
    flow_environments: tuple[EnvironmentSpec, ...],
    flow_qualification_responses: tuple[QualificationProviderResponse, ...],
    flow_run_records: tuple[RunRecord, ...],
    flow_artifact_stores: Mapping[Digest, ContentAddressedStore],
    campaign_records: tuple[CampaignRecord, ...],
    campaign_reports: tuple[CampaignReport, ...],
    model_discovery_snapshots: tuple[ModelDiscoverySnapshot, ...],
    route_canary_evidence: tuple[RouteCanaryEvidence, ...],
    campaign_run_records: tuple[RunRecord, ...],
    campaign_trial_results: tuple[CampaignTrialResult, ...],
    campaign_task_instances: tuple[TaskInstance, ...],
    campaign_sessions: tuple[SessionSpec, ...],
    campaign_environments: tuple[EnvironmentSpec, ...],
    repository_audit: AuditReport,
    local_containment: LocalContainmentCapability,
    command_receipts: tuple[VerifiedReleaseCommandReceipt, ...],
    repository_root: Path,
    sail_catalog_root: Path,
    flow_catalog_root: Path,
    authoring_provider_registration: PrivateRootRegistration,
    campaign_artifact_stores: Mapping[Digest, ContentAddressedStore] | None = None,
    participant_run_records: tuple[RunRecord, ...] = (),
    participant_task_specs: tuple[TaskSpec, ...] = (),
    participant_task_instances: tuple[TaskInstance, ...] = (),
    participant_releases: tuple[ReleaseManifest, ...] = (),
    participant_environments: tuple[EnvironmentSpec, ...] = (),
    participant_sessions: tuple[SessionSpec, ...] = (),
    participant_artifact_stores: Mapping[Digest, ContentAddressedStore] | None = None,
) -> ReleaseReport:
    """Project immutable source facts into one digest-bound readiness report."""

    if type(backend_sources) is not VerifiedBackendQualificationSources:
        raise TypeError("release backends require the live verified source registry")
    backend_qualification_sources = backend_sources.sources

    authoring = project_authoring_catalog(
        public_task_catalog,
        sail_catalog_attestation,
        sail_task_documents,
        sail_qualification_responses,
    )
    backend_definitions = {item.tool_id: item for item in backend_catalog.backends}
    source_by_pair = {
        (
            item.qualification.probe.tool_id,
            item.qualification.requested_capabilities[0],
        ): item
        for item in backend_qualification_sources
    }
    expected_pairs = {
        (definition.tool_id, capability)
        for definition in backend_catalog.backends
        for capability in definition.capabilities
    }
    if (
        len(source_by_pair) != len(backend_qualification_sources)
        or set(source_by_pair) != expected_pairs
    ):
        raise ValueError("backend sources must exactly cover every catalog capability")
    backends = tuple(
        _backend_evidence(
            tuple(source_by_pair[(tool_id, capability)] for capability in definition.capabilities),
            definition,
        )
        for tool_id, definition in backend_definitions.items()
    )
    backend_coverage = _backend_coverage(backends)
    flows = _flow_evidence(
        public_task_catalog,
        flow_catalog,
        flow_catalog_attestation,
        flow_task_documents,
        flow_environments,
        flow_qualification_responses,
        flow_run_records,
        flow_artifact_stores,
    )
    commands = tuple(project_release_command(item) for item in command_receipts)
    campaign_stores = (
        {} if campaign_artifact_stores is None else campaign_artifact_stores
    )
    campaigns = _campaign_evidence(
        campaign_records,
        campaign_reports,
        model_discovery_snapshots,
        route_canary_evidence,
        campaign_run_records,
        campaign_trial_results,
        campaign_sessions,
        campaign_environments,
        tuple(
            {
                item.task.digest: item.task
                for item in (*sail_task_documents, *flow_task_documents)
            }.values()
        ),
        (
            *(item.instance for item in sail_task_documents),
            *(item.instance for item in flow_task_documents),
            *campaign_task_instances,
        ),
        (
            *(item.release for item in sail_qualification_responses),
            *(item.release for item in flow_qualification_responses),
        ),
        backend_qualification_sources,
        campaign_stores,
    )
    participant_stores = (
        {} if participant_artifact_stores is None else participant_artifact_stores
    )
    participant_modes = project_participant_mode_suite(
        run_records=participant_run_records,
        task_specs=participant_task_specs,
        task_instances=participant_task_instances,
        releases=participant_releases,
        environments=participant_environments,
        sessions=participant_sessions,
        artifact_stores=participant_stores,
    )
    repository = _repository_evidence(repository_audit)
    private_roots = project_release_private_root_audit(
        repository=repository_root,
        repository_audit=repository_audit,
        public_catalog=public_task_catalog,
        sail_materialized_catalog_root=sail_catalog_root,
        sail_catalog_attestation=sail_catalog_attestation,
        flow_materialized_catalog_root=flow_catalog_root,
        flow_catalog_attestation=flow_catalog_attestation,
        authoring_provider_registration=authoring_provider_registration,
        backend_sources=backend_sources,
        command_receipts=command_receipts,
        flow_artifact_stores=flow_artifact_stores,
        campaign_artifact_stores=campaign_stores,
        participant_artifact_stores=participant_stores,
    )
    durable_executor = _durable_executor_evidence(local_containment)
    statuses = (
        authoring.status,
        _status_for_counts(_counts(item.status for item in backend_coverage)),
        _status_for_counts(_counts(item.status for item in flows)),
        _campaign_suite_status(campaigns),
        participant_modes.status,
        repository.status,
        _private_root_status(private_roots.status),
        durable_executor.status,
        _status_for_counts(_counts(item.status for item in commands)),
    )
    counts = _counts(statuses)
    return ReleaseReport(
        public_task_catalog_digest=public_task_catalog.digest,
        flow_catalog_attestation_digest=flow_catalog_attestation.digest,
        backend_catalog_digest=backend_catalog.digest,
        authoring=authoring,
        backends=backends,
        backend_coverage=backend_coverage,
        flows=flows,
        campaigns=campaigns,
        participant_modes=participant_modes,
        repository=repository,
        private_roots=private_roots,
        durable_executor=durable_executor,
        commands=commands,
        source_counts=counts,
        decision=_decision_for_counts(counts),
    )


def _unique_task_specs_by_digest(task_specs: tuple[TaskSpec, ...]) -> dict[str, TaskSpec]:
    by_digest = {item.digest: item for item in task_specs}
    if len(by_digest) != len(task_specs):
        raise ValueError("campaign TaskSpecs must have unique content identities")
    return by_digest


def _unique_by_digest[T: TaskInstance | ReleaseManifest](
    values: tuple[T, ...],
    label: str,
) -> dict[str, T]:
    by_digest = {item.digest: item for item in values}
    if len(by_digest) != len(values):
        raise ValueError(f"{label} must have unique content identities")
    return by_digest


def _flow_evidence(
    public_catalog: PublicTaskCatalog,
    catalog: FlowTaskCatalog,
    catalog_attestation: SealedCatalogAttestation,
    task_documents: tuple[DerivedTaskDocument, ...],
    environments: tuple[EnvironmentSpec, ...],
    qualification_responses: tuple[QualificationProviderResponse, ...],
    records: tuple[RunRecord, ...],
    artifact_stores: Mapping[Digest, ContentAddressedStore],
) -> tuple[FlowReleaseEvidence, ...]:
    flow_families = {
        item.family: item
        for item in public_catalog.families
        if item.root is TaskRoot.EDA_FLOW
    }
    if (
        len(flow_families) != 12
        or catalog.public_catalog_digest != public_catalog.digest
        or catalog.attestation != catalog_attestation
        or set(catalog.families) != set(flow_families)
        or catalog_attestation.capability
        is not PrivateAuthoringCapability.EDA_FLOW_CATALOG
        or catalog_attestation.public_catalog_digest != public_catalog.digest
    ):
        raise ValueError("flow sources do not bind the complete public task catalog")
    family_attestations = {
        item.family: item for item in catalog_attestation.families
    }
    if (
        len(family_attestations) != len(catalog_attestation.families)
        or set(family_attestations) != set(flow_families)
    ):
        raise ValueError("sealed flow attestation must exactly cover public flow metadata")
    documents: dict[str, DerivedTaskDocument] = {}
    for document in task_documents:
        reference = document.instance_reference
        if (
            reference.capability is not PrivateAuthoringCapability.EDA_FLOW_CATALOG
            or reference.instance_name != "base"
            or reference.family in documents
        ):
            raise ValueError("flow release sources require one base document per family")
        documents[reference.family] = document
    if set(documents) != set(flow_families):
        raise ValueError("flow task documents must exactly cover public flow metadata")
    environment_map = {item.digest: item for item in environments}
    if len(environment_map) != len(environments):
        raise ValueError("flow environments must have unique content identities")
    response_by_reference = {
        item.instance_reference_digest: item for item in qualification_responses
    }
    expected_references = {
        document.instance_reference.digest for document in documents.values()
    }
    if (
        len(response_by_reference) != len(qualification_responses)
        or set(response_by_reference) != expected_references
    ):
        raise ValueError("flow qualification responses must exactly cover derived instances")
    releases = tuple(item.release for item in qualification_responses)
    if set(artifact_stores) != {item.digest for item in releases}:
        raise ValueError("flow qualification requires one exact live CAS per release")
    required_environments = {
        digest for release in releases for digest in release.environment_digests
    }
    if set(environment_map) != required_environments:
        raise ValueError("flow EnvironmentSpecs must exactly cover release qualification")
    by_digest: dict[str, RunRecord] = {}
    for supplied_record in records:
        if supplied_record.integrity_digest in by_digest:
            raise ValueError("flow qualification record digests must be unique")
        by_digest[supplied_record.integrity_digest] = supplied_record
    consumed: set[str] = set()
    claimed: set[str] = set()
    summaries: list[FlowReleaseEvidence] = []
    for family, metadata in flow_families.items():
        document = documents[family]
        task = document.task
        instance = document.instance
        reference = document.instance_reference
        family_attestation = family_attestations[family]
        response = response_by_reference[reference.digest]
        release = response.release
        qualification = release.qualification
        if not isinstance(qualification, FlowReleaseQualification):
            raise ValueError("flow evidence requires a release-qualified flow manifest")
        if not isinstance(task.qualification, FlowQualificationSpec):
            raise ValueError("flow TaskSpec requires flow qualification semantics")
        evaluator_capabilities = {
            evaluator.capability for evaluator in task.evaluation.evaluators
        }
        matching_instance_evidence = tuple(
            item
            for item in family_attestation.instances
            if item.instance_reference_digest == reference.digest
            and item.instance_reference_id == reference.reference_id
        )
        if len(matching_instance_evidence) != 1:
            raise ValueError("flow document lacks one exact sealed instance qualification")
        instance_evidence = matching_instance_evidence[0]
        expected_witness_id = task.qualification.feasibility_witness_resource
        expected_negative_ids = set(task.qualification.negative_candidate_resources)
        if (
            family_attestation.public_metadata_digest != metadata.digest
            or family_attestation.task_spec_digest != task.digest
            or response.descriptor.digest
            != catalog_attestation.provider_descriptor_digest
            or response.descriptor.implementation_digest
            != catalog_attestation.provider_implementation_digest
            or response.descriptor.security_qualification_digest
            != catalog_attestation.provider_security_qualification_digest
            or response.descriptor.public_catalog_digest != public_catalog.digest
            or response.instance_reference_digest != reference.digest
            or response.qualification != instance_evidence
            or reference.public_metadata_digest != metadata.digest
            or reference.family != family
            or task.identity.family != family
            or instance.identity.task_family != family
            or instance.identity.task_spec_digest != task.digest
            or not set(metadata.required_capabilities).issubset(evaluator_capabilities)
            or release.task_spec_digest != task.digest
            or release.task_instance_digest != instance.digest
            or release.files != instance.generated_files
            or release.participant_bundle_digest != reference.participant_bundle_digest
            or release.verifier_bundle_digest != reference.verifier_bundle_digest
            or instance_evidence.family != family
            or instance_evidence.instance_name != "base"
            or instance_evidence.task_spec_digest != task.digest
            or instance_evidence.task_instance_digest != instance.digest
            or instance_evidence.release_digest != release.digest
            or instance_evidence.participant_bundle_digest
            != release.participant_bundle_digest
            or instance_evidence.verifier_bundle_digest != release.verifier_bundle_digest
            or instance_evidence.release_qualification_digest != qualification.digest
            or qualification.witness_resource_id != expected_witness_id
            or {item.candidate_resource_id for item in qualification.negative_results}
            != expected_negative_ids
            or len(release.environment_digests) != 1
        ):
            raise ValueError("flow release diverges from its sealed public authoring sources")
        environment_digest = release.environment_digests[0]
        inventory_by_resource = {
            item.candidate_resource_id: item
            for item in family_attestation.flow_candidate_inventory
        }
        evidence_by_resource = {
            qualification.witness_resource_id: qualification.witness_evidence_digest,
            **{
                item.candidate_resource_id: item.evidence_digest
                for item in qualification.negative_results
            },
        }
        try:
            candidate_records = {
                inventory_by_resource[resource_id].candidate_id: by_digest[evidence_digest]
                for resource_id, evidence_digest in evidence_by_resource.items()
            }
            joined_attestations = join_flow_candidate_attestations(
                catalog,
                family,
                environment_map[environment_digest],
                release,
                candidate_records,
                artifact_stores[release.digest],
            )
        except (KeyError, RuntimeError, ValueError) as error:
            raise ValueError("flow qualification failed live catalog and CAS replay") from error
        candidate_attestations = {
            item.candidate_resource_id: item
            for item in joined_attestations
        }
        expected_candidate_ids = {expected_witness_id, *expected_negative_ids}
        if (
            len(candidate_attestations) != len(expected_candidate_ids)
            or set(candidate_attestations) != expected_candidate_ids
            or set(inventory_by_resource) != expected_candidate_ids
            or any(
                item.environment_spec_digest != environment_digest
                for item in joined_attestations
            )
            or any(
                item.candidate_id != inventory_by_resource[resource_id].candidate_id
                or item.role is not inventory_by_resource[resource_id].role
                or item.content_manifest_digest
                != inventory_by_resource[resource_id].content_manifest_digest
                for resource_id, item in candidate_attestations.items()
            )
        ):
            raise ValueError("flow release lacks exact environment-bound candidate attestations")
        resources = {item.resource_id: item for item in task.resources}
        if any(
            resources.get(resource_id) is None
            or resources[resource_id].content_digest
            != candidate_attestations[resource_id].content_manifest_digest
            for resource_id in expected_candidate_ids
        ):
            raise ValueError("flow candidate attestations differ from TaskSpec content identities")
        authoring_source = next(
            item
            for item in task.resources
            if item.resource_id == task.qualification.authoring_source_resource
        )
        release_candidate = release.model_copy(
            update={
                "qualification": FlowReleaseCandidateQualification(
                    authoring_source_digest=authoring_source.content_digest,
                )
            }
        )
        expected = (
            (
                qualification.witness_resource_id,
                FlowRunRole.WITNESS,
                qualification.witness_evidence_digest,
                candidate_attestations[qualification.witness_resource_id],
            ),
            *(
                (
                    item.candidate_resource_id,
                    FlowRunRole.NEGATIVE,
                    item.evidence_digest,
                    candidate_attestations[item.candidate_resource_id],
                )
                for item in qualification.negative_results
            ),
        )
        expected_digests = [item[2] for item in expected]
        if len(expected_digests) != len(set(expected_digests)):
            raise ValueError("flow release qualification record digests must be unique")
        if claimed & set(expected_digests):
            raise ValueError("a flow qualification record cannot support multiple releases")
        claimed.update(expected_digests)
        run_summaries: list[FlowRunEvidence] = []
        for resource_id, role, digest, candidate_attestation in expected:
            expected_role = (
                FlowCandidateRole.FEASIBILITY_WITNESS
                if role is FlowRunRole.WITNESS
                else FlowCandidateRole.SEMANTIC_NEGATIVE
            )
            if (
                candidate_attestation.role is not expected_role
                or candidate_attestation.qualification_evidence_digest != digest
            ):
                raise ValueError("flow release qualification differs from candidate attestation")
            qualification_record = by_digest.get(digest)
            if qualification_record is None:
                status = ReleaseEvidenceStatus.UNAVAILABLE
            else:
                consumed.add(digest)
                status = _flow_record_status(
                    qualification_record,
                    task,
                    release,
                    release_candidate.digest,
                    candidate_attestation,
                    role,
                )
            run_summaries.append(
                FlowRunEvidence(
                    resource_id=resource_id,
                    role=role,
                    record_digest=digest,
                    status=status,
                )
            )
        counts = _counts(item.status for item in run_summaries)
        summaries.append(
            FlowReleaseEvidence(
                family=family,
                public_metadata_digest=metadata.digest,
                catalog_attestation_digest=catalog_attestation.digest,
                family_attestation_digest=family_attestation.digest,
                instance_reference_digest=reference.digest,
                task_spec_digest=release.task_spec_digest,
                task_instance_digest=release.task_instance_digest,
                release_digest=release.digest,
                qualification_digest=qualification.digest,
                runs=tuple(run_summaries),
                counts=counts,
                status=_status_for_counts(counts),
            )
        )
    if set(by_digest) != consumed:
        raise ValueError("flow run evidence contains records not referenced by a release")
    return tuple(summaries)


def _flow_record_status(
    record: RunRecord,
    task: TaskSpec,
    release: ReleaseManifest,
    release_candidate_digest: Digest,
    candidate: FlowCandidateAttestation,
    role: FlowRunRole,
) -> ReleaseEvidenceStatus:
    binding = record.header.binding
    if (
        binding.task.task_spec_digest != release.task_spec_digest
        or binding.task.instance_digest != release.task_instance_digest
        or binding.task.release_digest != release_candidate_digest
        or binding.environment.environment_spec_digest != candidate.environment_spec_digest
        or candidate.environment_spec_digest not in release.environment_digests
    ):
        return ReleaseEvidenceStatus.FAILED
    try:
        state = replay(record.header, task, record.events)
    except (JournalError, ValueError):
        return ReleaseEvidenceStatus.FAILED
    if (
        len(state.candidates) != 1
        or state.candidates[0].candidate_id != candidate.candidate_id
        or state.candidates[0].digest != candidate.expected_candidate_manifest_digest
    ):
        return ReleaseEvidenceStatus.FAILED
    results = tuple(
        item.result for item in state.stage_results if item.candidate_id == candidate.candidate_id
    )
    gate = hard_gate_status(task, results)
    outcomes = {item.outcome.kind for item in results}
    if role is FlowRunRole.WITNESS:
        passed = (
            gate.state is HardGateState.SUCCEEDED
            and state.terminal_reason is StopReason.VERIFIER_SUCCESS
            and state.successful_candidate_id == candidate.candidate_id
            and {item.stage_id for item in results}
            == {item.stage_id for item in task.evaluation.stages}
            and not outcomes - {OutcomeKind.PASSED, OutcomeKind.PROVED}
        )
    else:
        infrastructure = {
            OutcomeKind.INFRASTRUCTURE_FAILURE,
            OutcomeKind.LICENSE_UNAVAILABLE,
            OutcomeKind.SECURITY_VIOLATION,
            OutcomeKind.TIMEOUT,
            OutcomeKind.UNKNOWN,
        }
        passed = (
            gate.state is HardGateState.FAILED
            and not outcomes & infrastructure
            and bool(outcomes & {OutcomeKind.CANDIDATE_FAILURE, OutcomeKind.COUNTEREXAMPLE})
            and state.terminal_reason is StopReason.UNRANKABLE
            and state.successful_candidate_id is None
        )
    return ReleaseEvidenceStatus.PASSED if passed else ReleaseEvidenceStatus.FAILED


def _campaign_evidence(
    records: tuple[CampaignRecord, ...],
    reports: tuple[CampaignReport, ...],
    model_discovery_snapshots: tuple[ModelDiscoverySnapshot, ...],
    route_canary_evidence: tuple[RouteCanaryEvidence, ...],
    run_records: tuple[RunRecord, ...],
    trial_results: tuple[CampaignTrialResult, ...],
    sessions: tuple[SessionSpec, ...],
    environments: tuple[EnvironmentSpec, ...],
    task_specs: tuple[TaskSpec, ...],
    task_instances: tuple[TaskInstance, ...],
    releases: tuple[ReleaseManifest, ...],
    backend_qualification_sources: tuple[VerifiedBackendQualificationSource, ...],
    artifact_stores: Mapping[Digest, ContentAddressedStore],
) -> tuple[CampaignEvidence, ...]:
    by_campaign = {item.campaign_digest: item for item in reports}
    if len(by_campaign) != len(reports) or len(records) != len(reports):
        raise ValueError("campaign release sources require unique paired records and reports")
    canaries = {item.digest: item for item in route_canary_evidence}
    if len(canaries) != len(route_canary_evidence):
        raise ValueError("route canary evidence identities must be unique")
    discoveries = {item.digest: item for item in model_discovery_snapshots}
    if len(discoveries) != len(model_discovery_snapshots):
        raise ValueError("model discovery evidence identities must be unique")
    if run_records:
        if (
            len(run_records) != 3
            or len(trial_results) != 3
            or not 1 <= len(sessions) <= 3
            or not 1 <= len(environments) <= 3
        ):
            raise ValueError("release evidence requires all three end-to-end trial bundles")
    elif trial_results or sessions or environments:
        raise ValueError("partial end-to-end source bundles are invalid")
    tasks_by_digest = _unique_task_specs_by_digest(task_specs)
    instances_by_digest = _unique_by_digest(task_instances, "campaign task instances")
    releases_by_digest = _unique_by_digest(releases, "campaign release manifests")
    consumed_canaries: set[str] = set()
    consumed_discoveries: set[str] = set()
    summaries: list[CampaignEvidence] = []
    consumed: set[str] = set()
    for record in records:
        campaign = record.header.campaign
        if campaign.digest in consumed:
            raise ValueError("campaign records must have unique CampaignSpec identities")
        consumed.add(campaign.digest)
        report = by_campaign.get(campaign.digest)
        if report is None:
            raise ValueError("campaign record has no corresponding aggregate report")
        projected = project_campaign_report(record)
        if report != projected:
            raise ValueError("campaign report is not the projection of its durable record")
        statuses: list[ReleaseEvidenceStatus] = []
        positive_usage = 0
        for trial in report.trials:
            has_positive_usage = any(
                attempt.disposition is AttemptDisposition.COMPLETED
                and attempt.provider_usage is not None
                and attempt.provider_usage.total_tokens > 0
                for attempt in trial.provider_attempts
            )
            if has_positive_usage:
                positive_usage += 1
            if (
                trial.accounting_violation
                or trial.outcome.disposition is TrialDisposition.FAILED_BEFORE_RUN
                or any(item.provider_usage is None for item in trial.provider_attempts)
            ):
                statuses.append(ReleaseEvidenceStatus.FAILED)
            elif trial.outcome.disposition is TrialDisposition.NOT_DISPATCHED:
                statuses.append(ReleaseEvidenceStatus.UNAVAILABLE)
            elif (
                trial.outcome.terminal_reason not in COMPARABLE_TRIAL_STOP_REASONS
                or not has_positive_usage
            ):
                statuses.append(ReleaseEvidenceStatus.FAILED)
            else:
                statuses.append(ReleaseEvidenceStatus.PASSED)
        counts = _counts(statuses)
        model_set = record.header.model_set
        discovery_digest = _model_discovery_source(
            record.header.provider_config,
            model_set,
            discoveries,
        )
        consumed_discoveries.add(discovery_digest)
        campaign_canaries = _route_canary_sources(model_set, canaries)
        consumed_canaries.update(campaign_canaries)
        end_to_end = None
        if campaign.scope is CampaignScope.END_TO_END_SMOKE and run_records:
            try:
                smoke_tasks = tuple(
                    tasks_by_digest[item.header.binding.task.task_spec_digest]
                    for item in run_records
                )
                smoke_instances = tuple(
                    instances_by_digest[item.header.binding.task.instance_digest]
                    for item in run_records
                )
                smoke_releases = tuple(
                    releases_by_digest[item.header.binding.task.release_digest]
                    for item in run_records
                )
            except KeyError as error:
                raise ValueError(
                    "end-to-end run references an unavailable specification"
                ) from error
            end_to_end = project_end_to_end_smoke(
                campaign_record=record,
                campaign_report=report,
                trial_results=trial_results,
                run_records=run_records,
                task_specs=smoke_tasks,
                task_instances=smoke_instances,
                releases=smoke_releases,
                environments=environments,
                sessions=sessions,
                backend_qualification_sources=backend_qualification_sources,
                artifact_stores=artifact_stores,
            )
        summaries.append(
            CampaignEvidence(
                campaign_digest=campaign.digest,
                campaign_scope=campaign.scope,
                campaign_header_digest=record.header.digest,
                schedule_digest=report.schedule_digest,
                campaign_record_digest=record.integrity_digest,
                report_digest=report.digest,
                model_set_digest=model_set.digest,
                model_discovery_digest=discovery_digest,
                comparison_digest=_campaign_comparison_digest(record.header),
                controlled_variables_digest=_campaign_controlled_variables_digest(
                    record.header
                ),
                provider_logical_id=record.header.provider_config.profile.logical_id,
                provider_profile_digest=record.header.provider_config.profile.digest,
                provider_config_digest=record.header.provider_config.digest,
                route_ids=campaign.route_ids,
                route_canary_evidence_digests=campaign_canaries,
                task_bindings=tuple(
                    CampaignTaskBindingEvidence(
                        task_release_digest=task.task_release_digest,
                        binding_digest=_campaign_task_binding_digest(task),
                    )
                    for task in record.header.tasks
                ),
                reasoning_efforts=campaign.reasoning_efforts,
                paired_trial_seeds=campaign.paired_trial_seeds,
                covered_model_categories=tuple(
                    {category for route in model_set.routes for category in route.categories}
                ),
                uncovered_categories=model_set.uncovered_categories,
                positive_usage_trial_count=positive_usage,
                unknown_usage_attempt_count=report.token_accounting.unknown_usage_attempts,
                service_tier_accounting=report.service_tier_accounting,
                counts=counts,
                budget_violation=report.budget_violation,
                end_to_end=end_to_end,
                status=_status_for_counts(counts),
            )
        )
    if set(by_campaign) != consumed:
        raise ValueError("campaign report has no corresponding durable record")
    consumed_end_to_end = any(item.end_to_end is not None for item in summaries)
    if bool(run_records) != consumed_end_to_end:
        raise ValueError("end-to-end source bundle does not identify one smoke campaign")
    if not run_records and artifact_stores:
        raise ValueError("artifact stores require end-to-end run records")
    if set(canaries) != consumed_canaries:
        raise ValueError("route canary evidence contains unreferenced sources")
    if set(discoveries) != consumed_discoveries:
        raise ValueError("model discovery evidence contains unreferenced sources")
    return tuple(summaries)


def _model_discovery_source(
    provider: ResolvedProviderConfig,
    model_set: ModelSetManifest,
    discoveries: Mapping[str, ModelDiscoverySnapshot],
) -> Digest:
    discovery = discoveries.get(model_set.discovery_digest)
    selected_models = {
        *(route.requested_model for route in model_set.routes),
        *(route.requested_model for route in model_set.exclusions),
    }
    if (
        discovery is None
        or discovery.digest != model_set.discovery_digest
        or discovery.provider_profile_digest != provider.profile.digest
        or discovery.provider_config_digest != provider.digest
        or discovery.provider_config_digest != model_set.provider_config_digest
        or discovery.selected_provider_label != provider.selected_provider_label
        or not selected_models <= set(discovery.model_labels)
    ):
        raise ValueError("model set does not match its exact discovery source")
    return discovery.digest


def _route_canary_sources(
    model_set: ModelSetManifest,
    canaries: Mapping[str, RouteCanaryEvidence],
) -> tuple[Digest, ...]:
    digests: list[str] = []
    for route in model_set.routes:
        digest = route.qualification.canary_evidence_digest
        canary = canaries.get(digest)
        if (
            canary is None
            or canary.digest != digest
            or canary.requested_model != route.requested_model
            or canary.provider_reported_model != route.provider_reported_model
            or canary.reasoning_control is not route.qualification.reasoning_control
            or canary.tool_schema_digest
            != route.qualification.canary_tool_schema_digest
            or canary.observed_input_token_floor
            != route.qualification.observed_input_token_floor
            or canary.service_tier_requested != route.qualification.requested_service_tier
            or canary.provider_reported_service_tier
            != route.qualification.provider_reported_service_tier
        ):
            raise ValueError("model route qualification does not match its paid canary source")
        digests.append(digest)
    return tuple(digests)


def _campaign_comparison_digest(header: CampaignHeader) -> Digest:
    campaign = header.campaign
    return canonical_digest(
        {
            **_campaign_controlled_variables(header),
            "tasks": header.tasks,
            "reasoning_efforts": campaign.reasoning_efforts,
        },
        domain="release-campaign-comparison-v1",
    )


def _campaign_controlled_variables_digest(header: CampaignHeader) -> Digest:
    return canonical_digest(
        _campaign_controlled_variables(header),
        domain="release-campaign-controlled-variables-v1",
    )


def _campaign_controlled_variables(header: CampaignHeader) -> dict[str, object]:
    campaign = header.campaign
    token_limits = campaign.token_limits
    execution_limits = campaign.execution_limits
    routes = {item.route_id: item for item in header.model_set.routes}
    return {
        "model_set_digest": campaign.model_set_digest,
        "routes": tuple(routes[route_id] for route_id in campaign.route_ids),
        "prompt_digest": campaign.prompt_digest,
        "tool_schema_digest": campaign.tool_schema_digest,
        "feedback_policy_digest": campaign.feedback_policy_digest,
        "service_tier": campaign.service_tier,
        "task_order_seed": campaign.task_order_seed,
        "retry_policy": campaign.retry_policy,
        "token_limits": {
            "max_requests_per_trial": token_limits.max_requests_per_trial,
            "max_input_tokens_per_request": token_limits.max_input_tokens_per_request,
            "max_output_tokens_per_request": token_limits.max_output_tokens_per_request,
            "max_input_tokens_per_trial": token_limits.max_input_tokens_per_trial,
            "max_output_tokens_per_trial": token_limits.max_output_tokens_per_trial,
            "max_total_tokens_per_trial": token_limits.max_total_tokens_per_trial,
        },
        "execution_limits": {
            "max_turns_per_trial": execution_limits.max_turns_per_trial,
            "max_tool_calls_per_trial": execution_limits.max_tool_calls_per_trial,
            "max_wall_seconds_per_trial": execution_limits.max_wall_seconds_per_trial,
            "max_eda_compute_seconds_per_trial": (
                execution_limits.max_eda_compute_seconds_per_trial
            ),
            "max_license_seconds_per_trial": execution_limits.max_license_seconds_per_trial,
            "max_artifact_bytes_per_trial": execution_limits.max_artifact_bytes_per_trial,
        },
        "stop_policy": campaign.stop_policy,
    }


def _campaign_task_binding_digest(task: CampaignTask) -> Digest:
    return canonical_digest(task, domain="release-campaign-task-binding-v1")


def _campaign_suite_status(
    campaigns: tuple[CampaignEvidence, ...],
) -> ReleaseEvidenceStatus:
    required_scopes = {
        CampaignScope.END_TO_END_SMOKE,
        CampaignScope.MODEL_COMPARISON_PILOT,
        CampaignScope.COMMON_CORE,
        CampaignScope.REASONING_EFFORT_SENSITIVITY,
    }
    by_scope = {item.campaign_scope: item for item in campaigns}
    if not required_scopes.issubset(by_scope):
        return ReleaseEvidenceStatus.UNAVAILABLE
    required = tuple(by_scope[scope] for scope in required_scopes)
    if any(item.status is ReleaseEvidenceStatus.FAILED for item in required):
        return ReleaseEvidenceStatus.FAILED
    if any(item.status is ReleaseEvidenceStatus.UNAVAILABLE for item in required):
        return ReleaseEvidenceStatus.UNAVAILABLE
    smoke = by_scope[CampaignScope.END_TO_END_SMOKE].end_to_end
    if smoke is None:
        return ReleaseEvidenceStatus.UNAVAILABLE
    if smoke.status is ReleaseEvidenceStatus.FAILED:
        return ReleaseEvidenceStatus.FAILED
    if smoke.status is ReleaseEvidenceStatus.UNAVAILABLE:
        return ReleaseEvidenceStatus.UNAVAILABLE
    pilot = by_scope[CampaignScope.MODEL_COMPARISON_PILOT]
    common_core = by_scope[CampaignScope.COMMON_CORE]
    sensitivity = by_scope[CampaignScope.REASONING_EFFORT_SENSITIVITY]
    paired = (pilot, common_core)
    compared = (*paired, sensitivity)
    pilot_tasks = {
        item.task_release_digest: item.binding_digest for item in pilot.task_bindings
    }
    common_tasks = {
        item.task_release_digest: item.binding_digest for item in common_core.task_bindings
    }
    sensitivity_tasks = {
        item.task_release_digest: item.binding_digest for item in sensitivity.task_bindings
    }
    if (
        len({item.comparison_digest for item in paired}) != 1
        or len({item.controlled_variables_digest for item in compared}) != 1
        or len({item.model_set_digest for item in compared}) != 1
        or len({item.model_discovery_digest for item in compared}) != 1
        or len({item.provider_profile_digest for item in compared}) != 1
        or len({item.provider_config_digest for item in compared}) != 1
        or pilot.route_ids != common_core.route_ids
        or not set(sensitivity.route_ids).issubset(pilot.route_ids)
        or pilot_tasks != common_tasks
        or not sensitivity_tasks.items() <= common_tasks.items()
        or pilot.paired_trial_seeds != sensitivity.paired_trial_seeds
        or not set(pilot.paired_trial_seeds).issubset(common_core.paired_trial_seeds)
        or not set(common_core.reasoning_efforts).issubset(sensitivity.reasoning_efforts)
        or any(item.provider_profile_digest != RUST_CAT_PROFILE.digest for item in required)
        or any(item.provider_logical_id != RUST_CAT_PROFILE.logical_id for item in required)
    ):
        return ReleaseEvidenceStatus.FAILED
    return ReleaseEvidenceStatus.PASSED


def _repository_evidence(report: AuditReport) -> RepositoryAuditEvidence:
    if report.snapshot is None:
        raise ValueError("release repository audit has no committed snapshot identity")
    complete = sum(
        item.status
        in {
            CoverageStatus.COMPLETE,
            CoverageStatus.NOT_REQUIRED,
            CoverageStatus.NOT_USED,
        }
        for item in report.coverage
    )
    incomplete = sum(item.status is CoverageStatus.INCOMPLETE for item in report.coverage)
    status = {
        AuditStatus.PASS: ReleaseEvidenceStatus.PASSED,
        AuditStatus.VIOLATION: ReleaseEvidenceStatus.FAILED,
        AuditStatus.ERROR: ReleaseEvidenceStatus.FAILED,
        AuditStatus.INCOMPLETE: ReleaseEvidenceStatus.UNAVAILABLE,
    }[report.status]
    return RepositoryAuditEvidence(
        audit_digest=report.digest,
        snapshot=report.snapshot,
        mode=report.mode,
        audit_status=report.status,
        coverage=tuple(
            RepositoryCoverageEvidence(scope=item.scope, status=item.status)
            for item in report.coverage
        ),
        complete_coverage_count=complete,
        incomplete_coverage_count=incomplete,
        finding_count=len(report.findings),
        issue_count=len(report.issues),
        status=status,
    )


def _durable_executor_evidence(
    capability: LocalContainmentCapability,
) -> DurableExecutorEvidence:
    status = (
        ReleaseEvidenceStatus.PASSED
        if capability.availability is ProviderAvailability.AVAILABLE
        else ReleaseEvidenceStatus.UNAVAILABLE
    )
    return DurableExecutorEvidence(
        capability_digest=capability.digest,
        available_runtime_commands=tuple(item.command for item in capability.runtimes),
        control_plane_probe_digest=capability.control_plane_probe_digest,
        unavailable=capability.reason,
        status=status,
    )


def _private_root_status(status: PrivateRootAuditStatus) -> ReleaseEvidenceStatus:
    return {
        PrivateRootAuditStatus.PASS: ReleaseEvidenceStatus.PASSED,
        PrivateRootAuditStatus.VIOLATION: ReleaseEvidenceStatus.FAILED,
        PrivateRootAuditStatus.INCOMPLETE: ReleaseEvidenceStatus.UNAVAILABLE,
    }[status]


def _decision_for_counts(counts: EvidenceCounts) -> ReleaseDecision:
    if counts.failed:
        return ReleaseDecision.BLOCKED
    if counts.unavailable:
        return ReleaseDecision.INCOMPLETE
    return ReleaseDecision.READY
