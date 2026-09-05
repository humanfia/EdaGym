"""Canonical-document CLI boundary for provider campaign operations."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, RootModel, ValidationError

from edagym.canonical import canonical_bytes
from edagym.cli_support.documents import open_artifact_store
from edagym.providers.campaign import CampaignSpec, DateStamp, ModelSetManifest
from edagym.providers.campaign_budget import (
    CampaignAccountingError,
    CampaignBudgetProjection,
)
from edagym.providers.campaign_operation import (
    CampaignOperationRefusal,
    CampaignOperationRefusalReason,
    CampaignOperationRequest,
    CampaignOperationResult,
    FrozenCampaignProposal,
    execute_campaign_operation,
    open_rootless_campaign_host,
    prepare_campaign_trials,
)
from edagym.providers.campaign_reporting import project_campaign_report
from edagym.providers.campaign_runner import (
    CampaignRecord,
    CampaignReport,
)
from edagym.providers.campaign_schedule import (
    CampaignHeader,
    CampaignTask,
    build_campaign_schedule,
)
from edagym.providers.model import ProviderProfile, ResolvedProviderConfig
from edagym.providers.model_discovery import (
    ModelDiscoveryResult,
    ModelDiscoverySnapshot,
    ModelRouteCandidate,
    ModelRouteOutcome,
    ModelSetFreezeResult,
    ModelSetUnavailable,
    declare_explicit_model_candidates,
    discover_provider_models,
    freeze_model_set,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.security.credentials import (
    CodexCredentialSource,
    CredentialFormatError,
    CredentialSecurityError,
)
from edagym.specs.common import Digest, Identifier, SchemaVersion, StrictModel

_UNSATISFIED = 1
_INCOMPLETE = 3
_MAX_CAMPAIGN_REQUEST_BYTES = 64 << 20


class CampaignCliCommand(StrEnum):
    INSPECT = "inspect"
    DISCOVER = "discover"
    FREEZE = "freeze"
    RUN = "run"
    RESUME = "resume"
    REPORT = "report"


class CampaignCliFailureReason(StrEnum):
    INVALID_REQUEST = "invalid_request"
    PROVIDER_CONFIG_UNAVAILABLE = "provider_config_unavailable"
    MODEL_DISCOVERY_REJECTED = "model_discovery_rejected"
    MODEL_SET_REJECTED = "model_set_rejected"
    CAMPAIGN_REPORT_INCOMPLETE = "campaign_report_incomplete"


class CampaignCliFailure(StrictModel):
    """Portable, secret-free command failure."""

    schema_version: SchemaVersion = 1
    command: CampaignCliCommand
    reason: CampaignCliFailureReason | CampaignOperationRefusalReason
    trial_id: Identifier | None = None


class ProviderInspectRequest(StrictModel):
    schema_version: SchemaVersion = 1
    command: Literal[CampaignCliCommand.INSPECT] = CampaignCliCommand.INSPECT
    trusted_profile: ProviderProfile


class ProviderDiscoverRequest(StrictModel):
    schema_version: SchemaVersion = 1
    command: Literal[CampaignCliCommand.DISCOVER] = CampaignCliCommand.DISCOVER
    configuration: ResolvedProviderConfig
    explicit_candidates: tuple[ModelRouteCandidate, ...] | None = None


class ModelSetFreezeRequest(StrictModel):
    schema_version: SchemaVersion = 1
    command: Literal[CampaignCliCommand.FREEZE] = CampaignCliCommand.FREEZE
    freeze_kind: Literal["model_set"] = "model_set"
    configuration: ResolvedProviderConfig
    discovery: ModelDiscoverySnapshot
    candidates: tuple[ModelRouteCandidate, ...]
    outcomes: tuple[ModelRouteOutcome, ...]
    resolved_on: DateStamp


class CampaignBudgetFreezeRequest(StrictModel):
    schema_version: SchemaVersion = 1
    command: Literal[CampaignCliCommand.FREEZE] = CampaignCliCommand.FREEZE
    freeze_kind: Literal["campaign_budget"] = "campaign_budget"
    campaign: CampaignSpec
    model_set: ModelSetManifest
    provider_config: ResolvedProviderConfig
    tasks: tuple[CampaignTask, ...]


class CampaignFreezeRequest(
    RootModel[
        Annotated[
            ModelSetFreezeRequest | CampaignBudgetFreezeRequest,
            Field(discriminator="freeze_kind"),
        ]
    ]
):
    """Discriminated owner for the two immutable freeze operations."""


class CampaignRunRequest(CampaignOperationRequest):
    """Start the frozen campaign from an event-free durable journal."""

    command: Literal[CampaignCliCommand.RUN] = CampaignCliCommand.RUN


class CampaignResumeRequest(CampaignOperationRequest):
    """Continue a started campaign from its durable journal without re-dispatch."""

    command: Literal[CampaignCliCommand.RESUME] = CampaignCliCommand.RESUME


class CampaignReportRequest(StrictModel):
    schema_version: SchemaVersion = 1
    command: Literal[CampaignCliCommand.REPORT] = CampaignCliCommand.REPORT
    record: CampaignRecord


CampaignCliRequest = (
    ProviderInspectRequest
    | ProviderDiscoverRequest
    | CampaignFreezeRequest
    | CampaignRunRequest
    | CampaignResumeRequest
    | CampaignReportRequest
)

CampaignCliResult = (
    ResolvedProviderConfig
    | ModelDiscoveryResult
    | ModelSetFreezeResult
    | FrozenCampaignProposal
    | CampaignOperationResult
    | CampaignReport
    | CampaignCliFailure
)

_REQUEST_MODEL: dict[CampaignCliCommand, type[BaseModel]] = {
    CampaignCliCommand.INSPECT: ProviderInspectRequest,
    CampaignCliCommand.DISCOVER: ProviderDiscoverRequest,
    CampaignCliCommand.FREEZE: CampaignFreezeRequest,
    CampaignCliCommand.RUN: CampaignRunRequest,
    CampaignCliCommand.RESUME: CampaignResumeRequest,
    CampaignCliCommand.REPORT: CampaignReportRequest,
}


def execute_campaign_command(
    command: CampaignCliCommand,
    request_path: Path,
) -> tuple[CampaignCliResult, int]:
    """Validate one canonical request and invoke its sole semantic owner."""

    try:
        request = _load_request(request_path, _REQUEST_MODEL[command])
    except (OSError, ValueError, ValidationError):
        return _failure(command, CampaignCliFailureReason.INVALID_REQUEST), _UNSATISFIED

    if isinstance(request, ProviderInspectRequest):
        return _inspect(request)
    if isinstance(request, ProviderDiscoverRequest):
        return _discover(request)
    if isinstance(request, CampaignFreezeRequest):
        return _freeze(request.root)
    if isinstance(request, CampaignReportRequest):
        return _report(request)
    if isinstance(request, (CampaignRunRequest, CampaignResumeRequest)):
        return _operate(request)
    raise AssertionError("campaign request dispatch is incomplete")


def _load_request[TRequest: BaseModel](path: Path, model: type[TRequest]) -> TRequest:
    raw = path.read_bytes()
    if not raw or len(raw) > _MAX_CAMPAIGN_REQUEST_BYTES:
        raise ValueError("campaign request size is invalid")
    content = raw[:-1] if raw.endswith(b"\n") else raw
    request = model.model_validate_json(content)
    if canonical_bytes(request) != content:
        raise ValueError("campaign request is not canonically encoded")
    return request


def _inspect(request: ProviderInspectRequest) -> tuple[CampaignCliResult, int]:
    try:
        result = CodexCredentialSource(trusted_profile=request.trusted_profile).inspect_profile()
    except (CredentialFormatError, CredentialSecurityError):
        return (
            _failure(
                CampaignCliCommand.INSPECT,
                CampaignCliFailureReason.PROVIDER_CONFIG_UNAVAILABLE,
            ),
            _UNSATISFIED,
        )
    return result, 0


def _discover(request: ProviderDiscoverRequest) -> tuple[CampaignCliResult, int]:
    unavailable = discover_provider_models(request.configuration)
    if request.explicit_candidates is None:
        return unavailable, _UNSATISFIED
    try:
        discovery = declare_explicit_model_candidates(
            request.configuration,
            unavailable,
            request.explicit_candidates,
        )
    except ValueError:
        return (
            _failure(
                CampaignCliCommand.DISCOVER,
                CampaignCliFailureReason.MODEL_DISCOVERY_REJECTED,
            ),
            _UNSATISFIED,
        )
    return discovery, 0


def _freeze(
    request: ModelSetFreezeRequest | CampaignBudgetFreezeRequest,
) -> tuple[CampaignCliResult, int]:
    if isinstance(request, CampaignBudgetFreezeRequest):
        try:
            schedule = build_campaign_schedule(
                request.campaign,
                request.model_set,
                request.tasks,
            )
            header = CampaignHeader(
                campaign=request.campaign,
                model_set=request.model_set,
                provider_config=request.provider_config,
                tasks=request.tasks,
                schedule=schedule,
            )
            return (
                FrozenCampaignProposal(
                    header=header,
                    budget=CampaignBudgetProjection.from_campaign(
                        request.campaign,
                        schedule,
                    ),
                ),
                0,
            )
        except ValueError:
            return (
                _failure(
                    CampaignCliCommand.FREEZE,
                    CampaignCliFailureReason.MODEL_SET_REJECTED,
                ),
                _UNSATISFIED,
            )
    try:
        result = freeze_model_set(
            request.configuration,
            request.discovery,
            request.candidates,
            request.outcomes,
            resolved_on=request.resolved_on,
        )
    except ValueError:
        return (
            _failure(
                CampaignCliCommand.FREEZE,
                CampaignCliFailureReason.MODEL_SET_REJECTED,
            ),
            _UNSATISFIED,
        )
    return result, _UNSATISFIED if isinstance(result, ModelSetUnavailable) else 0


def _operate(
    request: CampaignRunRequest | CampaignResumeRequest,
) -> tuple[CampaignCliResult, int]:
    """Open the policy-bound stores, then hand every composition to the operation owner."""

    try:
        prepared = prepare_campaign_trials(
            request,
            artifact_stores=_campaign_artifact_stores(request),
        )
        with open_rootless_campaign_host(request) as host:
            result = execute_campaign_operation(
                request,
                prepared,
                resume=request.command is CampaignCliCommand.RESUME,
                host=host,
            )
    except CampaignOperationRefusal as refusal:
        return (
            CampaignCliFailure(
                command=request.command,
                reason=refusal.reason,
                trial_id=refusal.trial_id,
            ),
            _UNSATISFIED,
        )
    return result, 0


def _campaign_artifact_stores(
    request: CampaignOperationRequest,
) -> dict[Digest, ContentAddressedStore]:
    """One policy-bound store per environment beneath the requested artifact root."""

    root = Path(request.artifact_store_root)
    key_file = None if request.artifact_key_file is None else Path(request.artifact_key_file)
    return {
        environment.digest: open_artifact_store(
            root / environment.digest.removeprefix("sha256:"),
            environment,
            key_file,
        )
        for environment in request.environments
    }


def _report(request: CampaignReportRequest) -> tuple[CampaignCliResult, int]:
    try:
        return project_campaign_report(request.record), 0
    except CampaignAccountingError:
        return (
            _failure(
                CampaignCliCommand.REPORT,
                CampaignCliFailureReason.CAMPAIGN_REPORT_INCOMPLETE,
            ),
            _INCOMPLETE,
        )


def _failure(
    command: CampaignCliCommand,
    reason: CampaignCliFailureReason,
) -> CampaignCliFailure:
    return CampaignCliFailure(command=command, reason=reason)
