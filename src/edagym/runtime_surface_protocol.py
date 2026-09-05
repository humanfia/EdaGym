"""Neutral identities shared by runtime-surface issuers and collectors."""

from __future__ import annotations

from enum import StrEnum

from edagym.canonical import canonical_digest
from edagym.specs.common import Digest, StrictModel


class IsolationSurface(StrEnum):
    PARTICIPANT_WORKSPACE = "participant_workspace"
    TOOL_PROCESS = "tool_process"
    EDA_PROCESS = "eda_process"
    VERIFIER = "verifier"
    CONSOLE = "console"
    JOURNAL = "journal"
    ARTIFACT_STORE = "artifact_store"
    PARTICIPANT_EXPORT = "participant_export"


REQUIRED_ISOLATION_SURFACES: tuple[IsolationSurface, ...] = tuple(IsolationSurface)
CANARY_ENVIRONMENT_NAME = "EDAGYM_SYNTHETIC_CANARY"


class RuntimeSurfaceBinding(StrictModel):
    """Frozen portable semantics shared by a preflight and one paid trial."""

    campaign_digest: Digest
    campaign_schedule_digest: Digest
    scheduled_trial_digest: Digest
    provider_profile_digest: Digest
    provider_config_digest: Digest
    budget_binding_digest: Digest
    task_release_digest: Digest
    environment_spec_digest: Digest
    session_spec_digest: Digest
    harness_digest: Digest
    harness_schema_digest: Digest
    executor_digest: Digest
    export_policy_digest: Digest

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="runtime-surface-binding-v1")
