"""Canonical identities and outcome projections for evaluator executions."""

from __future__ import annotations

from edagym.canonical import canonical_digest
from edagym.evaluation.model import (
    CandidateFailureOutcome,
    InfrastructureFailureOutcome,
    LicenseUnavailableOutcome,
    SecurityViolationOutcome,
    StageOutcome,
    TimeoutOutcome,
    UnknownOutcome,
)
from edagym.executors.model import (
    ExecutionFailureKind,
    JobState,
)
from edagym.executors.model import (
    JobStateKind as ExecutorJobStateKind,
)
from edagym.run.trial_model import JobStateKind


def evaluation_job_id(run_id: str, candidate_id: str, stage_id: str) -> str:
    digest = canonical_digest(
        {"run_id": run_id, "candidate_id": candidate_id, "stage_id": stage_id},
        domain="evaluation-job-id-v1",
    )
    return f"job_{digest.removeprefix('sha256:')}"


def execution_artifact_id(run_id: str, job_id: str, local_id: str) -> str:
    digest = canonical_digest(
        {"run_id": run_id, "job_id": job_id, "local_id": local_id},
        domain="execution-artifact-id-v1",
    )
    return f"artifact_{digest.removeprefix('sha256:')}"


def run_job_state(state: JobState) -> JobStateKind:
    if state.state is ExecutorJobStateKind.COMPLETED:
        return JobStateKind.COMPLETED
    if state.state is ExecutorJobStateKind.CANCELLED:
        return JobStateKind.CANCELLED
    return JobStateKind.FAILED


def execution_failure_outcome(state: JobState) -> StageOutcome:
    if state.failure is ExecutionFailureKind.CANDIDATE:
        return CandidateFailureOutcome()
    if state.failure is ExecutionFailureKind.LICENSE_UNAVAILABLE:
        return LicenseUnavailableOutcome()
    if state.failure is ExecutionFailureKind.SECURITY_VIOLATION:
        return SecurityViolationOutcome()
    if state.failure is ExecutionFailureKind.TIMEOUT:
        return TimeoutOutcome()
    if state.failure is ExecutionFailureKind.CANCELLED:
        return UnknownOutcome()
    return InfrastructureFailureOutcome()
