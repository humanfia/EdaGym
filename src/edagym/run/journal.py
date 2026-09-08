"""Crash-safe task-bound journal and deterministic state replay."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

from pydantic import ValidationError

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.evaluation.model import (
    HardGateState,
    ScorerEligibilityKind,
    StageEligibilityKind,
    StageResult,
)
from edagym.evaluation.promotion import (
    hard_gate_status,
    scorer_eligibility,
    stage_eligibility,
    validate_stage_results,
)
from edagym.evaluation.scoring import build_candidate_score, measurement_sample_seeds
from edagym.participant_tool_protocol import EXECUTOR_PARTICIPANT_TOOL_NAME
from edagym.run.artifact_model import (
    ArtifactRecord,
)
from edagym.run.artifacts import SANITIZED_MEASUREMENTS_MEDIA_TYPE
from edagym.run.model import (
    ArtifactRecordedEvent,
    CandidateScoringState,
    CandidateStageResult,
    CandidateState,
    CandidateSubmittedEvent,
    CheckpointCommittedEvent,
    ControlTransferredEvent,
    EvaluationCompletedEvent,
    EvaluationStartedEvent,
    HarnessRunActor,
    InteractionDirection,
    InteractionRecordedEvent,
    JobStateChangedEvent,
    JobStateKind,
    JobStateSnapshot,
    LicenseLeaseAcquiredEvent,
    LicenseLeaseDeniedEvent,
    LicenseLeaseLostEvent,
    LicenseLeaseReleasedEvent,
    ParticipantIncarnationBinding,
    ParticipantIncarnationLifecycle,
    ParticipantIncarnationRecovery,
    ParticipantIncarnationRestoredEvent,
    ParticipantIncarnationStartedEvent,
    ParticipantIncarnationTerminatedEvent,
    ParticipantIncarnationTermination,
    ParticipantToolDispatch,
    ParticipantToolLostEvent,
    ParticipantToolReservedEvent,
    ParticipantToolSettledEvent,
    ParticipantToolUsage,
    PolicyDecisionEvent,
    ProducerKind,
    ProviderRequestStartedEvent,
    ProviderRequestState,
    ProviderResponseRecordedEvent,
    ProviderSecurityBinding,
    RunCommit,
    RunEndedEvent,
    RunEvent,
    RunHeader,
    RunPurpose,
    RunRecord,
    RunStartedEvent,
    RunState,
    ScoringRecordedEvent,
    StopReason,
    run_journal_anchor,
)
from edagym.security.canary_artifact import (
    PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE,
    PROVIDER_TRANSCRIPT_MEDIA_TYPE,
    ProviderTranscriptRole,
    provider_transcript_artifact_id,
)
from edagym.specs.common import (
    ArtifactClass,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.task import TaskSpec

_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700


_TERMINAL_JOB_STATES = frozenset(
    {
        JobStateKind.COMPLETED,
        JobStateKind.FAILED,
        JobStateKind.CANCELLED,
    }
)
_JOB_TRANSITIONS = {
    JobStateKind.QUEUED: frozenset(
        {
            JobStateKind.RUNNING,
            JobStateKind.FAILED,
            JobStateKind.CANCELLED,
        }
    ),
    JobStateKind.RUNNING: frozenset(
        {
            JobStateKind.CHECKPOINTING,
            JobStateKind.COMPLETED,
            JobStateKind.FAILED,
            JobStateKind.CANCELLED,
        }
    ),
    JobStateKind.CHECKPOINTING: frozenset(
        {
            JobStateKind.RUNNING,
            JobStateKind.COMPLETED,
            JobStateKind.FAILED,
            JobStateKind.CANCELLED,
        }
    ),
    JobStateKind.COMPLETED: frozenset(),
    JobStateKind.FAILED: frozenset(),
    JobStateKind.CANCELLED: frozenset(),
}


class JournalError(RuntimeError):
    """Base class for journal integrity and transition failures."""


class JournalCorruption(JournalError):
    """A durable journal prefix is malformed or internally inconsistent."""


class EventConflict(JournalError):
    """An event conflicts with a previously committed fact."""


class InvalidTransition(JournalError):
    """An event is well-formed but invalid in the current run state."""


def unresolved_tool_requests(
    events: Sequence[RunEvent],
    *,
    tool_name: str | None = None,
) -> tuple[InteractionRecordedEvent, ...]:
    """Return journaled tool requests without a corresponding tool result."""

    resolved = {
        event.payload.related_interaction_id
        for event in events
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
    }
    return tuple(
        event
        for event in events
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_REQUEST
        and event.payload.interaction_id not in resolved
        and (tool_name is None or event.payload.tool_name == tool_name)
    )


def participant_tool_dispatches(
    events: Sequence[RunEvent],
) -> Mapping[str, ParticipantToolDispatch]:
    """Project participant executor lifecycles from a validated journal prefix."""

    reservations: dict[str, ParticipantToolReservedEvent] = {}
    terminals: dict[str, ParticipantToolSettledEvent | ParticipantToolLostEvent] = {}
    for event in events:
        if isinstance(event, ParticipantToolReservedEvent):
            request_id = event.payload.request_interaction_id
            if request_id in reservations:
                raise InvalidTransition("participant tool request is already reserved")
            reservations[request_id] = event
        elif isinstance(event, ParticipantToolSettledEvent | ParticipantToolLostEvent):
            request_id = event.payload.request_interaction_id
            if request_id not in reservations:
                raise InvalidTransition("participant tool terminal fact has no reservation")
            if request_id in terminals:
                raise InvalidTransition("participant tool reservation is already terminal")
            terminals[request_id] = event
    return MappingProxyType(
        {
            request_id: ParticipantToolDispatch(
                reservation=reservation,
                terminal=terminals.get(request_id),
            )
            for request_id, reservation in reservations.items()
        }
    )


def participant_tool_usage(events: Sequence[RunEvent]) -> ParticipantToolUsage:
    """Project settled usage or conservative reservations from tool lifecycle facts."""

    compute_milliseconds = 0
    license_milliseconds = 0
    for dispatch in participant_tool_dispatches(events).values():
        terminal = dispatch.terminal
        if isinstance(terminal, ParticipantToolSettledEvent):
            compute_milliseconds += terminal.payload.elapsed_milliseconds
            license_milliseconds += terminal.payload.license_milliseconds
        else:
            compute_milliseconds += dispatch.reservation.payload.reserved_compute_milliseconds
            license_milliseconds += dispatch.reservation.payload.reserved_license_milliseconds
    return ParticipantToolUsage(
        eda_compute_milliseconds=compute_milliseconds,
        license_milliseconds=license_milliseconds,
    )


def participant_incarnation_lifecycle(
    events: Sequence[RunEvent],
) -> ParticipantIncarnationLifecycle:
    """Project the journal-owned participant controller generation chain."""

    incarnations: list[ParticipantIncarnationBinding] = []
    initial_started_sequence: int | None = None
    recoveries: list[ParticipantIncarnationRecovery] = []
    active: ParticipantIncarnationBinding | None = None
    pending: ParticipantIncarnationTermination | None = None
    pending_sequence: int | None = None
    for event in events:
        if isinstance(event, ParticipantIncarnationStartedEvent):
            if incarnations or active is not None or pending is not None:
                raise InvalidTransition("participant incarnation is already started")
            if event.payload.incarnation.generation != 0:
                raise InvalidTransition("initial participant incarnation must be generation zero")
            active = event.payload.incarnation
            incarnations.append(active)
            initial_started_sequence = event.sequence
        elif isinstance(event, ParticipantIncarnationTerminatedEvent):
            if active is None or pending is not None:
                raise InvalidTransition("participant termination has no active incarnation")
            if event.payload.incarnation_digest != active.digest:
                raise InvalidTransition("participant termination names a stale incarnation")
            pending = ParticipantIncarnationTermination(**event.payload.model_dump(mode="python"))
            pending_sequence = event.sequence
            active = None
        elif isinstance(event, ParticipantIncarnationRestoredEvent):
            if (
                pending is None
                or pending_sequence is None
                or active is not None
                or not incarnations
            ):
                raise InvalidTransition("participant restore has no terminated incarnation")
            prior = incarnations[-1]
            payload = event.payload
            if (
                payload.predecessor_incarnation_digest != prior.digest
                or payload.predecessor_incarnation_digest != pending.incarnation_digest
                or payload.checkpoint_id != pending.checkpoint_id
                or payload.checkpoint_manifest_digest != pending.checkpoint_manifest_digest
                or payload.incarnation.generation != prior.generation + 1
                or payload.incarnation.process.digest == prior.process.digest
                or payload.incarnation.workspace_identity_digest
                == prior.workspace_identity_digest
                or payload.incarnation.artifact_directory_identity_digest
                == prior.artifact_directory_identity_digest
            ):
                raise InvalidTransition(
                    "participant restore differs from its terminated generation"
                )
            active = payload.incarnation
            incarnations.append(active)
            recoveries.append(
                ParticipantIncarnationRecovery(
                    termination=pending,
                    terminated_sequence=pending_sequence,
                    restored_sequence=event.sequence,
                    restored_incarnation_digest=active.digest,
                    restored_manifest_digest=payload.restored_manifest_digest,
                )
            )
            pending = None
            pending_sequence = None
    return ParticipantIncarnationLifecycle(
        incarnations=tuple(incarnations),
        initial_started_sequence=initial_started_sequence,
        recoveries=tuple(recoveries),
        active_incarnation=active,
        pending_termination=pending,
        pending_termination_sequence=pending_sequence,
    )


def active_license_leases(
    events: Sequence[RunEvent],
) -> Mapping[str, LicenseLeaseAcquiredEvent]:
    """Project acquisitions whose release or custody loss is not yet journaled."""

    active: dict[str, LicenseLeaseAcquiredEvent] = {}
    for event in events:
        if isinstance(event, LicenseLeaseAcquiredEvent):
            if event.payload.job_id in active:
                raise InvalidTransition("execution job already has an active license lease")
            active[event.payload.job_id] = event
        elif isinstance(event, LicenseLeaseReleasedEvent | LicenseLeaseLostEvent):
            if active.pop(event.payload.job_id, None) is None:
                raise InvalidTransition("license closure has no active acquisition")
    return MappingProxyType(active)


def replay(header: RunHeader, task: TaskSpec, events: Sequence[RunEvent]) -> RunState:
    """Reconstruct run state while rechecking task evaluation semantics."""

    if task.digest != header.binding.task.task_spec_digest:
        raise JournalCorruption("task identity does not match the run binding")
    _validate_task_binding(header, task)
    actor_ids = {actor.actor_id for actor in header.binding.session.actors}
    task_stage_ids = {stage.stage_id for stage in task.evaluation.stages}
    current_writer = header.binding.session.initial_writer
    harnesses = {
        actor.actor_id: actor
        for actor in header.binding.session.actors
        if isinstance(actor, HarnessRunActor)
    }
    event_ids: set[object] = set()
    interactions: dict[str, InteractionRecordedEvent] = {}
    resolved_tool_requests: set[str] = set()
    participant_tool_reservations: dict[str, ParticipantToolReservedEvent] = {}
    participant_tool_terminals: dict[
        str,
        ParticipantToolSettledEvent | ParticipantToolLostEvent,
    ] = {}
    provider_requests: dict[str, ProviderRequestState] = {}
    campaign_provider_security: tuple[
        str,
        str,
        ProviderSecurityBinding,
        str,
    ] | None = None
    candidates: dict[str, CandidateState] = {}
    results_by_candidate: dict[str, list[StageResult]] = {}
    stage_results: list[CandidateStageResult] = []
    scoring: dict[str, CandidateScoringState] = {}
    artifacts: dict[str, ArtifactRecord] = {}
    checkpoints: list[str] = []
    checkpoint_events: dict[str, CheckpointCommittedEvent] = {}
    active_jobs: dict[str, tuple[str, str]] = {}
    job_states: dict[str, JobStateKind] = {}
    license_decisions: set[str] = set()
    active_license_leases: dict[str, LicenseLeaseAcquiredEvent] = {}
    terminal_reason = None
    successful_candidate_id = None

    for expected_sequence, event in enumerate(events):
        if event.run_id != header.run_id:
            raise JournalCorruption("journal event belongs to another run")
        if event.sequence != expected_sequence:
            raise JournalCorruption("journal event sequence is not contiguous")
        if event.event_id in event_ids:
            raise JournalCorruption("journal contains a duplicate event identifier")
        event_ids.add(event.event_id)
        if terminal_reason is not None:
            raise JournalCorruption("journal contains an event after run termination")
        if event.actor is not None and event.actor not in actor_ids:
            raise InvalidTransition("event actor is not bound to this run")
        _validate_event_producer(event)
        _validate_artifact_references(event, artifacts)

        if expected_sequence == 0:
            if not isinstance(event, RunStartedEvent):
                raise JournalCorruption("the first journal event must start the run")
            if event.payload.binding_digest != header.binding.digest:
                raise JournalCorruption("run-started event has the wrong binding digest")
        elif isinstance(event, RunStartedEvent):
            raise JournalCorruption("a run may be started only once")

        lifecycle = participant_incarnation_lifecycle(events[:expected_sequence])
        requires_incarnation = header.binding.purpose is not RunPurpose.STANDARD
        if expected_sequence == 1 and requires_incarnation and not isinstance(
            event, ParticipantIncarnationStartedEvent
        ):
            raise InvalidTransition(
                "campaign and preflight runs require an initial participant incarnation"
            )
        if lifecycle.pending_termination is not None and not isinstance(
            event, ParticipantIncarnationRestoredEvent
        ):
            raise InvalidTransition("terminated participant incarnation must be restored first")

        if isinstance(event, ParticipantIncarnationStartedEvent):
            if expected_sequence != 1:
                raise InvalidTransition("participant incarnation may be started only after the run")
            participant_incarnation_lifecycle((*events[:expected_sequence], event))
        elif isinstance(event, ParticipantIncarnationTerminatedEvent):
            active = lifecycle.active_incarnation
            committed_checkpoint = checkpoint_events.get(event.payload.checkpoint_id)
            if active is None or event.payload.incarnation_digest != active.digest:
                raise InvalidTransition("participant termination names no active incarnation")
            if (
                committed_checkpoint is None
                or not checkpoints
                or event.payload.checkpoint_id != checkpoints[-1]
                or event.payload.checkpoint_manifest_digest
                != committed_checkpoint.payload.manifest_digest
            ):
                raise InvalidTransition(
                    "participant termination requires the latest committed checkpoint"
                )
            if (
                active_jobs
                or active_license_leases
                or any(request.status is None for request in provider_requests.values())
                or any(
                    interaction.payload.direction is InteractionDirection.TOOL_REQUEST
                    and interaction_id not in resolved_tool_requests
                    for interaction_id, interaction in interactions.items()
                )
                or set(participant_tool_reservations) != set(participant_tool_terminals)
            ):
                raise InvalidTransition("participant termination requires quiescent durable work")
            participant_incarnation_lifecycle((*events[:expected_sequence], event))
        elif isinstance(event, ParticipantIncarnationRestoredEvent):
            pending = lifecycle.pending_termination
            committed_checkpoint = checkpoint_events.get(event.payload.checkpoint_id)
            if (
                pending is None
                or committed_checkpoint is None
                or event.payload.checkpoint_manifest_digest
                != committed_checkpoint.payload.manifest_digest
            ):
                raise InvalidTransition("participant restore differs from its checkpoint")
            participant_incarnation_lifecycle((*events[:expected_sequence], event))
        elif isinstance(event, ProviderRequestStartedEvent):
            if header.binding.purpose is RunPurpose.SYNTHETIC_PREFLIGHT:
                raise InvalidTransition("synthetic preflight runs cannot dispatch a provider")
            started_payload = event.payload
            actor = harnesses.get(started_payload.actor_id)
            if actor is None:
                raise InvalidTransition("provider request actor is not a bound harness")
            if started_payload.actor_id != current_writer:
                raise InvalidTransition(
                    "provider request actor is not the current workspace writer"
                )
            if started_payload.requested_model != actor.requested_model_route:
                raise InvalidTransition("provider request model differs from its run binding")
            campaign = header.binding.campaign
            if campaign is not None and (
                started_payload.requested_service_tier != campaign.service_tier
            ):
                raise InvalidTransition(
                    "campaign provider requests require their paid security binding"
                )
            if campaign is not None:
                request_security = (
                    started_payload.provider_profile_digest,
                    started_payload.provider_config_digest,
                    started_payload.security_binding,
                    started_payload.security_evidence_artifact_id,
                )
                if (
                    campaign_provider_security is not None
                    and request_security != campaign_provider_security
                ):
                    raise InvalidTransition(
                        "campaign provider requests must share one security attestation"
                    )
                campaign_provider_security = request_security
            if started_payload.request_id in provider_requests:
                raise InvalidTransition("provider request identifier already exists")
            _validate_provider_transcript(event, artifacts)
            provider_requests[started_payload.request_id] = ProviderRequestState(
                request_id=started_payload.request_id,
                actor_id=started_payload.actor_id,
                request_artifact_id=started_payload.request_artifact_id,
                security_evidence_artifact_id=(
                    started_payload.security_evidence_artifact_id
                ),
                provider_profile_digest=started_payload.provider_profile_digest,
                provider_config_digest=started_payload.provider_config_digest,
                requested_model=started_payload.requested_model,
                requested_service_tier=started_payload.requested_service_tier,
                observed_input_token_floor=(
                    started_payload.observed_input_token_floor
                ),
                security_binding=started_payload.security_binding,
                reserved_input_tokens=started_payload.reserved_input_tokens,
                reserved_output_tokens=started_payload.reserved_output_tokens,
            )
        elif isinstance(event, ProviderResponseRecordedEvent):
            response = event.payload
            request_state = provider_requests.get(response.request_id)
            if request_state is None:
                raise InvalidTransition("provider response has no matching request")
            if request_state.status is not None:
                raise InvalidTransition("provider request already has a response")
            _validate_provider_transcript(event, artifacts)
            provider_requests[response.request_id] = request_state.model_copy(
                update={
                    "provider_reported_model": response.provider_reported_model,
                    "provider_reported_service_tier": (
                        response.provider_reported_service_tier
                    ),
                    "status": response.status,
                    "usage": response.usage,
                }
            )
        elif isinstance(event, InteractionRecordedEvent):
            interaction_id = event.payload.interaction_id
            if interaction_id in interactions:
                raise InvalidTransition("interaction identifier already exists")
            if event.producer is ProducerKind.PARTICIPANT and event.actor != current_writer:
                raise InvalidTransition(
                    "only the workspace writer may emit participant interaction"
                )
            related_id = event.payload.related_interaction_id
            if related_id is not None:
                related = interactions.get(related_id)
                if (
                    related is None
                    or related.payload.direction is not InteractionDirection.TOOL_REQUEST
                    or related.actor != current_writer
                    or related.payload.tool_name != event.payload.tool_name
                ):
                    raise InvalidTransition(
                        "tool result relation does not name the active writer request"
                    )
                if related_id in resolved_tool_requests:
                    raise InvalidTransition("tool request already has a result")
                if (
                    related.payload.tool_name == EXECUTOR_PARTICIPANT_TOOL_NAME
                    and related_id in participant_tool_reservations
                    and related_id not in participant_tool_terminals
                ):
                    raise InvalidTransition(
                        "participant executor result requires a terminal dispatch fact"
                    )
                resolved_tool_requests.add(related_id)
            interactions[interaction_id] = event
        elif isinstance(event, ParticipantToolReservedEvent):
            reservation = event.payload
            request = interactions.get(reservation.request_interaction_id)
            if (
                request is None
                or request.payload.direction is not InteractionDirection.TOOL_REQUEST
                or request.payload.tool_name != EXECUTOR_PARTICIPANT_TOOL_NAME
                or reservation.request_interaction_id in resolved_tool_requests
            ):
                raise InvalidTransition(
                    "participant tool reservation has no unresolved executor request"
                )
            if reservation.request_interaction_id in participant_tool_reservations:
                raise InvalidTransition("participant tool request is already reserved")
            if reservation.executor_id != header.binding.environment.executor_id:
                raise InvalidTransition("participant tool reservation has the wrong executor")
            if reservation.budget_digest != header.binding.session.budget_digest:
                raise InvalidTransition("participant tool reservation has the wrong budget")
            matching_operations = tuple(
                operation
                for operation in header.binding.environment.participant_operations
                if operation.operation_id == reservation.operation_id
                and operation.operation_digest == reservation.operation_digest
                and operation.tool_id == reservation.tool_id
                and operation.capability is reservation.capability
            )
            if len(matching_operations) != 1:
                raise InvalidTransition(
                    "participant tool reservation is not a run-resolved operation"
                )
            matching_tools = tuple(
                tool
                for tool in header.binding.environment.tools
                if tool.tool_id == reservation.tool_id
                and tool.capability is reservation.capability
            )
            if len(matching_tools) != 1:
                raise InvalidTransition("participant tool reservation is not run-resolved")
            participant_tool_reservations[reservation.request_interaction_id] = event
        elif isinstance(event, ParticipantToolSettledEvent | ParticipantToolLostEvent):
            terminal = event.payload
            reservation_event = participant_tool_reservations.get(
                terminal.request_interaction_id
            )
            if reservation_event is None:
                raise InvalidTransition("participant tool terminal fact has no reservation")
            if terminal.request_interaction_id in participant_tool_terminals:
                raise InvalidTransition("participant tool reservation is already terminal")
            reservation = reservation_event.payload
            if (
                terminal.request_interaction_id in resolved_tool_requests
                or terminal.invocation_id != reservation.invocation_id
                or terminal.invocation_digest != reservation.invocation_digest
            ):
                raise InvalidTransition(
                    "participant tool terminal fact differs from its reservation"
                )
            if event.timestamp < reservation_event.timestamp:
                raise InvalidTransition("participant tool terminal fact precedes its reservation")
            if terminal.invocation_id in active_license_leases:
                raise InvalidTransition(
                    "participant tool terminal fact requires closed license custody"
                )
            if isinstance(event, ParticipantToolSettledEvent):
                if (
                    event.payload.operation_id != reservation.operation_id
                    or event.payload.operation_digest != reservation.operation_digest
                    or event.payload.input_manifest_digest
                    != reservation.input_manifest_digest
                ):
                    raise InvalidTransition(
                        "participant tool settlement differs from its reserved operation"
                    )
                if (
                    event.payload.elapsed_milliseconds
                    > reservation.reserved_compute_milliseconds
                    or event.payload.license_milliseconds
                    > reservation.reserved_license_milliseconds
                ):
                    raise InvalidTransition(
                        "participant tool settlement exceeds its resource reservation"
                    )
                artifact = artifacts[event.payload.evidence_artifact_id]
                if artifact.artifact_class is not ArtifactClass.EVIDENCE:
                    raise InvalidTransition(
                        "participant tool settlement must reference execution evidence"
                    )
            participant_tool_terminals[terminal.request_interaction_id] = event
        elif isinstance(event, ControlTransferredEvent):
            if not header.binding.session.handoff_enabled:
                raise InvalidTransition("this run does not permit control handoff")
            if event.payload.previous_writer != current_writer:
                raise InvalidTransition("control transfer names a stale writer")
            if event.payload.next_writer not in actor_ids:
                raise InvalidTransition("control transfer targets an unknown actor")
            if event.actor != current_writer:
                raise InvalidTransition("control transfer must be attributed to the current writer")
            current_writer = event.payload.next_writer
        elif isinstance(event, CandidateSubmittedEvent):
            candidate_payload = event.payload
            if event.actor != current_writer:
                raise InvalidTransition(
                    "candidate submission requires the current workspace writer"
                )
            if candidate_payload.candidate_id in candidates:
                raise InvalidTransition("candidate identifier already exists")
            if (
                candidate_payload.parent_candidate_id is not None
                and candidate_payload.parent_candidate_id not in candidates
            ):
                raise InvalidTransition("candidate parent does not exist")
            candidates[candidate_payload.candidate_id] = CandidateState(
                candidate_id=candidate_payload.candidate_id,
                digest=candidate_payload.candidate_digest,
                parent_candidate_id=candidate_payload.parent_candidate_id,
                actor=current_writer,
            )
            results_by_candidate[candidate_payload.candidate_id] = []
        elif isinstance(event, EvaluationStartedEvent):
            started = event.payload
            if started.candidate_id not in candidates:
                raise InvalidTransition("evaluation references an unknown candidate")
            if started.candidate_id in scoring:
                raise InvalidTransition("a scored candidate cannot start another evaluation")
            if started.stage_id not in task_stage_ids:
                raise InvalidTransition("evaluation references an unknown task stage")
            if started.job_id in job_states:
                raise InvalidTransition("evaluation job identifier was already used")
            candidate_results = results_by_candidate[started.candidate_id]
            if any(result.stage_id == started.stage_id for result in candidate_results):
                raise InvalidTransition("candidate stage already has a terminal result")
            eligibility = stage_eligibility(task, candidate_results, started.stage_id)
            if eligibility.state is not StageEligibilityKind.READY:
                raise InvalidTransition("evaluation stage is not eligible to start")
            active_jobs[started.job_id] = (started.candidate_id, started.stage_id)
            job_states[started.job_id] = JobStateKind.QUEUED
        elif isinstance(event, JobStateChangedEvent):
            changed = event.payload
            previous = job_states.get(changed.job_id)
            if previous is None:
                raise InvalidTransition("job state event references an unknown job")
            if changed.state not in _JOB_TRANSITIONS[previous]:
                raise InvalidTransition("job state transition is not allowed")
            job_states[changed.job_id] = changed.state
        elif isinstance(event, EvaluationCompletedEvent):
            completed = event.payload
            expected = active_jobs.get(completed.job_id)
            if expected is None:
                raise InvalidTransition("evaluation completion has no matching active job")
            if expected != (completed.candidate_id, completed.result.stage_id):
                raise InvalidTransition("evaluation completion does not match the started job")
            if job_states[completed.job_id] not in _TERMINAL_JOB_STATES:
                raise InvalidTransition("evaluation completion requires a terminal executor job")
            evidence_ids = {evidence.artifact_id for evidence in completed.result.evidence}
            if not evidence_ids.issubset(set(event.artifact_refs)):
                raise InvalidTransition("evaluation evidence is not declared by its event")
            _validate_measurement_provenance(
                header,
                task,
                completed.result,
                artifacts,
            )
            candidate_results = results_by_candidate[completed.candidate_id]
            prospective_results = [*candidate_results, completed.result]
            validate_stage_results(task, prospective_results)
            candidate_results.append(completed.result)
            stage_results.append(
                CandidateStageResult(
                    candidate_id=completed.candidate_id,
                    result=completed.result,
                )
            )
            active_jobs.pop(completed.job_id)
        elif isinstance(event, ScoringRecordedEvent):
            candidate_id = event.payload.candidate_id
            if candidate_id not in candidates:
                raise InvalidTransition("scoring references an unknown candidate")
            if candidate_id in scoring:
                raise InvalidTransition("candidate scoring is already recorded")
            if any(candidate == candidate_id for candidate, _ in active_jobs.values()):
                raise InvalidTransition("candidate scoring requires settled evaluations")
            candidate_results = results_by_candidate[candidate_id]
            _validate_scoring_decision(
                header,
                task,
                candidate_results,
                event,
            )
            scoring[candidate_id] = CandidateScoringState(
                candidate_id=candidate_id,
                decision=event.payload.decision,
            )
        elif isinstance(event, LicenseLeaseAcquiredEvent | LicenseLeaseDeniedEvent):
            license_fact = event.payload
            participant_reservation = next(
                (
                    reserved
                    for reserved in participant_tool_reservations.values()
                    if reserved.payload.invocation_id == license_fact.job_id
                ),
                None,
            )
            evaluator_admitted = (
                job_states.get(license_fact.job_id) is JobStateKind.QUEUED
            )
            participant_admitted = (
                participant_reservation is not None
                and participant_reservation.payload.request_interaction_id
                not in participant_tool_terminals
                and participant_reservation.payload.license_binding_id
                == license_fact.license_binding_id
            )
            if not evaluator_admitted and not participant_admitted:
                raise InvalidTransition(
                    "license decisions require queued evaluation or participant work"
                )
            if license_fact.job_id in license_decisions:
                raise InvalidTransition("execution job already has a license decision")
            license_decisions.add(license_fact.job_id)
            if isinstance(event, LicenseLeaseAcquiredEvent):
                active_license_leases[license_fact.job_id] = event
        elif isinstance(event, LicenseLeaseReleasedEvent | LicenseLeaseLostEvent):
            released_fact = event.payload
            acquired = active_license_leases.get(released_fact.job_id)
            if acquired is None:
                raise InvalidTransition("license release has no active acquisition")
            acquired_fact = acquired.payload
            if (
                released_fact.license_binding_id != acquired_fact.license_binding_id
                or released_fact.provider_id != acquired_fact.provider_id
                or released_fact.feature_class != acquired_fact.feature_class
            ):
                raise InvalidTransition("license release differs from its acquisition")
            if event.timestamp < acquired.timestamp:
                raise InvalidTransition("license release precedes its acquisition")
            active_license_leases.pop(released_fact.job_id)
        elif isinstance(event, ArtifactRecordedEvent):
            record = event.payload.record
            if record.logical_id in artifacts:
                raise InvalidTransition("artifact logical identifier already exists")
            artifacts[record.logical_id] = record
        elif isinstance(event, CheckpointCommittedEvent):
            checkpoint = event.payload
            if checkpoint.checkpoint_id in checkpoints:
                raise InvalidTransition("checkpoint identifier already exists")
            if (
                checkpoint.parent_checkpoint_id is not None
                and checkpoint.parent_checkpoint_id not in checkpoints
            ):
                raise InvalidTransition("checkpoint parent does not exist")
            artifact = artifacts[event.artifact_refs[0]]
            if artifact.artifact_class is not ArtifactClass.CHECKPOINT:
                raise InvalidTransition("checkpoint event must reference a checkpoint artifact")
            checkpoints.append(checkpoint.checkpoint_id)
            checkpoint_events[checkpoint.checkpoint_id] = event
        elif isinstance(event, RunEndedEvent):
            lifecycle = participant_incarnation_lifecycle(events[:expected_sequence])
            if (
                header.binding.purpose is not RunPurpose.STANDARD
                and lifecycle.active_incarnation is None
            ):
                raise InvalidTransition(
                    "run termination requires an active participant incarnation"
                )
            if event.producer is ProducerKind.PARTICIPANT and event.actor != current_writer:
                raise InvalidTransition(
                    "participant termination requires the current workspace writer"
                )
            if active_jobs:
                raise InvalidTransition("run cannot end with active evaluations")
            if any(state not in _TERMINAL_JOB_STATES for state in job_states.values()):
                raise InvalidTransition("run cannot end with active executor jobs")
            if active_license_leases:
                raise InvalidTransition("run cannot end with active license leases")
            if any(request.status is None for request in provider_requests.values()):
                raise InvalidTransition("run cannot end with unsettled provider requests")
            if any(
                interaction.payload.direction is InteractionDirection.TOOL_REQUEST
                and interaction_id not in resolved_tool_requests
                for interaction_id, interaction in interactions.items()
            ):
                raise InvalidTransition("run cannot end with unresolved participant tools")
            if set(participant_tool_reservations) != set(participant_tool_terminals):
                raise InvalidTransition("run cannot end with active participant tool dispatches")
            if event.payload.reason is StopReason.VERIFIER_SUCCESS:
                success_candidate_id = event.payload.successful_candidate_id
                if success_candidate_id is None or success_candidate_id not in candidates:
                    raise InvalidTransition("verifier success names an unknown candidate")
                gate_status = hard_gate_status(task, results_by_candidate[success_candidate_id])
                if gate_status.state is not HardGateState.SUCCEEDED:
                    raise InvalidTransition("verifier success requires every hard gate to pass")
                if success_candidate_id not in scoring:
                    raise InvalidTransition("verifier success requires a scoring decision")
                scoring_eligibility = scoring[success_candidate_id].decision.eligibility.state
                if scoring_eligibility not in {
                    ScorerEligibilityKind.READY,
                    ScorerEligibilityKind.NOT_CONFIGURED,
                }:
                    raise InvalidTransition("verifier success requires rankable scoring")
                successful_candidate_id = success_candidate_id
            terminal_reason = event.payload.reason

    if (
        events
        and header.binding.purpose is not RunPurpose.STANDARD
        and not participant_incarnation_lifecycle(events).incarnations
    ):
        raise InvalidTransition(
            "campaign and preflight runs require a participant incarnation"
        )

    return RunState(
        run_id=header.run_id,
        next_sequence=len(events),
        current_writer=current_writer,
        candidates=tuple(candidates.values()),
        stage_results=tuple(stage_results),
        scoring=tuple(scoring.values()),
        artifacts=tuple(artifacts.values()),
        checkpoint_ids=tuple(checkpoints),
        interaction_ids=tuple(sorted(interactions)),
        provider_requests=tuple(provider_requests.values()),
        jobs=tuple(
            JobStateSnapshot(job_id=job_id, state=state)
            for job_id, state in sorted(job_states.items())
        ),
        terminal_reason=terminal_reason,
        successful_candidate_id=successful_candidate_id,
    )


def _validate_measurement_provenance(
    header: RunHeader,
    task: TaskSpec,
    result: StageResult,
    artifacts: dict[str, ArtifactRecord],
) -> None:
    if not result.measurements:
        return
    stages = {stage.stage_id: stage for stage in task.evaluation.stages}
    evaluators = {evaluator.evaluator_id: evaluator for evaluator in task.evaluation.evaluators}
    specifications = {measurement.measurement_id: measurement for measurement in task.measurements}
    stage = stages[result.stage_id]
    capability = evaluators[stage.evaluator_id].capability
    tool = next(
        binding for binding in header.binding.environment.tools if binding.capability is capability
    )
    asset_ids = {asset.asset_id for asset in header.binding.environment.assets}
    for measurement in result.measurements:
        provenance = measurement.provenance
        specification = specifications[measurement.measurement_id]
        if provenance is None:
            raise InvalidTransition("persisted measurements require complete provenance")
        source = artifacts.get(provenance.source_artifact_id)
        if source is None or source.blob.digest != provenance.source_digest:
            raise InvalidTransition("measurement source artifact is not registered or changed")
        if (
            source.artifact_class is not ArtifactClass.MEASUREMENT
            or source.media_type != SANITIZED_MEASUREMENTS_MEDIA_TYPE
        ):
            raise InvalidTransition(
                "measurement provenance must reference a sanitized measurement artifact"
            )
        if provenance.source_artifact_id not in {
            evidence.artifact_id for evidence in result.evidence
        }:
            raise InvalidTransition("measurement source is not declared as stage evidence")
        if (
            provenance.unit is not specification.unit
            or provenance.tool_id != tool.tool_id
            or provenance.tool_version != tool.tool_version
            or provenance.library_id != specification.library_id
            or provenance.library_digest != specification.library_digest
            or provenance.corner != specification.corner
            or provenance.mode != specification.mode
            or provenance.task_seed != header.binding.task.instance_seed
        ):
            raise InvalidTransition("measurement provenance differs from the run binding")
        if provenance.sample_seeds != measurement_sample_seeds(
            header.binding.task.instance_seed,
            specification.measurement_id,
            specification.repetitions,
        ):
            raise InvalidTransition("measurement sample seeds differ from the run binding")
        if provenance.library_id in asset_ids:
            asset = next(
                item
                for item in header.binding.environment.assets
                if item.asset_id == provenance.library_id
            )
            if asset.restricted_digest != provenance.library_digest:
                raise InvalidTransition("measurement library digest differs from its run asset")
        elif provenance.library_id != "not_applicable":
            matching_resources = {
                resource.content_digest
                for resource in task.resources
                if resource.resource_id == provenance.library_id
            }
            if provenance.library_digest not in matching_resources:
                raise InvalidTransition("measurement library is not a resolved run or task asset")


def _validate_task_binding(header: RunHeader, task: TaskSpec) -> None:
    task_binding = header.binding.task
    if (
        task_binding.family != task.identity.family
        or task_binding.authoring_revision != task.identity.authoring_revision
        or header.binding.measurement_schema_digest
        != canonical_digest(task.measurements, domain="measurement-schema-v1")
        or header.binding.scorer_revision_digest
        != (None if task.evaluation.scorer is None else task.evaluation.scorer.revision_digest)
    ):
        raise JournalCorruption("task-derived run binding facts have diverged")
    expected_evaluators = {
        evaluator.evaluator_id: evaluator.revision_digest
        for evaluator in task.evaluation.evaluators
    }
    bound_evaluators = {
        evaluator.evaluator_id: evaluator.revision_digest for evaluator in header.binding.evaluators
    }
    if bound_evaluators != expected_evaluators:
        raise JournalCorruption("evaluator run bindings differ from the task")


def _validate_scoring_decision(
    header: RunHeader,
    task: TaskSpec,
    results: Sequence[StageResult],
    event: ScoringRecordedEvent,
) -> None:
    expected_eligibility = scorer_eligibility(task, results)
    decision = event.payload.decision
    if decision.eligibility != expected_eligibility:
        raise InvalidTransition("scoring eligibility differs from evaluator facts")
    score = decision.score
    if score is None:
        return
    if hard_gate_status(task, results).state is not HardGateState.SUCCEEDED:
        raise InvalidTransition("a score requires every hard gate to pass")
    if score != build_candidate_score(task, results):
        raise InvalidTransition("score differs from task-bound derivation")
    if (
        task.evaluation.scorer is not None
        and task.evaluation.scorer.revision_digest != header.binding.scorer_revision_digest
    ):
        raise InvalidTransition("scalar score differs from its run binding")


def _validate_event_producer(event: RunEvent) -> None:
    if isinstance(
        event,
        (
            RunStartedEvent,
            ParticipantIncarnationStartedEvent,
            ParticipantIncarnationTerminatedEvent,
            ParticipantIncarnationRestoredEvent,
            ProviderRequestStartedEvent,
            ProviderResponseRecordedEvent,
            ParticipantToolReservedEvent,
            ParticipantToolSettledEvent,
            ParticipantToolLostEvent,
            LicenseLeaseAcquiredEvent,
            LicenseLeaseDeniedEvent,
            LicenseLeaseLostEvent,
            LicenseLeaseReleasedEvent,
        ),
    ):
        allowed = {ProducerKind.CONTROLLER}
    elif isinstance(event, (ControlTransferredEvent, CandidateSubmittedEvent)):
        allowed = {ProducerKind.PARTICIPANT}
    elif isinstance(event, RunEndedEvent):
        allowed = (
            {ProducerKind.CONTROLLER, ProducerKind.PARTICIPANT}
            if event.payload.reason is StopReason.VERIFIER_SUCCESS
            else {ProducerKind.CONTROLLER}
        )
    elif isinstance(event, InteractionRecordedEvent):
        allowed = {ProducerKind.PARTICIPANT, ProducerKind.CONTROLLER}
    elif isinstance(
        event,
        (EvaluationStartedEvent, EvaluationCompletedEvent, ScoringRecordedEvent),
    ):
        allowed = {ProducerKind.EVALUATOR}
    elif isinstance(event, ArtifactRecordedEvent | CheckpointCommittedEvent):
        allowed = {ProducerKind.CONTROLLER}
    elif isinstance(event, JobStateChangedEvent):
        allowed = {ProducerKind.EXECUTOR}
    elif isinstance(event, PolicyDecisionEvent):
        allowed = {ProducerKind.POLICY}
    else:
        raise InvalidTransition("event kind has no producer policy")
    if event.producer not in allowed:
        raise InvalidTransition("event producer is not allowed for its kind")
    if isinstance(event, InteractionRecordedEvent):
        directions = (
            {
                InteractionDirection.PARTICIPANT_OUTPUT,
                InteractionDirection.TOOL_REQUEST,
            }
            if event.producer is ProducerKind.PARTICIPANT
            else {
                InteractionDirection.PARTICIPANT_INPUT,
                InteractionDirection.TOOL_RESULT,
            }
        )
        if event.payload.direction not in directions:
            raise InvalidTransition("interaction direction does not match its producer")


def _validate_artifact_references(
    event: RunEvent,
    artifacts: dict[str, ArtifactRecord],
) -> None:
    missing = set(event.artifact_refs) - artifacts.keys()
    if missing:
        raise InvalidTransition("event references an artifact that is not registered")
    allowed = {
        Visibility.PUBLIC: {Visibility.PUBLIC},
        Visibility.PARTICIPANT: {Visibility.PUBLIC, Visibility.PARTICIPANT},
        Visibility.REVIEWER: {
            Visibility.PUBLIC,
            Visibility.PARTICIPANT,
            Visibility.REVIEWER,
        },
        Visibility.VERIFIER: {
            Visibility.PUBLIC,
            Visibility.PARTICIPANT,
            Visibility.VERIFIER,
        },
        Visibility.AUTHOR: set(Visibility),
    }[event.visibility]
    if any(artifacts[artifact_id].visibility not in allowed for artifact_id in event.artifact_refs):
        raise InvalidTransition("event visibility would disclose a referenced artifact")


def _validate_provider_transcript(
    event: ProviderRequestStartedEvent | ProviderResponseRecordedEvent,
    artifacts: dict[str, ArtifactRecord],
) -> None:
    if event.visibility is not Visibility.AUTHOR:
        raise InvalidTransition("provider transcript facts require author visibility")
    record = artifacts[
        event.payload.request_artifact_id
        if isinstance(event, ProviderRequestStartedEvent)
        else event.artifact_refs[0]
    ]
    role = (
        ProviderTranscriptRole.REQUEST
        if isinstance(event, ProviderRequestStartedEvent)
        else ProviderTranscriptRole.RESPONSE
    )
    if (
        record.logical_id
        != provider_transcript_artifact_id(event.payload.request_id, role)
        or record.media_type != PROVIDER_TRANSCRIPT_MEDIA_TYPE
    ):
        raise InvalidTransition("provider transcript identity or media type is invalid")
    if (
        record.artifact_class is not ArtifactClass.TRAINING
        or record.sensitivity is not Sensitivity.CONFIDENTIAL
        or record.visibility is not Visibility.AUTHOR
        or record.redistribution is not Redistribution.FORBIDDEN
    ):
        raise InvalidTransition("provider transcript artifact policy is invalid")
    if isinstance(event, ProviderRequestStartedEvent):
        canary_record = artifacts[event.payload.security_evidence_artifact_id]
        if (
            canary_record.media_type != PROVIDER_CANARY_EVIDENCE_MEDIA_TYPE
            or canary_record.artifact_class is not ArtifactClass.EVIDENCE
            or canary_record.visibility is not Visibility.AUTHOR
        ):
            raise InvalidTransition("provider canary evidence artifact policy is invalid")


class RunJournal:
    """Own one immutable header and one append-only canonical event stream."""

    def __init__(self, directory: Path, header: RunHeader, task: TaskSpec) -> None:
        self.directory = directory
        self.header = header
        self.task = task
        self.header_path = directory / "run.json"
        self.events_path = directory / "events.jsonl"

    @classmethod
    def create(cls, state_root: Path, header: RunHeader, task: TaskSpec) -> RunJournal:
        if task.digest != header.binding.task.task_spec_digest:
            raise JournalError("task identity does not match the run header")
        _validate_task_binding(header, task)
        created_root = False
        try:
            state_root.mkdir(mode=_DIRECTORY_MODE, parents=True)
            created_root = True
        except FileExistsError:
            pass
        _require_secure_directory(state_root)
        if created_root:
            _fsync_directory(state_root.parent)
        lock_path = state_root / ".journal-create.lock"
        try:
            _write_exclusive(lock_path, b"")
            _fsync_directory(state_root)
        except FileExistsError:
            pass

        with _locked_file(lock_path, exclusive=True):
            final_directory = state_root / header.run_id.removeprefix("sha256:")
            if final_directory.exists():
                existing = cls.open(final_directory, task)
                if existing.header != header:
                    raise EventConflict("existing run directory has a conflicting header")
                return existing

            staging = Path(tempfile.mkdtemp(prefix=".run-incoming-", dir=state_root))
            os.chmod(staging, _DIRECTORY_MODE)
            try:
                _write_exclusive(staging / "run.json", canonical_bytes(header) + b"\n")
                _write_exclusive(staging / "events.jsonl", b"")
                _fsync_directory(staging)
                os.rename(staging, final_directory)
                _fsync_directory(state_root)
            except BaseException:
                _remove_staging_directory(staging)
                raise
        return cls.open(final_directory, task)

    @classmethod
    def open(cls, run_directory: Path, task: TaskSpec) -> RunJournal:
        _require_secure_directory(run_directory)
        header_content = _read_secure_file(
            run_directory / "run.json",
            maximum_bytes=4 * 1024 * 1024,
        )
        try:
            header = RunHeader.model_validate_json(header_content)
        except ValidationError as error:
            raise JournalCorruption("run header is not a valid canonical document") from error
        if header_content != canonical_bytes(header) + b"\n":
            raise JournalCorruption("run header is not canonically encoded")
        if run_directory.name != header.run_id.removeprefix("sha256:"):
            raise JournalCorruption("run directory name does not match run identity")
        if task.digest != header.binding.task.task_spec_digest:
            raise JournalCorruption("task identity does not match the run binding")
        _validate_task_binding(header, task)
        _require_secure_regular_file(run_directory / "events.jsonl")
        return cls(run_directory, header, task)

    def read_events(self) -> tuple[RunEvent, ...]:
        """Read the durable prefix without modifying a torn final record."""

        descriptor = os.open(
            self.events_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            data = _read_all(descriptor)
        finally:
            os.close(descriptor)
        events, _, _, _ = _decode_durable_prefix(data, self.header)
        replay(self.header, self.task, events)
        return events

    def integrity_digest(self) -> str:
        """Return the current hash-chain head for external tamper-evident anchoring."""

        descriptor = os.open(
            self.events_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            data = _read_all(descriptor)
        finally:
            os.close(descriptor)
        events, _, head_digest, _ = _decode_durable_prefix(data, self.header)
        replay(self.header, self.task, events)
        return head_digest

    def record(self) -> RunRecord:
        """Return a validated portable archive of the physical journal records."""

        descriptor = os.open(
            self.events_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            data = _read_all(descriptor)
        finally:
            os.close(descriptor)
        events, _, _, records = _decode_durable_prefix(data, self.header)
        replay(self.header, self.task, events)
        return RunRecord(header=self.header, commits=records)

    def events_committed_together(self, event_ids: Sequence[UUID]) -> bool:
        """Return whether all named events share one crash-atomic physical record."""

        required = frozenset(event_ids)
        if not required or len(required) != len(event_ids):
            raise ValueError("journal record query requires distinct event identifiers")
        descriptor = os.open(
            self.events_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            data = _read_all(descriptor)
        finally:
            os.close(descriptor)
        events, _, _, records = _decode_durable_prefix(data, self.header)
        replay(self.header, self.task, events)
        return any(
            required.issubset(event.event_id for event in record.events) for record in records
        )

    def state(self) -> RunState:
        return replay(self.header, self.task, self.read_events())

    def append(self, event: RunEvent) -> RunState:
        """Validate and durably commit one event, or return an idempotent replay."""

        return self.append_events((event,))

    def append_events(self, requested: Sequence[RunEvent]) -> RunState:
        """Commit related events as one crash-atomic journal record."""

        events_to_append = tuple(requested)
        if not events_to_append:
            raise ValueError("a journal record must contain at least one event")

        descriptor = os.open(
            self.events_path,
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            data = _read_all(descriptor)
            events, durable_length, head_digest, _ = _decode_durable_prefix(
                data,
                self.header,
            )
            if durable_length != len(data):
                os.ftruncate(descriptor, durable_length)
                os.fsync(descriptor)

            committed_by_id = {event.event_id: event for event in events}
            requested_ids = [event.event_id for event in events_to_append]
            if len(requested_ids) != len(set(requested_ids)):
                raise EventConflict("one journal record cannot reuse an event identifier")
            existing = [event_id in committed_by_id for event_id in requested_ids]
            if any(existing):
                if not all(existing):
                    raise EventConflict("journal record is only partially committed")
                if all(
                    canonical_bytes(committed_by_id[event.event_id]) == canonical_bytes(event)
                    for event in events_to_append
                ):
                    return replay(self.header, self.task, events)
                raise EventConflict("event identifier already owns different content")
            for offset, event in enumerate(events_to_append):
                if event.sequence != len(events) + offset:
                    raise EventConflict("event sequence does not own its journal position")
            committed_state = replay(self.header, self.task, events)
            if committed_state.terminal_reason is not None:
                raise InvalidTransition("a terminated run cannot accept another event")
            prospective = (*events, *events_to_append)
            state = replay(self.header, self.task, prospective)
            record = RunCommit.from_events(
                previous_record_digest=head_digest,
                events=events_to_append,
            )
            os.lseek(descriptor, 0, os.SEEK_END)
            _write_all_fd(descriptor, canonical_bytes(record) + b"\n")
            os.fsync(descriptor)
            return state
        finally:
            os.close(descriptor)

    def transact(self, factory: Callable[[RunState], RunEvent]) -> RunState:
        """Build and commit an event against the latest state under the journal lock."""

        return self.transact_events(lambda state: (factory(state),))

    def transact_events(
        self,
        factory: Callable[[RunState], Sequence[RunEvent]],
    ) -> RunState:
        """Build related events and commit them in one durable journal record."""

        descriptor = os.open(
            self.events_path,
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            _require_secure_fd(descriptor, regular=True)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            data = _read_all(descriptor)
            events, durable_length, head_digest, _ = _decode_durable_prefix(
                data,
                self.header,
            )
            if durable_length != len(data):
                os.ftruncate(descriptor, durable_length)
                os.fsync(descriptor)
            committed_state = replay(self.header, self.task, events)
            if committed_state.terminal_reason is not None:
                raise InvalidTransition("a terminated run cannot accept another event")
            requested = tuple(factory(committed_state))
            if not requested:
                raise ValueError("a journal transaction must contain at least one event")
            requested_ids = [event.event_id for event in requested]
            if len(requested_ids) != len(set(requested_ids)):
                raise EventConflict("transaction reused an event identifier")
            committed_ids = {event.event_id for event in events}
            if committed_ids.intersection(requested_ids):
                raise EventConflict("transaction reused a committed event identifier")
            for offset, event in enumerate(requested):
                if event.sequence != len(events) + offset:
                    raise EventConflict("transaction did not own its journal position")
            prospective = (*events, *requested)
            state = replay(self.header, self.task, prospective)
            record = RunCommit.from_events(
                previous_record_digest=head_digest,
                events=requested,
            )
            os.lseek(descriptor, 0, os.SEEK_END)
            _write_all_fd(descriptor, canonical_bytes(record) + b"\n")
            os.fsync(descriptor)
            return state
        finally:
            os.close(descriptor)


def _decode_durable_prefix(
    data: bytes,
    header: RunHeader,
) -> tuple[tuple[RunEvent, ...], int, str, tuple[RunCommit, ...]]:
    head_digest = run_journal_anchor(header)
    if not data:
        return (), 0, head_digest, ()
    durable_length = len(data)
    if not data.endswith(b"\n"):
        boundary = data.rfind(b"\n")
        durable_length = boundary + 1 if boundary >= 0 else 0
    durable = data[:durable_length]
    events: list[RunEvent] = []
    records: list[RunCommit] = []
    for line in durable.splitlines():
        if not line:
            raise JournalCorruption("journal contains an empty durable record")
        try:
            record = RunCommit.model_validate_json(line)
        except ValidationError as error:
            raise JournalCorruption("journal contains an invalid durable record") from error
        if canonical_bytes(record) != line:
            raise JournalCorruption("journal record is not canonically encoded")
        if record.previous_record_digest != head_digest:
            raise JournalCorruption("journal record hash chain is discontinuous")
        events.extend(record.events)
        records.append(record)
        head_digest = record.record_digest
    return tuple(events), durable_length, head_digest, tuple(records)


@contextmanager
def _locked_file(path: Path, *, exclusive: bool) -> Iterator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _require_secure_fd(descriptor, regular=True)
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield descriptor
    finally:
        os.close(descriptor)


def _read_secure_file(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = _require_secure_fd(descriptor, regular=True)
        if metadata.st_size > maximum_bytes:
            raise JournalCorruption("journal metadata exceeds its read bound")
        return _read_all(descriptor)
    finally:
        os.close(descriptor)


def _read_all(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        _FILE_MODE,
    )
    try:
        _write_all_fd(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all_fd(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written == 0:
            raise OSError("short write while committing journal data")
        view = view[written:]


def _require_secure_fd(descriptor: int, *, regular: bool) -> os.stat_result:
    metadata = os.fstat(descriptor)
    expected = stat.S_ISREG(metadata.st_mode) if regular else stat.S_ISDIR(metadata.st_mode)
    if not expected or metadata.st_uid != os.getuid():
        raise JournalError("journal paths must be owned and correctly typed")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise JournalError("journal paths cannot grant group or other access")
    return metadata


def _require_secure_directory(path: Path) -> os.stat_result:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        return _require_secure_fd(descriptor, regular=False)
    finally:
        os.close(descriptor)


def _require_secure_regular_file(path: Path) -> os.stat_result:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _require_secure_fd(descriptor, regular=True)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_staging_directory(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_file() and not child.is_symlink():
            child.unlink()
    with suppress(FileNotFoundError):
        path.rmdir()
