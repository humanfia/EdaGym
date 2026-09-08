"""Contract evidence for confidential Responses participant exchanges."""

from __future__ import annotations

import json
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from edagym.canonical import canonical_bytes
from edagym.participant_tool_protocol import COMMIT_INTENT_PARTICIPANT_TOOL_NAME
from edagym.participants.adapters import (
    CommandAgentAdapter,
    ParticipantAdapterError,
    ParticipantFailureKind,
)
from edagym.participants.admission import CampaignParticipantAdmission
from edagym.participants.controller import ParticipantController
from edagym.participants.model import ParticipantView, SubmitCandidateIntent
from edagym.participants.responses import (
    ParticipantToolResult,
    ProviderUsagePolicy,
    ResponsesParticipantAdapter,
    ResponsesParticipantSender,
    responses_instruction_digest,
    responses_tool_schema_digest,
)
from edagym.projections import project_atif
from edagym.projections.model import AtifInteractionExtra
from edagym.providers.model import (
    FunctionCall,
    FunctionCallInput,
    FunctionCallOutput,
    FunctionCallStatus,
    FunctionTool,
    ProviderSecurityBinding,
    ProviderUsage,
    RequestTokenClaim,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
    ToolParameter,
    ToolValueKind,
)
from edagym.providers.responses import ResponsesExchangeObserver
from edagym.resolution import resolve_run
from edagym.run.artifact_model import (
    ArtifactRecord,
)
from edagym.run.artifacts import ContentAddressedStore, EncryptionKey
from edagym.run.journal_storage import InvalidTransition
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    CampaignTrialRunBinding,
    InteractionDirection,
    InteractionRecordedEvent,
    ParticipantIncarnationBinding,
    ParticipantIncarnationStartedEvent,
    ParticipantIncarnationStartedPayload,
    ParticipantProcessIdentity,
    ProducerKind,
    ProviderResponseRecordedEvent,
    RunEndedEvent,
    RunEndedPayload,
    RunHeader,
    RunStartedEvent,
    RunStartedPayload,
    StopReason,
)
from edagym.security.canary_artifact import ProviderCanaryEvidence
from edagym.specs.common import ArtifactClass, Redistribution, Sensitivity, Visibility
from edagym.specs.environment import (
    ArtifactDisclosure,
    ArtifactPolicy,
    ArtifactRetentionRule,
    EnvironmentSpec,
    ManagedEncryption,
)
from edagym.specs.harness import (
    MeteredProviderHarnessBinding,
)
from edagym.specs.session import HarnessActor, SessionSpec

from .factories import (
    digest,
    environment_spec,
    provider_canary_evidence_fixture,
    provider_exchange_fixture,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)

_NOW = datetime(2026, 9, 4, tzinfo=UTC)
_PROMPT_CANARY = "PROMPT-CONTENT-MUST-STAY-ENCRYPTED"
_TOOL_OUTPUT_CANARY = "TOOL-OUTPUT-MUST-STAY-ENCRYPTED"
_RESPONSE_ID_CANARY = "response-id-must-not-enter-journal"
_CALL_ID_CANARY = "call-id-must-not-enter-journal"


def test_responses_request_requires_a_stateless_call_output_pair() -> None:
    claim = RequestTokenClaim(input_tokens=32, output_tokens=16)
    call = FunctionCallInput(
        call_id="call_a",
        name="edagym_observe_candidate",
        arguments='{"scope":"current"}',
    )
    output = FunctionCallOutput(call_id="call_a", output="observation")

    with pytest.raises(ValueError, match="matched call and output"):
        ResponsesRequest(model="route.test", inputs=(output,), token_claim=claim)
    with pytest.raises(ValueError, match="matched call and output"):
        ResponsesRequest(model="route.test", inputs=(call,), token_claim=claim)
    with pytest.raises(ValueError, match="must precede"):
        ResponsesRequest(model="route.test", inputs=(output, call), token_claim=claim)

    request = ResponsesRequest(
        model="route.test",
        inputs=(call, output),
        token_claim=claim,
    )
    assert "previous_response_id" not in request._wire_payload()
    assert request._wire_payload()["input"] == [call._wire_item(), output._wire_item()]


class _ObserveTool:
    def __init__(self, artifact_refs: tuple[str, ...] = ()) -> None:
        self._artifact_refs = artifact_refs

    @property
    def definition(self) -> FunctionTool:
        return FunctionTool(
            name="edagym_observe_candidate",
            description="Return a controller-approved candidate observation.",
            parameters=(
                ToolParameter(
                    name="scope",
                    kind=ToolValueKind.STRING,
                    description="The observation scope.",
                    choices=("current",),
                ),
            ),
        )

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult:
        assert json.loads(arguments) == {"scope": "current"}
        assert not view.candidates
        return ParticipantToolResult(
            output=_TOOL_OUTPUT_CANARY,
            artifact_refs=self._artifact_refs,
        )


class _TwoRequestSender:
    def __init__(
        self,
        *,
        canary_evidence: ProviderCanaryEvidence,
        include_usage: bool = True,
    ) -> None:
        self.requests: list[dict[str, object]] = []
        self._canary_evidence = canary_evidence
        self._include_usage = include_usage

    def request(
        self,
        *,
        trial_id: str,
        request_key: str,
        request: ResponsesRequest,
        observer: ResponsesExchangeObserver | None = None,
    ) -> ResponsesResult:
        assert observer is not None
        assert request_key.startswith("provider_request_")
        payload = request._wire_payload()
        self.requests.append(payload)
        request_body = json.dumps(payload, separators=(",", ":")).encode()
        observer.request_reserved(
            trial_id=trial_id,
            request_key=request_key,
            provider_profile_digest=digest("provider-profile"),
            provider_config_digest=digest("provider-config"),
            security_binding=ProviderSecurityBinding(
                canary_receipt_digest=self._canary_evidence.receipt.digest,
                runtime_surface_manifest_digest=(
                    self._canary_evidence.runtime_surface_manifest.digest
                ),
                budget_binding_digest=digest("provider-budget"),
            ),
            canary_evidence=self._canary_evidence,
            request_body=request_body,
            beta_features=(),
        )
        usage: ProviderUsage | None
        if len(self.requests) == 1 and self._include_usage:
            call = FunctionCall(
                call_id=_CALL_ID_CANARY,
                name="edagym_observe_candidate",
                arguments='{"scope":"current"}',
                status=FunctionCallStatus.COMPLETED,
            )
            response_id = _RESPONSE_ID_CANARY
            usage = ProviderUsage(input_tokens=10, output_tokens=4, total_tokens=14)
        else:
            intent = json.dumps(
                {
                    "kind": "submit_candidate",
                    "candidate_id": "candidate_a",
                    "parent_candidate_id": None,
                },
                separators=(",", ":"),
            )
            call = FunctionCall(
                call_id="terminal-call-id",
                name=COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
                arguments=json.dumps({"intent": intent}, separators=(",", ":")),
                status=FunctionCallStatus.COMPLETED,
            )
            response_id = "terminal-response-id"
            usage = (
                ProviderUsage(input_tokens=12, output_tokens=5, total_tokens=17)
                if self._include_usage
                else None
            )
        result = ResponsesResult(
            response_id=response_id,
            reported_model="route.snapshot",
            reported_service_tier="default",
            status=ResponseStatus.COMPLETED,
            outputs=(call,),
            usage=usage,
        )
        response_body = json.dumps(
            {
                "id": response_id,
                "call_id": call.call_id,
                "model": result.reported_model,
                "service_tier": result.reported_service_tier,
                "status": result.status,
            },
            separators=(",", ":"),
        ).encode()
        observer.response_received(response_body=response_body, result=result)
        return result


def _canary_evidence(
    journal: TrialJournal,
    *,
    provider_profile_digest: str = digest("provider-profile"),
    provider_config_digest: str = digest("provider-config"),
    budget_binding_digest: str = digest("provider-budget"),
) -> ProviderCanaryEvidence:
    return provider_canary_evidence_fixture(
        journal.header,
        actor_id="solver",
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        budget_binding_digest=budget_binding_digest,
    )


def test_responses_tool_continuation_records_exact_usage_without_public_content(
    tmp_path: Path,
) -> None:
    environment = _encrypted_environment()
    journal, store = _journal_and_store(tmp_path, environment)
    sender = _TwoRequestSender(canary_evidence=_canary_evidence(journal))
    adapter = ResponsesParticipantAdapter(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session_spec(),
        artifact_store=store,
        sender=sender,
        instruction=_PROMPT_CANARY,
        token_claim=RequestTokenClaim(input_tokens=128, output_tokens=64),
        tools=(_ObserveTool(),),
        service_tier="fast",
        clock=lambda: _NOW,
        event_id_factory=_uuid_factory(100),
        request_id_factory=_uuid_factory(200),
    )

    intent = adapter.next_intent(_view(journal))

    assert isinstance(intent, SubmitCandidateIntent)
    assert intent.candidate_id == "candidate_a"
    assert not hasattr(intent, "candidate_digest")
    assert len(sender.requests) == 2
    assert "previous_response_id" not in sender.requests[0]
    assert "previous_response_id" not in sender.requests[1]
    assert sender.requests[0]["store"] is False
    assert sender.requests[1]["store"] is False
    continued_input = sender.requests[1]["input"]
    assert isinstance(continued_input, list)
    assert continued_input[0] == {
        "role": "developer",
        "content": _PROMPT_CANARY,
    }
    assert isinstance(continued_input[1], dict)
    assert continued_input[1]["role"] == "user"
    assert continued_input[2:] == [
        {
            "type": "function_call",
            "call_id": _CALL_ID_CANARY,
            "name": "edagym_observe_candidate",
            "arguments": '{"scope":"current"}',
        },
        {
            "type": "function_call_output",
            "call_id": _CALL_ID_CANARY,
            "output": _TOOL_OUTPUT_CANARY,
        }
    ]

    state = journal.state()
    assert len(state.provider_requests) == 2
    assert sum(item.usage.input_tokens for item in state.provider_requests if item.usage) == 22
    assert sum(item.usage.output_tokens for item in state.provider_requests if item.usage) == 9
    assert all(item.status is ResponseStatus.COMPLETED for item in state.provider_requests)
    assert all(item.provider_reported_model == "route.snapshot" for item in state.provider_requests)
    assert all(item.requested_service_tier == "fast" for item in state.provider_requests)
    assert all(
        item.provider_reported_service_tier == "default" for item in state.provider_requests
    )

    events = journal.read_events()
    interactions = tuple(
        event for event in events if isinstance(event, InteractionRecordedEvent)
    )
    assert len(interactions) == 4
    requests = {
        event.payload.interaction_id: event
        for event in interactions
        if event.payload.direction is InteractionDirection.TOOL_REQUEST
    }
    results = tuple(
        event
        for event in interactions
        if event.payload.direction is InteractionDirection.TOOL_RESULT
    )
    assert len(requests) == len(results) == 2
    assert all(
        event.payload.related_interaction_id in requests
        and requests[event.payload.related_interaction_id].payload.tool_name
        == event.payload.tool_name
        for event in results
    )
    artifacts = tuple(
        event.payload.record
        for event in events
        if isinstance(event, ArtifactRecordedEvent)
    )
    transcripts = tuple(
        record for record in artifacts if record.artifact_class is ArtifactClass.TRAINING
    )
    assert len(artifacts) == 5
    assert len(transcripts) == 4
    assert all(record.sensitivity is Sensitivity.CONFIDENTIAL for record in transcripts)
    assert all(record.visibility is Visibility.AUTHOR for record in transcripts)
    assert all(record.redistribution is Redistribution.FORBIDDEN for record in transcripts)
    restored = b"\n".join(
        store.read_bytes(record.blob, maximum_bytes=record.blob.size_bytes)
        for record in artifacts
    )
    assert _PROMPT_CANARY.encode() in restored
    assert _TOOL_OUTPUT_CANARY.encode() in restored
    assert _RESPONSE_ID_CANARY.encode() in restored

    public_journal = journal.events_path.read_bytes()
    public_projection = canonical_bytes(project_atif(journal))
    atif = project_atif(journal)
    projected_interactions = tuple(
        step.extra
        for step in atif.steps
        if isinstance(step.extra, AtifInteractionExtra)
    )
    assert len(projected_interactions) == 4
    assert sum(item.related_interaction_id is not None for item in projected_interactions) == 2
    for canary in (
        _PROMPT_CANARY,
        _TOOL_OUTPUT_CANARY,
        _RESPONSE_ID_CANARY,
        _CALL_ID_CANARY,
        "terminal-response-id",
        "terminal-call-id",
    ):
        assert canary.encode() not in public_journal
        assert canary.encode() not in public_projection
    stored_envelopes = b"".join(
        path.read_bytes() for path in store.blob_root.rglob("*") if path.is_file()
    )
    assert _PROMPT_CANARY.encode() not in stored_envelopes
    assert _TOOL_OUTPUT_CANARY.encode() not in stored_envelopes


def test_ranked_participant_rejects_missing_usage_after_recording_route_evidence(
    tmp_path: Path,
) -> None:
    environment = _encrypted_environment()
    journal, store = _journal_and_store(tmp_path, environment)
    sender = _TwoRequestSender(
        canary_evidence=_canary_evidence(journal),
        include_usage=False,
    )
    adapter = ResponsesParticipantAdapter(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session_spec(),
        artifact_store=store,
        sender=sender,
        instruction=_PROMPT_CANARY,
        token_claim=RequestTokenClaim(input_tokens=128, output_tokens=64),
        usage_policy=ProviderUsagePolicy.EXACT,
        clock=lambda: _NOW,
        event_id_factory=_uuid_factory(300),
        request_id_factory=_uuid_factory(400),
    )

    with pytest.raises(ParticipantAdapterError) as captured:
        adapter.next_intent(_view(journal))

    assert captured.value.kind is ParticipantFailureKind.CHANNEL_FAILURE
    assert len(sender.requests) == 1
    request = journal.state().provider_requests[0]
    assert request.status is ResponseStatus.COMPLETED
    assert request.usage is None
    assert any(isinstance(event, ProviderResponseRecordedEvent) for event in journal.read_events())
    assert _PROMPT_CANARY.encode() not in journal.events_path.read_bytes()
    rendered = "".join(
        traceback.TracebackException.from_exception(
            captured.value,
            capture_locals=True,
        ).format()
    )
    assert _PROMPT_CANARY not in rendered
    assert "terminal-response-id" not in rendered
    assert "terminal-call-id" not in rendered


def test_run_cannot_end_with_an_unsettled_provider_request(tmp_path: Path) -> None:
    environment = _encrypted_environment()
    journal, _ = _journal_and_store(tmp_path, environment)
    exchange = provider_exchange_fixture(
        journal.header,
        request_id="unsettled_provider_request",
        actor_id="solver",
        requested_model="test-route",
        provider_profile_digest=digest("provider-profile"),
        provider_config_digest=digest("provider-config"),
        budget_binding_digest=digest("provider-budget"),
        reserved_input_tokens=32,
        reserved_output_tokens=16,
        usage=ProviderUsage(input_tokens=1, output_tokens=1, total_tokens=2),
    )
    journal.transact_events(
        lambda state: exchange.request_events(state, timestamp=_NOW)
    )

    with pytest.raises(InvalidTransition, match="unsettled provider requests"):
        journal.transact(
            lambda state: RunEndedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=UUID(int=999),
                timestamp=_NOW,
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                payload=RunEndedPayload(reason=StopReason.EXPLICIT_CANCEL),
            )
        )


def test_inner_tool_loop_stops_at_the_journal_derived_tool_budget(tmp_path: Path) -> None:
    environment = _encrypted_environment()
    base_session = session_spec()
    resources = base_session.resources.model_copy(update={"max_tool_calls": 1})
    session = SessionSpec.model_validate(
        {**base_session.model_dump(mode="python"), "resources": resources}
    )
    journal, store = _journal_and_store(tmp_path, environment, session=session)
    sender = _TwoRequestSender(canary_evidence=_canary_evidence(journal))
    adapter = ResponsesParticipantAdapter(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session,
        artifact_store=store,
        sender=sender,
        instruction=_PROMPT_CANARY,
        token_claim=RequestTokenClaim(input_tokens=128, output_tokens=64),
        tools=(_ObserveTool(),),
        clock=lambda: _NOW,
        event_id_factory=_uuid_factory(500),
        request_id_factory=_uuid_factory(600),
    )

    with pytest.raises(ParticipantAdapterError) as captured:
        adapter.next_intent(_view(journal))

    assert captured.value.kind is ParticipantFailureKind.TOOL_BUDGET
    assert len(sender.requests) == 1
    request = journal.state().provider_requests[0]
    assert request.status is ResponseStatus.COMPLETED
    assert request.usage is not None
    assert request.usage.total_tokens == 14
    assert sum(
        isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_REQUEST
        for event in journal.read_events()
    ) == 1


def test_tool_result_references_registered_author_evidence(tmp_path: Path) -> None:
    environment = _encrypted_environment()
    journal, store = _journal_and_store(tmp_path, environment)
    evidence_id = "tool_execution_evidence"
    blob = store.put_bytes(
        b"controller-owned evidence",
        artifact_class=ArtifactClass.EVIDENCE,
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.AUTHOR,
        redistribution=Redistribution.RESTRICTED,
    )
    journal.transact(
        lambda state: ArtifactRecordedEvent(
            run_id=state.run_id,
            sequence=state.next_sequence,
            event_id=UUID(int=700),
            timestamp=_NOW,
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.AUTHOR,
            payload=ArtifactRecordedPayload(
                record=ArtifactRecord(
                    logical_id=evidence_id,
                    blob=blob,
                    media_type="text/plain",
                    artifact_class=ArtifactClass.EVIDENCE,
                    sensitivity=Sensitivity.INTERNAL,
                    visibility=Visibility.AUTHOR,
                    redistribution=Redistribution.RESTRICTED,
                )
            ),
        )
    )
    adapter = ResponsesParticipantAdapter(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session_spec(),
        artifact_store=store,
        sender=_TwoRequestSender(canary_evidence=_canary_evidence(journal)),
        instruction=_PROMPT_CANARY,
        token_claim=RequestTokenClaim(input_tokens=128, output_tokens=64),
        tools=(_ObserveTool((evidence_id,)),),
        clock=lambda: _NOW,
        event_id_factory=_uuid_factory(710),
        request_id_factory=_uuid_factory(720),
    )

    adapter.next_intent(_view(journal))

    referenced = tuple(
        event
        for event in journal.read_events()
        if isinstance(event, InteractionRecordedEvent)
        and event.payload.direction is InteractionDirection.TOOL_RESULT
        and event.artifact_refs
    )
    assert len(referenced) == 1
    assert referenced[0].artifact_refs == (evidence_id,)
    assert referenced[0].visibility is Visibility.AUTHOR


class _MeteredSender(_TwoRequestSender):
    def __init__(
        self,
        *,
        campaign_digest: str,
        schedule_digest: str | None,
        provider_profile_digest: str,
        provider_config_digest: str,
        budget_binding_digest: str,
        canary_evidence: ProviderCanaryEvidence,
    ) -> None:
        super().__init__(canary_evidence=canary_evidence)
        self.campaign_digest = campaign_digest
        self.campaign_schedule_digest = schedule_digest
        self.provider_profile_digest = provider_profile_digest
        self.provider_config_digest = provider_config_digest
        self.budget_binding_digest = budget_binding_digest
        self.bound_trial_id = "campaign_trial"
        self.provider_security_binding = ProviderSecurityBinding(
            canary_receipt_digest=canary_evidence.receipt.digest,
            runtime_surface_manifest_digest=(
                canary_evidence.runtime_surface_manifest.digest
            ),
            budget_binding_digest=budget_binding_digest,
        )


class _NeverCommandChannel:
    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        raise AssertionError((view, maximum_response_bytes))


def test_campaign_participant_requires_exact_metered_admission(tmp_path: Path) -> None:
    environment = _encrypted_environment()
    instruction = "Use the bounded campaign tools."
    provider_profile_digest = digest("admitted-provider-profile")
    provider_config_digest = digest("admitted-provider-config")
    campaign_digest = digest("admitted-campaign")
    schedule_digest = digest("admitted-schedule")
    scheduled_trial_digest = digest("admitted-trial")
    budget_binding_digest = digest("admitted-budget")
    harness = MeteredProviderHarnessBinding(
        harness_id="metered_responses",
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        instruction_digest=responses_instruction_digest(instruction),
        tool_schema_digest=responses_tool_schema_digest((_ObserveTool().definition,)),
        scaffold_digest=digest("metered-scaffold"),
        maximum_requests_per_action=2,
    )
    base_session = session_spec()
    session = SessionSpec.model_validate(
        {
            **base_session.model_dump(mode="python"),
            "actors": (
                HarnessActor(
                    actor_id="solver",
                    harness_id=harness.harness_id,
                    harness_digest=harness.digest,
                    scaffold_digest=harness.scaffold_digest,
                    requested_model_route="route.snapshot",
                ),
            ),
        }
    )
    campaign = CampaignTrialRunBinding(
        campaign_digest=campaign_digest,
        schedule_digest=schedule_digest,
        scheduled_trial_digest=scheduled_trial_digest,
        paired_seed="1" * 32,
        repetition_index=0,
        route_id="snapshot_route",
        reasoning_effort="high",
        service_tier="fast",
    )
    journal, store = _journal_and_store(
        tmp_path,
        environment,
        session=session,
        campaign=campaign,
        trial_key="campaign_trial",
    )
    admission = CampaignParticipantAdmission(
        run_id=journal.header.run_id,
        task_release_digest=journal.header.binding.task.release_digest,
        environment_spec_digest=environment.digest,
        session_spec_digest=session.digest,
        trial_key=journal.header.binding.trial_key,
        campaign=campaign,
        actor_id="solver",
        harness_id=harness.harness_id,
        harness_digest=harness.digest,
        scaffold_digest=harness.scaffold_digest,
        provider_profile_digest=harness.provider_profile_digest,
        provider_config_digest=harness.provider_config_digest,
        requested_model="route.snapshot",
        instruction_digest=harness.instruction_digest,
        tool_schema_digest=harness.tool_schema_digest,
        maximum_requests_per_action=harness.maximum_requests_per_action,
        budget_binding_digest=budget_binding_digest,
    )
    sender = _MeteredSender(
        campaign_digest=campaign_digest,
        schedule_digest=schedule_digest,
        provider_profile_digest=provider_profile_digest,
        provider_config_digest=provider_config_digest,
        budget_binding_digest=budget_binding_digest,
        canary_evidence=_canary_evidence(
            journal,
            provider_profile_digest=provider_profile_digest,
            provider_config_digest=provider_config_digest,
            budget_binding_digest=budget_binding_digest,
        ),
    )

    def build(
        *,
        admitted: CampaignParticipantAdmission | None,
        participant_sender: ResponsesParticipantSender = sender,
        participant_instruction: str = instruction,
    ) -> ResponsesParticipantAdapter:
        return ResponsesParticipantAdapter(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            artifact_store=store,
            sender=participant_sender,
            instruction=participant_instruction,
            token_claim=RequestTokenClaim(input_tokens=128, output_tokens=64),
            tools=(_ObserveTool(),),
            maximum_requests_per_action=2,
            campaign_admission=admitted,
            usage_policy=ProviderUsagePolicy.EXACT,
            reasoning_effort="high",
            service_tier="fast",
        )

    assert build(admitted=admission).actor_kinds
    with pytest.raises(ValueError, match="typed metered admission"):
        build(admitted=None)
    with pytest.raises(ValueError, match="metered provider sender"):
        build(
            admitted=admission,
            participant_sender=_TwoRequestSender(
                canary_evidence=_canary_evidence(journal)
            ),
        )
    with pytest.raises(ValueError, match="metered provider sender"):
        build(
            admitted=admission,
            participant_sender=_MeteredSender(
                campaign_digest=campaign_digest,
                schedule_digest=None,
                provider_profile_digest=provider_profile_digest,
                provider_config_digest=provider_config_digest,
                budget_binding_digest=budget_binding_digest,
                canary_evidence=_canary_evidence(
                    journal,
                    provider_profile_digest=provider_profile_digest,
                    provider_config_digest=provider_config_digest,
                    budget_binding_digest=budget_binding_digest,
                ),
            ),
        )
    with pytest.raises(ValueError, match="behavior differs"):
        build(admitted=admission, participant_instruction="changed instruction")
    controller = ParticipantController(
        journal,
        CommandAgentAdapter(actor_id="solver", channel=_NeverCommandChannel()),
        session=session,
        snapshot_candidate=lambda intent: (_ for _ in ()).throw(
            AssertionError(intent.candidate_id)
        ),
    )
    with pytest.raises(ValueError, match="exact participant admission"):
        controller.act_once()


def _encrypted_environment() -> EnvironmentSpec:
    base = environment_spec()
    rules = tuple(
        ArtifactRetentionRule(
            artifact_class=artifact_class,
            retention_seconds=3600,
            allowed_disclosures=(
                (
                    ArtifactDisclosure(
                        sensitivity=Sensitivity.CONFIDENTIAL,
                        visibility=Visibility.AUTHOR,
                        redistribution=Redistribution.FORBIDDEN,
                    )
                    if artifact_class is ArtifactClass.TRAINING
                    else ArtifactDisclosure(
                        sensitivity=Sensitivity.INTERNAL,
                        visibility=Visibility.AUTHOR,
                        redistribution=Redistribution.RESTRICTED,
                    )
                ),
            ),
        )
        for artifact_class in ArtifactClass
    )
    policy = ArtifactPolicy(
        quota_bytes=64 * 1024**2,
        encryption=ManagedEncryption(
            provider_id="test_key_provider",
            policy_digest=digest("test-key-policy"),
        ),
        rules=rules,
    )
    values = base.model_dump(mode="python")
    values["artifact_policy"] = policy
    return EnvironmentSpec.model_validate(values)


def _journal_and_store(
    root: Path,
    environment: EnvironmentSpec,
    *,
    session: SessionSpec | None = None,
    campaign: CampaignTrialRunBinding | None = None,
    trial_key: str = "responses-participant",
) -> tuple[TrialJournal, ContentAddressedStore]:
    task = task_spec()
    instance = task_instance(task)
    release = release_manifest(task, instance, environment)
    bound_session = session_spec() if session is None else session
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=environment,
        session=bound_session,
        trial_key=trial_key,
        campaign=campaign,
    )
    header = RunHeader.from_binding(plan.binding)
    journal = TrialJournal.create(root / "journal", header, task)
    started = RunStartedEvent(
        run_id=header.run_id,
        sequence=0,
        event_id=UUID(int=1),
        timestamp=_NOW,
        producer=ProducerKind.CONTROLLER,
        visibility=Visibility.PUBLIC,
        payload=RunStartedPayload(binding_digest=header.binding.digest),
    )
    if campaign is not None:
        journal.append_events(
            (
                started,
                ParticipantIncarnationStartedEvent(
                    run_id=header.run_id,
                    sequence=1,
                    event_id=UUID(int=2),
                    timestamp=_NOW,
                    payload=ParticipantIncarnationStartedPayload(
                        incarnation=ParticipantIncarnationBinding(
                            generation=0,
                            process=ParticipantProcessIdentity(
                                process_id=1,
                                start_time_ticks=1,
                                boot_id_digest=digest("responses-participant-boot"),
                            ),
                            workspace_identity_digest=digest(
                                "responses-participant-workspace"
                            ),
                            artifact_directory_identity_digest=digest(
                                "responses-participant-artifacts"
                            ),
                        )
                    ),
                ),
            )
        )
    else:
        journal.append(started)
    store_root = root / "store"
    store_root.mkdir(mode=0o700)
    store = ContentAddressedStore(
        store_root,
        policy=environment.artifact_policy,
        encryption_key=EncryptionKey(key_id="test_key", value=b"k" * 32),
    )
    return journal, store


def _view(journal: TrialJournal) -> ParticipantView:
    return ParticipantView(
        run_id=journal.header.run_id,
        task_family=journal.header.binding.task.family,
        authoring_revision=journal.header.binding.task.authoring_revision,
        actor_id="solver",
    )


def _uuid_factory(start: int) -> Callable[[], UUID]:
    current = start

    def create() -> UUID:
        nonlocal current
        value = UUID(int=current)
        current += 1
        return value

    return create
