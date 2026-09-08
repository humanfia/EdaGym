"""Controller-side Responses harness with confidential, journaled exchanges."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, cast, runtime_checkable
from uuid import UUID, uuid4

from pydantic import TypeAdapter, ValidationError

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.participant_tool_protocol import COMMIT_INTENT_PARTICIPANT_TOOL_NAME
from edagym.participants.adapters import ParticipantAdapterError, ParticipantFailureKind
from edagym.participants.admission import CampaignParticipantAdmission
from edagym.participants.execution import participant_tool_interaction_id
from edagym.participants.model import (
    PARTICIPANT_INTENT_ADAPTER,
    ParticipantIntent,
    ParticipantView,
)
from edagym.providers.campaign_budget import ProviderBudgetOverrun
from edagym.providers.model import (
    FunctionCall,
    FunctionCallInput,
    FunctionCallOutput,
    FunctionCallStatus,
    FunctionTool,
    InputMessage,
    InputRole,
    ReasoningSummary,
    RequestTokenClaim,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
    ToolParameter,
    ToolValueKind,
)
from edagym.providers.responses import ResponsesExchangeObserver
from edagym.run.artifact_model import (
    ArtifactRecord,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.trial_journal import TrialJournal
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    ArtifactRecordedPayload,
    HarnessRunActor,
    InteractionDirection,
    InteractionRecordedEvent,
    InteractionRecordedPayload,
    ProducerKind,
    ProviderRequestStartedEvent,
    ProviderRequestStartedPayload,
    ProviderResponseRecordedEvent,
    ProviderResponseRecordedPayload,
    ProviderSecurityBinding,
    ProviderUsageFact,
    RunEvent,
    RunPurpose,
    RunState,
)
from edagym.security.canary_artifact import (
    PROVIDER_TRANSCRIPT_MEDIA_TYPE,
    ProviderCanaryEvidence,
    ProviderTranscriptRole,
    provider_transcript_artifact_id,
    store_provider_canary_evidence,
)
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    Identifier,
    Redistribution,
    Sensitivity,
    ServiceTierLabel,
    Visibility,
)
from edagym.specs.environment import ArtifactDisclosure, EnvironmentSpec
from edagym.specs.session import ActorKind, HarnessActor, SessionSpec

_MAXIMUM_TOOL_ARGUMENT_BYTES = 1024 * 1024
_IDENTIFIER_ADAPTER: TypeAdapter[str] = TypeAdapter(Identifier)


class ProviderUsagePolicy(StrEnum):
    EXACT = "exact"
    BEST_EFFORT = "best_effort"


class ParticipantToolResult:
    """One confidential tool result, either terminal or continued."""

    __slots__ = ("artifact_refs", "intent", "output")

    def __init__(
        self,
        *,
        intent: ParticipantIntent | None = None,
        output: str | None = None,
        artifact_refs: tuple[Identifier, ...] = (),
    ) -> None:
        if (intent is None) == (output is None):
            raise ValueError("a participant tool must either finish or return output")
        if output is not None:
            try:
                output_size = len(output.encode("utf-8"))
            except UnicodeEncodeError:
                raise ValueError("participant tool output must be valid UTF-8") from None
            if not output or output_size > 1_000_000:
                raise ValueError("participant tool output must be bounded and non-empty")
        try:
            normalized_refs = tuple(
                _IDENTIFIER_ADAPTER.validate_python(reference)
                for reference in artifact_refs
            )
        except (TypeError, ValidationError):
            raise ValueError("participant tool artifact references are invalid") from None
        if len(normalized_refs) != len(set(normalized_refs)):
            raise ValueError("participant tool artifact references must be unique")
        self.intent = intent
        self.output = output
        self.artifact_refs = tuple(sorted(normalized_refs))

    def __repr__(self) -> str:
        return "ParticipantToolResult(<confidential>)"


class ResponsesParticipantTool(Protocol):
    @property
    def definition(self) -> FunctionTool: ...

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult: ...


class ResponsesParticipantSender(Protocol):
    def request(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        request: ResponsesRequest,
        observer: ResponsesExchangeObserver | None = None,
    ) -> ResponsesResult: ...


@runtime_checkable
class MeteredResponsesParticipantSender(ResponsesParticipantSender, Protocol):
    """Non-secret identity exposed by a campaign-metered provider session."""

    @property
    def campaign_digest(self) -> Digest: ...

    @property
    def campaign_schedule_digest(self) -> Digest | None: ...

    @property
    def provider_profile_digest(self) -> Digest: ...

    @property
    def provider_config_digest(self) -> Digest: ...

    @property
    def budget_binding_digest(self) -> Digest: ...

    @property
    def bound_trial_id(self) -> Identifier | None: ...

    @property
    def provider_security_binding(self) -> ProviderSecurityBinding: ...

    @property
    def provider_canary_evidence(self) -> ProviderCanaryEvidence: ...


def responses_instruction_digest(instruction: str) -> Digest:
    """Bind the exact UTF-8 instruction used by a Responses harness."""

    if not instruction:
        raise ValueError("provider instruction must be non-empty")
    try:
        encoded = instruction.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("provider instruction must be valid UTF-8") from None
    if len(encoded) > 1_000_000:
        raise ValueError("provider instruction exceeds its byte bound")
    return canonical_digest(
        {"instruction": instruction},
        domain="responses-participant-instruction-v1",
    )


def responses_tool_schema_digest(definitions: Sequence[FunctionTool] = ()) -> Digest:
    """Bind extension tools together with the mandatory intent tool."""

    frozen = (IntentParticipantTool._DEFINITION, *definitions)
    if any(type(definition) is not FunctionTool for definition in frozen):
        raise TypeError("provider tool schemas must be FunctionTool values")
    names = [definition.name for definition in frozen]
    if not names or len(names) != len(set(names)):
        raise ValueError("provider tool schema names must be unique and non-empty")
    ordered = tuple(sorted(frozen, key=lambda definition: definition.name))
    return canonical_digest(ordered, domain="responses-participant-tool-schema-v1")


def _validate_campaign_admission(
    *,
    admission: CampaignParticipantAdmission | None,
    actor_id: str,
    bound_actor: HarnessRunActor,
    journal: TrialJournal,
    session: SessionSpec,
    sender: ResponsesParticipantSender,
    instruction_digest: Digest,
    tool_schema_digest: Digest,
    usage_policy: ProviderUsagePolicy,
    maximum_requests_per_action: int,
    reasoning_effort: str | None,
    service_tier: str | None,
) -> tuple[Digest, Digest] | None:
    campaign = journal.header.binding.campaign
    if campaign is None:
        if admission is not None:
            raise ValueError("campaign admission requires a campaign-bound run")
        return None
    if journal.header.binding.purpose is not RunPurpose.CAMPAIGN_TRIAL:
        raise ValueError("provider participants require a campaign trial run")
    if type(admission) is not CampaignParticipantAdmission:
        raise ValueError("campaign participants require typed metered admission")
    if not admission.matches_run(journal.header.binding, session):
        raise ValueError("campaign admission does not match the run trial binding")
    matching_session_actors = tuple(
        actor for actor in session.actors if actor.actor_id == admission.actor_id
    )
    if len(matching_session_actors) != 1:
        raise ValueError("campaign admission must identify one session harness")
    session_actor = matching_session_actors[0]
    if not isinstance(session_actor, HarnessActor) or (
        admission.actor_id != actor_id
        or admission.harness_id != session_actor.harness_id
        or admission.harness_digest != bound_actor.harness_digest
        or admission.scaffold_digest != bound_actor.scaffold_digest
        or admission.requested_model != bound_actor.requested_model_route
    ):
        raise ValueError("campaign admission does not match the bound participant harness")
    if (
        admission.instruction_digest != instruction_digest
        or admission.tool_schema_digest != tool_schema_digest
        or admission.maximum_requests_per_action != maximum_requests_per_action
        or usage_policy is not ProviderUsagePolicy.EXACT
        or admission.usage_policy != ProviderUsagePolicy.EXACT.value
        or admission.wire_protocol != "responses"
        or reasoning_effort != campaign.reasoning_effort
        or service_tier != campaign.service_tier
    ):
        raise ValueError("campaign participant behavior differs from its metered harness")

    try:
        metered_sender = cast(MeteredResponsesParticipantSender, sender)
        sender_identity = (
            metered_sender.campaign_digest,
            metered_sender.campaign_schedule_digest,
            metered_sender.provider_profile_digest,
            metered_sender.provider_config_digest,
            metered_sender.budget_binding_digest,
            metered_sender.bound_trial_id,
            metered_sender.provider_security_binding.budget_binding_digest,
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise ValueError("campaign participants require a metered provider sender") from None
    if sender_identity != (
        campaign.campaign_digest,
        campaign.schedule_digest,
        admission.provider_profile_digest,
        admission.provider_config_digest,
        admission.budget_binding_digest,
        journal.header.binding.trial_key,
        admission.budget_binding_digest,
    ):
        raise ValueError("metered provider sender does not match campaign admission")
    return (admission.provider_profile_digest, admission.provider_config_digest)


class IntentParticipantTool:
    """Decode the canonical participant intent at the provider boundary."""

    _DEFINITION = FunctionTool(
        name=COMMIT_INTENT_PARTICIPANT_TOOL_NAME,
        description=(
            "Commit one JSON string with kind submit_candidate, finish_training, "
            "interaction, or transfer_control. A submission has candidate_id and "
            "parent_candidate_id; never supply a digest because the controller snapshots "
            "content. Finishing concludes training with candidate_id. An interaction has "
            "interaction_id, direction, and artifact_refs. A transfer has next_writer."
        ),
        parameters=(
            ToolParameter(
                name="intent",
                kind=ToolValueKind.STRING,
                description="A JSON object matching the current participant intent schema.",
            ),
        ),
    )

    @property
    def definition(self) -> FunctionTool:
        return self._DEFINITION

    def invoke(self, arguments: str, view: ParticipantView) -> ParticipantToolResult:
        del view
        if len(arguments.encode("utf-8")) > _MAXIMUM_TOOL_ARGUMENT_BYTES:
            raise ParticipantAdapterError(ParticipantFailureKind.RESPONSE_BOUND)
        try:
            envelope = json.loads(arguments)
            if not isinstance(envelope, dict) or set(envelope) != {"intent"}:
                raise ValueError
            encoded = envelope["intent"]
            if not isinstance(encoded, str):
                raise ValueError
            intent = PARTICIPANT_INTENT_ADAPTER.validate_json(encoded)
        except (UnicodeEncodeError, ValueError):
            raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT) from None
        return ParticipantToolResult(intent=intent)


class ResponsesParticipantAdapter:
    """Run a strict controller-side tool loop without delegating credentials."""

    def __init__(
        self,
        *,
        actor_id: str,
        journal: TrialJournal,
        environment: EnvironmentSpec,
        session: SessionSpec,
        artifact_store: ContentAddressedStore,
        sender: ResponsesParticipantSender,
        instruction: str,
        token_claim: RequestTokenClaim,
        tools: Sequence[ResponsesParticipantTool] = (),
        usage_policy: ProviderUsagePolicy = ProviderUsagePolicy.EXACT,
        maximum_requests_per_action: int = 8,
        campaign_admission: CampaignParticipantAdmission | None = None,
        reasoning_effort: str | None = None,
        service_tier: str | None = None,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], UUID] = uuid4,
        request_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        if session.digest != journal.header.binding.session.session_spec_digest:
            raise ValueError("participant session does not match the run binding")
        if environment.digest != journal.header.binding.environment.environment_spec_digest:
            raise ValueError("participant environment does not match the run binding")
        if artifact_store.policy != environment.artifact_policy:
            raise ValueError("participant artifact store policy does not match the environment")
        if not artifact_store.encrypted:
            raise ValueError("provider transcripts require managed artifact encryption")
        instruction_digest = responses_instruction_digest(instruction)
        try:
            usage_policy = ProviderUsagePolicy(usage_policy)
        except ValueError:
            raise ValueError("provider usage policy is unsupported") from None
        if type(maximum_requests_per_action) is not int or maximum_requests_per_action <= 0:
            raise ValueError("provider action request bound must be a positive integer")
        model_budget = session.model_budget
        if model_budget is None:
            raise ValueError("a provider participant requires a model budget")
        if (
            token_claim.input_tokens > model_budget.max_input_tokens_per_request
            or token_claim.output_tokens > model_budget.max_output_tokens_per_request
        ):
            raise ValueError("provider token claim exceeds the session request budget")
        if maximum_requests_per_action > model_budget.max_requests:
            raise ValueError("provider action request bound exceeds the session budget")
        bound_actor = next(
            (
                actor
                for actor in journal.header.binding.session.actors
                if actor.actor_id == actor_id
            ),
            None,
        )
        if not isinstance(bound_actor, HarnessRunActor):
            raise ValueError("provider participant actor must be a bound harness")

        intent_tool = IntentParticipantTool()
        extension_definitions = tuple(tool.definition for tool in tools)
        definitions = (intent_tool.definition, *extension_definitions)
        if any(type(definition) is not FunctionTool for definition in definitions):
            raise ValueError("provider participant tools require frozen definitions")
        all_tools = (intent_tool, *tools)
        by_name = {
            definition.name: tool
            for definition, tool in zip(definitions, all_tools, strict=True)
        }
        if len(by_name) != len(all_tools):
            raise ValueError("provider participant tool names must be unique")
        tool_schema_digest = responses_tool_schema_digest(extension_definitions)
        expected_provider_identity = _validate_campaign_admission(
            admission=campaign_admission,
            actor_id=actor_id,
            bound_actor=bound_actor,
            journal=journal,
            session=session,
            sender=sender,
            instruction_digest=instruction_digest,
            tool_schema_digest=tool_schema_digest,
            usage_policy=usage_policy,
            maximum_requests_per_action=maximum_requests_per_action,
            reasoning_effort=reasoning_effort,
            service_tier=service_tier,
        )
        self.actor_id = actor_id
        self._actor = bound_actor
        self._journal = journal
        self._session = session
        self._store = artifact_store
        self._sender = sender
        self._instruction = instruction
        self._token_claim = token_claim
        self._tools: Mapping[str, ResponsesParticipantTool] = MappingProxyType(by_name)
        self._tool_definitions = definitions
        self._usage_policy = usage_policy
        self._maximum_requests_per_action = maximum_requests_per_action
        self._reasoning_effort = reasoning_effort
        self._service_tier = service_tier
        self._clock = clock if clock is not None else lambda: datetime.now(UTC)
        self._event_id_factory = event_id_factory
        self._request_id_factory = request_id_factory
        self._disclosure = _provider_transcript_disclosure(environment)
        self._expected_provider_identity = expected_provider_identity
        self._expected_security_binding = (
            None
            if campaign_admission is None
            else cast(MeteredResponsesParticipantSender, sender).provider_security_binding
        )
        self._campaign_admission = campaign_admission

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {self.actor_id: ActorKind.HARNESS}

    @property
    def campaign_admission(self) -> CampaignParticipantAdmission | None:
        return self._campaign_admission

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        if view.actor_id != self.actor_id or view.run_id != self._journal.header.run_id:
            raise ParticipantAdapterError(ParticipantFailureKind.ACTOR_MISMATCH)
        inputs: tuple[InputMessage | FunctionCallInput | FunctionCallOutput, ...] = (
            InputMessage(role=InputRole.DEVELOPER, content=self._instruction),
            InputMessage(
                role=InputRole.USER,
                content=canonical_bytes(view).decode("utf-8"),
            ),
        )
        for _ in range(self._maximum_requests_per_action):
            self._require_tool_budget()
            self._require_request_budget()
            request_id = f"provider_request_{self._request_id_factory().hex}"
            recorder = _JournalExchangeRecorder(
                actor=self._actor,
                request_id=request_id,
                journal=self._journal,
                store=self._store,
                disclosure=self._disclosure,
                token_claim=self._token_claim,
                requested_service_tier=self._service_tier,
                expected_provider_identity=self._expected_provider_identity,
                expected_security_binding=self._expected_security_binding,
                clock=self._clock,
                event_id_factory=self._event_id_factory,
            )
            request = ResponsesRequest(
                model=self._actor.requested_model_route,
                inputs=inputs,
                tools=self._tool_definitions,
                reasoning_effort=self._reasoning_effort,
                service_tier=self._service_tier,
                tool_choice_required=True,
                token_claim=self._token_claim,
            )
            try:
                result = self._sender.request(
                    trial_id=self._journal.header.binding.trial_key,
                    request_key=request_id,
                    request=request,
                    observer=recorder,
                )
                recorder.require_result(result)
                if self._usage_policy is ProviderUsagePolicy.EXACT and result.usage is None:
                    raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
                if result.status is not ResponseStatus.COMPLETED:
                    raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
                call = _one_tool_call(result)
                tool = self._tools[call.name]
                request_interaction_id = self._record_tool_request(
                    request_id=request_id,
                    tool_name=call.name,
                )
                tool_result = tool.invoke(call.arguments, view)
                self._record_tool_result(
                    request_interaction_id=request_interaction_id,
                    tool_name=call.name,
                    artifact_refs=tool_result.artifact_refs,
                )
            except ParticipantAdapterError:
                raise
            except ProviderBudgetOverrun:
                raise ParticipantAdapterError(
                    ParticipantFailureKind.PROVIDER_BUDGET_OVERRUN
                ) from None
            except Exception:
                raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE) from None
            if tool_result.intent is not None:
                return tool_result.intent
            if tool_result.output is None:
                raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
            inputs = (
                *inputs,
                FunctionCallInput(
                    call_id=call.call_id,
                    name=call.name,
                    arguments=call.arguments,
                ),
                FunctionCallOutput(call_id=call.call_id, output=tool_result.output),
            )
        raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)

    def _record_tool_request(self, *, request_id: str, tool_name: str) -> str:
        interaction_id = participant_tool_interaction_id(request_id, tool_name, "request")
        timestamp = self._clock()
        event_id = self._event_id_factory()
        self._journal.transact(
            lambda state: InteractionRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=event_id,
                timestamp=timestamp,
                producer=ProducerKind.PARTICIPANT,
                actor=self.actor_id,
                visibility=Visibility.PARTICIPANT,
                payload=InteractionRecordedPayload(
                    direction=InteractionDirection.TOOL_REQUEST,
                    interaction_id=interaction_id,
                    tool_name=tool_name,
                ),
            )
        )
        return interaction_id

    def _record_tool_result(
        self,
        *,
        request_interaction_id: str,
        tool_name: str,
        artifact_refs: tuple[Identifier, ...],
    ) -> None:
        interaction_id = participant_tool_interaction_id(
            request_interaction_id,
            tool_name,
            "result",
        )
        timestamp = self._clock()
        event_id = self._event_id_factory()

        def event(state: RunState) -> InteractionRecordedEvent:
            registered = {artifact.logical_id for artifact in state.artifacts}
            if not set(artifact_refs).issubset(registered):
                raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
            return InteractionRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=event_id,
                timestamp=timestamp,
                producer=ProducerKind.CONTROLLER,
                visibility=(Visibility.AUTHOR if artifact_refs else Visibility.PARTICIPANT),
                artifact_refs=artifact_refs,
                payload=InteractionRecordedPayload(
                    direction=InteractionDirection.TOOL_RESULT,
                    interaction_id=interaction_id,
                    related_interaction_id=request_interaction_id,
                    tool_name=tool_name,
                ),
            )

        self._journal.transact(event)

    def _require_request_budget(self) -> None:
        budget = self._session.model_budget
        if budget is None:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        requests = self._journal.state().provider_requests
        input_tokens = sum(
            item.usage.input_tokens if item.usage is not None else item.reserved_input_tokens
            for item in requests
        )
        output_tokens = sum(
            item.usage.output_tokens if item.usage is not None else item.reserved_output_tokens
            for item in requests
        )
        if (
            len(requests) + 1 > budget.max_requests
            or input_tokens + self._token_claim.input_tokens > budget.max_total_input_tokens
            or output_tokens + self._token_claim.output_tokens > budget.max_total_output_tokens
            or input_tokens + output_tokens + self._token_claim.total_tokens
            > budget.max_total_tokens
        ):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)

    def _require_tool_budget(self) -> None:
        tool_requests = sum(
            isinstance(event, InteractionRecordedEvent)
            and event.payload.direction is InteractionDirection.TOOL_REQUEST
            for event in self._journal.read_events()
        )
        if tool_requests >= self._session.resources.max_tool_calls:
            raise ParticipantAdapterError(ParticipantFailureKind.TOOL_BUDGET)


class _JournalExchangeRecorder:
    """Persist raw bytes and append only opaque provider facts to the run journal."""

    def __init__(
        self,
        *,
        actor: HarnessRunActor,
        request_id: str,
        journal: TrialJournal,
        store: ContentAddressedStore,
        disclosure: ArtifactDisclosure,
        token_claim: RequestTokenClaim,
        requested_service_tier: ServiceTierLabel | None,
        expected_provider_identity: tuple[Digest, Digest] | None,
        expected_security_binding: ProviderSecurityBinding | None,
        clock: Callable[[], datetime],
        event_id_factory: Callable[[], UUID],
    ) -> None:
        self._actor = actor
        self._request_id = request_id
        self._journal = journal
        self._store = store
        self._disclosure = disclosure
        self._token_claim = token_claim
        self._requested_service_tier = requested_service_tier
        self._expected_provider_identity = expected_provider_identity
        self._expected_security_binding = expected_security_binding
        self._clock = clock
        self._event_id_factory = event_id_factory
        self._started = False
        self._result: ResponsesResult | None = None

    def request_reserved(
        self,
        *,
        trial_id: Identifier,
        provider_profile_digest: Digest,
        provider_config_digest: Digest,
        security_binding: ProviderSecurityBinding,
        canary_evidence: ProviderCanaryEvidence,
        request_body: bytes,
        beta_features: tuple[str, ...],
    ) -> None:
        if beta_features or self._started or trial_id != self._journal.header.binding.trial_key:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        provider_identity = (provider_profile_digest, provider_config_digest)
        if (
            self._expected_provider_identity is not None
            and provider_identity != self._expected_provider_identity
        ):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        if (
            self._expected_security_binding is not None
            and security_binding != self._expected_security_binding
        ):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        if (
            security_binding.canary_receipt_digest != canary_evidence.receipt.digest
            or security_binding.runtime_surface_manifest_digest
            != canary_evidence.runtime_surface_manifest.digest
        ):
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        prior = self._journal.state().provider_requests
        identities = {
            (
                item.provider_profile_digest,
                item.provider_config_digest,
                item.security_binding,
            )
            for item in prior
            if item.actor_id == self._actor.actor_id
        }
        if identities and identities != {(*provider_identity, security_binding)}:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        record = self._store_transcript(request_body, ProviderTranscriptRole.REQUEST)
        security_record = store_provider_canary_evidence(canary_evidence, self._store)
        timestamp = self._clock()
        artifact_event_id = self._event_id_factory()
        security_artifact_event_id = self._event_id_factory()
        provider_event_id = self._event_id_factory()

        def events(state: RunState) -> tuple[RunEvent, ...]:
            existing_security = next(
                (
                    item
                    for item in state.artifacts
                    if item.logical_id == security_record.logical_id
                ),
                None,
            )
            if existing_security is not None and existing_security != security_record:
                raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
            security_events: tuple[RunEvent, ...] = ()
            if existing_security is None:
                security_events = (
                    ArtifactRecordedEvent(
                        run_id=state.run_id,
                        sequence=state.next_sequence + 1,
                        event_id=security_artifact_event_id,
                        timestamp=timestamp,
                        producer=ProducerKind.CONTROLLER,
                        visibility=Visibility.AUTHOR,
                        payload=ArtifactRecordedPayload(record=security_record),
                    ),
                )
            return (
                ArtifactRecordedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=artifact_event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.AUTHOR,
                    payload=ArtifactRecordedPayload(record=record),
                ),
                *security_events,
                ProviderRequestStartedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence + 1 + len(security_events),
                    event_id=provider_event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.AUTHOR,
                    artifact_refs=(record.logical_id, security_record.logical_id),
                    payload=ProviderRequestStartedPayload(
                        request_id=self._request_id,
                        actor_id=self._actor.actor_id,
                        request_artifact_id=record.logical_id,
                        security_evidence_artifact_id=security_record.logical_id,
                        provider_profile_digest=provider_profile_digest,
                        provider_config_digest=provider_config_digest,
                        requested_model=self._actor.requested_model_route,
                        requested_service_tier=self._requested_service_tier,
                        observed_input_token_floor=(
                            self._token_claim.observed_input_token_floor
                        ),
                        security_binding=security_binding,
                        reserved_input_tokens=self._token_claim.input_tokens,
                        reserved_output_tokens=self._token_claim.output_tokens,
                    ),
                ),
            )

        self._journal.transact_events(events)
        self._started = True

    def response_rejected(self, *, response_body: bytes) -> None:
        record = self._store_transcript(response_body, ProviderTranscriptRole.RESPONSE)
        self._journal.transact(
            lambda state: ArtifactRecordedEvent(
                run_id=state.run_id,
                sequence=state.next_sequence,
                event_id=self._event_id_factory(),
                timestamp=self._clock(),
                producer=ProducerKind.CONTROLLER,
                visibility=Visibility.AUTHOR,
                payload=ArtifactRecordedPayload(record=record),
            )
        )

    def response_received(
        self,
        *,
        response_body: bytes,
        result: ResponsesResult,
    ) -> None:
        if not self._started or self._result is not None:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)
        record = self._store_transcript(response_body, ProviderTranscriptRole.RESPONSE)
        usage = result.usage
        usage_fact = (
            None
            if usage is None
            else ProviderUsageFact(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                total_tokens=usage.total_tokens,
                cached_input_tokens=usage.cached_input_tokens,
                reasoning_tokens=usage.reasoning_tokens,
            )
        )
        timestamp = self._clock()
        artifact_event_id = self._event_id_factory()
        provider_event_id = self._event_id_factory()

        def events(state: RunState) -> tuple[RunEvent, ...]:
            return (
                ArtifactRecordedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence,
                    event_id=artifact_event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.AUTHOR,
                    payload=ArtifactRecordedPayload(record=record),
                ),
                ProviderResponseRecordedEvent(
                    run_id=state.run_id,
                    sequence=state.next_sequence + 1,
                    event_id=provider_event_id,
                    timestamp=timestamp,
                    producer=ProducerKind.CONTROLLER,
                    visibility=Visibility.AUTHOR,
                    artifact_refs=(record.logical_id,),
                    payload=ProviderResponseRecordedPayload(
                        request_id=self._request_id,
                        provider_reported_model=result.reported_model,
                        provider_reported_service_tier=result.reported_service_tier,
                        status=result.status,
                        usage=usage_fact,
                    ),
                ),
            )

        self._journal.transact_events(events)
        self._result = result

    def require_result(self, result: ResponsesResult) -> None:
        if not self._started or self._result is not result:
            raise ParticipantAdapterError(ParticipantFailureKind.CHANNEL_FAILURE)

    def _store_transcript(
        self,
        content: bytes,
        role: ProviderTranscriptRole,
    ) -> ArtifactRecord:
        blob = self._store.put_bytes(
            content,
            artifact_class=ArtifactClass.TRAINING,
            sensitivity=self._disclosure.sensitivity,
            visibility=self._disclosure.visibility,
            redistribution=self._disclosure.redistribution,
        )
        return ArtifactRecord(
            logical_id=provider_transcript_artifact_id(self._request_id, role),
            blob=blob,
            media_type=PROVIDER_TRANSCRIPT_MEDIA_TYPE,
            artifact_class=ArtifactClass.TRAINING,
            sensitivity=self._disclosure.sensitivity,
            visibility=self._disclosure.visibility,
            redistribution=self._disclosure.redistribution,
        )

    def __repr__(self) -> str:
        return "_JournalExchangeRecorder(<confidential>)"


def _one_tool_call(result: ResponsesResult) -> FunctionCall:
    calls = tuple(item for item in result.outputs if isinstance(item, FunctionCall))
    unsupported = tuple(
        item for item in result.outputs if not isinstance(item, (FunctionCall, ReasoningSummary))
    )
    if (
        len(calls) != 1
        or calls[0].status is not FunctionCallStatus.COMPLETED
        or unsupported
    ):
        raise ParticipantAdapterError(ParticipantFailureKind.INVALID_INTENT)
    return calls[0]


def _provider_transcript_disclosure(environment: EnvironmentSpec) -> ArtifactDisclosure:
    rule = next(
        item
        for item in environment.artifact_policy.rules
        if item.artifact_class is ArtifactClass.TRAINING
    )
    choices = tuple(
        item
        for item in rule.allowed_disclosures
        if item.sensitivity is Sensitivity.CONFIDENTIAL
        and item.visibility is Visibility.AUTHOR
        and item.redistribution is Redistribution.FORBIDDEN
    )
    if rule.retention_seconds == 0 or len(choices) != 1:
        raise ValueError("environment must retain one restricted provider transcript class")
    return choices[0]
