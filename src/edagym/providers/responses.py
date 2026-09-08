"""Direct HTTPS broker for Responses-compatible provider campaigns."""

from __future__ import annotations

import http.client
import json
import ssl
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Protocol, Self, SupportsIndex
from urllib.parse import urlsplit

from pydantic import TypeAdapter, ValidationError

from edagym.providers.campaign import RetryCondition
from edagym.providers.campaign_runner import CampaignRunner
from edagym.providers.model import (
    FunctionCall,
    FunctionCallStatus,
    OutputText,
    ProviderProfile,
    ProviderUsage,
    ReasoningSummary,
    Refusal,
    ResolvedProviderConfig,
    ResponsesRequest,
    ResponsesResult,
    ResponseStatus,
    immutable_headers,
)
from edagym.providers.provider_budget import (
    CampaignProviderBudget,
    ProviderBudget,
    StandaloneProviderBudget,
)
from edagym.run.trial_model import ProviderSecurityBinding
from edagym.security.canary import CanaryAttestation, CanaryPolicy, CanaryReceipt
from edagym.security.canary_artifact import (
    MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES,
    MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES,
    ProviderCanaryEvidence,
)
from edagym.security.credentials import (
    CredentialSource,
    ProviderAccessLease,
    _consume_attestation_for_provider_access,
)
from edagym.security.runtime_surface import RuntimeSurfaceManifest
from edagym.specs.common import Digest, Identifier, Sensitivity, ServiceTierLabel

_SERVICE_TIER = TypeAdapter(ServiceTierLabel)
_BROKER_AUTHORITY = object()


class ProviderTransportError(RuntimeError):
    """The direct provider exchange failed without exposing confidential payloads."""


class ProviderRedirectError(ProviderTransportError):
    """A redirect was rejected; authorization is never forwarded to another request."""


class ProviderHttpError(ProviderTransportError):
    """A provider returned a non-success status without exposing its raw response."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"provider returned HTTP status {status}")


class ProviderProtocolError(ProviderTransportError):
    """A provider response did not satisfy the typed Responses subset."""


class RawHttpResponse:
    """Confidential transport result with bounded bytes and normalized headers."""

    __slots__ = ("body", "headers", "status")

    classification = Sensitivity.CONFIDENTIAL

    def __init__(self, *, status: int, headers: Mapping[str, str], body: bytes) -> None:
        self.status = status
        self.headers = immutable_headers(headers)
        self.body = body

    def __repr__(self) -> str:
        return "RawHttpResponse(<confidential>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("raw provider responses cannot be serialized")


class ProviderTransport(Protocol):
    def exchange(
        self,
        *,
        profile: ProviderProfile,
        headers: Mapping[str, str],
        body: bytes,
    ) -> RawHttpResponse:
        """Perform exactly one request to the profile's fixed HTTPS origin."""


class ResponsesExchangeObserver(Protocol):
    """Controller-side sink for confidential request and response evidence."""

    def request_reserved(
        self,
        *,
        trial_id: Identifier,
        provider_profile_digest: Digest,
        provider_config_digest: Digest,
        security_binding: ProviderSecurityBinding,
        canary_evidence: ProviderCanaryEvidence,
        request_body: bytes,
    ) -> None: ...

    def response_received(
        self,
        *,
        response_body: bytes,
        result: ResponsesResult,
    ) -> None: ...


class DirectHttpsTransport:
    """Use direct TLS sockets with no redirects and no ambient proxy handling."""

    def __init__(
        self,
        *,
        timeout_seconds: int = 120,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if type(timeout_seconds) is not int or timeout_seconds <= 0:
            raise ValueError("HTTPS timeout must be a positive integer")
        self._timeout_seconds = timeout_seconds
        self._ssl_context = ssl_context or ssl.create_default_context()
        if (
            self._ssl_context.verify_mode is not ssl.CERT_REQUIRED
            or not self._ssl_context.check_hostname
        ):
            raise ValueError("HTTPS transport requires certificate and hostname verification")

    def exchange(
        self,
        *,
        profile: ProviderProfile,
        headers: Mapping[str, str],
        body: bytes,
    ) -> RawHttpResponse:
        return self._request(
            profile=profile,
            method="POST",
            path=profile.responses_path,
            headers=headers,
            body=body,
            maximum_response_bytes=MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES,
        )

    def retrieve_models(
        self,
        *,
        profile: ProviderProfile,
        headers: Mapping[str, str],
        maximum_response_bytes: int,
    ) -> RawHttpResponse:
        """Read the explicitly declared models endpoint on the fixed provider origin."""

        if profile.models_path is None:
            raise ProviderProtocolError("provider profile declares no models endpoint")
        if (
            type(maximum_response_bytes) is not int
            or maximum_response_bytes <= 0
            or maximum_response_bytes > MAX_PROVIDER_TRANSCRIPT_RESPONSE_BYTES
        ):
            raise ValueError("models response byte limit is invalid")
        return self._request(
            profile=profile,
            method="GET",
            path=profile.models_path,
            headers=headers,
            body=None,
            maximum_response_bytes=maximum_response_bytes,
        )

    def _request(
        self,
        *,
        profile: ProviderProfile,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum_response_bytes: int,
    ) -> RawHttpResponse:
        parsed = urlsplit(profile.origin)
        if parsed.hostname is None:
            raise ProviderTransportError("provider profile has no network host")
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=self._timeout_seconds,
            context=self._ssl_context,
        )
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            response = connection.getresponse()
            raw = response.read(maximum_response_bytes + 1)
            if len(raw) > maximum_response_bytes:
                raise ProviderTransportError("provider response exceeded the byte limit")
            if 300 <= response.status < 400:
                raise ProviderRedirectError("provider redirects are forbidden")
            content_type = response.getheader("Content-Type")
            normalized_headers = (
                {"content-type": content_type} if content_type is not None else {}
            )
            return RawHttpResponse(
                status=response.status,
                headers=normalized_headers,
                body=raw,
            )
        except (OSError, http.client.HTTPException):
            raise ProviderTransportError("direct HTTPS provider exchange failed") from None
        finally:
            connection.close()


class ResponsesBroker:
    """Consume one exact preflight attestation before loading campaign credentials."""

    def __init__(self, transport: ProviderTransport | None = None) -> None:
        self._transport = transport or DirectHttpsTransport()

    def open_trial_sender(
        self,
        *,
        configuration: ResolvedProviderConfig,
        runner: CampaignRunner,
        trial_id: Identifier,
        policy: CanaryPolicy,
        attestation: CanaryAttestation,
        credentials: CredentialSource,
    ) -> ResponsesCampaign:
        """Open one trial-bound sender after its exact credential-free preflight."""

        if runner.model_set.provider_config_digest != configuration.digest:
            raise ProviderProtocolError(
                "provider configuration does not match the frozen campaign model set"
            )
        try:
            trial = next(item for item in runner.schedule.trials if item.trial_id == trial_id)
        except StopIteration:
            raise ValueError("trial is not part of the frozen campaign schedule") from None
        budget = CampaignProviderBudget(runner)
        manifest_binding = attestation.runtime_surface_manifest.binding
        if (
            manifest_binding.campaign_digest != runner.campaign.digest
            or manifest_binding.campaign_schedule_digest != runner.schedule.digest
            or manifest_binding.scheduled_trial_digest != trial.digest
            or manifest_binding.task_release_digest != trial.binding.task_release_digest
            or manifest_binding.environment_spec_digest != trial.binding.environment_digest
            or manifest_binding.harness_digest != trial.binding.harness_digest
        ):
            raise ProviderProtocolError("runtime surface manifest does not match the trial")
        return self._open(
            configuration=configuration,
            campaign_digest=runner.campaign.digest,
            campaign_schedule_digest=runner.schedule.digest,
            bound_trial_id=trial_id,
            policy=policy,
            attestation=attestation,
            credentials=credentials,
            budget=budget,
        )

    def open_probe(
        self,
        *,
        configuration: ResolvedProviderConfig,
        campaign_digest: Digest,
        policy: CanaryPolicy,
        attestation: CanaryAttestation,
        credentials: CredentialSource,
        budget: StandaloneProviderBudget,
    ) -> ResponsesCampaign:
        """Open a bounded provider probe before a campaign manifest exists."""

        return self._open(
            configuration=configuration,
            campaign_digest=campaign_digest,
            campaign_schedule_digest=None,
            bound_trial_id=None,
            policy=policy,
            attestation=attestation,
            credentials=credentials,
            budget=budget,
        )

    def _open(
        self,
        *,
        configuration: ResolvedProviderConfig,
        campaign_digest: Digest,
        campaign_schedule_digest: Digest | None,
        bound_trial_id: Identifier | None,
        policy: CanaryPolicy,
        attestation: CanaryAttestation,
        credentials: CredentialSource,
        budget: ProviderBudget,
    ) -> ResponsesCampaign:
        if type(attestation) is not CanaryAttestation:
            raise ProviderProtocolError("provider campaigns require a concrete canary attestation")
        if (
            policy.provider_profile_digest != configuration.profile.digest
            or policy.provider_config_digest != configuration.digest
            or policy.budget_binding_digest != budget.binding_digest
            or budget.campaign_digest != campaign_digest
        ):
            raise ProviderProtocolError("canary policy does not match the provider campaign")
        manifest = attestation.runtime_surface_manifest
        manifest_binding = manifest.binding
        if (
            manifest_binding.campaign_digest != campaign_digest
            or manifest_binding.provider_profile_digest != configuration.profile.digest
            or manifest_binding.provider_config_digest != configuration.digest
            or manifest_binding.budget_binding_digest != budget.binding_digest
            or (
                campaign_schedule_digest is not None
                and manifest_binding.campaign_schedule_digest != campaign_schedule_digest
            )
        ):
            raise ProviderProtocolError("runtime surface manifest does not match the campaign")
        grant, receipt = _consume_attestation_for_provider_access(
            policy=policy,
            attestation=attestation,
        )
        canary_evidence = ProviderCanaryEvidence(
            policy=policy,
            receipt=receipt,
            runtime_surface_manifest=manifest,
        )
        access = credentials.acquire(grant=grant)
        if access.resolved != configuration:
            access.close()
            raise ProviderProtocolError(
                "credential source returned a different provider projection"
            )
        return ResponsesCampaign(
            configuration=configuration,
            campaign_digest=campaign_digest,
            campaign_schedule_digest=campaign_schedule_digest,
            bound_trial_id=bound_trial_id,
            canary_evidence=canary_evidence,
            access=access,
            budget=budget,
            transport=self._transport,
            _authority=_BROKER_AUTHORITY,
        )


class ResponsesCampaign:
    """Controller-only provider session with shared atomic campaign budget."""

    __slots__ = (
        "_access",
        "_bound_trial_id",
        "_budget",
        "_campaign_digest",
        "_campaign_schedule_digest",
        "_canary_evidence",
        "_closed",
        "_configuration",
        "_security_binding",
        "_transport",
    )

    def __init__(
        self,
        *,
        configuration: ResolvedProviderConfig,
        campaign_digest: Digest,
        campaign_schedule_digest: Digest | None,
        bound_trial_id: Identifier | None,
        canary_evidence: ProviderCanaryEvidence,
        access: ProviderAccessLease,
        budget: ProviderBudget,
        transport: ProviderTransport,
        _authority: object,
    ) -> None:
        if _authority is not _BROKER_AUTHORITY:
            access.close()
            raise ProviderProtocolError("provider senders can only be issued by the broker")
        if type(canary_evidence) is not ProviderCanaryEvidence:
            access.close()
            raise ProviderProtocolError("provider sender requires canonical canary evidence")
        binding = canary_evidence.runtime_surface_manifest.binding
        if (
            binding.campaign_digest != campaign_digest
            or binding.provider_profile_digest != configuration.profile.digest
            or binding.provider_config_digest != configuration.digest
            or binding.budget_binding_digest != budget.binding_digest
            or (
                campaign_schedule_digest is not None
                and binding.campaign_schedule_digest != campaign_schedule_digest
            )
        ):
            access.close()
            raise ProviderProtocolError("provider canary evidence does not match the sender")
        self._configuration = configuration
        self._campaign_digest = campaign_digest
        self._campaign_schedule_digest = campaign_schedule_digest
        self._bound_trial_id = bound_trial_id
        self._canary_evidence = canary_evidence
        self._access = access
        self._budget = budget
        self._transport = transport
        self._security_binding = ProviderSecurityBinding(
            canary_receipt_digest=canary_evidence.receipt.digest,
            runtime_surface_manifest_digest=canary_evidence.runtime_surface_manifest.digest,
            budget_binding_digest=budget.binding_digest,
        )
        self._closed = False

    @property
    def canary_receipt(self) -> CanaryReceipt:
        return self._canary_evidence.receipt

    @property
    def provider_canary_evidence(self) -> ProviderCanaryEvidence:
        return self._canary_evidence

    @property
    def runtime_surface_manifest(self) -> RuntimeSurfaceManifest:
        return self._canary_evidence.runtime_surface_manifest

    @property
    def provider_security_binding(self) -> ProviderSecurityBinding:
        return self._security_binding

    @property
    def bound_trial_id(self) -> Identifier | None:
        return self._bound_trial_id

    @property
    def campaign_digest(self) -> Digest:
        return self._campaign_digest

    @property
    def campaign_schedule_digest(self) -> Digest | None:
        return self._campaign_schedule_digest

    @property
    def provider_profile_digest(self) -> Digest:
        return self._configuration.profile.digest

    @property
    def provider_config_digest(self) -> Digest:
        return self._configuration.digest

    @property
    def budget_binding_digest(self) -> Digest:
        return self._budget.binding_digest

    def request(
        self,
        *,
        trial_id: Identifier,
        request_key: Identifier,
        request: ResponsesRequest,
        observer: ResponsesExchangeObserver | None = None,
    ) -> ResponsesResult:
        if self._closed:
            raise ProviderProtocolError("provider campaign is closed")
        if self._bound_trial_id is not None and trial_id != self._bound_trial_id:
            raise ProviderProtocolError("provider sender is bound to another campaign trial")
        if self._bound_trial_id is not None and observer is None:
            raise ProviderProtocolError("campaign provider requests require a run journal observer")
        claim = request.token_claim
        body = request._wire_body()
        if len(body) > MAX_PROVIDER_TRANSCRIPT_REQUEST_BYTES:
            raise ProviderProtocolError("serialized request exceeds the wire byte limit")
        reservation = self._budget.reserve_provider_attempt(
            trial_id=trial_id,
            request_key=request_key,
            requested_model=request.model,
            token_claim=claim,
            security_binding=self._security_binding,
        )
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            self._access.credential.authorize(
                headers,
                profile_digest=self._configuration.profile.digest,
            )
            if observer is not None:
                observer.request_reserved(
                    trial_id=trial_id,
                    provider_profile_digest=self._configuration.profile.digest,
                    provider_config_digest=self._configuration.digest,
                    security_binding=self._security_binding,
                    canary_evidence=self._canary_evidence,
                    request_body=body,
                )
        except BaseException:
            reservation.cancel()
            raise

        reservation.mark_dispatched()
        try:
            raw = self._transport.exchange(
                profile=self._configuration.profile,
                headers=immutable_headers(headers),
                body=body,
            )
            if not 200 <= raw.status < 300:
                raise ProviderHttpError(raw.status)
            if not raw.headers.get("content-type", "").casefold().startswith(
                "application/json"
            ):
                raise ProviderProtocolError("provider success response is not JSON")
            result = _decode_result(raw.body)
            _validate_tool_calls(request, result)
        except BaseException as error:
            reservation.settle_failed(failure_condition=_retry_condition(error))
            raise
        if observer is not None:
            try:
                observer.response_received(response_body=raw.body, result=result)
            except BaseException:
                reservation.settle_completed(
                    usage=result.usage,
                    provider_reported_model=result.reported_model,
                    provider_reported_service_tier=result.reported_service_tier,
                    provider_response_status=result.status,
                )
                raise
        reservation.settle_completed(
            usage=result.usage,
            provider_reported_model=result.reported_model,
            provider_reported_service_tier=result.reported_service_tier,
            provider_response_status=result.status,
        )
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._access.close()
        self._closed = True

    def __enter__(self) -> Self:
        if self._closed:
            raise ProviderProtocolError("provider campaign is closed")
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return "ResponsesCampaign(<controller-only>)"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("provider campaign senders cannot be serialized")


def _retry_condition(error: BaseException) -> RetryCondition | None:
    if isinstance(error, ProviderHttpError):
        if error.status == 429:
            return RetryCondition.RATE_LIMITED
        if 500 <= error.status < 600:
            return RetryCondition.SERVER_UNAVAILABLE
        return None
    if type(error) is ProviderTransportError:
        return RetryCondition.CONNECT_FAILURE
    return None


def _decode_result(raw: bytes) -> ResponsesResult:
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderProtocolError("provider response is not valid UTF-8 JSON") from None
    if not isinstance(decoded, dict):
        raise ProviderProtocolError("provider response must be an object")
    response_id = decoded.get("id")
    reported_model = decoded.get("model")
    reported_service_tier = decoded.get("service_tier")
    status = decoded.get("status")
    output = decoded.get("output")
    if (
        not isinstance(response_id, str)
        or not isinstance(reported_model, str)
        or not isinstance(status, str)
        or not isinstance(output, list)
    ):
        raise ProviderProtocolError("provider response lacks required typed fields")
    if reported_service_tier is not None:
        try:
            reported_service_tier = _SERVICE_TIER.validate_python(reported_service_tier)
        except ValidationError:
            raise ProviderProtocolError("provider service tier is invalid") from None

    outputs: list[OutputText | FunctionCall | Refusal | ReasoningSummary] = []
    call_ids: set[str] = set()
    for item in output:
        if not isinstance(item, dict):
            raise ProviderProtocolError("provider output item must be an object")
        item_type = item.get("type")
        if item_type == "message":
            content = item.get("content")
            if not isinstance(content, list):
                raise ProviderProtocolError("provider message content must be a list")
            for part in content:
                if not isinstance(part, dict):
                    raise ProviderProtocolError("provider message part must be an object")
                part_type = part.get("type")
                if part_type == "output_text":
                    text = part.get("text")
                    if not isinstance(text, str):
                        raise ProviderProtocolError("provider output text must be a string")
                    outputs.append(OutputText(text))
                elif part_type == "refusal":
                    refusal = part.get("refusal")
                    if not isinstance(refusal, str):
                        raise ProviderProtocolError("provider refusal must be a string")
                    outputs.append(Refusal(refusal))
                else:
                    raise ProviderProtocolError("provider message part type is unsupported")
        elif item_type == "function_call":
            call_id = item.get("call_id")
            name = item.get("name")
            arguments = item.get("arguments")
            call_status = item.get("status")
            if (
                not isinstance(call_id, str)
                or not isinstance(name, str)
                or not isinstance(arguments, str)
            ):
                raise ProviderProtocolError("provider function call fields must be strings")
            if call_id in call_ids:
                raise ProviderProtocolError("provider function call identifiers must be unique")
            if call_status is not None:
                try:
                    call_status = FunctionCallStatus(call_status)
                except (TypeError, ValueError):
                    raise ProviderProtocolError(
                        "provider function call status is unsupported"
                    ) from None
            try:
                arguments_value = json.loads(arguments)
            except json.JSONDecodeError:
                raise ProviderProtocolError("provider function arguments are not JSON") from None
            if not isinstance(arguments_value, dict):
                raise ProviderProtocolError("provider function arguments must be a JSON object")
            call_ids.add(call_id)
            outputs.append(
                FunctionCall(
                    call_id=call_id,
                    name=name,
                    arguments=arguments,
                    status=call_status,
                )
            )
        elif item_type == "reasoning":
            summary = item.get("summary", [])
            if not isinstance(summary, list):
                raise ProviderProtocolError("provider reasoning summary must be a list")
            texts: list[str] = []
            for part in summary:
                if not isinstance(part, dict) or part.get("type") != "summary_text":
                    raise ProviderProtocolError("provider reasoning summary item is unsupported")
                text = part.get("text")
                if not isinstance(text, str):
                    raise ProviderProtocolError("provider reasoning summary text must be a string")
                texts.append(text)
            outputs.append(ReasoningSummary(tuple(texts)))
        else:
            raise ProviderProtocolError("provider output item type is unsupported")
    try:
        typed_status = ResponseStatus(status)
    except ValueError:
        raise ProviderProtocolError("provider response status is unsupported") from None
    return ResponsesResult(
        response_id=response_id,
        reported_model=reported_model,
        reported_service_tier=reported_service_tier,
        status=typed_status,
        outputs=tuple(outputs),
        usage=_decode_usage(decoded.get("usage")),
    )


def _validate_tool_calls(request: ResponsesRequest, result: ResponsesResult) -> None:
    calls = [output for output in result.outputs if isinstance(output, FunctionCall)]
    if request.tool_choice_required and len(calls) != 1:
        raise ProviderProtocolError("provider did not return the one required tool call")
    for output in result.outputs:
        if isinstance(output, FunctionCall) and not request._accepts_tool_call(output.name):
            raise ProviderProtocolError("provider called a tool outside the request contract")


def _decode_usage(value: object) -> ProviderUsage | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProviderProtocolError("provider usage must be an object")
    input_tokens = _usage_counter(value, "input_tokens")
    output_tokens = _usage_counter(value, "output_tokens")
    total_tokens = _usage_counter(value, "total_tokens")
    cached = _nested_usage_counter(value, "input_tokens_details", "cached_tokens")
    reasoning = _nested_usage_counter(value, "output_tokens_details", "reasoning_tokens")
    try:
        return ProviderUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cached_input_tokens=cached,
            reasoning_tokens=reasoning,
        )
    except ValueError as error:
        raise ProviderProtocolError("provider usage counters are inconsistent") from error


def _usage_counter(value: Mapping[str, object], name: str) -> int:
    counter = value.get(name)
    if type(counter) is not int or counter < 0:
        raise ProviderProtocolError("provider usage lacks a required non-negative counter")
    return counter


def _nested_usage_counter(
    value: Mapping[str, object],
    group_name: str,
    counter_name: str,
) -> int | None:
    group = value.get(group_name)
    if group is None:
        return None
    if not isinstance(group, dict):
        raise ProviderProtocolError("provider usage detail must be an object")
    counter = group.get(counter_name)
    if counter is None:
        return None
    if type(counter) is not int or counter < 0:
        raise ProviderProtocolError("provider usage detail must be a non-negative counter")
    return counter
