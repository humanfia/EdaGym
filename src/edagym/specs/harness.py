"""Canonical harness identities shared by configuration, campaigns, and execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from edagym.canonical import canonical_digest
from edagym.providers.model import WireProtocol
from edagym.specs.common import Digest, Identifier, JcsPositiveInt, StrictModel


class HarnessKind(StrEnum):
    CONTROLLED_AGENT = "controlled_agent"
    NATIVE_CLI = "native_cli"


class NativeCliKind(StrEnum):
    CODEX_EXEC = "codex_exec"
    CLAUDE_CODE = "claude_code"

    @property
    def wire_protocol(self) -> WireProtocol:
        return (
            WireProtocol.RESPONSES if self is NativeCliKind.CODEX_EXEC else WireProtocol.MESSAGES
        )


class MeteredUsagePolicy(StrEnum):
    EXACT = "exact"


class _ProviderHarnessBinding(StrictModel):
    harness_id: Identifier
    provider_profile_digest: Digest
    provider_config_digest: Digest
    wire_protocol: WireProtocol
    instruction_digest: Digest
    tool_schema_digest: Digest
    scaffold_digest: Digest
    usage_policy: Literal[MeteredUsagePolicy.EXACT] = MeteredUsagePolicy.EXACT

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="campaign-harness-v3")


class MeteredProviderHarnessBinding(_ProviderHarnessBinding):
    kind: Literal[HarnessKind.CONTROLLED_AGENT] = HarnessKind.CONTROLLED_AGENT
    wire_protocol: Literal[WireProtocol.RESPONSES] = WireProtocol.RESPONSES
    maximum_requests_per_action: JcsPositiveInt


class NativeCliHarnessBinding(_ProviderHarnessBinding):
    kind: Literal[HarnessKind.NATIVE_CLI] = HarnessKind.NATIVE_CLI
    cli: NativeCliKind
    executable_digest: Digest
    transport_digest: Digest
    cli_version: Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[ -~]+$")]

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        if self.wire_protocol is not self.cli.wire_protocol:
            raise ValueError("native harness protocol differs from its CLI adapter")
        return self


CampaignHarnessBinding = Annotated[
    MeteredProviderHarnessBinding | NativeCliHarnessBinding,
    Field(discriminator="kind"),
]
