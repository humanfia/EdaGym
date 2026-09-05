"""Semantic evidence for the canonical campaign command boundary."""

from __future__ import annotations

import json
from pathlib import Path

from edagym.canonical import canonical_bytes
from edagym.cli_support.campaigns import (
    CampaignCliCommand,
    CampaignCliFailure,
    CampaignCliFailureReason,
    ProviderDiscoverRequest,
    execute_campaign_command,
)
from edagym.providers.campaign import ModelCategory, ModelReferenceKind
from edagym.providers.model import (
    ProviderDefaults,
    ProviderProfile,
    ResolvedProviderConfig,
)
from edagym.providers.model_discovery import (
    ModelDiscoverySnapshot,
    ModelDiscoverySource,
    ModelRouteCandidate,
)


def test_campaign_discovery_command_requires_one_canonical_document(tmp_path: Path) -> None:
    configuration = ResolvedProviderConfig(
        selected_provider_label="DeclaredGateway",
        profile=ProviderProfile(
            logical_id="declared.gateway",
            origin="https://gateway.test",
            responses_path="/v1/responses",
        ),
        defaults=ProviderDefaults(requested_model="route-frontier"),
    )
    request = ProviderDiscoverRequest(
        configuration=configuration,
        explicit_candidates=(
            ModelRouteCandidate(
                route_id="frontier",
                requested_model="route-frontier",
                reference_kind=ModelReferenceKind.UNKNOWN,
                categories=(ModelCategory.FRONTIER_REASONING,),
            ),
        ),
    )
    request_path = tmp_path / "discover.json"
    request_path.write_bytes(canonical_bytes(request) + b"\n")

    result, status = execute_campaign_command(
        CampaignCliCommand.DISCOVER,
        request_path,
    )

    assert status == 0
    assert isinstance(result, ModelDiscoverySnapshot)
    assert result.source is ModelDiscoverySource.EXPLICIT_CANDIDATES
    assert result.provider_config_digest == configuration.digest

    request_path.write_text(
        json.dumps(request.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    rejected, rejected_status = execute_campaign_command(
        CampaignCliCommand.DISCOVER,
        request_path,
    )
    assert rejected_status == 1
    assert isinstance(rejected, CampaignCliFailure)
    assert rejected.reason is CampaignCliFailureReason.INVALID_REQUEST
