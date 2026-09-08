"""Descriptor and grant boundaries for explicitly configured credential files."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import edagym.security.credentials as credential_module
from edagym.canonical import canonical_bytes
from edagym.cli_support.campaigns import (
    CampaignCliCommand,
    ProviderInspectRequest,
    execute_campaign_command,
)
from edagym.config.model import (
    CredentialConfig,
    CredentialDecoder,
    EdaGymConfig,
    ProfileConfig,
    ProfileViewConfig,
    ProviderConfig,
    SiteConfig,
)
from edagym.config.resolve import freeze_profile
from edagym.providers.model import RUST_CAT_PROFILE, ProviderDefaults, ResolvedProviderConfig
from edagym.providers.provider_budget import StandaloneProviderBudget
from edagym.security.credentials import (
    ConfiguredCredentialSource,
    CredentialFormatError,
    CredentialSecurityError,
    ProviderAccessGrant,
    _consume_attestation_for_provider_access,
)
from tests.test_provider_security import _budget, _clean_attestation, _digest


def _source(
    root: Path,
    *,
    document: object,
    decoder: CredentialDecoder = CredentialDecoder.CODEX_API_KEY_JSON,
) -> tuple[ConfiguredCredentialSource, ResolvedProviderConfig, CredentialConfig]:
    directory = root / "credentials"
    directory.mkdir(parents=True, mode=0o700)
    path = directory / "auth.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    credential = CredentialConfig(
        credential_id="provider_auth", decoder=decoder, file_path=path.absolute()
    )
    configuration = ResolvedProviderConfig(
        selected_provider_label="declared_route",
        profile=RUST_CAT_PROFILE,
        defaults=ProviderDefaults(requested_model="route.test"),
        credential_source_digest=credential.digest,
    )
    return (
        ConfiguredCredentialSource(configuration=configuration, credential=credential),
        configuration,
        credential,
    )


def _grant(configuration: ResolvedProviderConfig, root: Path) -> ProviderAccessGrant:
    campaign_digest = _digest(f"credential-grant-{root.name}")
    budget = StandaloneProviderBudget(campaign_digest=campaign_digest, ledger=_budget())
    policy, attestation = _clean_attestation(configuration, campaign_digest, budget, root)
    grant, _ = _consume_attestation_for_provider_access(policy=policy, attestation=attestation)
    return grant


def test_provider_inspection_resolves_frozen_paths_without_reading_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, expected, credential = _source(tmp_path, document={"OPENAI_API_KEY": "stub"})
    profile = ProfileConfig(
        profile_id="local",
        site_id="local",
        participant=ProfileViewConfig(),
        evaluator=ProfileViewConfig(),
    )
    config = EdaGymConfig(
        sites=(SiteConfig(site_id="local", state_root=tmp_path / "state"),),
        profiles=(profile,),
        credentials=(credential.model_copy(update={"file_path": Path("credentials/auth.json")}),),
        providers=(
            ProviderConfig(
                provider_id=expected.selected_provider_label,
                profile=expected.profile,
                defaults=expected.defaults,
                credential_reference=credential.credential_id,
            ),
        ),
        source_path=tmp_path / "site.toml",
    )
    snapshot = freeze_profile(config, profile)
    request = ProviderInspectRequest(
        config_snapshot=snapshot, provider_id=expected.selected_provider_label
    )
    path = tmp_path / "inspect.json"
    path.write_bytes(canonical_bytes(request))
    path.chmod(0o600)

    def refuse_open(*args: object, **kwargs: object) -> bytearray:
        raise AssertionError("provider inspection opened a credential file")

    monkeypatch.setattr(credential_module, "_read_owned_private_file", refuse_open)
    result, status = execute_campaign_command(CampaignCliCommand.INSPECT, path)
    assert status == 0 and result == expected
    assert b"stub" not in canonical_bytes(result)


def test_configured_source_requires_consumed_preflight_before_opening_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, configuration, _ = _source(tmp_path, document={"OPENAI_API_KEY": "stub"})
    opened: list[str] = []
    read = credential_module._read_owned_private_file

    def observe(directory_fd: int, name: str, *, uid: int) -> bytearray:
        opened.append(name)
        return read(directory_fd, name, uid=uid)

    monkeypatch.setattr(credential_module, "_read_owned_private_file", observe)
    monkeypatch.setenv("HOME", "/unavailable/ambient-home")
    monkeypatch.setenv("CODEX_HOME", "/unavailable/ambient-codex")
    with pytest.raises(TypeError):
        source.acquire(grant=object())  # type: ignore[arg-type]
    with pytest.raises(CredentialSecurityError):
        ProviderAccessGrant(
            provider_profile_digest=configuration.profile.digest,
            provider_config_digest=configuration.digest,
            campaign_digest=_digest("forged-campaign"),
            budget_binding_digest=_digest("forged-budget"),
            receipt_digest=_digest("forged-receipt"),
            manifest_digest=_digest("forged-manifest"),
            _issuer=object(),
        )
    assert not opened
    grant = _grant(configuration, tmp_path / "preflight")
    with source.acquire(grant=grant) as access:
        headers: dict[str, str] = {}
        access.credential.authorize(headers, profile=configuration.profile)
        assert headers["Authorization"] == "Bearer stub"
    assert opened == ["auth.json"]
    opened.clear()
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=grant)
    assert not opened


def test_credential_locator_is_bound_to_the_provider_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, configuration, credential = _source(tmp_path, document={"OPENAI_API_KEY": "stub"})
    other = credential.model_copy(
        update={"file_path": credential.file_path.with_name("other.json")}
    )
    with pytest.raises(CredentialSecurityError):
        ConfiguredCredentialSource(configuration=configuration, credential=other)
    other_config = configuration.model_copy(update={"credential_source_digest": other.digest})
    grant = _grant(other_config, tmp_path / "wrong-source-preflight")

    def refuse_open(*args: object, **kwargs: object) -> bytearray:
        raise AssertionError("a mismatched credential grant reached its file")

    monkeypatch.setattr(credential_module, "_read_owned_private_file", refuse_open)
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=grant)


def test_configured_source_rejects_links_public_modes_and_nonregular_files(tmp_path: Path) -> None:
    source, configuration, credential = _source(tmp_path, document={"OPENAI_API_KEY": "stub"})
    path = credential.file_path
    path.chmod(0o644)
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=_grant(configuration, tmp_path / "public-file"))
    path.chmod(0o600)
    alias = path.with_name("alias")
    alias.hardlink_to(path)
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=_grant(configuration, tmp_path / "hardlink"))
    alias.unlink()
    path.replace(alias)
    path.symlink_to(alias)
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=_grant(configuration, tmp_path / "symlink"))
    path.unlink()
    os.mkfifo(path, mode=0o600)
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=_grant(configuration, tmp_path / "fifo"))


@pytest.mark.parametrize(
    ("decoder", "valid", "wrong"),
    [
        (
            CredentialDecoder.CODEX_API_KEY_JSON,
            {"OPENAI_API_KEY": "stub"},
            {"nested": {"OPENAI_API_KEY": "stub"}},
        ),
        (
            CredentialDecoder.CLAUDE_SETTINGS_API_KEY,
            {"env": {"ANTHROPIC_API_KEY": "stub", "ANTHROPIC_AUTH_TOKEN": "unselected"}},
            {"env": {"ANTHROPIC_AUTH_TOKEN": "stub"}},
        ),
        (
            CredentialDecoder.CLAUDE_SETTINGS_AUTH_TOKEN,
            {"env": {"ANTHROPIC_AUTH_TOKEN": "stub", "ANTHROPIC_API_KEY": "unselected"}},
            {"env": {"ANTHROPIC_API_KEY": "stub"}},
        ),
    ],
)
def test_credential_decoder_uses_only_its_declared_field(
    tmp_path: Path, decoder: CredentialDecoder, valid: object, wrong: object
) -> None:
    source, configuration, credential = _source(tmp_path, document=valid, decoder=decoder)
    with source.acquire(grant=_grant(configuration, tmp_path / "valid")) as access:
        headers: dict[str, str] = {}
        access.credential.authorize(headers, profile=configuration.profile)
        assert headers["Authorization"] == "Bearer stub"
    credential.file_path.write_text(json.dumps(wrong))
    with pytest.raises(CredentialFormatError):
        source.acquire(grant=_grant(configuration, tmp_path / "wrong-field"))
    credential.file_path.write_text('{"env":{},"env":{},"OPENAI_API_KEY":"stub"}')
    with pytest.raises(CredentialFormatError):
        source.acquire(grant=_grant(configuration, tmp_path / "duplicate-key"))


def test_credential_replacement_during_read_is_rejected_and_buffer_erased(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, configuration, credential = _source(tmp_path, document={"OPENAI_API_KEY": "original"})
    replacement = credential.file_path.with_name("replacement")
    replacement.write_text('{"OPENAI_API_KEY":"replacement"}')
    replacement.chmod(0o600)
    original = credential_module._read_stable_bytes
    observed: list[bytearray] = []

    def replace_after_open(descriptor: int) -> bytearray:
        content = original(descriptor)
        observed.append(content)
        credential.file_path.unlink()
        replacement.replace(credential.file_path)
        return content

    monkeypatch.setattr(credential_module, "_read_stable_bytes", replace_after_open)
    with pytest.raises(CredentialSecurityError):
        source.acquire(grant=_grant(configuration, tmp_path / "replacement-preflight"))
    assert observed and all(value == bytearray(len(value)) for value in observed)
