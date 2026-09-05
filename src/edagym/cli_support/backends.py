"""Backend qualification and environment verification at the CLI boundary."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from edagym.canonical import canonical_digest
from edagym.cli_support.documents import open_artifact_store
from edagym.cli_support.errors import CliFailure
from edagym.drivers.catalog import backend_by_id
from edagym.drivers.closure import ResolvedExecutionClosure
from edagym.drivers.deployment import (
    BackendDeploymentConfiguration,
    BackendDeploymentRegistry,
    SiteContainerConfiguration,
    load_backend_deployment_configuration,
    load_backend_deployment_registry,
)
from edagym.drivers.fixtures import fixture_for
from edagym.drivers.fixtures.model import FixtureRole
from edagym.drivers.licensing import (
    CommercialQualificationAuthorizationError,
    CommercialQualificationLicenseBroker,
    HostModuleLicenseProvider,
)
from edagym.drivers.model import (
    BackendDefinition,
    BackendProbe,
    QualificationState,
    UnavailableReason,
    Vendor,
)
from edagym.drivers.probe import (
    AuthorizedBackendResolutionError,
    AuthorizedBackendResolutionReason,
    ResolvedInstallation,
    probe_backend,
    resolve_authorized_commercial_backend,
)
from edagym.drivers.qualification import (
    BackendQualification,
    QualificationDisposition,
    qualify_backend,
    qualify_commercial_backend,
)
from edagym.drivers.qualification_resources import QualificationResourceGrant
from edagym.executors.asset_policy import AssetSourcePolicy, load_system_asset_source_policy
from edagym.executors.licenses import LeaseState, LicenseLease, LicenseProvider, LicenseUnavailable
from edagym.specs.common import ArtifactClass, Capability
from edagym.specs.environment import (
    AttestedHostToolLocator,
    BrokeredHostToolExecutor,
    EnvironmentSpec,
    ImageToolLocator,
    ToolBinding,
)

_UNSATISFIED = 1
_INCOMPLETE = 3


@dataclass(frozen=True, slots=True, repr=False)
class FlowHostBindings:
    """Process-local host paths, clean environments, and opaque license providers."""

    tool_paths: Mapping[str, Path]
    tool_environments: Mapping[str, Mapping[str, str]]
    tool_closures: Mapping[str, ResolvedExecutionClosure]
    site_container_configurations: Mapping[str, SiteContainerConfiguration]
    license_providers: Mapping[str, LicenseProvider]
    asset_source_policy: AssetSourcePolicy

    def __repr__(self) -> str:
        return "FlowHostBindings(<restricted>)"


class _EnvironmentLicenseProvider:
    """Route one environment provider identity across its bound feature classes."""

    def __init__(
        self,
        provider_id: str,
        providers: Mapping[str, HostModuleLicenseProvider],
    ) -> None:
        if not providers or any(item.provider_id != provider_id for item in providers.values()):
            raise ValueError("license provider routes must share one provider identity")
        self.provider_id = provider_id
        self._providers = MappingProxyType(dict(providers))

    def acquire(
        self,
        *,
        feature_class: str,
        run_id: str,
        ttl_seconds: int,
    ) -> LicenseLease:
        provider = self._providers.get(feature_class)
        if provider is None:
            raise LicenseUnavailable("license feature is unavailable")
        return provider.acquire(
            feature_class=feature_class,
            run_id=run_id,
            ttl_seconds=ttl_seconds,
        )

    def renew(self, lease: LicenseLease, *, ttl_seconds: int) -> LeaseState:
        provider = self._providers.get(lease.feature_class)
        if provider is None or lease.provider_id != self.provider_id:
            raise LicenseUnavailable("license lease is not owned by this provider")
        return provider.renew(lease, ttl_seconds=ttl_seconds)

    def release(self, lease: LicenseLease) -> LeaseState:
        provider = self._providers.get(lease.feature_class)
        if provider is None or lease.provider_id != self.provider_id:
            raise LicenseUnavailable("license lease is not owned by this provider")
        return provider.release(lease)


def probe_declared_backends(
    definitions: Iterable[BackendDefinition],
    *,
    backend_deployment: Path | None = None,
) -> tuple[BackendProbe, ...]:
    """Probe catalog backends from one optional descriptor-stable registry."""

    selected = tuple(definitions)
    if backend_deployment is None:
        return tuple(probe_backend(definition)[0] for definition in selected)
    registry = _load_backend_registry(backend_deployment)
    if not registry.revalidate():
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED)
    try:
        for tool_id in registry.tool_ids:
            backend_by_id(tool_id)
    except KeyError:
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED) from None
    probes = tuple(_probe_with_registry(definition, registry) for definition in selected)
    if not registry.revalidate():
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED)
    return probes


def qualify_declared_backend(
    definition: BackendDefinition,
    environment: EnvironmentSpec,
    *,
    capability: Capability | None,
    scratch_root: Path,
    store_root: Path,
    key_file: Path | None,
    timeout_seconds: int,
    authorize_commercial: bool,
    backend_deployment: Path | None = None,
) -> BackendQualification:
    """Run the canonical fixture under the environment-owned artifact policy."""

    if timeout_seconds < 1 or timeout_seconds > 3600:
        raise CliFailure("invalid-qualification-timeout", status=_UNSATISFIED)
    try:
        resource_grant = QualificationResourceGrant(
            limits=environment.resources,
            command_timeout_seconds=timeout_seconds,
        )
    except ValueError:
        raise CliFailure("invalid-qualification-resource-grant", status=_UNSATISFIED) from None
    if authorize_commercial and definition.vendor is Vendor.OPEN_SOURCE:
        raise CliFailure("commercial-authorization-not-applicable", status=_UNSATISFIED)
    requested = None if capability is None else (capability,)
    if capability is not None and capability not in definition.capabilities:
        raise CliFailure("backend-capability-mismatch", status=_UNSATISFIED)
    deployment_configuration = _load_backend_configuration(
        backend_deployment,
        definition.tool_id,
        required=definition.vendor is not Vendor.OPEN_SOURCE,
    )
    probe, installation = probe_backend(
        definition,
        deployment_configuration=deployment_configuration,
    )
    if not authorize_commercial or definition.vendor is Vendor.OPEN_SOURCE:
        store = None
        disclosure = None
        if probe.state is QualificationState.INVOCABLE:
            disclosure = environment.artifact_policy.persistent_disclosure(
                ArtifactClass.EVIDENCE
            )
            if disclosure is None:
                raise CliFailure("evidence-retention-disabled", status=_UNSATISFIED)
            store = open_artifact_store(store_root, environment, key_file)
        try:
            return qualify_backend(
                definition,
                probe,
                installation,
                scratch_root=scratch_root,
                capabilities=requested,
                artifact_store=store,
                artifact_disclosure=disclosure,
                deployment_configuration=deployment_configuration,
                resource_grant=resource_grant,
            )
        except (OSError, ValueError, RuntimeError):
            raise CliFailure("backend-qualification-failed", status=_INCOMPLETE) from None

    if capability is None:
        raise CliFailure("commercial-capability-required", status=_UNSATISFIED)
    return _qualify_commercial(
        definition,
        probe,
        environment,
        capability=capability,
        scratch_root=scratch_root,
        store_root=store_root,
        key_file=key_file,
        resource_grant=resource_grant,
        deployment_configuration=deployment_configuration,
    )


def qualification_status(qualification: BackendQualification) -> int:
    if qualification.disposition is QualificationDisposition.CONFORMANT:
        return 0
    if qualification.disposition in {
        QualificationDisposition.UNAVAILABLE,
        QualificationDisposition.NONCONFORMANT,
    }:
        return _UNSATISFIED
    return _INCOMPLETE


def verify_environment(
    environment: EnvironmentSpec,
    *,
    backend_deployment: Path | None = None,
) -> tuple[dict[str, object], bool]:
    """Compare local backend evidence with every host-resolved tool binding."""

    results: list[dict[str, object]] = []
    satisfied = True
    for binding in environment.tool_bindings:
        result = _verify_tool_binding(binding, backend_deployment=backend_deployment)
        results.append(result)
        satisfied &= result["state"] == "verified"
    return (
        {
            "environment_id": environment.identity.environment_id,
            "environment_digest": environment.digest,
            "verified": satisfied,
            "tools": results,
        },
        satisfied,
    )


def resolve_flow_host_bindings(
    environment: EnvironmentSpec,
    tool_ids: frozenset[str],
    *,
    authorize_commercial: bool,
    backend_deployment: Path | None = None,
) -> FlowHostBindings:
    """Resolve the exact broker inputs without inheriting the caller's environment."""

    if not isinstance(environment.executor, BrokeredHostToolExecutor):
        raise CliFailure("flow-brokered-executor-required", status=_UNSATISFIED)
    if not tool_ids:
        raise CliFailure("flow-tools-required", status=_UNSATISFIED)
    asset_source_policy = (
        load_system_asset_source_policy()
        if backend_deployment is None
        else _load_backend_registry(backend_deployment).asset_source_policy()
    )
    definitions: dict[str, BackendDefinition] = {}
    for tool_id in sorted(tool_ids):
        try:
            definitions[tool_id] = backend_by_id(tool_id)
        except KeyError:
            raise CliFailure("unknown-backend", status=_UNSATISFIED) from None

    commercial = frozenset(
        tool_id
        for tool_id, definition in definitions.items()
        if definition.vendor is not Vendor.OPEN_SOURCE
    )
    if commercial and not authorize_commercial:
        raise CliFailure("flow-commercial-authorization-required", status=_UNSATISFIED)
    deployment_configurations: dict[str, BackendDeploymentConfiguration] = {}
    for tool_id in sorted(commercial):
        configuration = _load_backend_configuration(
            backend_deployment,
            tool_id,
            required=True,
        )
        assert configuration is not None
        deployment_configurations[tool_id] = configuration
    providers_by_binding = _flow_license_providers(
        environment,
        commercial,
        deployment_configurations,
    )
    tool_paths: dict[str, Path] = {}
    tool_environments: dict[str, Mapping[str, str]] = {}
    tool_closures: dict[str, ResolvedExecutionClosure] = {}
    site_container_configurations: dict[str, SiteContainerConfiguration] = {}
    used_backend_deployment = bool(commercial)
    for tool_id, definition in definitions.items():
        bindings = tuple(
            binding for binding in environment.tool_bindings if binding.tool_id == tool_id
        )
        if not bindings:
            raise CliFailure("flow-tool-not-bound", status=_UNSATISFIED)
        if any(
            binding.capability not in definition.capabilities
            or binding.driver_digest != definition.driver_digest
            or not isinstance(binding.locator, AttestedHostToolLocator)
            for binding in bindings
        ):
            raise CliFailure("flow-tool-binding-mismatch", status=_UNSATISFIED)
        if definition.vendor is Vendor.OPEN_SOURCE:
            if any(binding.license_binding_id is not None for binding in bindings):
                raise CliFailure("flow-open-source-license-binding-invalid", status=_UNSATISFIED)
            probe, installation = probe_backend(definition)
            if installation is None or not all(
                _binding_matches_installation(binding, installation)
                for binding in bindings
            ):
                configuration = _load_backend_configuration(
                    backend_deployment,
                    tool_id,
                    required=backend_deployment is not None,
                )
                if configuration is not None:
                    used_backend_deployment = True
                    deployment_configurations[tool_id] = configuration
                    probe, installation = probe_backend(
                        definition,
                        deployment_configuration=configuration,
                    )
            if probe.state is not QualificationState.INVOCABLE or installation is None:
                raise CliFailure("flow-tool-unavailable", status=_UNSATISFIED)
        else:
            configuration = deployment_configurations[tool_id]
            probe, _ = probe_backend(
                definition,
                deployment_configuration=configuration,
            )
            installation = _resolve_commercial_flow_tool(
                definition,
                probe,
                bindings,
                environment,
                providers_by_binding,
                deployment_configuration=configuration,
            )
        configuration = deployment_configurations.get(tool_id)
        if isinstance(configuration, SiteContainerConfiguration):
            site_container_configurations[tool_id] = configuration
        matches = all(
            _binding_matches_installation(binding, installation) for binding in bindings
        )
        tool_paths[tool_id] = installation.executable_path
        tool_closures[tool_id] = installation.execution_closure
        if definition.vendor is Vendor.OPEN_SOURCE:
            tool_environments[tool_id] = MappingProxyType(dict(installation.environment))
        else:
            installation.environment.clear()
            tool_environments[tool_id] = MappingProxyType({})
        if not matches:
            raise CliFailure("flow-tool-binding-mismatch", status=_UNSATISFIED)
    if backend_deployment is not None and not used_backend_deployment:
        raise CliFailure("flow-backend-deployment-unused", status=_UNSATISFIED)
    return FlowHostBindings(
        tool_paths=MappingProxyType(tool_paths),
        tool_environments=MappingProxyType(tool_environments),
        tool_closures=MappingProxyType(tool_closures),
        site_container_configurations=MappingProxyType(site_container_configurations),
        license_providers=_providers_by_id(providers_by_binding),
        asset_source_policy=asset_source_policy,
    )


def _flow_license_providers(
    environment: EnvironmentSpec,
    commercial_tool_ids: frozenset[str],
    deployment_configurations: Mapping[str, BackendDeploymentConfiguration],
) -> Mapping[str, HostModuleLicenseProvider]:
    licenses = {binding.license_binding_id: binding for binding in environment.licenses}
    providers: dict[str, HostModuleLicenseProvider] = {}
    for tool_id in sorted(commercial_tool_ids):
        tool_bindings = tuple(
            binding for binding in environment.tool_bindings if binding.tool_id == tool_id
        )
        license_ids = {binding.license_binding_id for binding in tool_bindings}
        if None in license_ids or len(license_ids) != 1:
            raise CliFailure("commercial-license-binding-required", status=_UNSATISFIED)
        license_id = next(iter(license_ids))
        if license_id is None:
            raise CliFailure("commercial-license-binding-required", status=_UNSATISFIED)
        license_binding = licenses.get(license_id)
        locators = {binding.locator for binding in tool_bindings}
        configuration = deployment_configurations.get(tool_id)
        if (
            license_binding is None
            or len(locators) != 1
            or not isinstance(next(iter(locators)), AttestedHostToolLocator)
            or configuration is None
            or not configuration.revalidate()
        ):
            raise CliFailure("commercial-license-binding-invalid", status=_UNSATISFIED)
        provider = HostModuleLicenseProvider(
            provider_id=license_binding.provider_id,
            feature_class=license_binding.feature_class,
            deployment_configuration=configuration,
            max_checkouts=license_binding.max_checkouts,
        )
        if provider.provider_digest != license_binding.provider_digest:
            raise CliFailure("commercial-provider-binding-mismatch", status=_UNSATISFIED)
        existing = providers.get(license_id)
        if existing is not None and existing.provider_digest != provider.provider_digest:
            raise CliFailure("commercial-license-binding-invalid", status=_UNSATISFIED)
        providers[license_id] = provider
    return MappingProxyType(providers)


def _resolve_commercial_flow_tool(
    definition: BackendDefinition,
    metadata_probe: BackendProbe,
    bindings: tuple[ToolBinding, ...],
    environment: EnvironmentSpec,
    providers: Mapping[str, HostModuleLicenseProvider],
    *,
    deployment_configuration: BackendDeploymentConfiguration,
) -> ResolvedInstallation:
    if metadata_probe.state is not QualificationState.DETECTED:
        raise CliFailure("commercial-backend-not-detected", status=_UNSATISFIED)
    license_id = bindings[0].license_binding_id
    if license_id is None:
        raise CliFailure("commercial-license-binding-required", status=_UNSATISFIED)
    license_binding = next(
        item for item in environment.licenses if item.license_binding_id == license_id
    )
    provider = providers[license_id]
    try:
        lease = provider.acquire(
            feature_class=license_binding.feature_class,
            run_id="flow_runtime_preflight",
            ttl_seconds=license_binding.lease_ttl_seconds,
        )
    except LicenseUnavailable:
        raise CliFailure("flow-commercial-license-unavailable", status=_INCOMPLETE) from None
    try:
        resolved_probe, installation = resolve_authorized_commercial_backend(
            definition,
            metadata_probe,
            lease,
            deployment_configuration=deployment_configuration,
        )
    except AuthorizedBackendResolutionError as error:
        code = _commercial_resolution_code(error.reason)
        raise CliFailure(code, status=_INCOMPLETE) from None
    finally:
        provider.release(lease)
    if resolved_probe.state is not QualificationState.INVOCABLE:
        raise CliFailure("flow-commercial-resolution-failed", status=_INCOMPLETE)
    return installation


def _providers_by_id(
    providers_by_binding: Mapping[str, HostModuleLicenseProvider],
) -> Mapping[str, LicenseProvider]:
    routes: dict[str, dict[str, HostModuleLicenseProvider]] = {}
    for provider in providers_by_binding.values():
        features = routes.setdefault(provider.provider_id, {})
        existing = features.get(provider.feature_class)
        if existing is not None and existing.provider_digest != provider.provider_digest:
            raise CliFailure("commercial-license-binding-invalid", status=_UNSATISFIED)
        features[provider.feature_class] = provider
    result: dict[str, LicenseProvider] = {}
    for provider_id, features in routes.items():
        result[provider_id] = (
            next(iter(features.values()))
            if len(features) == 1
            else _EnvironmentLicenseProvider(provider_id, features)
        )
    return MappingProxyType(result)


def _commercial_resolution_code(reason: AuthorizedBackendResolutionReason) -> str:
    if reason in {
        AuthorizedBackendResolutionReason.BINDING_MISMATCH,
        AuthorizedBackendResolutionReason.MODULE_METADATA_CHANGED,
        AuthorizedBackendResolutionReason.EXECUTABLE_IDENTITY_CHANGED,
    }:
        return "flow-commercial-identity-mismatch"
    if reason is AuthorizedBackendResolutionReason.LICENSE_LEASE_UNAVAILABLE:
        return "flow-commercial-license-unavailable"
    if reason is AuthorizedBackendResolutionReason.HOST_RUNTIME_DEPENDENCY_UNAVAILABLE:
        return "flow-commercial-runtime-unavailable"
    return "flow-commercial-resolution-failed"


def _binding_matches_installation(
    binding: ToolBinding,
    installation: ResolvedInstallation,
) -> bool:
    return (
        isinstance(binding.locator, AttestedHostToolLocator)
        and installation.definition.tool_id == binding.tool_id
        and installation.definition.driver_digest == binding.driver_digest
        and installation.version_label == binding.tool_version
        and installation.executable_name == binding.locator.executable
        and installation.deployment_attestation_digest
        == binding.locator.deployment_attestation_digest
    )


def _load_backend_configuration(
    deployment_path: Path | None,
    tool_id: str,
    *,
    required: bool,
) -> BackendDeploymentConfiguration | None:
    if deployment_path is None:
        if required:
            raise CliFailure("backend-deployment-required", status=_UNSATISFIED)
        return None
    try:
        configuration = load_backend_deployment_configuration(
            Path(os.path.abspath(deployment_path)),
            tool_id,
        )
    except (OSError, ValueError):
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED) from None
    if configuration.tool_id != tool_id or not configuration.revalidate():
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED)
    return configuration


def _load_backend_registry(deployment_path: Path) -> BackendDeploymentRegistry:
    try:
        return load_backend_deployment_registry(Path(os.path.abspath(deployment_path)))
    except (OSError, ValueError):
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED) from None


def _probe_with_registry(
    definition: BackendDefinition,
    registry: BackendDeploymentRegistry,
) -> BackendProbe:
    try:
        configuration = registry.configuration_for(definition.tool_id)
    except (OSError, ValueError):
        raise CliFailure("backend-deployment-invalid", status=_UNSATISFIED) from None
    if configuration is None:
        return BackendProbe(
            tool_id=definition.tool_id,
            vendor=definition.vendor,
            capabilities=definition.capabilities,
            state=QualificationState.UNAVAILABLE,
            host_support_mode=definition.host_support_mode,
            driver_digest=definition.driver_digest,
            reason=UnavailableReason.POLICY_UNAVAILABLE,
        )
    return probe_backend(
        definition,
        deployment_configuration=configuration,
    )[0]


def _qualify_commercial(
    definition: BackendDefinition,
    probe: BackendProbe,
    environment: EnvironmentSpec,
    *,
    capability: Capability,
    scratch_root: Path,
    store_root: Path,
    key_file: Path | None,
    resource_grant: QualificationResourceGrant,
    deployment_configuration: BackendDeploymentConfiguration | None,
) -> BackendQualification:
    if (
        probe.state is not QualificationState.DETECTED
        or deployment_configuration is None
        or deployment_configuration.tool_id != definition.tool_id
        or not deployment_configuration.revalidate()
    ):
        raise CliFailure("commercial-backend-not-detected", status=_UNSATISFIED)
    fixture = fixture_for(definition.tool_id, capability)
    if fixture is None:
        raise CliFailure("qualification-fixture-unavailable", status=_UNSATISFIED)
    tool_bindings = [
        binding
        for binding in environment.tool_bindings
        if binding.tool_id == definition.tool_id and binding.capability is capability
    ]
    if len(tool_bindings) != 1 or tool_bindings[0].license_binding_id is None:
        raise CliFailure("commercial-license-binding-required", status=_UNSATISFIED)
    tool_binding = tool_bindings[0]
    license_binding_id = tool_binding.license_binding_id
    if license_binding_id is None:
        raise CliFailure("commercial-license-binding-required", status=_UNSATISFIED)
    license_bindings = {
        binding.license_binding_id: binding for binding in environment.licenses
    }
    license_binding = license_bindings[license_binding_id]
    provider = HostModuleLicenseProvider(
        provider_id=license_binding.provider_id,
        feature_class=license_binding.feature_class,
        deployment_configuration=deployment_configuration,
        max_checkouts=license_binding.max_checkouts,
    )
    if provider.provider_digest != license_binding.provider_digest:
        raise CliFailure("commercial-provider-binding-mismatch", status=_UNSATISFIED)
    disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.EVIDENCE)
    if disclosure is None:
        raise CliFailure("evidence-retention-disabled", status=_UNSATISFIED)
    store = open_artifact_store(store_root, environment, key_file)
    broker = CommercialQualificationLicenseBroker(
        binding=license_binding,
        provider=provider,
        deployment_configuration=deployment_configuration,
    )
    maximum_execution = (
        resource_grant.command_timeout_seconds
        * len(fixture.invocations)
        * len(FixtureRole)
    )
    try:
        authorization = broker.authorize(
            definition=definition,
            metadata_probe=probe,
            fixture=fixture,
            run_id=f"qualification_{definition.tool_id}",
            max_execution_seconds=maximum_execution,
        )
        with authorization:
            return qualify_commercial_backend(
                definition,
                probe,
                authorization,
                scratch_root=scratch_root,
                artifact_store=store,
                artifact_disclosure=disclosure,
                resource_grant=resource_grant,
                deployment_configuration=deployment_configuration,
            )
    except (OSError, ValueError, RuntimeError, CommercialQualificationAuthorizationError):
        raise CliFailure("commercial-qualification-failed", status=_INCOMPLETE) from None


def _verify_tool_binding(
    binding: ToolBinding,
    *,
    backend_deployment: Path | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "capability": binding.capability,
        "tool_id": binding.tool_id,
        "state": "mismatch",
    }
    try:
        definition = backend_by_id(binding.tool_id)
    except KeyError:
        result["reason"] = "unknown_backend"
        return result
    if (
        binding.capability not in definition.capabilities
        or binding.driver_digest != definition.driver_digest
    ):
        result["reason"] = "driver_binding_mismatch"
        return result
    if isinstance(binding.locator, ImageToolLocator):
        result["state"] = "unverified"
        result["reason"] = "image_executor_required"
        return result
    probe, installation = probe_backend(definition)
    if (
        installation is None
        or not _binding_matches_installation(binding, installation)
    ) and backend_deployment is not None:
        try:
            configuration = _load_backend_configuration(
                backend_deployment,
                definition.tool_id,
                required=True,
            )
        except CliFailure:
            result["reason"] = "deployment_invalid"
            return result
        assert configuration is not None
        probe, installation = probe_backend(
            definition,
            deployment_configuration=configuration,
        )
    if installation is None:
        result["state"] = probe.state
        result["reason"] = probe.reason or "authorized_resolution_required"
        return result
    if probe.state is QualificationState.INVOCABLE and _binding_matches_installation(
        binding,
        installation,
    ):
        result["state"] = "verified"
        result["probe_digest"] = canonical_digest(probe, domain="backend-probe-v1")
    else:
        result["reason"] = "resolved_identity_mismatch"
    return result
