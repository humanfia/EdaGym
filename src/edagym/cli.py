"""Thin command-line access to EdaGym semantic owners."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Never

from pydantic import BaseModel, ValidationError

from edagym import __version__
from edagym.authoring.materialization import (
    materialize_private_catalog,
    verify_materialized_catalog,
)
from edagym.authoring.provider import (
    DerivedTaskDocument,
    ExternalAuthoringProvider,
    PrivateAuthoringCapability,
    QualificationProviderResponse,
)
from edagym.benchmark.model import BenchmarkQualityReport, BenchmarkSpec, TrialObservation
from edagym.benchmark.schedule import BenchmarkSchedule
from edagym.benchmark.store import load_instances, prepare_benchmark
from edagym.canonical import canonical_bytes
from edagym.cli_support.backends import (
    probe_declared_backends,
    qualification_status,
    qualify_declared_backend,
    verify_environment,
)
from edagym.cli_support.campaigns import (
    CampaignCliCommand,
    execute_campaign_command,
)
from edagym.cli_support.documents import (
    load_model,
    open_artifact_store,
    open_run_artifact_stores,
    parse_keyed_paths,
)
from edagym.cli_support.errors import CliFailure
from edagym.cli_support.flows import (
    evaluate_flow_candidate,
    load_flow_pack,
    qualify_flow_pack,
)
from edagym.cli_support.runs import (
    open_run,
)
from edagym.config import initialize_config, load_config
from edagym.config.model import EdaGymConfig
from edagym.config.qualification import qualify_profile
from edagym.config.resolve import resolve_profile
from edagym.drivers.catalog import (
    BACKEND_CATALOG,
    BACKENDS,
    backend_by_id,
    validate_catalog,
)
from edagym.drivers.deployment import load_backend_deployment_registry
from edagym.drivers.model import QualificationState
from edagym.drivers.qualification import BackendQualification, QualificationDisposition
from edagym.executors.capabilities import probe_local_containment
from edagym.executors.deployment import (
    load_executor_deployment_registry,
    unconfigured_executor_statuses,
)
from edagym.flow_tasks import FlowTaskCatalog, load_private_flow_catalog
from edagym.policy.repository import (
    AuditMode,
    AuditStatus,
    RepositoryPolicy,
    audit_repository,
)
from edagym.policy.runtime_storage import read_private
from edagym.projections import (
    HumanizeTraceAudience,
    ProjectionUnavailable,
    project_atif,
    project_course_report,
    project_harbor,
    project_humanize,
    project_leaderboard_entry,
    project_nemo,
)
from edagym.providers.campaign_runner import CampaignRecord, CampaignReport
from edagym.providers.model_discovery import ModelDiscoverySnapshot
from edagym.providers.qualification import RouteCanaryEvidence
from edagym.providers.trial_evidence import CampaignTrialResult
from edagym.release_backend_sources import load_backend_qualification_sources
from edagym.release_commands import (
    ReleaseCommandPurpose,
    ReleaseCommandReceipt,
    ReleaseEvidenceStatus,
    execute_release_command,
    execute_release_commands,
    release_command_requires_installation,
)
from edagym.release_executors import (
    VerifiedExecutorQualification,
    VmExecutorQualificationSource,
    verify_executor_qualification_source,
)
from edagym.release_reporting import (
    ReleaseDecision,
    ReleaseReport,
    build_release_report,
)
from edagym.resolution import ResolutionError, resolve_run
from edagym.run.artifacts import ArtifactStoreError, ContentAddressedStore
from edagym.run.journal import JournalError, RunJournal
from edagym.run.model import RunRecord
from edagym.serialization import DocumentKind
from edagym.specs.common import Capability
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import BenchmarkMode, CourseMode, SessionSpec
from edagym.specs.task import TaskSpec
from edagym.task_families.catalog import (
    EDA_FLOW_FAMILIES,
    PUBLIC_TASK_CATALOG,
    SAIL_RTL_FAMILIES,
    TaskFamilyDefinition,
)
from edagym.web import create_web_app

_SUCCESS = 0
_UNSATISFIED = 1
_INVALID_INVOCATION = 2
_INCOMPLETE = 3
_RUN_KEYED_PATH = "RUN_ID=PATH"
class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        self.print_usage(sys.stderr)
        self.exit(_INVALID_INVOCATION, f"edagym: invocation error: {message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="edagym", description="EDA task and evaluation runtime")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config",
        dest="config_path",
        type=Path,
        help="select one private TOML configuration document",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a private configuration skeleton")
    init.add_argument("--config", dest="config_path", required=True, type=Path)
    init.add_argument("--root", required=True, type=Path)
    init.set_defaults(handler=_init_config)

    config = commands.add_parser("config", help="check, show, or import configuration")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    for config_command in ("check", "show"):
        checker = config_commands.add_parser(config_command)
        checker.add_argument(
            "--config",
            dest="config_path",
            required=False,
            default=argparse.SUPPRESS,
            type=Path,
        )
        checker.set_defaults(handler=_config_check)
    importer = config_commands.add_parser("import", help="explicitly import a legacy document")
    importer.add_argument("--source", required=True, type=Path)
    importer.add_argument("--output", required=True, type=Path)
    importer.set_defaults(handler=_config_import)

    web = commands.add_parser("web", help="serve the authenticated browser shell")
    web_commands = web.add_subparsers(dest="web_command", required=True)
    serve = web_commands.add_parser("serve")
    serve.add_argument(
        "--config",
        dest="config_path",
        default=argparse.SUPPRESS,
        type=Path,
    )
    serve.add_argument(
        "--check",
        action="store_true",
        help="validate and print startup metadata without binding a socket",
    )
    serve.set_defaults(handler=_web_serve)

    doctor = commands.add_parser(
        "doctor",
        help="probe backends and durable local execution prerequisites",
    )
    doctor.add_argument("--json", action="store_true", help="emit canonical JSON")
    doctor.add_argument("--config", dest="config_path", type=Path, default=argparse.SUPPRESS)
    doctor.add_argument("--site", dest="site_id")
    doctor.add_argument(
        "--backend-deployment",
        type=Path,
        help="load one owner-only backend deployment registry",
    )
    doctor.add_argument(
        "--executor-deployment",
        type=Path,
        help="load one owner-only executor deployment registry",
    )
    doctor.set_defaults(handler=_doctor)

    _add_backend_commands(commands)
    _add_tool_commands(commands)
    _add_campaign_commands(commands)
    _add_factory_benchmark_commands(commands)
    _add_task_commands(commands)
    _add_environment_commands(commands)
    _add_run_commands(commands)
    _add_release_report_command(commands)
    _add_release_command(commands)

    evaluate = commands.add_parser("evaluate", help="evaluate one executable EDA flow candidate")
    evaluate.add_argument("family")
    evaluate.add_argument("candidate_id")
    evaluate.add_argument("--environment", required=True, type=Path)
    evaluate.add_argument("--release", required=True, type=Path)
    evaluate.add_argument("--workspace", required=True, type=Path)
    evaluate.add_argument("--runtime-root", required=True, type=Path)
    evaluate.add_argument("--store-root", required=True, type=Path)
    evaluate.add_argument("--artifact-key-file", type=Path)
    evaluate.add_argument(
        "--asset",
        action="append",
        default=[],
        metavar="ASSET_ID=PATH",
        help="bind one evaluator asset to an absolute host path",
    )
    evaluate.add_argument(
        "--authorize-commercial",
        action="store_true",
        help="authorize the declared commercial tool and license bindings",
    )
    evaluate.add_argument(
        "--backend-deployment",
        type=Path,
        help="load an owner-only backend deployment registry",
    )
    evaluate.add_argument(
        "--author-calibration",
        action="store_true",
        help="admit only an exact canonical author candidate for calibration",
    )
    evaluate.add_argument("--timeout-seconds", default=300, type=int)
    _add_private_authoring_provider_arguments(evaluate)
    evaluate.set_defaults(handler=_evaluate)

    report = commands.add_parser("report", help="derive a course or leaderboard report")
    _add_run_locator(report)
    report.add_argument("--session", required=True, type=Path)
    report.add_argument(
        "--kind",
        choices=("auto", "course", "leaderboard"),
        default="auto",
    )
    report.set_defaults(handler=_report)

    export = commands.add_parser("export", help="derive an external projection")
    export_commands = export.add_subparsers(dest="export_command", required=True)
    for name, handler in (
        ("atif", _export_atif),
        ("harbor", _export_harbor),
        ("nemo", _export_nemo),
    ):
        export_parser = export_commands.add_parser(name, help=f"derive the {name} projection")
        _add_run_locator(export_parser)
        export_parser.set_defaults(handler=handler)
    humanize = export_commands.add_parser(
        "humanize",
        help="derive the Humanize session and trace projection",
    )
    _add_run_locator(humanize)
    humanize.add_argument("--session", required=True, type=Path)
    humanize.add_argument(
        "--audience",
        choices=tuple(audience.value for audience in HumanizeTraceAudience),
        default=HumanizeTraceAudience.PARTICIPANT.value,
    )
    humanize.set_defaults(handler=_export_humanize)

    spec = commands.add_parser("spec", help="validate a versioned canonical document")
    spec_commands = spec.add_subparsers(dest="spec_command", required=True)
    spec_validate = spec_commands.add_parser("validate", help="validate a canonical document")
    spec_validate.add_argument(
        "kind",
        choices=(
            "backend_qualification",
            "task",
            "environment",
            "session",
            "task_instance",
            "release_manifest",
            "release_command",
            "release_report",
            "benchmark",
            "benchmark_quality_report",
            "benchmark_schedule",
            "trial_observation",
            "config",
            "run_manifest",
        ),
    )
    spec_validate.add_argument("path", type=Path)
    spec_validate.set_defaults(handler=_validate_spec)

    repository = commands.add_parser("repository", help="audit Git repository boundaries")
    repository_commands = repository.add_subparsers(dest="repository_command", required=True)
    audit = repository_commands.add_parser("audit", help="run the secret-safe repository audit")
    audit.add_argument("--mode", choices=("commit", "release"), default="commit")
    audit.add_argument("--repository", default=".", type=Path)
    audit.add_argument("--gitleaks", default=Path("/usr/bin/gitleaks"), type=Path)
    audit.add_argument("--json", action="store_true", help="emit canonical JSON")
    audit.set_defaults(handler=_repository_audit)
    return parser


def _add_release_report_command(
    commands: argparse._SubParsersAction[_ArgumentParser],
) -> None:
    report = commands.add_parser(
        "release-report",
        help="derive release readiness from immutable evidence",
    )
    report.add_argument("--sail-catalog-root", required=True, type=Path)
    report.add_argument(
        "--backend-source-registry",
        required=True,
        type=Path,
    )
    report.add_argument("--backend-deployment", required=True, type=Path)
    report.add_argument("--flow-catalog-root", required=True, type=Path)
    _add_private_authoring_provider_arguments(report)
    report.add_argument("--flow-environment", action="append", required=True, type=Path)
    report.add_argument(
        "--flow-qualification-response",
        action="append",
        required=True,
        type=Path,
    )
    report.add_argument("--flow-store-root", required=True, type=Path)
    report.add_argument("--flow-artifact-key-file", type=Path)
    report.add_argument("--flow-run", action="append", default=[], type=Path)
    report.add_argument("--campaign-record", action="append", required=True, type=Path)
    report.add_argument("--campaign-report", action="append", required=True, type=Path)
    report.add_argument("--model-discovery", action="append", required=True, type=Path)
    report.add_argument("--route-canary", action="append", required=True, type=Path)
    report.add_argument("--campaign-run", action="append", default=[], type=Path)
    report.add_argument("--campaign-trial-result", action="append", default=[], type=Path)
    report.add_argument("--campaign-task-instance", action="append", default=[], type=Path)
    report.add_argument("--campaign-session", action="append", default=[], type=Path)
    report.add_argument("--campaign-environment", action="append", default=[], type=Path)
    report.add_argument(
        "--campaign-store-root",
        action="append",
        default=[],
        metavar=_RUN_KEYED_PATH,
    )
    report.add_argument(
        "--campaign-artifact-key-file",
        action="append",
        default=[],
        metavar=_RUN_KEYED_PATH,
    )
    report.add_argument("--participant-run", action="append", default=[], type=Path)
    report.add_argument("--participant-task", action="append", default=[], type=Path)
    report.add_argument("--participant-task-instance", action="append", default=[], type=Path)
    report.add_argument("--participant-release", action="append", default=[], type=Path)
    report.add_argument("--participant-environment", action="append", default=[], type=Path)
    report.add_argument("--participant-session", action="append", default=[], type=Path)
    report.add_argument(
        "--participant-store-root",
        action="append",
        default=[],
        metavar=_RUN_KEYED_PATH,
    )
    report.add_argument(
        "--participant-artifact-key-file",
        action="append",
        default=[],
        metavar=_RUN_KEYED_PATH,
    )
    report.add_argument("--executor-deployment", type=Path)
    report.add_argument("--executor-qualification", type=Path)
    report.add_argument("--executor-qualification-store-root", type=Path)
    report.add_argument("--executor-qualification-key-file", type=Path)
    report.add_argument("--command-environment", required=True, type=Path)
    report.add_argument("--command-store-root", required=True, type=Path)
    report.add_argument("--command-artifact-key-file", type=Path)
    report.add_argument("--command-timeout-seconds", default=3600, type=int)
    report.add_argument("--repository", default=".", type=Path)
    report.add_argument("--gitleaks", default=Path("/usr/bin/gitleaks"), type=Path)
    report.set_defaults(handler=_release_report)


def _add_release_command(
    commands: argparse._SubParsersAction[_ArgumentParser],
) -> None:
    command = commands.add_parser(
        "release-command",
        help="execute one repository-bound release verification command",
    )
    command.add_argument("purpose", choices=tuple(ReleaseCommandPurpose))
    command.add_argument("--environment", required=True, type=Path)
    command.add_argument("--store-root", required=True, type=Path)
    command.add_argument("--artifact-key-file", type=Path)
    command.add_argument("--repository", default=Path("."), type=Path)
    command.add_argument("--gitleaks", default=Path("/usr/bin/gitleaks"), type=Path)
    command.add_argument("--timeout-seconds", default=3600, type=int)
    command.set_defaults(handler=_release_command)


def _add_backend_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    backend = commands.add_parser("backend", help="inspect and qualify EDA backends")
    backend_commands = backend.add_subparsers(dest="backend_command", required=True)
    backend_list = backend_commands.add_parser("list", help="list declared backends")
    backend_list.add_argument("--json", action="store_true", help="emit canonical JSON")
    backend_list.set_defaults(handler=_backend_list)
    backend_probe = backend_commands.add_parser(
        "probe", help="probe one backend without a workload"
    )
    backend_probe.add_argument("tool_id")
    backend_probe.add_argument(
        "--backend-deployment",
        type=Path,
        help="load one owner-only backend deployment registry",
    )
    backend_probe.add_argument("--json", action="store_true", help="emit canonical JSON")
    backend_probe.set_defaults(handler=_backend_probe)

    qualify = backend_commands.add_parser("qualify", help="run canonical backend fixtures")
    qualify.add_argument("tool_id")
    qualify.add_argument("--environment", required=True, type=Path)
    qualify.add_argument("--scratch-root", required=True, type=Path)
    qualify.add_argument("--store-root", required=True, type=Path)
    qualify.add_argument("--artifact-key-file", type=Path)
    qualify.add_argument(
        "--capability",
        choices=tuple(capability.value for capability in Capability),
    )
    qualify.add_argument("--timeout-seconds", default=120, type=int)
    qualify.add_argument(
        "--authorize-commercial",
        action="store_true",
        help="authorize one declared commercial fixture and license checkout",
    )
    qualify.add_argument("--backend-deployment", type=Path)
    qualify.add_argument("--json", action="store_true", help="emit canonical JSON")
    qualify.set_defaults(handler=_backend_qualify)


def _add_tool_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    """Expose the configuration-first qualification entry point."""

    tool = commands.add_parser("tool", help="qualify configured tool views")
    tool_commands = tool.add_subparsers(dest="tool_command", required=True)
    qualify = tool_commands.add_parser("qualify", help="check one configured profile")
    qualify.add_argument("--profile", required=True)
    qualify.add_argument("--json", action="store_true", help="emit canonical JSON")
    qualify.set_defaults(handler=_tool_qualify)


def _add_campaign_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    campaign = commands.add_parser(
        "campaign",
        help="inspect, freeze, execute, and report provider campaigns",
    )
    campaign_commands = campaign.add_subparsers(dest="campaign_command", required=True)
    for command in CampaignCliCommand:
        command_parser = campaign_commands.add_parser(command.value)
        command_parser.add_argument("--request", required=True, type=Path)
        command_parser.set_defaults(handler=_campaign_command, campaign_operation=command)


def _add_factory_benchmark_commands(
    commands: argparse._SubParsersAction[_ArgumentParser],
) -> None:
    """Expose bounded calibration/benchmark lifecycle commands.

    The commands validate the private configuration and report an explicit
    unavailable state until a station campaign supplies real evidence. They do
    not fabricate model observations or silently spend provider budget.
    """

    factory = commands.add_parser("factory", help="derive task-factory evidence")
    factory_commands = factory.add_subparsers(dest="factory_command", required=True)
    calibrate = factory_commands.add_parser("calibrate", help="derive a calibration report")
    calibrate.add_argument("--campaign", required=True)
    calibrate.set_defaults(handler=_factory_calibrate)

    benchmark = commands.add_parser("benchmark", help="prepare, run, and report benchmarks")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_command", required=True)
    prepare = benchmark_commands.add_parser("prepare", help="freeze a benchmark matrix")
    prepare.add_argument("--spec", required=True, type=Path)
    prepare.add_argument("--phase", required=True)
    prepare.add_argument("--instance", action="append", default=[])
    prepare.set_defaults(handler=_benchmark_lifecycle)
    evolve = benchmark_commands.add_parser("evolve", help="create a revision request")
    evolve.add_argument("--from", dest="from_revision", required=True)
    evolve.set_defaults(handler=_benchmark_lifecycle)
    for name in ("run", "resume", "report"):
        command_parser = benchmark_commands.add_parser(name)
        command_parser.add_argument("--campaign", required=True)
        command_parser.set_defaults(handler=_benchmark_lifecycle)


def _add_task_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    task = commands.add_parser("task", help="validate, generate, and qualify tasks")
    task_commands = task.add_subparsers(dest="task_command", required=True)
    catalog = task_commands.add_parser("catalog", help="list clean-room task families")
    catalog.add_argument("--kind", choices=("all", "sail", "eda-flow"), default="all")
    catalog.add_argument("--json", action="store_true", help="emit canonical JSON")
    catalog.set_defaults(handler=_task_catalog)

    validate = task_commands.add_parser("validate", help="validate a canonical task document")
    validate.add_argument("path", type=Path)
    validate.set_defaults(handler=_validate_task)

    generate = task_commands.add_parser(
        "generate", help="generate task instances or materialize a private catalog"
    )
    generate.add_argument("output", nargs="?", type=Path)
    generate.add_argument("--family")
    generate.add_argument("--difficulty", default="single_transaction")
    generate.add_argument("--count", default=1, type=int)
    generate.add_argument("--seed")
    generate.add_argument("--profile")
    _add_private_authoring_provider_arguments(generate, required=False)
    generate.set_defaults(handler=_task_generate)

    qualify = task_commands.add_parser("qualify", help="qualify a Sail catalog or EDA flow pack")
    source = qualify.add_mutually_exclusive_group(required=True)
    source.add_argument("--catalog-root", type=Path)
    source.add_argument("--flow")
    qualify.add_argument("--environment", type=Path)
    qualify.add_argument("--scratch-root", type=Path)
    qualify.add_argument("--store-root", type=Path)
    qualify.add_argument("--artifact-key-file", type=Path)
    qualify.add_argument(
        "--asset",
        action="append",
        default=[],
        metavar="ASSET_ID=PATH",
        help="bind one evaluator asset to an absolute host path",
    )
    qualify.add_argument(
        "--authorize-commercial",
        action="store_true",
        help="authorize the declared commercial tool and license bindings",
    )
    qualify.add_argument(
        "--backend-deployment",
        type=Path,
        help="load an owner-only backend deployment registry",
    )
    qualify.add_argument("--timeout-seconds", default=300, type=int)
    _add_private_authoring_provider_arguments(qualify, required=False)
    qualify.set_defaults(handler=_task_qualify)

    release = task_commands.add_parser("release", help="verify and emit one frozen task release")
    release.add_argument("catalog_root", type=Path)
    release.add_argument("family")
    release.add_argument("instance")
    release.set_defaults(handler=_task_release)


def _add_private_authoring_provider_arguments(
    parser: argparse.ArgumentParser,
    *,
    required: bool = True,
) -> None:
    parser.add_argument("--authoring-provider", type=Path, required=required)
    parser.add_argument("--authoring-provider-executable-digest", required=required)
    parser.add_argument("--authoring-provider-implementation-digest", required=required)
    parser.add_argument("--authoring-provider-descriptor-digest", required=required)


def _add_environment_commands(
    commands: argparse._SubParsersAction[_ArgumentParser],
) -> None:
    environment = commands.add_parser("environment", help="resolve and verify environments")
    environment_commands = environment.add_subparsers(dest="environment_command", required=True)
    resolve = environment_commands.add_parser("resolve", help="resolve one immutable run plan")
    _add_resolved_inputs(resolve)
    resolve.set_defaults(handler=_environment_resolve)

    verify = environment_commands.add_parser("verify", help="verify local tool identities")
    verify.add_argument("path", type=Path)
    verify.add_argument("--backend-deployment", type=Path)
    verify.set_defaults(handler=_environment_verify)


def _add_run_commands(commands: argparse._SubParsersAction[_ArgumentParser]) -> None:
    from edagym.cli_run import add_run_commands

    add_run_commands(commands)


def _add_resolved_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task", required=True, type=Path)
    parser.add_argument("--instance", required=True, type=Path)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--session", required=True, type=Path)
    parser.add_argument("--trial-key", required=True)


def _add_run_locator(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("directory", type=Path)
    parser.add_argument("--task", required=True, type=Path)


def _emit(value: object, *, as_json: bool = True) -> None:
    if as_json:
        sys.stdout.buffer.write(canonical_bytes(value) + b"\n")
        return
    if isinstance(value, str):
        print(value)
        return
    if isinstance(value, Sequence):
        for item in value:
            print(item)
        return
    print(value)


def _model_json(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(
        mode="json",
        exclude_defaults=False,
        exclude_none=False,
        exclude_unset=False,
    )


def _config_path(arguments: argparse.Namespace) -> Path:
    path = getattr(arguments, "config_path", None)
    if not isinstance(path, Path):
        raise CliFailure("config-required", status=_INVALID_INVOCATION)
    return path


def _init_config(arguments: argparse.Namespace) -> int:
    config = initialize_config(arguments.config_path, arguments.root)
    _emit(config.redacted_view())
    return _SUCCESS


def _config_check(arguments: argparse.Namespace) -> int:
    config = load_config(_config_path(arguments))
    _emit(config.redacted_view())
    return _SUCCESS


def _config_import(arguments: argparse.Namespace) -> int:
    from edagym.config.load import import_legacy_config

    config = import_legacy_config(arguments.source, arguments.output)
    _emit(config.redacted_view())
    return _SUCCESS


def _web_serve(arguments: argparse.Namespace) -> int:
    config = load_config(_config_path(arguments))
    application = create_web_app(config)
    print(canonical_bytes(application.startup_info).decode("utf-8"))
    if arguments.check:
        return _SUCCESS
    import uvicorn

    uvicorn.run(
        application,
        host=config.web.host,
        port=config.web.port,
        log_level="info",
    )
    return _SUCCESS


def _doctor(arguments: argparse.Namespace) -> int:
    config_payload: dict[str, object] | None = None
    if getattr(arguments, "config_path", None) is not None:
        config = load_config(arguments.config_path)
        if arguments.site_id is not None:
            from edagym.config.resolve import resolve_site

            resolve_site(config, arguments.site_id)
        config_payload = config.redacted_view()
    validate_catalog()
    probes = probe_declared_backends(
        BACKENDS,
        backend_deployment=arguments.backend_deployment,
    )
    local_containment = probe_local_containment()
    if arguments.executor_deployment is None:
        executor_statuses = unconfigured_executor_statuses()
    else:
        try:
            with load_executor_deployment_registry(
                arguments.executor_deployment.absolute()
            ) as deployment:
                executor_statuses = deployment.statuses(now_epoch_seconds=int(time.time()))
        except (OSError, RuntimeError, ValueError):
            raise CliFailure("invalid-executor-deployment", status=_UNSATISFIED) from None
    payload = {
        "config": config_payload,
        "local_containment": _model_json(local_containment),
        "executors": [_model_json(status) for status in executor_statuses],
        "backends": [_model_json(probe) for probe in probes],
        "counts": {
            state.value: sum(probe.state is state for probe in probes)
            for state in QualificationState
        },
    }
    if arguments.json:
        _emit(payload)
    else:
        _emit(
            [
                "local_containment\t"
                f"{local_containment.availability.value}\t"
                f"{local_containment.reason.value if local_containment.reason else '-'}",
                *(
                    f"{status.kind.value}\t{status.availability.value}\t"
                    f"{status.reason.value if status.reason else '-'}"
                    for status in executor_statuses
                ),
                *(
                    f"{probe.tool_id}\t{probe.state.value}\t"
                    f"{probe.reason.value if probe.reason else '-'}"
                    for probe in probes
                ),
            ],
            as_json=False,
        )
    return _SUCCESS


def _backend_list(arguments: argparse.Namespace) -> int:
    validate_catalog()
    if arguments.json:
        _emit([_model_json(definition) for definition in BACKENDS])
    else:
        _emit(
            [
                f"{definition.tool_id}\t{definition.vendor.value}\t"
                f"{','.join(capability.value for capability in definition.capabilities)}"
                for definition in BACKENDS
            ],
            as_json=False,
        )
    return _SUCCESS


def _backend_probe(arguments: argparse.Namespace) -> int:
    try:
        definition = backend_by_id(arguments.tool_id)
    except KeyError:
        raise CliFailure("unknown-backend", status=_INVALID_INVOCATION) from None
    probe = probe_declared_backends(
        (definition,),
        backend_deployment=arguments.backend_deployment,
    )[0]
    if arguments.json:
        _emit(probe)
    else:
        reason = probe.reason.value if probe.reason is not None else "-"
        _emit(f"{probe.tool_id}\t{probe.state.value}\t{reason}", as_json=False)
    return _SUCCESS if probe.state is not QualificationState.UNAVAILABLE else _UNSATISFIED


def _backend_qualify(arguments: argparse.Namespace) -> int:
    try:
        definition = backend_by_id(arguments.tool_id)
    except KeyError:
        raise CliFailure("unknown-backend", status=_INVALID_INVOCATION) from None
    environment = load_model(arguments.environment, "environment", EnvironmentSpec)
    _ensure_private_directory(arguments.scratch_root)
    qualification = qualify_declared_backend(
        definition,
        environment,
        capability=(None if arguments.capability is None else Capability(arguments.capability)),
        scratch_root=arguments.scratch_root,
        store_root=arguments.store_root,
        key_file=arguments.artifact_key_file,
        timeout_seconds=arguments.timeout_seconds,
        authorize_commercial=arguments.authorize_commercial,
        backend_deployment=arguments.backend_deployment,
    )
    if arguments.json:
        _emit(qualification)
    else:
        _emit(
            f"{qualification.probe.tool_id}\t{qualification.disposition.value}\t"
            f"{qualification.digest}",
            as_json=False,
        )
    return qualification_status(qualification)


def _tool_qualify(arguments: argparse.Namespace) -> int:
    """Run controlled tool probes and persist private qualification receipts."""


    try:
        config = load_config(_config_path(arguments))
        resolved = resolve_profile(config, arguments.profile)
    except (OSError, ValueError, ValidationError):
        raise CliFailure("tool-qualification-unavailable", status=_INCOMPLETE) from None
    receipts = qualify_profile(resolved)
    available = bool(receipts) and all(
        item.disposition is QualificationDisposition.CONFORMANT for item in receipts
    )
    reasons = tuple(sorted({item.failure.value for item in receipts if item.failure is not None}))
    _emit(
        {
            "profile_id": resolved.profile_id,
            "status": "available" if available else "unavailable",
            "reasons": reasons or ("execution_qualification_required",),
            "receipt_count": len(receipts),
        }
    )
    return _SUCCESS if available else _UNSATISFIED


def _campaign_command(arguments: argparse.Namespace) -> int:
    result, status = execute_campaign_command(
        arguments.campaign_operation,
        arguments.request,
    )
    _emit(result)
    return status


def _factory_calibrate(arguments: argparse.Namespace) -> int:
    config = load_config(_config_path(arguments))
    _emit(
        {
            "status": "incomplete",
            "reason": "station_campaign_evidence_required",
            "campaign_id": arguments.campaign,
            "config_digest": config.digest,
            "framework_ready": False,
            "station_campaign_complete": False,
            "benchmark_quality_qualified": False,
        }
    )
    return _INCOMPLETE


def _benchmark_lifecycle(arguments: argparse.Namespace) -> int:
    config = load_config(_config_path(arguments))
    if arguments.benchmark_command == "prepare":
        if not arguments.instance:
            _emit({
                "status": "incomplete",
                "reason": "qualified_instance_ids_required",
                "framework_ready": True,
                "station_campaign_complete": False,
                "benchmark_quality_qualified": False,
            })
            return _INCOMPLETE
        try:
            spec = BenchmarkSpec.model_validate_json(read_private(arguments.spec))
            if spec.phase.value != arguments.phase:
                raise ValueError("benchmark phase does not match the frozen specification")
            profile_id = config.profiles[0].profile_id
            resolved = resolve_profile(config, profile_id)
            instances = load_instances(resolved.site.state_root, tuple(arguments.instance))
            schedule = prepare_benchmark(spec, instances, resolved.site.state_root)
        except (OSError, ValueError, ValidationError):
            raise CliFailure("benchmark-preparation-failed", status=_INCOMPLETE) from None
        _emit({
            "status": "prepared",
            "benchmark_digest": spec.digest,
            "schedule_digest": schedule.digest,
            "entries": schedule.size,
            "phase": spec.phase.value,
            "framework_ready": True,
            "station_campaign_complete": False,
            "benchmark_quality_qualified": False,
        })
        return _SUCCESS
    identifier = getattr(arguments, "campaign", None) or getattr(arguments, "spec", None)
    identifier = identifier or getattr(arguments, "from_revision", None)
    _emit(
        {
            "status": "incomplete",
            "reason": "real_station_and_frozen_evidence_required",
            "operation": arguments.benchmark_command,
            "identifier": identifier,
            "config_digest": config.digest,
            "framework_ready": False,
            "station_campaign_complete": False,
            "benchmark_quality_qualified": False,
        }
    )
    return _INCOMPLETE


def _task_catalog(arguments: argparse.Namespace) -> int:
    families: list[tuple[str, TaskFamilyDefinition]] = []
    if arguments.kind in {"all", "sail"}:
        families.extend(("sail", family) for family in SAIL_RTL_FAMILIES)
    if arguments.kind in {"all", "eda-flow"}:
        families.extend(("eda-flow", family) for family in EDA_FLOW_FAMILIES)
    if arguments.json:
        _emit([{"kind": kind, "family": _model_json(family)} for kind, family in families])
    else:
        _emit([f"{kind}\t{family.family}" for kind, family in families], as_json=False)
    return _SUCCESS


def _authoring_provider(arguments: argparse.Namespace) -> ExternalAuthoringProvider:
    values = (
        arguments.authoring_provider,
        arguments.authoring_provider_executable_digest,
        arguments.authoring_provider_implementation_digest,
        arguments.authoring_provider_descriptor_digest,
    )
    if any(item is None for item in values):
        raise CliFailure("private-authoring-provider-required", status=_INVALID_INVOCATION)
    return ExternalAuthoringProvider(
        arguments.authoring_provider,
        expected_executable_digest=arguments.authoring_provider_executable_digest,
        expected_implementation_digest=arguments.authoring_provider_implementation_digest,
        expected_descriptor_digest=arguments.authoring_provider_descriptor_digest,
    )


def _private_flow_catalog(arguments: argparse.Namespace) -> FlowTaskCatalog:
    try:
        return load_private_flow_catalog(
            _authoring_provider(arguments),
            PUBLIC_TASK_CATALOG,
        )
    except (OSError, ValueError, RuntimeError):
        raise CliFailure("private-flow-catalog-unavailable", status=_INCOMPLETE) from None


def _validate_task(arguments: argparse.Namespace) -> int:
    return _validate_path(arguments.path, "task")


def _task_generate(arguments: argparse.Namespace) -> int:
    if arguments.family is not None:
        from edagym.authoring.factory import GenerationRequest, generate_task
        from edagym.config.resolve import resolve_profile
        from edagym.specs.release import QualificationStatus

        try:
            config = load_config(_config_path(arguments))
            if arguments.profile is None and not config.profiles:
                from edagym.config.resolve import resolve_site

                resolved_site = resolve_site(config, config.sites[0].site_id)
            else:
                profile_id = arguments.profile or config.profiles[0].profile_id
                resolved_site = resolve_profile(config, profile_id).site
            seed = arguments.seed or ("0" * 32)
            request = GenerationRequest(
                family=arguments.family,
                difficulty=arguments.difficulty,
                seed=seed,
                count=arguments.count,
            )
            generated = generate_task(request, resolved_site)
        except CliFailure:
            raise
        except (OSError, ValueError, ValidationError):
            raise CliFailure("task-generation-failed", status=_INCOMPLETE) from None
        _emit(
            [
                {
                    "instance_digest": item.instance.digest,
                    "instance_id": item.instance_id,
                    "task_family": item.instance.identity.task_family,
                    "difficulty": arguments.difficulty,
                    "qualification": item.instance.qualification.status.value
                    if item.instance.qualification is not None
                    else None,
                }
                for item in generated
            ]
        )
        return (
            _SUCCESS
            if all(
                item.instance.qualification is not None
                and item.instance.qualification.status is QualificationStatus.QUALIFIED
                for item in generated
            )
            else _INCOMPLETE
        )
    if arguments.output is None:
        raise CliFailure("task-generation-arguments-required", status=_INVALID_INVOCATION)
    try:
        receipt = materialize_private_catalog(
            _authoring_provider(arguments),
            PrivateAuthoringCapability.SAIL_RTL_CATALOG,
            PUBLIC_TASK_CATALOG,
            arguments.output,
        )
    except (OSError, ValueError, RuntimeError):
        raise CliFailure("task-generation-failed", status=_INCOMPLETE) from None
    _emit(receipt)
    return _SUCCESS


def _task_qualify(arguments: argparse.Namespace) -> int:
    if arguments.catalog_root is not None:
        if (
            any(
                item is not None
                for item in (
                    arguments.environment,
                    arguments.scratch_root,
                    arguments.store_root,
                    arguments.artifact_key_file,
                    arguments.backend_deployment,
                    arguments.authoring_provider,
                    arguments.authoring_provider_executable_digest,
                    arguments.authoring_provider_implementation_digest,
                    arguments.authoring_provider_descriptor_digest,
                )
            )
            or arguments.asset
            or arguments.authorize_commercial
        ):
            raise CliFailure("unexpected-flow-arguments", status=_INVALID_INVOCATION)
        try:
            receipt = verify_materialized_catalog(
                arguments.catalog_root,
                PUBLIC_TASK_CATALOG,
            )
        except (OSError, ValueError, RuntimeError):
            raise CliFailure("task-qualification-failed", status=_UNSATISFIED) from None
        _emit(receipt)
        return _SUCCESS
    if (
        arguments.environment is None
        or arguments.scratch_root is None
        or arguments.store_root is None
    ):
        raise CliFailure("flow-qualification-arguments-required", status=_INVALID_INVOCATION)
    environment = load_model(arguments.environment, "environment", EnvironmentSpec)
    catalog = _private_flow_catalog(arguments)
    pack = load_flow_pack(arguments.flow, catalog)
    result = qualify_flow_pack(
        pack,
        catalog.canonical_task(pack.family),
        environment,
        catalog=catalog,
        scratch_root=arguments.scratch_root,
        store_root=arguments.store_root,
        key_file=arguments.artifact_key_file,
        asset_paths=_parse_asset_paths(arguments.asset),
        timeout_seconds=arguments.timeout_seconds,
        authorize_commercial=arguments.authorize_commercial,
        backend_deployment=arguments.backend_deployment,
    )
    _emit(result)
    return _SUCCESS


def _task_release(arguments: argparse.Namespace) -> int:
    try:
        receipt = verify_materialized_catalog(
            arguments.catalog_root,
            PUBLIC_TASK_CATALOG,
        )
    except (OSError, ValueError, RuntimeError):
        raise CliFailure("task-release-not-qualified", status=_UNSATISFIED) from None
    if arguments.family not in {entry.family for entry in receipt.attestation.families}:
        raise CliFailure("unknown-task-family", status=_INVALID_INVOCATION)
    family_attestation = next(
        item
        for item in receipt.attestation.families
        if item.family == arguments.family
    )
    instance_matches = [
        item
        for item in family_attestation.instances
        if item.instance_name == arguments.instance
    ]
    if len(instance_matches) != 1:
        raise CliFailure("unknown-task-instance", status=_INVALID_INVOCATION)
    instance = instance_matches[0]
    _emit(
        {
            "catalog_digest": receipt.digest,
            "family_attestation_digest": family_attestation.digest,
            "instance_reference_digest": instance.instance_reference_digest,
            "release_qualification_digest": instance.release_qualification_digest,
            "release_digest": instance.release_digest,
        }
    )
    return _SUCCESS


def _environment_resolve(arguments: argparse.Namespace) -> int:
    task, instance, release, environment, session = _load_resolved_inputs(arguments)
    try:
        plan = resolve_run(
            task=task,
            instance=instance,
            release=release,
            environment=environment,
            session=session,
            trial_key=arguments.trial_key,
        )
    except ResolutionError:
        raise CliFailure("run-resolution-failed", status=_UNSATISFIED) from None
    _emit(plan)
    return _SUCCESS


def _environment_verify(arguments: argparse.Namespace) -> int:
    environment = load_model(arguments.path, "environment", EnvironmentSpec)
    payload, verified = verify_environment(
        environment,
        backend_deployment=arguments.backend_deployment,
    )
    _emit(payload)
    return _SUCCESS if verified else _UNSATISFIED


def _evaluate(arguments: argparse.Namespace) -> int:
    environment = load_model(arguments.environment, "environment", EnvironmentSpec)
    release = load_model(arguments.release, "release_manifest", ReleaseManifest)
    catalog = _private_flow_catalog(arguments)
    pack = load_flow_pack(arguments.family, catalog)
    result, status = evaluate_flow_candidate(
        pack,
        catalog.canonical_task(pack.family),
        arguments.candidate_id,
        environment,
        release,
        workspace=arguments.workspace,
        runtime_root=arguments.runtime_root,
        store_root=arguments.store_root,
        key_file=arguments.artifact_key_file,
        asset_paths=_parse_asset_paths(arguments.asset),
        timeout_seconds=arguments.timeout_seconds,
        authorize_commercial=arguments.authorize_commercial,
        backend_deployment=arguments.backend_deployment,
        author_calibration=arguments.author_calibration,
    )
    _emit(result)
    return status


def _report(arguments: argparse.Namespace) -> int:
    journal = open_run(arguments.directory, arguments.task)
    session = load_model(arguments.session, "session", SessionSpec)
    kind = arguments.kind
    if kind == "auto":
        if isinstance(session.mode, CourseMode):
            kind = "course"
        elif isinstance(session.mode, BenchmarkMode):
            kind = "leaderboard"
        else:
            raise CliFailure("report-unavailable", status=_UNSATISFIED)
    try:
        projection = (
            project_course_report(journal, session)
            if kind == "course"
            else project_leaderboard_entry(journal, session)
        )
    except ProjectionUnavailable:
        raise CliFailure("report-unavailable", status=_UNSATISFIED) from None
    _emit(projection)
    return _SUCCESS


def _export_atif(arguments: argparse.Namespace) -> int:
    return _export(arguments, project_atif)


def _export_harbor(arguments: argparse.Namespace) -> int:
    return _export(arguments, project_harbor)


def _export_nemo(arguments: argparse.Namespace) -> int:
    return _export(arguments, project_nemo)


def _export_humanize(arguments: argparse.Namespace) -> int:
    journal = open_run(arguments.directory, arguments.task)
    session = load_model(arguments.session, "session", SessionSpec)
    try:
        projection = project_humanize(
            journal,
            session,
            audience=HumanizeTraceAudience(arguments.audience),
        )
    except ProjectionUnavailable:
        raise CliFailure("projection-unavailable", status=_UNSATISFIED) from None
    _emit(projection)
    return _SUCCESS


def _export(
    arguments: argparse.Namespace,
    projector: Callable[[RunJournal], BaseModel],
) -> int:
    journal = open_run(arguments.directory, arguments.task)
    try:
        projection = projector(journal)
    except ProjectionUnavailable:
        raise CliFailure("projection-unavailable", status=_UNSATISFIED) from None
    _emit(projection)
    return _SUCCESS


def _validate_spec(arguments: argparse.Namespace) -> int:
    return _validate_path(arguments.path, arguments.kind)


def _validate_path(path: Path, kind: DocumentKind) -> int:
    expected: dict[DocumentKind, type[BaseModel]] = {
        "backend_qualification": BackendQualification,
        "task": TaskSpec,
        "environment": EnvironmentSpec,
        "session": SessionSpec,
        "task_instance": TaskInstance,
        "release_manifest": ReleaseManifest,
        "release_command": ReleaseCommandReceipt,
        "release_report": ReleaseReport,
        "benchmark": BenchmarkSpec,
        "benchmark_quality_report": BenchmarkQualityReport,
        "benchmark_schedule": BenchmarkSchedule,
        "trial_observation": TrialObservation,
        "config": EdaGymConfig,
    }
    document = load_model(path, kind, expected[kind])
    payload: dict[str, object] = {"kind": kind, "status": "valid"}
    digest = getattr(document, "digest", None)
    if isinstance(digest, str):
        payload["digest"] = digest
    _emit(payload)
    return _SUCCESS


def _release_report(arguments: argparse.Namespace) -> int:
    try:
        deployment_registry = load_backend_deployment_registry(
            arguments.backend_deployment.absolute()
        )
        backend_sources = load_backend_qualification_sources(
            arguments.backend_source_registry.absolute(),
            catalog=BACKEND_CATALOG,
            deployment_registry=deployment_registry,
        )
    except (OSError, RuntimeError, ValueError):
        raise CliFailure("invalid-backend-source-registry", status=_UNSATISFIED) from None
    try:
        provider = _authoring_provider(arguments)
        authoring_provider_registration = provider.source_registration()
        sail_export = provider.open_catalog(
            PrivateAuthoringCapability.SAIL_RTL_CATALOG
        ).consume()
        materialized_sail_catalog = verify_materialized_catalog(
            arguments.sail_catalog_root,
            PUBLIC_TASK_CATALOG,
        )
        if sail_export.attestation != materialized_sail_catalog.attestation:
            raise ValueError("live Sail catalog differs from materialized catalog")
        sail_documents = sail_export.derived_tasks
        sail_qualifications = tuple(
            provider.qualify(
                PrivateAuthoringCapability.SAIL_RTL_CATALOG,
                document.instance_reference,
            )
            for document in sail_documents
        )
        materialized_flow_catalog = verify_materialized_catalog(
            arguments.flow_catalog_root,
            PUBLIC_TASK_CATALOG,
        )
        flow_catalog = load_private_flow_catalog(provider, PUBLIC_TASK_CATALOG)
        if flow_catalog.attestation != materialized_flow_catalog.attestation:
            raise ValueError("live flow catalog differs from materialized catalog")
    except (OSError, RuntimeError, ValueError):
        raise CliFailure("invalid-private-authoring-catalog", status=_UNSATISFIED) from None
    flow_documents = tuple(
        DerivedTaskDocument(
            instance_reference=flow_catalog.canonical_task(family).instance_reference,
            task=flow_catalog.canonical_task(family).task,
            instance=flow_catalog.canonical_task(family).instance,
        )
        for family in flow_catalog.families
    )
    flow_environments = tuple(
        _load_json_model(path, EnvironmentSpec, "invalid-flow-environment")
        for path in arguments.flow_environment
    )
    flow_qualification_selectors = tuple(
        _load_json_model(
            path,
            QualificationProviderResponse,
            "invalid-flow-qualification-response",
        )
        for path in arguments.flow_qualification_response
    )
    flow_document_by_reference = {
        item.instance_reference.digest: item for item in flow_documents
    }
    if (
        len(flow_document_by_reference) != len(flow_documents)
        or len(
            {item.instance_reference_digest for item in flow_qualification_selectors}
        )
        != len(flow_qualification_selectors)
        or {item.instance_reference_digest for item in flow_qualification_selectors}
        != set(flow_document_by_reference)
    ):
        raise CliFailure("invalid-flow-qualification-response", status=_UNSATISFIED)
    flow_environment_by_digest = {item.digest: item for item in flow_environments}
    if len(flow_environment_by_digest) != len(flow_environments):
        raise CliFailure("invalid-flow-environment", status=_UNSATISFIED)
    try:
        flow_qualifications = tuple(
            provider.qualify(
                PrivateAuthoringCapability.EDA_FLOW_CATALOG,
                flow_document_by_reference[selector.instance_reference_digest].instance_reference,
                environment=flow_environment_by_digest[
                    selector.release.environment_digests[0]
                ],
            )
            for selector in flow_qualification_selectors
        )
        live_by_reference = {
            item.instance_reference_digest: item for item in flow_qualifications
        }
        selected_by_reference = {
            item.instance_reference_digest: item
            for item in flow_qualification_selectors
        }
        if live_by_reference != selected_by_reference:
            raise ValueError("live flow qualifications differ from frozen selectors")
        flow_artifact_stores = {
            response.release.digest: open_artifact_store(
                arguments.flow_store_root,
                flow_environment_by_digest[response.release.environment_digests[0]],
                arguments.flow_artifact_key_file,
            )
            for response in flow_qualifications
        }
    except (IndexError, KeyError, OSError, ValueError):
        raise CliFailure("invalid-flow-artifact-store", status=_UNSATISFIED) from None
    records = tuple(
        _load_json_model(path, RunRecord, "invalid-flow-run") for path in arguments.flow_run
    )
    campaign_records = tuple(
        _load_json_model(path, CampaignRecord, "invalid-campaign-record")
        for path in arguments.campaign_record
    )
    campaigns = tuple(
        _load_json_model(path, CampaignReport, "invalid-campaign-report")
        for path in arguments.campaign_report
    )
    model_discoveries = tuple(
        _load_json_model(path, ModelDiscoverySnapshot, "invalid-model-discovery")
        for path in arguments.model_discovery
    )
    route_canaries = tuple(
        _load_json_model(path, RouteCanaryEvidence, "invalid-route-canary")
        for path in arguments.route_canary
    )
    campaign_runs = tuple(
        _load_json_model(path, RunRecord, "invalid-campaign-run") for path in arguments.campaign_run
    )
    campaign_trial_results = tuple(
        _load_json_model(path, CampaignTrialResult, "invalid-campaign-trial-result")
        for path in arguments.campaign_trial_result
    )
    campaign_task_instances = tuple(
        _load_json_model(path, TaskInstance, "invalid-campaign-task-instance")
        for path in arguments.campaign_task_instance
    )
    campaign_sessions = tuple(
        _load_json_model(path, SessionSpec, "invalid-campaign-session")
        for path in arguments.campaign_session
    )
    campaign_environments = tuple(
        _load_json_model(path, EnvironmentSpec, "invalid-campaign-environment")
        for path in arguments.campaign_environment
    )
    campaign_stores = _run_keyed_stores(
        campaign_runs,
        campaign_environments,
        store_roots=arguments.campaign_store_root,
        key_files=arguments.campaign_artifact_key_file,
        code="invalid-campaign-store",
    )
    participant_runs = tuple(
        _load_json_model(path, RunRecord, "invalid-participant-run")
        for path in arguments.participant_run
    )
    participant_tasks = tuple(
        _load_json_model(path, TaskSpec, "invalid-participant-task")
        for path in arguments.participant_task
    )
    participant_instances = tuple(
        _load_json_model(path, TaskInstance, "invalid-participant-task-instance")
        for path in arguments.participant_task_instance
    )
    participant_releases = tuple(
        _load_json_model(path, ReleaseManifest, "invalid-participant-release")
        for path in arguments.participant_release
    )
    participant_environments = tuple(
        _load_json_model(path, EnvironmentSpec, "invalid-participant-environment")
        for path in arguments.participant_environment
    )
    participant_sessions = tuple(
        _load_json_model(path, SessionSpec, "invalid-participant-session")
        for path in arguments.participant_session
    )
    participant_stores = _run_keyed_stores(
        participant_runs,
        participant_environments,
        store_roots=arguments.participant_store_root,
        key_files=arguments.participant_artifact_key_file,
        code="invalid-participant-store",
    )
    command_environment = load_model(
        arguments.command_environment,
        "environment",
        EnvironmentSpec,
    )
    command_store = open_artifact_store(
        arguments.command_store_root,
        command_environment,
        arguments.command_artifact_key_file,
    )
    repository = audit_repository(
        arguments.repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(
            external_scanner_executable=os.fspath(arguments.gitleaks),
        ),
    )
    if repository.status is not AuditStatus.PASS or repository.snapshot is None:
        raise CliFailure("repository-audit-not-passing", status=int(repository.exit_code))
    try:
        commands = execute_release_commands(
            repository=arguments.repository,
            repository_audit=repository,
            artifact_store=command_store,
            timeout_seconds=arguments.command_timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError):
        raise CliFailure("release-command-execution-failed", status=_INCOMPLETE) from None
    with ExitStack() as resources:
        executor_registry = None
        if arguments.executor_deployment is not None:
            try:
                executor_registry = resources.enter_context(
                    load_executor_deployment_registry(
                        arguments.executor_deployment.absolute()
                    )
                )
            except (OSError, RuntimeError, ValueError):
                raise CliFailure("invalid-executor-deployment", status=_UNSATISFIED) from None
        executor_qualification = _executor_qualification(arguments)
        try:
            report = build_release_report(
                public_task_catalog=PUBLIC_TASK_CATALOG,
                sail_catalog_attestation=materialized_sail_catalog.attestation,
                sail_task_documents=sail_documents,
                sail_qualification_responses=sail_qualifications,
                backend_catalog=BACKEND_CATALOG,
                backend_sources=backend_sources,
                flow_catalog=flow_catalog,
                flow_catalog_attestation=materialized_flow_catalog.attestation,
                flow_task_documents=flow_documents,
                flow_environments=flow_environments,
                flow_qualification_responses=flow_qualifications,
                flow_run_records=records,
                flow_artifact_stores=flow_artifact_stores,
                campaign_records=campaign_records,
                campaign_reports=campaigns,
                model_discovery_snapshots=model_discoveries,
                route_canary_evidence=route_canaries,
                campaign_run_records=campaign_runs,
                campaign_trial_results=campaign_trial_results,
                campaign_task_instances=campaign_task_instances,
                campaign_sessions=campaign_sessions,
                campaign_environments=campaign_environments,
                repository_audit=repository,
                local_containment=probe_local_containment(),
                command_receipts=commands,
                repository_root=arguments.repository,
                sail_catalog_root=arguments.sail_catalog_root,
                flow_catalog_root=arguments.flow_catalog_root,
                authoring_provider_registration=authoring_provider_registration,
                campaign_artifact_stores=campaign_stores,
                participant_run_records=participant_runs,
                participant_task_specs=participant_tasks,
                participant_task_instances=participant_instances,
                participant_releases=participant_releases,
                participant_environments=participant_environments,
                participant_sessions=participant_sessions,
                participant_artifact_stores=participant_stores,
                executor_deployment_registry=executor_registry,
                executor_qualification=executor_qualification,
            )
        except (ValueError, ValidationError):
            raise CliFailure("invalid-release-evidence", status=_UNSATISFIED) from None
    _emit(report)
    return {
        ReleaseDecision.READY: _SUCCESS,
        ReleaseDecision.BLOCKED: _UNSATISFIED,
        ReleaseDecision.INCOMPLETE: _INCOMPLETE,
    }[report.decision]


def _release_command(arguments: argparse.Namespace) -> int:
    environment = load_model(arguments.environment, "environment", EnvironmentSpec)
    store = open_artifact_store(
        arguments.store_root,
        environment,
        arguments.artifact_key_file,
    )
    audit = audit_repository(
        arguments.repository,
        AuditMode.RELEASE,
        policy=RepositoryPolicy(
            external_scanner_executable=os.fspath(arguments.gitleaks),
        ),
    )
    if audit.status is not AuditStatus.PASS or audit.snapshot is None:
        raise CliFailure("repository-audit-not-passing", status=int(audit.exit_code))
    purpose = ReleaseCommandPurpose(arguments.purpose)
    try:
        installation = (
            execute_release_command(
                purpose=ReleaseCommandPurpose.CLEAN_INSTALLATION,
                repository=arguments.repository,
                repository_audit=audit,
                input_subject_digest=audit.snapshot.digest,
                artifact_store=store,
                timeout_seconds=arguments.timeout_seconds,
            )
            if release_command_requires_installation(purpose)
            else None
        )
        verified = execute_release_command(
            purpose=purpose,
            repository=arguments.repository,
            repository_audit=audit,
            input_subject_digest=(
                PUBLIC_TASK_CATALOG.digest
                if purpose is ReleaseCommandPurpose.AUTHORING_CONTRACT
                else audit.snapshot.digest
            ),
            artifact_store=store,
            timeout_seconds=arguments.timeout_seconds,
            installation=installation,
        )
    except (KeyError, OSError, RuntimeError, ValueError):
        raise CliFailure("release-command-failed", status=_INCOMPLETE) from None
    _emit(verified.receipt)
    return {
        ReleaseEvidenceStatus.PASSED: _SUCCESS,
        ReleaseEvidenceStatus.FAILED: _UNSATISFIED,
        ReleaseEvidenceStatus.UNAVAILABLE: _INCOMPLETE,
    }[verified.receipt.status]

def _repository_audit(arguments: argparse.Namespace) -> int:
    report = audit_repository(
        arguments.repository,
        AuditMode(arguments.mode),
        policy=RepositoryPolicy(
            external_scanner_executable=os.fspath(arguments.gitleaks),
        ),
    )
    _emit(report.as_dict() if arguments.json else report.to_text(), as_json=arguments.json)
    return int(report.exit_code)


def _load_resolved_inputs(
    arguments: argparse.Namespace,
) -> tuple[TaskSpec, TaskInstance, ReleaseManifest, EnvironmentSpec, SessionSpec]:
    return (
        load_model(arguments.task, "task", TaskSpec),
        load_model(arguments.instance, "task_instance", TaskInstance),
        load_model(arguments.release, "release_manifest", ReleaseManifest),
        load_model(arguments.environment, "environment", EnvironmentSpec),
        load_model(arguments.session, "session", SessionSpec),
    )


def _load_json_model[T: BaseModel](path: Path, model: type[T], code: str) -> T:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return model.model_validate(json.load(stream))
    except (OSError, ValueError, ValidationError):
        raise CliFailure(code, status=_UNSATISFIED) from None


def _parse_asset_paths(values: Sequence[str]) -> dict[str, Path]:
    return parse_keyed_paths(
        values,
        code="invalid-flow-asset-binding",
        status=_INVALID_INVOCATION,
    )


def _run_keyed_stores(
    run_records: tuple[RunRecord, ...],
    environments: tuple[EnvironmentSpec, ...],
    *,
    store_roots: Sequence[str],
    key_files: Sequence[str],
    code: str,
) -> dict[str, ContentAddressedStore]:
    return open_run_artifact_stores(
        run_records,
        environments,
        parse_keyed_paths(store_roots, code=code, status=_INVALID_INVOCATION),
        parse_keyed_paths(key_files, code=code, status=_INVALID_INVOCATION),
        code=code,
    )


def _executor_qualification(
    arguments: argparse.Namespace,
) -> VerifiedExecutorQualification | None:
    """Replay the committed VM executor qualification; an absent source stays unregistered."""

    source_path = arguments.executor_qualification
    store_root = arguments.executor_qualification_store_root
    key_file = arguments.executor_qualification_key_file
    if source_path is None and store_root is None and key_file is None:
        return None
    if source_path is None or store_root is None:
        raise CliFailure("executor-qualification-store-required", status=_INVALID_INVOCATION)
    source = _load_json_model(
        source_path,
        VmExecutorQualificationSource,
        "invalid-executor-qualification",
    )
    store = open_artifact_store(store_root, source.environment, key_file)
    try:
        return verify_executor_qualification_source(source, store)
    except (ArtifactStoreError, OSError, TypeError, ValueError):
        raise CliFailure("invalid-executor-qualification", status=_UNSATISFIED) from None


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        raise CliFailure("scratch-root-unavailable", status=_INCOMPLETE) from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CliFailure("scratch-root-insecure", status=_UNSATISFIED)


def _safe_error(code: str) -> None:
    sys.stderr.buffer.write(canonical_bytes({"error": code}) + b"\n")


def main(arguments: list[str] | None = None) -> int:
    parser = _parser()
    parsed = parser.parse_args(arguments)
    handler: Callable[[argparse.Namespace], int] = parsed.handler
    try:
        return handler(parsed)
    except CliFailure as error:
        _safe_error(error.code)
        return error.status
    except KeyboardInterrupt:
        _safe_error("interrupted")
        return _INCOMPLETE
    except (OSError, ValueError, ValidationError, JournalError):
        _safe_error("operation-failed")
        return _INCOMPLETE
    except Exception:
        _safe_error("internal-error")
        return _INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(main())
