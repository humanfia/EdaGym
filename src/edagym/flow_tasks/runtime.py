"""Canonical flow evaluator runtime backed by the executor's trusted supervisor."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Literal, Self

from pydantic import Field, model_validator

from edagym.canonical import canonical_digest
from edagym.evaluation.model import (
    ArtifactEvidence,
    CandidateFailureOutcome,
    EvidenceKind,
    InfrastructureFailureOutcome,
    MeasurementEvidence,
    MeasurementProvenance,
    PassedOutcome,
    StageResult,
)
from edagym.evaluation.scoring import measurement_sample_seeds
from edagym.executors.model import (
    COMPOSITE_REPORT_LOGICAL_ID,
    COMPOSITE_REPORT_PATH,
    ExecutionResult,
    InvocationPlan,
    InvocationView,
    OutputDeclaration,
    RecipeCommand,
    ToolRecipeCommand,
    WorkspaceRecipeCommand,
)
from edagym.flow_tasks.canonical import (
    CanonicalFlowTask,
    flow_evaluator_id,
    flow_evaluator_revision_digest,
    require_flow_environment,
    validate_canonical_flow_task,
)
from edagym.flow_tasks.model import (
    FlowStageDefinition,
    FlowTaskPack,
    RegexNumberRule,
    RuleSource,
    TaskAsset,
    ToolCommand,
    WorkspaceCommand,
)
from edagym.flow_tasks.rootless import (
    rootless_flow_arguments,
    validate_rootless_flow_environment,
)
from edagym.flow_tasks.rules import evaluate_acceptance_rules
from edagym.run.artifacts import ContentAddressedStore
from edagym.runtime.model import EvaluationArtifacts, EvaluationContext, EvaluatorRuntime
from edagym.specs.common import (
    ArtifactClass,
    Digest,
    SchemaVersion,
    StrictModel,
)
from edagym.specs.environment import (
    BrokeredHostToolExecutor,
    EnvironmentSpec,
    RootlessLocalExecutor,
)

_MAXIMUM_RESULT_BYTES = 64 * 1024 * 1024


class CommandReportEntry(StrictModel):
    identity_digest: Digest
    exit_code: int | None
    failure: Literal["spawn_failed"] | None
    stdout_digest: Digest
    stdout_size_bytes: int = Field(ge=0)
    stderr_digest: Digest
    stderr_size_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_failure(self) -> Self:
        if (self.exit_code is None) != (self.failure is not None):
            raise ValueError("command failure requires exactly one missing exit code")
        return self


class CompositeCommandReport(StrictModel):
    schema_version: SchemaVersion = 1
    status: Literal["completed", "driver_error"]
    commands: tuple[CommandReportEntry, ...]

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status == "driver_error" and self.commands:
            raise ValueError("driver errors cannot claim completed commands")
        if self.status == "completed" and not self.commands:
            raise ValueError("completed composite reports require command evidence")
        return self


class FlowEvaluatorRuntime(EvaluatorRuntime):
    """Materialize sealed verifier assets and parse one immutable flow recipe."""

    def __init__(
        self,
        *,
        pack: FlowTaskPack,
        canonical: CanonicalFlowTask,
        environment: EnvironmentSpec,
        stage: FlowStageDefinition,
        artifact_store: ContentAddressedStore,
    ) -> None:
        validate_runtime_inputs(pack, canonical, environment)
        if stage not in pack.stages:
            raise ValueError("flow evaluator stage does not belong to its task pack")
        self._pack = pack
        self._canonical = canonical
        self._environment = environment
        self._stage = stage
        self._artifact_store = artifact_store
        self._recipe = _recipe(stage, environment)
        primary = self._recipe[0]
        if not isinstance(primary, ToolRecipeCommand):
            raise ValueError("flow recipes must begin with their primary tool")
        self._primary: ToolRecipeCommand = primary

    @property
    def evaluator_id(self) -> str:
        return flow_evaluator_id(self._stage.stage_id)

    @property
    def evaluator_revision_digest(self) -> str:
        return flow_evaluator_revision_digest(self._stage)

    @property
    def driver_digest(self) -> str:
        return self._primary.driver_digest

    def prepare(self, context: EvaluationContext) -> InvocationPlan:
        self._validate_context(context)
        _reserve_outputs(context.workspace, self._stage.output_paths)
        if isinstance(self._environment.executor, BrokeredHostToolExecutor):
            _materialize_assets(context.workspace, self._stage.assets)
        outputs = [
            OutputDeclaration(
                logical_id=COMPOSITE_REPORT_LOGICAL_ID,
                path=COMPOSITE_REPORT_PATH,
                media_type="application/json",
                artifact_class=ArtifactClass.EVIDENCE,
            )
        ]
        outputs.extend(
            OutputDeclaration(
                logical_id=_output_id(position),
                path=path,
                media_type=_output_media_type(path),
                artifact_class=ArtifactClass.EVIDENCE,
                required=False,
            )
            for position, path in enumerate(self._stage.output_paths)
        )
        return InvocationPlan(
            invocation_id=context.job_id,
            capability=self._primary.capability,
            tool_id=self._primary.tool_id,
            driver_digest=self._primary.driver_digest,
            view=InvocationView.EVALUATOR,
            executable=self._primary.executable,
            input_manifest_digest=context.input_manifest_digest,
            recipe=self._recipe,
            outputs=tuple(outputs),
        )

    def evaluate(
        self,
        context: EvaluationContext,
        execution: ExecutionResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult:
        self._validate_context(context)
        report = CompositeCommandReport.model_validate_json(
            _read_artifact(
                self._artifact_store,
                artifacts,
                COMPOSITE_REPORT_LOGICAL_ID,
            )
        )
        expected_identities = tuple(
            canonical_digest(command, domain="composite-recipe-command-v1")
            for command in self._recipe
        )
        actual_identities = tuple(command.identity_digest for command in report.commands)
        if actual_identities != expected_identities[: len(actual_identities)]:
            raise ValueError("composite report command identity diverges from its recipe")
        if report.status == "driver_error" or not report.commands:
            return StageResult(
                stage_id=self._stage.stage_id,
                outcome=InfrastructureFailureOutcome(),
            )
        terminal = report.commands[-1]
        if any(
            command.failure is not None or command.exit_code != 0
            for command in report.commands[:-1]
        ):
            raise ValueError("composite report continued after a terminal command")
        if (
            terminal.failure is None
            and terminal.exit_code == 0
            and len(report.commands) != len(self._recipe)
        ):
            raise ValueError("a successful composite report omitted recipe commands")
        if any(command.failure is not None for command in report.commands):
            return StageResult(
                stage_id=self._stage.stage_id,
                outcome=InfrastructureFailureOutcome(),
            )

        stdout = _read_artifact(self._artifact_store, artifacts, "executor.stdout")
        stderr = _read_artifact(self._artifact_store, artifacts, "executor.stderr")
        _validate_stream_report(
            stdout,
            tuple(
                (command.stdout_size_bytes, command.stdout_digest) for command in report.commands
            ),
            "stdout",
        )
        _validate_stream_report(
            stderr,
            tuple(
                (command.stderr_size_bytes, command.stderr_digest) for command in report.commands
            ),
            "stderr",
        )
        files = {
            path: _read_artifact(self._artifact_store, artifacts, local_id)
            for position, path in enumerate(self._stage.output_paths)
            if (local_id := _output_id(position)) in artifacts
        }
        exit_codes = tuple(
            command.exit_code for command in report.commands if command.exit_code is not None
        )
        if len(files) != len(self._stage.output_paths) and all(
            exit_code == 0 for exit_code in exit_codes
        ):
            return StageResult(
                stage_id=self._stage.stage_id,
                outcome=InfrastructureFailureOutcome(),
            )
        result = evaluate_acceptance_rules(
            self._stage.rules,
            exit_codes=exit_codes,
            stdout=stdout,
            stderr=stderr,
            files=files,
        )
        measurements = {item.measurement_id for item in result.measurements}
        declared = {
            item.measurement_id
            for item in context.task.measurements
            if item.producer_stage_id == self._stage.stage_id
        }
        if not measurements.issubset(declared):
            raise ValueError("flow result emitted an undeclared measurement")
        evidence = _declared_evidence(artifacts)
        evidence_ids = {item.artifact_id for item in evidence}
        measurements_with_provenance = tuple(
            MeasurementEvidence(
                measurement_id=measurement.measurement_id,
                samples=measurement.samples,
                provenance=_measurement_provenance(
                    context,
                    self._stage,
                    artifacts,
                    measurement.measurement_id,
                ),
            )
            for measurement in result.measurements
        )
        if any(
            measurement.provenance is None
            or measurement.provenance.source_artifact_id not in evidence_ids
            for measurement in measurements_with_provenance
        ):
            raise ValueError("measurement source is not visible under the feedback policy")
        return StageResult(
            stage_id=self._stage.stage_id,
            outcome=PassedOutcome() if result.accepted else CandidateFailureOutcome(),
            measurements=measurements_with_provenance,
            evidence=evidence,
        )

    def _validate_context(self, context: EvaluationContext) -> None:
        if (
            context.task.digest != self._canonical.task.digest
            or context.instance.digest != self._canonical.instance.digest
            or context.environment != self._environment
            or context.release.verifier_bundle_digest
            != self._canonical.instance_reference.verifier_bundle_digest
            or context.stage.stage_id != self._stage.stage_id
            or context.stage.evaluator_id != self.evaluator_id
            or context.assignment.driver_digest != self.driver_digest
        ):
            raise ValueError("flow evaluator context does not match its sealed release")


def validate_runtime_inputs(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
) -> None:
    """Validate provider-derived run inputs and all recipe tool identities."""

    validate_canonical_flow_task(pack, canonical)
    require_flow_environment(pack, environment)
    if isinstance(environment.executor, RootlessLocalExecutor):
        validate_rootless_flow_environment(pack, environment)
    elif not isinstance(environment.executor, BrokeredHostToolExecutor):
        raise ValueError("composite flow recipes require a trusted recipe supervisor")


def flow_evaluator_runtimes(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
    artifact_store: ContentAddressedStore,
) -> tuple[FlowEvaluatorRuntime, ...]:
    """Build exact evaluator coverage for RunOrchestrator."""

    return tuple(
        FlowEvaluatorRuntime(
            pack=pack,
            canonical=canonical,
            environment=environment,
            stage=stage,
            artifact_store=artifact_store,
        )
        for stage in pack.stages
    )


def _recipe(
    stage: FlowStageDefinition,
    environment: EnvironmentSpec,
) -> tuple[RecipeCommand, ...]:
    bindings = {
        (binding.capability, binding.tool_id): binding for binding in environment.tool_bindings
    }
    recipe: list[RecipeCommand] = []
    rootless = isinstance(environment.executor, RootlessLocalExecutor)
    for command in stage.commands:
        if isinstance(command, ToolCommand):
            binding = bindings.get((command.capability, command.tool_id))
            if binding is None:
                raise ValueError("flow recipe command has no exact environment binding")
            recipe.append(
                ToolRecipeCommand(
                    tool_id=binding.tool_id,
                    capability=binding.capability,
                    driver_digest=binding.driver_digest,
                    executable=binding.locator.executable,
                    arguments=(
                        rootless_flow_arguments(stage, command.arguments)
                        if rootless
                        else command.arguments
                    ),
                )
            )
        elif isinstance(command, WorkspaceCommand):
            recipe.append(
                WorkspaceRecipeCommand(
                    executable=command.executable,
                    arguments=command.arguments,
                )
            )
        else:
            raise TypeError("unsupported flow command")
    if not recipe or not isinstance(recipe[0], ToolRecipeCommand):
        raise ValueError("a flow recipe must begin with a resolved tool")
    if recipe[0].capability is not stage.capability:
        raise ValueError("a flow recipe must begin with its declared stage capability")
    return tuple(recipe)


def _read_artifact(
    store: ContentAddressedStore,
    artifacts: EvaluationArtifacts,
    local_id: str,
) -> bytes:
    artifact = artifacts[local_id]
    if artifact.record.blob.size_bytes > _MAXIMUM_RESULT_BYTES:
        raise ValueError("flow evaluation artifact exceeds its parser bound")
    return store.read_bytes(
        artifact.record.blob,
        maximum_bytes=artifact.record.blob.size_bytes,
    )


def _validate_stream_report(
    content: bytes,
    entries: tuple[tuple[int, str], ...],
    stream_name: str,
) -> None:
    offset = 0
    for size, expected_digest in entries:
        chunk = content[offset : offset + size]
        actual_digest = f"sha256:{hashlib.sha256(chunk).hexdigest()}"
        if len(chunk) != size or actual_digest != expected_digest:
            raise ValueError(f"composite {stream_name} disagrees with its command report")
        offset += size
    if offset != len(content):
        raise ValueError(f"composite {stream_name} has unreported bytes")


def _declared_evidence(
    artifacts: EvaluationArtifacts,
) -> tuple[ArtifactEvidence, ...]:
    return tuple(
        ArtifactEvidence(
            kind=(
                EvidenceKind.LOG
                if local_id in {"executor.stdout", "executor.stderr"}
                else EvidenceKind.REPORT
            ),
            artifact_id=artifact.record.logical_id,
        )
        for local_id, artifact in artifacts.items()
        if artifact.record.artifact_class in {ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE}
    )


def _measurement_provenance(
    context: EvaluationContext,
    stage: FlowStageDefinition,
    artifacts: EvaluationArtifacts,
    measurement_id: str,
) -> MeasurementProvenance:
    matches = [
        rule
        for rule in stage.rules
        if isinstance(rule, RegexNumberRule) and rule.measurement_id == measurement_id
    ]
    if len(matches) != 1:
        raise ValueError("measurement does not have one source rule")
    rule = matches[0]
    if rule.source is RuleSource.STDOUT:
        local_id = "executor.stdout"
    elif rule.source is RuleSource.STDERR:
        local_id = "executor.stderr"
    else:
        if rule.path is None:
            raise ValueError("file measurement does not name its source")
        local_id = _output_id(stage.output_paths.index(rule.path))
    source = artifacts[local_id].record
    specification = next(
        item for item in context.task.measurements if item.measurement_id == measurement_id
    )
    tool = next(
        item
        for item in context.environment.tool_bindings
        if item.capability is context.assignment.capability
        and item.tool_id == context.assignment.tool_id
    )
    return MeasurementProvenance(
        unit=specification.unit,
        tool_id=tool.tool_id,
        tool_version=tool.tool_version,
        library_id=specification.library_id,
        library_digest=specification.library_digest,
        corner=specification.corner,
        mode=specification.mode,
        task_seed=context.instance.identity.seed,
        sample_seeds=measurement_sample_seeds(
            context.instance.identity.seed,
            specification.measurement_id,
            specification.repetitions,
        ),
        source_artifact_id=source.logical_id,
        source_digest=source.blob.digest,
    )


def _reserve_outputs(workspace: Path, paths: Sequence[str]) -> None:
    for path in (*paths, COMPOSITE_REPORT_PATH):
        target = workspace / path
        try:
            target.lstat()
        except FileNotFoundError:
            continue
        raise ValueError("candidate snapshot occupies a verifier-owned output path")


def _materialize_assets(workspace: Path, assets: Sequence[TaskAsset]) -> None:
    root = os.open(
        workspace,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for asset in assets:
            _write_relative(root, asset.path, asset.content.encode("utf-8"))
    finally:
        os.close(root)


def _write_relative(root: int, relative: str, content: bytes) -> None:
    parts = PurePosixPath(relative).parts
    parent = os.dup(root)
    try:
        for part in parts[:-1]:
            with suppress(FileExistsError):
                os.mkdir(part, mode=0o700, dir_fd=parent)
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            metadata = os.fstat(child)
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                os.close(child)
                raise ValueError("verifier asset parent is not privately controlled")
            os.close(parent)
            parent = child
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if not written:
                    raise OSError("short write while materializing verifier assets")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _output_id(position: int) -> str:
    return f"flow_output_{position}"


def _output_media_type(path: str) -> str:
    suffix = path.rpartition(".")[2].lower()
    return {
        "csv": "text/csv",
        "def": "text/plain",
        "json": "application/json",
        "lib": "text/plain",
        "log": "text/plain",
        "rpt": "text/plain",
        "v": "text/x-verilog",
    }.get(suffix, "application/octet-stream")
