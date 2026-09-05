"""Typed authoring recipes for non-Sail EDA workflows."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.specs.common import Capability, Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.task import MeasurementUnit, MetricDirection, StagePurpose

DECIMAL_CAPTURE_PATTERN = r"(-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)"


class CandidateExpectation(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class Comparison(StrEnum):
    LESS_EQUAL = "less_equal"
    GREATER_EQUAL = "greater_equal"


class NumberSelection(StrEnum):
    FIRST = "first"
    MINIMUM = "minimum"
    MAXIMUM = "maximum"


class RuleSource(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"
    FILE = "file"


class TaskAsset(StrictModel):
    path: str
    content: Annotated[str, Field(max_length=8 * 1024 * 1024)]

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or not value or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("task asset paths must be normalized relative POSIX paths")
        return path.as_posix()


class CandidateVariant(StrictModel):
    candidate_id: Identifier
    expectation: CandidateExpectation
    assets: tuple[TaskAsset, ...]

    @model_validator(mode="after")
    def validate_assets(self) -> Self:
        paths = [asset.path for asset in self.assets]
        if not paths or len(paths) != len(set(paths)):
            raise ValueError("candidate assets must be unique and non-empty")
        return self


class ToolCommand(StrictModel):
    kind: Literal["tool"] = "tool"
    tool_id: Identifier
    capability: Capability
    arguments: tuple[str, ...]

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in item or "\n" in item or "\r" in item for item in value):
            raise ValueError("command arguments cannot contain control boundaries")
        return value


class WorkspaceCommand(StrictModel):
    kind: Literal["workspace"] = "workspace"
    executable: str
    arguments: tuple[str, ...] = ()

    @field_validator("executable")
    @classmethod
    def normalize_executable(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or not value or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("workspace executables must be normalized relative paths")
        return path.as_posix()

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in item or "\n" in item or "\r" in item for item in value):
            raise ValueError("command arguments cannot contain control boundaries")
        return value


TaskCommand = Annotated[ToolCommand | WorkspaceCommand, Field(discriminator="kind")]


class ExitRule(StrictModel):
    kind: Literal["exit"] = "exit"
    expected_codes: tuple[int, ...] = (0,)

    @field_validator("expected_codes")
    @classmethod
    def validate_codes(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("exit rules require unique expected codes")
        return tuple(sorted(value))


class ContainsRule(StrictModel):
    kind: Literal["contains"] = "contains"
    source: RuleSource
    token: Annotated[str, Field(min_length=1, max_length=256)]
    path: str | None = None

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if (self.source is RuleSource.FILE) != (self.path is not None):
            raise ValueError("file containment rules require exactly one file path")
        if self.path is not None:
            TaskAsset(path=self.path, content="")
        return self


class RegexNumberRule(StrictModel):
    kind: Literal["regex_number"] = "regex_number"
    source: RuleSource
    pattern: Annotated[str, Field(min_length=1, max_length=512)]
    comparison: Comparison
    threshold: Annotated[str, Field(pattern=r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")]
    selection: NumberSelection = NumberSelection.FIRST
    measurement_id: Identifier | None = None
    measurement_unit: MeasurementUnit | None = None
    metric_direction: MetricDirection | None = None
    metric_target: Annotated[
        str | None,
        Field(pattern=r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$"),
    ] = None
    library_path: str | None = None
    corner: Identifier | None = None
    mode: Identifier | None = None
    path: str | None = None

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if (self.source is RuleSource.FILE) != (self.path is not None):
            raise ValueError("file numeric rules require exactly one file path")
        if self.path is not None:
            TaskAsset(path=self.path, content="")
        if self.library_path is not None:
            TaskAsset(path=self.library_path, content="")
        context = (
            self.measurement_unit,
            self.metric_direction,
            self.corner,
            self.mode,
        )
        if (self.measurement_id is not None) != all(item is not None for item in context):
            raise ValueError(
                "measurement extraction requires an explicit unit, direction, corner, and mode"
            )
        if self.measurement_id is None and self.library_path is not None:
            raise ValueError("only measurement extraction may identify a library asset")
        if self.measurement_id is None and self.metric_target is not None:
            raise ValueError("only measurement extraction may define an objective target")
        if self.metric_direction is MetricDirection.NONE:
            raise ValueError("flow measurements must be optimization objectives")
        if (self.metric_direction is MetricDirection.TARGET) != (self.metric_target is not None):
            raise ValueError("target objectives require exactly one metric target")
        return self


AcceptanceRule = Annotated[
    ExitRule | ContainsRule | RegexNumberRule,
    Field(discriminator="kind"),
]


class FlowStageDefinition(StrictModel):
    stage_id: Identifier
    capability: Capability
    purpose: StagePurpose
    requirement_ids: tuple[Identifier, ...]
    depends_on: tuple[Identifier, ...] = ()
    assets: tuple[TaskAsset, ...]
    commands: tuple[TaskCommand, ...]
    rules: tuple[AcceptanceRule, ...]
    output_paths: tuple[str, ...] = ()

    @field_validator("requirement_ids", "depends_on")
    @classmethod
    def normalize_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("stage references must be unique")
        return tuple(sorted(value))

    @field_validator("output_paths")
    @classmethod
    def normalize_output_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("stage output paths must be unique")
        for path in value:
            TaskAsset(path=path, content="")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_stage(self) -> Self:
        asset_paths = [asset.path for asset in self.assets]
        if len(asset_paths) != len(set(asset_paths)):
            raise ValueError("stage assets must have unique paths")
        if not self.commands or not self.rules:
            raise ValueError("flow stages require commands and semantic acceptance rules")
        primary = self.commands[0]
        if not isinstance(primary, ToolCommand) or primary.capability is not self.capability:
            raise ValueError("a flow stage must begin with its declared primary capability")
        if sum(isinstance(rule, ExitRule) for rule in self.rules) != 1:
            raise ValueError("a flow stage requires exactly one typed exit rule")
        referenced_files = {
            rule.path
            for rule in self.rules
            if not isinstance(rule, ExitRule) and rule.source is RuleSource.FILE
        }
        if not referenced_files.issubset(self.output_paths):
            raise ValueError("file acceptance rules must reference declared stage outputs")
        if set(asset_paths) & set(self.output_paths):
            raise ValueError("verifier assets and collected outputs must be disjoint")
        measurements = [
            rule.measurement_id
            for rule in self.rules
            if isinstance(rule, RegexNumberRule) and rule.measurement_id is not None
        ]
        if len(measurements) != len(set(measurements)):
            raise ValueError("stage measurement identities must be unique")
        return self


class FlowTaskPack(StrictModel):
    schema_version: SchemaVersion = 1
    family: Identifier
    semantic_definition_digest: Digest
    authoring_revision: Annotated[int, Field(strict=True, ge=1)] = 1
    requirements: tuple[Identifier, ...]
    candidates: tuple[CandidateVariant, ...]
    stages: tuple[FlowStageDefinition, ...]

    @field_validator("requirements")
    @classmethod
    def normalize_requirements(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("pack requirements must be unique and non-empty")
        return tuple(sorted(value))

    @field_validator("candidates")
    @classmethod
    def normalize_candidates(
        cls, value: tuple[CandidateVariant, ...]
    ) -> tuple[CandidateVariant, ...]:
        return tuple(sorted(value, key=lambda candidate: candidate.candidate_id))

    @field_validator("stages")
    @classmethod
    def normalize_stages(
        cls, value: tuple[FlowStageDefinition, ...]
    ) -> tuple[FlowStageDefinition, ...]:
        return tuple(sorted(value, key=lambda stage: stage.stage_id))

    @model_validator(mode="after")
    def validate_pack(self) -> Self:
        candidate_ids = [candidate.candidate_id for candidate in self.candidates]
        expectations = [candidate.expectation for candidate in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate identifiers must be unique")
        if expectations.count(CandidateExpectation.ACCEPTED) != 1:
            raise ValueError("a task pack requires exactly one feasibility witness")
        if CandidateExpectation.REJECTED not in expectations:
            raise ValueError("a task pack requires at least one rejected candidate")
        candidate_payloads = {
            tuple(sorted((asset.path, asset.content) for asset in candidate.assets))
            for candidate in self.candidates
        }
        if len(candidate_payloads) != len(self.candidates):
            raise ValueError("qualification candidates must contain distinct submissions")

        stages = {stage.stage_id: stage for stage in self.stages}
        if len(stages) != len(self.stages) or not stages:
            raise ValueError("stage identifiers must be unique and non-empty")
        checked = {
            requirement
            for stage in self.stages
            if stage.purpose is StagePurpose.HARD_GATE
            for requirement in stage.requirement_ids
        }
        if checked != set(self.requirements):
            raise ValueError("hard gates must own every pack requirement exactly by reference")
        for stage in self.stages:
            if set(stage.depends_on) - stages.keys() or stage.stage_id in stage.depends_on:
                raise ValueError("stage dependencies must reference other stages")
            if set(stage.requirement_ids) - set(self.requirements):
                raise ValueError("stages cannot reference undeclared requirements")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(stage_id: str) -> None:
            if stage_id in visiting:
                raise ValueError("flow stages must form an acyclic graph")
            if stage_id in visited:
                return
            visiting.add(stage_id)
            for dependency in stages[stage_id].depends_on:
                visit(dependency)
            visiting.remove(stage_id)
            visited.add(stage_id)

        for stage_id in stages:
            visit(stage_id)

        common_paths = {asset.path for stage in self.stages for asset in stage.assets}
        if len(common_paths) != sum(len(stage.assets) for stage in self.stages):
            raise ValueError("stage assets cannot shadow one another")
        output_paths = {path for stage in self.stages for path in stage.output_paths}
        for candidate in self.candidates:
            paths = {asset.path for asset in candidate.assets}
            if paths & (common_paths | output_paths):
                raise ValueError("candidate assets cannot occupy evaluator-owned paths")
        submission_shapes = {
            tuple(sorted(asset.path for asset in candidate.assets)) for candidate in self.candidates
        }
        if len(submission_shapes) != 1:
            raise ValueError("qualification candidates must share one submission file contract")
        return self

    @property
    def submission_paths(self) -> tuple[str, ...]:
        return tuple(sorted(asset.path for asset in self.candidates[0].assets))

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain="eda-flow-task-pack-v1")
