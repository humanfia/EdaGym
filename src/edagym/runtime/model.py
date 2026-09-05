"""Trusted evaluator boundary used by the run orchestrator."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from edagym.evaluation.model import StageResult
from edagym.executors.model import ExecutionResult, InvocationPlan
from edagym.resolution import StageDriverAssignment
from edagym.run.model import ArtifactRecord, CandidateState
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import ReleaseManifest, TaskInstance
from edagym.specs.session import SessionSpec
from edagym.specs.task import StageSpec, TaskSpec


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """Immutable identities and paths for one candidate-stage evaluation."""

    run_id: str
    job_id: str
    input_manifest_digest: str
    task: TaskSpec
    instance: TaskInstance
    release: ReleaseManifest
    environment: EnvironmentSpec
    session: SessionSpec
    candidate: CandidateState
    stage: StageSpec
    assignment: StageDriverAssignment
    workspace: Path


@dataclass(frozen=True, slots=True)
class EvaluationArtifact:
    """One executor-local artifact and its run-global immutable record."""

    local_id: str
    record: ArtifactRecord


class EvaluationArtifacts(Mapping[str, EvaluationArtifact]):
    """Read-only artifact index passed to a trusted evaluator parser."""

    def __init__(self, artifacts: tuple[EvaluationArtifact, ...]) -> None:
        indexed = {artifact.local_id: artifact for artifact in artifacts}
        if len(indexed) != len(artifacts):
            raise ValueError("evaluation artifact local identifiers must be unique")
        self._artifacts = MappingProxyType(indexed)

    def __getitem__(self, key: str) -> EvaluationArtifact:
        return self._artifacts[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._artifacts)

    def __len__(self) -> int:
        return len(self._artifacts)


class EvaluatorRuntime(Protocol):
    """Prepare one sealed invocation and interpret its typed execution result."""

    @property
    def evaluator_id(self) -> str: ...

    @property
    def evaluator_revision_digest(self) -> str: ...

    @property
    def driver_digest(self) -> str: ...

    def prepare(self, context: EvaluationContext) -> InvocationPlan: ...

    def evaluate(
        self,
        context: EvaluationContext,
        execution: ExecutionResult,
        artifacts: EvaluationArtifacts,
    ) -> StageResult: ...
