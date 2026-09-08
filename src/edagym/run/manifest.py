"""Frozen run binding derived from a private configuration snapshot."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import field_validator, model_validator

from edagym.canonical import canonical_digest
from edagym.config.model import PrivateConfigSnapshot
from edagym.specs.common import Capability, Digest, Identifier, StrictModel
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.release import TaskInstance


class RunPurpose(StrEnum):
    TASK = "task"
    QUALIFICATION = "qualification"


class RunManifest(StrictModel):
    """One immutable binding for task, views, session, harness, and budgets."""

    schema_version: Literal[3] = 3
    purpose: RunPurpose = RunPurpose.TASK
    run_id: Identifier
    task_instance_digest: Digest
    task_spec_digest: Digest
    private_config_snapshot_digest: Digest
    creation_intent_digest: Digest | None = None
    participant: EnvironmentSpec | None = None
    evaluator: EnvironmentSpec | None = None
    session_id: Identifier
    session_digest: Digest
    initial_writer: Identifier | None = None
    harness_id: Identifier | None = None
    budget_digest: Digest
    capabilities: tuple[Capability, ...] = ()
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("manifest timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("capabilities")
    @classmethod
    def normalize_capabilities(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        if len(value) != len(set(value)):
            raise ValueError("manifest capabilities must be unique")
        return tuple(sorted(value, key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_environments(self) -> Self:
        if (self.participant is None) != (self.evaluator is None):
            raise ValueError("a run freezes both execution views together")
        if any(
            environment is not None
            and environment.identity.provenance != (self.private_config_snapshot_digest,)
            for environment in (self.participant, self.evaluator)
        ):
            raise ValueError("run environments must derive from the frozen snapshot")
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            self.model_dump(mode="json", exclude_none=True), domain="run-manifest-v3"
        )

    @classmethod
    def from_snapshot(
        cls,
        *,
        run_id: str,
        task: TaskInstance,
        task_spec_digest: Digest,
        snapshot: PrivateConfigSnapshot,
        session_id: str,
        initial_writer: str | None = None,
        capabilities: tuple[Capability, ...] = (),
        created_at: datetime | None = None,
        creation_intent_digest: Digest | None = None,
        participant: EnvironmentSpec | None = None,
        evaluator: EnvironmentSpec | None = None,
        purpose: RunPurpose = RunPurpose.TASK,
    ) -> RunManifest:
        """Mechanically derive a manifest without copying private path values."""

        timestamp = datetime.now(UTC) if created_at is None else created_at
        if task_spec_digest != task.identity.task_spec_digest:
            raise ValueError("run task and specification identities disagree")
        session = next(
            (item for item in snapshot.configuration.sessions if item.session_id == session_id),
            None,
        )
        if session is None:
            raise ValueError("run session is absent from the frozen configuration")
        return cls(
            purpose=purpose,
            run_id=run_id,
            task_instance_digest=task.digest,
            task_spec_digest=task_spec_digest,
            private_config_snapshot_digest=snapshot.digest,
            creation_intent_digest=creation_intent_digest,
            participant=participant,
            evaluator=evaluator,
            session_id=session_id,
            session_digest=canonical_digest(session, domain="session-configuration-v1"),
            initial_writer=initial_writer,
            harness_id=session.harness_id,
            budget_digest=canonical_digest(
                {"requests": session.max_requests, "wall_seconds": session.max_wall_seconds},
                domain="episode-budget-v1",
            ),
            capabilities=capabilities,
            created_at=timestamp,
        )
