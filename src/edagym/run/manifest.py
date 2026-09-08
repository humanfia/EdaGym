"""Frozen run binding derived from a private configuration snapshot."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import field_validator

from edagym.canonical import canonical_digest
from edagym.config.model import PrivateConfigSnapshot
from edagym.specs.common import Capability, Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.environment import NetworkKind
from edagym.specs.release import TaskInstance


class ManifestView(StrictModel):
    """Private execution identity of one participant or evaluator view."""

    tool_ids: tuple[Identifier, ...]
    library_ids: tuple[Identifier, ...]
    runtime_digest: Digest | None
    network: NetworkKind
    resource_digest: Digest | None = None
    storage_digest: Digest | None = None

    @field_validator("tool_ids", "library_ids")
    @classmethod
    def normalize_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("manifest view identifiers must be unique")
        return tuple(sorted(value))


class RunManifest(StrictModel):
    """One immutable binding for task, views, session, harness, and budgets."""

    schema_version: SchemaVersion = 1
    run_id: Identifier
    task_instance_digest: Digest
    task_spec_digest: Digest
    private_config_snapshot_digest: Digest
    creation_intent_digest: Digest | None = None
    participant: ManifestView
    evaluator: ManifestView
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

    @property
    def digest(self) -> Digest:
        return canonical_digest(
            self.model_dump(mode="json", exclude_none=True), domain="run-manifest-v1"
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
            run_id=run_id,
            task_instance_digest=task.digest,
            task_spec_digest=task_spec_digest,
            private_config_snapshot_digest=snapshot.digest,
            creation_intent_digest=creation_intent_digest,
            participant=ManifestView(
                tool_ids=snapshot.participant.tool_ids,
                library_ids=snapshot.participant.library_ids,
                runtime_digest=snapshot.participant.runtime_digest,
                network=snapshot.participant.network,
                resource_digest=snapshot.participant.resource_digest,
                storage_digest=snapshot.participant.storage_digest,
            ),
            evaluator=ManifestView(
                tool_ids=snapshot.evaluator.tool_ids,
                library_ids=snapshot.evaluator.library_ids,
                runtime_digest=snapshot.evaluator.runtime_digest,
                network=snapshot.evaluator.network,
                resource_digest=snapshot.evaluator.resource_digest,
                storage_digest=snapshot.evaluator.storage_digest,
            ),
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
