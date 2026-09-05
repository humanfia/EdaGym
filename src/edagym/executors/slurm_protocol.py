"""Canonical durable state and compute-node launch contract for Slurm."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from edagym.executors.model import EnvironmentEntry, ExecutionResult, InvocationPlan, JobHandle
from edagym.specs.common import (
    Digest,
    Identifier,
    JcsNonNegativeInt,
    JcsPositiveInt,
    SchemaVersion,
    Seed128Hex,
    StrictModel,
)
from edagym.specs.environment import EnvironmentSpec
from edagym.specs.environment import SlurmApptainerExecutor as SlurmExecutorSpec


def validate_slurm_absolute_path(value: str) -> str:
    if not value.startswith("/") or any(
        character in value for character in "\x00\r\n,:%"
    ):
        raise ValueError("Slurm paths must be safe absolute paths")
    return value


class SlurmRecordPhase(StrEnum):
    PREPARED = "prepared"
    ACCEPTED = "accepted"
    SUBMITTED = "submitted"
    ABANDONED = "abandoned"


class HostDirectoryBinding(StrictModel):
    """Controller-local path and directory object used for later collection."""

    path: Annotated[str, Field(min_length=1, max_length=4096)]
    device: JcsNonNegativeInt
    inode: JcsNonNegativeInt
    owner: JcsNonNegativeInt

    _validate_path = field_validator("path")(validate_slurm_absolute_path)


class SlurmSharedDirectory(StrictModel):
    """Shared path whose node-local object is bound by the compute worker."""

    path: Annotated[str, Field(min_length=1, max_length=4096)]
    owner: JcsNonNegativeInt

    _validate_path = field_validator("path")(validate_slurm_absolute_path)


class SlurmInputBinding(StrictModel):
    asset_id: Identifier
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    restricted_digest: Digest
    target: Annotated[str, Field(min_length=2, max_length=240)]

    _validate_path = field_validator("path")(validate_slurm_absolute_path)
    _validate_target = field_validator("target")(validate_slurm_absolute_path)


class SlurmLaunchManifest(StrictModel):
    """Private delayed-launch inputs revalidated on the assigned compute node."""

    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    invocation_digest: Digest
    site_policy_digest: Digest
    control_nonce: Seed128Hex
    workspace: SlurmSharedDirectory
    artifact_directory: SlurmSharedDirectory
    control_directory: SlurmSharedDirectory
    image_path: Annotated[str, Field(min_length=1, max_length=4096)]
    image_digest: Digest
    assets: tuple[SlurmInputBinding, ...] = ()
    apptainer_path: Annotated[str, Field(min_length=1, max_length=4096)]
    apptainer_digest: Digest
    workspace_target: Annotated[str, Field(min_length=2, max_length=240)]
    artifact_target: Annotated[str, Field(min_length=2, max_length=240)]
    working_directory: Annotated[str, Field(min_length=2, max_length=4096)]
    pids: JcsPositiveInt
    file_size_bytes: JcsPositiveInt
    payload_environment: tuple[EnvironmentEntry, ...]
    payload_executable: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"),
    ]
    payload_arguments: tuple[Annotated[str, Field(max_length=16_384)], ...]
    control_target: Annotated[str, Field(min_length=2, max_length=240)]

    @field_validator("assets")
    @classmethod
    def normalize_assets(
        cls,
        value: tuple[SlurmInputBinding, ...],
    ) -> tuple[SlurmInputBinding, ...]:
        asset_ids = [item.asset_id for item in value]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("Slurm preflight assets must be unique")
        return tuple(sorted(value, key=lambda item: item.asset_id))

    _validate_file_paths = field_validator("image_path", "apptainer_path")(
        validate_slurm_absolute_path
    )
    _validate_container_paths = field_validator(
        "workspace_target",
        "artifact_target",
        "working_directory",
        "control_target",
    )(validate_slurm_absolute_path)


class SlurmJobRecord(StrictModel):
    """Controller-private durable binding between one invocation and one batch job."""

    schema_version: SchemaVersion = 1
    capability_digest: Digest
    phase: SlurmRecordPhase
    plan: InvocationPlan
    environment: EnvironmentSpec
    workspace: HostDirectoryBinding
    artifact_directory: HostDirectoryBinding
    control_directory: HostDirectoryBinding
    job_name: Identifier
    scheduler_comment: Annotated[str, Field(pattern=r"^edagym-v1:[0-9a-f]{64}$")]
    control_nonce: Seed128Hex
    scheduler_job_id: Annotated[str, Field(pattern=r"^[1-9][0-9]*$")] | None = None
    scheduler_cluster: (
        Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")] | None
    ) = None
    scheduler_submit_time: (
        Annotated[
            str,
            Field(
                pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$"
            ),
        ]
        | None
    ) = None
    scheduler_uid: JcsNonNegativeInt | None = None
    result: ExecutionResult | None = None

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        if not isinstance(self.environment.executor, SlurmExecutorSpec):
            raise ValueError("Slurm records require a Slurm environment")
        has_accepted_identity = self.scheduler_job_id is not None
        has_bound_identity = (
            has_accepted_identity
            and self.scheduler_submit_time is not None
            and self.scheduler_uid is not None
        )
        if self.phase is SlurmRecordPhase.ACCEPTED and not has_accepted_identity:
            raise ValueError("accepted Slurm records require the scheduler job id")
        if self.phase is SlurmRecordPhase.SUBMITTED and not has_bound_identity:
            raise ValueError("submitted Slurm records require a bound scheduler identity")
        if self.phase in {SlurmRecordPhase.PREPARED, SlurmRecordPhase.ABANDONED} and (
            has_accepted_identity
            or self.scheduler_cluster is not None
            or self.scheduler_submit_time is not None
            or self.scheduler_uid is not None
        ):
            raise ValueError("unowned Slurm records cannot carry scheduler identities")
        if self.phase is SlurmRecordPhase.ACCEPTED and (
            self.scheduler_submit_time is not None or self.scheduler_uid is not None
        ):
            raise ValueError("accepted Slurm records cannot carry partial bound identities")
        if self.result is not None and self.phase is not SlurmRecordPhase.SUBMITTED:
            raise ValueError("only submitted Slurm records carry collected results")
        if self.result is not None and self.result.state.handle != self.handle:
            raise ValueError("collected Slurm evidence belongs to another invocation")
        return self

    @property
    def handle(self) -> JobHandle:
        return JobHandle(
            job_id=self.plan.invocation_id,
            invocation_digest=self.plan.digest,
            executor_id=self.environment.executor.executor_id,
        )
