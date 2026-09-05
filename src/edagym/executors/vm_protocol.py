"""Canonical host-to-guest protocol for one disposable VM invocation."""

from __future__ import annotations

import base64
import binascii
import hashlib
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, TypeAdapter, field_validator, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.model import ExecutionFailureKind, InvocationPlan, JobStateKind
from edagym.specs.common import (
    Digest,
    Identifier,
    JcsPositiveInt,
    SchemaVersion,
    StrictModel,
    validate_relative_path,
)

VM_GUEST_CHANNEL_NAME = "org.edagym.control.0"
VM_GUEST_CHANNEL_PATH = f"/dev/virtio-ports/{VM_GUEST_CHANNEL_NAME}"
VM_GUEST_ROOT = PurePosixPath("/edagym")
VM_PROTOCOL_DIGEST_DOMAIN = "vm-guest-protocol-v1"
VM_PROTOCOL_MAX_FRAME_BYTES = 64 * 1024 * 1024
_WIRE_MODE = Literal[0o600, 0o700]


class VmTreeEntryKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"


class VmInlineBlob(StrictModel):
    digest: Digest
    size_bytes: Annotated[int, Field(strict=True, ge=0)]
    content_base64: Annotated[str, Field(max_length=VM_PROTOCOL_MAX_FRAME_BYTES)]

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        try:
            content = base64.b64decode(self.content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("VM inline content is not canonical base64") from None
        observed = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if len(content) != self.size_bytes or observed != self.digest:
            raise ValueError("VM inline content differs from its identity")
        if base64.b64encode(content).decode("ascii") != self.content_base64:
            raise ValueError("VM inline content is not canonically encoded")
        return self

    @classmethod
    def from_bytes(cls, content: bytes) -> VmInlineBlob:
        return cls(
            digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
            size_bytes=len(content),
            content_base64=base64.b64encode(content).decode("ascii"),
        )

    def decode(self) -> bytes:
        return base64.b64decode(self.content_base64, validate=True)


class VmTreeEntry(StrictModel):
    path: str
    kind: VmTreeEntryKind
    mode: _WIRE_MODE
    blob: VmInlineBlob | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        if (self.kind is VmTreeEntryKind.FILE) != (self.blob is not None):
            raise ValueError("only VM transfer files carry inline content")
        return self


class VmTransferTree(StrictModel):
    target: Annotated[str, Field(min_length=2, max_length=240)]
    readonly: bool
    root_is_file: bool = False
    root_mode: _WIRE_MODE
    root_blob: VmInlineBlob | None = None
    entries: tuple[VmTreeEntry, ...] = ()

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        path = PurePosixPath(value)
        if not value.startswith("/") or path == PurePosixPath("/") or ".." in path.parts:
            raise ValueError("VM transfer target must be an absolute non-root path")
        return path.as_posix()

    @field_validator("entries")
    @classmethod
    def normalize_entries(cls, value: tuple[VmTreeEntry, ...]) -> tuple[VmTreeEntry, ...]:
        paths = [entry.path for entry in value]
        if len(paths) != len(set(paths)):
            raise ValueError("VM transfer entries must have unique paths")
        return tuple(sorted(value, key=lambda entry: entry.path))

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        if self.root_is_file != (self.root_blob is not None):
            raise ValueError("only VM transfer root files carry inline content")
        if self.root_is_file and self.entries:
            raise ValueError("VM root-file transfers cannot contain child entries")
        return self


class VmAssetTransfer(StrictModel):
    asset_id: Identifier
    restricted_digest: Digest
    tree: VmTransferTree

    @model_validator(mode="after")
    def require_readonly(self) -> Self:
        if not self.tree.readonly:
            raise ValueError("VM assets must be transferred read-only")
        return self


class VmGuestLaunch(StrictModel):
    kind: Literal["launch"] = "launch"
    schema_version: SchemaVersion = 1
    plan: InvocationPlan
    invocation_digest: Digest
    environment_digest: Digest
    workspace: VmTransferTree
    artifact_target: Annotated[str, Field(min_length=2, max_length=240)]
    assets: tuple[VmAssetTransfer, ...] = ()
    wall_seconds: JcsPositiveInt
    output_limit_bytes: JcsPositiveInt

    @field_validator("assets")
    @classmethod
    def normalize_assets(
        cls, value: tuple[VmAssetTransfer, ...]
    ) -> tuple[VmAssetTransfer, ...]:
        identities = [asset.asset_id for asset in value]
        if len(identities) != len(set(identities)):
            raise ValueError("VM launch assets must be unique")
        return tuple(sorted(value, key=lambda asset: asset.asset_id))

    @model_validator(mode="after")
    def validate_launch(self) -> Self:
        if self.plan.digest != self.invocation_digest:
            raise ValueError("VM launch plan differs from its canonical identity")
        if self.workspace.readonly or self.workspace.root_is_file:
            raise ValueError("VM workspaces must be writable directories")
        if self.workspace.target != (VM_GUEST_ROOT / "workspace").as_posix() or (
            self.artifact_target != (VM_GUEST_ROOT / "artifacts").as_posix()
        ):
            raise ValueError("VM writable targets must belong to the invocation namespace")
        if any(
            asset.tree.target != (VM_GUEST_ROOT / "assets" / asset.asset_id).as_posix()
            for asset in self.assets
        ):
            raise ValueError("VM asset targets must belong to the invocation namespace")
        targets = [self.workspace.target, self.artifact_target]
        targets.extend(asset.tree.target for asset in self.assets)
        paths = [PurePosixPath(target) for target in targets]
        for position, path in enumerate(paths):
            if any(
                path == other or path in other.parents or other in path.parents
                for other in paths[position + 1 :]
            ):
                raise ValueError("VM transfer targets must be disjoint")
        return self

    @property
    def digest(self) -> str:
        return canonical_digest(self, domain=VM_PROTOCOL_DIGEST_DOMAIN)


class VmGuestControl(StrictModel):
    kind: Literal["status", "cancel"]
    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    invocation_digest: Digest


class VmGuestAccepted(StrictModel):
    kind: Literal["accepted"] = "accepted"
    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    invocation_digest: Digest
    request_digest: Digest


class VmGuestRunning(StrictModel):
    kind: Literal["running"] = "running"
    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    invocation_digest: Digest
    request_digest: Digest


class VmGuestOutput(StrictModel):
    logical_id: Identifier
    blob: VmInlineBlob


class VmGuestResult(StrictModel):
    kind: Literal["result"] = "result"
    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    invocation_digest: Digest
    request_digest: Digest
    environment_digest: Digest
    state: Literal[
        JobStateKind.COMPLETED,
        JobStateKind.FAILED,
        JobStateKind.CANCELLED,
        JobStateKind.TIMED_OUT,
    ]
    exit_code: Annotated[int, Field(strict=True, ge=0, le=255)]
    failure: ExecutionFailureKind | None = None
    stdout: VmInlineBlob
    stderr: VmInlineBlob
    outputs: tuple[VmGuestOutput, ...] = ()

    @field_validator("outputs")
    @classmethod
    def normalize_outputs(cls, value: tuple[VmGuestOutput, ...]) -> tuple[VmGuestOutput, ...]:
        identities = [output.logical_id for output in value]
        if len(identities) != len(set(identities)):
            raise ValueError("VM guest outputs must be unique")
        return tuple(sorted(value, key=lambda output: output.logical_id))

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.state is JobStateKind.COMPLETED:
            if self.exit_code != 0 or self.failure is not None:
                raise ValueError("completed VM commands require a clean exit")
        elif self.failure is None:
            raise ValueError("failed VM commands require a failure classification")
        return self


VmGuestRequest = Annotated[VmGuestLaunch | VmGuestControl, Field(discriminator="kind")]
VmGuestReply = Annotated[
    VmGuestAccepted | VmGuestRunning | VmGuestResult,
    Field(discriminator="kind"),
]
VM_GUEST_REQUEST_ADAPTER: TypeAdapter[VmGuestRequest] = TypeAdapter(VmGuestRequest)
VM_GUEST_REPLY_ADAPTER: TypeAdapter[VmGuestReply] = TypeAdapter(VmGuestReply)


def encode_vm_message(message: StrictModel) -> bytes:
    encoded = canonical_bytes(message)
    if len(encoded) > VM_PROTOCOL_MAX_FRAME_BYTES:
        raise ValueError("VM protocol frame exceeds its fixed bound")
    return encoded
