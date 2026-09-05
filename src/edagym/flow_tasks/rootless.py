"""Verifier-asset projection for rootless EDA-flow evaluation."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from edagym.executors.assets import asset_content_digest
from edagym.flow_tasks.canonical import (
    CanonicalFlowTask,
    flow_candidate_manifest_digest,
    flow_candidate_resource_id,
    require_flow_environment,
    validate_canonical_flow_task,
)
from edagym.flow_tasks.model import (
    CandidateExpectation,
    FlowStageDefinition,
    FlowTaskPack,
    TaskAsset,
    ToolCommand,
)
from edagym.specs.common import Digest
from edagym.specs.environment import (
    AssetBinding,
    EnvironmentSpec,
    FilesystemScope,
    ReadonlyAssetMount,
    RootlessLocalExecutor,
)
from edagym.specs.release import FlowReleaseQualification, ReleaseManifest

_VERIFIER_ROOT = "/edagym-flow-verifier"


@dataclass(frozen=True, slots=True, repr=False)
class RootlessFlowEnvironment:
    """Path-free environment plus controller-only verifier asset locators."""

    environment: EnvironmentSpec
    asset_paths: Mapping[str, Path]

    def __repr__(self) -> str:
        return (
            "RootlessFlowEnvironment("
            f"environment_digest={self.environment.digest!r}, asset_paths=<restricted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class FlowWitnessMaterialization:
    """Controller-only paths bound to one qualified feasibility witness."""

    candidate_id: str
    candidate_resource_id: str
    candidate_manifest_digest: Digest
    witness_evidence_digest: Digest
    files: Mapping[str, Path]

    def __repr__(self) -> str:
        return (
            "FlowWitnessMaterialization("
            f"candidate_id={self.candidate_id!r}, "
            f"candidate_resource_id={self.candidate_resource_id!r}, "
            f"candidate_manifest_digest={self.candidate_manifest_digest!r}, "
            "files=<restricted>)"
        )


def bind_rootless_flow_verifier_assets(
    pack: FlowTaskPack,
    environment: EnvironmentSpec,
    asset_root: Path,
) -> RootlessFlowEnvironment:
    """Materialize exact pack assets outside the candidate workspace and bind them read-only."""

    if not isinstance(environment.executor, RootlessLocalExecutor):
        raise ValueError("rootless flow assets require a rootless environment")
    if any(
        mount.scope is FilesystemScope.EVALUATOR
        for mount in environment.filesystem.readonly_assets
    ):
        raise ValueError("flow evaluator assets must have one pack-derived owner")
    _create_private_root(asset_root)

    paths: dict[str, Path] = {}
    bindings: list[AssetBinding] = list(environment.assets)
    mounts: list[ReadonlyAssetMount] = list(environment.filesystem.readonly_assets)
    for stage in pack.stages:
        if not stage.assets:
            continue
        _require_direct_asset_arguments(stage)
        asset_id = flow_verifier_asset_id(stage.stage_id)
        stage_root = asset_root / stage.stage_id
        stage_root.mkdir(mode=0o700)
        for asset in stage.assets:
            _write_asset(stage_root, asset)
        _make_tree_read_only(stage_root)
        paths[asset_id] = stage_root
        bindings.append(
            AssetBinding(
                asset_id=asset_id,
                restricted_digest=asset_content_digest(stage_root),
                allowed_scopes=(FilesystemScope.EVALUATOR,),
            )
        )
        mounts.append(
            ReadonlyAssetMount(
                asset_id=asset_id,
                scope=FilesystemScope.EVALUATOR,
                target=flow_verifier_asset_target(stage.stage_id),
            )
        )

    identity = environment.identity.model_validate(
        {
            **environment.identity.model_dump(mode="python"),
            "provenance": (
                *environment.identity.provenance,
                f"flow_pack:{pack.digest}",
            ),
        }
    )
    filesystem = environment.filesystem.model_validate(
        {
            **environment.filesystem.model_dump(mode="python"),
            "readonly_assets": tuple(mounts),
        }
    )
    bound = EnvironmentSpec.model_validate(
        {
            **environment.model_dump(mode="python"),
            "identity": identity,
            "assets": tuple(bindings),
            "filesystem": filesystem,
        }
    )
    validate_rootless_flow_environment(pack, bound)
    return RootlessFlowEnvironment(
        environment=bound,
        asset_paths=MappingProxyType(paths),
    )


def materialize_flow_witness(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
    release: ReleaseManifest,
    destination: Path,
) -> FlowWitnessMaterialization:
    """Materialize the exact qualified witness for a provider-free preflight."""

    validate_canonical_flow_task(pack, canonical)
    require_flow_environment(pack, environment)
    qualification = release.qualification
    if (
        not isinstance(qualification, FlowReleaseQualification)
        or release.task_spec_digest != canonical.task.digest
        or release.task_instance_digest != canonical.instance.digest
        or release.environment_digests != (environment.digest,)
    ):
        raise ValueError("flow witness requires the exact qualified release binding")
    witnesses = tuple(
        candidate
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.ACCEPTED
    )
    if len(witnesses) != 1:
        raise ValueError("flow pack does not have one feasibility witness")
    witness = witnesses[0]
    resource_id = flow_candidate_resource_id(witness)
    if qualification.witness_resource_id != resource_id:
        raise ValueError("flow release names another feasibility witness")

    _create_private_root(destination)
    paths: dict[str, Path] = {}
    for asset in witness.assets:
        _write_asset(destination, asset)
        paths[asset.path] = destination / asset.path
    if set(paths) != set(pack.submission_paths):
        raise ValueError("flow witness changes the participant submission contract")
    return FlowWitnessMaterialization(
        candidate_id=witness.candidate_id,
        candidate_resource_id=resource_id,
        candidate_manifest_digest=flow_candidate_manifest_digest(witness, environment),
        witness_evidence_digest=qualification.witness_evidence_digest,
        files=MappingProxyType(paths),
    )


def validate_rootless_flow_environment(
    pack: FlowTaskPack,
    environment: EnvironmentSpec,
) -> None:
    """Require the exact read-only verifier closure derived from one flow pack."""

    if not isinstance(environment.executor, RootlessLocalExecutor):
        raise ValueError("flow verifier asset validation requires a rootless environment")
    expected = {
        (
            flow_verifier_asset_id(stage.stage_id),
            flow_verifier_asset_target(stage.stage_id),
        )
        for stage in pack.stages
        if stage.assets
    }
    actual = {
        (mount.asset_id, mount.target)
        for mount in environment.filesystem.readonly_assets
        if mount.scope is FilesystemScope.EVALUATOR
    }
    if actual != expected:
        raise ValueError("rootless flow environment has a stale verifier asset closure")
    by_id = {binding.asset_id: binding for binding in environment.assets}
    if any(
        by_id.get(asset_id) is None
        or by_id[asset_id].allowed_scopes != (FilesystemScope.EVALUATOR,)
        for asset_id, _target in expected
    ):
        raise ValueError("rootless flow verifier assets have an invalid scope")
    for stage in pack.stages:
        if stage.assets:
            _require_direct_asset_arguments(stage)


def rootless_flow_arguments(
    stage: FlowStageDefinition,
    arguments: tuple[str, ...],
) -> tuple[str, ...]:
    """Rewrite only exact verifier-owned argv members to their immutable mount targets."""

    asset_paths = {asset.path for asset in stage.assets}
    target = flow_verifier_asset_target(stage.stage_id)
    return tuple(
        f"{target}/{argument}" if argument in asset_paths else argument
        for argument in arguments
    )


def flow_verifier_asset_id(stage_id: str) -> str:
    return f"flow_verifier_{stage_id}"


def flow_verifier_asset_target(stage_id: str) -> str:
    return f"{_VERIFIER_ROOT}/{stage_id}"


def _require_direct_asset_arguments(stage: FlowStageDefinition) -> None:
    direct = {
        argument
        for command in stage.commands
        if isinstance(command, ToolCommand)
        for argument in command.arguments
    }
    if any(asset.path not in direct for asset in stage.assets):
        raise ValueError(
            "rootless flow verifier assets must be direct immutable tool arguments"
        )


def _create_private_root(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("flow verifier asset root must be absolute")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError("flow verifier asset root must be new") from None
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("flow verifier asset root is not owner-controlled")


def _write_asset(root: Path, asset: TaskAsset) -> None:
    parent = root
    parts = PurePosixPath(asset.path).parts
    for part in parts[:-1]:
        parent = parent / part
        with suppress(FileExistsError):
            parent.mkdir(mode=0o700)
        metadata = parent.lstat()
        if (
            parent.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ValueError("flow verifier asset parent is not owner-controlled")
    destination = parent / parts[-1]
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        content = asset.content.encode("utf-8")
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if not count:
                raise OSError("flow verifier asset write made no progress")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _make_tree_read_only(root: Path) -> None:
    directories: list[Path] = []
    for path in root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink():
            raise ValueError("flow verifier assets cannot contain symbolic links")
        if stat.S_ISDIR(metadata.st_mode):
            directories.append(path)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("flow verifier assets must be regular files")
        path.chmod(0o400)
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o500)
    root.chmod(0o500)


__all__ = [
    "FlowWitnessMaterialization",
    "RootlessFlowEnvironment",
    "bind_rootless_flow_verifier_assets",
    "flow_verifier_asset_id",
    "flow_verifier_asset_target",
    "materialize_flow_witness",
    "rootless_flow_arguments",
    "validate_rootless_flow_environment",
]
