"""Private resolution for open EDA tools in immutable rootless images."""

from __future__ import annotations

import hashlib
import os
import re
import resource
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, SupportsIndex

from edagym.canonical import canonical_digest
from edagym.drivers.closure import (
    ROOTLESS_IMAGE_FILE_SIZE_LIMIT_BYTES,
    ROOTLESS_IMAGE_PROBE_LIMITS,
    ExecutionClosureKind,
    ExecutionClosureRequirementRef,
    ResolvedExecutionClosure,
    rootless_image_arguments,
    rootless_image_execution_closure,
    trusted_immutable_executable,
)
from edagym.drivers.deployment import private_container_host_environment
from edagym.specs.common import Digest

_MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
_PROBE_TIMEOUT_SECONDS = ROOTLESS_IMAGE_PROBE_LIMITS.wall_seconds
_SHA256SUM_ENTRYPOINT = "/usr/bin/sha256sum"
_CAT_ENTRYPOINT = "/usr/bin/cat"
_PROBE_OWNER_LABEL = "io.edagym.image-probe"
_SHA256SUM_LINE = re.compile(rb"^([0-9a-f]{64})  (/[^\r\n]+)$")


@dataclass(frozen=True, slots=True, repr=False)
class RootlessImageExecutionRecipe:
    """Private image and in-image entrypoint selected for one backend."""

    image_digest: str
    tool_entrypoint: str
    package_manifest_path: str
    package_manifest_digest: str
    package_manifest_checksum_path: str

    def __post_init__(self) -> None:
        paths = tuple(
            PurePosixPath(value)
            for value in (
                self.tool_entrypoint,
                self.package_manifest_path,
                self.package_manifest_checksum_path,
            )
        )
        if (
            re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_digest) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.package_manifest_digest) is None
            or len(paths) != len(set(paths))
            or any(not path.is_absolute() for path in paths)
            or any(part in {"", ".", ".."} for path in paths for part in path.parts[1:])
            or any(
                "\x00" in value
                for value in (
                    self.tool_entrypoint,
                    self.package_manifest_path,
                    self.package_manifest_checksum_path,
                )
            )
        ):
            raise ValueError("rootless-image recipe is not canonical")

    @property
    def requirement_digest(self) -> Digest:
        return canonical_digest(
            {
                "kind": ExecutionClosureKind.ROOTLESS_IMAGE,
                "image_digest": self.image_digest,
                "tool_entrypoint": self.tool_entrypoint,
                "package_manifest_path": self.package_manifest_path,
                "package_manifest_digest": self.package_manifest_digest,
                "package_manifest_checksum_path": self.package_manifest_checksum_path,
            },
            domain="execution-closure-requirement-v1",
        )

    def __repr__(self) -> str:
        return "RootlessImageExecutionRecipe(image=<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("rootless-image recipes cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class RootlessImageConfiguration:
    """Process-local runtime and digest-pinned image reference."""

    recipe: RootlessImageExecutionRecipe
    engine_path: Path
    image_reference: str
    _host_environment: Mapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            not self.engine_path.is_absolute()
            or not self.image_reference.endswith(f"@{self.recipe.image_digest}")
            or "\x00" in self.image_reference
        ):
            raise ValueError("rootless-image configuration is not digest-pinned")
        object.__setattr__(
            self,
            "_host_environment",
            MappingProxyType(private_container_host_environment()),
        )

    @property
    def host_environment(self) -> Mapping[str, str]:
        return self._host_environment

    def revalidate(self) -> bool:
        return trusted_immutable_executable(
            self.engine_path
        ) == self.engine_path and _image_identity_matches(self)

    def __repr__(self) -> str:
        return "RootlessImageConfiguration(paths=<restricted>, image=<restricted>)"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Any:
        raise TypeError("rootless-image configurations cannot be serialized")


def resolve_rootless_image_execution_closure(
    requirement: ExecutionClosureRequirementRef,
    configuration: RootlessImageConfiguration,
    *,
    scratch_root: Path,
) -> ResolvedExecutionClosure | None:
    """Resolve and attest one image-native executable without a mutable tag."""

    recipe = configuration.recipe
    if (
        recipe.requirement_digest != requirement.requirement_digest
        or not configuration.revalidate()
    ):
        return None
    try:
        with tempfile.TemporaryDirectory(
            prefix="edagym-rootless-image-resolution-",
            dir=_validated_scratch_root(scratch_root),
        ) as workspace_name:
            workspace = Path(workspace_name)
            workspace.chmod(0o700)
            output = _run_bounded(
                configuration.engine_path,
                rootless_image_arguments(
                    workspace,
                    configuration.image_reference,
                    _SHA256SUM_ENTRYPOINT,
                    (recipe.tool_entrypoint, recipe.package_manifest_path),
                ),
                configuration.host_environment,
                workspace,
            )
            identities = _sha256sum_identities(output)
            if (
                set(identities)
                != {
                    recipe.tool_entrypoint,
                    recipe.package_manifest_path,
                }
                or identities[recipe.package_manifest_path] != recipe.package_manifest_digest
            ):
                return None
            tool_digest = identities[recipe.tool_entrypoint]
            package_manifest = _run_bounded(
                configuration.engine_path,
                rootless_image_arguments(
                    workspace,
                    configuration.image_reference,
                    _CAT_ENTRYPOINT,
                    (recipe.package_manifest_path,),
                ),
                configuration.host_environment,
                workspace,
            )
            checksum = _run_bounded(
                configuration.engine_path,
                rootless_image_arguments(
                    workspace,
                    configuration.image_reference,
                    _CAT_ENTRYPOINT,
                    (recipe.package_manifest_checksum_path,),
                ),
                configuration.host_environment,
                workspace,
            )
            expected_checksum = (
                recipe.package_manifest_digest.removeprefix("sha256:").encode("ascii") + b"\n"
            )
            if (
                package_manifest is None
                or checksum != expected_checksum
                or f"sha256:{hashlib.sha256(package_manifest).hexdigest()}"
                != recipe.package_manifest_digest
            ):
                return None
            closure = rootless_image_execution_closure(
                requirement,
                engine=configuration.engine_path,
                host_environment=configuration.host_environment,
                image_reference=configuration.image_reference,
                image_digest=recipe.image_digest,
                tool_entrypoint=recipe.tool_entrypoint,
                tool_entrypoint_digest=tool_digest,
                package_manifest=package_manifest,
                package_manifest_digest=recipe.package_manifest_digest,
            )
            if closure is None or not configuration.revalidate() or not closure.revalidate():
                return None
            return closure
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError, ValueError):
        return None


def _sha256sum_identities(output: bytes | None) -> dict[str, str]:
    if output is None:
        return {}
    identities: dict[str, str] = {}
    for line in output.splitlines():
        match = _SHA256SUM_LINE.fullmatch(line)
        if match is None:
            return {}
        path = match.group(2).decode("ascii")
        if path in identities:
            return {}
        identities[path] = f"sha256:{match.group(1).decode('ascii')}"
    return identities


def inspect_rootless_image_tool(
    closure: ResolvedExecutionClosure,
    configuration: RootlessImageConfiguration,
    arguments: tuple[str, ...],
    *,
    scratch_root: Path,
    accepted_exit_codes: tuple[int, ...],
) -> bytes | None:
    """Run one bounded metadata probe through the exact image closure."""

    runtime = closure.rootless_image_runtime
    if runtime is None or not configuration.revalidate() or not closure.revalidate():
        return None
    try:
        with tempfile.TemporaryDirectory(
            prefix="edagym-rootless-image-version-",
            dir=_validated_scratch_root(scratch_root),
        ) as workspace_name:
            workspace = Path(workspace_name)
            workspace.chmod(0o700)
            output = _run_bounded(
                closure.entrypoint_path,
                runtime.invocation_arguments(workspace, arguments),
                runtime.host_environment,
                workspace,
                accepted_exit_codes=accepted_exit_codes,
            )
            if output is None or not configuration.revalidate() or not closure.revalidate():
                return None
            return output if output.strip() else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _image_identity_matches(configuration: RootlessImageConfiguration) -> bool:
    try:
        completed = subprocess.run(
            (
                os.fspath(configuration.engine_path),
                "image",
                "inspect",
                "--format",
                "{{.Digest}}",
                configuration.image_reference,
            ),
            env=configuration.host_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd="/",
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return (
        completed.returncode == 0
        and completed.stdout.strip() == configuration.recipe.image_digest.encode("ascii")
    )


def _run_bounded(
    executable: Path,
    arguments: tuple[str, ...],
    environment: Mapping[str, str],
    workspace: Path,
    *,
    accepted_exit_codes: tuple[int, ...] = (0,),
) -> bytes | None:
    if not arguments or arguments[0] != "run":
        raise ValueError("image probes require a container invocation")
    identity = canonical_digest(
        {"workspace": os.fspath(workspace), "arguments": arguments},
        domain="rootless-image-probe-v1",
    ).removeprefix("sha256:")
    name = f"edagym-probe-{identity}"
    receipt = workspace / f"{name}.cid"
    output: bytes | None = None
    try:
        created = subprocess.run(
            (
                os.fspath(executable),
                "create",
                f"--name={name}",
                f"--label={_PROBE_OWNER_LABEL}={identity}",
                f"--cidfile={receipt}",
                *arguments[1:],
            ),
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
            preexec_fn=_apply_limits,
        )
        if created.returncode == 0:
            completed = subprocess.run(
                (os.fspath(executable), "start", "--attach", name),
                cwd=workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=_PROBE_TIMEOUT_SECONDS,
                check=False,
                preexec_fn=_apply_limits,
            )
            if (
                completed.returncode in accepted_exit_codes
                and len(completed.stdout) <= _MAX_PROBE_OUTPUT_BYTES
            ):
                output = completed.stdout
    except (OSError, subprocess.SubprocessError):
        output = None
    finally:
        # A timeout may occur after creation. Query the prepared identity even
        # when create did not return a handle; never remove an unowned resource.
        try:
            inspected = subprocess.run(
                (
                    os.fspath(executable),
                    "inspect",
                    "--format",
                    f'{{{{.Id}}}} {{{{ index .Config.Labels "{_PROBE_OWNER_LABEL}" }}}}',
                    name,
                ),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
            fields = inspected.stdout.decode("ascii").strip().split()
            if (
                inspected.returncode == 0
                and len(fields) == 2
                and re.fullmatch(r"[0-9a-f]{64}", fields[0])
                and fields[1] == identity
            ):
                removed = subprocess.run(
                    (os.fspath(executable), "rm", "--force", "--time=0", fields[0]),
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=_PROBE_TIMEOUT_SECONDS,
                    check=False,
                )
                if removed.returncode != 0:
                    output = None
            else:
                output = None
        except (OSError, subprocess.SubprocessError, UnicodeError):
            output = None
    return output


def _validated_scratch_root(root: Path) -> Path:
    if root.is_symlink():
        raise ValueError("rootless-image scratch root cannot be a symbolic link")
    resolved = root.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("rootless-image scratch root must be private to its owner")
    return resolved


def _apply_limits() -> None:
    os.umask(0o077)
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (
            ROOTLESS_IMAGE_FILE_SIZE_LIMIT_BYTES,
            ROOTLESS_IMAGE_FILE_SIZE_LIMIT_BYTES,
        ),
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
