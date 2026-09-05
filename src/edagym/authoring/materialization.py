"""Atomic local materialization of digest-bound private catalog exports."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import secrets
import stat
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, Self

from pydantic import field_validator, model_validator

from edagym.authoring.content import content_digest
from edagym.authoring.provider import (
    AuthoringProviderError,
    ExportCatalogResponse,
    ExportMemberDescriptor,
    ExportMemberRole,
    PrivateAuthoringCapability,
    PrivateAuthoringProviderDescriptor,
    SealedCatalogAttestation,
    exported_member_manifest_digest,
    validate_catalog_attestation,
    validate_export_member_roles,
    validate_member_path_set,
)
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.specs.common import Digest, SchemaVersion, StrictModel
from edagym.specs.release import IntegerParameterValue, TaskInstance
from edagym.specs.task import TaskSpec
from edagym.task_families.catalog import PublicTaskCatalog

_RECEIPT_NAME = ".edagym-private-catalog.json"
_MAXIMUM_RECEIPT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _TreeSnapshot:
    files: frozenset[str]
    directories: frozenset[str]
    file_identities: tuple[tuple[str, tuple[int, ...]], ...]
    directory_identities: tuple[tuple[str, tuple[int, ...]], ...]


class CatalogExportLease(Protocol):
    def consume(self) -> ExportCatalogResponse: ...


class CatalogProvider(Protocol):
    def open_catalog(
        self,
        capability: PrivateAuthoringCapability,
    ) -> CatalogExportLease: ...


class CatalogMaterializationReceipt(StrictModel):
    """Path-free evidence persisted beside a restricted catalog tree."""

    schema_version: SchemaVersion = 1
    provider: PrivateAuthoringProviderDescriptor
    attestation: SealedCatalogAttestation
    members: tuple[ExportMemberDescriptor, ...]

    @field_validator("members")
    @classmethod
    def normalize_members(
        cls,
        value: tuple[ExportMemberDescriptor, ...],
    ) -> tuple[ExportMemberDescriptor, ...]:
        paths = [item.relative_path for item in value]
        if not value or _RECEIPT_NAME in paths:
            raise ValueError("materialized catalog members require unique non-reserved paths")
        validate_member_path_set(tuple(paths))
        validate_member_path_set(tuple(_materialized_path(item) for item in value))
        return tuple(sorted(value, key=lambda item: item.relative_path))

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if exported_member_manifest_digest(self.members) != self.attestation.member_manifest_digest:
            raise ValueError("materialization receipt does not bind its member manifest")
        validate_catalog_attestation(self.provider, self.attestation)
        validate_export_member_roles(self.attestation, self.members)
        return self

    @property
    def digest(self) -> Digest:
        return canonical_digest(self, domain="private-catalog-materialization-receipt-v1")


def materialize_private_catalog(
    provider: CatalogProvider,
    capability: PrivateAuthoringCapability,
    public_catalog: PublicTaskCatalog,
    output_root: Path,
) -> CatalogMaterializationReceipt:
    """Consume a catalog lease and atomically create one owner-only tree."""

    exported = provider.open_catalog(capability).consume()
    if exported.descriptor.public_catalog_digest != public_catalog.digest:
        raise AuthoringProviderError("provider export targets a different public catalog")
    receipt = _receipt(exported)
    _write_atomic(output_root, exported, receipt)
    return verify_materialized_catalog(output_root, public_catalog)


def verify_materialized_catalog(
    root: Path,
    public_catalog: PublicTaskCatalog,
) -> CatalogMaterializationReceipt:
    """Verify exact bytes without importing or reconstructing private authoring logic."""

    root = root.absolute()
    _require_external_destination(root)
    root_fd = _open_absolute_directory(root)
    try:
        _require_owner_only_directory(root_fd)
        receipt = _load_receipt(root_fd)
        if receipt.provider.public_catalog_digest != public_catalog.digest:
            raise AuthoringProviderError(
                "materialized catalog targets a different public catalog"
            )
        expected_files = {
            _RECEIPT_NAME,
            *(_materialized_path(item) for item in receipt.members),
        }
        expected_directories = _parent_directories(expected_files)
        before = _scan_tree(root_fd)
        if before.files != expected_files or before.directories != expected_directories:
            raise AuthoringProviderError(
                "materialized catalog has missing or unexpected tree entries"
            )
        verified_members: list[tuple[ExportMemberDescriptor, bytes]] = []
        for member in receipt.members:
            content = _read_file_at(
                root_fd,
                _materialized_path(member),
                maximum_bytes=member.size_bytes,
            )
            if (
                len(content) != member.size_bytes
                or content_digest(content) != member.content_digest
            ):
                raise AuthoringProviderError(
                    "materialized catalog member failed content verification"
                )
            verified_members.append((member, content))
        _verify_derived_documents(receipt.attestation, tuple(verified_members))
        if _load_receipt(root_fd) != receipt:
            raise AuthoringProviderError("materialized catalog receipt changed during verification")
        after = _scan_tree(root_fd)
        if after != before:
            raise AuthoringProviderError("materialized catalog changed during verification")
        return receipt
    finally:
        os.close(root_fd)


def _receipt(exported: ExportCatalogResponse) -> CatalogMaterializationReceipt:
    return CatalogMaterializationReceipt(
        provider=exported.descriptor,
        attestation=exported.attestation,
        members=tuple(item.descriptor for item in exported.members),
    )


def _write_atomic(
    output_root: Path,
    exported: ExportCatalogResponse,
    receipt: CatalogMaterializationReceipt,
) -> None:
    output_root = output_root.absolute()
    parent = output_root.parent
    _require_external_destination(output_root)
    parent_fd = _open_absolute_directory(parent)
    staging_name = f".edagym-catalog-{secrets.token_hex(16)}"
    try:
        _require_owner_only_directory(parent_fd)
        try:
            os.stat(output_root.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise AuthoringProviderError("materialized catalog destination must not exist")
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            for member in exported.members:
                _write_file_at(staging_fd, _materialized_path(member), member.content)
            _write_file_at(staging_fd, _RECEIPT_NAME, canonical_bytes(receipt) + b"\n")
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        _rename_noreplace(parent_fd, staging_name, output_root.name)
        os.fsync(parent_fd)
    except Exception:
        _remove_tree_at(parent_fd, staging_name)
        raise
    finally:
        os.close(parent_fd)


def _write_file_at(root_fd: int, relative_path: str, content: bytes) -> None:
    parts = PurePosixPath(relative_path).parts
    parent_fd = _open_or_create_directories(root_fd, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written == 0:
                    raise OSError("catalog member write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise AuthoringProviderError("atomic no-replace catalog publication is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise AuthoringProviderError("materialized catalog destination already exists")
        raise OSError(error_number, os.strerror(error_number))


def _materialized_path(member: ExportMemberDescriptor) -> str:
    role_root = {
        ExportMemberRole.PUBLIC_FILE: "public",
        ExportMemberRole.PARTICIPANT_FILE: "participant",
        ExportMemberRole.VERIFIER_FILE: "verifier",
        ExportMemberRole.TASK_SPEC_DOCUMENT: "author/task-specs",
        ExportMemberRole.TASK_INSTANCE_DOCUMENT: "author/task-instances",
        ExportMemberRole.AUTHOR_EVIDENCE: "author",
        ExportMemberRole.FLOW_TASK_PACK: "author/flow-packs",
    }[member.role]
    return f"{role_root}/{member.relative_path}"


def _load_receipt(root_fd: int) -> CatalogMaterializationReceipt:
    content = _read_file_at(root_fd, _RECEIPT_NAME, maximum_bytes=_MAXIMUM_RECEIPT_BYTES)
    if not content.endswith(b"\n") or content.endswith(b"\n\n"):
        raise AuthoringProviderError("catalog receipt must have one final newline")
    try:
        document = json.loads(content, object_pairs_hook=_unique_object)
        receipt = CatalogMaterializationReceipt.model_validate(document)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise AuthoringProviderError("catalog receipt is invalid") from error
    if content != canonical_bytes(receipt) + b"\n":
        raise AuthoringProviderError("catalog receipt is not canonically encoded")
    return receipt


def _verify_derived_documents(
    attestation: SealedCatalogAttestation,
    members: tuple[tuple[ExportMemberDescriptor, bytes], ...],
) -> None:
    documents: dict[str, dict[ExportMemberRole, bytes]] = {}
    for member, content in members:
        if member.role not in {
            ExportMemberRole.TASK_SPEC_DOCUMENT,
            ExportMemberRole.TASK_INSTANCE_DOCUMENT,
        }:
            continue
        if member.instance_reference_id is None:
            raise AuthoringProviderError("typed task document lacks its opaque instance")
        scoped = documents.setdefault(member.instance_reference_id, {})
        if member.role in scoped:
            raise AuthoringProviderError("typed task document role is duplicated")
        scoped[member.role] = content
    qualifications = {
        instance.instance_reference_id: instance
        for family in attestation.families
        for instance in family.instances
    }
    required_roles = {
        ExportMemberRole.TASK_SPEC_DOCUMENT,
        ExportMemberRole.TASK_INSTANCE_DOCUMENT,
    }
    for reference_id, scoped in documents.items():
        if scoped.keys() != required_roles:
            raise AuthoringProviderError("typed task and instance documents must be paired")
        qualification = qualifications.get(reference_id)
        if qualification is None:
            raise AuthoringProviderError("typed task document has no sealed qualification")
        try:
            task_content = scoped[ExportMemberRole.TASK_SPEC_DOCUMENT]
            instance_content = scoped[ExportMemberRole.TASK_INSTANCE_DOCUMENT]
            task = TaskSpec.model_validate_json(task_content)
            instance = TaskInstance.model_validate_json(instance_content)
        except ValueError as error:
            raise AuthoringProviderError("typed task document is invalid") from error
        actual_difficulty = {
            item.parameter_id: item.value
            for item in instance.identity.parameters
            if isinstance(item, IntegerParameterValue)
        }
        expected_difficulty = {
            item.parameter_id: item.value for item in qualification.difficulty
        }
        if (
            task_content != canonical_bytes(task)
            or instance_content != canonical_bytes(instance)
            or task.digest != qualification.task_spec_digest
            or instance.digest != qualification.task_instance_digest
            or task.identity.family != qualification.family
            or instance.identity.task_family != qualification.family
            or instance.identity.task_spec_digest != task.digest
            or len(actual_difficulty) != len(instance.identity.parameters)
            or actual_difficulty != expected_difficulty
        ):
            raise AuthoringProviderError(
                "typed task documents diverge from their sealed qualification"
            )


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise AuthoringProviderError("catalog directory must be absolute")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _require_owner_only_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise AuthoringProviderError("catalog directory must be owner-only")


def _open_or_create_directories(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    try:
        for component in parts:
            with suppress(FileExistsError):
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            _require_owner_only_directory(child)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_file_at(root_fd: int, relative_path: str, *, maximum_bytes: int) -> bytes:
    parts = PurePosixPath(relative_path).parts
    parent_fd = _open_existing_directories(root_fd, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise AuthoringProviderError("catalog member is not an owner-only bounded file")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise AuthoringProviderError("catalog member exceeds its declared size bound")
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after) or len(content) != after.st_size:
            raise AuthoringProviderError("catalog member changed while it was read")
        return bytes(content)
    finally:
        os.close(descriptor)


def _open_existing_directories(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    try:
        for component in parts:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            _require_owner_only_directory(child)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _scan_tree(root_fd: int) -> _TreeSnapshot:
    files: set[str] = set()
    directories: set[str] = set()
    file_identities: dict[str, tuple[int, ...]] = {}
    directory_identities: dict[str, tuple[int, ...]] = {}

    def visit(directory_fd: int, prefix: str) -> None:
        before = os.fstat(directory_fd)
        for name in sorted(os.listdir(directory_fd)):
            relative = f"{prefix}/{name}" if prefix else name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    _require_owner_only_directory(child)
                    directories.add(relative)
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative)
                file_identities[relative] = _file_identity(metadata)
            else:
                raise AuthoringProviderError("catalog tree contains a non-regular entry")
        after = os.fstat(directory_fd)
        if _directory_identity(before) != _directory_identity(after):
            raise AuthoringProviderError("catalog directory changed during tree inspection")
        directory_identities[prefix] = _directory_identity(after)

    visit(root_fd, "")
    return _TreeSnapshot(
        files=frozenset(files),
        directories=frozenset(directories),
        file_identities=tuple(sorted(file_identities.items())),
        directory_identities=tuple(sorted(directory_identities.items())),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _parent_directories(paths: set[str]) -> set[str]:
    result: set[str] = set()
    for path in paths:
        parts = PurePosixPath(path).parts
        for length in range(1, len(parts)):
            result.add("/".join(parts[:length]))
    return result


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(metadata.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        for child in os.listdir(descriptor):
            _remove_tree_at(descriptor, child)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)


def _require_external_destination(path: Path) -> None:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        result = subprocess.run(
            (
                "git",
                "-c",
                "safe.directory=*",
                "-C",
                os.fspath(path.parent),
                "rev-parse",
                "--is-inside-work-tree",
                "--show-toplevel",
            ),
            capture_output=True,
            check=False,
            env=environment,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AuthoringProviderError("private catalog destination cannot be audited") from error
    if _contains_repository_marker(path.parent):
        raise AuthoringProviderError(
            "private catalogs cannot be materialized inside a Git worktree"
        )
    if result.returncode == 0:
        lines = result.stdout.splitlines()
        if not lines or lines[0] not in {b"true", b"false"}:
            raise AuthoringProviderError("private catalog destination has invalid Git evidence")
        if lines[0] == b"true":
            raise AuthoringProviderError(
                "private catalogs cannot be materialized inside a Git worktree"
            )
        return
    not_repository = b"fatal: not a git repository "
    if result.returncode == 128 and result.stderr.startswith(not_repository):
        return
    raise AuthoringProviderError("private catalog destination Git audit failed")


def _contains_repository_marker(start: Path) -> bool:
    descriptor = _open_absolute_directory(start)
    try:
        while True:
            try:
                os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise AuthoringProviderError(
                    "private catalog destination repository markers cannot be audited"
                ) from error
            else:
                return True
            current = os.fstat(descriptor)
            parent = os.open(
                "..",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            parent_metadata = os.fstat(parent)
            if (current.st_dev, current.st_ino) == (
                parent_metadata.st_dev,
                parent_metadata.st_ino,
            ):
                os.close(parent)
                return False
            os.close(descriptor)
            descriptor = parent
    finally:
        os.close(descriptor)


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("catalog receipt contains duplicate keys")
        result[key] = value
    return result


__all__ = [
    "CatalogMaterializationReceipt",
    "materialize_private_catalog",
    "verify_materialized_catalog",
]
