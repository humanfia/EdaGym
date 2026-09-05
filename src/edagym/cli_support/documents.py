"""Strict document and artifact-store loading for CLI operations."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ValidationError

from edagym.cli_support.errors import CliFailure
from edagym.run.artifacts import (
    ArtifactStoreError,
    ContentAddressedStore,
    EncryptionKey,
    encryption_key_from_file_descriptor,
)
from edagym.serialization import DocumentKind, load_yaml_document
from edagym.specs.environment import EnvironmentSpec, ManagedEncryption

_UNSATISFIED = 1
_INCOMPLETE = 3


def load_model[TModel: BaseModel](
    path: Path,
    kind: DocumentKind,
    expected: type[TModel],
) -> TModel:
    """Load one exact schema owner without exposing parser diagnostics."""

    try:
        document = load_yaml_document(path, kind=kind)
    except (OSError, ValueError, ValidationError):
        raise CliFailure(f"invalid-{kind.replace('_', '-')}", status=_UNSATISFIED) from None
    if not isinstance(document, expected):
        raise CliFailure(f"invalid-{kind.replace('_', '-')}", status=_UNSATISFIED)
    return document


def open_artifact_store(
    root: Path,
    environment: EnvironmentSpec,
    key_file: Path | None,
) -> ContentAddressedStore:
    """Open the environment-owned artifact policy with an optional managed key."""

    encryption = environment.artifact_policy.encryption
    if isinstance(encryption, ManagedEncryption):
        if key_file is None:
            raise CliFailure("artifact-key-required", status=_UNSATISFIED)
        key = _read_private_key(key_file, encryption.provider_id)
    else:
        if key_file is not None:
            raise CliFailure("artifact-key-not-accepted", status=_UNSATISFIED)
        key = None
    try:
        return ContentAddressedStore(
            root,
            policy=environment.artifact_policy,
            encryption_key=key,
        )
    except (OSError, ValueError, RuntimeError):
        raise CliFailure("artifact-store-unavailable", status=_INCOMPLETE) from None


def _read_private_key(path: Path, key_id: str) -> EncryptionKey:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise CliFailure("artifact-key-unavailable", status=_UNSATISFIED) from None
    try:
        try:
            return encryption_key_from_file_descriptor(
                key_id=key_id,
                descriptor=descriptor,
            )
        except (ArtifactStoreError, OSError, ValueError):
            raise CliFailure("artifact-key-insecure", status=_UNSATISFIED) from None
    finally:
        os.close(descriptor)
