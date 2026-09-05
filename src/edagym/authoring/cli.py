"""Command-line access to the public private-authoring boundary."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

from edagym.authoring.contracts import (
    AuthoringContractReceipt,
    CatalogVerificationProjection,
)
from edagym.authoring.materialization import (
    CatalogMaterializationReceipt,
    materialize_private_catalog,
    verify_materialized_catalog,
)
from edagym.authoring.provider import (
    ExternalAuthoringProvider,
    PrivateAuthoringCapability,
)
from edagym.canonical import canonical_bytes
from edagym.task_families.catalog import PUBLIC_TASK_CATALOG


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Operate the restricted authoring boundary")
    commands = parser.add_subparsers(dest="command", required=True)
    contract = commands.add_parser("contract", help="verify the public provider contract")
    contract.set_defaults(handler=_contract)

    materialize = commands.add_parser(
        "materialize",
        help="materialize one private catalog through a trusted provider",
    )
    materialize.add_argument("capability", choices=tuple(PrivateAuthoringCapability))
    materialize.add_argument("output", type=Path)
    _add_provider_arguments(materialize)
    materialize.set_defaults(handler=_materialize)

    verify = commands.add_parser("verify", help="verify a materialized private catalog")
    verify.add_argument("root", type=Path)
    verify.set_defaults(handler=_verify)
    parsed = parser.parse_args(arguments)
    handler = cast(Callable[[argparse.Namespace], int], parsed.handler)
    return handler(parsed)


def _add_provider_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider-executable", required=True, type=Path)
    parser.add_argument("--provider-executable-digest", required=True)
    parser.add_argument("--provider-implementation-digest", required=True)
    parser.add_argument("--provider-descriptor-digest", required=True)
    parser.add_argument("--timeout-seconds", default=3600, type=int)


def _provider(arguments: argparse.Namespace) -> ExternalAuthoringProvider:
    return ExternalAuthoringProvider(
        arguments.provider_executable,
        expected_executable_digest=arguments.provider_executable_digest,
        expected_implementation_digest=arguments.provider_implementation_digest,
        expected_descriptor_digest=arguments.provider_descriptor_digest,
        timeout_seconds=arguments.timeout_seconds,
    )


def _contract(_arguments: argparse.Namespace) -> int:
    _emit(AuthoringContractReceipt())
    return 0


def _materialize(arguments: argparse.Namespace) -> int:
    receipt = materialize_private_catalog(
        _provider(arguments),
        PrivateAuthoringCapability(arguments.capability),
        PUBLIC_TASK_CATALOG,
        arguments.output,
    )
    _emit_receipt(receipt)
    return 0


def _verify(arguments: argparse.Namespace) -> int:
    receipt = verify_materialized_catalog(arguments.root, PUBLIC_TASK_CATALOG)
    _emit_receipt(receipt)
    return 0


def _emit_receipt(receipt: CatalogMaterializationReceipt) -> None:
    _emit(CatalogVerificationProjection.from_receipt(receipt))


def _emit(value: object) -> None:
    sys.stdout.buffer.write(canonical_bytes(value) + b"\n")


__all__ = ["main"]
