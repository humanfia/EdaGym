#!/usr/bin/env python3
"""Run EdaGym repository policy checks without rendering secret values."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit repository security boundaries")
    parser.add_argument(
        "--mode",
        choices=("commit", "release"),
        default="commit",
        help="commit scans the index and HEAD; release also scans every Git object",
    )
    parser.add_argument(
        "--repository",
        default=".",
        help="repository or a directory inside it",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="metadata-only report format",
    )
    parser.add_argument(
        "--gitleaks",
        default="/usr/bin/gitleaks",
        help="absolute path to the trusted external scanner",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    source_root = Path(__file__).resolve().parents[1] / "src"
    sys.path.insert(0, str(source_root))

    from edagym.policy.repository import AuditMode, RepositoryPolicy, audit_repository

    parsed = _parser().parse_args(arguments)
    try:
        report = audit_repository(
            parsed.repository,
            AuditMode(parsed.mode),
            policy=RepositoryPolicy(external_scanner_executable=parsed.gitleaks),
        )
    except Exception:
        print("repository-audit mode=unknown status=error", file=sys.stderr)
        return 3
    print(report.to_json() if parsed.format == "json" else report.to_text())
    return int(report.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
