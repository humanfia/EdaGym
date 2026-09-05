#!/usr/bin/env python3
"""Verify that committed JSON Schemas match their semantic owners."""

from pathlib import Path

from edagym.schemas import schema_exports_are_current


def main() -> int:
    return 0 if schema_exports_are_current(Path("schemas")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
