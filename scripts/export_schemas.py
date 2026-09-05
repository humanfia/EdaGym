#!/usr/bin/env python3
"""Regenerate committed JSON Schemas from their Pydantic owners."""

from __future__ import annotations

import argparse
from pathlib import Path

from edagym.schemas import export_schemas


def main() -> int:
    parser = argparse.ArgumentParser(description="Export EdaGym JSON Schemas")
    parser.add_argument("directory", nargs="?", type=Path, default=Path("schemas"))
    arguments = parser.parse_args()
    export_schemas(arguments.directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
