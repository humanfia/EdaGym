"""Bounded physical-rule qualification through the KLayout database engine."""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_NATIVE_DATABASE_BYTES = 64 * 1024 * 1024
_MAX_RECTANGLES = 10_000
_MAX_COORDINATE_NM = 10**9
_RULE_ID = "minimum_spacing"
_TOP_CELL = "TOP"
_CONDUCTOR_LAYER = (1, 0)
_LABEL_LAYER = (10, 0)
_MINIMUM_SPACING_NM = 200
_PORT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _document(path: Path) -> dict[str, Any]:
    encoded = path.read_bytes()
    if not encoded or len(encoded) > _MAX_INPUT_BYTES:
        raise ValueError("layout input has an invalid size")
    value = json.loads(encoded)
    if not isinstance(value, dict) or set(value) != {
        "minimum_spacing_nm",
        "rectangles_nm",
    }:
        raise ValueError("layout input has an invalid shape")
    return value


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if value > _MAX_COORDINATE_NM:
        raise ValueError(f"{name} exceeds the coordinate limit")
    return value


def _rectangles(value: object) -> tuple[tuple[int, int, int, int], ...]:
    if not isinstance(value, list) or not 2 <= len(value) <= _MAX_RECTANGLES:
        raise ValueError("layout must contain a bounded rectangle collection")
    rectangles: list[tuple[int, int, int, int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 4:
            raise ValueError("layout rectangles require four coordinates")
        if any(
            isinstance(coordinate, bool) or not isinstance(coordinate, int) for coordinate in item
        ):
            raise ValueError("layout rectangle coordinates must be integers")
        x1, y1, x2, y2 = item
        if min(x1, y1) < 0 or max(x2, y2) > _MAX_COORDINATE_NM or x1 >= x2 or y1 >= y2:
            raise ValueError("layout rectangle coordinates are invalid")
        rectangles.append((x1, y1, x2, y2))
    return tuple(rectangles)


def _engine_version() -> str:
    """Report the installed engine version only after the engine itself imports."""

    import klayout.db  # noqa: F401

    return importlib.metadata.version("klayout")


def _check(input_path: Path, output_path: Path) -> None:
    import klayout.db as kdb

    document = _document(input_path)
    minimum_spacing = _positive_integer(
        document["minimum_spacing_nm"],
        "minimum_spacing_nm",
    )
    region = kdb.Region()
    for rectangle in _rectangles(document["rectangles_nm"]):
        region.insert(kdb.Box(*rectangle))
    violations = region.space_check(minimum_spacing)
    report = {
        "engine": "klayout.db",
        "engine_version": _engine_version(),
        "rule_id": _RULE_ID,
        "minimum_spacing_nm": minimum_spacing,
        "violation_count": int(violations.size()),
    }
    encoded = (
        json.dumps(
            report,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    with output_path.open("xb") as stream:
        stream.write(encoded)


def _relative_leaf(value: str, role: str) -> Path:
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or len(candidate.parts) != 1
        or candidate.parts[0] in {"", ".", ".."}
        or "\x00" in value
    ):
        raise ValueError(f"{role} must be a normalized relative leaf")
    return Path(value)


def _open_private_input(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_INPUT_BYTES
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValueError("physical-verification input is not a bounded private file")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _require_new_outputs(paths: tuple[Path, ...], inputs: tuple[Path, ...]) -> None:
    if len(paths) != len(set(paths)) or set(paths) & set(inputs):
        raise ValueError("physical-verification paths must be distinct")
    for path in paths:
        try:
            path.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError("physical-verification outputs must not exist")


def _secure_generated_output(path: Path) -> tuple[int, tuple[int, int, int, int]]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > _MAX_NATIVE_DATABASE_BYTES
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise ValueError("native results database is not a bounded private file")
        os.fchmod(descriptor, 0o600)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise ValueError("native results database changed while secured")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _require_unchanged_output(
    descriptor: int,
    identity: tuple[int, int, int, int],
) -> None:
    metadata = os.fstat(descriptor)
    if (
        (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != identity
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("native results database changed during replay")


def _write_private_summary(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
        ):
            raise ValueError("physical-verification summary is not a private file")
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or after.st_size != len(content)
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise ValueError("physical-verification summary changed while written")
    finally:
        os.close(descriptor)


def _verify(
    layout_path: Path,
    schematic_path: Path,
    drc_database_path: Path,
    lvs_database_path: Path,
    summary_path: Path,
) -> None:
    import klayout.db as kdb
    import klayout.rdb as krdb

    _require_new_outputs(
        (drc_database_path, lvs_database_path, summary_path),
        (layout_path, schematic_path),
    )
    layout_descriptor = _open_private_input(layout_path)
    schematic_descriptor = _open_private_input(schematic_path)
    drc_descriptor: int | None = None
    lvs_descriptor: int | None = None
    try:
        layout = kdb.Layout()
        layout.read(f"/proc/self/fd/{layout_descriptor}")
        top = layout.cell(_TOP_CELL)
        if top is None or layout.dbu != 0.001:
            raise ValueError("layout does not implement the physical-verification contract")
        metal_index = layout.find_layer(*_CONDUCTOR_LAYER)
        label_index = layout.find_layer(*_LABEL_LAYER)
        if metal_index is None or metal_index < 0 or label_index is None or label_index < 0:
            raise ValueError("layout is missing a required verification layer")
        metal = kdb.Region(top.begin_shapes_rec(metal_index))
        labels = kdb.Texts(top.begin_shapes_rec(label_index))
        spacing_violations = metal.space_check(_MINIMUM_SPACING_NM)
        violation_count = int(spacing_violations.size())

        report = krdb.ReportDatabase("physical-verification")
        report_cell = report.create_cell(_TOP_CELL)
        report_category = report.create_category("minimum-metal-spacing")
        report.create_items(
            report_cell.rdb_id(),
            report_category.rdb_id(),
            kdb.CplxTrans(layout.dbu),
            spacing_violations,
        )
        report.save(str(drc_database_path))
        drc_descriptor, drc_identity = _secure_generated_output(drc_database_path)
        replayed_report = krdb.ReportDatabase("physical-verification-replay")
        replayed_report.load(f"/proc/self/fd/{drc_descriptor}")
        replayed_violation_count = int(replayed_report.num_items())
        if replayed_violation_count != violation_count:
            raise ValueError("native DRC database disagrees with the engine result")

        extractor = kdb.LayoutToNetlist(_TOP_CELL, layout.dbu)
        extractor.register(metal, "metal")
        extractor.register(labels, "labels")
        extractor.connect(metal)
        extractor.connect(metal, labels)
        extractor.extract_netlist()
        extracted = extractor.netlist()
        top_circuit = extracted.top_circuit()
        if top_circuit is None:
            raise ValueError("layout extraction omitted the top circuit")
        port_names: set[str] = set()
        for net in tuple(top_circuit.each_net()):
            names = tuple(item.strip() for item in net.name.split(",") if item.strip())
            for name in names:
                if _PORT_NAME.fullmatch(name) is None or name in port_names:
                    raise ValueError("layout labels are not unique bounded port names")
                port_names.add(name)
                top_circuit.connect_pin(top_circuit.create_pin(name), net)
        reference = kdb.Netlist()
        reference.read(
            f"/proc/self/fd/{schematic_descriptor}",
            kdb.NetlistSpiceReader(),
        )
        compared = bool(kdb.NetlistComparer().compare(extracted, reference))
        extractor.write(str(lvs_database_path))
        lvs_descriptor, lvs_identity = _secure_generated_output(lvs_database_path)
        replayed_extractor = kdb.LayoutToNetlist()
        replayed_extractor.read(f"/proc/self/fd/{lvs_descriptor}")
        replayed_netlist = replayed_extractor.netlist()
        replayed_top = replayed_netlist.top_circuit()
        if replayed_top is None:
            raise ValueError("native LVS database omitted the top circuit")

        summary = {
            "schema_version": 1,
            "minimum_spacing_nm": _MINIMUM_SPACING_NM,
            "drc_violation_count": violation_count,
            "drc_database_item_count": replayed_violation_count,
            "drc_database_nonempty": True,
            "lvs_compared": True,
            "lvs_matched": compared,
            "layout_net_count": sum(1 for _ in replayed_top.each_net()),
            "layout_pin_count": replayed_top.pin_count(),
            "lvs_database_nonempty": True,
        }
        encoded = (
            json.dumps(
                summary,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
        _write_private_summary(summary_path, encoded)
        _require_unchanged_output(drc_descriptor, drc_identity)
        _require_unchanged_output(lvs_descriptor, lvs_identity)
    finally:
        if drc_descriptor is not None:
            os.close(drc_descriptor)
        if lvs_descriptor is not None:
            os.close(lvs_descriptor)
        os.close(layout_descriptor)
        os.close(schematic_descriptor)


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if values == ["--version"]:
        print(f"klayout.db {_engine_version()}")
        return 0
    os.umask(0o077)
    try:
        if len(values) == 3 and values[0] == "check":
            _check(
                _relative_leaf(values[1], "layout input"),
                _relative_leaf(values[2], "DRC output"),
            )
        elif len(values) == 6 and values[0] == "verify":
            _verify(
                _relative_leaf(values[1], "layout input"),
                _relative_leaf(values[2], "schematic input"),
                _relative_leaf(values[3], "DRC database output"),
                _relative_leaf(values[4], "LVS database output"),
                _relative_leaf(values[5], "summary output"),
            )
        else:
            raise ValueError("unsupported physical-verification operation")
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        print("physical-verification input rejected", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
