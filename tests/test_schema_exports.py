"""Evidence that committed schemas remain derived rather than independent owners."""

from __future__ import annotations

from pathlib import Path

from edagym.schemas import export_schemas


def test_committed_schemas_match_their_model_owners(tmp_path: Path) -> None:
    generated = tmp_path / "schemas"
    export_schemas(generated)
    committed = Path(__file__).resolve().parents[1] / "schemas"

    generated_files = sorted(path.name for path in generated.iterdir())
    committed_files = sorted(path.name for path in committed.iterdir())
    assert committed_files == generated_files
    for name in generated_files:
        assert (committed / name).read_bytes() == (generated / name).read_bytes()
