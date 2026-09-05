"""Evidence for stable canonical identity and strict document ingestion."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal, localcontext
from typing import Self

import pytest
from pydantic import ValidationError, field_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.serialization import (
    DuplicateKeyError,
    UnsupportedSchemaVersion,
    load_document,
    load_yaml,
)
from edagym.specs.common import CanonicalDecimal, SchemaVersion, StrictModel, Visibility
from tests.factories import task_instance, task_spec


class CanonicalFixture(StrictModel):
    schema_version: SchemaVersion = 1
    label: str
    amount: CanonicalDecimal
    visibility: Visibility = Visibility.PUBLIC
    observed_at: datetime
    names: tuple[str, ...]
    optional: str | None = None

    @field_validator("names")
    @classmethod
    def normalize_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(value))

    def assert_fixture(self) -> Self:
        return self


def test_canonical_bytes_and_digest_are_stable() -> None:
    fixture = CanonicalFixture(
        label="canonical",
        amount=Decimal("1.2300"),
        observed_at=datetime(2026, 9, 4, 12, 30, tzinfo=UTC),
        names=("zeta", "alpha"),
    ).assert_fixture()
    expected = (
        b'{"amount":"1.23","label":"canonical","names":["alpha","zeta"],'
        b'"observed_at":"2026-09-04T12:30:00Z","optional":null,'
        b'"schema_version":1,"visibility":"public"}'
    )
    assert canonical_bytes(fixture) == expected
    assert canonical_digest(fixture, domain="canonical-fixture-v1") == (
        "sha256:e7ac8041d76d8392779aff2e0c856d4236c7dc7c794a56db1b6774de45f28584"
    )

    reordered = fixture.model_copy(update={"names": ("alpha", "zeta")})
    changed = fixture.model_copy(update={"amount": Decimal("1.24")})
    assert canonical_bytes(reordered) == expected
    assert canonical_digest(changed, domain="canonical-fixture-v1") != canonical_digest(
        fixture,
        domain="canonical-fixture-v1",
    )


def test_document_loader_rejects_ambiguous_or_noncanonical_input() -> None:
    with pytest.raises(DuplicateKeyError):
        load_yaml("schema_version: 1\nschema_version: 1\n")
    with pytest.raises(UnsupportedSchemaVersion):
        load_document({"schema_version": 2}, kind="task")
    with pytest.raises(UnsupportedSchemaVersion):
        load_document({"schema_version": 1.0}, kind="task")
    with pytest.raises(ValidationError):
        CanonicalFixture.model_validate(
            {
                "label": "float",
                "amount": 1.25,
                "observed_at": datetime.now(UTC),
                "names": ("one",),
            }
        )
    with pytest.raises((ValueError, ValidationError)):
        CanonicalFixture(
            label="nan",
            amount=Decimal("NaN"),
            observed_at=datetime.now(UTC),
            names=("one",),
        )


def test_canonical_decimal_persistence_uses_schema_admissible_fixed_point() -> None:
    fixture = CanonicalFixture(
        label="large",
        amount=Decimal("1E+3"),
        observed_at=datetime(2026, 9, 4, tzinfo=UTC),
        names=("one",),
    )
    encoded = canonical_bytes(fixture)

    assert b'"amount":"1000"' in encoded
    assert CanonicalFixture.model_validate_json(encoded) == fixture
    wide = fixture.model_copy(
        update={"amount": Decimal("123456789012345678901234567890.1200")}
    )
    with localcontext() as context:
        context.prec = 4
        low_precision = canonical_bytes(wide)
    with localcontext() as context:
        context.prec = 50
        high_precision = canonical_bytes(wide)
    assert low_precision == high_precision
    assert b'"amount":"123456789012345678901234567890.12"' in low_precision
    with pytest.raises(ValidationError, match="fixed-point"):
        CanonicalFixture.model_validate(
            {
                **fixture.model_dump(mode="python"),
                "amount": "1E+3",
            }
        )


def test_full_width_seed_has_a_canonical_identity() -> None:
    task = task_spec()
    instance = task_instance(task)
    identity = instance.identity.model_copy(
        update={"seed": "ffffffffffffffffffffffffffffffff"}
    )
    full_width = instance.model_copy(update={"identity": identity})

    assert b'"seed":"ffffffffffffffffffffffffffffffff"' in canonical_bytes(full_width)
    assert full_width.digest.startswith("sha256:")
