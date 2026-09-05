"""Closed domain types shared by EdaGym specifications."""

from __future__ import annotations

import re
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    WithJsonSchema,
)

from edagym.canonical import canonical_decimal_string

Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$", min_length=1, max_length=96),
]

ModelLabel = Annotated[
    str,
    StringConstraints(min_length=1, max_length=160, pattern=r"^[^\s]+$"),
]

ServiceTierLabel = Annotated[
    str,
    StringConstraints(min_length=1, max_length=32, pattern=r"^[^\s]+$"),
]

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Seed128Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
JCS_INTEGER_MAX = 2**53 - 1
JcsPositiveInt = Annotated[int, Field(strict=True, ge=1, le=JCS_INTEGER_MAX)]
JcsNonNegativeInt = Annotated[int, Field(strict=True, ge=0, le=JCS_INTEGER_MAX)]
_DECIMAL_STRING_PATTERN = r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$"


def _decimal_from_non_float(value: Any) -> Any:
    if isinstance(value, (float, bool)):
        raise ValueError(
            "decimal values must be encoded as strings or integers, not floats or booleans"
        )
    if isinstance(value, str) and re.fullmatch(_DECIMAL_STRING_PATTERN, value) is None:
        raise ValueError("decimal strings must use fixed-point notation")
    return value


def _normalize_decimal(value: Decimal) -> Decimal:
    if not value.is_finite():
        raise ValueError("decimal values must be finite")
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise ValueError("finite decimal has a non-integer exponent")
    normalized_digits = list(digits)
    while normalized_digits and normalized_digits[-1] == 0:
        normalized_digits.pop()
        exponent += 1
    if not normalized_digits:
        return Decimal(0)
    return Decimal((sign, tuple(normalized_digits), exponent))


CanonicalDecimal = Annotated[
    Decimal,
    BeforeValidator(_decimal_from_non_float),
    AfterValidator(_normalize_decimal),
    PlainSerializer(canonical_decimal_string, return_type=str, when_used="json"),
    WithJsonSchema(
        {
            "anyOf": [
                {"type": "integer"},
                {"type": "string", "pattern": _DECIMAL_STRING_PATTERN},
            ]
        },
        mode="validation",
    ),
]


def _require_schema_version_one(value: Any) -> Any:
    if type(value) is not int or value != 1:
        raise ValueError("schema_version must be the integer 1")
    return value


SchemaVersion = Annotated[Literal[1], BeforeValidator(_require_schema_version_one)]


class StrictModel(BaseModel):
    """Immutable model with unknown fields and non-finite numbers rejected."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        validate_default=True,
    )


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class Redistribution(StrEnum):
    ALLOWED = "allowed"
    RESTRICTED = "restricted"
    FORBIDDEN = "forbidden"


class Visibility(StrEnum):
    PUBLIC = "public"
    PARTICIPANT = "participant"
    REVIEWER = "reviewer"
    VERIFIER = "verifier"
    AUTHOR = "author"


class ProviderResponseStatus(StrEnum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    IN_PROGRESS = "in_progress"
    QUEUED = "queued"
    CANCELLED = "cancelled"


class Capability(StrEnum):
    HW_IR_LOWERING = "hw.ir_lowering"
    RTL_SIMULATION = "rtl.simulation"
    RTL_LINT = "rtl.lint"
    CDC_RDC = "rtl.cdc_rdc"
    FORMAL_PROPERTY = "formal.property"
    EQUIVALENCE = "formal.equivalence"
    ASIC_SYNTHESIS = "asic.synthesis"
    STATIC_TIMING = "asic.sta"
    DIGITAL_IMPLEMENTATION = "asic.pnr"
    POWER_ANALYSIS = "asic.power_analysis"
    POWER_INTEGRITY = "asic.power_integrity"
    PARASITIC_EXTRACTION = "asic.parasitic_extraction"
    PHYSICAL_VERIFICATION = "physical.verification"
    CIRCUIT_SIMULATION = "circuit.simulation"
    FPGA_IMPLEMENTATION = "fpga.implementation"
    HIGH_LEVEL_SYNTHESIS = "hls.synthesis"
    DESIGN_FOR_TEST = "dft.insertion"
    CELL_CHARACTERIZATION = "cell.characterization"


class ArtifactClass(StrEnum):
    EPHEMERAL = "ephemeral"
    DIAGNOSTIC = "diagnostic"
    CANDIDATE = "candidate"
    CHECKPOINT = "checkpoint"
    EVIDENCE = "evidence"
    MEASUREMENT = "measurement"
    RELEASE = "release"
    TRAINING = "training"


def validate_relative_path(value: str) -> str:
    """Reject paths that could escape a generated task or artifact root."""

    path = PurePosixPath(value)
    if path.is_absolute() or not value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("path must be a normalized non-empty relative POSIX path")
    return path.as_posix()
