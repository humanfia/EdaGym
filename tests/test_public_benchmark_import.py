"""Semantic boundary evidence for public benchmark imports."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from edagym.authoring.public_benchmarks import import_public_calibration_task
from edagym.specs.common import Redistribution
from edagym.specs.task import (
    PublicCalibrationTaskOrigin,
    TaskNamespace,
    TaskSpec,
)

from .factories import digest, task_spec


def _manifest(snapshot: str = "verilog-eval-snapshot") -> PublicCalibrationTaskOrigin:
    return PublicCalibrationTaskOrigin(
        source_id="verilog_eval",
        source_snapshot_digest=digest(snapshot),
        source_resource_ids=("behavior",),
        license_spdx_expression="MIT",
        redistribution=Redistribution.ALLOWED,
        provenance=("https://github.com/NVlabs/verilog-eval",),
    )


def test_public_import_binds_manifest_identity_and_derives_resource_licenses() -> None:
    native = task_spec()
    manifest = _manifest()
    public = import_public_calibration_task(native, manifest)
    different_snapshot = import_public_calibration_task(native, _manifest("other-snapshot"))

    assert native.identity.namespace is TaskNamespace.NATIVE_SEALED
    assert public.identity.namespace is TaskNamespace.PUBLIC_CALIBRATION
    assert public.identity.origin == manifest
    assert public.resources == native.resources
    assert public.digest != native.digest
    assert public.digest != different_snapshot.digest
    source_license = next(item for item in public.licensing if item.resource_id == "behavior")
    native_license = next(item for item in public.licensing if item.resource_id == "generator")
    original_native_license = next(
        item for item in native.licensing if item.resource_id == "generator"
    )
    assert (
        source_license.spdx_expression,
        source_license.redistribution,
        source_license.provenance,
    ) == (
        manifest.license_spdx_expression,
        manifest.redistribution,
        manifest.provenance,
    )
    assert native_license == original_native_license

    tampered = public.model_dump(mode="python")
    tampered["licensing"] = (
        *(
            item.model_copy(update={"spdx_expression": "Apache-2.0"})
            if item.resource_id == "behavior"
            else item
            for item in public.licensing
        ),
    )
    with pytest.raises(ValidationError):
        TaskSpec.model_validate(tampered)
    with pytest.raises(ValueError, match="native sealed"):
        import_public_calibration_task(public, _manifest())
