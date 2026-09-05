"""Manifest-only admission of public benchmark task snapshots."""

from __future__ import annotations

from edagym.specs.task import (
    NativeSealedTaskOrigin,
    PublicCalibrationTaskOrigin,
    ResourceLicense,
    TaskIdentity,
    TaskSpec,
)


def import_public_calibration_task(
    task: TaskSpec,
    manifest: PublicCalibrationTaskOrigin,
) -> TaskSpec:
    """Bind a native task template to public source metadata without content I/O."""

    if not isinstance(task.identity.origin, NativeSealedTaskOrigin):
        raise ValueError("only native sealed task templates may enter the public importer")
    source_resources = set(manifest.source_resource_ids)
    licensing = tuple(
        ResourceLicense(
            resource_id=item.resource_id,
            spdx_expression=(
                manifest.license_spdx_expression
                if item.resource_id in source_resources
                else item.spdx_expression
            ),
            redistribution=(
                manifest.redistribution
                if item.resource_id in source_resources
                else item.redistribution
            ),
            provenance=(
                manifest.provenance if item.resource_id in source_resources else item.provenance
            ),
        )
        for item in task.licensing
    )
    return TaskSpec.model_validate(
        {
            **task.model_dump(mode="python"),
            "identity": TaskIdentity(
                family=task.identity.family,
                authoring_revision=task.identity.authoring_revision,
                origin=manifest,
            ),
            "licensing": licensing,
        }
    )
