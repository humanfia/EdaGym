"""Task generation, private materialization, and qualification admission."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from pydantic import Field, TypeAdapter

from edagym.authoring.qualification import validate_qualification
from edagym.authoring.rtl_repair import DIFFICULTIES, FAMILY, content_digest, generate_repair
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.config.resolve import ResolvedSite
from edagym.policy.runtime_storage import private_directory, read_private, write_private
from edagym.run.artifacts import ContentAddressedStore
from edagym.run.model import BlobRef
from edagym.specs.common import (
    ArtifactClass,
    Identifier,
    Redistribution,
    Seed128Hex,
    Sensitivity,
    StrictModel,
    Visibility,
)
from edagym.specs.environment import ArtifactDisclosure, ArtifactPolicy, ArtifactRetentionRule
from edagym.specs.release import (
    GeneratedFile,
    QualificationStatus,
    TaskInstance,
    TaskInstanceIdentity,
    TaskLineage,
    TaskQualificationEvidence,
)
from edagym.specs.task import TaskSpec
from edagym.task_families.catalog import PUBLIC_TASK_CATALOG

_AUTHORING_QUOTA_BYTES = 64 * 1024 * 1024
_RETENTION_SECONDS = 30 * 24 * 3600
_IDENTIFIER = TypeAdapter(Identifier)


class GenerationRequest(StrictModel):
    family: Identifier
    difficulty: Identifier
    seed: Seed128Hex
    count: int = Field(strict=True, ge=1, le=1000)
    authoring_revision: int = Field(strict=True, ge=1, default=1)
    split: Literal["development", "calibration", "confirmatory_holdout"] = "development"


@dataclass(frozen=True)
class GeneratedTask:
    task: TaskSpec
    instance: TaskInstance
    contents: Mapping[str, bytes]

    @property
    def instance_id(self) -> str:
        return f"task_{self.instance.digest[7:]}"


Qualifier = Callable[[TaskInstance, TaskSpec], TaskQualificationEvidence]


class TaskFactory:
    """Materialize actual generators and keep answers in the private artifact store."""

    @staticmethod
    def catalog() -> tuple[dict[str, object], ...]:
        design = generate_repair("0" * 32, DIFFICULTIES[0], 1)
        runnable = {
            "family": design.task.identity.family,
            "root": "eda_flow",
            "contract": "Repair a streaming queue while preserving its ready/valid contract.",
            "instance_names": DIFFICULTIES,
            "capabilities": tuple(sorted({
                capability.value
                for evaluator in design.task.evaluation.evaluators
                for capability in (evaluator.capability, *evaluator.supporting_capabilities)
            })),
            "generator_available": True,
        }
        metadata = []
        for family in PUBLIC_TASK_CATALOG.families:
            if family.family == FAMILY:
                metadata.append(runnable)
                continue
            metadata.append({
                "family": family.family,
                "root": family.root.value,
                "contract": family.semantic_contract,
                "instance_names": family.instance_names,
                "capabilities": tuple(item.value for item in family.required_capabilities),
                "generator_available": False,
                "unavailable_reason": "generator_not_qualified",
            })
        return tuple(metadata)

    def generate(
        self,
        request: GenerationRequest,
        *,
        site: ResolvedSite | None = None,
        qualifier: Qualifier | None = None,
    ) -> tuple[GeneratedTask, ...]:
        if request.family != FAMILY:
            raise ValueError("task family has no registered executable generator")
        generated = []
        for offset in range(request.count):
            seed = hashlib.sha256(
                bytes.fromhex(request.seed) + offset.to_bytes(8, "big")
            ).hexdigest()[:32]
            design = generate_repair(seed, request.difficulty, request.authoring_revision)
            task = design.task
            visibility = {item.resource_id: item for item in task.visibility}
            licensing = {item.resource_id: item for item in task.licensing}
            files = tuple(
                GeneratedFile(
                    path=resource.path,
                    content_digest=resource.content_digest,
                    size_bytes=len(design.files[resource.path]),
                    media_type=resource.media_type,
                    source_resource_ids=(resource.resource_id,),
                    visibility=visibility[resource.resource_id].visibility,
                    sensitivity=visibility[resource.resource_id].sensitivity,
                    redistribution=licensing[resource.resource_id].redistribution,
                )
                for resource in task.resources
            )
            # Width/seed variants share this concrete ring-buffer skeleton. They
            # cannot be counted as independent benchmark blocks or split apart.
            base_design = "ready_valid_ring_buffer_v1"
            instance = TaskInstance(
                identity=TaskInstanceIdentity(
                    task_family=task.identity.family,
                    authoring_revision=task.identity.authoring_revision,
                    task_spec_digest=task.digest,
                    generator_digest=task.generator.implementation_digest,
                    seed=seed,
                    parameters=design.parameters,
                ),
                lineage=TaskLineage(
                    lineage_id=base_design,
                    base_design_id=base_design,
                    generator_revision=request.authoring_revision,
                    split=request.split,
                    mechanism_ids=design.mechanism_ids,
                ),
                generated_files=files,
                reference_bundle_digest=canonical_digest(
                    tuple(item for item in files if item.visibility is Visibility.AUTHOR),
                    domain="reference-bundle-v1",
                ),
                verifier_bundle_digest=canonical_digest(
                    tuple(item for item in files if item.visibility is Visibility.VERIFIER),
                    domain="verifier-bundle-v1",
                ),
                qualification=TaskQualificationEvidence(status=QualificationStatus.PENDING),
            )
            if qualifier is not None:
                instance = instance.model_copy(update={"qualification": qualifier(instance, task)})
                validate_qualification(instance, task)
            item = GeneratedTask(task, instance, design.files)
            if site is not None:
                self.persist(item, site.state_root)
            generated.append(item)
        return tuple(generated)

    def persist(self, generated: GeneratedTask, state_root: Path) -> None:
        validate_qualification(generated.instance, generated.task)
        root = private_directory(state_root / "authoring", create=True)
        store = _store(root)
        for file in generated.instance.generated_files:
            content = generated.contents[file.path]
            if content_digest(content) != file.content_digest or len(content) != file.size_bytes:
                raise ValueError("generated content disagrees with its immutable manifest")
            store.put_bytes(
                content,
                artifact_class=ArtifactClass.RELEASE,
                sensitivity=file.sensitivity,
                visibility=file.visibility,
                redistribution=file.redistribution,
            )
        destination = root / "instances" / generated.instance_id
        write_private(destination / "task.json", canonical_bytes(generated.task) + b"\n")
        write_private(destination / "instance.json", canonical_bytes(generated.instance) + b"\n")

    def load(self, state_root: Path, instance_id: str) -> GeneratedTask:
        _IDENTIFIER.validate_python(instance_id)
        root = private_directory(state_root / "authoring")
        directory = root / "instances" / instance_id
        task = TaskSpec.model_validate_json(read_private(directory / "task.json"))
        instance = TaskInstance.model_validate_json(read_private(directory / "instance.json"))
        validate_qualification(instance, task)
        store = _store(root)
        contents = {}
        for file in instance.generated_files:
            if file.size_bytes is None:
                raise ValueError("generated task has no complete content manifest")
            contents[file.path] = store.read_bytes(
                BlobRef(digest=file.content_digest, size_bytes=file.size_bytes),
                maximum_bytes=_AUTHORING_QUOTA_BYTES,
            )
        result = GeneratedTask(task, instance, contents)
        if result.instance_id != instance_id:
            raise ValueError("task instance identifier disagrees with its stored contents")
        return result

    def qualify(
        self, generated: GeneratedTask, site: ResolvedSite, qualifier: Qualifier
    ) -> GeneratedTask:
        instance = generated.instance.model_copy(
            update={"qualification": qualifier(generated.instance, generated.task)}
        )
        result = replace(generated, instance=instance)
        self.persist(result, site.state_root)
        return result


def generate_task(
    request: GenerationRequest,
    site: ResolvedSite | None = None,
    *,
    factory: TaskFactory | None = None,
    qualifier: Qualifier | None = None,
) -> tuple[GeneratedTask, ...]:
    return (factory or TaskFactory()).generate(request, site=site, qualifier=qualifier)


def _store(root: Path) -> ContentAddressedStore:
    disclosure = tuple(
        ArtifactDisclosure(
            sensitivity=Sensitivity.INTERNAL,
            visibility=visibility,
            redistribution=Redistribution.FORBIDDEN,
        )
        for visibility in (Visibility.PARTICIPANT, Visibility.VERIFIER, Visibility.AUTHOR)
    )
    return ContentAddressedStore(
        private_directory(root / "cas", create=True),
        policy=ArtifactPolicy(
            quota_bytes=_AUTHORING_QUOTA_BYTES,
            rules=tuple(
                ArtifactRetentionRule(
                    artifact_class=kind,
                    retention_seconds=_RETENTION_SECONDS,
                    allowed_disclosures=disclosure,
                )
                for kind in ArtifactClass
            ),
        ),
    )


__all__ = ["GeneratedTask", "GenerationRequest", "Qualifier", "TaskFactory", "generate_task"]
