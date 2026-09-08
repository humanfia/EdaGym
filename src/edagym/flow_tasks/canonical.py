"""Validation and qualification of provider-derived EDA-flow tasks."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

from edagym.authoring.provider import (
    DerivedTaskDocument,
    FlowCandidateRole,
    OpaqueTaskInstanceReference,
    PrivateAuthoringCapability,
    flow_candidate_resource_id_for_role,
)
from edagym.canonical import canonical_bytes, canonical_digest
from edagym.evaluation.model import HardGateState, OutcomeKind
from edagym.evaluation.promotion import hard_gate_status
from edagym.flow_tasks.model import (
    CandidateExpectation,
    CandidateVariant,
    FlowStageDefinition,
    FlowTaskPack,
    RegexNumberRule,
    ToolCommand,
)
from edagym.run.artifact_model import (
    ArtifactManifest,
    ArtifactRecord,
    BlobRef,
    ManifestEntry,
)
from edagym.run.artifacts import (
    ARTIFACT_MANIFEST_MEDIA_TYPE,
    ContentAddressedStore,
)
from edagym.run.trial_journal import replay
from edagym.run.trial_model import (
    RunRecord,
    StopReason,
)
from edagym.specs.common import ArtifactClass
from edagym.specs.environment import (
    BrokeredHostToolExecutor,
    EnvironmentSpec,
    RootlessLocalExecutor,
)
from edagym.specs.release import (
    FlowReleaseCandidateQualification,
    FlowReleaseQualification,
    NegativeCandidateQualification,
    ReleaseManifest,
    TaskInstance,
)
from edagym.specs.task import FlowQualificationSpec, TaskSpec, WorkspaceInterface
from edagym.task_families.catalog import EDA_FLOW_FAMILIES


@dataclass(frozen=True, slots=True)
class CanonicalFlowTask:
    """Provider-derived run inputs and their path-free sealed identity."""

    task: TaskSpec
    instance: TaskInstance
    instance_reference: OpaqueTaskInstanceReference

    def __post_init__(self) -> None:
        DerivedTaskDocument(
            instance_reference=self.instance_reference,
            task=self.task,
            instance=self.instance,
        )


def validate_canonical_flow_task(pack: FlowTaskPack, canonical: CanonicalFlowTask) -> None:
    """Validate provider-derived run inputs without reconstructing hidden authoring output."""

    reference = canonical.instance_reference
    if reference.capability is not PrivateAuthoringCapability.EDA_FLOW_CATALOG:
        raise ValueError("canonical flow task has the wrong provider capability")
    metadata = next(
        (item for item in EDA_FLOW_FAMILIES if item.family == pack.family),
        None,
    )
    if metadata is None or pack.semantic_definition_digest != metadata.digest:
        raise ValueError("flow pack does not bind one public family definition")
    if (
        reference.family != pack.family
        or canonical.task.identity.family != pack.family
        or canonical.task.identity.authoring_revision != pack.authoring_revision
        or canonical.instance.identity.authoring_revision != pack.authoring_revision
    ):
        raise ValueError("provider-derived flow task does not belong to its private pack")
    if not isinstance(canonical.task.interface, WorkspaceInterface) or (
        canonical.task.interface.submission_paths != pack.submission_paths
    ):
        raise ValueError("provider-derived flow task changes the submission contract")
    if {item.requirement_id for item in canonical.task.contract.requirements} != set(
        pack.requirements
    ):
        raise ValueError("provider-derived flow task changes the requirement contract")

    expected_evaluators = {
        flow_evaluator_id(stage.stage_id): (
            stage.capability,
            flow_evaluator_revision_digest(stage),
        )
        for stage in pack.stages
    }
    actual_evaluators = {
        evaluator.evaluator_id: (evaluator.capability, evaluator.revision_digest)
        for evaluator in canonical.task.evaluation.evaluators
    }
    if actual_evaluators != expected_evaluators:
        raise ValueError("provider-derived evaluator identities diverge from the private pack")
    expected_stages = {
        stage.stage_id: (
            flow_evaluator_id(stage.stage_id),
            stage.depends_on,
            stage.purpose,
            stage.requirement_ids,
        )
        for stage in pack.stages
    }
    actual_stages = {
        stage.stage_id: (
            stage.evaluator_id,
            stage.depends_on,
            stage.purpose,
            stage.requirement_ids,
        )
        for stage in canonical.task.evaluation.stages
    }
    if actual_stages != expected_stages:
        raise ValueError("provider-derived evaluation graph diverges from the private pack")

    qualification = canonical.task.qualification
    if not isinstance(qualification, FlowQualificationSpec):
        raise ValueError("provider-derived flow task lacks flow qualification metadata")
    witness = {
        flow_candidate_resource_id(candidate)
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.ACCEPTED
    }
    negatives = {
        flow_candidate_resource_id(candidate)
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.REJECTED
    }
    if (
        {qualification.feasibility_witness_resource} != witness
        or set(qualification.negative_candidate_resources) != negatives
    ):
        raise ValueError("provider-derived qualification identities diverge from the private pack")
    declared_measurements = {
        (measurement.measurement_id, measurement.producer_stage_id)
        for measurement in canonical.task.measurements
    }
    expected_measurements = {
        (rule.measurement_id, stage.stage_id)
        for stage in pack.stages
        for rule in stage.rules
        if isinstance(rule, RegexNumberRule) and rule.measurement_id is not None
    }
    if declared_measurements != expected_measurements:
        raise ValueError("provider-derived measurements diverge from the private pack")


def derive_flow_release_candidate(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
) -> ReleaseManifest:
    """Project a non-promotable manifest from validated provider inputs."""

    validate_canonical_flow_task(pack, canonical)
    require_flow_environment(pack, environment)
    reference = canonical.instance_reference
    return ReleaseManifest(
        task_spec_digest=canonical.task.digest,
        task_instance_digest=canonical.instance.digest,
        participant_bundle_digest=reference.participant_bundle_digest,
        verifier_bundle_digest=reference.verifier_bundle_digest,
        environment_digests=(environment.digest,),
        files=canonical.instance.generated_files,
        qualification=FlowReleaseCandidateQualification(
            authoring_source_digest=pack.digest,
        ),
    )


def derive_flow_release(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
    qualification_records: Mapping[str, RunRecord],
    artifact_store: ContentAddressedStore,
) -> ReleaseManifest:
    """Admit a release after validating complete author qualification records."""

    if artifact_store.policy != environment.artifact_policy:
        raise ValueError("qualification artifact store does not match the environment")
    release_candidate = derive_flow_release_candidate(pack, canonical, environment)
    _validate_qualification_records(
        pack,
        canonical,
        environment,
        release_candidate,
        qualification_records,
        artifact_store,
    )
    witness = next(
        candidate
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.ACCEPTED
    )
    negatives = tuple(
        candidate
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.REJECTED
    )
    reference = canonical.instance_reference
    return ReleaseManifest(
        task_spec_digest=canonical.task.digest,
        task_instance_digest=canonical.instance.digest,
        participant_bundle_digest=reference.participant_bundle_digest,
        verifier_bundle_digest=reference.verifier_bundle_digest,
        environment_digests=(environment.digest,),
        files=canonical.instance.generated_files,
        qualification=FlowReleaseQualification(
            witness_resource_id=flow_candidate_resource_id(witness),
            witness_evidence_digest=qualification_records[witness.candidate_id].integrity_digest,
            negative_results=tuple(
                NegativeCandidateQualification(
                    candidate_resource_id=flow_candidate_resource_id(candidate),
                    evidence_digest=qualification_records[
                        candidate.candidate_id
                    ].integrity_digest,
                )
                for candidate in negatives
            ),
        ),
    )


def flow_evaluator_id(stage_id: str) -> str:
    return f"flow.{stage_id}"


def flow_evaluator_revision_digest(stage: FlowStageDefinition) -> str:
    return canonical_digest(stage, domain="flow-evaluator-revision-v1")


def flow_candidate_resource_id(candidate: CandidateVariant) -> str:
    """Return the canonical author-only resource identity for one flow candidate."""

    role = (
        FlowCandidateRole.FEASIBILITY_WITNESS
        if candidate.expectation is CandidateExpectation.ACCEPTED
        else FlowCandidateRole.SEMANTIC_NEGATIVE
    )
    return flow_candidate_resource_id_for_role(candidate.candidate_id, role)


def flow_candidate_manifest_digest(
    candidate: CandidateVariant,
    environment: EnvironmentSpec,
) -> str:
    """Derive the exact retained candidate-manifest digest for qualification."""

    disclosure = environment.artifact_policy.persistent_disclosure(ArtifactClass.CANDIDATE)
    if disclosure is None:
        raise ValueError("flow qualification requires retained candidate snapshots")
    manifest = ArtifactManifest(
        artifact_class=ArtifactClass.CANDIDATE,
        sensitivity=disclosure.sensitivity,
        visibility=disclosure.visibility,
        redistribution=disclosure.redistribution,
        entries=tuple(
            ManifestEntry(
                path=asset.path,
                blob=BlobRef(
                    digest=_content_digest(asset.content.encode("utf-8")),
                    size_bytes=len(asset.content.encode("utf-8")),
                ),
                mode=0o644,
            )
            for asset in candidate.assets
        ),
    )
    return _content_digest(canonical_bytes(manifest))


def require_flow_environment(pack: FlowTaskPack, environment: EnvironmentSpec) -> None:
    """Require exact environment bindings for every command in a private recipe."""

    if not isinstance(
        environment.executor,
        (BrokeredHostToolExecutor, RootlessLocalExecutor),
    ):
        raise ValueError("flow recipes require an executor with a trusted recipe supervisor")
    bindings = {(binding.capability, binding.tool_id) for binding in environment.tool_bindings}
    required = {
        (command.capability, command.tool_id)
        for stage in pack.stages
        for command in stage.commands
        if isinstance(command, ToolCommand)
    }
    if not required.issubset(bindings):
        raise ValueError("environment does not bind every tool in the flow recipe")


def _validate_qualification_records(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
    environment: EnvironmentSpec,
    release_candidate: ReleaseManifest,
    records: Mapping[str, RunRecord],
    artifact_store: ContentAddressedStore,
) -> None:
    candidates = {candidate.candidate_id: candidate for candidate in pack.candidates}
    if set(records) != set(candidates):
        raise ValueError("flow release requires one qualification run per author candidate")
    for candidate_id, candidate in candidates.items():
        record = records[candidate_id]
        binding = record.header.binding
        if (
            binding.task.task_spec_digest != canonical.task.digest
            or binding.task.instance_digest != canonical.instance.digest
            or binding.task.release_digest != release_candidate.digest
            or binding.environment.environment_spec_digest != environment.digest
        ):
            raise ValueError("qualification run is not bound to the release candidate")
        state = replay(record.header, canonical.task, record.events)
        _verify_record_artifacts(artifact_store, state.artifacts)
        if len(state.candidates) != 1 or state.candidates[0].candidate_id != candidate_id:
            raise ValueError("qualification runs must contain exactly their named candidate")
        if state.candidates[0].digest != flow_candidate_manifest_digest(
            candidate, environment
        ):
            raise ValueError("qualification run did not evaluate the author candidate bytes")
        results = tuple(
            item.result for item in state.stage_results if item.candidate_id == candidate_id
        )
        status = hard_gate_status(canonical.task, results)
        outcomes = {result.outcome.kind for result in results}
        if candidate.expectation is CandidateExpectation.ACCEPTED:
            if (
                status.state is not HardGateState.SUCCEEDED
                or state.terminal_reason is not StopReason.VERIFIER_SUCCESS
                or state.successful_candidate_id != candidate_id
                or {result.stage_id for result in results}
                != {stage.stage_id for stage in pack.stages}
                or outcomes - {OutcomeKind.PASSED, OutcomeKind.PROVED}
            ):
                raise ValueError("feasibility witness did not pass every evaluator stage")
        else:
            infrastructure = {
                OutcomeKind.INFRASTRUCTURE_FAILURE,
                OutcomeKind.LICENSE_UNAVAILABLE,
                OutcomeKind.SECURITY_VIOLATION,
                OutcomeKind.TIMEOUT,
                OutcomeKind.UNKNOWN,
            }
            if (
                status.state is not HardGateState.FAILED
                or outcomes & infrastructure
                or not outcomes
                & {OutcomeKind.CANDIDATE_FAILURE, OutcomeKind.COUNTEREXAMPLE}
                or state.terminal_reason is not StopReason.UNRANKABLE
            ):
                raise ValueError("negative qualification lacks a semantic rejection")


def _verify_record_artifacts(
    artifact_store: ContentAddressedStore,
    artifacts: tuple[ArtifactRecord, ...],
) -> None:
    for artifact in artifacts:
        artifact_store.verify_disclosure(
            artifact.blob,
            artifact_class=artifact.artifact_class,
            sensitivity=artifact.sensitivity,
            visibility=artifact.visibility,
            redistribution=artifact.redistribution,
        )
        if artifact.media_type != ARTIFACT_MANIFEST_MEDIA_TYPE:
            continue
        content = artifact_store.read_bytes(
            artifact.blob,
            maximum_bytes=artifact.blob.size_bytes,
        )
        manifest = ArtifactManifest.model_validate_json(content)
        if (
            canonical_bytes(manifest) != content
            or manifest.artifact_class is not artifact.artifact_class
            or manifest.sensitivity is not artifact.sensitivity
            or manifest.visibility is not artifact.visibility
            or manifest.redistribution is not artifact.redistribution
        ):
            raise ValueError("qualification manifest diverges from its artifact record")
        for entry in manifest.entries:
            artifact_store.verify_disclosure(
                entry.blob,
                artifact_class=artifact.artifact_class,
                sensitivity=artifact.sensitivity,
                visibility=artifact.visibility,
                redistribution=artifact.redistribution,
            )


def _content_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


__all__ = [
    "CanonicalFlowTask",
    "derive_flow_release",
    "derive_flow_release_candidate",
    "flow_candidate_manifest_digest",
    "flow_candidate_resource_id",
    "flow_evaluator_id",
    "flow_evaluator_revision_digest",
    "require_flow_environment",
    "validate_canonical_flow_task",
]
