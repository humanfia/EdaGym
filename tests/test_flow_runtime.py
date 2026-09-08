"""Evidence for canonical, executor-backed EDA-flow task operation."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from edagym.authoring.provider import (
    DerivedTaskDocument,
    DifficultyBinding,
    FlowCandidateInventory,
    FlowCandidateRole,
    OpaqueTaskInstanceReference,
    PrivateAuthoringCapability,
)
from edagym.canonical import canonical_digest
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.local import BrokeredHostExecutor
from edagym.executors.report import CompositeCommandReport
from edagym.flow_tasks.canonical import (
    CanonicalFlowTask,
    derive_flow_release,
    flow_candidate_resource_id,
    flow_evaluator_id,
    flow_evaluator_revision_digest,
)
from edagym.flow_tasks.catalog import (
    FlowTaskCatalog,
    flow_candidate_content_manifest_digest,
)
from edagym.flow_tasks.model import (
    CandidateExpectation,
    CandidateVariant,
    Comparison,
    ContainsRule,
    ExitRule,
    FlowStageDefinition,
    FlowTaskPack,
    RegexNumberRule,
    RuleSource,
    TaskAsset,
    ToolCommand,
    WorkspaceCommand,
)
from edagym.flow_tasks.qualification import qualify_flow_release
from edagym.run.artifact_model import (
    ArtifactManifest,
)
from edagym.run.artifacts import (
    ArtifactStoreError,
    ContentAddressedStore,
)
from edagym.run.trial_journal import replay
from edagym.run.trial_model import (
    ArtifactRecordedEvent,
    EvaluationCompletedEvent,
    RunRecord,
    RunState,
)
from edagym.specs.common import (
    ArtifactClass,
    Capability,
    Redistribution,
    Sensitivity,
    Visibility,
)
from edagym.specs.environment import (
    ArtifactDisclosure,
    AttestedHostToolLocator,
    BrokeredHostToolExecutor,
    EnvironmentSpec,
    ToolBinding,
)
from edagym.specs.release import (
    FlowReleaseQualification,
    GeneratedFile,
    IntegerParameterValue,
    TaskInstance,
    TaskInstanceIdentity,
)
from edagym.specs.task import (
    NOT_APPLICABLE_LIBRARY_DIGEST,
    Aggregation,
    ContractSpec,
    DifficultyAxis,
    EvaluationGraph,
    EvaluatorSpec,
    FlowQualificationSpec,
    GeneratorSpec,
    IntegerDomain,
    MeasurementSpec,
    MeasurementUnit,
    MetricDirection,
    RequirementKind,
    RequirementSpec,
    ResourceLicense,
    ResourceSpec,
    ResourceVisibility,
    StagePurpose,
    StageSpec,
    TaskIdentity,
    TaskSpec,
    WorkspaceInterface,
)
from edagym.task_families.catalog import EDA_FLOW_FAMILIES

from .factories import digest, environment_spec, require_local_containment


@dataclass(frozen=True)
class _SyntheticFlowCatalog:
    pack: FlowTaskPack
    canonical: CanonicalFlowTask
    inventory: tuple[FlowCandidateInventory, ...]

    def task_pack(self, family: str) -> FlowTaskPack:
        if family != self.pack.family:
            raise KeyError(family)
        return self.pack

    def canonical_task(
        self,
        family: str,
        instance_name: str = "base",
    ) -> CanonicalFlowTask:
        if family != self.pack.family or instance_name != "base":
            raise KeyError((family, instance_name))
        return self.canonical

    def family_attestation(self, family: str) -> object:
        if family != self.pack.family:
            raise KeyError(family)
        return SimpleNamespace(flow_candidate_inventory=self.inventory)


def test_flow_qualification_uses_journal_cas_and_composite_executor(
    tmp_path: Path,
) -> None:
    require_local_containment()
    pack = _runtime_pack()
    canonical = _synthetic_provider_canonical(pack)
    environment = _environment_for(pack)
    store = ContentAddressedStore(
        _private_directory(tmp_path / "store"),
        policy=environment.artifact_policy,
    )
    executor = BrokeredHostExecutor(
        executor_id=environment.executor.executor_id,
        tool_paths={"verilator": Path(sys.executable)},
        tool_environments={"verilator": {}},
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=tmp_path / "executor-state",
    )

    qualified = qualify_flow_release(
        pack,
        canonical,
        environment,
        runtime_root=tmp_path / "qualification",
        artifact_store=store,
        executor=executor,
        poll_interval_seconds=0,
    )

    assert isinstance(qualified.release.qualification, FlowReleaseQualification)
    assert set(qualified.records) == {"reference", "semantic_negative"}
    reference = _state(qualified.records["reference"], canonical.task)
    negative = _state(qualified.records["semantic_negative"], canonical.task)
    assert reference.successful_candidate_id == "reference"
    assert reference.stage_results[0].result.outcome.kind.value == "passed"
    assert negative.successful_candidate_id is None
    assert negative.stage_results[0].result.outcome.kind.value == "candidate_failure"
    for candidate in pack.candidates:
        for asset in candidate.assets:
            path = tmp_path / "qualification" / "workspaces" / candidate.candidate_id / asset.path
            assert path.stat().st_mode & 0o777 == 0o600
    for record in qualified.records.values():
        assert any(isinstance(event, EvaluationCompletedEvent) for event in record.events)
        assert sum(isinstance(event, ArtifactRecordedEvent) for event in record.events) >= 4
        assert record.integrity_digest.startswith("sha256:")
        candidate_record = next(
            event.payload.record
            for event in record.events
            if isinstance(event, ArtifactRecordedEvent)
            and event.payload.record.artifact_class is ArtifactClass.CANDIDATE
        )
        candidate_manifest = ArtifactManifest.model_validate_json(
            store.read_bytes(
                candidate_record.blob,
                maximum_bytes=candidate_record.blob.size_bytes,
            )
        )
        assert tuple(entry.path for entry in candidate_manifest.entries) == (pack.submission_paths)
    command_report_record = next(
        event.payload.record
        for event in qualified.records["reference"].events
        if isinstance(event, ArtifactRecordedEvent)
        and event.payload.record.media_type == "application/json"
    )
    command_report = CompositeCommandReport.model_validate_json(
        store.read_bytes(
            command_report_record.blob,
            maximum_bytes=command_report_record.blob.size_bytes,
        )
    )
    assert len(command_report.commands) == 2
    assert len({item.identity_digest for item in command_report.commands}) == 2

    orphan_store = ContentAddressedStore(
        _private_directory(tmp_path / "orphan-store"),
        policy=environment.artifact_policy,
    )
    with pytest.raises(ArtifactStoreError):
        derive_flow_release(
            pack,
            canonical,
            environment,
            qualified.records,
            orphan_store,
        )


def _runtime_pack() -> FlowTaskPack:
    family = next(item for item in EDA_FLOW_FAMILIES if item.family == "rtl_verification_repair")
    prepare = """\
from pathlib import Path

Path("runner.py").chmod(0o700)
"""
    runner = """\
#!/usr/bin/python3
from pathlib import Path

candidate = Path("candidate.txt").read_text(encoding="utf-8").strip()
if candidate != "accepted-semantics":
    raise SystemExit(3)
Path("measurement.rpt").write_text("SCORE 2\\n", encoding="utf-8")
print("EDAGYM_TEST_PASS")
"""
    return FlowTaskPack(
        family=family.family,
        semantic_definition_digest=family.digest,
        requirements=("semantic_contract",),
        candidates=(
            CandidateVariant(
                candidate_id="reference",
                expectation=CandidateExpectation.ACCEPTED,
                assets=(TaskAsset(path="candidate.txt", content="accepted-semantics\n"),),
            ),
            CandidateVariant(
                candidate_id="semantic_negative",
                expectation=CandidateExpectation.REJECTED,
                assets=(TaskAsset(path="candidate.txt", content="wrong-semantics\n"),),
            ),
        ),
        stages=(
            FlowStageDefinition(
                stage_id="semantic_gate",
                capability=Capability.RTL_SIMULATION,
                purpose=StagePurpose.HARD_GATE,
                requirement_ids=("semantic_contract",),
                assets=(
                    TaskAsset(path="prepare.py", content=prepare),
                    TaskAsset(path="runner.py", content=runner),
                ),
                commands=(
                    ToolCommand(
                        tool_id="verilator",
                        capability=Capability.RTL_SIMULATION,
                        arguments=("prepare.py",),
                    ),
                    WorkspaceCommand(executable="runner.py"),
                ),
                rules=(
                    ExitRule(),
                    ContainsRule(
                        source=RuleSource.STDOUT,
                        token="EDAGYM_TEST_PASS",
                    ),
                    RegexNumberRule(
                        source=RuleSource.FILE,
                        path="measurement.rpt",
                        pattern=r"SCORE\s+([0-9]+)",
                        comparison=Comparison.GREATER_EQUAL,
                        threshold="1",
                        measurement_id="score",
                        measurement_unit=MeasurementUnit.DIMENSIONLESS,
                        metric_direction=MetricDirection.MAXIMIZE,
                        corner="not_applicable",
                        mode="test",
                    ),
                ),
                output_paths=("measurement.rpt",),
            ),
        ),
    )


def _synthetic_provider_canonical(pack: FlowTaskPack) -> CanonicalFlowTask:
    """Build one explicit provider document for the synthetic runtime-only pack."""

    family = next(item for item in EDA_FLOW_FAMILIES if item.family == pack.family)
    stage = pack.stages[0]
    witness = next(
        candidate
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.ACCEPTED
    )
    negative = next(
        candidate
        for candidate in pack.candidates
        if candidate.expectation is CandidateExpectation.REJECTED
    )
    generator_resource_id = "synthetic_generator"
    behavior_resource_id = "synthetic_behavior"
    authoring_resource_id = "synthetic_authoring_source"
    evaluator_resource_id = "synthetic_evaluator"
    witness_resource_id = flow_candidate_resource_id(witness)
    negative_resource_id = flow_candidate_resource_id(negative)
    resources = (
        ResourceSpec(
            resource_id=generator_resource_id,
            content_digest=digest("synthetic-flow-generator"),
            media_type="application/json",
            path="authoring/generator.json",
        ),
        ResourceSpec(
            resource_id=behavior_resource_id,
            content_digest=digest("synthetic-flow-behavior"),
            media_type="text/plain",
            path="public/behavior.txt",
        ),
        ResourceSpec(
            resource_id=authoring_resource_id,
            content_digest=pack.digest,
            media_type="application/json",
            path="authoring/flow-task-pack.json",
        ),
        ResourceSpec(
            resource_id=evaluator_resource_id,
            content_digest=digest("synthetic-flow-evaluator"),
            media_type="application/json",
            path="verifier/semantic-gate.json",
        ),
        ResourceSpec(
            resource_id=witness_resource_id,
            content_digest=digest("synthetic-flow-witness"),
            media_type="application/json",
            path="authoring/witness.json",
        ),
        ResourceSpec(
            resource_id=negative_resource_id,
            content_digest=digest("synthetic-flow-negative"),
            media_type="application/json",
            path="authoring/negative.json",
        ),
    )
    task = TaskSpec(
        identity=TaskIdentity(
            family=pack.family,
            authoring_revision=pack.authoring_revision,
        ),
        interface=WorkspaceInterface(submission_paths=pack.submission_paths),
        generator=GeneratorSpec(
            implementation_resource=generator_resource_id,
            implementation_digest=resources[0].content_digest,
            seed_bits=128,
            parameters=tuple(
                IntegerDomain(
                    parameter_id=axis.axis_id,
                    default=axis.base_value,
                    minimum=min(axis.base_value, axis.advanced_value),
                    maximum=max(axis.base_value, axis.advanced_value),
                )
                for axis in family.difficulty_axes
            ),
        ),
        contract=ContractSpec(
            public_behavior_resource=behavior_resource_id,
            requirements=tuple(
                RequirementSpec(
                    requirement_id=requirement_id,
                    kind=RequirementKind.BEHAVIORAL,
                    description=family.semantic_contract,
                )
                for requirement_id in pack.requirements
            ),
        ),
        resources=resources,
        visibility=tuple(
            ResourceVisibility(
                resource_id=resource.resource_id,
                visibility=(
                    Visibility.PUBLIC
                    if resource.resource_id == behavior_resource_id
                    else Visibility.VERIFIER
                    if resource.resource_id == evaluator_resource_id
                    else Visibility.AUTHOR
                ),
                sensitivity=(
                    Sensitivity.PUBLIC
                    if resource.resource_id == behavior_resource_id
                    else Sensitivity.INTERNAL
                ),
            )
            for resource in resources
        ),
        evaluation=EvaluationGraph(
            evaluators=(
                EvaluatorSpec(
                    evaluator_id=flow_evaluator_id(stage.stage_id),
                    capability=stage.capability,
                    implementation_resource=evaluator_resource_id,
                    revision_digest=flow_evaluator_revision_digest(stage),
                ),
            ),
            stages=(
                StageSpec(
                    stage_id=stage.stage_id,
                    evaluator_id=flow_evaluator_id(stage.stage_id),
                    purpose=stage.purpose,
                    requirement_ids=stage.requirement_ids,
                ),
            ),
        ),
        measurements=(
            MeasurementSpec(
                measurement_id="score",
                producer_stage_id=stage.stage_id,
                unit=MeasurementUnit.DIMENSIONLESS,
                library_id="not_applicable",
                library_digest=NOT_APPLICABLE_LIBRARY_DIGEST,
                corner="not_applicable",
                mode="test",
                direction=MetricDirection.MAXIMIZE,
                repetitions=1,
                aggregation=Aggregation.MEDIAN,
                valid_minimum=Decimal(0),
            ),
        ),
        difficulty_axes=tuple(
            DifficultyAxis(axis_id=axis.axis_id, parameter_id=axis.axis_id)
            for axis in family.difficulty_axes
        ),
        qualification=FlowQualificationSpec(
            authoring_source_resource=authoring_resource_id,
            feasibility_witness_resource=witness_resource_id,
            negative_candidate_resources=(negative_resource_id,),
        ),
        licensing=tuple(
            ResourceLicense(
                resource_id=resource.resource_id,
                spdx_expression="Apache-2.0",
                redistribution=Redistribution.ALLOWED,
                provenance=("synthetic-test",),
            )
            for resource in resources
        ),
    )
    generated_file = GeneratedFile(
        path="verifier/semantic-gate.json",
        content_digest=resources[3].content_digest,
        media_type="application/json",
        source_resource_ids=(evaluator_resource_id,),
        visibility=Visibility.VERIFIER,
        sensitivity=Sensitivity.INTERNAL,
        redistribution=Redistribution.ALLOWED,
    )
    instance = TaskInstance(
        identity=TaskInstanceIdentity(
            task_family=pack.family,
            authoring_revision=pack.authoring_revision,
            task_spec_digest=task.digest,
            generator_digest=task.generator.implementation_digest,
            seed="0" * 32,
            parameters=tuple(
                IntegerParameterValue(
                    parameter_id=axis.axis_id,
                    value=axis.base_value,
                )
                for axis in family.difficulty_axes
            ),
        ),
        generated_files=(generated_file,),
    )
    difficulty = tuple(
        DifficultyBinding(parameter_id=axis.axis_id, value=axis.base_value)
        for axis in family.difficulty_axes
    )
    reference = OpaqueTaskInstanceReference(
        provider_id="synthetic_flow_provider",
        capability=PrivateAuthoringCapability.EDA_FLOW_CATALOG,
        family=pack.family,
        instance_name="base",
        public_metadata_digest=family.digest,
        public_derivation_scope_digest=canonical_digest(
            {
                "difficulty": difficulty,
                "family": pack.family,
                "instance_name": "base",
            },
            domain="private-derivation-public-scope-v1",
        ),
        task_spec_digest=task.digest,
        task_instance_digest=instance.digest,
        participant_bundle_digest=digest("synthetic-participant-bundle"),
        verifier_bundle_digest=digest("synthetic-verifier-bundle"),
        reference_id=digest("synthetic-flow-instance-reference"),
    )
    document = DerivedTaskDocument(
        instance_reference=reference,
        task=task,
        instance=instance,
    )
    return CanonicalFlowTask(
        task=document.task,
        instance=document.instance,
        instance_reference=document.instance_reference,
    )


def _synthetic_flow_catalog(
    pack: FlowTaskPack,
    canonical: CanonicalFlowTask,
) -> FlowTaskCatalog:
    inventory = tuple(
        FlowCandidateInventory(
            candidate_id=candidate.candidate_id,
            candidate_resource_id=flow_candidate_resource_id(candidate),
            role=(
                FlowCandidateRole.FEASIBILITY_WITNESS
                if candidate.expectation is CandidateExpectation.ACCEPTED
                else FlowCandidateRole.SEMANTIC_NEGATIVE
            ),
            content_manifest_digest=flow_candidate_content_manifest_digest(candidate),
        )
        for candidate in pack.candidates
    )
    return cast(
        FlowTaskCatalog,
        _SyntheticFlowCatalog(pack=pack, canonical=canonical, inventory=inventory),
    )


def _environment_for(pack: FlowTaskPack) -> EnvironmentSpec:
    base = environment_spec()
    visible_evidence = ArtifactDisclosure(
        sensitivity=Sensitivity.INTERNAL,
        visibility=Visibility.PARTICIPANT,
        redistribution=Redistribution.RESTRICTED,
    )
    artifact_policy = base.artifact_policy.model_copy(
        update={
            "rules": tuple(
                rule.model_copy(update={"allowed_disclosures": (visible_evidence,)})
                if rule.artifact_class in {ArtifactClass.DIAGNOSTIC, ArtifactClass.EVIDENCE}
                else rule
                for rule in base.artifact_policy.rules
            )
        }
    )
    commands = {
        (command.capability, command.tool_id)
        for stage in pack.stages
        for command in stage.commands
        if isinstance(command, ToolCommand)
    }
    tools = tuple(
        ToolBinding(
            capability=capability,
            tool_id=tool_id,
            tool_version="1.0",
            driver_id=f"{tool_id}_driver",
            driver_digest=digest(f"driver-{tool_id}"),
            locator=AttestedHostToolLocator(
                executable=(Path(sys.executable).name if len(commands) == 1 else tool_id),
                deployment_attestation_digest=digest(f"deployment-{tool_id}"),
            ),
        )
        for capability, tool_id in sorted(commands, key=lambda item: item[0].value)
    )
    return EnvironmentSpec.model_validate(
        {
            **base.model_dump(mode="python"),
            "executor": BrokeredHostToolExecutor(
                executor_id="flow_broker",
                implementation_digest=digest("flow-broker-executor"),
                broker_id="flow_broker",
                broker_digest=digest("flow-broker"),
                participant_image_digest=digest("flow-participant-image"),
            ),
            "artifact_policy": artifact_policy,
            "tool_bindings": tools,
        }
    )


def _state(record: RunRecord, task: TaskSpec) -> RunState:
    return replay(record.header, task, record.events)


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path
