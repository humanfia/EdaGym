"""Native operation evidence uses private CAS bytes and the existing run journal."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from edagym.config import initialize_config
from edagym.config.model import EdaGymConfig, PrivateConfigSnapshot
from edagym.executors.model import (
    ExecutionResult,
    JobHandle,
    JobState,
    JobStateKind,
    NativeHarnessPlan,
)
from edagym.implementation import framework_implementation_digest
from edagym.participants.harness import HarnessFinal
from edagym.run.artifact_model import ArtifactManifest, ManifestEntry
from edagym.run.artifacts import PRIVATE_ARTIFACT_KEY_PROVIDER_ID, ContentAddressedStore
from edagym.run.journal import RunJournal
from edagym.run.journal_storage import InvalidTransition
from edagym.run.manifest import RunManifest
from edagym.run.model import RUN_EVENT, EventCursor, EventKind, Principal
from edagym.runtime.engine import EngineError, RunEngine
from edagym.specs.common import ArtifactClass, Visibility
from edagym.specs.environment import PROTECTED_RAW_DISCLOSURE, ManagedEncryption
from edagym.specs.harness import NativeCliHarnessBinding, NativeCliKind
from tests.factories import digest, environment_spec, task_instance, task_spec
from tests.test_native_participant import _encode, _events
from tests.test_run_evidence import _confidential_policy


@pytest.fixture
def native_evidence(tmp_path: Path) -> tuple[RunEngine, RunJournal, NativeHarnessPlan, bytes]:
    config = initialize_config(tmp_path / "config.toml", tmp_path / "state")
    config = EdaGymConfig.model_validate(
        {
            **config.model_dump(),
            "credentials": [
                {
                    "credential_id": "provider",
                    "decoder": "codex_api_key_json_v1",
                    "file_path": tmp_path / "credential.json",
                }
            ],
            "providers": [
                {
                    "provider_id": "provider",
                    "credential_reference": "provider",
                    "profile": {
                        "logical_id": "synthetic",
                        "origin": "https://example.invalid",
                        "request_path": "/v1/responses",
                    },
                    "defaults": {
                        "requested_model": "synthetic",
                        "reasoning_effort": "high",
                        "service_tier": "default",
                    },
                }
            ],
            "harnesses": [
                {
                    "kind": "native_cli",
                    "harness_id": "native",
                    "version_label": "synthetic",
                    "cli": "codex_exec",
                    "executable_path": tmp_path / "codex",
                    "provider_id": "provider",
                }
            ],
            "sessions": [{"session_id": "native", "kind": "agent", "harness_id": "native"}],
        }
    )
    snapshot = PrivateConfigSnapshot(config_digest=config.digest, configuration=config)
    policy = _confidential_policy().model_copy(
        update={
            "encryption": ManagedEncryption(
                provider_id=PRIVATE_ARTIFACT_KEY_PROVIDER_ID,
                policy_digest=digest("native-private-policy"),
            )
        }
    )
    environment = environment_spec()
    environment = environment.model_copy(
        update={
            "identity": environment.identity.model_copy(update={"provenance": (snapshot.digest,)}),
            "executor": environment.executor.model_copy(
                update={
                    "implementation_digest": framework_implementation_digest(),
                }
            ),
            "artifact_policy": policy,
        }
    )
    instance = task_instance(task_spec())
    manifest = RunManifest.from_snapshot(
        run_id="native-run",
        task=instance,
        task_spec_digest=instance.identity.task_spec_digest,
        snapshot=snapshot,
        session_id="native",
        participant=environment,
        evaluator=environment,
    )
    engine = RunEngine(config.sites[0].state_root)
    journal = RunJournal.create(engine.runs_root, manifest, snapshot)
    store = ContentAddressedStore.open_private(
        journal.directory / "participant" / "cas", policy=policy
    )
    starter = store.put_bytes(
        b"module dut; endmodule\n", artifact_class=ArtifactClass.CHECKPOINT,
        **PROTECTED_RAW_DISCLOSURE.model_dump(),
    )
    workspace = store.put_manifest(
        ArtifactManifest(
            artifact_class=ArtifactClass.CHECKPOINT,
            entries=(ManifestEntry(path="dut.sv", blob=starter, mode=0o644),),
            **PROTECTED_RAW_DISCLOSURE.model_dump(),
        )
    )
    timestamp = datetime.now(UTC)
    for kind, payload in (
        (EventKind.RUN_PREPARED, {"manifest_digest": manifest.digest}),
        (EventKind.RUN_STARTED, {"workspace": workspace}),
    ):
        journal.append(
            RUN_EVENT.validate_python(
                {
                    "kind": kind,
                    "sequence": len(journal.read()),
                    "event_id": kind.value,
                    "run_id": manifest.run_id,
                    "timestamp": timestamp,
                    "payload": payload,
                }
            )
        )
    raw = _encode(_events(NativeCliKind.CODEX_EXEC))
    source = store.put_bytes(
        raw, artifact_class=ArtifactClass.DIAGNOSTIC, **PROTECTED_RAW_DISCLOSURE.model_dump()
    )
    prompt = store.put_bytes(
        b"Run the synthetic design check.", artifact_class=ArtifactClass.DIAGNOSTIC,
        **PROTECTED_RAW_DISCLOSURE.model_dump(),
    )
    stderr = store.put_bytes(
        b"", artifact_class=ArtifactClass.DIAGNOSTIC, **PROTECTED_RAW_DISCLOSURE.model_dump()
    )
    plan = NativeHarnessPlan(
        invocation_id="native-operation",
        run_id=manifest.digest,
        input_manifest_digest=workspace.semantic_digest,
        prompt=prompt,
        executable_asset_id="native-executable",
        deadline=journal.state().projection.deadline,
        harness=NativeCliHarnessBinding(
            harness_id="native",
            cli=NativeCliKind.CODEX_EXEC,
            cli_version="synthetic",
            wire_protocol=NativeCliKind.CODEX_EXEC.wire_protocol,
            provider_profile_digest=config.providers[0].profile.digest,
            provider_config_digest=digest("native-provider"),
            instruction_digest=digest("instruction"),
            tool_schema_digest=digest("tools"),
            scaffold_digest=digest("scaffold"),
            executable_digest=digest("executable"),
            transport_digest=digest("transport"),
        ),
    )
    handle = JobHandle(
        job_id=plan.invocation_id,
        invocation_digest=plan.digest,
        executor_id=environment.executor.executor_id,
    )
    for kind, payload in (
        (EventKind.OPERATION_PREPARED, {"plan": plan, "input_manifest": workspace}),
        (EventKind.OPERATION_RUNNING, {"operation_id": plan.invocation_id, "handle": handle}),
        (
            EventKind.OPERATION_TERMINAL,
            {
                "operation_id": plan.invocation_id,
                "result": ExecutionResult(
                    state=JobState(handle=handle, state=JobStateKind.COMPLETED, exit_code=0),
                    stdout=source,
                    stderr=stderr,
                ),
            },
        ),
    ):
        journal.append(
            RUN_EVENT.validate_python(
                {
                    "kind": kind,
                    "sequence": len(journal.read()),
                    "event_id": kind.value,
                    "run_id": manifest.run_id,
                    "timestamp": timestamp,
                    "visibility": Visibility.AUTHOR,
                    "payload": payload,
                }
            )
        )
    return engine, journal, plan, raw


def test_native_observations_reopen_from_private_source_without_a_second_record(
    native_evidence: tuple[RunEngine, RunJournal, NativeHarnessPlan, bytes],
) -> None:
    engine, journal, plan, raw = native_evidence
    participant = Principal(principal_id="participant")
    author = Principal(principal_id="author", allowed_visibilities=(Visibility.AUTHOR,))
    with pytest.raises(EngineError, match="author visibility"):
        engine.native_transcript(journal.manifest.run_id, plan.invocation_id, participant)
    visible = engine.stream_run(journal.manifest.run_id, EventCursor(sequence=0), participant)
    assert all(
        event.kind
        not in {
            EventKind.OPERATION_PREPARED,
            EventKind.OPERATION_RUNNING,
            EventKind.OPERATION_TERMINAL,
        }
        for event in visible.events
    )
    reopened = RunEngine(engine.state_root)
    head = journal.record().integrity_digest
    transcript = reopened.native_transcript(journal.manifest.run_id, plan.invocation_id, author)
    terminal = journal.state().operations[0].terminal
    assert terminal is not None
    assert transcript.stdout == raw
    assert transcript.source_digest == terminal.payload.result.stdout.digest
    assert transcript.supported and isinstance(transcript.events[-1], HarnessFinal)
    assert RunJournal.open(journal.directory).record().integrity_digest == head


def test_native_run_replay_refuses_harness_substitution_and_public_facts(
    native_evidence: tuple[RunEngine, RunJournal, NativeHarnessPlan, bytes],
) -> None:
    from edagym.run.journal import replay

    _, journal, plan, _ = native_evidence
    events = journal.read()
    for index in (2, 3, 4):
        changed = (
            *events[:index],
            events[index].model_copy(update={"visibility": Visibility.PUBLIC}),
            *events[index + 1 :],
        )
        with pytest.raises(InvalidTransition, match="private"):
            replay(journal.manifest, changed)
    prepared = RUN_EVENT.validate_python(
        {
            **events[2].model_dump(),
            "payload": {
                **events[2].payload.model_dump(),
                "plan": plan.model_copy(
                    update={
                        "harness": plan.harness.model_copy(
                            update={"harness_id": "another-harness"}
                        ),
                    }
                ),
            },
        }
    )
    with pytest.raises(InvalidTransition, match="bound harness"):
        replay(journal.manifest, (*events[:2], prepared, *events[3:]))
