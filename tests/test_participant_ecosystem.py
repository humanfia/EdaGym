"""Evidence for isolated calibration and journal-derived session boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
import traceback
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.assets import AssetValidationError
from edagym.participants import (
    CalibrationCommandChannel,
    CalibrationHarnessSpec,
    CommandAgentAdapter,
    ParticipantActionProjection,
    ParticipantAdapterError,
    ParticipantController,
    ParticipantFailureKind,
    ParticipantIntent,
    ParticipantProjectedEvent,
    ParticipantProjectionRegistry,
    ParticipantView,
    participant_asset_digest,
)
from edagym.resolution import resolve_run
from edagym.run.journal import RunJournal
from edagym.run.model import (
    ProducerKind,
    RunHeader,
    RunStartedEvent,
    RunStartedPayload,
)
from edagym.specs.common import Visibility
from edagym.specs.environment import (
    AssetBinding,
    EnvironmentSpec,
    FilesystemScope,
    ImageToolLocator,
    ReadonlyAssetMount,
    RootlessLocalExecutor,
)
from edagym.specs.session import ActorKind, FixedWriter, HarnessActor, SessionSpec
from tests.factories import (
    digest,
    environment_spec,
    release_manifest,
    session_spec,
    task_instance,
    task_spec,
)

_PODMAN = Path("/usr/bin/podman")
_ALPINE_DIGEST = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
_ALPINE_REFERENCE = f"docker.io/library/alpine@{_ALPINE_DIGEST}"


def _runtime_digest() -> str:
    if not _PODMAN.exists():
        return digest("unavailable-podman")
    content = _PODMAN.read_bytes()
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _harness(
    scaffold_digest: str,
    *,
    executable: str = "/bin/echo",
    arguments: tuple[str, ...] = (),
    maximum_turn_seconds: int = 2,
    maximum_response_bytes: int = 1024,
) -> CalibrationHarnessSpec:
    return CalibrationHarnessSpec(
        harness_id="container_cli",
        image_digest=_ALPINE_DIGEST,
        runtime_executable_digest=_runtime_digest(),
        executable=executable,
        arguments=arguments,
        scaffold_asset_id="calibration_scaffold",
        scaffold_digest=scaffold_digest,
        requested_model_route="external-route",
        maximum_turn_seconds=maximum_turn_seconds,
        maximum_response_bytes=maximum_response_bytes,
    )


def _environment(harness: CalibrationHarnessSpec) -> EnvironmentSpec:
    base = environment_spec()
    executor = base.executor
    assert isinstance(executor, RootlessLocalExecutor)
    document = base.model_dump(mode="json")
    document["executor"] = {
        **executor.model_dump(mode="json"),
        "image_digest": harness.image_digest,
    }
    tool_bindings = []
    for binding in base.tool_bindings:
        locator = binding.locator
        assert isinstance(locator, ImageToolLocator)
        tool_bindings.append(
            binding.model_copy(
                update={
                    "locator": locator.model_copy(update={"image_digest": harness.image_digest})
                }
            )
        )
    document["tool_bindings"] = tool_bindings
    document["assets"] = [
        AssetBinding(
            asset_id=harness.scaffold_asset_id,
            restricted_digest=harness.scaffold_digest,
            allowed_scopes=(FilesystemScope.PARTICIPANT,),
        ).model_dump(mode="json")
    ]
    document["filesystem"] = {
        **base.filesystem.model_dump(mode="json"),
        "readonly_assets": [
            ReadonlyAssetMount(
                asset_id=harness.scaffold_asset_id,
                scope=FilesystemScope.PARTICIPANT,
                target="/scaffold",
            ).model_dump(mode="json")
        ],
    }
    return EnvironmentSpec.model_validate(document)


def _journal(
    tmp_path: Path,
    harness: CalibrationHarnessSpec,
    *,
    environment: EnvironmentSpec | None = None,
) -> tuple[RunJournal, EnvironmentSpec, SessionSpec]:
    task = task_spec()
    bound_environment = _environment(harness) if environment is None else environment
    instance = task_instance(task)
    release = release_manifest(task, instance, bound_environment)
    base = session_spec()
    session = SessionSpec(
        session_id="container_cli_session",
        mode=base.mode,
        actors=(
            HarnessActor(
                actor_id="solver",
                harness_id=harness.harness_id,
                harness_digest=harness.digest,
                scaffold_digest=harness.scaffold_digest,
                requested_model_route=harness.requested_model_route,
            ),
        ),
        writer=FixedWriter(writer="solver"),
        feedback=base.feedback,
        recovery=base.recovery,
        resources=base.resources,
        model_budget=base.model_budget,
    )
    plan = resolve_run(
        task=task,
        instance=instance,
        release=release,
        environment=bound_environment,
        session=session,
        trial_key="container-cli-0001",
    )
    journal = RunJournal.create(tmp_path / "journal", RunHeader.from_binding(plan.binding), task)
    journal.append(
        RunStartedEvent(
            run_id=journal.header.run_id,
            sequence=0,
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            producer=ProducerKind.CONTROLLER,
            visibility=Visibility.PUBLIC,
            payload=RunStartedPayload(binding_digest=plan.binding.digest),
        )
    )
    return journal, bound_environment, session


def _scaffold(tmp_path: Path) -> Path:
    path = tmp_path / "scaffold.txt"
    path.write_text("bounded calibration scaffold\n", encoding="ascii")
    path.chmod(0o600)
    return path


def _channel(
    tmp_path: Path,
    harness: CalibrationHarnessSpec,
    scaffold: Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> tuple[CalibrationCommandChannel, RunJournal, EnvironmentSpec, SessionSpec]:
    journal, environment, session = _journal(tmp_path, harness)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    store = tmp_path / "cas"
    store.mkdir(mode=0o700)
    channel = CalibrationCommandChannel(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session,
        harness=harness,
        podman_path=_PODMAN,
        image_reference=_ALPINE_REFERENCE,
        workspace=workspace,
        artifact_store_root=store,
        participant_assets={harness.scaffold_asset_id: scaffold},
        asset_source_policy=load_system_asset_source_policy(),
        clock=clock,
    )
    return channel, journal, environment, session


def _view(journal: RunJournal) -> ParticipantView:
    return ParticipantView(
        run_id=journal.header.run_id,
        task_family="stream_guard",
        authoring_revision=1,
        actor_id="solver",
    )


def _require_probe_image() -> None:
    if not _PODMAN.exists():
        pytest.skip("Podman is unavailable")
    present = subprocess.run(
        (os.fspath(_PODMAN), "image", "exists", _ALPINE_REFERENCE),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if present.returncode != 0:
        pytest.skip("the pinned local probe image is unavailable")


def test_calibration_channel_binds_content_runtime_and_hermetic_entrypoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_probe_image()
    monkeypatch.setenv("HOST_SECRET_CANARY", "must-not-enter-launcher")
    intent_payload = json.dumps(
        {
            "kind": "interaction",
            "interaction_id": "isolated_turn",
            "direction": "participant_output",
            "artifact_refs": [],
        },
        separators=(",", ":"),
    )
    scaffold = _scaffold(tmp_path)
    harness = _harness(participant_asset_digest(scaffold), arguments=(intent_payload,))
    channel, journal, _, _ = _channel(tmp_path, harness, scaffold)
    adapter = CommandAgentAdapter(
        actor_id="solver",
        channel=channel,
        maximum_response_bytes=harness.maximum_response_bytes,
    )

    intent = adapter.next_intent(_view(journal))

    assert intent.kind == "interaction"
    assert adapter.actor_kinds == {"solver": ActorKind.HARNESS}
    channel.close()
    with pytest.raises(ParticipantAdapterError) as cancelled:
        adapter.next_intent(_view(journal))
    assert cancelled.value.kind is ParticipantFailureKind.COMMAND_CANCELLED


def test_calibration_boundary_rejects_free_environment_and_mutable_identity(
    tmp_path: Path,
) -> None:
    scaffold = _scaffold(tmp_path)
    scaffold_digest = participant_asset_digest(scaffold)
    document = {
        **_harness(scaffold_digest).model_dump(mode="json"),
        "environment": {"API_TOKEN": "credential-canary"},
    }
    with pytest.raises(ValidationError) as invalid_environment:
        CalibrationHarnessSpec.model_validate(document)
    assert "credential-canary" not in str(invalid_environment.value)

    with pytest.raises(ValueError, match="absolute container path"):
        CalibrationHarnessSpec.model_validate(
            {**_harness(scaffold_digest).model_dump(mode="json"), "executable": "wrapper"}
        )
    with pytest.raises(ValueError, match="argv-only"):
        CalibrationHarnessSpec.model_validate(
            {**_harness(scaffold_digest).model_dump(mode="json"), "executable": "/bin/sh"}
        )

    if not _PODMAN.exists():
        return
    bound = _harness(scaffold_digest)
    journal, environment, session = _journal(tmp_path, bound)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    store = tmp_path / "cas"
    store.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="actor binding"):
        CalibrationCommandChannel(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            harness=bound.model_copy(update={"arguments": ("--changed",)}),
            podman_path=_PODMAN,
            image_reference=_ALPINE_REFERENCE,
            workspace=workspace,
            artifact_store_root=store,
            participant_assets={bound.scaffold_asset_id: scaffold},
            asset_source_policy=load_system_asset_source_policy(),
        )

    untrusted_launcher = tmp_path / "podman"
    untrusted_launcher.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    untrusted_launcher.chmod(0o700)
    with pytest.raises(ValueError, match="root-owned"):
        CalibrationCommandChannel(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            harness=bound,
            podman_path=untrusted_launcher,
            image_reference=_ALPINE_REFERENCE,
            workspace=workspace,
            artifact_store_root=store,
            participant_assets={bound.scaffold_asset_id: scaffold},
            asset_source_policy=load_system_asset_source_policy(),
        )

    with pytest.raises(AssetValidationError):
        CalibrationCommandChannel(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            harness=bound,
            podman_path=_PODMAN,
            image_reference=_ALPINE_REFERENCE,
            workspace=store,
            artifact_store_root=store,
            participant_assets={bound.scaffold_asset_id: scaffold},
            asset_source_policy=load_system_asset_source_policy(),
        )


def test_calibration_rejects_overlapping_asset_sources(tmp_path: Path) -> None:
    if not _PODMAN.exists():
        pytest.skip("Podman is unavailable")
    scaffold = _scaffold(tmp_path)
    harness = _harness(participant_asset_digest(scaffold))
    base_environment = _environment(harness)
    document = base_environment.model_dump(mode="python")
    document["assets"] = (
        *base_environment.assets,
        AssetBinding(
            asset_id="duplicate_scaffold",
            restricted_digest=harness.scaffold_digest,
            allowed_scopes=(FilesystemScope.PARTICIPANT,),
        ),
    )
    document["filesystem"] = base_environment.filesystem.model_copy(
        update={
            "readonly_assets": (
                *base_environment.filesystem.readonly_assets,
                ReadonlyAssetMount(
                    asset_id="duplicate_scaffold",
                    scope=FilesystemScope.PARTICIPANT,
                    target="/duplicate-scaffold",
                ),
            )
        }
    )
    environment = EnvironmentSpec.model_validate(document)
    journal, _, session = _journal(tmp_path, harness, environment=environment)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    store = tmp_path / "cas"
    store.mkdir(mode=0o700)

    with pytest.raises(AssetValidationError):
        CalibrationCommandChannel(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            harness=harness,
            podman_path=_PODMAN,
            image_reference=_ALPINE_REFERENCE,
            workspace=workspace,
            artifact_store_root=store,
            participant_assets={
                harness.scaffold_asset_id: scaffold,
                "duplicate_scaffold": scaffold,
            },
            asset_source_policy=load_system_asset_source_policy(),
        )


def test_directory_asset_manifest_detects_content_and_structure_changes(tmp_path: Path) -> None:
    asset = tmp_path / "asset"
    asset.mkdir(mode=0o700)
    nested = asset / "nested"
    nested.mkdir(mode=0o700)
    payload = nested / "model.dat"
    payload.write_text("first\n", encoding="ascii")
    payload.chmod(0o600)
    original = participant_asset_digest(asset)

    payload.write_text("second\n", encoding="ascii")
    changed_content = participant_asset_digest(asset)
    empty = asset / "empty"
    empty.mkdir(mode=0o700)
    changed_structure = participant_asset_digest(asset)

    assert len({original, changed_content, changed_structure}) == 3
    (asset / "link").symlink_to(payload)
    with pytest.raises(ValueError, match="links or special files"):
        participant_asset_digest(asset)


@pytest.mark.parametrize(
    ("executable", "arguments", "response_bound", "failure"),
    (
        ("/bin/false", (), 1024, ParticipantFailureKind.COMMAND_EXIT),
        ("/usr/bin/yes", (), 32, ParticipantFailureKind.RESPONSE_BOUND),
        ("/bin/sleep", ("10",), 1024, ParticipantFailureKind.COMMAND_TIMEOUT),
    ),
)
def test_calibration_channel_preserves_sanitized_bounded_failures(
    tmp_path: Path,
    executable: str,
    arguments: tuple[str, ...],
    response_bound: int,
    failure: ParticipantFailureKind,
) -> None:
    _require_probe_image()
    scaffold = _scaffold(tmp_path)
    harness = _harness(
        participant_asset_digest(scaffold),
        executable=executable,
        arguments=arguments,
        maximum_turn_seconds=1,
        maximum_response_bytes=response_bound,
    )
    channel, journal, _, _ = _channel(tmp_path, harness, scaffold)
    payload = _view(journal).model_dump_json().encode()

    with pytest.raises(ParticipantAdapterError) as captured:
        channel.exchange(payload, maximum_response_bytes=response_bound)

    channel.close()
    del payload
    rendered = "".join(
        traceback.TracebackException.from_exception(
            captured.value,
            capture_locals=True,
        ).format()
    )
    assert "y\ny\ny\ny" not in rendered
    assert captured.value.kind is failure
    assert captured.value.__context__ is None


def test_calibration_channel_revalidates_assets_before_launch(tmp_path: Path) -> None:
    if not _PODMAN.exists():
        pytest.skip("Podman is unavailable")
    scaffold = _scaffold(tmp_path)
    harness = _harness(participant_asset_digest(scaffold))
    channel, journal, _, _ = _channel(tmp_path, harness, scaffold)
    scaffold.write_text("changed after binding\n", encoding="ascii")

    with pytest.raises(ParticipantAdapterError) as changed:
        channel.exchange(
            _view(journal).model_dump_json().encode(),
            maximum_response_bytes=harness.maximum_response_bytes,
        )

    assert changed.value.kind is ParticipantFailureKind.CHANNEL_FAILURE
    channel.close()


def test_calibration_workspace_identity_and_lifecycle_owner_are_exclusive(
    tmp_path: Path,
) -> None:
    if not _PODMAN.exists():
        pytest.skip("Podman is unavailable")
    scaffold = _scaffold(tmp_path)
    harness = _harness(participant_asset_digest(scaffold))
    channel, journal, environment, session = _channel(tmp_path, harness, scaffold)
    workspace = tmp_path / "workspace"
    store = tmp_path / "cas"
    with pytest.raises(ValueError, match="already owns"):
        CalibrationCommandChannel(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            harness=harness,
            podman_path=_PODMAN,
            image_reference=_ALPINE_REFERENCE,
            workspace=workspace,
            artifact_store_root=store,
            participant_assets={harness.scaffold_asset_id: scaffold},
            asset_source_policy=load_system_asset_source_policy(),
        )

    original = tmp_path / "original-workspace"
    workspace.rename(original)
    workspace.mkdir(mode=0o700)
    with pytest.raises(ParticipantAdapterError) as replaced:
        channel.exchange(
            _view(journal).model_dump_json().encode(),
            maximum_response_bytes=harness.maximum_response_bytes,
        )
    assert replaced.value.kind is ParticipantFailureKind.CHANNEL_FAILURE
    channel.close()


def test_calibration_channel_recovers_a_crash_owned_container(tmp_path: Path) -> None:
    _require_probe_image()
    scaffold = _scaffold(tmp_path)
    harness = _harness(
        participant_asset_digest(scaffold),
        executable="/bin/sleep",
        arguments=("30",),
        maximum_turn_seconds=30,
    )
    journal, environment, session = _journal(tmp_path, harness)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    store = tmp_path / "cas"
    store.mkdir(mode=0o700)
    owner_path = journal.directory / "participant-runtime" / "active-container.json"
    child = os.fork()
    if child == 0:
        try:
            channel = CalibrationCommandChannel(
                actor_id="solver",
                journal=journal,
                environment=environment,
                session=session,
                harness=harness,
                podman_path=_PODMAN,
                image_reference=_ALPINE_REFERENCE,
                workspace=workspace,
                artifact_store_root=store,
                participant_assets={harness.scaffold_asset_id: scaffold},
                asset_source_policy=load_system_asset_source_policy(),
            )
            channel.exchange(
                _view(journal).model_dump_json().encode(),
                maximum_response_bytes=harness.maximum_response_bytes,
            )
        finally:
            os._exit(1)

    container_name: str | None = None
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if owner_path.exists():
                document = json.loads(owner_path.read_text(encoding="ascii"))
                candidate = document.get("container_name")
                if isinstance(candidate, str) and _container_exists(candidate):
                    container_name = candidate
                    break
            time.sleep(0.05)
        assert container_name is not None

        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        child = 0
        assert owner_path.exists()
        assert _container_exists(container_name)

        recovered = CalibrationCommandChannel(
            actor_id="solver",
            journal=journal,
            environment=environment,
            session=session,
            harness=harness,
            podman_path=_PODMAN,
            image_reference=_ALPINE_REFERENCE,
            workspace=workspace,
            artifact_store_root=store,
            participant_assets={harness.scaffold_asset_id: scaffold},
            asset_source_policy=load_system_asset_source_policy(),
        )
        assert not owner_path.exists()
        assert not _container_exists(container_name)
        recovered.close()
    finally:
        if child:
            with suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        if container_name is not None:
            subprocess.run(
                (os.fspath(_PODMAN), "rm", "--force", "--ignore", container_name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


def test_calibration_channel_enforces_remaining_run_wall_budget(tmp_path: Path) -> None:
    if not _PODMAN.exists():
        pytest.skip("Podman is unavailable")
    scaffold = _scaffold(tmp_path)
    harness = _harness(participant_asset_digest(scaffold))
    expired = datetime.max.replace(tzinfo=UTC)
    channel, journal, _, _ = _channel(
        tmp_path,
        harness,
        scaffold,
        clock=lambda: expired,
    )

    with pytest.raises(ParticipantAdapterError) as exhausted:
        channel.exchange(
            _view(journal).model_dump_json().encode(),
            maximum_response_bytes=harness.maximum_response_bytes,
        )

    assert exhausted.value.kind is ParticipantFailureKind.COMMAND_TIMEOUT
    channel.close()


def test_rootless_calibration_enforces_bound_file_size(tmp_path: Path) -> None:
    _require_probe_image()
    scaffold = _scaffold(tmp_path)
    harness = _harness(
        participant_asset_digest(scaffold),
        executable="/bin/dd",
        arguments=("if=/dev/zero", "of=oversize.bin", "bs=4096", "count=1"),
    )
    base_environment = _environment(harness)
    environment = EnvironmentSpec.model_validate(
        {
            **base_environment.model_dump(mode="python"),
            "resources": base_environment.resources.model_copy(update={"disk_bytes": 1024}),
        }
    )
    journal, _, session = _journal(tmp_path, harness, environment=environment)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    store = tmp_path / "cas"
    store.mkdir(mode=0o700)
    channel = CalibrationCommandChannel(
        actor_id="solver",
        journal=journal,
        environment=environment,
        session=session,
        harness=harness,
        podman_path=_PODMAN,
        image_reference=_ALPINE_REFERENCE,
        workspace=workspace,
        artifact_store_root=store,
        participant_assets={harness.scaffold_asset_id: scaffold},
        asset_source_policy=load_system_asset_source_policy(),
    )

    with pytest.raises(ParticipantAdapterError) as captured:
        channel.exchange(
            _view(journal).model_dump_json().encode(),
            maximum_response_bytes=harness.maximum_response_bytes,
        )

    channel.close()
    assert captured.value.kind is ParticipantFailureKind.COMMAND_EXIT
    assert (workspace / "oversize.bin").stat().st_size <= environment.resources.disk_bytes


def test_rootless_calibration_does_not_inherit_host_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_probe_image()
    monkeypatch.setenv("HOST_SECRET_CANARY", "must-not-enter-container")
    monkeypatch.setenv("LD_PRELOAD", "must-not-enter-container")
    scaffold = _scaffold(tmp_path)
    harness = _harness(
        participant_asset_digest(scaffold),
        executable="/usr/bin/env",
        maximum_response_bytes=4096,
    )
    channel, journal, _, _ = _channel(tmp_path, harness, scaffold)

    output = channel.exchange(
        _view(journal).model_dump_json().encode(),
        maximum_response_bytes=harness.maximum_response_bytes,
    )

    assert b"HOST_SECRET_CANARY" not in output
    assert b"must-not-enter-container" not in output
    assert b"PATH=/usr/local/bin:/usr/bin:/bin" in output
    assert b"LD_PRELOAD=" in output
    channel.close()


def test_session_projection_can_only_drive_journal_owned_views(tmp_path: Path) -> None:
    scaffold = _scaffold(tmp_path)
    harness = _harness(participant_asset_digest(scaffold))
    journal, _, session = _journal(tmp_path, harness)
    adapter = _IntentAdapter()
    controller = ParticipantController(
        journal,
        adapter,
        session=session,
        snapshot_candidate=lambda intent: (_ for _ in ()).throw(
            AssertionError(intent.candidate_id)
        ),
    )
    registry = ParticipantProjectionRegistry()
    projection = registry.open(controller)

    events = tuple(projection.stream_once())

    assert len(events) == 1
    assert isinstance(events[0], ParticipantProjectedEvent)
    assert isinstance(events[0].result, ParticipantActionProjection)
    assert events[0].result.run_id == journal.header.run_id
    assert events[0].result.next_sequence == 2
    assert adapter.last_view == _view(journal)
    assert adapter.calls == 1
    with pytest.raises(ValueError, match="only one session"):
        registry.open(controller)
    projection.close()
    with pytest.raises(ParticipantAdapterError) as closed:
        projection.act_once()
    assert closed.value.kind is ParticipantFailureKind.COMMAND_CANCELLED


class _IntentAdapter:
    def __init__(self) -> None:
        self.calls = 0
        self.last_view: ParticipantView | None = None

    @property
    def actor_kinds(self) -> Mapping[str, ActorKind]:
        return {"solver": ActorKind.HARNESS}

    def next_intent(self, view: ParticipantView) -> ParticipantIntent:
        self.calls += 1
        self.last_view = view
        return CommandAgentAdapter(
            actor_id="solver",
            channel=_IntentChannel(),
        ).next_intent(view)


class _IntentChannel:
    def exchange(self, view: bytes, *, maximum_response_bytes: int) -> bytes:
        del view, maximum_response_bytes
        return (
            b'{"kind":"interaction","interaction_id":"projected_turn",'
            b'"direction":"participant_output","artifact_refs":[]}'
        )


def _container_exists(name: str) -> bool:
    completed = subprocess.run(
        (os.fspath(_PODMAN), "container", "exists", name),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0
