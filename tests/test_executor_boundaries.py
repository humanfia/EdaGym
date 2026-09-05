"""Real process evidence for sealed and rootless execution boundaries."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from edagym.drivers.catalog import BACKENDS
from edagym.drivers.probe import probe_backend
from edagym.drivers.rootless_image import (
    RootlessImageConfiguration,
    RootlessImageExecutionRecipe,
)
from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.capabilities import (
    ProviderAvailability,
    RootlessContainerCapability,
    probe_rootless_container,
)
from edagym.executors.local import (
    BrokeredHostExecutor,
    CollectionError,
    ExecutorUnavailable,
)
from edagym.executors.model import (
    COMPOSITE_REPORT_LOGICAL_ID,
    COMPOSITE_REPORT_PATH,
    EnvironmentEntry,
    ExecutionFailureKind,
    InvocationPlan,
    InvocationView,
    JobHandle,
    JobStateKind,
    OutputDeclaration,
    ToolRecipeCommand,
    WorkspaceRecipeCommand,
)
from edagym.executors.rootless import RootlessContainerExecutor
from edagym.executors.rootless_storage import RootlessStorageProvider
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass, Capability
from edagym.specs.environment import (
    AttestedHostToolLocator,
    BrokeredHostToolExecutor,
    ContainerRuntime,
    EnvironmentIdentity,
    EnvironmentSpec,
    FilesystemPolicy,
    FilesystemScope,
    ImageToolLocator,
    ResourceLimits,
    RootlessLocalExecutor,
    ToolBinding,
)
from tests.factories import digest, environment_spec, require_local_containment

if TYPE_CHECKING:
    from edagym.drivers.probe import ResolvedInstallation

_OPEN_EDA_DIGEST = "sha256:f16c3b60966fdec335d07a870a9ace43823e4c93f74f92baae8ec0fa1c0b47e8"
_OPEN_EDA_REFERENCE = f"localhost/edagym-open-eda@{_OPEN_EDA_DIGEST}"
_OPEN_EDA_MANIFEST_DIGEST = (
    "sha256:a32d161bb902faaddc34a585dee8cecba4d4d15f0029d3948dd5219bf6af5ec9"
)


def _directories(root: Path) -> tuple[Path, Path, Path, Path]:
    paths = tuple(root / name for name in ("workspace", "outputs", "jobs", "cas"))
    for path in paths[:3]:
        path.mkdir(mode=0o700, parents=True)
    return paths[0], paths[1], paths[2], paths[3]


def _wait(
    executor: BrokeredHostExecutor | RootlessContainerExecutor,
    handle: JobHandle,
) -> JobStateKind:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        state = executor.inspect(handle)
        if state.state is not JobStateKind.RUNNING:
            return state.state
        time.sleep(0.01)
    raise AssertionError("executor job did not terminate")


def _base_environment(
    executor: BrokeredHostToolExecutor | RootlessLocalExecutor,
    tool: ToolBinding,
) -> EnvironmentSpec:
    baseline = environment_spec()
    return EnvironmentSpec(
        identity=EnvironmentIdentity(
            environment_id="executor_test",
            authoring_revision=1,
        ),
        executor=executor,
        tool_bindings=(tool,),
        filesystem=FilesystemPolicy(
            workspace_target="/workspace",
            artifact_target="/artifacts",
        ),
        resources=ResourceLimits(
            cpu_millicores=1000,
            memory_bytes=1024**3,
            pids=128,
            disk_bytes=1024**3,
            wall_seconds=20,
        ),
        artifact_policy=baseline.artifact_policy,
    )


def _rootless_runtime(
) -> tuple[EnvironmentSpec, ResolvedInstallation, RootlessContainerCapability]:
    definition = next(item for item in BACKENDS if item.tool_id == "yosys")
    configuration = RootlessImageConfiguration(
        recipe=RootlessImageExecutionRecipe(
            image_digest=_OPEN_EDA_DIGEST,
            tool_entrypoint="/usr/bin/yosys",
            package_manifest_path="/usr/share/edagym/dpkg-manifest.tsv",
            package_manifest_digest=_OPEN_EDA_MANIFEST_DIGEST,
            package_manifest_checksum_path="/usr/share/edagym/dpkg-manifest.sha256",
        ),
        engine_path=Path("/usr/bin/podman"),
        image_reference=_OPEN_EDA_REFERENCE,
    )
    probe, installation = probe_backend(
        definition,
        rootless_image_configuration=configuration,
    )
    capability = probe_rootless_container(
        image_references={_OPEN_EDA_DIGEST: _OPEN_EDA_REFERENCE}
    )
    if (
        installation is None
        or capability.availability is not ProviderAvailability.AVAILABLE
        or capability.runtime is None
    ):
        pytest.skip(f"the pinned open EDA image is unavailable: {probe.reason}")
    tool = ToolBinding(
        capability=Capability.ASIC_SYNTHESIS,
        tool_id=definition.tool_id,
        tool_version=installation.version_label,
        driver_id="yosys_rootless_driver",
        driver_digest=definition.driver_digest,
        locator=ImageToolLocator(
            image_digest=_OPEN_EDA_DIGEST,
            executable=installation.executable_name,
            deployment_attestation_digest=installation.deployment_attestation_digest,
        ),
    )
    environment = _base_environment(
        RootlessLocalExecutor(
            executor_id="podman_rootless",
            implementation_digest=digest("podman-rootless"),
            runtime=ContainerRuntime.PODMAN,
            runtime_version=capability.runtime.version,
            runtime_probe_digest=capability.runtime.version_output_digest,
            image_digest=_OPEN_EDA_DIGEST,
        ),
        tool,
    )
    return environment, installation, capability


def _rootless_environment() -> tuple[EnvironmentSpec, str]:
    environment, installation, _ = _rootless_runtime()
    return environment, installation.definition.driver_digest


def test_brokered_executor_scrubs_ambient_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_local_containment()
    monkeypatch.setenv("SYNTHETIC_SECRET", "must-not-reach-child")
    workspace, outputs, jobs, cas = _directories(tmp_path)
    executable = Path(sys.executable).resolve()
    executable_name = executable.name
    driver_digest = digest("python-driver")
    tool = ToolBinding(
        capability=Capability.RTL_SIMULATION,
        tool_id="python_probe",
        tool_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        driver_id="python_probe_driver",
        driver_digest=driver_digest,
        locator=AttestedHostToolLocator(
            executable=executable_name,
            deployment_attestation_digest=digest("python-deployment"),
        ),
    )
    environment = _base_environment(
        BrokeredHostToolExecutor(
            executor_id="sealed_broker",
            implementation_digest=digest("sealed-broker"),
            broker_id="local_broker",
            broker_digest=digest("local-broker"),
            participant_image_digest=digest("participant-image"),
        ),
        tool,
    )
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = BrokeredHostExecutor(
        executor_id="sealed_broker",
        tool_paths={"python_probe": executable},
        tool_environments={"python_probe": {}},
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=jobs,
    )
    script = (
        "import os,pathlib;"
        "assert os.getenv('SYNTHETIC_SECRET') is None;"
        "workspace=pathlib.Path.cwd().resolve();"
        "controlled=[pathlib.Path(os.environ[name]).resolve() for name in "
        "('HOME','TMPDIR','XDG_CACHE_HOME','XDG_CONFIG_HOME')];"
        "assert all(path.is_dir() and path != workspace and workspace not in path.parents "
        "for path in controlled);"
        "assert all(path.stat().st_mode & 0o077 == 0 for path in controlled);"
        "workspace_vendor=pathlib.Path('vendor-state');workspace_vendor.mkdir();"
        "workspace_vendor.chmod(0o755);"
        "workspace_file=workspace_vendor/'state.bin';workspace_file.write_bytes(b'state');"
        "workspace_file.chmod(0o644);"
        "artifact_vendor=controlled[0]/'vendor-state';artifact_vendor.mkdir();"
        "artifact_vendor.chmod(0o777);"
        "artifact_file=artifact_vendor/'state.bin';artifact_file.write_bytes(b'state');"
        "artifact_file.chmod(0o666);"
        "result=pathlib.Path('result.txt');"
        "result.write_text('ok');"
        "result.chmod(0o644);"
        "print('sealed-ok')"
    )
    plan = InvocationPlan(
        invocation_id="sealed_probe",
        capability=Capability.RTL_SIMULATION,
        tool_id="python_probe",
        driver_digest=driver_digest,
        view=InvocationView.EVALUATOR,
        executable=executable_name,
        arguments=("-c", script),
        environment=(
            EnvironmentEntry(name="HOME", value="/"),
            EnvironmentEntry(name="TMPDIR", value="/"),
        ),
        input_manifest_digest=digest("empty-input"),
        outputs=(
            OutputDeclaration(
                logical_id="result",
                path="result.txt",
                media_type="text/plain",
                artifact_class=ArtifactClass.EVIDENCE,
            ),
        ),
    )
    handle = executor.launch(
        plan,
        environment=environment,
        workspace=workspace,
        artifact_directory=outputs,
        asset_paths={},
        scope=FilesystemScope.EVALUATOR,
    )
    repeated = executor.launch(
        plan,
        environment=environment,
        workspace=workspace,
        artifact_directory=outputs,
        asset_paths={},
        scope=FilesystemScope.EVALUATOR,
    )
    assert repeated == handle
    with pytest.raises(ExecutorUnavailable, match="identity already owns"):
        executor.launch(
            plan.model_copy(update={"arguments": ("-c", "raise SystemExit(2)")}),
            environment=environment,
            workspace=workspace,
            artifact_directory=outputs,
            asset_paths={},
            scope=FilesystemScope.EVALUATOR,
        )
    assert _wait(executor, handle) is JobStateKind.COMPLETED
    result = executor.collect(handle)
    assert store.read_bytes(result.stdout, maximum_bytes=1024) == b"sealed-ok\n"
    assert store.read_bytes(result.outputs[0].blob, maximum_bytes=16) == b"ok"
    assert (workspace / "result.txt").stat().st_mode & 0o777 == 0o600
    assert (workspace / "vendor-state").stat().st_mode & 0o777 == 0o700
    assert (workspace / "vendor-state" / "state.bin").stat().st_mode & 0o777 == 0o600
    retained = next(outputs.glob("*/h/vendor-state"))
    assert retained.stat().st_mode & 0o777 == 0o700
    assert (retained / "state.bin").stat().st_mode & 0o777 == 0o600


def test_brokered_wall_deadline_terminates_the_scope_without_controller_polling(
    tmp_path: Path,
) -> None:
    require_local_containment()
    workspace, outputs, jobs, cas = _directories(tmp_path)
    executable = Path(sys.executable).resolve()
    driver_digest = digest("python-deadline-driver")
    tool = ToolBinding(
        capability=Capability.RTL_SIMULATION,
        tool_id="python_deadline_probe",
        tool_version=f"{sys.version_info.major}.{sys.version_info.minor}",
        driver_id="python_deadline_driver",
        driver_digest=driver_digest,
        locator=AttestedHostToolLocator(
            executable=executable.name,
            deployment_attestation_digest=digest("python-deadline-deployment"),
        ),
    )
    base = _base_environment(
        BrokeredHostToolExecutor(
            executor_id="deadline_broker",
            implementation_digest=digest("deadline-broker"),
            broker_id="local_deadline_broker",
            broker_digest=digest("local-deadline-broker"),
            participant_image_digest=digest("participant-image"),
        ),
        tool,
    )
    environment = base.model_copy(
        update={"resources": base.resources.model_copy(update={"wall_seconds": 1})}
    )
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = BrokeredHostExecutor(
        executor_id="deadline_broker",
        tool_paths={tool.tool_id: executable},
        tool_environments={tool.tool_id: {}},
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=jobs,
    )
    program = (
        "from pathlib import Path; import subprocess, sys, time; "
        "child=subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(120)'], start_new_session=True); "
        "Path('deadline-child.pid').write_text(str(child.pid), encoding='ascii'); "
        "time.sleep(120)"
    )
    handle = executor.launch(
        InvocationPlan(
            invocation_id="independent_deadline",
            capability=tool.capability,
            tool_id=tool.tool_id,
            driver_digest=tool.driver_digest,
            view=InvocationView.EVALUATOR,
            executable=tool.locator.executable,
            arguments=("-c", program),
            input_manifest_digest=digest("deadline-input"),
        ),
        environment=environment,
        workspace=workspace,
        artifact_directory=outputs,
        asset_paths={},
        scope=FilesystemScope.EVALUATOR,
    )
    marker = workspace / "deadline-child.pid"
    marker_deadline = time.monotonic() + 5
    while time.monotonic() < marker_deadline and not marker.exists():
        time.sleep(0.01)
    assert marker.exists()
    descendant = Path(f"/proc/{int(marker.read_text(encoding='ascii'))}")
    termination_deadline = time.monotonic() + 5
    while time.monotonic() < termination_deadline and descendant.exists():
        time.sleep(0.05)
    assert not descendant.exists()

    state = executor.inspect(handle)
    assert state.state is JobStateKind.TIMED_OUT
    assert state.failure is ExecutionFailureKind.TIMEOUT
    executor.collect(handle)


@pytest.mark.skipif(not Path("/usr/bin/podman").exists(), reason="Podman is unavailable")
def test_rootless_container_hides_host_paths_and_parent_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYNTHETIC_SECRET", "must-not-reach-container")
    _, _, jobs, cas = _directories(tmp_path)
    environment, installation, capability = _rootless_runtime()
    binding = environment.tool_bindings[0]
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = RootlessContainerExecutor(
        executor_id="podman_rootless",
        implementation_digest=environment.executor.implementation_digest,
        capability=capability,
        tool_installations={installation.definition.tool_id: installation},
        storage_provider=RootlessStorageProvider(maximum_quota_bytes=2 * 1024**3),
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=jobs,
    )
    storage_root = tmp_path / "executor-storage"
    storage_root.mkdir(mode=0o700)
    invocation_id = "rootless_probe"
    lease = executor.create_storage(
        environment=environment,
        runtime_root=storage_root,
        run_id=digest("rootless-boundary-run"),
        invocation_id=invocation_id,
    )
    (lease.workspace / "design.v").write_text(
        "module top(input a, output y); assign y = a; endmodule\n",
        encoding="ascii",
    )
    checker = lease.workspace / "check.sh"
    checker.write_text(
        "#!/bin/sh\nset -eu\n"
        'test -z "${SYNTHETIC_SECRET:-}"\n'
        "test ! -e /site-assets\n"
        "test -s result.v\n"
        "printf container-ok > result.txt\n",
        encoding="ascii",
    )
    checker.chmod(0o700)
    plan = InvocationPlan(
        invocation_id=invocation_id,
        capability=binding.capability,
        tool_id=binding.tool_id,
        driver_digest=binding.driver_digest,
        view=InvocationView.PARTICIPANT,
        executable=binding.locator.executable,
        recipe=(
            ToolRecipeCommand(
                tool_id=binding.tool_id,
                capability=binding.capability,
                driver_digest=binding.driver_digest,
                executable=binding.locator.executable,
                arguments=(
                    "-q",
                    "-p",
                    "read_verilog design.v; synth -top top; "
                    "write_verilog -noattr result.v",
                ),
            ),
            WorkspaceRecipeCommand(executable="check.sh"),
        ),
        input_manifest_digest=digest("empty-input"),
        outputs=(
            OutputDeclaration(
                logical_id=COMPOSITE_REPORT_LOGICAL_ID,
                path=COMPOSITE_REPORT_PATH,
                media_type="application/json",
                artifact_class=ArtifactClass.EVIDENCE,
            ),
            OutputDeclaration(
                logical_id="result",
                path="result.txt",
                media_type="text/plain",
                artifact_class=ArtifactClass.EVIDENCE,
            ),
        ),
    )
    try:
        handle = executor.launch(
            plan,
            environment=environment,
            workspace=lease.workspace,
            artifact_directory=lease.artifact_directory,
            asset_paths={},
            scope=FilesystemScope.PARTICIPANT,
        )
        assert _wait(executor, handle) is JobStateKind.COMPLETED
        result = executor.collect(handle)
        output = next(item for item in result.outputs if item.logical_id == "result")
        assert store.read_bytes(output.blob, maximum_bytes=32) == b"container-ok"
    finally:
        executor.abandon(invocation_id)
        lease.close()


def test_output_collection_never_follows_workspace_links(tmp_path: Path) -> None:
    require_local_containment()
    workspace, outputs, jobs, cas = _directories(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    executable = Path(sys.executable).resolve()
    driver_digest = digest("python-link-driver")
    tool = ToolBinding(
        capability=Capability.RTL_SIMULATION,
        tool_id="python_link_probe",
        tool_version=f"{sys.version_info.major}.{sys.version_info.minor}",
        driver_id="python_link_driver",
        driver_digest=driver_digest,
        locator=AttestedHostToolLocator(
            executable=executable.name,
            deployment_attestation_digest=digest("python-link-deployment"),
        ),
    )
    environment = _base_environment(
        BrokeredHostToolExecutor(
            executor_id="sealed_broker",
            implementation_digest=digest("sealed-link-broker"),
            broker_id="local_broker",
            broker_digest=digest("local-link-broker"),
            participant_image_digest=digest("participant-link-image"),
        ),
        tool,
    )
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = BrokeredHostExecutor(
        executor_id="sealed_broker",
        tool_paths={"python_link_probe": executable},
        tool_environments={"python_link_probe": {}},
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=jobs,
    )
    script = (
        "import pathlib;"
        f"outside=pathlib.Path({str(outside)!r});"
        "pathlib.Path('linked').symlink_to(outside, target_is_directory=True);"
        "(outside / 'result.txt').write_text('outside')"
    )
    plan = InvocationPlan(
        invocation_id="linked_output_probe",
        capability=Capability.RTL_SIMULATION,
        tool_id="python_link_probe",
        driver_digest=driver_digest,
        view=InvocationView.EVALUATOR,
        executable=executable.name,
        arguments=("-c", script),
        input_manifest_digest=digest("empty-input"),
        outputs=(
            OutputDeclaration(
                logical_id="result",
                path="linked/result.txt",
                media_type="text/plain",
                artifact_class=ArtifactClass.EVIDENCE,
            ),
        ),
    )
    handle = executor.launch(
        plan,
        environment=environment,
        workspace=workspace,
        artifact_directory=outputs,
        asset_paths={},
        scope=FilesystemScope.EVALUATOR,
    )
    assert _wait(executor, handle) is JobStateKind.COMPLETED
    with pytest.raises(CollectionError, match="opened safely"):
        executor.collect(handle)
    assert (outside / "result.txt").read_text() == "outside"
