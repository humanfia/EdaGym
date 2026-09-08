"""Execution and restart evidence for the trusted-cluster Slurm adapter."""

from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

from edagym.executors.asset_policy import load_system_asset_source_policy
from edagym.executors.assets import asset_content_digest
from edagym.executors.capabilities import ExecutorCapability, probe_slurm_apptainer
from edagym.executors.local import ExecutorUnavailable
from edagym.executors.model import (
    InvocationPlan,
    InvocationView,
    JobStateKind,
    OutputDeclaration,
)
from edagym.executors.slurm import SlurmApptainerExecutor
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass, Capability
from edagym.specs.environment import (
    EnvironmentIdentity,
    EnvironmentSpec,
    FilesystemPolicy,
    FilesystemScope,
    ImageToolLocator,
    ToolBinding,
)
from edagym.specs.environment import SlurmApptainerExecutor as SlurmExecutorSpec
from tests.factories import digest, environment_spec


def _private_directories(root: Path) -> tuple[Path, Path, Path, Path]:
    paths = tuple(root / name for name in ("workspace", "artifacts", "jobs", "cas"))
    for path in paths[:3]:
        path.mkdir(mode=0o700)
    return paths[0], paths[1], paths[2], paths[3]


def _scheduler_program(state_path: Path, command_name: str) -> str:
    return textwrap.dedent(
        f"""\
        #!{os.fspath(Path(sys.executable).resolve())}
        import json
        import os
        import pathlib
        import subprocess
        import sys

        state_path = pathlib.Path({os.fspath(state_path)!r})

        def load():
            if not state_path.exists():
                return {{"mode": "complete", "next_id": 41, "jobs": {{}}}}
            return json.loads(state_path.read_text())

        def save(state):
            state_path.write_text(json.dumps(state, sort_keys=True))
            state_path.chmod(0o600)

        def execute(job):
            completed = subprocess.run(
                [job["script"]],
                check=False,
                cwd=job["chdir"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env={{"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}},
            )
            pathlib.Path(job["stdout"]).write_bytes(completed.stdout)
            pathlib.Path(job["stderr"]).write_bytes(completed.stderr)
            job["active"] = False
            job["state"] = "COMPLETED" if completed.returncode == 0 else "FAILED"
            job["exit_code"] = f"{{completed.returncode}}:0"
            job["reason"] = "None"

        name = {command_name!r}
        arguments = sys.argv[1:]
        if arguments == ["--version"]:
            print("apptainer version 1.5.3" if name == "apptainer" else "slurm 24.11.5")
            raise SystemExit(0)

        state = load()
        if name == "scontrol" and arguments == ["ping"]:
            print("Slurmctld(primary) at test-controller is UP")
            raise SystemExit(0)
        if name == "sacct" and "--starttime=now" in arguments:
            raise SystemExit(0)
        if name == "apptainer" and arguments == ["exec", "--help"]:
            print(
                "--cleanenv --containall --network --no-eval --no-mount "
                "--pids-limit --writable-tmpfs"
            )
            raise SystemExit(0)
        if name == "squeue":
            assert "--all" in arguments
            requested_id = next(
                (item.split("=", 1)[1] for item in arguments if item.startswith("--jobs=")),
                None,
            )
            requested_name = next(
                (item.split("=", 1)[1] for item in arguments if item.startswith("--name=")),
                None,
            )
            for job in state["jobs"].values():
                if job["active"] and (
                    (requested_id is not None and job["id"] == requested_id)
                    or (requested_name is not None and job["name"] == requested_name)
                ):
                    print(job["id"])
            raise SystemExit(0)
        if name == "scontrol" and arguments[:2] == ["show", "job"]:
            selector = arguments[2]
            for job in state["jobs"].values():
                selected = (
                    job["id"] == selector
                    or selector == f"jobname={{job['name']}}"
                )
                if selected:
                    print(
                        f"JobId={{job['id']}} JobName={{job['name']}} "
                        f"UserId=test({{os.getuid()}}) JobState={{job['state']}} "
                        f"Comment={{job['comment']}} SubmitTime={{job['submit_time']}} "
                        f"Reason={{job['reason']}} ExitCode={{job['exit_code']}} "
                        f"Restarts={{job['restarts']}}"
                    )
            raise SystemExit(0)
        if name == "scontrol" and arguments[-2:-1] == ["release"]:
            job = state["jobs"].get(arguments[-1])
            if job is None:
                raise SystemExit(1)
            if job["active"] and job["reason"] == "JobHeldUser":
                job["reason"] = "None"
                job["state"] = "RUNNING"
                execute(job)
                save(state)
            raise SystemExit(0)
        if name == "sacct":
            requested = next(
                item.split("=", 1)[1]
                for item in arguments
                if item.startswith("--jobs=")
            )
            job = state["jobs"].get(requested)
            if job is not None and not job["active"]:
                print(
                    f"{{job['id']}}|{{job['state']}}|{{job['exit_code']}}|"
                    f"{{job['submit_time']}}|{{job['name']}}|{{os.getuid()}}|"
                    f"testcluster|{{job['restarts']}}"
                )
            raise SystemExit(0)
        if name == "scancel":
            requested = arguments[-1]
            job = state["jobs"].get(requested)
            if job is None:
                raise SystemExit(1)
            if job["active"]:
                job["active"] = False
                job["state"] = "CANCELLED"
                job["exit_code"] = "0:15"
                job["reason"] = "None"
                save(state)
            raise SystemExit(0)
        if name == "sbatch":
            scheduler_id = str(state["next_id"])
            state["next_id"] += 1
            option = lambda prefix: next(
                item.split("=", 1)[1]
                for item in arguments
                if item.startswith(prefix)
            )
            job = {{
                "id": scheduler_id,
                "name": option("--job-name="),
                "comment": option("--comment="),
                "state": "PENDING",
                "exit_code": "0:0",
                "active": True,
                "reason": "JobHeldUser",
                "restarts": 0,
                "submit_time": "2026-09-04T12:00:00",
                "script": arguments[-1],
                "chdir": option("--chdir="),
                "stdout": option("--output="),
                "stderr": option("--error="),
            }}
            state["jobs"][scheduler_id] = job
            save(state)
            if state["mode"] == "orphan":
                print("not-a-job-id")
                raise SystemExit(0)
            print(scheduler_id)
            raise SystemExit(0)
        if name == "apptainer" and arguments and arguments[0] == "exec":
            assert "--containall" in arguments
            assert "--cleanenv" in arguments
            assert "--no-eval" in arguments
            assert "--no-mount" in arguments
            assert "hostfs,cwd,home,tmp,bind-paths" in arguments
            assert arguments[arguments.index("--network") + 1] == "none"
            assert os.getenv("SYNTHETIC_SECRET") is None
            binds = [
                arguments[position + 1]
                for position, item in enumerate(arguments)
                if item == "--bind"
            ]
            sources = {{item.split(":", 2)[1]: item.split(":", 2)[0] for item in binds}}
            marker_argument = next(
                item
                for item in arguments
                if item.startswith("/run/edagym-control/edagym-payload-started-")
            )
            marker = (
                pathlib.Path(sources["/run/edagym-control"])
                / pathlib.Path(marker_argument).name
            )
            marker.write_text("")
            marker.chmod(0o600)
            payload = arguments[arguments.index("payload-tool") :]
            workspace = pathlib.Path(sources["/workspace"])
            (workspace / "result.txt").write_text("\\n".join(payload))
            (workspace / "result.txt").chmod(0o600)
            print("payload-ok")
            raise SystemExit(0)
        raise SystemExit(64)
        """
    )


def _fake_control_plane(root: Path, *, mode: str) -> tuple[dict[str, Path], Path]:
    state_path = root / "scheduler-state.json"
    state_path.write_text(json.dumps({"mode": mode, "next_id": 41, "jobs": {}}))
    state_path.chmod(0o600)
    paths = {}
    for name in ("sbatch", "sacct", "scancel", "scontrol", "squeue", "apptainer"):
        path = root / name
        path.write_text(_scheduler_program(state_path, name))
        path.chmod(0o700)
        paths[name] = path
    return paths, state_path


def _capability(paths: dict[str, Path]) -> ExecutorCapability:
    interpreter = Path(sys.executable).resolve()
    if interpreter.stat().st_uid != 0:
        pytest.skip("the Slurm worker interpreter must be a root-owned trusted executable")
    capability = probe_slurm_apptainer(
        provider_id="test_cluster",
        provider_digest=digest("test-cluster-provider"),
        site_policy_digest=digest("test-cluster-policy"),
        sbatch_path=paths["sbatch"],
        sacct_path=paths["sacct"],
        scancel_path=paths["scancel"],
        scontrol_path=paths["scontrol"],
        squeue_path=paths["squeue"],
        apptainer_path=paths["apptainer"],
        python_path=Path(sys.executable).resolve(),
    )
    assert capability.availability.value == "available"
    return capability


def _environment(capability: ExecutorCapability, image_digest: str) -> EnvironmentSpec:
    baseline = environment_spec()
    runtime = next(item for item in capability.runtimes if item.command == "apptainer")
    driver_digest = digest("slurm-payload-driver")
    return EnvironmentSpec(
        identity=EnvironmentIdentity(
            environment_id="trusted_cluster_test",
            authoring_revision=1,
        ),
        executor=SlurmExecutorSpec(
            executor_id="slurm_batch",
            implementation_digest=digest("slurm-executor"),
            provider_id="test_cluster",
            provider_digest=digest("test-cluster-provider"),
            apptainer_version=runtime.version,
            apptainer_probe_digest=runtime.version_output_digest,
            image_digest=image_digest,
        ),
        tool_bindings=(
            ToolBinding(
                capability=Capability.RTL_SIMULATION,
                tool_id="payload_tool",
                tool_version="1.0.0",
                driver_id="payload_tool_driver",
                driver_digest=driver_digest,
                locator=ImageToolLocator(
                    image_digest=image_digest,
                    executable="payload-tool",
                    deployment_attestation_digest=digest("payload-tool-deployment"),
                ),
            ),
        ),
        filesystem=FilesystemPolicy(
            workspace_target="/workspace",
            artifact_target="/artifacts",
        ),
        resources=baseline.resources.model_copy(
            update={
                "cpu_millicores": 1000,
                "memory_bytes": 1024**3,
                "pids": 64,
                "disk_bytes": 1024**3,
                "wall_seconds": 60,
            }
        ),
        checkpoint=baseline.checkpoint,
        artifact_policy=baseline.artifact_policy,
    )


def _plan(view: InvocationView = InvocationView.EVALUATOR) -> InvocationPlan:
    return InvocationPlan(
        invocation_id="slurm_probe",
        run_id=digest("slurm-probe-run"),
        capability=Capability.RTL_SIMULATION,
        tool_id="payload_tool",
        driver_digest=digest("slurm-payload-driver"),
        view=view,
        executable="payload-tool",
        arguments=("literal", "$(touch should-not-exist)"),
        input_manifest_digest=digest("slurm-input"),
        outputs=(
            OutputDeclaration(
                logical_id="result",
                path="result.txt",
                media_type="text/plain",
                artifact_class=ArtifactClass.EVIDENCE,
            ),
        ),
    )


def _executor(
    *,
    paths: dict[str, Path],
    capability: ExecutorCapability,
    image_path: Path,
    image_digest: str,
    store: ContentAddressedStore,
    jobs: Path,
) -> SlurmApptainerExecutor:
    return SlurmApptainerExecutor(
        executor_id="slurm_batch",
        implementation_digest=digest("slurm-executor"),
        provider_id="test_cluster",
        provider_digest=digest("test-cluster-provider"),
        site_policy_digest=digest("test-cluster-policy"),
        capability=capability,
        sbatch_path=paths["sbatch"],
        sacct_path=paths["sacct"],
        scancel_path=paths["scancel"],
        scontrol_path=paths["scontrol"],
        squeue_path=paths["squeue"],
        apptainer_path=paths["apptainer"],
        python_path=Path(sys.executable).resolve(),
        image_paths={image_digest: image_path},
        asset_source_policy=load_system_asset_source_policy(),
        artifact_store=store,
        job_state_root=jobs,
    )


def test_slurm_execution_is_restartable_and_never_a_participant_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYNTHETIC_SECRET", "controller-only-marker")
    workspace, artifacts, jobs, cas = _private_directories(tmp_path)
    paths, state_path = _fake_control_plane(tmp_path, mode="complete")
    capability = _capability(paths)
    image_path = tmp_path / "image.sif"
    image_path.write_bytes(b"immutable-test-image")
    image_path.chmod(0o600)
    image_digest = asset_content_digest(image_path)
    environment = _environment(capability, image_digest)
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = _executor(
        paths=paths,
        capability=capability,
        image_path=image_path,
        image_digest=image_digest,
        store=store,
        jobs=jobs,
    )

    with pytest.raises(ExecutorUnavailable, match="not a participant isolation boundary"):
        executor.launch(
            _plan(InvocationView.PARTICIPANT),
            environment=environment,
            workspace=workspace,
            artifact_directory=artifacts,
            asset_paths={},
            scope=FilesystemScope.PARTICIPANT,
        )
    handle = executor.launch(
        _plan(),
        environment=environment,
        workspace=workspace,
        artifact_directory=artifacts,
        asset_paths={},
        scope=FilesystemScope.EVALUATOR,
    )
    assert handle.job_id == _plan().invocation_id

    reconstructed = _executor(
        paths=paths,
        capability=capability,
        image_path=image_path,
        image_digest=image_digest,
        store=store,
        jobs=jobs,
    )
    assert reconstructed.inspect(handle).state is JobStateKind.COMPLETED
    result = reconstructed.collect(handle)
    assert store.read_bytes(result.stdout, maximum_bytes=32) == b"payload-ok\n"
    assert store.read_bytes(result.outputs[0].blob, maximum_bytes=128) == (
        b"payload-tool\nliteral\n$(touch should-not-exist)"
    )
    assert not (workspace / "should-not-exist").exists()
    scheduler_state = json.loads(state_path.read_text())
    scheduler_state["jobs"]["41"]["restarts"] = 1
    state_path.write_text(json.dumps(scheduler_state, sort_keys=True))
    state_path.chmod(0o600)
    with pytest.raises(ExecutorUnavailable, match="requeued"):
        reconstructed.inspect(handle)


def test_slurm_abandon_recovers_an_uncertain_submission(tmp_path: Path) -> None:
    workspace, artifacts, jobs, cas = _private_directories(tmp_path)
    paths, state_path = _fake_control_plane(tmp_path, mode="orphan")
    capability = _capability(paths)
    image_path = tmp_path / "image.sif"
    image_path.write_bytes(b"immutable-test-image")
    image_path.chmod(0o600)
    image_digest = asset_content_digest(image_path)
    environment = _environment(capability, image_digest)
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = _executor(
        paths=paths,
        capability=capability,
        image_path=image_path,
        image_digest=image_digest,
        store=store,
        jobs=jobs,
    )
    with pytest.raises(ExecutorUnavailable, match="invalid job identity"):
        executor.launch(
            _plan(),
            environment=environment,
            workspace=workspace,
            artifact_directory=artifacts,
            asset_paths={},
            scope=FilesystemScope.EVALUATOR,
        )

    reconstructed = _executor(
        paths=paths,
        capability=capability,
        image_path=image_path,
        image_digest=image_digest,
        store=store,
        jobs=jobs,
    )
    reconstructed.abandon(_plan().invocation_id)
    reconstructed.abandon(_plan().invocation_id)
    scheduler_state = json.loads(state_path.read_text())
    job = scheduler_state["jobs"]["41"]
    assert job["state"] == "CANCELLED"
    assert job["active"] is False


def test_slurm_rejects_an_image_inside_the_writable_workspace(tmp_path: Path) -> None:
    workspace, artifacts, jobs, cas = _private_directories(tmp_path)
    paths, _ = _fake_control_plane(tmp_path, mode="complete")
    capability = _capability(paths)
    image_path = workspace / "image.sif"
    image_path.write_bytes(b"writable-image")
    image_path.chmod(0o600)
    image_digest = asset_content_digest(image_path)
    environment = _environment(capability, image_digest)
    store = ContentAddressedStore(cas, policy=environment.artifact_policy)
    executor = _executor(
        paths=paths,
        capability=capability,
        image_path=image_path,
        image_digest=image_digest,
        store=store,
        jobs=jobs,
    )

    with pytest.raises(ExecutorUnavailable, match="image overlaps"):
        executor.launch(
            _plan(),
            environment=environment,
            workspace=workspace,
            artifact_directory=artifacts,
            asset_paths={},
            scope=FilesystemScope.EVALUATOR,
        )
