"""Real recovery evidence for executor-owned rootless writable storage."""

from __future__ import annotations

import multiprocessing
import os
import signal
import subprocess
from multiprocessing.connection import Connection
from pathlib import Path

import pytest

from edagym.executors.local import ExecutorUnavailable
from edagym.executors.rootless_storage import (
    RootlessStorageLease,
    RootlessStorageProvider,
)
from tests.factories import digest

_STORAGE_RUNTIMES = (
    Path("/usr/sbin/mkfs.ext4"),
    Path("/usr/bin/fuse2fs"),
    Path("/usr/bin/fusermount3"),
)
_INVOCATION_ID = "durable_invocation"


def _create_storage(
    provider: RootlessStorageProvider,
    runtime_root: Path,
) -> RootlessStorageLease:
    return provider.create(
        runtime_root=runtime_root,
        invocation_id=_INVOCATION_ID,
        run_id=digest("rootless-storage-run"),
        environment_spec_digest=digest("rootless-storage-environment"),
        executor_id="rootless_executor",
        executor_implementation_digest=digest("rootless-storage-executor"),
        maximum_bytes=32 * 1024 * 1024,
    )


def _storage_controller(root_text: str, ready: Connection) -> None:
    runtime_root = Path(root_text)
    lease = _create_storage(
        RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024),
        runtime_root,
    )
    (lease.workspace / "workspace-marker").write_bytes(b"workspace-preserved\n")
    (lease.artifact_directory / "artifact-marker").write_bytes(b"artifact-preserved\n")
    ready.send(lease.receipt.digest)
    signal.pause()


@pytest.mark.skipif(
    not all(path.is_file() for path in _STORAGE_RUNTIMES),
    reason="rootless storage runtimes are unavailable",
)
def test_rootless_storage_reconstructs_and_releases_one_durable_substrate(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "rootless-storage"
    runtime_root.mkdir(mode=0o700)
    initial = _create_storage(
        RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024),
        runtime_root,
    )
    marker = initial.workspace / "preserved.txt"
    marker.write_bytes(b"durable-rootless-storage\n")
    marker.chmod(0o600)

    reconstructed = _create_storage(
        RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024),
        runtime_root,
    )
    assert reconstructed.receipt == initial.receipt
    assert (reconstructed.workspace / marker.name).read_bytes() == marker.read_bytes()

    subprocess.run(
        ("/usr/bin/fusermount3", "-u", reconstructed.workspace.parent.as_posix()),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    reconstructed.close()
    initial.close()
    assert not (runtime_root / _INVOCATION_ID).exists()

    retried = _create_storage(
        RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024),
        runtime_root,
    )
    retried.close()


@pytest.mark.skipif(
    not all(path.is_file() for path in _STORAGE_RUNTIMES),
    reason="rootless storage runtimes are unavailable",
)
def test_rootless_storage_release_resumes_after_partial_node_cleanup(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "rootless-storage-partial-release"
    runtime_root.mkdir(mode=0o700)
    lease = _create_storage(
        RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024),
        runtime_root,
    )
    mountpoint = lease.workspace.parent
    subprocess.run(
        ("/usr/bin/fusermount3", "-u", mountpoint.as_posix()),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    blocker = mountpoint / "transient-blocker"
    blocker.write_bytes(b"retry release")
    blocker.chmod(0o600)

    with pytest.raises(ExecutorUnavailable, match="not empty"):
        lease.close()
    blocker.unlink()
    lease.close()

    assert not (runtime_root / _INVOCATION_ID).exists()
    assert not os.path.ismount(mountpoint)


@pytest.mark.skipif(
    not all(path.is_file() for path in _STORAGE_RUNTIMES),
    reason="rootless storage runtimes are unavailable",
)
def test_rootless_storage_rejects_quota_above_deployment_ceiling_before_creation(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "rootless-storage-ceiling"
    runtime_root.mkdir(mode=0o700)
    provider = RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024)

    with pytest.raises(ExecutorUnavailable, match="disk quota"):
        provider.create(
            runtime_root=runtime_root,
            invocation_id="oversized_invocation",
            run_id=digest("rootless-storage-run"),
            environment_spec_digest=digest("rootless-storage-environment"),
            executor_id="rootless_executor",
            executor_implementation_digest=digest("rootless-storage-executor"),
            maximum_bytes=128 * 1024 * 1024,
        )
    assert not (runtime_root / "oversized_invocation").exists()


@pytest.mark.skipif(
    not all(path.is_file() for path in _STORAGE_RUNTIMES),
    reason="rootless storage runtimes are unavailable",
)
def test_rootless_storage_survives_controller_sigkill_and_provider_remount(
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "rootless-storage-recovery"
    runtime_root.mkdir(mode=0o700)
    context = multiprocessing.get_context("spawn")
    received, ready = context.Pipe(duplex=False)
    controller = context.Process(
        target=_storage_controller,
        args=(runtime_root.as_posix(), ready),
    )
    controller.start()
    ready.close()
    try:
        assert received.poll(30), "storage controller did not publish its receipt"
        original_receipt_digest = received.recv()
        assert isinstance(original_receipt_digest, str)
        assert original_receipt_digest.startswith("sha256:")
        controller.kill()
        controller.join(10)
        assert controller.exitcode == -signal.SIGKILL
    finally:
        if controller.is_alive():
            controller.kill()
            controller.join(10)
        received.close()
        controller.close()

    mountpoint = runtime_root / _INVOCATION_ID / "mount"
    assert os.path.ismount(mountpoint)
    subprocess.run(
        ("/usr/bin/fusermount3", "-u", mountpoint.as_posix()),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert not os.path.ismount(mountpoint)

    reconstructed = _create_storage(
        RootlessStorageProvider(maximum_quota_bytes=64 * 1024 * 1024),
        runtime_root,
    )
    assert reconstructed.receipt.invocation_id == _INVOCATION_ID
    assert (reconstructed.workspace / "workspace-marker").read_bytes() == (
        b"workspace-preserved\n"
    )
    assert (reconstructed.artifact_directory / "artifact-marker").read_bytes() == (
        b"artifact-preserved\n"
    )
    reconstructed.close()
    assert not (runtime_root / _INVOCATION_ID).exists()
    assert not os.path.ismount(mountpoint)
