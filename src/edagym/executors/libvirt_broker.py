"""Concrete qemu-session broker for one immutable-kernel VM per invocation."""

from __future__ import annotations

import fcntl
import hashlib
import os
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal, Self

from pydantic import TypeAdapter, ValidationError, model_validator

from edagym.canonical import canonical_bytes, canonical_digest
from edagym.executors.asset_identity import (
    AssetIdentityError,
    capture_asset_descriptor,
    file_identity,
)
from edagym.executors.capabilities import (
    ExecutorCapability,
    ExecutorProviderKind,
    LibvirtConnection,
    ProviderAvailability,
    libvirt_control_environment,
)
from edagym.executors.licenses import LicenseLease
from edagym.executors.local import ExecutorUnavailable, UnknownJob, _disclosure_for
from edagym.executors.model import (
    CollectedOutput,
    ExecutionFailureKind,
    ExecutionResult,
    InvocationPlan,
    JobHandle,
    JobState,
    JobStateKind,
)
from edagym.executors.vm import (
    GrantAccess,
    HostResourceGrant,
    VmIsolationCleanup,
    VmResourceKind,
)
from edagym.executors.vm_protocol import (
    VM_GUEST_REPLY_ADAPTER,
    VM_PROTOCOL_MAX_FRAME_BYTES,
    VmAssetTransfer,
    VmGuestAccepted,
    VmGuestControl,
    VmGuestLaunch,
    VmGuestReply,
    VmGuestResult,
    VmGuestRunning,
    VmInlineBlob,
    VmTransferTree,
    VmTreeEntry,
    VmTreeEntryKind,
    encode_vm_message,
)
from edagym.run.artifact_model import (
    BlobRef,
)
from edagym.run.artifacts import ContentAddressedStore
from edagym.specs.common import ArtifactClass, Digest, Identifier, SchemaVersion, StrictModel
from edagym.specs.environment import (
    ArtifactDisclosure,
    EnvironmentSpec,
    FilesystemScope,
    NoNetwork,
    VmPerRunExecutor,
)

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_DOMAIN_NAMESPACE = "https://edagym.invalid/libvirt/invocation/v1"
_FRAME_HEADER = struct.Struct(">I")
_IDENTIFIER_ADAPTER = TypeAdapter(Identifier)
_TRANSFER_CHUNK_BYTES = 1024 * 1024
_DEFAULT_OUTPUT_LIMIT_BYTES = 8 * 1024 * 1024


class LibvirtBrokerPhase(StrEnum):
    PREPARED = "prepared"
    DEFINED = "defined"
    RUNNING = "running"
    TERMINAL = "terminal"


class LibvirtBrokerRecord(StrictModel):
    """Private durable owner for a defined guest and its canonical result."""

    schema_version: SchemaVersion = 1
    capability_digest: Digest
    phase: LibvirtBrokerPhase
    plan: InvocationPlan
    environment: EnvironmentSpec
    domain_name: Identifier
    domain_uuid: str
    request_digest: Digest
    result: ExecutionResult | None = None

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        if (self.phase is LibvirtBrokerPhase.TERMINAL) != (self.result is not None):
            raise ValueError("only terminal VM broker records carry a result")
        if self.result is not None and self.result.state.handle != self.handle:
            raise ValueError("VM broker result belongs to another invocation")
        try:
            if str(uuid.UUID(self.domain_uuid)) != self.domain_uuid:
                raise ValueError
        except ValueError:
            raise ValueError("VM broker domain UUID is not canonical") from None
        return self

    @property
    def handle(self) -> JobHandle:
        return JobHandle(
            job_id=self.plan.invocation_id,
            invocation_digest=self.plan.digest,
            executor_id=self.environment.executor.executor_id,
        )


class LibvirtFence(StrictModel):
    schema_version: SchemaVersion = 1
    invocation_id: Identifier
    lifecycle_fence_digest: Digest


class LibvirtKernelImage:
    """Runtime-only immutable kernel/initramfs binding with no path representation."""

    __slots__ = (
        "_image_digest",
        "_initrd_digest",
        "_initrd_path",
        "_kernel_arguments",
        "_kernel_digest",
        "_kernel_path",
    )

    def __init__(
        self,
        *,
        kernel_path: Path,
        initrd_path: Path,
        kernel_arguments: str,
    ) -> None:
        if (
            not kernel_arguments
            or len(kernel_arguments) > 4096
            or any(character in kernel_arguments for character in "\x00\r\n")
        ):
            raise ExecutorUnavailable("VM kernel arguments are invalid")
        self._kernel_path = _canonical_private_file(kernel_path)
        self._initrd_path = _canonical_private_file(initrd_path)
        self._kernel_digest = _file_digest(self._kernel_path)
        self._initrd_digest = _file_digest(self._initrd_path)
        self._kernel_arguments = kernel_arguments
        self._image_digest = canonical_digest(
            {
                "kernel_digest": self._kernel_digest,
                "initrd_digest": self._initrd_digest,
                "kernel_arguments": kernel_arguments,
            },
            domain="libvirt-kernel-image-v1",
        )

    @property
    def image_digest(self) -> str:
        return self._image_digest

    def verify(self) -> None:
        if (
            _file_digest(self._kernel_path) != self._kernel_digest
            or _file_digest(self._initrd_path) != self._initrd_digest
        ):
            raise ExecutorUnavailable("VM boot image changed after registration")


class SessionLibvirtVmBroker:
    """Run no-network commands in disposable qemu:///session guests."""

    def __init__(
        self,
        *,
        executor_id: str,
        implementation_digest: str,
        provider_id: str,
        provider_digest: str,
        capability: ExecutorCapability,
        virsh_path: Path,
        images: Mapping[str, LibvirtKernelImage],
        artifact_store: ContentAddressedStore,
        state_root: Path,
        control_root: Path,
        connection: LibvirtConnection = LibvirtConnection.SESSION,
        boot_timeout_seconds: int = 60,
    ) -> None:
        if (
            capability.kind is not ExecutorProviderKind.LIBVIRT_KVM
            or capability.availability is not ProviderAvailability.AVAILABLE
            or capability.provider_id != provider_id
            or capability.provider_digest != provider_digest
            or connection is not LibvirtConnection.SESSION
        ):
            raise ExecutorUnavailable("libvirt session capability is unavailable or stale")
        runtime = next(
            (item for item in capability.runtimes if item.command == "virsh"),
            None,
        )
        if runtime is None or boot_timeout_seconds <= 0 or boot_timeout_seconds > 600:
            raise ExecutorUnavailable("libvirt broker runtime policy is incomplete")
        if set(images) != {image.image_digest for image in images.values()}:
            raise ExecutorUnavailable("libvirt image registry identities disagree")
        self.executor_id = _IDENTIFIER_ADAPTER.validate_python(executor_id)
        self._implementation_digest = implementation_digest
        self._provider_id = provider_id
        self._provider_digest = provider_digest
        self._capability = capability
        self._virsh_path = _canonical_private_file(virsh_path)
        if _file_digest(self._virsh_path) != runtime.executable_digest:
            raise ExecutorUnavailable("libvirt runtime differs from capability evidence")
        self._virsh_digest = runtime.executable_digest
        self._images = MappingProxyType(dict(images))
        self._artifact_store = artifact_store
        self._state_root = _prepare_private_directory(state_root, parents=True)
        self._control_root = _prepare_private_directory(control_root, parents=True)
        self._lock_root = _prepare_private_directory(
            self._state_root / ".locks",
            parents=False,
        )
        self._connection = connection
        self._boot_timeout_seconds = boot_timeout_seconds
        self._thread_locks: dict[str, threading.Lock] = {}
        self._thread_lock_index = threading.Lock()

    @property
    def capability_digest(self) -> str:
        return self._capability.digest

    @property
    def artifact_store(self) -> ContentAddressedStore:
        return self._artifact_store

    def launch(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        scope: FilesystemScope,
        workspace: HostResourceGrant,
        artifact_directory: HostResourceGrant,
        assets: Mapping[str, HostResourceGrant],
        license_lease: LicenseLease | None,
    ) -> JobHandle:
        with (
            self._provider_guard() as provider_lock,
            self._invocation_guard(plan.invocation_id) as invocation_lock,
        ):
            return self._launch_locked(
                plan,
                environment=environment,
                scope=scope,
                workspace=workspace,
                artifact_directory=artifact_directory,
                assets=assets,
                license_lease=license_lease,
                lifecycle_locks=(provider_lock, invocation_lock),
            )

    def _launch_locked(
        self,
        plan: InvocationPlan,
        *,
        environment: EnvironmentSpec,
        scope: FilesystemScope,
        workspace: HostResourceGrant,
        artifact_directory: HostResourceGrant,
        assets: Mapping[str, HostResourceGrant],
        license_lease: LicenseLease | None,
        lifecycle_locks: tuple[int, int],
    ) -> JobHandle:
        executor = environment.executor
        if (
            not isinstance(executor, VmPerRunExecutor)
            or executor.executor_id != self.executor_id
            or executor.implementation_digest != self._implementation_digest
            or getattr(executor, "provider_id", None) != self._provider_id
            or getattr(executor, "provider_digest", None) != self._provider_digest
        ):
            raise ExecutorUnavailable("environment does not bind this libvirt broker")
        if not isinstance(environment.network, NoNetwork):
            raise ExecutorUnavailable("concrete libvirt broker currently requires no network")
        if plan.recipe:
            raise ExecutorUnavailable("VM guest agent does not support composite recipes")
        if license_lease is not None:
            raise ExecutorUnavailable("VM guest agent has no credential proxy")
        if workspace.access is not GrantAccess.READ_WRITE or (
            artifact_directory.access is not GrantAccess.READ_WRITE
        ):
            raise ExecutorUnavailable("VM writable grants have incorrect access")
        if (
            workspace.guest_target != environment.filesystem.workspace_target
            or artifact_directory.guest_target != environment.filesystem.artifact_target
        ):
            raise ExecutorUnavailable("VM writable grants have incorrect targets")
        expected_assets = {
            mount.asset_id: mount
            for mount in environment.filesystem.readonly_assets
            if mount.scope is scope
        }
        if set(assets) != set(expected_assets) or any(
            grant.access is not GrantAccess.READ_ONLY
            or grant.guest_target != expected_assets[asset_id].target
            for asset_id, grant in assets.items()
        ):
            raise ExecutorUnavailable("VM asset grants differ from the scoped closure")
        image = self._images.get(executor.image_digest)
        if image is None:
            raise ExecutorUnavailable("VM boot image is not registered")
        image.verify()
        if environment.resources.cpu_millicores % 1000:
            raise ExecutorUnavailable("VM CPU limits require whole virtual CPUs")
        if environment.resources.memory_bytes % 1024:
            raise ExecutorUnavailable("VM memory limits require whole KiB")
        self._require_concurrency_slot(environment)

        job_directory = self._job_directory(plan.invocation_id)
        if self._fence_path(plan.invocation_id).exists():
            raise ExecutorUnavailable("VM invocation is durably fenced")
        if job_directory.exists():
            raise ExecutorUnavailable("VM invocation already has durable state")
        job_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
        output_limit = min(environment.resources.disk_bytes, _DEFAULT_OUTPUT_LIMIT_BYTES)
        transfer_budget = VM_PROTOCOL_MAX_FRAME_BYTES // 3
        workspace_tree, workspace_bytes = _pack_transfer_tree(
            workspace,
            readonly=False,
            byte_limit=transfer_budget,
        )
        transfer_budget -= workspace_bytes
        asset_transfers: list[VmAssetTransfer] = []
        for asset_id in sorted(assets):
            grant = assets[asset_id]
            restricted_digest = grant.restricted_digest
            if restricted_digest is None:
                raise ExecutorUnavailable("VM asset grant lacks its restricted identity")
            try:
                observed = capture_asset_descriptor(grant.fileno())
            except AssetIdentityError:
                raise ExecutorUnavailable("VM asset grant cannot be recaptured") from None
            if observed.restricted_digest != restricted_digest:
                raise ExecutorUnavailable("VM asset grant changed before transfer")
            tree, transferred = _pack_transfer_tree(
                grant,
                readonly=True,
                byte_limit=transfer_budget,
            )
            transfer_budget -= transferred
            asset_transfers.append(
                VmAssetTransfer(
                    asset_id=asset_id,
                    restricted_digest=restricted_digest,
                    tree=tree,
                )
            )
        request = VmGuestLaunch(
            plan=plan,
            invocation_digest=plan.digest,
            environment_digest=environment.digest,
            workspace=workspace_tree,
            artifact_target=artifact_directory.guest_target,
            assets=tuple(asset_transfers),
            wall_seconds=environment.resources.wall_seconds,
            output_limit_bytes=output_limit,
        )
        request_bytes = encode_vm_message(request)
        request_path = job_directory / "request.json"
        _write_exclusive(request_path, request_bytes)
        domain_name, domain_uuid = _domain_identity(self.executor_id, plan.invocation_id)
        record = LibvirtBrokerRecord(
            capability_digest=self._capability.digest,
            phase=LibvirtBrokerPhase.PREPARED,
            plan=plan,
            environment=environment,
            domain_name=domain_name,
            domain_uuid=domain_uuid,
            request_digest=request.digest,
        )
        self._write_record(record, create=True)
        domain_xml = self._domain_xml(record, image)
        xml_path = job_directory / "domain.xml"
        _write_exclusive(xml_path, domain_xml)
        self._run_virsh("define", os.fspath(xml_path), inherited=lifecycle_locks)
        record = self._transition(record, LibvirtBrokerPhase.DEFINED)
        self._write_record(record)
        self._run_virsh("start", record.domain_name, inherited=lifecycle_locks)
        self._verify_domain_definition(record, image)
        accepted = self._exchange(
            record,
            request,
            timeout_seconds=self._boot_timeout_seconds,
        )
        if not isinstance(accepted, VmGuestAccepted):
            raise ExecutorUnavailable("VM guest did not accept the invocation")
        self._require_reply_identity(record, accepted)
        record = self._transition(record, LibvirtBrokerPhase.RUNNING)
        self._write_record(record)
        with suppress(OSError):
            request_path.unlink()
        return record.handle

    def inspect(self, handle: JobHandle) -> JobState:
        with self._invocation_guard(handle.job_id):
            record = self._owned_record(handle)
            if record.result is not None:
                return record.result.state
            if not self._domain_exists(record):
                result = self._empty_result(
                    record,
                    state=JobStateKind.LOST,
                    exit_code=1,
                    failure=ExecutionFailureKind.INFRASTRUCTURE,
                )
                self._write_record(self._terminal(record, result))
                return result.state
            reply = self._exchange(
                record,
                VmGuestControl(
                    kind="status",
                    invocation_id=handle.job_id,
                    invocation_digest=handle.invocation_digest,
                ),
                timeout_seconds=20,
            )
            self._require_reply_identity(record, reply)
            if isinstance(reply, VmGuestRunning):
                return JobState(handle=handle, state=JobStateKind.RUNNING)
            if not isinstance(reply, VmGuestResult):
                raise ExecutorUnavailable("VM guest returned an invalid status reply")
            result = self._materialize_result(record, reply)
            self._write_record(self._terminal(record, result))
            return result.state

    def cancel(self, handle: JobHandle) -> JobState:
        with self._invocation_guard(handle.job_id):
            record = self._owned_record(handle)
            if record.result is not None:
                return record.result.state
            if self._domain_exists(record):
                with suppress(ExecutorUnavailable):
                    reply = self._exchange(
                        record,
                        VmGuestControl(
                            kind="cancel",
                            invocation_id=handle.job_id,
                            invocation_digest=handle.invocation_digest,
                        ),
                        timeout_seconds=5,
                    )
                    self._require_reply_identity(record, reply)
                self._destroy_domain(record)
            result = self._empty_result(
                record,
                state=JobStateKind.CANCELLED,
                exit_code=143,
                failure=ExecutionFailureKind.CANCELLED,
            )
            self._write_record(self._terminal(record, result))
            return result.state

    def collect(self, handle: JobHandle) -> ExecutionResult:
        state = self.inspect(handle)
        if state.state in {JobStateKind.QUEUED, JobStateKind.RUNNING}:
            raise ExecutorUnavailable("VM output cannot be collected before termination")
        with self._invocation_guard(handle.job_id):
            record = self._owned_record(handle)
            assert record.result is not None
            self._destroy_domain(record)
            return record.result

    def abandon(self, invocation_id: str) -> VmIsolationCleanup:
        try:
            normalized = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        except ValidationError:
            raise ExecutorUnavailable("invalid VM invocation identity") from None
        with self._invocation_guard(normalized):
            job_directory = self._job_directory(normalized)
            if not job_directory.exists():
                job_directory.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            fence_path = self._fence_path(normalized)
            if fence_path.exists():
                fence = self._load_fence(normalized)
            else:
                fence = LibvirtFence(
                    invocation_id=normalized,
                    lifecycle_fence_digest=canonical_digest(
                        {
                            "invocation_id": normalized,
                            "provider_digest": self._provider_digest,
                        },
                        domain="libvirt-permanent-lifecycle-fence-v1",
                    ),
                )
                _write_exclusive(fence_path, canonical_bytes(fence) + b"\n")
                _fsync_directory(job_directory)
            record = None
            if self._record_path(normalized).exists():
                record = self._load_record(normalized)
                self._destroy_domain(record)
            else:
                self._destroy_unrecorded_domain(normalized)
            for path in (
                job_directory / "request.json",
                job_directory / "domain.xml",
                self._control_path(normalized),
            ):
                with suppress(FileNotFoundError):
                    path.unlink()
            remaining: list[VmResourceKind] = []
            if self._domain_name_exists(_domain_identity(self.executor_id, normalized)[0]):
                remaining.append(VmResourceKind.MACHINE)
            if self._control_path(normalized).exists():
                remaining.append(VmResourceKind.GUEST_CONTROL_CHANNEL)
            return VmIsolationCleanup(
                invocation_id=normalized,
                lifecycle_fence_digest=fence.lifecycle_fence_digest,
                remaining_resources=tuple(remaining),
            )

    def _materialize_result(
        self,
        record: LibvirtBrokerRecord,
        reply: VmGuestResult,
    ) -> ExecutionResult:
        if reply.environment_digest != record.environment.digest:
            raise ExecutorUnavailable("VM guest result belongs to another environment")
        handle = record.handle
        state = JobState(
            handle=handle,
            state=reply.state,
            exit_code=reply.exit_code,
            failure=reply.failure,
        )
        diagnostic = _disclosure_for(
            record.environment,
            artifact_class=ArtifactClass.DIAGNOSTIC,
        )
        stdout = self._store_blob(reply.stdout, diagnostic)
        stderr = self._store_blob(reply.stderr, diagnostic)
        declarations = {item.logical_id: item for item in record.plan.outputs}
        outputs: list[CollectedOutput] = []
        for output in reply.outputs:
            declaration = declarations.get(output.logical_id)
            if declaration is None:
                raise ExecutorUnavailable("VM guest returned an undeclared output")
            disclosure = _disclosure_for(record.environment, declaration.artifact_class)
            blob = self._artifact_store.put_bytes(
                output.blob.decode(),
                artifact_class=declaration.artifact_class,
                sensitivity=disclosure.sensitivity,
                visibility=disclosure.visibility,
                redistribution=disclosure.redistribution,
            )
            outputs.append(
                CollectedOutput(
                    logical_id=declaration.logical_id,
                    blob=blob,
                    media_type=declaration.media_type,
                    artifact_class=declaration.artifact_class,
                )
            )
        return ExecutionResult(
            state=state,
            stdout=stdout,
            stderr=stderr,
            outputs=tuple(outputs),
        )

    def _store_blob(
        self,
        blob: VmInlineBlob,
        disclosure: ArtifactDisclosure,
    ) -> BlobRef:
        return self._artifact_store.put_bytes(
            blob.decode(),
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )

    def _empty_result(
        self,
        record: LibvirtBrokerRecord,
        *,
        state: JobStateKind,
        exit_code: int,
        failure: ExecutionFailureKind,
    ) -> ExecutionResult:
        disclosure = _disclosure_for(record.environment, ArtifactClass.DIAGNOSTIC)
        empty = self._artifact_store.put_bytes(
            b"",
            artifact_class=ArtifactClass.DIAGNOSTIC,
            sensitivity=disclosure.sensitivity,
            visibility=disclosure.visibility,
            redistribution=disclosure.redistribution,
        )
        return ExecutionResult(
            state=JobState(
                handle=record.handle,
                state=state,
                exit_code=exit_code,
                failure=failure,
            ),
            stdout=empty,
            stderr=empty,
        )

    def _domain_xml(self, record: LibvirtBrokerRecord, image: LibvirtKernelImage) -> bytes:
        socket_path = self._control_path(record.plan.invocation_id)
        if len(os.fsencode(socket_path)) >= 100:
            raise ExecutorUnavailable("VM control socket path exceeds its runtime bound")
        domain = ElementTree.Element("domain", {"type": "kvm"})
        ElementTree.SubElement(domain, "name").text = record.domain_name
        ElementTree.SubElement(domain, "uuid").text = record.domain_uuid
        ElementTree.SubElement(domain, "memory", {"unit": "KiB"}).text = str(
            record.environment.resources.memory_bytes // 1024
        )
        ElementTree.SubElement(domain, "vcpu", {"placement": "static"}).text = str(
            record.environment.resources.cpu_millicores // 1000
        )
        os_node = ElementTree.SubElement(domain, "os")
        ElementTree.SubElement(
            os_node,
            "type",
            {"arch": "x86_64", "machine": "q35"},
        ).text = "hvm"
        ElementTree.SubElement(os_node, "kernel").text = os.fspath(image._kernel_path)
        ElementTree.SubElement(os_node, "initrd").text = os.fspath(image._initrd_path)
        ElementTree.SubElement(os_node, "cmdline").text = image._kernel_arguments
        features = ElementTree.SubElement(domain, "features")
        ElementTree.SubElement(features, "acpi")
        ElementTree.SubElement(features, "apic")
        ElementTree.SubElement(domain, "cpu", {"mode": "host-passthrough", "check": "none"})
        ElementTree.SubElement(domain, "clock", {"offset": "utc"})
        for event in ("on_poweroff", "on_reboot", "on_crash"):
            ElementTree.SubElement(domain, event).text = "destroy"
        metadata = ElementTree.SubElement(domain, "metadata")
        invocation = ElementTree.SubElement(
            metadata,
            f"{{{_DOMAIN_NAMESPACE}}}invocation",
            {"id": record.plan.invocation_id},
        )
        invocation.set("digest", record.plan.digest)
        devices = ElementTree.SubElement(domain, "devices")
        serial = ElementTree.SubElement(devices, "serial", {"type": "pty"})
        ElementTree.SubElement(
            serial,
            "target",
            {"type": "isa-serial", "port": "0"},
        )
        console = ElementTree.SubElement(devices, "console", {"type": "pty"})
        ElementTree.SubElement(
            console,
            "target",
            {"type": "serial", "port": "0"},
        )
        channel = ElementTree.SubElement(devices, "channel", {"type": "unix"})
        ElementTree.SubElement(
            channel,
            "source",
            {"mode": "bind", "path": os.fspath(socket_path)},
        )
        ElementTree.SubElement(
            channel,
            "target",
            {"type": "virtio", "name": "org.edagym.control.0"},
        )
        ElementTree.SubElement(devices, "memballoon", {"model": "none"})
        return bytes(ElementTree.tostring(domain, encoding="utf-8", xml_declaration=True))

    def _exchange(
        self,
        record: LibvirtBrokerRecord,
        message: VmGuestLaunch | VmGuestControl,
        *,
        timeout_seconds: int,
    ) -> VmGuestReply:
        encoded = encode_vm_message(message)
        deadline = time.monotonic() + timeout_seconds
        connection: socket.socket | None = None
        while time.monotonic() < deadline:
            candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            candidate.settimeout(min(1.0, max(deadline - time.monotonic(), 0.1)))
            try:
                candidate.connect(os.fspath(self._control_path(record.plan.invocation_id)))
            except OSError:
                candidate.close()
                time.sleep(0.1)
                continue
            connection = candidate
            break
        if connection is None:
            raise ExecutorUnavailable("VM guest control channel is unavailable")
        try:
            connection.settimeout(max(deadline - time.monotonic(), 0.1))
            connection.sendall(_FRAME_HEADER.pack(len(encoded)) + encoded)
            header = _receive_exact(connection, _FRAME_HEADER.size)
            size = _FRAME_HEADER.unpack(header)[0]
            if size <= 0 or size > VM_PROTOCOL_MAX_FRAME_BYTES:
                raise ExecutorUnavailable("VM guest reply exceeds its protocol bound")
            content = _receive_exact(connection, size)
        except (OSError, TimeoutError):
            raise ExecutorUnavailable("VM guest control exchange failed") from None
        finally:
            connection.close()
        try:
            return VM_GUEST_REPLY_ADAPTER.validate_json(content)
        except ValidationError:
            raise ExecutorUnavailable("VM guest returned an invalid canonical reply") from None

    @staticmethod
    def _require_reply_identity(record: LibvirtBrokerRecord, reply: object) -> None:
        if (
            getattr(reply, "invocation_id", None) != record.plan.invocation_id
            or getattr(reply, "invocation_digest", None) != record.plan.digest
            or getattr(reply, "request_digest", None) != record.request_digest
        ):
            raise ExecutorUnavailable("VM guest reply belongs to another invocation")

    def _owned_record(self, handle: JobHandle) -> LibvirtBrokerRecord:
        if handle.executor_id != self.executor_id:
            raise UnknownJob("VM job handle belongs to another executor")
        record = self._load_record(handle.job_id)
        if record.handle != handle or self._fence_path(handle.job_id).exists():
            raise UnknownJob("VM job handle is not active in this broker")
        return record

    def _domain_exists(self, record: LibvirtBrokerRecord) -> bool:
        identity = self._run_virsh("domuuid", record.domain_name, allow_failure=True)
        if identity.returncode != 0:
            return False
        if identity.stdout.decode("ascii", errors="strict").strip() != record.domain_uuid:
            raise ExecutorUnavailable("libvirt domain identity changed")
        executor = record.environment.executor
        if not isinstance(executor, VmPerRunExecutor):
            raise ExecutorUnavailable("libvirt record executor is invalid")
        image = self._images.get(executor.image_digest)
        if image is None:
            raise ExecutorUnavailable("libvirt record image is unavailable")
        self._verify_domain_definition(record, image)
        return True

    def _domain_name_exists(self, domain_name: str) -> bool:
        completed = self._run_virsh("domuuid", domain_name, allow_failure=True)
        return completed.returncode == 0 and bool(completed.stdout.strip())

    def _destroy_domain(self, record: LibvirtBrokerRecord) -> None:
        identity = self._run_virsh("domuuid", record.domain_name, allow_failure=True)
        if identity.returncode != 0:
            return
        if identity.stdout.decode("ascii", errors="strict").strip() != record.domain_uuid:
            raise ExecutorUnavailable("libvirt domain identity changed")
        executor = record.environment.executor
        if not isinstance(executor, VmPerRunExecutor):
            raise ExecutorUnavailable("libvirt record executor is invalid")
        image = self._images.get(executor.image_digest)
        if image is None:
            raise ExecutorUnavailable("libvirt record image is unavailable")
        self._verify_domain_definition(record, image)
        state = self._run_virsh("domstate", record.domain_name, allow_failure=True)
        if state.returncode == 0 and state.stdout.strip().lower() not in {
            b"shut off",
            b"shutoff",
        }:
            self._run_virsh("destroy", record.domain_name)
        self._run_virsh("undefine", record.domain_name, allow_failure=True)

    def _verify_domain_definition(
        self,
        record: LibvirtBrokerRecord,
        image: LibvirtKernelImage,
    ) -> None:
        completed = self._run_virsh("dumpxml", record.domain_name)
        try:
            domain = ElementTree.fromstring(completed.stdout)
        except ElementTree.ParseError:
            raise ExecutorUnavailable("libvirt domain definition is invalid") from None
        invocation = domain.find(f"./metadata/{{{_DOMAIN_NAMESPACE}}}invocation")
        channel = next(
            (
                item
                for item in domain.findall("./devices/channel")
                if (target := item.find("target")) is not None
                and target.get("name") == "org.edagym.control.0"
            ),
            None,
        )
        channel_source = None if channel is None else channel.find("source")
        forbidden = tuple(
            domain.findall(f"./devices/{kind}")
            for kind in ("disk", "filesystem", "hostdev", "interface")
        )
        if (
            domain.tag != "domain"
            or domain.get("type") != "kvm"
            or domain.findtext("name") != record.domain_name
            or domain.findtext("uuid") != record.domain_uuid
            or invocation is None
            or invocation.get("id") != record.plan.invocation_id
            or invocation.get("digest") != record.plan.digest
            or domain.findtext("./os/kernel") != os.fspath(image._kernel_path)
            or domain.findtext("./os/initrd") != os.fspath(image._initrd_path)
            or domain.findtext("./os/cmdline") != image._kernel_arguments
            or channel_source is None
            or channel_source.get("path")
            != os.fspath(self._control_path(record.plan.invocation_id))
            or any(forbidden)
        ):
            raise ExecutorUnavailable("libvirt domain differs from its sealed definition")

    def _destroy_unrecorded_domain(self, invocation_id: str) -> None:
        domain_name, domain_uuid = _domain_identity(self.executor_id, invocation_id)
        identity = self._run_virsh("domuuid", domain_name, allow_failure=True)
        if identity.returncode != 0:
            return
        if identity.stdout.decode("ascii", errors="strict").strip() != domain_uuid:
            raise ExecutorUnavailable("unrecorded libvirt domain identity is ambiguous")
        self._run_virsh("destroy", domain_name, allow_failure=True)
        self._run_virsh("undefine", domain_name, allow_failure=True)

    def _run_virsh(
        self,
        *arguments: str,
        inherited: tuple[int, ...] = (),
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        descriptor = _open_verified_file(self._virsh_path, self._virsh_digest, executable=True)
        os.set_inheritable(descriptor, True)
        try:
            try:
                completed = subprocess.run(
                    (
                        os.fspath(self._virsh_path),
                        "-c",
                        self._connection.value,
                        *arguments,
                    ),
                    executable=f"/proc/self/fd/{descriptor}",
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    env=libvirt_control_environment(self._connection),
                    pass_fds=(descriptor, *inherited),
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                raise ExecutorUnavailable("libvirt control command is unavailable") from None
        finally:
            os.close(descriptor)
        if len(completed.stdout) > 4 * 1024 * 1024 or (
            completed.returncode != 0 and not allow_failure
        ):
            raise ExecutorUnavailable("libvirt control command failed")
        return completed

    def _require_concurrency_slot(self, environment: EnvironmentSpec) -> None:
        active = 0
        for candidate in self._state_root.iterdir():
            if not candidate.is_dir() or candidate.name == ".locks":
                continue
            try:
                invocation_id = _IDENTIFIER_ADAPTER.validate_python(candidate.name)
            except ValidationError:
                raise ExecutorUnavailable("VM broker state contains an invalid owner") from None
            record_path = self._record_path(invocation_id)
            if not record_path.exists():
                continue
            record = self._load_record(invocation_id)
            if (
                record.environment.digest == environment.digest
                and record.phase is not LibvirtBrokerPhase.TERMINAL
            ):
                active += 1
        if active >= environment.resources.max_concurrency:
            raise ExecutorUnavailable("VM environment concurrency limit is exhausted")

    @contextmanager
    def _provider_guard(self) -> Iterator[int]:
        path = self._state_root / ".provider.lock"
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            _PRIVATE_FILE_MODE,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            ):
                raise ExecutorUnavailable("VM provider lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield descriptor
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @contextmanager
    def _invocation_guard(self, invocation_id: str) -> Iterator[int]:
        try:
            normalized = _IDENTIFIER_ADAPTER.validate_python(invocation_id)
        except ValidationError:
            raise ExecutorUnavailable("invalid VM invocation identity") from None
        with self._thread_lock_index:
            thread_lock = self._thread_locks.setdefault(normalized, threading.Lock())
        with thread_lock:
            path = self._lock_root / f"{normalized}.lock"
            descriptor = os.open(
                path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                _PRIVATE_FILE_MODE,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                ):
                    raise ExecutorUnavailable("VM lifecycle lock is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                try:
                    yield descriptor
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _load_record(self, invocation_id: str) -> LibvirtBrokerRecord:
        try:
            content = _read_private_file(self._record_path(invocation_id))
            record = LibvirtBrokerRecord.model_validate_json(content)
        except (OSError, ValidationError):
            raise UnknownJob("VM broker record is unavailable") from None
        if canonical_bytes(record) + b"\n" != content:
            raise ExecutorUnavailable("VM broker record is not canonical")
        if record.capability_digest != self._capability.digest:
            raise ExecutorUnavailable("VM broker record belongs to another capability")
        return record

    def _load_fence(self, invocation_id: str) -> LibvirtFence:
        try:
            content = _read_private_file(self._fence_path(invocation_id))
            fence = LibvirtFence.model_validate_json(content)
        except (OSError, ValidationError):
            raise ExecutorUnavailable("VM lifecycle fence is invalid") from None
        if fence.invocation_id != invocation_id or canonical_bytes(fence) + b"\n" != content:
            raise ExecutorUnavailable("VM lifecycle fence identity is invalid")
        return fence

    def _write_record(self, record: LibvirtBrokerRecord, *, create: bool = False) -> None:
        path = self._record_path(record.plan.invocation_id)
        content = canonical_bytes(record) + b"\n"
        if create:
            _write_exclusive(path, content)
        else:
            descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix="record.")
            try:
                os.fchmod(descriptor, _PRIVATE_FILE_MODE)
                _write_all(descriptor, content)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                os.replace(temporary, path)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                with suppress(FileNotFoundError):
                    os.unlink(temporary)
        _fsync_directory(path.parent)

    @staticmethod
    def _transition(
        record: LibvirtBrokerRecord,
        phase: LibvirtBrokerPhase,
    ) -> LibvirtBrokerRecord:
        return LibvirtBrokerRecord.model_validate(
            {**record.model_dump(mode="python"), "phase": phase}
        )

    @staticmethod
    def _terminal(
        record: LibvirtBrokerRecord,
        result: ExecutionResult,
    ) -> LibvirtBrokerRecord:
        return LibvirtBrokerRecord.model_validate(
            {
                **record.model_dump(mode="python"),
                "phase": LibvirtBrokerPhase.TERMINAL,
                "result": result,
            }
        )

    def _job_directory(self, invocation_id: str) -> Path:
        return self._state_root / invocation_id

    def _record_path(self, invocation_id: str) -> Path:
        return self._job_directory(invocation_id) / "record.json"

    def _fence_path(self, invocation_id: str) -> Path:
        return self._job_directory(invocation_id) / "fence.json"

    def _control_path(self, invocation_id: str) -> Path:
        digest = hashlib.sha256(
            f"{self.executor_id}\x00{invocation_id}".encode("ascii")
        ).hexdigest()
        return self._control_root / f"{digest[:32]}.sock"


def _pack_transfer_tree(
    grant: HostResourceGrant,
    *,
    readonly: bool,
    byte_limit: int,
) -> tuple[VmTransferTree, int]:
    descriptor = grant.fileno()
    metadata = os.fstat(descriptor)
    if stat.S_ISREG(metadata.st_mode):
        content = _read_stable_file(descriptor, metadata, byte_limit)
        return (
            VmTransferTree(
                target=grant.guest_target,
                readonly=readonly,
                root_is_file=True,
                root_mode=_wire_mode(metadata.st_mode),
                root_blob=VmInlineBlob.from_bytes(content),
            ),
            len(content),
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise ExecutorUnavailable("VM transfer root is not a regular file or directory")
    entries: list[VmTreeEntry] = []
    transferred = _pack_directory(
        descriptor,
        prefix=PurePosixPath(),
        entries=entries,
        byte_limit=byte_limit,
    )
    return (
        VmTransferTree(
            target=grant.guest_target,
            readonly=readonly,
            root_mode=_wire_mode(metadata.st_mode),
            entries=tuple(entries),
        ),
        transferred,
    )


def _pack_directory(
    descriptor: int,
    *,
    prefix: PurePosixPath,
    entries: list[VmTreeEntry],
    byte_limit: int,
) -> int:
    before = os.fstat(descriptor)
    names = sorted(os.listdir(descriptor))
    transferred = 0
    for name in names:
        if not name or name in {".", ".."} or "/" in name:
            raise ExecutorUnavailable("VM workspace contains an invalid entry")
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        relative = (prefix / name).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            try:
                if file_identity(os.fstat(child)) != file_identity(metadata):
                    raise ExecutorUnavailable("VM workspace directory changed during transfer")
                entries.append(
                    VmTreeEntry(
                        path=relative,
                        kind=VmTreeEntryKind.DIRECTORY,
                        mode=_wire_mode(metadata.st_mode),
                    )
                )
                transferred += _pack_directory(
                    child,
                    prefix=prefix / name,
                    entries=entries,
                    byte_limit=byte_limit - transferred,
                )
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ExecutorUnavailable("VM workspaces cannot contain links or special files")
        child = os.open(
            name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=descriptor,
        )
        try:
            if file_identity(os.fstat(child)) != file_identity(metadata):
                raise ExecutorUnavailable("VM workspace file changed during transfer")
            content = _read_stable_file(child, metadata, byte_limit - transferred)
        finally:
            os.close(child)
        transferred += len(content)
        entries.append(
            VmTreeEntry(
                path=relative,
                kind=VmTreeEntryKind.FILE,
                mode=_wire_mode(metadata.st_mode),
                blob=VmInlineBlob.from_bytes(content),
            )
        )
    if names != sorted(os.listdir(descriptor)) or file_identity(
        os.fstat(descriptor)
    ) != file_identity(before):
        raise ExecutorUnavailable("VM workspace changed during transfer")
    return transferred


def _read_stable_file(descriptor: int, expected: os.stat_result, byte_limit: int) -> bytes:
    if expected.st_size > byte_limit:
        raise ExecutorUnavailable("VM transfer exceeds its fixed input bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    content = b""
    while block := os.read(descriptor, _TRANSFER_CHUNK_BYTES):
        content += block
        if len(content) > byte_limit:
            raise ExecutorUnavailable("VM transfer exceeds its fixed input bound")
    if file_identity(os.fstat(descriptor)) != file_identity(expected):
        raise ExecutorUnavailable("VM transfer file changed while read")
    return content


def _wire_mode(mode: int) -> Literal[0o600, 0o700]:
    return 0o700 if stat.S_IMODE(mode) & 0o100 else 0o600


def _domain_identity(executor_id: str, invocation_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(f"{executor_id}\x00{invocation_id}".encode("ascii")).digest()
    return f"edagym-{digest.hex()[:32]}", str(uuid.UUID(bytes=digest[:16]))


def _canonical_private_file(path: Path) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ExecutorUnavailable("runtime file must use a canonical absolute path")
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ExecutorUnavailable("runtime file violates its ownership policy")
    return path


def _prepare_private_directory(path: Path, *, parents: bool) -> Path:
    if not path.is_absolute() or (path.exists() and path.resolve(strict=True) != path):
        raise ExecutorUnavailable("VM broker directory must use a canonical absolute path")
    path.mkdir(mode=_PRIVATE_DIRECTORY_MODE, parents=parents, exist_ok=True)
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise ExecutorUnavailable("VM broker directory is not owner-only")
    return path


def _file_digest(path: Path) -> str:
    descriptor = _open_verified_file(path, expected_digest=None, executable=False)
    try:
        return _descriptor_digest(descriptor)
    finally:
        os.close(descriptor)


def _open_verified_file(
    path: Path,
    expected_digest: str | None,
    *,
    executable: bool,
) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ExecutorUnavailable("runtime file cannot be opened safely") from None
    metadata = os.fstat(descriptor)
    digest = _descriptor_digest(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (executable and not metadata.st_mode & stat.S_IXUSR)
        or (expected_digest is not None and digest != expected_digest)
    ):
        os.close(descriptor)
        raise ExecutorUnavailable("runtime file identity changed")
    return descriptor


def _descriptor_digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while block := os.read(descriptor, _TRANSFER_CHUNK_BYTES):
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return f"sha256:{digest.hexdigest()}"


def _write_exclusive(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        _PRIVATE_FILE_MODE,
    )
    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_file(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            or metadata.st_size > VM_PROTOCOL_MAX_FRAME_BYTES
        ):
            raise OSError("unsafe private file")
        content = b""
        while block := os.read(descriptor, _TRANSFER_CHUNK_BYTES):
            content += block
        return content
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    content = bytearray()
    while len(content) < size:
        block = connection.recv(size - len(content))
        if not block:
            raise OSError("short VM guest reply")
        content.extend(block)
    return bytes(content)
