# Environment Contract

`EnvironmentSpec` is the canonical description of everything allowed to execute
or become visible during a run. It binds an executor, tool installations,
assets, network policy, resources, license channels, checkpoint capability, and
artifact retention policy.

## Tool resolution

A tool binding names one logical capability and one backend. Resolution freezes
the driver revision and exact tool version. A host locator exposes only an
executable basename and one opaque deployment-attestation digest; module names,
host paths, environment values, and closure topology remain deployment-private.
An image locator additionally binds its immutable OCI digest. The same
deployment-attestation digest is copied into the resolved run binding, so a run
record cannot introduce a competing version or closure identity. Detection only
means a candidate installation was found. Invocation means a safe metadata probe
succeeded. Support is advertised only when a real workload and its negative case
produce conformant typed evidence.

The executor fixes the locator domain. Brokered host environments admit only
attested host locators. Rootless, VM, microVM, and Slurm environments admit only
image locators whose image digest equals the executor image digest. Invalid
cross-boundary combinations cannot become canonical environment identities.

Upgrading a tool invalidates qualification because version, driver, fixture,
parser, and closure identities are part of the evidence.

## Execution profiles

- Rootless local execution is the isolation boundary for participant-controlled
  open-tool work. It uses a digest-pinned image, an unprivileged runtime,
  read-only root filesystem, no capabilities, no-new-privileges, no ambient
  credentials, an explicit network policy, and bounded resources. Composite
  evaluator recipes and their supervisor enter through executor-owned read-only
  control mounts, never through the participant workspace.
  Payloads and the container monitor remain inside one delegated invocation
  scope, which enforces the wall deadline and retains its termination reason.
  Podman logs have an explicit byte limit derived from artifact policy.
- Brokered host execution keeps the participant separate from a trusted,
  registered EDA recipe. It is suitable for sealed commercial evaluation.
- Both local profiles supervise each invocation through the user systemd
  manager. They require root-owned executables that are neither group- nor
  world-writable: `/usr/bin/systemd-run`, `/usr/bin/systemctl`, and
  `/usr/bin/env`.
  The shared read-only capability probe reports a typed unavailable reason when
  any prerequisite is absent or the user manager cannot be reached; construction
  never falls back to an unsupervised child process.
- VM-per-run execution is the isolation target for untrusted interactive code
  that must use commercial tools or private assets. The concrete session
  libvirt broker admits no network device, disk, host mount, snapshot, or
  credential proxy. Its guest accepts transfers only below the fixed
  `/edagym` run namespace, keeps the root control agent and virtio channel
  inaccessible to the unprivileged command uid, and returns descriptor-safe
  declared outputs through the artifact store.
- Slurm and Apptainer provide scheduling and packaging for a controlled HPC
  domain; they are not presented as a cross-tenant security boundary. The
  Slurm executor therefore admits evaluator and tool views only, requires a
  no-network environment, disables inherited host mounts and environments,
  and binds each scheduler allocation to one EdaGym invocation identity.
  Controller restart recovery uses the private durable submission record plus
  the scheduler-owned job name and comment. An uncertain submission is
  cancelled and proven absent before the journal may recover past it. Licensed
  jobs remain unavailable until a trusted scheduler-side credential bridge is
  bound; controller license values are never written into a batch script.
  `site_policy_digest` is the external attestation owner for the remaining
  trusted-site assumptions: shared controller/compute paths, owner-only locked
  parents, workspace quota enforcement, accounting visibility, immutable image
  publication, and a qualified image helper closure containing `/bin/sh` and
  `/usr/bin/env`. The worker binds fresh node-local directory identities and
  revalidates every pathname immediately before Apptainer starts; it does not
  claim resistance to a hostile process with the scheduler user's uid. Such a
  site is unavailable for participant isolation even when its packaging canary
  passes.
- Cloud or local microVM implementations may implement the same executor
  protocol without changing task or run semantics.

Unsupported host capabilities are explicit. An environment that requests a
stronger isolation or checkpoint profile than the executor can provide is
rejected rather than silently downgraded.

A VM broker owns the durable namespace for every per-run machine, writable
layer, and guest control channel. Executor recovery succeeds only when the
capability-bound broker returns an observation for the exact invocation with
no remaining resources. The same authoritative query makes cleanup of an
already absent invocation idempotent. A controller process restart is covered
by this boundary; it is not represented as a host reboot or a VM snapshot.

## Files and network

The participant receives a writable private workspace plus exact read-only
assets. Broad host and site-storage roots, control sockets, host PID or IPC
namespaces, arbitrary devices, and privileged containers are forbidden. Asset
resolution constructs a minimal closure; a path merely existing on the host
does not authorize mounting it.

Network access defaults to none. Any allowed endpoint belongs to a typed policy
enforced outside the guest. Environment variables and prompts are not security
controls. The verifier uses a separate identity, mount view, and network policy.

## Licenses

Commercial licenses are acquired by a trusted `LicenseProvider`. Participants
receive neither license variables nor files. A lease exposes only an opaque
identity and records tool, feature class, wait duration, state, and lifetime.
Cancellation and timeout release the lease. License rejection or loss is not a
candidate failure.

## Persistence

Checkpoint capability is closed and explicit: none, application database,
quiescent filesystem, or VM snapshot. The capability states what can be
restored, not what happens to be present after a crash.

An application checkpoint binds a driver digest, a non-overlapping path set,
and admitted evaluator boundaries. It captures only that tool-declared durable
database after a promoting result at one of those boundaries. A filesystem
checkpoint contains the complete stable regular-file tree while no evaluation
job is active; it makes no claim about process memory, open descriptors,
license sessions, or remote services. Both forms restore through a verified
private staging tree and an atomic no-replace publication. A VM checkpoint must
contain executor-managed guest memory and disk state. VM recovery remains
unavailable until an executor owns its capture and restore lifecycle.

Artifact policy decides which class and disclosure combinations may persist.
The content-addressed store verifies policy and digest on every read. Garbage
collection follows the complete reachable manifest closure and must respect
committed checkpoint pins and active restore leases.

`DIAGNOSTIC` and `EVIDENCE` own raw execution streams and native tool reports;
`MEASUREMENT` owns only canonical typed numeric results produced by the trusted
evaluator. Any environment with a license binding requires managed encryption
and confidential, author-only, non-redistributable disclosure for both raw
classes. Its measurement rule may independently permit participant or public
disclosure. Credential patterns are rejected for every class. Host paths,
network endpoints, and license routes are rejected before any non-author
artifact is committed.

EDA software, technology libraries, device models, and images are external
inputs. EdaGym records logical asset IDs and digests, but does not package or
install those assets. `user_image` is a digest-pinned image the user already
owns; `installed_tree` is a later site-owned closure contract. Missing assets
produce an explicit unavailable result. Participant and evaluator views are
separate and are derived from the selected private profile.

`config.execution.project_environment` derives grants, read-only library mounts,
resource limits, and artifact policy from the frozen profile. It checks the
snapshot, view, installation, and runtime identities against the tool probe
receipts. This projection is input to execution qualification; it does not itself
establish tool visibility or qualify a task. Library source paths and the storage
root stay in the private resolved profile.

Runnable profiles explicitly set positive `cpu_millicores`, `memory_bytes`,
`process_count`, `wall_seconds`, `storage.max_bytes`, and
`storage.output_max_bytes`. CPU millicores limit the CPU rate. The distinct
`cpu_seconds` cumulative budget and `storage.max_inodes` are currently unsupported
by this projection and cause typed admission failures when nonzero. Zero resource
values mean unconfigured, never unlimited. Artifact retention comes from
`storage.retention_seconds` (30 days by default). Raw diagnostic and evidence
artifacts use the existing confidential, author-only disclosure policy and local
managed encryption. Other evaluator artifacts retain verifier visibility.
`ContentAddressedStore.open_private` keeps a mode `0600` key beside each private
CAS; the key is not an artifact and cannot be regenerated for an existing store.
The raw artifact policy still rejects credentials. Unsupported networking,
verifier trust, and tool environment
references likewise fail explicitly. Relative paths are resolved in the snapshot
before deriving either view.

Configured image probes resolve the selected executable inside the pinned image,
check its bytes and version, and return that same installation to the rootless
executor. The observed launcher entrypoint also selects the interpreter used by
composite execution; tools in one view must agree on that image and interpreter.
Backend definitions own supporting executable names, such as Icarus `vvp`.
The shared image probe resolves and hashes those programs alongside the primary
executable. One closure digest binds their entrypoint set; composite commands can
select only a driver-declared program from that set and use its observed absolute
path. A missing supporting program makes the installation unavailable.
The configured tool ID and the adapter ID are distinct: a logical
`synthesis` binding can use the `yosys` adapter without changing adapter identity.
Image package inventories remain optional additional evidence; when a deployment
declares one, its content and checksum are still verified. A successful version
and launcher probe remains `probe_only` until the view and workload canaries pass.
