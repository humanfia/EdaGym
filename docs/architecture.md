# Architecture

EdaGym is a task, execution, and evidence runtime for electronic design
automation. Its core is deliberately independent of any model provider, EDA
vendor, scheduler, or course platform.

## Semantic owners

Four records own runtime truth:

- `TaskSpec` owns the problem contract, generated-input domain, resource
  visibility, evaluator graph, hard requirements, and measurement schema.
- `EnvironmentSpec` owns the executor, exact tool and asset bindings, network
  and filesystem policy, resources, license channels, artifact policy, and
  checkpoint capability.
- `SessionSpec` owns the participant mode, actors, single-writer control,
  feedback policy, recovery policy, and budgets.
- `RunRecord` owns the immutable run binding and its append-only event history.

Task instances and release manifests are deterministic derivatives of a
`TaskSpec`. Resolved run bindings freeze the selected task instance, release,
environment, session, evaluators, and trial identity. Reports and ecosystem
formats are projections from the journal; none is allowed to become a second
runtime ledger.

Release readiness is also a projection. `ReleaseReport` references immutable
authoring, backend, flow-run, campaign, repository-audit, and command evidence
by digest, validates their status partitions, and derives one decision. Raw
logs and other source facts remain with their existing owners.

## Protocols

Participants implement one operation:

```text
next_intent(ParticipantView) -> ParticipantIntent
```

An intent records an interaction, submits an immutable candidate, or transfers
the single-writer lease. Human, command, Responses-compatible, and hybrid
participants share this boundary.

`CalibrationCommandChannel` runs a frozen wrapper inside the rootless participant
image already bound by `EnvironmentSpec`. The host command is always Podman
with fixed isolation flags. The exact runtime binary, image, absolute wrapper
entrypoint, arguments, scaffold asset, route, actor, and run are digest-bound
before launch. The wrapper receives a fixed non-secret process environment,
task networking is disabled, and only content-verified participant assets are
visible. Its writable workspace has a durable run-bound inode manifest and is
disjoint from the journal, artifact store, and credential configuration. One
canonical view and one bounded intent cross standard input and output.

The calibration transport is absent from paid campaign interfaces. It has no
provider dispatch or usage-accounting authority. `CampaignTask` instead requires
a `MeteredProviderHarnessBinding` tied to the campaign header's provider profile,
configuration, and wire protocol. Campaign replay also requires the run's
provider request facts to match the settled dispatch requests and usage. The
calibration container owner is written durably before launch and recovered by
the next exclusive channel owner after a crash. Both its turn limit and the
remaining run wall budget constrain the deadline.

`ParticipantSessionProjection` accepts only a `ParticipantController`; callers
cannot submit a `ParticipantView`. Each action is therefore derived from the
current journal state, committed through the controller, and returned as a
strictly typed digest-only projection. `ParticipantProjectionRegistry` permits
one such projection per run. This generic projection deliberately claims no
third-party session API compatibility.

`project_humanize` is a separate, stateless journal projection. It maps bound
benchmark sessions to fresh logical sessions and training sessions to stateful
logical sessions, exposes participant actions as turns, and produces an
audience-bounded trace of event references. Its reviewer view stops at reviewer
visibility and remains advisory; it cannot read verifier or author facts and
cannot decide task success. It writes no Humanize cycle or backend transcript.

`HumanizeParticipantAdapter` is the corresponding optional execution bridge.
It drives an injected Humanize-compatible agent directly for fresh benchmark
turns or through one retained session for stateful training turns, requests the
canonical structured intent envelope, and commits no state outside the normal
controller. `CodexExecParticipantAdapter` similarly compiles a benchmark view
into one fixed ephemeral non-interactive invocation. Its injected transport
owns executable deployment and credentials; participant content cannot alter
the argument vector. Neither adapter is an executor or a campaign credential
owner.

`edagym run human-turn` exposes the same boundary to a person over one bounded
JSON line. The active writer must be a human actor bound to that exact adapter.
A hybrid transfer therefore changes the single writer only through a journaled
`transfer_control` intent.

Evaluators implement two operations:

```text
prepare(EvaluationContext) -> InvocationPlan
evaluate(EvaluationContext, ExecutionResult, EvaluationArtifacts) -> StageResult
```

`prepare` binds a candidate and evaluator revision to a sealed tool invocation.
`evaluate` converts trusted execution evidence into a typed outcome and typed
measurements. A participant statement that work is complete is only a
submission; evaluator evidence decides acceptance.

Restricted task authoring is a separate path-free protocol. The public
repository owns the exact family catalog and wire schemas, while a controller
accepts an external provider only against trusted executable,
implementation-closure, and descriptor digests. The provider supports catalog
export, scoped derivation, instance qualification, evaluator opening, and
evaluation. Derivation uses a public family, named difficulty values, and a
provider-owned opaque seed handle. It returns typed task and instance documents
bound to an opaque reference; the public runtime validates those documents and
never regenerates hidden authoring content.

An evaluator open returns a journal-safe descriptor and an authenticated nonce
held only by a non-copyable, non-serializable in-process lease. Evaluation
consumes that nonce exactly once and transports a bounded canonical candidate
member set, not a host path or implicit content-store locator. The provider's
descriptor binds evidence that replay is rejected server-side and that
untrusted HDL, scripts, and tool inputs execute in a rootless container,
virtual machine, or microVM without exposing verifier assets. Only typed stage
results and digest-only evidence cross back into the journal.

Catalog members carry explicit public, participant, verifier, author-evidence,
or flow-pack roles. Participant and verifier role-manifest digests are
recomputed against each opaque instance. Materialization uses descriptor-bound
no-follow file operations, stable bounded reads, owner-only directories, and
an atomic sibling rename. A private catalog destination inside any Git
worktree is rejected even when ignored.

An optional task-bound scorer is a canonical weighted-sum definition:

```text
scalar = intercept + sum(coefficient[measurement] * aggregate[measurement])
```

`TaskSpec` binds its terms, output direction, precision, canonical JSON resource,
and derived revision. The core evaluates it only after journal-derived hard-gate
and measurement eligibility succeeds. Otherwise the runtime records the
aggregate vector as a Pareto score. A typed scoring decision is appended before
terminal success; journal replay recomputes eligibility, every aggregate, and
the optional scalar from the authoritative stage results. Scoring therefore has
no separate process, credential, lifecycle, or trust boundary.

EDA-flow stages may carry an immutable composite recipe. The broker validates
each command against the resolved environment, passes the resolved recipe to a
trusted supervisor through a sealed memory file, and executes each argument
vector without a shell in one executor job. This preserves the workspace across
compile, implementation, and generated-program invocations. The supervisor's
per-command identities, exit codes, and stream digests are retained as a CAS
report, while the evaluator interprets acceptance rules from CAS bytes rather
than mutable host paths. Licensed native reports and streams remain encrypted
author evidence; only the evaluator's canonical `MEASUREMENT` artifact may use
a participant or public disclosure rule.

## Composition

The runtime composes three independent adapter layers:

```text
participant adapter
    -> journal-backed controller
    -> evaluator DAG
    -> tool driver
    -> executor
    -> EDA process
```

Tool drivers own command planning and result interpretation. Executors own the
isolation and lifecycle of processes. Evaluators own task-specific acceptance
semantics. Keeping these roles distinct allows one task to use different EDA
implementations without copying its objective or verifier.

Correctness and feasibility stages are hard gates. Optimization measurements
are retained in their native domains with tool, library, corner, mode, unit,
seed, and provenance. Cross-tool reports may compare behavior and trends but do
not merge unlike metric domains.

Leaderboard entries project measurements and scores only for the candidate
named by a public verifier-success event. Failed and incomplete candidates
remain journal evidence but cannot enter candidate ranking. Partition-level
success rates still count every structurally valid declared trial.

## Durable execution

The journal is sequence-checked, hash-chained, and replayed into run state. The
artifact store is content-addressed and policy-bound. A durable checkpoint is a
committed manifest whose complete blob closure can be verified. Process
survival, a scheduler retry, or a partially written directory is not a
checkpoint.

Filesystem and application restore are transactional: a verified tree is built
in a private sibling and published with an atomic no-replace rename.
Application capture additionally requires a driver digest, exact database path
set, and a promoting result at a declared evaluator boundary. VM recovery needs
an executor-owned memory and disk snapshot. These capabilities never fall back
to another checkpoint kind when their lifecycle is unavailable. An interrupted
restore leaves no partial destination; its owner-only staging tree is retained
because automatic pathname cleanup is unsafe in the presence of another
same-UID process.

The runtime derives stop decisions from journal facts and hard budgets. It
keeps terminal reason separate from evaluation outcome so timeout, license,
infrastructure, candidate, and security failures remain distinguishable.

Rootless invocation plans bind their run identity in the v2 invocation digest;
handles therefore cannot alias equal operation names in different runs. A
private launch receipt precedes Podman creation. Container identity and labels
bind the plan, run, and frozen environment, and a retained container ID prevents
cleanup from adopting a replacement with copied labels.

Rootless payloads and conmon occupy the invocation's delegated systemd scope.
That scope owns the wall deadline. Kernel cgroup membership is captured while
the payload is alive, so recovery can prove that the complete scope is empty
even if conmon died before updating Podman's cached state. A known timeout or
cancel may have no exit code; a missing container without a reliable outcome
remains an infrastructure failure. The composite supervisor streams both
diagnostic channels so interrupted commands retain their partial output.

The executor publishes a canonical terminal observation and then a complete
CAS result receipt. Collection can be retried across controller loss. The
caller must commit that result to its journal before releasing the container
and storage. Cleanup retains result and identity receipts, allowing later
reads to verify the same CAS closure. Resource ownership checks are independent
of containment-health checks: a matching container ID and frozen labels permit
targeted cleanup even when execution isolation can no longer be established.
Unknown outcomes require fencing before the terminal failure is journaled.

## Paid campaign accounting

`BenchmarkSpec` owns the cases, model/harness/policy cells, repetition count,
and episode solving budget. Its request, token, turn, tool-call, experiment,
wall-time, EDA-compute, license, and artifact limits are checked against the
session before dispatch. `CampaignSpec` references that benchmark digest and
owns aggregate reservation limits. `CampaignBudgetProjection` derives the
combined envelope from the frozen header; it does not maintain competing
per-episode settings.

`CampaignRunner` is the accounting owner for a scheduled campaign. Every
external dispatch records its worst-case resource reservation in a private,
hash-chained campaign journal before the side effect begins, then records
provider-reported or measured settlement. Reports replay that durable event
stream; process-local projections are never accounting authorities. A restart
conservatively charges dispatched reservations whose final usage is unknown and
cancels reservations that never reached dispatch.

`CampaignHeader` freezes the benchmark, qualified model set, task bindings,
cell bindings, provider configuration, and derived schedule together. Tasks own
no harness. Scheduling interleaves the declared cells within each task and
repetition; the benchmark schedule seed, lineage block, and repetition determine a shared
paired seed. Campaign trials retain their canonical `ScheduledEvaluation`; the
benchmark preparation and campaign dispatch paths share one schedule builder.
Pilot and common-core scopes no longer impose a fixed task count.
Every completed outcome carries the exact scheduled instance, environment,
harness, route, reasoning effort, service tier, and repetition. Cell aggregates
and success-at-k keep different harnesses separate, while requested and reported
service tiers are counted from individual attempts. Campaign-wide summaries
remain operational accounting, not benchmark inference.

The campaign specification, benchmark, header, schedule, and report use version
2. Harness bindings form a closed controlled-provider/native-CLI union. The
current Responses dispatcher explicitly refuses native bindings; native CLI
execution through RunEngine remains integration work.

The provider transport consumes `CampaignProviderBudget`, an adapter over the
same runner; it does not keep a second campaign ledger.
`StandaloneProviderBudget` is limited to bounded provider probes that precede a
campaign and is bound separately in the credential-isolation attestation.

`edagym campaign run` and `edagym campaign resume` execute a frozen proposal
from one canonical request document. The request names the proposal, the
harness instruction, the restricted authoring provider with its three trusted
digests, the materialized flow catalog root, the backend and executor
deployment registries, the container engine and the rootless-image tool
recipes, host asset paths, the artifact store root with an optional key file,
the state root, and the exact environment and session documents. The frozen
provider configuration is the only credential profile. Preparation resolves
every campaign task to its provider-qualified release, participant files, and
evaluator runtimes before any credential or journal is touched; a family
without an in-process evaluator runtime is refused as unavailable.

Each pending trial is then admitted by the host boundary: a rootless executor
created from the deployment registry, the synthetic-secret preflight that
issues the trial's canary attestation, and the metered Responses sender the
broker opens only against that attestation, the credential source, and the
runner's budget binding. `CampaignTrialDispatcher` performs the dispatch. Run
requires an event-free campaign journal; resume reopens the same journal,
admits only trials without a terminal outcome, and lets the dispatcher adopt
durable work reservations and run journals, so an interrupted trial continues
instead of being dispatched twice. A cap reached before dispatch ends every
unfinished trial with that typed stop reason; any other failure is a typed
refusal naming the trial. Trial receipts are rebuilt from the campaign and run
journals rather than stored again, and the campaign report exists only when no
trial is pending. One exclusive lock per state root refuses a concurrent
operation instead of queueing it.

## Extension rules

A new backend is admitted only with an executable fixture and typed evidence.
A new task family defines semantics and reuses existing capabilities. A new
executor implements the existing execution protocol. A new report consumes the
journal. Extensions must not add parallel task schemas, process runners,
scoreboards, or event stores.

The current control-plane boundary is `RunEngine`: browser, CLI, and agent
adapters submit the same typed intents and read cursor-based projections. A
private TOML configuration resolves user-owned tools and libraries into one
immutable snapshot referenced by each `RunManifest`; execution views are
derived from that snapshot. A version-4 manifest freezes both observed
`EnvironmentSpec` projections, including tool deployment attestations, runtime,
resources, library content identities, and artifact policy. The original
configuration digest remains unchanged when the selected snapshot is resolved
again. An unavailable run can lack execution projections; resume never fills
them from a later configuration.

`project_environment` derives executor identity from the installed framework
source and the observed container runtime. The framework identity covers the
complete Python package and controller Python version, so implementation
changes require a new run. `RunEngine.resume` rechecks tool closures and bounded
library sources against the frozen projections before admitting continuation.
Private paths remain in the configuration snapshot. Older control-plane
manifests are not upgraded implicitly.

The manifest also distinguishes task runs from qualification runs. Both use
the same typed operation facts and the same `RunJournal`. A prepared operation
binds its input manifest and filesystem view; its running fact binds the
executor handle; its terminal fact binds collected results and any resulting
participant workspace. Cancellation is a journaled command that the active
controller observes without surrendering its controller lock.

Recovery never relaunches an operation whose launch evidence has disappeared.
It derives the container identity from the prepared operation, fences its
resources, and atomically records an unknown operation result with a failed run.
Reliable retained results remain distinguishable from unknown outcomes, including
their observed exit codes. Losing a participant workspace terminates the run even
when its tool result survived. Once committed, the journal and CAS own that
result; cleanup does not require the executor's secondary result receipt.

`journal_storage` owns atomic metadata publication, canonical grouped commits,
hash chains, file locks, and recovery of a torn final record. The release-based
campaign workflow currently retains its own replay semantics in `trial_model`
and `trial_journal`, using that same physical storage owner. These trial
consumers still need migration to RunEngine; the module separation does not
claim that campaign integration is complete.

Queue repair qualification executes every declared reference and mutant through
RunEngine. Candidate-only synthesis produces a netlist for a separate private
monitor operation. An indexed FIFO checker independently validates the
generator's deque-derived expectations. Admission reopens the qualification
run, both view receipts, and their CAS evidence. Editing, submission, and
browser control transfer consume these same run contracts.
Qualification manifests bind their view and independent-oracle evidence before
canary execution. A terminal publication binds the completed canary journal
prefix after derived evidence and instance files are durable. Resume reuses
completed operations, schedules missing canaries, and can rebuild those derived
files from the published journal.

These bindings do not confer tool-visibility or task qualification. Framework
readiness, station campaign completion, and benchmark quality remain
independent evidence states.
