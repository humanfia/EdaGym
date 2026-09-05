# Release Report

`ReleaseReport` is the canonical release-readiness projection. It combines the
immutable evidence already owned by task authoring, backend qualification,
flow qualification runs, paid campaign journals, repository policy, and
release commands. It does not copy tool logs, task files, provider exchanges,
or other raw evidence.

Each source is represented by its content digest, its mechanically derived
status, and the smallest useful counts. The projection admits only the exact
twenty Sail families and twelve EDA-flow families named by the public catalog.
Private task bytes are supplied by a restricted provider and are never
reconstructed by release reporting. The public task catalog and sealed catalog
attestations are explicit inputs whose digests remain in the report. Sail evidence binds the clean-room audit,
provider descriptor and implementation, every typed `TaskSpec`, both frozen
`TaskInstance` values, both release manifests, and the sealed family
qualification. Flow evidence binds each provider-derived base task and
instance, its public family metadata, exact environment, sealed family and
instance identity, environment-bound candidate attestations, and every
qualification `RunRecord`. Each full candidate resource identity is joined to
its task content-manifest identity and the exact environment-dependent
candidate manifest replayed by the evaluator; a budget stop cannot stand in
for rejection of a negative candidate.

Backend evidence covers an explicitly supplied public backend catalog.
Readiness is based on
logical capability coverage rather than on installation probes: every
capability needs a conformant acceptance/rejection pair, the core simulation,
formal, equivalence, synthesis, timing, implementation, physical-verification,
and circuit capabilities need two independent driver and opaque deployment
attestation identities, and FPGA implementation needs conformant Vivado, Quartus, and
Achronix identities. Optional unavailable tools remain visible without
invalidating coverage supplied by independent conformant tools.

The paid campaign projection accepts the append-only `CampaignRecord`, its
derived `CampaignReport`, and the exact `RouteCanaryEvidence` named by every
route in the model set. It reconstructs the report from the record and checks
each canary's digest, requested and reported model labels, reasoning support,
service-tier observations, and positive token counters against the route.
Release
readiness requires a three-task, one-route, one-repetition end-to-end smoke
campaign, one eight-task pilot, and one eight-task common-core campaign. The
required suite also includes the six-task reasoning-effort sensitivity matrix.
The pilot and common core select the same frozen model routes and share their
other comparison dimensions, model set, provider profile, and provider configuration.
The common core has three paired repetitions by construction. Every trial
needs a comparable terminal outcome and positive provider-reported token
usage. Any dispatched attempt whose usage is unknown makes required campaign
evidence fail; a successful retry cannot hide a potentially billable unknown
attempt. All required campaigns use the Rust.cat Responses-compatible
gateway; requested and provider-reported model labels remain separate facts
and do not establish official hosting. Each required model category is either
covered by a qualified route or carries a typed model-set exclusion; an honest
unavailable category is not relabelled as success and does not by itself fail
EdaGym. Expanded-breadth campaigns remain optional and require separate spend
approval. The six-task reasoning-effort sensitivity campaign is required for
every route whose canary qualified reasoning control. It shares the
pilot/common-core model set, exact task-binding subset, harness, feedback,
per-trial budget, seed, and provider variables while varying the reasoning
effort dimension.

The smoke attestation is a derived projection, not a second run ledger. It
exactly joins all three scheduled `RunRecord` values and their
`CampaignTrialResult` receipts to the campaign journal, task specifications,
instances, releases, environments, and sessions. The joined trials must cover
Sail RTL, synthesis or static timing, and a physical, analog, or FPGA flow.
Exactly one of the three supplied `SessionSpec` values must be a stateful
training session; the other two are fresh sessions. That designated training
trial must show a changed child candidate after a completed workspace write,
controlled feedback followed by another completed provider response, a
committed checkpoint, participant termination and restore, then another
provider response, completed workspace write, settled EDA call, and eventual
hidden-verifier success. The recovery projection binds distinct process,
workspace, and artifact generations to the exact checkpoint manifest. The
public recovery attestation also binds the source RunRecord and live CAS
closure, termination and restoration sequence, and the first post-restore
provider request, EDA invocation, and accepted candidate. Across the three
trials, settled
participant operations must prove both open-source and commercial EDA use.
Participant-owned EDA input is never admitted through the brokered host
executor. For each paid run, release reopens the exact private artifact store
and mechanically verifies candidate snapshots, checkpoints, evidence, and
every declared artifact reference against the journal and environment policy.
The public report retains the closure digest and artifact-class counts, not
private logical artifact names; a caller-supplied portable receipt is not
accepted. Missing recovery,
runtime-surface, CAS-content, or tool-execution proof remains `unavailable`;
task-author qualification runs cannot substitute for paid participant
evidence. ATIF and report projections are rebuilt from the same run journals.

Participant-session evidence is its own gate. It joins one human, one agent,
and one hybrid session run record to its task specification, instance,
release, environment, session, and exact private artifact store, then derives
ATIF, Harbor, NeMo, course, and leaderboard coverage from those journals. An
empty inventory is `unavailable`; a partial bundle is rejected.

The private-root audit is a further gate. Every required private root role,
including the executor deployment registry and the executor qualification
store, must be registered from a live source that release already verified; a
role that no verified source registered stays missing and keeps the report
`incomplete`.

The repository entry preserves every named audit surface and requires complete
release-mode coverage. It owns the exact object format, commit, tree, index,
worktree, ref set, reflog inventory, LFS inventory, and scanned object scope.
A command entry contains the digest of its exact command plan and either
CAS-verified exit evidence, a typed failure, or a typed unavailable reason.
The required command purposes cover an isolated wheel installation, the public
authoring contract, generated schemas, static analysis, the full Python test
suite, the VM guest Go test and build, and final Git state. The authoring
contract command accepts only the canonical machine-readable receipt emitted by
`python -m edagym.authoring contract`; its public catalog digest must equal the
public catalog owner. Focused unit-test commands are not release purposes and
cannot stand in for live isolation, recovery, or participant evidence.

Durable local execution is a separate typed gate. `doctor` and
`release-report` use the same read-only capability probe. Availability requires
trusted `/usr/bin/systemd-run`, `/usr/bin/systemctl`, and `/usr/bin/env`
executables plus a reachable user systemd manager. A missing, mutable, or
untrusted executable and an unavailable user manager are reported with typed
`unavailable` reasons; the local executors are not presented as portable when
that containment boundary is absent.

The decision has three values:

- `ready` means every required release source and coverage rule passed.
- `blocked` means at least one source failed.
- `incomplete` means no source failed but at least one was unavailable.

The model validates every count and partition and derives one status for each
release gate: authoring, backend coverage, flow qualification, paid campaigns,
participant sessions, repository audit, private roots, durable local
execution, and command evidence. Its
domain-separated digest changes whenever an evidence identity, result, or
availability fact changes. Missing canonical inventory cannot become a
vacuous success.

## Command-line projection

`edagym release-report` accepts one explicit public catalog and clean-room
audit; the sealed private-catalog attestation; the Sail task specifications,
instances, release manifests, and instance qualifications; the complete
backend qualification inventory; the twelve flow task specifications, release
manifests, environment-bound candidate attestations, and qualification run
records; paired campaign records and reports; exact route-canary sources; the
three smoke run records, terminal trial receipts, instances, sessions, and
environments; plus one policy-bound CAS for retained command output. It does
not import a private pack registry, resolve a private provider implicitly, or
promote caller-supplied command receipts into release evidence. The repository
release audit, canonical command runner, and local containment probe run in the
same process as the projection. Paid participant evidence is supplied per run: `--campaign-store-root
RUN_ID=PATH` with an optional `--campaign-artifact-key-file RUN_ID=PATH`
reopens the exact private store of each smoke run record, so the CAS-content
proofs above are computed instead of reported `unavailable`. Human, agent, and
hybrid sessions arrive as `--participant-run`, `--participant-task`,
`--participant-task-instance`, `--participant-release`,
`--participant-environment`, and `--participant-session` documents together
with `--participant-store-root RUN_ID=PATH` and an optional
`--participant-artifact-key-file RUN_ID=PATH`. Every store binding must name a
supplied run record whose bound environment owns the store policy; a store
without its run record, or a run record without its store, is rejected.

Executor evidence is `--executor-deployment PATH`, the owner-only executor
deployment registry, and `--executor-qualification PATH`, a
`VmExecutorQualificationSource` document carrying the committed disposable-VM
receipt, its CAS commitment, the exact environment, and one invocation plan
per lifecycle scenario. The receipt is replayed with
`verify_vm_executor_qualification` against the store opened from
`--executor-qualification-store-root PATH` and an optional
`--executor-qualification-key-file PATH`. The private-root audit registers the
executor deployment registry only from that live registry descriptor and the
executor qualification store only from a store that replayed the committed
receipt; omitting either input leaves its role missing rather than passing.
The command emits the canonical report when
all source inventories are structurally complete, then returns status `0` for
`ready`, `1` for `blocked`, or `3` for `incomplete`.

Release command plans contain only a closed purpose-specific argument vector,
the audited repository snapshot, and the actual root-owned executable digest.
The local authority opens `/usr/bin/git`, `/usr/bin/python3.12`, and
`/usr/lib/golang/bin/go` without following symlinks, executes the opened file
descriptors directly, and verifies their content identities before and after
use. Every invocation starts in a new process group. A timeout sends `TERM`,
then bounded `KILL`, and reaps the leader so child processes cannot outlive the
receipt.
Python checks additionally bind the receipt and content inventory of the clean
wheel installation used for imports. Receipts bind timestamps, exit status,
and stdout, stderr, and manifest blobs in the exact CAS; status is derived from
those facts and the CAS closure is rechecked during report projection. Output
bytes, commercial diagnostics, credentials, and private paths do not enter the
report.
