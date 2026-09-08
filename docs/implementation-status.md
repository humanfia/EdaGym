# Configuration-driven runtime implementation status

This branch is an implementation checkpoint, not a completed release.

## Implemented foundations

- Private configuration loading, immutable profile snapshots, generated task
  instances, and run manifests.
- CLI and authenticated loopback browser adapters for task browsing and run
  control. Runs without execution qualification remain explicitly unavailable.
- Configured image probes that resolve the same tool and supervisor entrypoints
  used by rootless execution, including driver-declared supporting programs,
  with durable private closure evidence.
- Profile-derived execution environments with declared tool grants, scoped
  library mount declarations, resource limits, and artifact policy.
- Run manifest v4 freezes the observed participant and evaluator environments,
  including framework source identity. Resume verifies both against the original
  private snapshot and rejects tool, library, or implementation drift.
- Benchmark specifications, schedule and reporting foundations, and external
  participant adapter contracts.
- Removal of framework-owned EDA installation/build paths and unconditional
  KLayout runtime dependency.
- Encrypted private storage for raw EDA diagnostics and evidence, with an
  owner-only key retained across controller restarts.
- Content references and immutable artifact manifests have one model owner,
  independent of journal events and executor types. Their disclosure rules
  derive from the existing environment policy model.
- Run-bound rootless execution with durable launch, container identity, terminal,
  and CAS result receipts. A delegated user scope owns each operation's deadline;
  collection and scoped cleanup survive controller loss.
- Recovery derives resource identity from the prepared operation when launch
  evidence is missing. It fences only that operation's container and scope before
  recording an unknown outcome and terminal infrastructure failure together.
  Retained results preserve reliable execution evidence; a participant operation
  with a lost workspace still terminates the run. Cleanup validates committed
  journal results and CAS directly, without requiring a second result receipt.
- Configuration v2 owns tool visibility per filesystem view. The explicit v1
  importer converts agreeing tool declarations and refuses conflicting modes.
- Complete-image bundle qualification through the configured rootless executor,
  with a retained file inventory, read-only library canaries, private framework
  boundaries, and empty automatic secret mounts. Exact views remain unavailable
  until filesystem exclusion evidence exists.
- Manifest-bound run events and release-trial events use one atomic journal
  storage implementation. RunEngine no longer has a separate JSONL codec.
- Configured queue repair qualification executes its declared reference and
  mutants, validates generated expectations with an independent FIFO checker,
  and binds both view receipts and the resulting run/CAS evidence to admission.
- Qualification runs freeze their view and independent-oracle evidence before
  executing canaries. Resume schedules missing candidates, reuses recorded
  operations, and publishes the resulting instance in one terminal journal
  commit after its evidence files are durable. The qualification receipt binds
  the preceding journal prefix, avoiding a circular digest dependency. Published
  runs can reconstruct missing derived receipts and instance documents; ordinary
  task resume revalidates the retained qualification before advancing.
- RunEngine executes participant tools, freezes edits and candidates, evaluates
  candidate-only synthesis followed by private netlist simulation, and replays
  operation results and workspace checkpoints. The CLI can qualify generated
  instances; the browser can open them and submit the same typed actions as a
  direct agent, including control transfer and cancellation.

## Validation

The full suite reports **325 passed** in 681.10 seconds (exit 0). Retained CLI
checks exercise configuration-based run creation, frozen snapshot recovery, and
cursor replay. Retired help-inventory and `human-turn` tests were removed.
Campaign tests verify complete frozen products without fixed task-role quotas;
release evidence must cover the corresponding frozen trial and task bindings.

Ruff, strict mypy (213 source files), generated schema consistency, and
`git diff --check` pass. Actual rootless synthesis uses configured tool identity
and cgroup limits of 250 millicores, 128 MiB memory, and 32 processes. Icarus
compilation and simulation use the same resolved installation and preserve
successful and failing simulation exit statuses. Concurrent private CAS openers
share a durable encryption key; reopening after key loss refuses replacement.

Actual controller SIGKILL audits recover running, collected, and created
containers, including creation with lost cidfiles. They also recover cancellation
and deadline expiry, retain partial diagnostics, and reread the same CAS result
after cleanup. Unknown runtime exit codes remain absent even when a reliable
timeout or cancellation cause exists. Concurrent runs reject foreign handles;
cleaning one preserves the other, and retained IDs reject replacement containers
with copied labels. No task-owned containers or filesystem mounts remain after
validation. The guest wire contract was updated and formatting checked; no VM,
Slurm, or guest-agent deployment was exercised.

Actual bundle-view audits inventory 8,256 image files and 679 executable files,
including tools and data beyond the API grants. Both views retain read-only
synthetic library attachments. A separate nonempty-parent canary proves that
the secret mount is empty and read-only without modifying its host source.
Four saved qualifications reopened with matching inputs, plans, results,
environment and snapshot bindings, and CAS closure after cleanup. Framework
package paths are refused as library sources. Explicit configuration import
preserves typed credential references while rejecting unknown inline credential
fields. These checks establish view conformance, not task qualification.

Fresh-controller audits reproduced both frozen environments, rejected changed
library content and framework source, and accepted restored library content.
Actual image probes during browser create and resume leave the ASGI event loop
responsive. These audits use unqualified tasks and do not imply execution
qualification or integrated run recovery.

A separate real-tool audit exercised three generated RTL repair references and
thirteen semantic mutants across three difficulty levels. All expected outcomes
were observed through 32 collected and released rootless operations. Synthesis
received only the candidate design; simulation received its netlist and the
private oracle. This proves the tool and artifact handoff, not integrated
RunEngine execution or TaskInstance qualification on its own.

The integrated single-transaction repair audit qualified its reference and all
four declared semantic mutants, rejected the initial broken design, accepted a
repaired submission, executed a participant tool, and replayed the same terminal
result after duplicate submission, resume, and scoped cleanup. Two real HTTP
checks also exercised human/agent handoff, stale-writer rejection, hidden private
files and evaluator events, SSE framing, and cancellation of a running tool.
An actual headless browser opened a qualified instance, rendered its source and
SSE events, saved an edit, invoked a participant tool, saved a checkpoint, and
submitted a passing repair. The terminal editor was read-only and no page script
errors occurred. The initial workspace screenshot was inspected. A fresh-venv
wheel audit verified packaged modules and static assets, installed implementation
identity, every exported schema, initialization, and the loopback web check.

Three additional RunEngine SIGKILL audits interrupted an active tool before
natural exit, before deadline expiry, and during a participant workspace CAS
write. Fresh controllers recovered the same operation and produced completed,
timed-out, and completed results respectively. Repeated resume added no execution
or journal facts, and scoped cleanup completed. These audits do not cover every
interruption point in task qualification or every missing-receipt case.

Two qualification SIGKILL audits interrupted execution between canaries and
after derived evidence files were durable but before publication. Recovery
preserved existing completed operations, finished only missing canaries, and
published a stable result. Operation counts were 2 to 10 and 10 to 10,
respectively. Repeated qualification and reconstruction of a deleted derived
instance document added no journal facts. A retained real-tool check rejects
ordinary task resume when its qualification receipt is missing, then verifies
that the source qualification run reconstructs it without new execution.

Four additional SIGKILL audits remove the launch namespace, the owned container,
the writable storage, or the launch receipt after result collection. The first
three recover the same operation as an unknown outcome and a failed run. The
storage-loss case retains its observed zero exit code without treating it as a
successful run. The collected-result case preserves its completed result.
Repeated resume adds no facts, and scoped cleanup proves container absence.
The retained launch-receipt-loss test also verifies terminal infrastructure
failure without reexecution. An initial full-suite checkpoint failure exposed
the need to separate resource ownership checks from containment-health checks
during cleanup; both checkpoint modes pass in the full regression above.
A separate collected-result audit asserts that its terminal journal fact exists
before the first cleanup call, preserving result publication before resource
release. One later application-checkpoint continuation failed during executor
startup in the release-trial controller. Three further rounds of both checkpoint
modes and 120 concurrent starts, including composite tool/workspace commands,
did not reproduce it. The controller now retains the underlying exception at
debug logging level; that intermittent startup failure remains unresolved.

## Campaign matrix migration

Benchmark and campaign schema version 2 freeze task instances, evaluation cells,
repetitions, and episode budgets. Tasks no longer own harnesses. The benchmark
schedule is the sole owner of ordering and lineage pairing; prepared benchmark
loads verify the entire derived schedule, and campaign trials retain those same
scheduled evaluations. Bootstrap resampling and execution ordering have separate
seeds owned by the benchmark specification.

The campaign header validates the complete frozen inputs and derives the
reservation envelope before opening a journal. Sessions must match the episode
request, token, turn, tool-call, experiment, wall-time, EDA-compute, license, and
artifact limits. Campaign global caps cannot silently reduce those allowances.
Outcome replay also checks the exact task-instance digest.

Campaign cell aggregates and success-at-k preserve harness-specific denominators.
Service-tier accounting compares each attempt with its own requested tier. A
shared integration fixture replaces the old task-owned harness inputs. The
numeric compatibility module is removed; consumers use the canonical domains.
A direct prepared-store probe verified qualification refusal and rejection of a
persisted schedule whose pairing was changed while retaining its benchmark digest.

Validation of the unchanged source covered all 325 tests. The full invocation
completed with 311 passed and 14 failed in 740.81 seconds (exit 1); all 14 failures
occurred while signing Git fixture commits through a stale inherited SSH agent.
Rerunning exactly those tests with the existing signing agent and a command-scoped
key setting produced 14 passed in 7.36 seconds (exit 0). No source changes were
needed between these runs. Ruff, strict mypy over 212 source files, generated
schema checks, and diff checks passed. The real-tool and checkpoint checks passed
in the full invocation; the previously observed intermittent startup failure is
not claimed fixed by that result.

This completes the frozen-matrix migration, not stage F. The current Responses
runtime explicitly refuses native CLI bindings. Native execution, relay/grant
integration, config-snapshot operation references, RunEngine accounting joins,
and campaign concurrency limits remain unfinished. Benchmark inference still
requires harness-separated analysis before real native/controlled comparisons;
the campaign-wide operational summaries are not that inference.

## Typed harness configuration

Configuration schema version 3 replaces the optional-field harness record with
controlled and native CLI branches. Native bindings require an explicit CLI kind,
provider reference, and executable path; controlled bindings reject executable
paths. Human sessions remain harness-free. Snapshot path normalization follows
the native branch, and the config digest domain advances with the schema.

The offline import command owns version conversion for both earlier schemas.
Ambiguous native inputs require correction before import; frozen snapshots are
not rewritten. Inline probes exercised relative-path freezing, required native
inputs, invalid controlled fields, and explicit version 1 and 2 import. No tests
were added for constraints already enforced by the discriminated schema.

Validation on the final source passed the three CLI checks (1.73 seconds) and
four real-tool configured-run checks (300.27 seconds), both with exit 0. Ruff,
strict mypy over 214 source files, schema consistency, and diff checks passed.
An earlier real-tool invocation was invalidated by a concurrent source edit and
rejected by the frozen implementation identity check; it is not passing evidence.

This is a configuration prerequisite for stage F. It does not implement native
execution, relay grants, or the RunEngine campaign consumer.

## Native Responses transport and isolated CLI probes

The Responses sender now has one shared pre-dispatch reservation and settlement
path for ordinary JSON responses and native event streams. The native request
boundary preserves namespace/custom tools, freezes model controls, caps output,
and rejects hosted tools. The Unix relay adds a scoped bearer capability, an
absolute admission deadline, a fixed endpoint, and descriptor-owned socket
cleanup that also works beneath long private state paths. The stream decoder
requires exact terminal usage and rejects unsupported or incomplete receipts.
Observed rejected bodies are retained through the private response observer.

Credential-free experiments ran both installed native CLIs in network-disabled
containers with individual executable mounts, fresh homes, and a Unix-socket
fake provider. Both executed a synthetic command while host paths, host ambient
secrets, and external networking remained unavailable. The Codex executable
closure needed its code-mode companion. The Claude Code probe also observed an
auxiliary title request: top-level episode usage omitted it while per-model usage
included it. The relay must account for such calls at the request boundary.

The native Codex experiment was then routed through the implemented relay and
shared sender with synthetic credentials and a bounded probe ledger. Two upstream
requests completed and their synthetic usage matched the ledger. With the request
cap reduced to one, the second request was refused before reaching the upstream;
the first request's charge remained committed. These are protocol and accounting
experiments, not real model capability canaries or benchmark scores.

The full regression suite passed 332 tests in 757.44 seconds (exit 0). A later
private probe identified that a CLI could copy its relay capability into request
content. The relay now refuses that value in the normalized body before the
observer or provider is called, and its refusal reasons use a closed enum. Only
the relay and its test changed after the full run; all seven affected checks
passed again in 9.55 seconds (exit 0). Ruff, strict mypy over 216 source files,
generated schema consistency, and diff checks passed. No test-owned containers
or mounts remained after validation.

Messages transport, configured native executable admission, credential-source
selection, and the RunEngine campaign/event joins remain unfinished. The existing
campaign dispatcher still refuses native cells. The relay experiments do not
waive that gate or establish native campaign qualification.

## Provider wire identity migration

Provider profiles and resolved provider configurations now use version two.
The profile owns one explicit request path and a closed Responses/Messages wire
configuration. Credential authorization verifies that profile's digest and
projects its authentication and API-version headers. Caller-supplied identity
headers and incompatible Codex credential profiles are rejected. Responses
requests refuse a mismatched protocol before reservation or dispatch.

Generated campaign schemas and existing provider consumers use the new identity.
Old profile documents and their attestations require regeneration and
requalification; no legacy-field fallback is retained. Messages request and
stream parsing, native relay integration, and configured credential-source
selection remain unfinished. This migration does not enable native campaigns.

The focused provider checks passed 33 tests in 14.64 seconds. The subsequent
full suite passed 336 tests in 759.24 seconds (exit 0), with source, test, and
schema identities unchanged during the run. Ruff, strict mypy over 216 source
files, generated schema consistency, and diff checks passed. The new evidence
uses real local TLS to verify profile-bound endpoints and credential headers,
and verifies that protocol mismatch produces neither dispatch nor reservation.
No test-owned containers or mounts remained after validation.

## Remaining integration

- Complete exact-toolset filesystem exclusion qualification.
- Integrate interruptions during view qualification before a task run manifest
  exists. Exercise the broader concurrent-run and corruption matrix, including
  damaged storage records or backing files whose safe reconciliation has not
  been established.
- Investigate the intermittent release-trial checkpoint startup failure.
- Complete participant feedback and artifact presentation beyond the current
  outcome/event view, and broaden the rendered browser interaction checks.
- Migrate the remaining release-trial controllers and projections to RunEngine.
  Shared physical journal storage does not complete that semantic migration.
- Connect harnesses and campaigns to the same engine and collect real benchmark
  evidence. No completed six-model campaign or qualified benchmark is claimed.

Profile projection alone does not qualify a view or make RunEngine executable.
Raw logs, private configuration, tool observations, and runtime artifacts remain
outside version control.
