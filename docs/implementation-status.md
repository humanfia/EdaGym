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

The full suite reports **324 passed** in 639.08 seconds (exit 0). Retained CLI
checks exercise configuration-based run creation, frozen snapshot recovery, and
cursor replay. Retired help-inventory and `human-turn` tests were removed.
Campaign tests verify complete frozen products without fixed task-role quotas;
release evidence must cover the corresponding frozen trial and task bindings.
After moving publication-group validation to the atomic commit owner, the final
configured-run, CLI, and schema checks report **7 passed** in 258.26 seconds
(exit 0). A direct check confirms that mixed publication groups are rejected
before writing and valid existing publication groups retain their identity.

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

## Remaining integration

- Complete exact-toolset filesystem exclusion qualification.
- Integrate interruptions during view qualification before a task run manifest
  exists. Exercise the broader concurrent-run and corruption matrix, and finish
  typed termination/fencing when operation receipts or writable storage are
  missing.
- Complete participant feedback and artifact presentation beyond the current
  outcome/event view, and broaden the rendered browser interaction checks.
- Migrate the remaining release-trial controllers and projections to RunEngine.
  Shared physical journal storage does not complete that semantic migration.
- Connect harnesses and campaigns to the same engine and collect real benchmark
  evidence. No completed six-model campaign or qualified benchmark is claimed.

Profile projection alone does not qualify a view or make RunEngine executable.
Raw logs, private configuration, tool observations, and runtime artifacts remain
outside version control.
