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
- Run manifest v2 freezes the observed participant and evaluator environments,
  including framework source identity. Resume verifies both against the original
  private snapshot and rejects tool, library, or implementation drift.
- Benchmark specifications, schedule and reporting foundations, and external
  participant adapter contracts.
- Removal of framework-owned EDA installation/build paths and unconditional
  KLayout runtime dependency.
- Encrypted private storage for raw EDA diagnostics and evidence, with an
  owner-only key retained across controller restarts.
- Run-bound rootless execution with durable launch, container identity, terminal,
  and CAS result receipts. A delegated user scope owns each operation's deadline;
  collection and scoped cleanup survive controller loss.
- Configuration v2 owns tool visibility per filesystem view. The explicit v1
  importer converts agreeing tool declarations and refuses conflicting modes.
- Complete-image bundle qualification through the configured rootless executor,
  with a retained file inventory, read-only library canaries, private framework
  boundaries, and empty automatic secret mounts. Exact views remain unavailable
  until filesystem exclusion evidence exists.

## Validation

The full suite reports **321 passed** in 373.90 seconds (exit 0). Retained CLI
checks exercise configuration-based run creation, frozen snapshot recovery, and
cursor replay. Retired help-inventory and `human-turn` tests were removed.
Campaign tests verify complete frozen products without fixed task-role quotas;
release evidence must cover the corresponding frozen trial and task bindings.

Ruff, strict mypy (207 source files), generated schema consistency, and
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
RunEngine execution or TaskInstance qualification.

## Remaining integration

- Complete exact-toolset filesystem exclusion qualification and integrate view
  receipts into run admission and recovery.
- Bind generated reference/mutant qualification to the execution workflow.
- Connect RunEngine tool, edit, and submit operations to execution and recovery;
  consolidate the existing journal implementations into one semantic owner.
- Validate crash recovery, concurrent runs, scoped cleanup, and browser handoff
  through that integrated workflow.
- Connect harnesses and campaigns to the same engine and collect real benchmark
  evidence. No completed six-model campaign or qualified benchmark is claimed.

Profile projection alone does not qualify a view or make RunEngine executable.
Raw logs, private configuration, tool observations, and runtime artifacts remain
outside version control.
