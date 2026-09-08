# Configuration-driven runtime implementation status

This branch is an implementation checkpoint, not a completed release.

## Implemented foundations

- Private configuration loading, immutable profile snapshots, generated task
  instances, and run manifests.
- CLI and authenticated loopback browser adapters for task browsing and run
  control. Runs without execution qualification remain explicitly unavailable.
- Configured image probes that resolve the same tool and supervisor entrypoints
  used by rootless execution, with durable private closure evidence.
- Profile-derived execution environments with declared tool grants, scoped
  library mount declarations, resource limits, and artifact policy.
- Benchmark specifications, schedule and reporting foundations, and external
  participant adapter contracts.
- Removal of framework-owned EDA installation/build paths and unconditional
  KLayout runtime dependency.

## Validation

The full suite reports **316 passed** in 305.87 seconds (exit 0). Retained CLI
checks exercise configuration-based run creation, frozen snapshot recovery, and
cursor replay. Retired help-inventory and `human-turn` tests were removed.
Campaign tests verify complete frozen products without fixed task-role quotas;
release evidence must cover the corresponding frozen trial and task bindings.

Ruff, strict mypy (204 source files), generated schema consistency, and
`git diff --check` pass. The four executor boundary tests pass, including actual
rootless synthesis using configured tool identity and limits. The container
checks cgroup limits of 250 millicores, 128 MiB memory, and 32 processes.

## Remaining integration

- Complete positive and negative tool-visibility and library-view qualification.
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
