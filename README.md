# EdaGym

EdaGym is a reproducible task, execution, and evaluation runtime for electronic
design automation. It supports human participants, software agents, and explicit
human-agent handoffs without making a particular agent harness or EDA vendor part
of the core model.

The project is built around four sources of truth:

- `TaskSpec` defines a task, its generated instances, visibility boundaries,
  evaluator graph, constraints, and measurements.
- `EnvironmentSpec` resolves executors, toolchains, libraries, network policy,
  resources, licensing, and persistence.
- `SessionSpec` defines participant control, feedback, and budgets.
- `RunRecord` is the immutable identity and append-only evidence for one run.

Correctness and feasibility are hard gates. Optimization metrics remain typed raw
measurements; scalar rewards and reports are derived projections. A tool backend
is advertised as supported only after its real qualification fixture passes.

Raw runs, credentials, proprietary assets, and the local `temp/` directory are
never source-controlled.

`edagym backend list` is a candidate inventory, not a support claim. Support
requires a persisted `conformant` result from `edagym backend qualify` with
paired evidence for each requested capability.
