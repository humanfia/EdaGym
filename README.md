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

## Configuration-first runtime

EdaGym supplies the framework and typed contracts. Users supply EDA tools,
libraries, runtimes, credentials, and model routes through one private TOML
file; the package does not install, download, build, or redistribute them.

```text
edagym init --config ./edagym.private.toml --root ~/.local/share/edagym
edagym --config ./edagym.private.toml config check
edagym --config ./edagym.private.toml web serve --check
```

The default web entry point is loopback-only and uses a bearer token stored in
an owner-only file. Task generation, run control, browser actions, and direct
agent actions share `TaskInstance`, `RunManifest`, `RunJournal`, and typed
intent contracts. A missing tool or qualification is reported as unavailable.

Framework readiness, station campaign completion, and benchmark quality are
separate evidence-derived states. No mock, smoke run, or capability inventory
is presented as a real six-model Agent-only result.
