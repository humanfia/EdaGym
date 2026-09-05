# Task Contract

`TaskSpec` is the canonical authoring contract. It defines identity, interface,
generator, requirements, resources, visibility, evaluator DAG, measurement
schema, difficulty axes, and qualification rules.

## Identity and derivation

Canonical serialization uses RFC 8785 JSON Canonicalization Scheme bytes and a
domain-separated SHA-256 digest. A `TaskInstance` binds the task digest,
generator digest, 128-bit seed, and typed parameter values. A `ReleaseManifest`
binds the instance, participant and verifier bundles, exact environments, file
digests, and qualification evidence.

`TaskIdentity.origin` is the only task namespace and provenance authority.
Repository-authored tasks default to `native_sealed`. A public dataset enters
through `import_public_calibration_task` with a `public_calibration` origin that
binds its source identifier, source snapshot digest, SPDX expression,
redistribution policy, and provenance. The importer performs no network or
dataset-content I/O. The origin names the exact source resources and derives
only their licenses; native evaluator and scaffold licenses remain independent.

Public calibration tasks may run fresh benchmark-style calibration sessions,
but they cannot produce sealed leaderboard entries or enter model-comparison
campaigns of any scope. Campaign schedules carry the complete
typed origin and validate it again against the resolved `TaskSpec`.

Secondary JSON schemas and readable documents are generated from typed models.
They are validation and interchange artifacts, not competing definitions.

Private authoring implementations live outside the public repository. The
public catalog owns only participant-visible family metadata, exact interface
profiles, difficulty axes, named base and advanced instances, and required
capabilities. A restricted provider derives a typed `TaskSpec` and
`TaskInstance` from those public parameters plus a provider-owned opaque seed
handle. The response binds both documents, the participant and verifier bundle
digests, and a path-free opaque instance reference. Public code validates that
binding; it does not reconstruct an oracle, reference candidate, hidden case,
mutant, testbench, author candidate, or private flow recipe.

The controller accepts a provider only when the measured executable digest,
implementation-closure digest, and complete descriptor digest match trusted
restricted configuration. The descriptor binds qualification evidence for a
rootless container, virtual machine, or microVM candidate boundary, verifier
confidentiality, network confinement, and server-side rejection of replayed
one-shot evaluator nonces. Candidate files cross the evaluator protocol as a
bounded canonical member set rather than through an implicit host path. No
provider locator, credential, seed handle, or evaluator nonce is serializable
as release or journal evidence.

## Visibility and sensitivity

Every resource has an explicit visibility, sensitivity, redistribution policy,
and provenance. Visibility describes who may receive a resource; sensitivity
describes how it must be stored and projected. Public resources must also be
publicly classified and redistributable.

Participant views are derived field by field. Author sources, reference
candidates, hidden cases, private diagnostics, commercial assets, and verifier
implementation details are not copied into the participant bundle. An original
authoring manifest is never exposed as a shortcut for producing a public view.

## Evaluation graph

Evaluator identifiers and stage identifiers are unique. Dependencies must
exist, the graph must be acyclic, and each requirement has one semantic owner.
A hard-gate result controls downstream eligibility. Observation and
optimization stages cannot turn a failed hard requirement into a successful
candidate.

Measurements use closed, typed units. A measurement retains its evaluator,
tool, environment, library or PDK identity, corner, mode, seed, and artifact
provenance in the private run record. Its public provenance target is a
canonical `MEASUREMENT` artifact containing only the measurement identifier,
unit, decimal samples, and deterministic sample seeds. A separate confidential
evidence artifact retains
the link back to raw diagnostics or native reports. Public projections omit
tool, library, PDK, corner, mode, and task-seed identity; they retain only the
typed value, deterministic sample seeds, and sanitized artifact reference. A
scorer is an optional derived view; typed measurements remain the authority.

Each `MeasurementSpec` also owns its repetition count and aggregation rule.
Minimum, maximum, mean, median, and direction-aware worst-case aggregation are
derived from exact rational arithmetic over the journaled decimal samples.
When an average has no finite decimal expansion, the specification's decimal
precision and the fixed round-half-even rule produce one deterministic value.
Scoring is ineligible until every hard gate succeeds and every measurement
producer has a promoting result.

Without a scorer resource, the score is the aggregated raw vector and Pareto
comparison follows each measurement direction. No implicit weighting or unit
conversion is permitted. A scalar score exists only when `TaskSpec` binds an
immutable canonical weighted-sum resource, coefficients, revision, output
direction, and decimal precision. Journal replay derives the scalar again from
the same aggregate vector retained with its result. The scorer does not own or
rewrite raw measurement provenance.

## Qualification

A released task has a known feasibility witness that passes its complete frozen
evaluator graph. Negative candidates must compile or otherwise reach the
semantic joint they are intended to test and then be rejected for the expected
reason. Parser failure, tool failure, and a rejected candidate are different
outcomes.

Sail-rooted RTL families additionally require executable Sail semantics,
independent known answers, a synthesizable reference candidate, compiled RTL
mutants, temporal or structural checks where transaction comparison is
insufficient, and multiple independent RTL frontends. Sail owns architectural
semantics for these families; a host-language model may cross-check it but may
not replace it.

Non-Sail `FlowTaskPack` values are restricted authoring recipes, not runtime
result records and not tracked repository assets. The provider supplies the
pack together with a qualified typed task and instance. Public code checks the
workspace interface, requirements, evaluator graph, measurement ownership,
candidate identities, public difficulty binding, and opaque bundle identities
against that provider output; it never derives the task, seed, or verifier
files from a built-in pack. Every declared tool command must resolve to the
exact capability, tool, and driver in the environment. Supporting tools in a
composite stage are included in the run binding even though one primary
capability owns the stage.

Flow release qualification submits the feasibility witness and every negative
candidate through `RunOrchestrator`. The final `ReleaseManifest` is admitted
only from the resulting hash-chained `RunRecord` values and their verified CAS
closure: the witness must pass the complete evaluator graph, negatives must
reach a semantic rejection, and each candidate snapshot digest must match the
authoring bytes. Direct host evaluation is not release evidence.

## Difficulty

Authoring parameters describe controllable sources of difficulty. Observed
difficulty belongs to the complete tuple of task instance, environment,
participant and harness, feedback policy, and budget. Reports therefore retain
success counts, evaluator funnel, first-success cost, compute time, license
time, and artifact footprint instead of treating an author label as a score.
