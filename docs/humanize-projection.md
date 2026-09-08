# Humanize projection

EdaGym exposes Humanize's flow vocabulary as a stateless view of a validated
run journal. It does not embed the Humanize runtime, write a Humanize cycle, or
copy a backend transcript.

The distinction is deliberate. Humanize defines an agent as configuration and
a session as one conversation held across turns. Calling an agent directly
creates a fresh session for that turn; retaining `agent.new()` creates a
stateful session. Humanize also keeps a cycle as the shape of one flow run while
the backend remains the owner of the transcript. These definitions are in the
[Humanize concepts](https://docs.humanfia.ai/humanize2/guide/concepts),
[agent reference](https://docs.humanfia.ai/humanize2/reference/agents), and
[tracing guide](https://docs.humanfia.ai/humanize2/guide/tracing).

## Mapping

`project_humanize(journal, session, audience=...)` derives one
`HumanizeRunProjection`:

| Humanize concept | EdaGym source |
| --- | --- |
| cycle | one validated `RunRecord` prefix |
| agent | one actor in the bound `SessionSpec` |
| fresh session | one deterministic logical session per participant turn |
| stateful session | one deterministic logical session per actor in the run |
| turn | one participant-produced boundary event |
| trace slice | one audience-visible boundary event reference |
| continuation | the parent run identity in the bound `RunLineage` |

A benchmark session always uses fresh sessions and must have empty lineage.
This preserves the benchmark rule that trials do not inherit earlier work. A
training session uses a stateful logical session per actor and carries only its
parent run identity. Checkpoint and candidate lineage remain with the journal.
Logical session identifiers describe the EdaGym view; they
are not backend conversation identifiers and create no resumable model state.

The projected turn is a participant-produced boundary fact committed by
EdaGym, including a participant-visible tool request. Confidential provider
request and response records are not reclassified as visible Humanize turns.

## Reviewer boundary

Humanize's actor-and-reviewer pattern keeps the actor in one session and opens a
fresh reviewer each round. Its reviewer returns structured completion and notes
to the actor. The pattern is documented by
[official/rlar](https://docs.humanfia.ai/humanize2/flows/rlar) and the
[flow reference](https://docs.humanfia.ai/humanize2/reference/flows).

The EdaGym projection retains the fresh-reviewer property but not Humanize's
completion authority. A review is advisory participant input. Only EdaGym's
task-bound evaluators, scoring rules, and terminal journal transition decide
whether a design passed. The projection records this as
`completion_authority = "edagym_verifier"`.

Participant projections admit only `public` and `participant` events. Reviewer
projections additionally admit `reviewer` events. Neither admits `verifier` or
`author` events. The trace allowlist contains run boundaries, participant
interactions, control transfers, candidate submissions, checkpoints, and run
termination. It excludes evaluator jobs, license custody, policy decisions,
provider transcripts, artifact metadata, raw messages, and artifact references.
Projected slice indices are contiguous, so omitted events do not leave journal
sequence gaps as a side channel.

## Identity and ownership

Turn and logical-session identifiers are deterministic digests of their
journal-owned identities. The projection identifier is a digest of the complete
visible cycle projection. Repeating a projection over the same visible journal
prefix produces the same document. Adding only verifier- or author-visible facts
does not alter a participant or reviewer projection.

The journal remains the only runtime ledger. This projection starts no agent,
opens no model session, stores no flow state, reads no sandbox path, and claims
no compatibility with Humanize's cycle or Chrome trace file formats.

## Participant adapter

`HumanizeParticipantAdapter` is the separate execution bridge. It accepts an
already configured object implementing Humanize's documented `AgentBase` and
`SessionBase` call surface. It never imports Humanize, selects a provider,
loads an account, or handles credentials. The adapter passes the canonical
participant view as the prompt and requests one Pydantic
`ParticipantIntentEnvelope`; the normal participant controller validates and
commits that intent.

Benchmark mode calls the injected agent directly for every action, which gives
each turn a fresh session. Training mode calls `agent.new(workspace)` once and
retains that session for subsequent turns. Closing the adapter closes the held
training session. These are the fresh and stateful behaviors defined by the
Humanize agent reference. Course mode is rejected because it has no matching
projection strategy.

The adapter is not an isolation boundary. Its immutable harness contract
requires the `workspace-write` permission rung, and the enclosing EdaGym
environment remains responsible for providing the isolated workspace. The
agent configuration is represented only by a non-secret digest bound into the
session harness. `probe_humanize_runtime()` reports whether the optional `hmz`
module is discoverable without importing or configuring it; an unavailable
probe remains an honest capability downgrade. Every resulting action still
passes through the journal-owned single-writer controller.

Human-only and hybrid handoff runs are separate from the Agent-only benchmark
roster. The browser uses the same `TransferControlIntent`, candidate, feedback,
checkpoint, and cancel events as direct agents; local UI state never decides
who owns a run or whether a result is eligible for scoring.
