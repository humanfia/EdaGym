# External participant channels

External runtimes are adapters around the canonical participant operation:

```text
ParticipantView -> ParticipantIntent
```

They do not own session state, task truth, evaluator feedback, credentials, or
the run ledger. Their output is untrusted until the participant controller has
validated the active actor and committed the intent to the journal.

## Non-interactive CLI channel

`CodexExecParticipantAdapter` provides a fresh benchmark-only compatibility
channel for the documented non-interactive CLI. Its immutable harness binds the
requested model route, CLI version, executable digest, transport digest,
instruction digest, guest workspace, output schema, response bound, sandbox,
and ephemeral policy.

For each view it derives one `CodexExecInvocation`. The argument vector is
closed and contains only `exec`, `--ephemeral`, `--json`, `--model`,
`--sandbox workspace-write`, `--output-schema`, `--output-last-message`,
`--cd`, and stdin prompt selection. Participant data never becomes an argument.
The output schema is generated from `ParticipantIntentEnvelope`, the same model
used to decode the bounded result. The command shape follows the
[official non-interactive CLI reference](https://developers.openai.com/codex/cli/reference).

The executable transport is injected by the trusted runner. EdaGym does not
look up an executable, inherit a process environment, read a user configuration
directory, or load credentials in this channel. A deployment may supply a
credential-owning host proxy or an isolated runtime, but it must attest the
executable, version, and transport identities already bound by the harness.
This ephemeral adapter rejects training sessions instead of claiming resume
semantics it does not implement. Metered campaigns continue to use the
Responses-compatible participant boundary.

## Credential-free campaign preflight

`SyntheticPreflightLauncher` accepts only the sealed rootless-container
executor. It runs the exact frozen campaign trial without provider access,
executes the fixed credential-absence probes, and issues one descriptor-bound
attestation over the settled run and all runtime surfaces. The provider broker
must consume that single-use attestation before acquiring credentials.

The libvirt executor can qualify its fixed no-network probe boundary, but it is
not a campaign-trial launcher until the generic runtime supplies disjoint
per-invocation artifact directories. A brokered host executor is never an
admissible boundary for participant-controlled candidate bytes.

## Human terminal turn

`edagym run human-turn` performs one explicit human action. It requires that
the journal's current writer is a bound human actor using the canonical bounded
JSON-line adapter. The command writes exactly one participant-visible
`ParticipantView` to stdout, reads one bounded typed intent from stdin, and
commits it through `ParticipantController`.

In a hybrid session, a `transfer_control` intent journals the previous and next
writer before the command returns. Other actors are present only as inactive
bindings during that turn, so they cannot write concurrently. Candidate
submission is available when the environment, candidate root, and artifact
store inputs are supplied together; it uses the same immutable snapshot owner
as `edagym run submit`. There is no second stdout response: success is the exit
status, and the journal is the sole owner of the committed action. This keeps
evaluator, author, provider, raw artifact content, and hidden-event counts out
of the human terminal channel.

For a paid hybrid run, campaign admission is actor-scoped. A human turn carries
no provider admission and is accepted only for the exact bound JSON-line human
adapter. After the journal records a human-to-harness transfer, the trusted
campaign dispatcher may wrap its admitted harness with
`AdmittedCampaignContinuationAdapter` and reopen the same run. The wrapper
derives the current writer and latest handoff from replayed journal events,
exposes the original metered admission, and cannot authorize a different
harness or session.
