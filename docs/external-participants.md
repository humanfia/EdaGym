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

## Native provider relay

Provider identities use the version-two `ProviderProfile`: an explicit
`request_path` and a closed `ResponsesWire` or `MessagesWire` configuration.
`CredentialLease.authorize` verifies the complete profile digest before adding
its credential headers. Responses uses Bearer authorization; Messages explicitly
selects Bearer or `x-api-key` and pins `anthropic-version` to `2023-06-01`.
Messages beta features are frozen in the profile; each request selects an admitted
subset. The request identity and private observer evidence include that selection.
Caller-supplied controller identity headers are refused. This follows the header contract in
the [Messages API overview](https://platform.claude.com/docs/en/api/overview).

The version-two profile and resolved-config digest domains replace version one.
Old profile documents must be regenerated with `request_path` and `wire`; there
is no legacy-field decoder. Existing attestations and campaign bindings must be
requalified against the new identity. WebSocket and storage restrictions remain
owned by the actual request adapters; duplicated always-false profile flags and
the redundant provider-kind label have been removed.

Native Responses and Messages requests use the shared provider sender. Controlled
Responses requests still reject a Messages profile before reservation or dispatch;
a controlled Messages participant is not yet connected. A provider profile alone
does not qualify a native harness or enable a native campaign.

`NativeProviderRelay` exposes one short-lived trial capability on a private
Unix socket. It accepts only the fixed path for its sender's protocol, requires its issued
bearer token, and rejects requests after the absolute deadline supplied by the
controller. The caller derives that deadline and the model, effort, service tier,
and request limits from its frozen run. The relay does not issue upstream access:
its sender must already have passed `ResponsesBroker` admission.

`NativeProviderRequest` normalizes the declared wire protocol. The Responses
adapter preserves message histories, namespace tools, and custom tool calls. The
Messages adapter preserves text, client tool conversations, and actually supplied
thinking blocks; it supports the frozen adaptive/disabled thinking modes and
output effort. It admits the native SDK's fixed `/v1/messages?beta=true` entry
point, while the upstream destination remains the profile's fixed request path.
Both adapters fix model controls, cap output tokens, require stateless streaming,
and reject provider-hosted tools and unsupported input forms. Ordinary Responses
requests and native streams use the same
reservation, dispatch, and settlement implementation. Multiple relays can share
that accounting owner. No token counter lives in the relay.

The transport currently buffers each bounded stream before forwarding it. One
recognized terminal event with exact provider usage is required. Unknown events,
incomplete streams, missing usage, and inconsistent terminal receipts are
failures. Messages requires a complete `message_start` / `message_delta` /
`message_stop` sequence and sums uncached, cache-creation, and cache-read input
tokens. Cumulative usage updates replace prior counters; they are not added
together. Missing cache counts cannot establish an exact total. A provider
output-limit stop with a valid receipt settles its exact usage and remains an
incomplete response. These rules follow the
[streaming contract](https://platform.claude.com/docs/en/build-with-claude/streaming)
and [cache usage contract](https://platform.claude.com/docs/en/build-with-claude/prompt-caching).

Model fallback blocks or a changed serving-model delta raise the distinct
`ProviderModelChangeError`. The relay returns a terminal authorization refusal
for model changes and exhausted fixed budgets, so the CLI does not interpret
local budget exhaustion as a transient rate limit. Observed rejected response
bodies remain private evidence; their
presence is not asserted to be a valid provider result. Dispatched requests with
unknown usage retain the conservative charge established by the budget owner.
Authorization headers are not supplied to transcript observers. The relay refuses
its capability token in a normalized request body before invoking an observer or
the provider. Upstream authorization is added only inside the sender. Native
process-output admission remains part of the unfinished run-event integration.

This transport has been exercised with a native CLI and synthetic provider
responses inside a network-disabled container. It is not yet the configured
RunEngine campaign launcher. Controlled Messages integration, native execution closure
admission, and the unified run-event adapter remain required before native cells
can be declared available for scored campaigns.

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

Native Claude Code and Codex adapters, when configured, are evaluated as
`model + harness` cells with their own qualification and hard budget. A
controlled provider adapter is a separate experimental class; its observations
are never silently substituted for an unavailable native cell. Credentials and
raw provider transcripts remain in the private run store.
