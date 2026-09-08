# Security Model

EdaGym executes participant-controlled files and commands near valuable EDA
software, libraries, licenses, model credentials, and proprietary results. Its
security model treats the participant, candidate, generated scripts, and model
output as untrusted.

## Trust domains

The trusted controller owns specifications, credentials, policy enforcement,
journaling, artifact disclosure, and verifier scheduling. The participant
domain owns only its projected task view and workspace. The verifier domain
receives immutable hidden resources and the submitted candidate through a
one-way handoff. Commercial EDA processes execute either in the verifier domain
or behind a registered host broker.

Containers reduce exposure but are not described as a strong hostile-tenant
boundary. Untrusted interactive work with commercial assets requires a
dedicated VM or an equivalent independently enforced isolation domain.

## Repository boundary

`/temp/` is ignored at the repository root and is the default local state area.
Credentials, raw model exchanges, proprietary databases, private reports,
workspaces, and run state must remain in ignored or external restricted
storage. Production code and released task sources cannot depend on `temp`.

Repository audit covers the index, tracked paths, refs, reflogs, stashes, LFS
pointers and objects, loose and packed objects, and unreachable objects. It
reports metadata only. Release audit fails closed when a required scanner or
coverage source is unavailable.

## Credential boundary

Provider credentials are read in place by a narrow controller-only source. The
credential value cannot be represented in typed specifications, event payloads,
command arguments, child environments, containers, crash output, or public
artifacts. Authentication files must be owned by the invoking user and have no
group or other permissions.

Before credentials are loaded, a synthetic marker remains installed in the
controller-owned launch mapping throughout a dry run. A one-use collector then
scans descriptor-bound sources for the participant workspace, tool process,
EDA process, verifier, console, journal, artifact store, and participant export.
The collector rejects missing, aliased, linked, non-private, unreadable, or
concurrently changed sources. Callers cannot replace these scans with supplied
observation bytes. The marker is removed before an opaque attestation is
returned, and that attestation authorizes exactly one matching provider
campaign. The model-provider network channel is separate from the task sandbox
network policy.

## Artifact and path safety

Persistent artifacts carry class, visibility, sensitivity, redistribution, and
provenance. Secret material is never persisted. Confidential model traffic and
response identifiers remain in encrypted or private restricted storage;
public projections contain only allowed aggregate facts.

Raw EDA streams and native reports are `DIAGNOSTIC` or `EVIDENCE`. In licensed
environments they are always encrypted, confidential, author-only, and
non-redistributable. A trusted evaluator may derive a canonical numeric
`MEASUREMENT` artifact under its independent disclosure rule. Durable
measurement provenance points to that sanitized artifact; an encrypted
author-only link artifact preserves the raw source relationship. Credential
patterns are rejected at every persistence boundary, while host paths,
endpoints, and license routes are rejected from every non-author artifact.

Participant-controlled trees are captured and restored relative to already
opened private directory descriptors. Symlink traversal, mutable ancestor
replacement, device files, hard-link ambiguity, tree escape, and unstable files
are rejected. Restore is staged in the same controlled parent and committed by
an atomic rename only after content and metadata verification. Tool processes
inherit an owner-only umask. Output collection accepts only a current-user-owned
regular descriptor and seals it to mode `0600` before CAS ingestion.

## Runtime restrictions

Rootless containers use a read-only root filesystem, drop every capability,
enable no-new-privileges, set hard CPU, memory, process, file, output, and wall
limits, and default to no network. The host root, broad NAS roots, runtime
socket, credential directories, verifier tree, artifact store, and journal are
never participant mounts.

The commercial broker accepts only a registered fixture or evaluator recipe,
content-bound inputs, exact tool binding, and one-time authorization. It injects
license state only into the trusted EDA process. Native output remains private;
only typed measurements selected by a trusted parser can cross the disclosure
boundary.

## Failure semantics

Policy denial, security violation, candidate rejection, tool crash, timeout,
license failure, and infrastructure loss remain distinct outcomes. Redaction is
defense in depth and cannot replace isolation. A missing verifier result or a
failed security check never becomes a candidate result by inference.

Web state is not a second database: the UI renders authenticated projections
of the journal and allowed artifacts. Tokens are sent only in an
`Authorization` header, state-changing requests require a matching `Origin`
and idempotency key, and evaluator or secret visibility is filtered before an
event leaves the control plane. The package contains no EDA installer or
functional technology-library payload.
