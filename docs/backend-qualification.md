# Backend Qualification

Backend declarations are an inventory of tool-capability candidates. They do
not constitute support claims.

## States

- `detected` means a module or executable can be identified without executing a
  licensed workload.
- `invocable` means a safe version or metadata probe started successfully.
- `conformant` means the exact version completed a canonical real workload, the
  parser produced typed evidence, a negative workload reached the intended
  semantic check, required artifacts were retained, and policy boundaries were
  audited.
- `unavailable` names a structured missing binary, dependency, host capability,
  library, or license reason.

Only `conformant` tool-capability pairs are selectable as supported backends.
`edagym backend list` is only the declared candidate inventory and makes no
support claim. `edagym backend qualify --json` emits an inspection projection.
Release authority is issued only by same-process live verification of the exact
artifact store, parser, environment, deployment, and probe. Serialized JSON
cannot be imported as release authority, and there is no separately maintained
support table.

## Evidence identity

A qualification binds:

```text
tool and vendor
capability
tool version and executable digest
opaque deployment attestation or immutable image identity
driver-owned canonical version projection and probe digest
driver revision
fixture-pair digest and role-specific fixture digest
fixture-owned semantic claim identity
acceptance or rejection evidence role
typed expected semantic rejection reason
parser revision
opaque restricted-asset identities and digests
input and output artifact digests
exit status and typed outcome
artifact policy
explicit environment-owned resource grant
commercial authorization receipt when required
```

Each fixture owns one input topology, invocation sequence, output topology, and
parser identity. Its two immutable cases differ only in trusted input bytes.
The acceptance case must be accepted, while the rejection case must be
classified with the exact reason frozen in its snapshot. A qualification record
recomputes the pair digest and rejects missing, duplicate, or cross-wired roles.

Timeouts, missing programs or libraries, license denial, unexpected tool exits,
missing outputs, parser exceptions, and unrecognized output are operational
failures. They can never satisfy the rejection role. A tool-specific nonzero
completion status may reach the semantic parser only when the fixture and parser
both bind that exact status to the rejection role; acceptance and every earlier
invocation still require zero. This distinction prevents a broken installation
or malformed input from masquerading as semantic discrimination.

Version probes use their complete output by default. A driver whose banner
contains runtime-only fields must declare one exact, capture-free projection for
its stable version identity. The resulting probe digest binds that sanitized
identity to the executable, module metadata, command, and version label; raw
volatile banner text is never used as a reusable environment identity.

An execution closure is private runtime state bound into one opaque deployment
attestation. Public backend definitions contain no deployment selection or
closure topology. The owner-only deployment registry contains host paths, image
references, mounts, environment names, and other site-specific values.
The registry must be a non-symlink, single-link, `0600` regular file owned by
the controller identity, and its descriptor identity and exact content are
revalidated before and after execution.

`edagym doctor --backend-deployment` and `edagym backend probe
--backend-deployment` consume that same registry through one descriptor-stable
loader. These commands perform metadata probing only: they neither run a
qualification workload nor acquire a license. A catalog tool with no registry
selection is reported as policy-unavailable, while a malformed or changed
registry rejects the command. Public output contains only typed state and opaque
attestation digests.

A site-container closure binds the immutable OCI manifest, root-owned launcher
and image inspector, modulefile, tool entrypoint, required sibling components,
and filtered non-secret tool environment. Each is revalidated around probing
and every workload invocation. License-bearing values are injected only from
the active lease and are never retained in the resolved installation. This
trusted broker is an evaluator execution boundary; it is not a participant
sandbox and does not grant a participant access to the site software tree.

Restricted libraries use the same separation. A fixture declares an opaque
asset ID and mount-relative target. A private runtime grant supplies the source
descriptor and restricted digest. Qualification copies through descriptor-safe
boundaries into its owner-private workspace, then revalidates the source and
materialized copy before and after every tool invocation. Vendor library bytes
and source paths are not qualification artifacts and never enter the portable
record.

A parser fixture alone, a version command, a mocked result, or an EDA-like text
marker is not qualification evidence. `conformant` is derived only when both
roles passed for every requested capability and no capability gap remains.
The inspection record is a versioned `backend_qualification` document with a
mechanically generated JSON Schema and is accepted by `edagym spec validate`;
that structural validation does not confer release authority.
If executing a candidate itself constitutes license-agreement acceptance,
metadata detection remains non-executing and qualification reports the typed
`eula_acceptance_required` gap. Generic commercial authorization is not legal
assent and cannot invoke that backend.

The fixture snapshot also carries a stable `semantic_claim_id`. It names the
scope actually exercised by the parser rather than widening a result to the
entire capability family. For example, bounded total-power estimation is not an
IR-drop or electromigration signoff claim, and placement-estimated SPEF is not
routed or signoff extraction.

Release consumes exactly one process-local verified source for every declared
tool-capability pair. An evidence source reopens an exclusive live artifact
store, checks its exact evidence and protected-diagnostic closure, and replays
the canonical parser for both roles. A gap source repeats the live probe and
carries no artifact store. Sources for one tool must use one identical probe,
cover disjoint capability partitions, and together cover every capability
declared by that backend. Aggregation is derived only after those checks;
missing capabilities cannot disappear from the projection.

## Commercial tools

Metadata discovery does not check out a license. A commercial workload requires
an explicit, single-use authorization bound to the tool, capability, driver,
fixture pair, and run. Its execution allowance and lease lifetime cover both
roles plus the version revalidation. License configuration is visible only to
the trusted process.
Persisted logs use a marker or field allowlist. Declared native reports are
allowed only in a managed-encrypted store with confidential, author-only,
non-redistributable disclosure. Imported commercial evidence must preserve that
disclosure on every input and output artifact. Retained content is checked for
license endpoints, host identity, and private path leakage.

## Cross-tool rules

Independent implementations are used to cross-check behavior and trends.
Measurements retain their own tool, library, corner, mode, and unit domains.
Area, delay, power, or routing values from unlike environments are not merged
into one nominal metric.

Randomized implementation runs retain every seed and failure. Default summaries
report the distribution and failure rate, never only the best run.

## Adding a backend

A backend should reuse an existing capability. Add its concrete command
resolution, one minimal paired fixture, a typed semantic discriminator, trusted
machine-readable parsing, artifact contract, cancellation and timeout behavior,
and secret-safe qualification. The negative input must be valid for the tool and
must reach the same semantic joint as the accepted input. Do not add a
vendor-specific task schema or a second process runner.

Qualification consumes external asset bindings from the selected profile and
does not infer support from a version string or a host executable alone. A
missing Liberty, LEF, device model, license, or rootless runtime is a typed
qualification gap. The public wheel retains only adapters, schemas, and
synthetic protocol fixtures.
