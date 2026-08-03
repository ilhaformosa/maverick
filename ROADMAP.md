# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Planning Input Rule

Design drafts and reconciliation notes are non-authoritative planning inputs.
When they conflict, `STATUS.md` alone controls current truth and authorization,
while `ROADMAP.md` controls execution order. Only a minimal slice placed here
enters execution; every other proposal remains deferred, neither automatically
adopted nor automatically rejected.

## Current Repository-Local Queue

### T027b-2c4 — fixed-slot successful target-stream ownership

- **User result:** A future private direct-v3 target dispatch can return one
  already-connected TCP target without losing it or creating a second socket
  owner outside the existing fixed eight request slots.
- **Scope:** Add one optional connected target socket to each existing
  `PendingClassicConnect` slot. While work is admitted the slot owns target
  metadata; while it is in flight the actor-owned future temporarily owns the
  token and any connected socket; after synchronous completion checks pass, the
  same originating slot alone owns that socket in `WaitingNextStage`. Update
  only the registry's obsolete source-scan test so it continues to prohibit
  registry network ownership while recognizing this explicit runtime slot
  owner; registry production code and responsibility remain unchanged.
- **Acceptance:** Keep exactly eight slots and no second socket map, array, or
  queue; recheck generation, active and unrevoked state, hard and attempt
  deadlines, stream, port, frame limit, in-flight state, consumed target, and
  empty socket owner before handoff; drop a rejected or abandoned socket; prove
  single and eight-socket completion, unchanged ninth-request rejection,
  peer-half-close stability, fixed four-completion rounds, zero target-open
  observations, and bounded socket closure on timeout, panic, cancellation,
  expiry, revocation, peer or local close, inbox close, actor abort, connection
  drop, and registry reclaim. Keep `ServerConnection: Send` and keep registry
  ownership limited to its sender and task ID.
- **Out of scope:** No production opener call, DNS, new connect policy, success
  response, DATA read or write, relay, fallback, slot reuse, product-server
  caller, public API, schema, wire or version change, metrics behavior or owner
  change, `relay.rs`, registry production code, `runtime_metrics.rs`,
  `server.rs`, config, manifest, lockfile, dependency, vendor, core, client,
  SDK, CLI, `STATUS.md`, CI, remote, deployment, release, real-network,
  credential, infrastructure, or system-network work.
- **Stop conditions:** Stop before any file outside `ROADMAP.md`,
  `crates/maverick-server/src/quiche_runtime.rs`, and
  `crates/maverick-server/src/quiche_endpoint.rs` changes, except for the
  architecture-only source-scan assertion in
  `crates/maverick-server/src/quiche_registry.rs`. Any need for a ninth slot,
  another socket collection, a production DNS/connect/opener call, a response
  or data plane, metrics observation, registry production change or new
  responsibility, public API, dependency, or `STATUS.md` change requires
  re-adjudication.

This remains repository-local, private, feature-gated socket-ownership
foundation. Production target dispatch is still fixed `Unavailable`, and the
test-only dispatch seam uses loopback with OS-assigned ephemeral ports. Zero
target-open observations and retained sockets do not establish H3 target
connectivity, a data plane, runtime readiness, a release result, or a product
result; the endpoint still has no product-server startup caller.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Wait for a concrete input.** Accept privacy-safe Beta feedback, a
   reproduced failure, or an explicit owner-defined minimal task. Do not infer
   a new product, release, deployment, or real-network authorization.
2. **Define one smallest slice.** Before implementation, put its user result,
   file scope, acceptance checks, out-of-scope boundary, and stop conditions in
   this queue. Preserve `STATUS.md` as the sole current-truth and authorization
   source.
3. **Keep stronger supply-chain claims deferred.** Provenance and attestation
   need an explicit identity and remote-permission design; signatures need a
   trust-root and key-custody decision; reproducible builds need a separate
   byte-for-byte build experiment. An SBOM is not any of those things.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work without a reproduced Beta need and an explicit
  compatibility and security decision.
- No production-readiness relabeling from local tests or disposable-VM package
  installation.
- No rustls fork or vendored unmerged server-ECH patch in the current execution
  plan.
- No remote, paid, privileged, or host-network action outside the current
  authorization recorded in `STATUS.md`.

## Failure-Driven Follow-Up

Use the shortest failure-driven next step:

- install failed -> simplify the artifact;
- daily use failed -> fix reliability/usability;
- TLS fingerprint was blocked -> improve the default TLS/handshake path;
- active probe distinguished the server -> harden handshake/fallback behavior;
- Beta baseline passed -> accept privacy-safe feedback, but do not recruit
  another user or widen platform, protocol, packaging, or governance scope
  without a separate owner decision.

The Maverick protocol version, config version, and stored-profile schema
version remain `1` in the published Beta.4 release; existing authentication and
frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
