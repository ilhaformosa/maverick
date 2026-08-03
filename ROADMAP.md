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

### T023b-1 — authenticated-generation lifetime and limits

- **User result:** Every feature-gated direct-quiche authenticated generation
  retains the server confirmation that the existing auth-v3 verifier accepted.
  The generation retains its verified admission expiry, hard expiry, selected
  maximum frame size, and selected maximum concurrent flows. It enforces both
  expiries and the effective local flow limit of one; this slice does not claim
  Maverick frame-size enforcement. Admission expiry prevents a new test-private
  classic CONNECT from starting. Hard expiry makes the local capability and
  application I/O fail closed, revokes the driver, and best-effort closes the
  QUIC generation. Dropping the lease for an active flow wakes that flow and
  fails it; dropping an idle lease returns only its permit.
- **Scope:** Change only this queue and
  `crates/maverick-client/src/quiche_foundation.rs`. Capture one trusted Unix
  time and monotonic anchor before authentication; derive both deadlines from
  that unchanged anchor and the verified absolute expiries. Retain one private
  immutable policy by `Arc` across the authenticated generation, lease, and
  proof. Reuse the existing verifier, manager, bounded command queue, driver,
  flow reference, resource limits, failure path, and close path. The effective
  local flow limit is the smaller of the verified selected limit and the
  existing one-lease foundation limit, which remains one.
- **Acceptance:** First retain a focused red test, then make the complete local
  matrix green. Prove client and server retain the same absolute expiries and
  selected frame/flow limits even though their monotonic anchors are local;
  authentication time never moves a deadline; admission is strict before/equal/
  after while an already armed flow may cross admission; hard equality closes
  idle and stalled active generations; active-flow lease drop really wakes and
  fails the flow; idle lease drop does not close the generation and permits a
  same-generation reacquire; manager close, replacement generation, wrong
  generation, policy-`Arc` identity, backpressure, cancellation, reclamation,
  and fixed privacy-safe diagnostics remain correct. Hard-close checks require
  failed flow response, inactive leases, cleared bounded buffers, returned
  permits, reclaimed tasks and loopback sockets, one physical connection, and
  no retry. The selected limits remain observable only to private tests; the
  effective local flow limit is one.
- **Out of scope:** No real target, DNS, socket relay, authority parser, second
  connection, fallback, external credential/profile revocation feed, watcher,
  task, queue, manager, framework, public API, core primitive, dependency,
  Cargo/lock/manifest, config/schema/wire/version, server/SDK/CLI/vendor,
  `STATUS.md`, CI, push, PR, merge, tag, release, remote, deployment, real
  network, or system-network change. Retaining `max_frame_size` does not claim
  Maverick frame-size enforcement in this raw reference flow; retaining a peer
  flow limit above one does not claim multiple real flows. Manager close,
  generation replacement, active-flow lease drop, and hard expiry are local
  revocation inputs only; external credential/profile revocation remains
  deferred.
- **Stop conditions:** Stop on a third changed file; a need for an external
  watcher or revocation feed, new task/queue/framework, real target/DNS/socket,
  authority parsing, second connection, fallback, public/core/dependency/config/
  schema/wire/version change, or unstable wall-clock sleep test; inability to
  fail closed at deadline equality before new application I/O; any T026d or
  T027a-1 authorization, one-generation, one-stream, no-retry, cleanup,
  backpressure, or privacy regression; or any focused or full local gate
  failure.

This private reference slice is not external credential revocation, a product
H3 data plane, multi-flow support, a release result, or authorization for
publication, deployment, or real-network work.

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
