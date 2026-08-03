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

### T026d-1 — product-private authenticated-generation handoff

- **User result:** Inside the private feature-gated direct-quiche foundation,
  one physical H3 generation authenticates exactly once before its manager can
  hand out a module-private, unforgeable generation-bound authenticated
  capability. Client success means
  the complete 320-byte confirmation passed local receipt verification; server
  success means only that the complete confirmation with FIN was accepted by
  its local quiche send queue, not that the client received or acknowledged it.
  Auth success itself does not close the connection; it remains managed until
  explicit close or fail-closed transport termination.
- **Scope:** Change only this queue and
  `crates/maverick-client/src/quiche_foundation.rs`. Move the reusable T026c
  auth slot, strict H3 event state machine, bounded body handling, and direct-v3
  verification into one non-test private module. Consume one by-value validated
  client or server role config before I/O, use its same singleton profile,
  exact authority, and exact path, bind all facts to the manager generation,
  and keep fixtures, fault injection, and outcome spies test-only.
- **Acceptance:** Preserve the accurate pre-change reds that ordinary acquire
  was foundation-ready before auth and the non-test H3 path rejected the exact
  POST. Prove both roles authenticate once, manager handoff cannot precede auth,
  request authority and same-generation raw SNI compare independently, split
  DATA is exact, duplicate/trailer/wrong-stream/reset/GOAWAY/priority/Datagram/
  push/deadline and auth/context/receipt failures close without retry, real
  `StreamBlocked`, partial, and `Done` branches retain one stream and the exact
  unwritten suffix, server-local queue success can precede client receipt
  failure, close invalidates leases, and a replacement starts Fresh and
  reauthenticates. Keep one physical connection, no fallback, fixed resources,
  privacy-safe diagnostics, cleared auth buffers, and complete reclamation.
- **Out of scope:** No product entry, Developer Mode, CONNECT or Extended
  CONNECT, target, DNS, egress, user DATA, UDP relay, CLI, SDK, server product
  runtime, public API, dependency, Cargo/lock/vendor/core change, wire or
  version change, CI, push, PR, tag, release, remote, deployment, real network,
  or system-network work. `STATUS.md` remains unchanged, and this task defines
  no release scope.
- **Stop conditions:** Stop on a third changed file, unavailable same-generation
  raw SNI or ordered headers, a need for another queue, manager, registry,
  timeout framework, dependency/vendor/core/public API/wire/version change,
  sensitive production diagnostic, fallback or data-plane work, or any focused
  or full local gate regression. If a retry branch cannot be forced through the
  real quiche API without such expansion, record it as deferred instead of
  manufacturing evidence.

This private handoff is not tied to a release version and does not authorize
publication, push, deployment, or real-network work.

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
