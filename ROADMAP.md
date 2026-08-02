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

### T026c — test-private direct-H3 auth-v3 runtime reference

- **User result:** Inside the private feature-gated quiche foundation, one real
  `127.0.0.1` QUIC/H3 generation performs exactly one frozen auth-v3 POST: the
  client sends the canonical 256-byte control, the server verifies it with the
  same-generation exporter and sends the canonical 320-byte confirmation, the
  client completely verifies it, and both roles close. This is a test-private
  runtime reference, not product H3 or a release result.
- **Scope:** Change only this queue and
  `crates/maverick-client/src/quiche_foundation.rs`. Extend the existing private
  driver and its bounded resources; reuse the canonical auth-v3 core primitive,
  singleton preselection, live TLS/H3 facts, strict peer-push gate, Datagram
  gate, and connection-local zero-trace gate. Keep `FoundationObservation`
  limited to TLS/H3 facts and place test-private auth results in a separate
  fixed, non-sensitive result.
- **Acceptance:** Prove red on the accepted T026b-2 baseline with a real exact
  six-field H3 POST rejected as pre-auth activity, then green for one split-DATA
  256/320 exchange, complete verification, same-generation binding, exact-once
  admission, server closure after its final response send is queued, client
  closure after complete response verification, a private call graph with no
  target/DNS/egress work, bounded cleanup, and zero H3/QPACK trace records.
  Cover malformed fields, ordering, lengths, DATA/event sequencing, duplicate
  control, Datagram and strict-push rejection, malformed or cross-generation
  auth bytes, fixed diagnostics, and unchanged observation semantics. All
  focused and full local gates must pass before one local commit.
- **Out of scope:** Product H3, CONNECT or Extended CONNECT, target or DNS work,
  egress, relay, user flows or DATA, UDP tunneling, fallback, public API,
  product config/schema/version, auth wire/core changes, qlog, outer QUIC log
  claims, exhaustive forced coverage of every partial-write, `Done`,
  `StreamBlocked`, or deadline branch, CI, push, PR, tag, release, remote,
  deployment, real-network, and system-network work remain deferred.
  `STATUS.md` is unchanged.
- **Stop conditions:** Stop if this needs a third file, dependency/vendor/Cargo
  work, a public item, product configuration, a wire/core change, raw peer data
  in diagnostics, a second resource framework, wire-driven profile selection,
  H3/QPACK formatting before suppression, target/data-plane work, fallback, or
  facts copied from another physical generation; also stop on any T023a,
  T026b-1, T026b-2, or full local gate regression.

This slice is not tied to a release version, does not define v1.3 release scope,
and does not authorize CI, publication, push, deployment, or real-network work.

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
