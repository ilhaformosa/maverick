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

### T027b-2b2-0 — verified credential-expiry core prerequisite

- **User result:** Later server auth-v3 foundation work can read the exact
  credential expiry ceiling already retained by successful core verification.
  This is read-only core metadata, not runnable authentication, a connection or
  capability, a data plane, or a user-visible product result.
- **Scope:** Add one privacy-safe accessor to the already-public verified
  `ClientControl` type. Cover the real core verifier with two distinct legal
  expiry values, read the metadata before confirmation encoding consumes the
  verified value, and preserve identical confirmation bytes and canonical
  vectors when every wire input is unchanged.
- **Acceptance:** Retain focused compile-failure-to-pass evidence for the
  missing accessor; return each exact trusted not-after value without a default,
  truncation, or cross-binding; keep parsed/unverified values outside the
  verified API boundary; preserve malformed, expired, PSK, encoder, verifier,
  and canonical-vector behavior; and pass the core, lint, rustdoc, and local
  product gates.
- **Out of scope:** No shared generation policy, server authentication runtime,
  SETTINGS or transport integration, flow or data plane, config, stored schema,
  protocol, frame, wire, version, `STATUS.md`, CI, remote, deployment, release,
  real network, or system-network change.
- **Stop conditions:** Stop on a fourth changed file, any manifest, lockfile,
  dependency, public type, field, trait, or schema expansion, runtime wiring,
  generation/deadline state, capability framework, wire change, or required
  regression failure.

This accessor remains a repository-local foundation prerequisite only.

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
