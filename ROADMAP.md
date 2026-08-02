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

### T013b-1 — direct auth-v3 canonical docs and executable vectors

- **User result:** Freeze one byte-exact, independently reproducible contract
  for direct H2/H3 connection authentication before any runtime implementation,
  so later client and server work cannot silently choose different layouts,
  identities, policy meanings, exporter inputs, or downgrade behavior.
- **Scope:** Add one direct auth-v3 specification, four neutral canonical H2/H3
  ClientControl/ServerConfirmation vectors, and strict test-only
  encoder/parser/verifier coverage. The tests reuse the existing conformance
  framework and existing SHA-256, HMAC-SHA256, HKDF-SHA256, and Serde
  dependencies. They check the exact four-part credential tuple against local
  provisioning and an independent trusted connection context, atomically model
  the one-control auth slot, and reject unknown values, reserved bits,
  malformed lengths, transcript or commitment changes, carrier/TLS/profile/path
  or exporter/generation mismatch, early data, unsafe clock/expiry/limits,
  legacy bytes, PSK reuse, and duplicate control messages.
- **Acceptance:** The test-side oracle independently rebuilds and verifies all
  four fixed messages; H2 and H3 positive vectors and the complete negative
  matrix pass locked and offline. Existing v1/v2 vector bytes and legacy
  exporter label remain unchanged. The repository format, core tests, strict
  core lint, user smoke, and local harness pass; the diff is privacy-safe,
  changes exactly the authorized seven files, leaves `STATUS.md` unchanged,
  and ends as one clean local commit.
- **Out of scope:** Production parser or runtime auth-v3; changes to the current
  product auth, config, frame, wire, stored-profile, or public API versions;
  peer-confirmed product results; reconnect/state-transfer proof; server
  admission or H3 data plane; TLS-terminating-front application sessions or
  per-flow MACs; PQ/hybrid guarantees; release, publication, CI, or real-network
  work. These docs and vectors are not a product result and do not define a
  v1.3 release scope. T015/PQ remains `DEFER`.
- **Stop conditions:** Stop if this needs an eighth file, a Cargo or lockfile
  change, a new dependency, production parser/runtime/public API work, a legacy
  byte or label reinterpretation, fronted/PQ/reconnect/admission/H3-data-plane
  implementation, a protocol contradiction that cannot be resolved entirely
  inside docs/tests, an oracle that cannot independently reproduce the golden
  bytes, or any private data in the diff.

This slice is not tied to a release version and does not define release scope.

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
