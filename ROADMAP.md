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

### T027c-0a — preserve Noise key zeroization in all-feature builds

- **User result:** The complete local feature combination compiles without
  weakening the cleanup of the temporary Noise static private-key copy.
- **Scope:** Replace the conflicting manual wipe in the existing Noise
  handshake builder with the repository's existing RAII zeroization wrapper.
  Keep the borrowed key live until Snow consumes its builder, then zeroize it
  on both success and every error return. Do not add a dependency or change any
  public API, configuration, stored schema, protocol, authentication, frame, or
  wire version.
- **Acceptance:** Preserve the original all-feature compiler failure as red
  evidence. Prove the Noise initiator and responder paths, the core
  `noise-experimental` target set, and the whole workspace all-feature target
  set compile and test successfully. Keep errors privacy-safe and preserve all
  default-feature behavior and the cumulative T020-Q1 through T027b-2d4b local
  foundation gates.
- **Out of scope:** This integration blocker repair does not enable Noise in a
  product path, change runtime policy, or establish H3 product readiness,
  real-network evidence, user results, release results, or publication
  authorization. T027c-0 cumulative closure and the later product-wiring audit
  remain separate work.
- **Stop conditions:** Stop before changing any file outside `ROADMAP.md` and
  `crates/maverick-core/src/noise.rs`; adding a dependency; removing private-key
  cleanup; claiming physical-memory erasure from a unit test; or changing a
  public surface, version domain, `STATUS.md`, runtime, remote, deployment,
  release, infrastructure, credential, real-network, or system-network state.

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
