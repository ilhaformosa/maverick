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

### T013c-1 — singleton direct-v3 trusted provisioning binding

- **User result:** Give each future direct-v3 server/listener binding one
  explicit locally provisioned profile selected before any wire message is
  read, so frozen wire commitments can prove equality only and can never choose
  an identity, epoch, profile, path, or PSK.
- **Scope:** Add owned `maverick-core` provisioning data for the three opaque
  IDs, expected server identity, direct mapping and path, nonzero epoch,
  credential expiry, and `SecretString`; one fixed-size nonzero opaque local
  handle; an exact-one-profile binding construction gate; and an opaque
  preselected capability that provides a temporary view to the existing T013b-2
  verifier without exposing or copying the secret. A startup/reload-only helper
  may check multiple independent singleton bindings by reusing the existing
  O(n²) trusted-profile validator and rejecting duplicate handles. Change
  exactly `ROADMAP.md`, `crates/maverick-core/src/auth_v3.rs`, and the new
  `crates/maverick-core/tests/auth_v3_provisioning.rs`.
- **Acceptance:** Zero handles and zero/multiple profile cardinality fail
  closed. Owned profile construction reuses the existing validator for opaque
  IDs, direct mapping/path, epoch, expiry, and secret validity. One valid
  singleton produces a preselected capability whose temporary profile view
  passes the production encode/verify flow. After profile A is preselected, a
  correctly signed profile-B control or a wire-changed commitment/epoch is
  rejected without switching profiles or trying B. Startup consistency rejects
  duplicate handles, tuples, PSK reuse, and deployment-mapping conflicts.
  Debug and errors are fixed, bounded, value-free, and source-free; owned secret
  state has no Clone, Default, or Serde API. All four frozen auth-v3 vectors,
  legacy v1/v2 conformance, locked offline core and SDK tests, formatting,
  strict core lint, warning-free core docs, both local product gates, final
  three-file audit, and privacy gates pass.
- **Binding rule:** Every direct-v3 server/listener binding has exactly one
  explicit profile. Multiple independent singleton bindings may use independent
  opaque local handles. Shared-listener multi-profile dispatch is `BLOCK` and
  requires a future protocol/dispatch design. Wire tuple, commitment, epoch,
  credential hint, path, Host, SNI, or PSK trials must never select a profile.
- **Out of scope:** Client/server role config; SDK or stored-profile schema;
  real H2/H3 exporter and runtime wiring; generation slots; duplicate control,
  close, no-state-transfer, no-fallback, timers, or revocation enforcement;
  sessions, reconnects, targets, flows, or data-plane work; fronted
  authentication; and PQ/hybrid policy. Those remain deferred. This slice does
  not enable runtime, change product facts, or modify `STATUS.md`.
- **Stop conditions:** Stop if this needs a fourth file, Cargo or lockfile
  change, new dependency, config/schema/SDK/runtime work, shared-listener
  multi-profile behavior, wire selection or PSK trial, specification/vector or
  version change, or private data in the diff.

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
