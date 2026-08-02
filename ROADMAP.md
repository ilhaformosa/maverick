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

### T012c-1 — trusted direct-v3 expected authority input

- **User result:** Before any future direct-v3 I/O, the validated client and
  server role configs each own one byte-exact trusted expected authority. A
  missing or malformed value fails closed instead of being guessed from a
  request, SNI, listener, certificate, DNS result, or dial endpoint.
- **Scope:** Change only this queue, `CONFIG.md`, the frozen direct-auth-v3 spec,
  the existing core schema-3 role parser, its role-config tests, and three
  `#[cfg(test)]` fixture sites. In
  `crates/maverick-client/src/direct_v3_h2.rs`, only delete the obsolete
  bad-name runtime-gate row. In
  `crates/maverick-server/src/direct_v3_h2.rs`, only add neutral `localhost` as
  the server fixture's expected authority. In
  `crates/maverick-client/src/quiche_foundation.rs`, only add the existing
  `T026C_AUTHORITY` to the H3 server fixture. Make
  `maverick.expected_authority` required for schema-3 servers, preserve the
  validated text through one read-only accessor, and apply one private strict
  DNS/SNI-hostname validator to both roles without normalization.
- **Acceptance:** Preserve real canonical-parser red evidence for the former
  missing-server-field and loose-client-name behavior, then prove legal
  lowercase, uppercase, internal-hyphen, and ASCII-punycode values round-trip
  byte for byte. Prove both roles reject non-host authority forms, IP literals,
  invalid DNS labels, non-ASCII, whitespace/control input, and overlong labels
  or names. Prove server missing/null/unknown/misplaced fields fail closed,
  errors and Debug remain fixed and value-free, and config-v1, policy-only v2,
  stored-profile, old-reader, wire, runtime, and version boundaries do not move.
- **Out of scope:** H2/H3 runtime wiring, live request or SNI comparison,
  authentication, Developer Mode, target/DNS/egress work, config/auth/frame/
  protocol/stored-schema version changes, dependencies, SDK/CLI/client/server
  runtime changes, CI, push, PR, tag, release, remote, deployment, real-network,
  and system-network work remain deferred. `STATUS.md` is unchanged.
- **Stop conditions:** Stop on any ninth file, any non-test or production-runtime
  change in the three fixture files above, or any further scope expansion. Also
  stop for Cargo/dependency or URL/IDNA work, a version or wire change,
  authority inference from runtime input, separate client/server validators,
  input-bearing errors, runtime I/O, product H3, target work, or a focused/full
  local gate regression.

This pre-runtime prerequisite is not tied to a release version, does not define
v1.3 release scope, and does not authorize CI, publication, push, deployment,
or real-network work.

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
