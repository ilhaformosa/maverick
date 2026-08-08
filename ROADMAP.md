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

### T027c-0c — make the local dependency inventory honest and usable offline

- **User result:** The cumulative H3 foundation check can run from local caches
  without attempting network access, pretending cached package status is
  current, or mistaking a test's forbidden-source needle for real unsafe Rust.
- **Scope:** Add one explicit offline mode to
  `scripts/security-dependency-inventory.sh`, make dependency-policy warnings
  and scanner-tool errors fail closed, add one focused shell regression, and
  split one test-only source needle without weakening the first-party unsafe
  scanner. Limit product-file scope to the existing `quiche_runtime.rs` test
  module.
- **Acceptance:** Offline mode scans the cached RustSec database, uses locked
  offline dependency metadata, checks cached advisory/yanked/policy data with
  warnings denied, and states that online freshness remains unproved. The
  existing online mode remains the release-facing path. Real unsafe constructs
  still match the unchanged scanner, while the test-only literal no longer
  creates a false positive.
- **Out of scope:** No `STATUS.md`, product runtime, protocol, wire version,
  public API, config schema, dependency, deployment, remote, CI, or release
  change. This slice does not close T027c-0 or authorize T027c-1 by itself.
- **Stop conditions:** Stop before changing any additional product file,
  weakening or excluding scanner coverage, adding a dependency or coordination
  framework, using the network, or presenting cached checks as current online
  or release evidence.

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
