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

### T013c-3d — paired rustls direct-H2 auth-v3 loopback reference

- **User result:** One dormant local reference composes the accepted real
  client and server gates on one `127.0.0.1` plus ephemeral-port physical
  generation, so the frozen 256-byte ClientControl and 320-byte
  ServerConfirmation are mutually verified without enabling a user flow or
  data plane.
- **Scope:** Add one empty, non-default client feature named
  `unstable-direct-v3-reference-test-support` and expose through
  `maverick-client` only under that feature one public, unstable wrapper around
  the existing client gate. This slice's design adjudication explicitly
  accepts that SemVer-observable cross-crate test-support surface as public but
  outside the stable compatibility promise. The wrapper fixes rustls, accepts
  the existing
  `DirectV3ClientRoleConfig`, returns only a fixed success or failure, and
  returns success only after confirmation verification and physical teardown.
  Enable that feature only from the server's dev-dependencies. In the existing
  server direct-H2 test module, bind the real server gate first and pass its
  actual loopback port into a matching client role. Do not duplicate TLS, H2,
  auth-v3, or process-coordination machinery.
- **Acceptance:** The positive paired test uses matching singleton config-v3
  profile data, opaque identifiers, epoch, synthetic secret, raw path, CA, and
  certificate pin. One fresh TCP/rustls TLS 1.3/H2 generation carries exactly
  one control and one confirmation; mutual verification demonstrates the
  same-generation exporter binding. The server observes no second request and
  ends `Closed`, while the client wrapper returns success only after teardown.
  A bounded mismatched synthetic-secret control makes both real gates fail and
  close without authentication, fallback, retry, target, relay, or data-plane
  work. Preserve the existing fourteen focused server tests and eight focused
  client tests. Default and no-default-feature builds must not enable the test
  feature, and all ordinary local gates remain green.
- **Runtime and truth boundary:** This is dormant local interoperability
  evidence only. The fresh TLS no-early-data observation is not resumed-session
  0-RTT evidence. Immediate physical close is not a graceful-drain result. The
  opt-in symbol is an acknowledged public API surface, but it is unstable
  repository test support and is absent from default and no-default-feature
  product builds. There is no new default or stable product API. Source
  compatibility risk is limited to downstream code that explicitly enables
  this unstable feature, and such code is outside the compatibility promise.
  The wrapper exposes no `SendRequest`, stream, connection, session, receipt,
  secret, exporter, or capability. This does not establish multi-flow,
  listener, scheduler, pool, fallback, relay, runtime, user-flow, data-plane,
  production, release, or real-network results. `STATUS.md` remains byte for
  byte unchanged and is the sole current-truth and authorization source. This
  queue is not a completed ledger and does not define v1.3 release scope.
- **Out of scope:** `run_client`, `run_server`, listeners, schedulers, pools,
  fallback, relay, targets, DNS, egress, user-flow and data-plane mapping,
  multi-profile or shared-connection management, H3/quiche,
  BrowserMimic/BoringSSL, Auto, fronted routes, revocation, hard-expiry
  enforcement, CLI, SDK, stored profiles, release, remote, system-network, and
  real-network work remain deferred.
- **Stop conditions:** The exact changed-file boundary is `ROADMAP.md`,
  `Cargo.lock`, `crates/maverick-client/Cargo.toml`,
  `crates/maverick-client/src/lib.rs`, `crates/maverick-server/Cargo.toml`, and
  `crates/maverick-server/src/direct_v3_h2.rs`; stop and re-adjudicate before
  changing any other file. Also stop rather than change the frozen carrier
  mapping, wire format, vector, core auth, config schema, or accepted client or
  server gate implementation; widen the single accepted unstable public seam,
  promise compatibility for it, add a stable public API, or enable the test
  seam by default; connect product runtime, data-plane, or fallback work; use
  developer-sensitive data; or perform any remote, CI, system-network, or
  real-network action.

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
