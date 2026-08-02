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

### T013c-3b — server-side rustls direct-H2 auth-v3 connection control reference gate

- **User result:** One dormant server-only reference seam demonstrates the
  frozen auth-v3 control gate on one real loopback rustls/TLS 1.3 and H2
  physical generation, without enabling a product client or data plane.
- **Scope:** Add one crate-private server module that accepts only a config-v3
  H2 server role through rustls, validates the exact raw control carrier,
  observes same-generation TLS facts and the RFC 9266 exporter, consumes one
  pre-auth slot, verifies the frozen 256-byte control, and locally queues the
  exact 320-byte confirmation before recording authentication. Add only the
  narrow core bridge needed to bind actual runtime facts to the already
  preselected singleton profile. Keep the legacy/default server entry points
  unchanged and leave `STATUS.md` byte for byte unchanged.
- **Acceptance:** Real `127.0.0.1` plus ephemeral-port tests cover the positive
  rustls/H2 exchange, exact request and response mapping, same-generation
  exporter binding, no early data, the `Fresh -> Authenticating ->
  Authenticated | Closed` gate, unique-slot consumption, generation-wide close
  on every failure or duplicate, and the final 320-byte `END_STREAM` local h2
  acceptance boundary. Pre-I/O tests reject H3, non-rustls selection, raw `?`
  or `#`, and a path that cannot round-trip byte for byte before listener or
  connection work. Fixed diagnostics reveal no peer, path, opaque identity,
  secret, exporter, nonce, session, endpoint, or backend error.
- **Runtime and truth boundary:** The seam is dormant and server-only. It is
  not called by `run_server`, `start_server`, CLI, SDK, or the default runtime.
  Loopback evidence is a local reference result, not a working product,
  production, multi-flow, user-flow, or release result. `STATUS.md` remains the
  sole current-truth and authorization source. This queue is not a completed
  ledger and does not define v1.3 release scope.
- **Out of scope:** Product client, pooling, user-flow or data-plane mapping,
  DNS, egress, targets, relay, fallback, multi-profile or shared-listener
  dispatch, H3, BrowserMimic/BoringSSL, Auto, fronted routes, revocation,
  hard-expiry enforcement, CLI, SDK, stored profiles, release, remote, and real
  network work remain deferred.
- **Stop conditions:** The exact changed-file boundary is `ROADMAP.md`,
  `Cargo.lock`, `crates/maverick-core/src/auth_v3.rs`,
  `crates/maverick-server/Cargo.toml`,
  `crates/maverick-server/src/direct_v3_h2.rs`, and
  `crates/maverick-server/src/lib.rs`; stop and re-adjudicate before changing
  any other file. Also stop rather than add a stable public runtime API, a
  wire/vector/schema/version change, a legacy behavior change, runtime
  enablement, remote action, or private data.

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
