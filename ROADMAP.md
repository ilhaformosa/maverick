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

### T013c-3c — client-side rustls direct-H2 auth-v3 connection control reference gate

- **User result:** One dormant client-only reference seam demonstrates one
  strict frozen auth-v3 control exchange on one real loopback rustls/TLS 1.3
  and H2 physical generation, without enabling a product server, user flow, or
  data plane.
- **Scope:** Add one crate-private client module that accepts only a config-v3
  H2 client role through rustls, validates the exact raw control carrier before
  I/O, observes same-generation TLS facts and the RFC 9266 exporter, sends the
  exact 256-byte control, strictly verifies the exact 320-byte confirmation,
  and then closes the physical generation. Extract only the narrow rustls
  CA/pin/WebPKI helper needed to share the legacy client trust logic. Keep every
  legacy/default client entry point and behavior unchanged and leave
  `STATUS.md` byte for byte unchanged.
- **Acceptance:** Real `127.0.0.1` plus ephemeral-port tests cover the positive
  rustls/H2 exchange, exact request and response mapping, same-generation
  exporter binding, no early data, the `Fresh -> Authenticating ->
  Authenticated -> Closed` reference gate, fixed whole-control deadline, and
  generation-wide physical close after success or every failure. Pre-I/O tests
  reject H3, non-rustls selection, raw `?` or `#`, a path that cannot round
  trip byte for byte, and an invalid server name before connect work. Response
  tests reject wrong metadata, truncated/trailing bodies, trailers, invalid
  confirmation fields, wrong exporter provenance, and peer stalls. Fixed
  diagnostics reveal no address, server name, CA path, pin, control path,
  opaque identity, secret, exporter, nonce, session, or backend error.
- **Runtime and truth boundary:** The seam is dormant and client-only. It is
  not called by `run_client`, existing listeners, the legacy H2 connector,
  connection pool, CLI, SDK, or the default runtime. Loopback evidence is a
  local reference result, not a working product, production, multi-flow,
  user-flow, data-plane, or release result. `STATUS.md` remains the sole
  current-truth and authorization source. This queue is not a completed ledger
  and does not define v1.3 release scope.
- **Out of scope:** Product server, pooling, user-flow or data-plane mapping,
  DNS, egress, targets, relay, fallback, multi-profile or shared connection
  management, H3/quiche, BrowserMimic/BoringSSL, Auto, fronted routes,
  revocation, hard-expiry enforcement, CLI, SDK, stored profiles, release,
  remote, and real-network work remain deferred.
- **Stop conditions:** The exact changed-file boundary is `ROADMAP.md`,
  `Cargo.lock`, `crates/maverick-client/Cargo.toml`,
  `crates/maverick-client/src/lib.rs`,
  `crates/maverick-client/src/h2_transport.rs`, and new
  `crates/maverick-client/src/direct_v3_h2.rs`; stop and re-adjudicate before
  changing any other file. Also stop rather than add a stable public runtime
  API, product-server dependency, wire/vector/schema/version change, legacy
  behavior change, runtime enablement, remote action, or private data.

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
