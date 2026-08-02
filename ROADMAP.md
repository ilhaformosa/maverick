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

### T022a — private same-generation QUIC auth-v3 exporter binding gate

- **User result:** One crate-private, feature-gated loopback proof shows that
  both ends of the same real quiche QUIC/TLS generation derive the frozen RFC
  9266 auth-v3 exporter and use it to mutually verify the existing 256-byte
  ClientControl and 320-byte ServerConfirmation. A replacement generation must
  authenticate from the beginning and cannot verify the old generation's
  control or inherit authenticated state.
- **Scope:** Extend only the existing T021b single-identity manager and driver
  observation. Bind each observation to its local `ConnectionGeneration`,
  confirm TLS 1.3 from the live BoringSSL `SslRef`, preserve the legacy channel
  binding label with absent context, and additionally derive exactly 32 bytes
  with `AUTH_V3_EXPORTER_LABEL` and present-empty context. Keep exporter bytes
  in a private redacted wrapper. Compose the existing auth-v3 core primitive
  only in focused loopback tests using one synthetic singleton profile and a
  neutral exact control path; do not add a manager, registry, or public seam.
- **Acceptance:** Client and server observations from one real physical
  generation have byte-identical auth-v3 exporters, actual TLS 1.3 and ALPN
  `h3`, no early data, peer QUIC transport parameters, and peer H3 SETTINGS.
  Each observation token matches a lease from its own manager. The client
  control verifies with the server's same-generation context, and the server
  confirmation verifies with the client's. After both managers close, a
  second real loopback generation has fresh tokens, rejects the first
  generation's control and exporter provenance, and completes a new auth-v3
  primitive from the beginning. Tests also reject the legacy-label exporter,
  a changed or other-generation exporter, and absent RFC 9266 context while
  explicitly accepting `Some(&[])`. Preserve all Q1/T021b resource,
  observation, peer-fact, group, ALPN, legacy-exporter, and shutdown tests.
- **Runtime and truth boundary:** This is crate-private, non-default,
  loopback-only foundation evidence. H3 control streams and SETTINGS exist only
  because quiche establishes H3; no auth control, request, CONNECT, DATA, or
  Datagram payload is sent. Fresh-handshake no-early-data evidence is not a
  resumed-session 0-RTT test. Manager close proves bounded reclamation, not
  graceful drain. This does not establish product runtime, user-visible H3,
  authentication state transition, target or flow handling, relay, fallback,
  production, release, or real-network results. `STATUS.md` remains byte for
  byte unchanged and is the sole current-truth and authorization source. This
  queue is not a completed ledger and does not define v1.3 release scope.
- **Out of scope:** H3 request/control payload, CONNECT, target, DNS, egress,
  relay, fallback, user flow, data plane, Datagram payload, resumed sessions,
  state transfer, multi-profile or shared-identity management, core/SDK/public
  API, config, wire, frame, vector, schema, version, release, CI, remote,
  system-network, and real-network work remain deferred.
- **Stop conditions:** The exact changed-file boundary is `ROADMAP.md` and
  `crates/maverick-client/src/quiche_foundation.rs`; stop before changing any
  third file. Also stop if TLS 1.3 cannot be proven from the live `SslRef`, the
  exporter cannot be tied to the exact manager generation, raw TLS/quiche types
  or secrets would cross a public boundary, the frozen core/wire/config must
  change, or success would require an H3 request, CONNECT, target, flow, auth
  runtime, private data, remote action, or host-network change.

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
