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

### T013c-3a1 — freeze direct-H2 auth-v3 control mapping and rustls trust

- **User result:** A future direct-H2 client and server can implement the same
  auth-v3 control exchange without guessing how HTTP/2 carries it or which TLS
  facts are trusted.
- **Scope:** Documentation only. Freeze the request and success-response
  method, a canonical raw path-and-query with the query completely absent,
  exact content types, body lengths, stream endings, trailer rejection,
  generation-wide failure behavior, connection ordering, and the first
  rustls-only direct-H2 trust observations. Freeze a fixed privacy-safe pre-I/O
  gate that rejects a configured tunnel path containing raw `?` or `#`, or any
  path that cannot round-trip byte for byte as a legal HTTP/2 path component.
  Only `ROADMAP.md` and `docs/AUTH_V3_DIRECT_SPEC.md` may change.
- **Acceptance:** The canonical contract gives one unambiguous mapping for the
  256-byte `ClientControl` and 320-byte `ServerConfirmation`; closes the whole
  physical TLS/H2 generation on every pre-auth, duplicate, carrier-shape, or
  auth failure without legacy fallback; requires the raw HTTP/2 path-and-query
  to equal the validated tunnel path byte for byte with no query component and
  rejects even a trailing empty `?`; requires complete confirmation before
  exposing an authenticated capability; and distinguishes actual rustls TLS
  1.3, H2 ALPN, exporter, and no-early-data observations from configured or
  offered values. The future rustls reference entry point rejects an
  unrepresentable configured path or a non-rustls/non-H2 selection before any
  I/O, without changing the current config-schema-3 parser or any existing
  legacy backend/carrier path. The server's only `Authenticating` to
  `Authenticated` transition point is after local h2 acceptance of the response
  headers and all 320 response bytes, with the final send carrying `END_STREAM`
  and returning success. One or more `send_data` operations may carry the body;
  construction, headers alone, capacity reservation, any partial DATA prefix,
  or a cumulative length below or above 320 bytes is insufficient. This is only
  a local h2 acceptance/queueing boundary, not proof of peer receipt. The
  mapping remains only a future control seam, not a user-flow/data-plane or
  multi-flow implementation.
- **Runtime and truth boundary:** This slice enables no runtime, changes no
  current product fact, and leaves `STATUS.md` byte for byte unchanged.
  `STATUS.md` remains the sole current-truth and authorization source. This
  queue remains planning, not a completed-work ledger or a v1.3 release scope.
- **Out of scope:** User-flow HTTP/data-plane mapping, multi-flow capability,
  runtime generation state, CLI, SDK, client, server, H3, BrowserMimic/BoringSSL,
  fronted routes, Auto, multi-profile selection, PSK trials, legacy fallback,
  config-schema-3 parser tightening, stored profiles, rotation, and PQ/hybrid
  policy remain deferred.
- **Stop conditions:** Stop if a third file, Cargo or lockfile change, Rust
  source, test or vector change, wire/schema change, runtime enablement, remote
  work, real-network action, release action, or private data is required.

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
