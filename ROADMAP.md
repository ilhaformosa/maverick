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

### T026b-1 — adopt a repository-internal quiche strict peer-push gate

- **User result:** Maverick's private direct-quiche foundation always enables a
  reviewed fail-closed H3 setting, so known peer `MAX_PUSH_ID`, `PUSH_PROMISE`,
  `CANCEL_PUSH`, push-form `PRIORITY_UPDATE`, and push-stream activity cannot
  stay hidden during later pre-auth direct-H3 runtime work. This removes one
  foundation blocker only; it does not implement the T026 auth-v3 runtime.
- **Source, license, and maintenance:** Use a repository-internal, version-pinned
  library copy under `vendor/quiche-0.29.3`, derived from the exact crates.io
  archive and its BSD-2-Clause license. Retain the archive checksum, upstream
  VCS commit, license digest, narrow maintained patches, omissions, and date in
  the vendor provenance. Do not use a public fork. Maverick maintainers own
  review, rebasing, and security maintenance of this copy. Keep it excluded
  from workspace membership so root all-targets do not build upstream examples;
  sample keys, examples, the FFI build feature, qlog, and unrelated tools stay
  absent.
- **Scope:** Change only `ROADMAP.md`, root and client Cargo manifests,
  `Cargo.lock`, the private `quiche_foundation.rs`, one focused client
  integration test, and `vendor/quiche-0.29.3/**`. Keep exact quiche 0.29.3 as
  a repository path dependency and preserve one `boring`/`boring-sys` 4.22.0
  graph. A clearly named unstable test-support feature may expose quiche's
  internal in-memory session only to the focused test. `STATUS.md`, public APIs,
  config, schemas, stored profiles, protocol/auth/frame versions, core, SDK,
  server crate, and legacy H2 stay byte for byte unchanged.
- **Acceptance:** Re-hash the source, license, POC patch, and vendor inventory;
  first reproduce that crates.io 0.29.3 lacks the setter and hides the known
  push frames. Then prove through real in-memory QUIC/H3 receive paths that
  strict mode rejects each listed frame or stream before state, QPACK, or TODO
  acceptance with fixed `FrameUnexpected`, wire code `0x105`, and an empty
  reason. Cover both peer directions, malformed QPACK input, fragmented
  non-shortest varint input before SETTINGS, and close propagation. Preserve
  default-false behavior, existing push-stream behavior, SETTINGS and QPACK
  request handling, request-form `PRIORITY_UPDATE`, GOAWAY, and unknown/reserved
  frames. Generate loopback certificates only at test runtime. Prove the one
  shared foundation H3 builder enables strict mode for both client and server
  roles before connection creation or H3 I/O, with no configuration fallback.
  Strict errors, sources, and H3 trace output must not expose peer-controlled
  values. Offline metadata/tree, lock review, tests, formatting, lint, rustdoc,
  smoke, harness, dependency inventory, deny, audit, exact-file, privacy, and
  `STATUS.md` blob gates must pass before one local commit.
- **Runtime and truth boundary:** This gate does not handle GOAWAY,
  request-form `PRIORITY_UPDATE`, Datagrams, or other pre-auth events and state.
  T026 runtime must still inspect quiche's separate bounded Datagram receive
  queue before any final authentication state transition. qlog remains disabled,
  and the outer quiche logging/privacy boundary remains in force. This queue is
  execution order, not a completion ledger; `STATUS.md` remains the only
  current product truth and authorization source.
- **Out of scope:** T026 auth-v3 runtime, CONNECT or Extended CONNECT, authority,
  target, DNS, egress, relay, user DATA or Datagram payload, fallback, public
  API or configuration, new protocol/framework work, user-visible H3, release,
  CI, remote, deployment, real-network, and system-network changes remain
  deferred.
- **Stop conditions:** Stop if exact source or license provenance cannot be
  proven; the patch needs QUIC/TLS core, dependencies, unsafe code, a second
  quiche/BoringSSL, qlog, string parsing, public API, config/schema/version, or
  another repository file; the path source fails the existing deny policy; any
  known push activity still returns `Done`; compatibility, unknown/reserved,
  privacy, dependency, or full local gates regress; tests need a committed key;
  or target/DNS/CONNECT/relay/user-data capability is introduced.

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
