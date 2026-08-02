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

### T020-Q1 — direct quiche foundation and exporter preflight

- **User result:** Establish whether the selected quiche route can safely enter
  formal development without making H3 user-visible.
- **Scope:** Pin compatible dependencies with one BoringSSL linkage, add a
  private feature-gated adapter seam with a first-party Tokio UDP driver, and
  exercise it only through a bounded `127.0.0.1` native-H3 connection test.
- **Acceptance:** macOS builds the pinned dependency set; the final graph has
  exactly one `boring` and `boring-sys`; the same live QUIC TLS connection
  provides a channel-binding exporter and actual negotiated-group observation;
  ALPN is H3, 0-RTT is off, peer H3 SETTINGS advertise Extended CONNECT and
  Datagram, and connection, stream, QPACK, header, task, and Datagram queues
  have explicit bounds. Default and old experimental-H3 behavior stay intact.
- **Out of scope:** User-visible native H3; CONNECT target relay; auth v3; UDP
  proxy; Auto selection; config, protocol, auth, frame, wire, or stored-profile
  version changes; real infrastructure; remote repository or release work;
  T021.
- **Stop conditions:** Stop if the route needs two BoringSSL linkages, cannot
  obtain exporter/group evidence from the current QUIC TLS connection, needs a
  broad TLS/QUIC fork or public core/SDK backend types, changes a versioned
  contract, or cannot preserve local compatibility and bounded resources.

This slice is not tied to a release version and does not define release scope.

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
