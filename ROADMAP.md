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

### T021b — private single-identity QUIC ownership and reuse

- **User result:** Prove that one private manager instance represents one
  identity slot and owns and reuses exactly one live bounded QUIC/H3 connection
  generation. Two sequential safe borrows use that same physical connection
  without making H3 user-visible or carrying a real target or authentication.
- **Scope:** Reuse and narrowly refactor the existing T020-Q1 quiche driver so
  it remains live after handshake and H3 SETTINGS behind a fixed-capacity,
  non-waiting command channel and one-lease limit. Keep generation proof private,
  add deterministic close with bounded join and drop cancellation, and force
  the CLI logging layer to suppress the `quiche` target namespace regardless of
  external filter requests. Use only `127.0.0.1`, ephemeral ports, and temporary
  self-signed test certificates.
- **Acceptance:** Two sequential acquire/release operations return the same
  private generation token while the physical connection-creation count stays
  one. Concurrent lease, command, and task capacity exhaustion rejects
  immediately with fixed privacy-safe errors. Close rejects new borrows and
  reclaims the task, socket, permit, command sender, and bounded join; manager
  drop cancellation is proven without arbitrary sleeps or detached tasks. The
  T020-Q1 exporter, actual negotiated group, peer transport parameters, ALPN,
  0-RTT rejection, H3 SETTINGS, and resource-limit checks remain. An external
  `quiche=trace` request emits no quiche CID, address, header, marker, or raw
  backend error. Default H2 and the older experimental H3 path stay unchanged.
- **Out of scope:** Automatic reconnect or generation changes; graceful QUIC
  drain; address recovery; multiple identities or endpoints; real CONNECT
  requests or Datagram payloads; auth v3; server product integration;
  production certificate trust; config or CLI transport selection; Auto or
  user-visible H3; Linux, real-network, load, publication, or release work.
- **Stop conditions:** Stop if this needs a second driver, router, or framework;
  an unbounded queue; a public third-party backend type; a config, protocol,
  auth, frame, wire, stored-profile, or other version change; a sixth product
  file; a new dependency; unreliable log suppression; authentication or a data
  plane; or if one-connection reuse and complete resource reclamation cannot be
  proven locally.

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
