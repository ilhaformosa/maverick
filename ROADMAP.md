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

### T027b-2b2-1 — direct-H3 server role, SNI, and SETTINGS foundation

- **User result:** The private native-quiche server foundation freezes one
  trusted config-v3 direct-H3 server role before certificate access, UDP bind,
  or other I/O. Every admitted connection retains that same role owner, checks
  the live TLS SNI byte for byte, and becomes pre-auth foundation-ready only
  after actual peer SETTINGS processing proves the fixed bounded H3 contract.
- **Scope:** Keep one private `Arc<ServerRoleConfig>` owner across endpoint,
  registry, connection config, and connection actor ownership. Require exact
  live SNI, QUIC Datagram queues of 32/32, a 16-KiB field-section limit, zero
  QPACK table and blocked streams, Extended CONNECT, H3 Datagram, and the peer
  QUIC Datagram transport parameter. Poll mandatory H3 work while treating a
  missing peer SETTINGS record as not ready, and reject every application H3
  event or readable QUIC Datagram before authentication with fixed,
  privacy-safe connection closure.
- **Acceptance:** Retain red-to-green evidence for the former disabled
  Datagram and Extended CONNECT settings and H3-object-only readiness; reject
  legacy and direct-H2 roles before certificate or bind work; prove one Arc
  owner reaches each connection; cover missing, case-mismatched, different, and
  exact SNI; use live quiche peers to prove readiness waits for processed
  SETTINGS and to reject every peer fault representable by the live API; drive
  the production validator across every missing or mismatched required setting;
  keep SETTINGS and QPACK handling internal; reject pre-auth Datagrams,
  ordinary requests, and auth-shaped POST requests with code `0x105` and an
  empty reason; retain the five-second handshake wall deadline while waiting;
  and preserve all existing termination, CID, source/global-capacity, bounded
  flush, actor-inbox, and `JoinSet` tests.
- **Out of scope:** No ClientControl, ServerConfirmation, exporter, PSK, MAC,
  expiry, capability, or authentication state; no request authority or path
  authentication parser; no CONNECT, flow admission, target, DNS, egress,
  opener, TCP, relay, metric, data plane, public runtime/config/SDK/CLI API,
  schema, protocol, frame, wire, version, `STATUS.md`, CI, remote, deployment,
  release, real network, or system-network change. This foundation is not user
  H3, target connectivity, relay capability, or a product result.
- **Stop conditions:** Stop on a fifth changed file, manifest, lockfile,
  dependency, vendor, core, client, SDK, CLI, spec, config, or status change;
  any need to make the public role cloneable or add a public extraction API;
  a server dependency on the client; global auth state, an unbounded resource,
  auth or data-plane work; unavailable live SNI or peer SETTINGS; or any legacy
  H3, strict-push, privacy, lifecycle, CID, capacity, or `JoinSet` regression.

This remains a private repository-local role/SNI/peer-SETTINGS and pre-auth
rejection foundation only.

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
