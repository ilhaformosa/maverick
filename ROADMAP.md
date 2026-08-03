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

### T027b-2b2-2 — direct-H3 server auth-v3 generation runtime

- **User result:** One private native-quiche server connection authenticates
  its one physical generation exactly once after the existing role, live SNI,
  TLS 1.3, ALPN, and peer-SETTINGS gates. Only complete acceptance of the exact
  320-byte confirmation body with final FIN installs a minimal, secret-free
  authenticated-generation capability.
- **Scope:** Preselect the singleton trusted local profile before wire input;
  accept only the frozen POST control request on one stream; export the frozen
  32-byte auth-v3 value from that same live TLS connection; delegate control
  verification and confirmation encoding to core; retry only identical
  response headers and the remaining confirmation suffix; enforce a fixed
  ten-second auth wall plus the frozen credential-capped admission and hard
  expiries; and use the existing `0x105` empty-reason close, flush, drain, and
  actor-reclaim lifecycle for slice-owned failures.
- **Acceptance:** Prove live same-generation success, exact
  SETTINGS-before-Headers ordering, fixed 256/320-byte shapes, fragmented
  request collection, blocked and partial response retry, final-FIN-only
  activation, duplicate and second-stream rejection, reset/stop rejection,
  wrong live exporter/profile and wire-field rejection, Datagram and other
  pre-auth activity rejection,
  an activity-independent wall deadline, expiry/revocation races, stable
  generation identity, bounded resources and errors, value-free formatting,
  secret-free capability state, and real loopback `0x105` flush/drain/reclaim.
  Preserve the focused T027b-2b1c and T027b-2b2-1 lifecycle, strict-push,
  SETTINGS, CID, capacity, inbox, and `JoinSet` coverage.
- **Out of scope:** No T027b-2b3 flow gate; CONNECT flow, target or endpoint
  parsing, DNS, egress, opener, TCP/UDP relay, or T028 data plane; no production
  client runtime, fronted or per-flow MAC, H2 fallback, legacy downgrade, retry,
  public API, manifest, dependency, schema, protocol, auth, frame, wire,
  version, `STATUS.md`, CI, remote, deployment, release, real-network, or
  system-network change. This private feature-gated slice is not runnable H3,
  target connectivity, relay capability, runtime readiness, or a product
  result.
- **Stop conditions:** Stop on any fourth product file, registry, core, client,
  manifest, lockfile, dependency, vendor, public API, spec, config, version, or
  status change; any server dependency on client code; registry scan, multiple
  PSK attempt, wire-selected profile, copied cryptography or verification
  rules, unbounded resource, secret or untrusted-value exposure, target/data-
  plane seam, or regression in strict peer-push, close/drain, CID, capacity, or
  actor ownership.

This remains a private repository-local direct-H3 authentication and generation
capability lifecycle only.

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
