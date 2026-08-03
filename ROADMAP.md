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

### T027b-2b1a — bounded server CID registry and synchronous packet router

- **User result:** `maverick-server` can privately route one bounded packet at a
  time among at most eight server-owned native-quiche connections. This is only
  a local foundation parking-and-routing table; it is not a listener, server
  endpoint, authenticated runtime, data plane, or user-visible product result.
- **Scope:** Add one private synchronous CID registry around the existing
  single-connection engine. Keep packets fixed at 1,350 bytes, active
  connections at eight, connections per source IP at two, aliases per
  connection at two, total route keys at sixteen, server-SCID collision attempts
  at four, and timeout sweep work at eight. Generate one stable server-owned
  SCID with `OsRng`, register it together with the client Initial DCID alias,
  route exact `SocketAddr` matches, and remove both aliases and source capacity
  atomically when a connection is reclaimed. Reuse no second source-count table.
- **Acceptance:** Retain the focused red-to-green result. Prove two synthetic
  clients receive distinct live server SCIDs and reach H3 without cross-routing;
  Initial retransmission reuses one connection; later server-SCID packets route;
  supported tokenless Initial envelope rules are exact; unknown, malformed,
  unsupported, token-bearing, and wrong-address packets do not grow state;
  global and per-source-IP caps apply before connection creation; RNG failure
  and four collisions leave no partial entry; cleanup restores capacity; live
  `source_ids()` remains exactly one and matches the registered server SCID; and
  fixed private errors, synchronous APIs, default, legacy H3, client foundation,
  strict-push, lint, dependency, and local product gates remain green.
- **Out of scope:** No UDP socket or listener, task, channel, Retry or address
  validation, Version Negotiation, Stateless Reset, CID rotation or retirement,
  NAT rebinding, migration, multipath, auth-v3, ClientControl,
  ServerConfirmation, policy, lease, quota, parser caller, target, egress, DNS,
  opener, TCP stream, relay, metrics, public API, config, protocol, frame, wire,
  schema, version, `STATUS.md`, CI, remote, deployment, release, or
  system-network change. The capacity caps bound damage only; without Retry they
  do not prove address ownership or spoofing-DoS resistance.
- **Stop conditions:** Stop on a fifth changed file, any manifest, lockfile, or
  dependency change, a server-to-client production dependency, any public
  third-party type, a need for a socket/listener/task/channel/auth/parser/target/
  relay seam, more than one server SCID per connection, an unbounded collection
  or loop, an async router, a default or legacy-H3 behavior change, or any
  required regression failure.

This registry remains local foundation only. T027b-2b1b, including any real UDP
listener or driver, is deferred and not started by this slice.

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
