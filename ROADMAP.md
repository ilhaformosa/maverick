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

### T027b-2b1b — bounded local UDP endpoint and connection actors

- **User result:** `maverick-server` can privately run one local-only native-
  quiche UDP endpoint whose bounded per-connection actors own their connection
  state. This is repository-local lifecycle and routing foundation, not an
  authenticated runtime, data plane, or user-visible product result.
- **Scope:** Keep one endpoint task as the sole UDP receive loop, CID registry,
  and actor `JoinSet` owner. Move each accepted `ServerConnection` into exactly
  one actor with an inbox of four packets. Route with `try_send`, keep the
  existing registry as the only global/per-source capacity fact, receive at
  most 1,351 bytes to reject oversize datagrams, flush at most sixteen outbound
  packets per actor round, use one absolute two-second socket-send deadline for
  that entire round, cap handshake wall time and QUIC idle time at five seconds,
  and use a two-second graceful cancel/join deadline. At that deadline, abort
  remaining actors, drain the `JoinSet` empty, reclaim joined routes, and report
  the exceeded budget rather than returning with live work. Bind only
  `127.0.0.1:0` through a private test seam.
- **Acceptance:** Retain focused red-to-green evidence. Prove real loopback UDP
  Initial creation and later server-SCID routing for two isolated clients;
  queue-full and oversize drops; exact-address routing; global/per-source caps
  and post-join reuse; fair sixteen-packet flush rounds; cancellation and timer
  bounds; joined cleanup after normal exit, panic, timeout, and shutdown; fixed
  privacy-safe socket/actor errors; exclusive `ServerConnection` ownership;
  and unchanged default, legacy H3, client foundation, strict-push, dependency,
  lint, and local product gates.
- **Out of scope:** No Retry or address validation, Version Negotiation,
  Stateless Reset, CID rotation or retirement, NAT rebinding, migration,
  multipath, auth-v3, ClientControl, ServerConfirmation, policy, parser caller,
  target, egress, DNS, opener, TCP stream, relay, metrics, public API, config,
  protocol, frame, wire, schema, version, `STATUS.md`, CI, remote, deployment,
  release, real network, or system-network change. Capacity caps still do not
  prove peer-address ownership or spoofing-DoS resistance.
- **Stop conditions:** Stop on a sixth changed file, any manifest, lockfile, or
  dependency change, a server-to-client production dependency, any public
  third-party type, a need for auth/parser/target/relay work, an unbounded
  collection, queue, wait, flush, or shutdown, shared-lock connection state, a
  default or legacy-H3 behavior change, or any required regression failure.

This endpoint remains local foundation only. T027b-2b2 is deferred and is not
started by this slice.

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
