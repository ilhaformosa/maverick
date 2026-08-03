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

### T027b-2b1c — bounded native-QUIC termination draining

- **User result:** The private local-only native-quiche server foundation keeps
  a closing connection owned until quiche reports it closed, so a locally
  requested close gets a bounded send opportunity and peer draining can finish
  its protocol timer. This is repository-local lifecycle correctness, not an
  authenticated runtime, data plane, or user-visible product result.
- **Scope:** Separate active, close-pending-send, draining, and closed transport
  states directly from live quiche facts. Keep synchronous registry aliases,
  source accounting, and capacity until `is_closed()`. Make connection actors
  capture their terminal reason, flush a pending close before processing an
  already-due transport timer, continue bounded receive and timer work while
  draining, and use a 1.5-second actor termination deadline inside the existing
  two-second endpoint join budget. The endpoint still aborts overdue actors and
  unconditionally drains its `JoinSet` before reclaiming joined routes.
- **Acceptance:** Retain focused red-to-green evidence. Feed server close
  datagrams into a real quiche peer and verify the exact peer error; prove local
  close and peer draining retain both CID aliases, source/global capacity, and
  actor ownership until the transport closes and the actor joins; prove
  established cancellation sends a real close while pre-key cancellation and
  handshake failure remain hard-bounded; preserve stable server-SCID checks
  around every receive, send, and timer operation; and keep all previous
  endpoint, registry, default, legacy-H3, client, strict-push, lint, and local
  product gates.
- **Out of scope:** No Retry or address validation, Version Negotiation,
  Stateless Reset, CID rotation or retirement, NAT rebinding, migration,
  multipath, auth-v3, ClientControl, ServerConfirmation, policy, parser caller,
  target, egress, DNS, opener, TCP stream, relay, metrics, public API, config,
  protocol, frame, wire, schema, version, `STATUS.md`, CI, remote, deployment,
  release, real network, or system-network change. Capacity caps still do not
  prove peer-address ownership or spoofing-DoS resistance.
- **Stop conditions:** Stop on a fifth changed file, any manifest, lockfile, or
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
