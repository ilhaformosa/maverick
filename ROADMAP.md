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

### T027c-1d — Private client runtime-policy owner

**User result.** The private direct-H3 client foundation owns its runtime time
snapshot, fixed receipt-acceptance caps, task budget, manager, and observation
receiver. A production-facing private start path no longer asks its caller to
supply or guess server expiry or maximum-flow policy. This remains a
feature-gated, loopback-only foundation seam. It is not a CLI/SOCKS/data-plane
path, product readiness, real routing, or a release result.

**Scope.** Limit this slice to `ROADMAP.md` and the client's private quiche
foundation. Split trusted generation-auth inputs by client and server role.
Give the client only one trusted wall-clock/monotonic snapshot and fixed
65,536-byte/128-flow receipt acceptance caps; the authenticated lease keeps
the existing effective local limit of one. Add one private production client
owner that reserves one permit from its existing per-owner task budget before
startup and owns the resulting manager plus observation receiver. Provide
private start, authenticated-acquire, and bounded asynchronous close paths.
Keep config-v3 role validation before socket I/O and preserve CA, server-name,
and optional pin verification order.

**Acceptance.** The production time provider is sampled exactly once per owner
start, and client trusted inputs contain no server admission expiry, hard
expiry, maximum-frame, or maximum-flow policy. Invalid client inputs fail
before socket I/O and return the reserved permit. Server confirmations at the
65,536-byte/128-flow receipt caps authenticate; either value above its cap
fails closed with a fixed privacy-safe error. Explicit owner close invalidates
an issued lease and returns every task permit. Startup and authentication
failure paths explicitly close any created manager and reclaim permits. The
existing v1, H2, DNS, non-loopback, zero-port, and missing-custom-CA gates stay
closed. Focused local feature tests cover these contracts without external
network access.

**Out of scope.** Do not add a public API, public clock injection, CLI, SDK,
SOCKS, CONNECT/data-plane or dynamic-target wiring, streaming, DNS or
non-loopback support, real-network I/O, a second manager/task framework, or any
manifest, feature, schema, protocol, authentication-wire, or stored-profile
change. Fixed receipt values are acceptance ceilings, not a negotiated server
policy and not an increase to the one-lease local runtime limit.

**Stop conditions.** Stop and re-adjudicate before touching a third file,
exposing a runtime owner, clock, or quiche type publicly, moving server policy
into client inputs, enabling non-loopback I/O, changing wire/schema/version
contracts, or requiring core, server, CLI, SDK, manifest, or feature changes.

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
