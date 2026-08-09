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

### T027c-2f — First-flow post-success peer-failure isolation

**User result.** After the first fixed repository-controlled loopback SOCKS5
peer receives success and exchanges an initial byte and acknowledgement through
the real H3 and TCP target path, that peer resets its local connection. The sole
client owner cancels and closes the dirty flow; no second
SOCKS peer, authenticated acquire, H3 request stream, or TCP target is admitted.
All client and server resources are reclaimed within fixed bounds.

This remains repository-local private failure-composition evidence. It is not
the normal `start_client` SOCKS service, external service shutdown, recovery,
retry, reconnect, product end-to-end behavior, readiness, release, or
real-network evidence.

**Scope.** Limit this slice to `ROADMAP.md`,
`crates/maverick-client/src/lib.rs`,
`crates/maverick-client/src/quiche_foundation.rs`, and
`crates/maverick-server/src/quiche_endpoint.rs`. Preserve the T027c-2e clean
two-peer runner unchanged. Add at most one sibling fixed-result repository-test
seam under the existing `unstable-direct-v3-reference-test-support` plus
`quiche-foundation` feature combination. It may return only the existing fixed
error/result and must not expose a listener, owner, manager, generation, lease,
flow, stream, target, probe, secret, or quiche type.

Use one real loopback SOCKS peer, one private client owner, one manager, one
driver task, one client UDP socket, one authenticated generation, one real
server endpoint and actor, and one real loopback TCP target. The peer must
receive SOCKS success and send one fixed trigger byte. The target must read that
byte and return one fixed acknowledgement before the peer resets its local TCP
connection. Require the client flow cancel to complete, return the sole lease
permit, explicitly close the owner, return its task permit, and drop the bounded
listener. Do not execute the second
accept, SOCKS parse, authenticated acquire, flow open, or peer driver. After
cleanup, a connection probe to the internal SOCKS listener must be refused.

**Acceptance.** Record a focused behavioral red on the clean T027c-2e parent
before teaching the fixed-result seam to recognize this exact expected failure.
The red must traverse the real SOCKS, client quiche, server endpoint and TCP
target path; it must not be a missing symbol, mock, source scan, arbitrary quiet
period, or timeout-only result. Record its command, exit status, fixed observed
result, and root cause. This closes a missing proof contract; it is not evidence
that the normal product is broken or that the current runtime admitted a
second flow.

The green cross-crate test requires the peer to observe SOCKS success, the
first target to receive the exact trigger and return the exact acknowledgement,
and both sides to observe bounded failure cleanup. Require exactly one
successful target-open metric observation,
with all target resolution and connection failure/timeout counters zero. One
server actor's existing test gate must observe exactly one target-open
completion. Keep a different real loopback second-target listener open as a
sentinel. After the client, endpoint, actor and target task have joined, require
its nonblocking accept to report no queued connection; timeout-only silence is
not the sole proof because the sequential coordinator itself must return before
the endpoint is cancelled and the listener is examined.

Require no second SOCKS success or authenticated acquire. Rebind the first and
second target addresses, the internal SOCKS listener address, and the server
UDP address after their owners are dropped. Require the server registry, actor
set and unregistered slot to be empty, all task and lease permits returned, and
no transport-drain entry, collection, timeout, hard-expiry or join-abort
observation. Preserve the T027c-2e two-clean-peer composition, T027c-2d
exact-collection and two-stream regressions, T027c-2c one-shot
active-disconnect regression, and the existing rejection, expiry, reset,
stale-handle, cancellation and close-drain tests.
Repeat the focused T027c-2f cross-crate test at least 20 times, then run the
complete client and server quiche suites, default and no-default compatibility,
Clippy, Rustdoc, `user-smoke.sh`, and `local-harness.sh`.

**Out of scope.** Do not modify `STATUS.md`, manifests, `Cargo.lock`, core,
normal `start_client`, `ClientHandle`, the normal SOCKS/session/HTTP CONNECT
service, CLI, SDK, default features, protocol, authentication, frame, schema,
stored profile, metrics schema, or version. Do not change the production
manager, driver, authenticated-generation, route, server actor, target-open, or
relay state machines merely to make the test pass.

Do not add external shutdown control, a successful second flow, a third peer,
an open-ended listener loop, concurrent flows, a second active route, a flow
map, replacement generation, reconnect, retry, backoff, Domain/DNS, UDP relay,
non-loopback or real-network I/O. Do not broaden this slice into wrong-auth,
egress-policy, target-open-failure, second-flow-failure, or failure-matrix work.

**Stop conditions.** Stop and re-adjudicate before touching a fifth file;
changing production runtime behavior; increasing a queue, lease, task, flow,
actor, target or buffer capacity; adding a command, channel, `Notify`, task,
manager, driver, actor or coordinator; accepting a second peer after the dirty
first flow; or using a generic error, timeout-only silence, source scan, mock
transport or synthetic counter as the sole isolation proof.

Stop on any need for external shutdown, concurrency, automatic replacement, a
stable public API, a third peer, Domain/DNS, UDP, non-loopback I/O, or a wire,
schema or version change. If bounded cancellation and cleanup cannot be proven
through the existing private test seam without production-state changes, stop
rather than weakening the acceptance contract.

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
