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

### T027c-2g — Private active-flow controller shutdown lifecycle

**User result.** A fixed repository-controlled loopback SOCKS5 peer receives
success, sends one trigger byte through the real H3 path, and receives the TCP
target's acknowledgement while both sockets remain open. A controller future
outside the private service future then sends one shutdown signal. The service
stops admission, explicitly cancels the active H3 flow, closes its accepted
SOCKS connection and sole owner, and reclaims every client and server resource
within fixed bounds. The peer and target must observe closure caused by that
service cleanup; neither may disconnect first.

This is repository-local private lifecycle-composition evidence. It is not a
normal `start_client` or `ClientHandle::shutdown` path, a public shutdown
handle, a normal product SOCKS/H3 service, product end-to-end behavior,
readiness, recovery, release, or real-network evidence.

**Scope.** Limit this slice to `ROADMAP.md`,
`crates/maverick-client/src/lib.rs`,
`crates/maverick-client/src/quiche_foundation.rs`, and
`crates/maverick-server/src/quiche_endpoint.rs`. Preserve the T027c-2e clean
two-peer and T027c-2f first-peer-failure runners unchanged. Add at most one
sibling fixed-result repository-test seam under the existing
`unstable-direct-v3-reference-test-support` plus `quiche-foundation` feature
combination. It may return only the existing fixed error/result and must not
expose a shutdown sender or receiver, listener, owner, manager, generation,
lease, flow, stream, target, probe, secret, or quiche type.

Use one real loopback SOCKS peer, one private client owner, one manager, one
driver task, one client UDP socket, one authenticated generation, one real
server endpoint and actor, and one real loopback TCP target. The repository
runner may create exactly one bounded `oneshot<()>`: its sender belongs only to
the fixed peer/controller future and its receiver only to the accepted-service
future. The peer may send the signal only after observing SOCKS success,
sending the exact trigger, and receiving the exact target acknowledgement. It
must then keep its TCP stream open and wait for service-induced EOF or reset.
The target must likewise stay open after acknowledging the trigger and wait for
service-induced EOF or reset.

On the received signal, the accepted-service future must drop its bounded
listener, explicitly cancel the private flow and wait for that command to
complete, close the accepted local connection, return the sole lease permit,
and explicitly close the owner before returning its task permit. After cleanup,
a connection probe to the internal SOCKS listener must be refused and its exact
address must be reusable. Owner or manager Drop abort fallback is not an
accepted shutdown result.

**Acceptance.** Record a focused behavioral red on the clean T027c-2f parent.
The red must traverse the real SOCKS, client quiche, server endpoint and TCP
target path; observe the exact trigger and acknowledgement; and positively
observe that the peer's shutdown signal was sent and received. Before the
explicit cancel branch exists, the private scaffold must return a fixed typed
failure rather than treating future drop as shutdown. The red must not be a
missing symbol, mock, source scan, arbitrary quiet period, or timeout-only
result. Record its command, exit status, fixed observed result, and root cause.
This closes a missing private proof contract; it is not evidence that the
normal product shutdown path is broken.

The green cross-crate test requires mutually matching typed outcomes: the
controller sent the signal only after real success and acknowledgement, the
service received it and completed flow cancellation, and both the peer and
target observed bounded closure only afterward. Receiver closure, ordinary
relay failure, `DriverStopped`, timeout, owner-close failure, or a peer/target
disconnect before the signal must fail the test rather than count as expected
shutdown.

Require exactly one successful target-open metric observation, with all target
resolution and connection failure/timeout counters zero. One server actor's
existing test gate must observe exactly one target-open completion. Send the
endpoint cancellation only after the client runner and target observer have
both completed, so endpoint shutdown cannot impersonate client cleanup. Then
require the server registry, actor set and unregistered slot to be empty.
Rebind the target address, internal SOCKS-listener address, and server UDP
address after their owners are dropped. Require all task and lease permits
returned and no transport-drain entry, collection, timeout, hard-expiry or
join-abort observation.

Preserve the T027c-2f failure-isolation, T027c-2e two-clean-peer, T027c-2d
exact-collection and two-stream, and T027c-2c active-disconnect regressions,
plus the existing rejection, expiry, reset, stale-handle, cancellation and
close-drain tests. Repeat the focused T027c-2g cross-crate test at least 20
times, then run the complete client and server quiche suites, default and
no-default compatibility, Clippy, Rustdoc, `user-smoke.sh`, and
`local-harness.sh`.

**Out of scope.** Do not modify `STATUS.md`, manifests, `Cargo.lock`, core,
normal `start_client`, `ClientHandle`, the normal SOCKS/session/HTTP CONNECT
service, CLI, SDK, default features, protocol, authentication, frame, schema,
stored profile, metrics schema, or version. Do not change the production
manager, driver, authenticated-generation, route, server actor, target-open, or
relay state machines merely to make the test pass.

Do not expose a public shutdown capability, accept a second peer, open a second
flow or target, add an open-ended listener loop, concurrent flows, a second
active route, a flow map, replacement generation, reconnect, retry, backoff,
Domain/DNS, UDP relay, non-loopback or real-network I/O. Do not broaden this
slice into shutdown matrices, idle shutdown, wrong-auth, egress-policy,
target-open-failure, peer-failure, or recovery work.

**Stop conditions.** Stop and re-adjudicate before touching a fifth file;
changing production runtime behavior; increasing a queue, lease, task, flow,
actor, target or buffer capacity; adding more than the one private oneshot; or
adding a command, `Notify`, task, manager, driver, actor or reusable shutdown
coordinator. Stop if proof requires the peer or target to disconnect first,
relies on Drop/abort as graceful shutdown, or uses a generic error,
timeout-only silence, source scan, mock transport or synthetic counter as the
sole shutdown evidence.

Stop on any need for normal product wiring, a stable public API or returned
shutdown handle, concurrency, automatic replacement, a second peer or target,
Domain/DNS, UDP, non-loopback I/O, or a wire, schema or version change. If
bounded explicit cancellation and cleanup cannot be proven through the private
test seam without production-state changes, stop rather than weakening the
acceptance contract.

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
