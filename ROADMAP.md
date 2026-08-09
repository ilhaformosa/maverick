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

### T027c-2d — Same-generation sequential private CONNECT reuse

**User result.** One private native-quiche client owner can finish one
loopback IP-literal Classic CONNECT flow, wait until the peer QUIC transport
has collected that exact request stream, and then open one second sequential
flow on the same physical connection and authenticated generation. The second
flow uses a distinct request stream and distinct authority. This remains
repository-local private-foundation evidence. It is not concurrent-flow
support, a long-running SOCKS service, automatic reconnection, the normal
`start_client`, CLI, SDK, product end-to-end behavior, readiness, release, or
real-network evidence.

**Scope.** Limit this slice to `ROADMAP.md` and
`crates/maverick-client/src/quiche_foundation.rs`. Preserve the existing single
driver task, capacity-one command queue, capacity-one authenticated lease,
fixed 16-KiB flow buffers, loopback-only authority, and privacy-safe fixed
errors. Only a private flow that completed cleanly in both directions may
return to the same role's `Dormant` route, and only after
`stream_capacity(stream_id)` reports the exact matching
`InvalidStreamState(stream_id)`. Local FIN acceptance, application EOF, lease
reclamation, `stream_finished`, `stream_closed`, a counter, or elapsed time is
not collection evidence.

If a second authenticated acquire arrives while the first clean stream is
waiting for collection, retain that one response in the existing bounded
pending-acquire slot. Do not return a usable lease early and then reject its
open as a route race. After exact collection, clear the first flow's stream,
authority, identity, proof, mailbox, pending buffers, and half-close state
before waking the acquire. Reference CONNECT remains one-shot and `Consumed`.
Cancellation, reset, STOP_SENDING, malformed events, dirty completion,
authentication failure, admission or hard expiry, owner close, and driver
error remain fail-closed and never rearm the generation.

**Acceptance.** Preserve a behavioral red on the clean baseline: the existing
real manager/driver/quiche full-duplex test completes its first private flow,
then the second open is rejected and only one request stream exists. Add the
new expectation before changing product code so the same authenticated owner
and generation must complete a second sequential flow instead.

The green test uses the existing real loopback quiche pair, one client owner,
one manager, one driver task, one UDP socket, and one authentication exchange.
It records both lease generation identifiers and requires them to match. The
two flows use different canonical loopback authorities and different fixed
payloads, finish both directions independently, open exactly two distinct H3
request streams, and return the sole lease permit after each flow. The second
acquire starts without a sleep or polling loop. Final explicit close returns
all client and peer task permits.

Extend the strict real-quiche collection regression so the route is not ready
for another private flow while the first request FIN remains unacknowledged.
After the real peer acknowledgement arrives and only the exact first stream is
collected, the route becomes ready. Keep the withheld-ACK timeout, hard-expiry,
active-cancel, unfinished-half, duplicate-FIN, stale-handle, and legacy
reference one-shot regressions green. Repeat the focused two-flow test at least
20 times to catch acquire/collection scheduling races. Then run the complete
client quiche feature suite, default and no-default compatibility, Clippy,
Rustdoc, `user-smoke.sh`, and `local-harness.sh`.

**Out of scope.** Do not add concurrent client flows, a second active route,
flow map, listener loop, another local peer, replacement generation,
reconnection, retry, backoff, external service-shutdown control, Domain/DNS,
UDP relay, non-loopback or real-network I/O. Do not modify `lib.rs`, the normal
`start_client`, `ClientHandle`, session, SOCKS or HTTP CONNECT service, core,
server, CLI, SDK, manifests, `Cargo.lock`, protocol, authentication, frame,
schema, stored profile, or version. Do not add or expose a public API, feature,
owner, lease, flow, stream, listener, exporter, secret, observation, or quiche
type. This private quality evidence does not update `STATUS.md`.

**Stop conditions.** Stop and re-adjudicate before touching a third file;
increasing any queue, lease, task, flow, or buffer capacity; adding a command,
channel, `Notify`, task, manager, driver, actor, or runtime coordinator;
allowing rearm before exact collection or after any failure, cancel, dirty
completion, or expiry; requiring client concurrency, automatic replacement,
server changes, a public symbol, Domain/DNS, non-loopback I/O, or a wire,
schema, or version change. Stop rather than using two owners or two QUIC
connections as evidence for same-generation sequential reuse.

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
