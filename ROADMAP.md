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

### T025b — TUN target-aware independent-receive contract

**Foundation result.** A connector-declared duplex `DatagramFlow` can receive
one same-target UDP datagram after a normal local request/response, even when
the packet runtime has no new local packet to exchange. The runtime still owns
one association per existing `{app, target}` key and uses its existing bounded
response path. This is a public TUN runtime contract and fake-connector
foundation, not a real Maverick H3 consumer, general UDP duplex guarantee,
product TUN result, real-network result, or release result.

**Confirmed source gap.** `DatagramFlow` currently exposes only request/response
`exchange`, and `FlowConnector::open_udp` receives no target. The UDP worker
therefore waits only for a local command and cannot ask an already-open flow for
a remote datagram. The worker key already fixes both app and target, the event
path already rejects a response whose endpoint differs from that target, and
the existing event channel, single pending response, accepted backpressure,
idle bound, flow permit, and shutdown path are sufficient. No new production
worker, queue, map, lock, or buffer is needed.

**Scope.** Hard-limit the complete card to five files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-tun/src/lib.rs`,
`crates/maverick-tun/src/runtime.rs`, and
`crates/maverick-tun/tests/runtime.rs`. Behavioral red may change only the
roadmap, the two additive default method skeletons in `lib.rs`, and the runtime
test; it must not change runtime behavior or `STATUS.md`. Preserve every client,
server, core, SOCKS, DNS, TCP, direct-v3, manifest, dependency, feature,
`Cargo.lock`, protocol/frame/config/profile version, and published Beta.4
artifact. The bounded fake-fixture channel and mutexes remain test-only and do
not count as product/runtime resources.

**Public contract skeleton.** Keep existing required `DatagramFlow::exchange`,
`DatagramFlow::close`, and `FlowConnector::open_udp` signatures and semantics.
Add object-safe `DatagramFlow::receive_unsolicited` with a default that waits
for cancellation and returns `Cancelled`, so existing serial implementations
remain source-compatible and cannot busy-loop or masquerade as clean EOF. An
override returns the next independently received datagram, or `Ok(None)` only
for clean remote close; the result makes no request-correlation claim, its
future must be safe to cancel, and the capability is fixed for the flow
lifetime. Add object-safe `FlowConnector::open_udp_for_target` whose
default ignores the target and delegates to `open_udp`. These are additive but
SemVer-observable public Rust API changes and can cause downstream same-name
method conflicts; do not call them private or absolutely non-breaking.

**Behavioral red.** Add one final-shape fake-connector packet-runtime test
based on parent `0553f2509719de07a62d0a072b00492801982f80`. Its target-aware
open override records the exact runtime target and returns one fake duplex
flow. First send local packet A and require its normal echo. Wait boundedly for
the runtime to
poll independent receive, then send local packet B; B must still echo, proving
that dropping the pending cancellation-safe receive future does not damage the
flow. Without sending another local packet, inject one wrong-target datagram
followed by one exact-target push. Only the exact-target payload may reach the
original TUN app.

The parent runtime must complete A and B but never call target-aware open or
independent receive. Capture those missing observations as data rather than
propagating a timeout. Close the input, require one open, no failed association,
non-forced shutdown, and a fully quiescent snapshot, then fail only at fixed
panic `TUN duplex UDP unsolicited receive stayed unavailable`, producing exit
101. A compile failure, immediate unsupported error, busy loop, wrong-target
delivery, second open, leaked task/association/buffer, forced shutdown, timeout
as the test error, or different panic is not an accepted red. Freeze the exact
command, output, changed files, diff check, privacy scan, and binary diff hash,
then stop for independent green authorization.

**Green runtime.** Open the worker with
`open_udp_for_target(key.target, cancel)` under the existing connect bound. In
the existing UDP worker, select among cancellation, the existing command
receiver, independent receive, and one idle deadline. A local command must win
without poisoning the receive side: end the select scope and drop that pending
future before calling the unchanged bounded `exchange`. A remote datagram must
reuse the same `EngineEvent::UdpResponse`, endpoint-equality gate, event
channel, single `pending_response`, accepted oneshot, packet writer, and payload
limit.
Successful activity in either direction refreshes the idle bound. Clean remote
close ends the association; receive/exchange/oversize/close failure preserves
the existing failed-association accounting; runtime cancellation is not a
failure.

Keep exactly one worker and one flow owner. Do not add a production task,
channel, queue, lock, map, second pending response, retry, replay, correlation
identifier, configuration field, counter, or new public error variant. The
serial default receive remains pending until cancellation and existing DNS
port-53 interception, TCP, serial exchange, admission, buffering, and shutdown
behavior remain unchanged.

**Evidence and compatibility.** The exact RED/Green test must prove initial
exchange health, cancellation and reuse of a pending independent receive,
same-target push delivery without a new local packet, wrong-target rejection,
one target-aware open, existing bounds, clean shutdown, and quiescence. Re-run
the full `maverick-tun` library/runtime suite and workspace matrices. Only after
formatting, strict Clippy, warning-denied Rustdoc, `user-smoke.sh`, and
`local-harness.sh` pass may `STATUS.md` record this foundation and its exact
limits.

No fake flow proves legacy H3, the Maverick client connector, transport
pressure, blocked-send concurrent receive, packet ordering, fairness, no loss,
request/response correlation, games or voice suitability, general TUN product
behavior, or release readiness. Package versions and Beta.4 remain unchanged;
any later publication of the public trait additions requires a new prerelease
and must not rewrite Beta.4.

**Stop conditions.** Stop if implementation needs any client, server, core,
SOCKS, manifest, dependency, feature, `Cargo.lock`, or sixth file; changes an
existing required trait signature; cannot keep both new methods object-safe
with source-compatible defaults; cannot safely cancel independent receive; or
needs a new production task/channel/queue/lock/map/buffer/counter/config/error
variant.
Also stop if a wrong-target datagram can reach the app, serial or DNS behavior
changes, existing bounded response/backpressure or shutdown cannot be reused,
or the result would need to be described as real H3, end-to-end Maverick TUN,
general UDP duplex, product readiness, a real-network result, or a release.

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
