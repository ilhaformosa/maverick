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

### T025c — normal TUN legacy-H3 duplex consumer

**User result.** One normal `start_client` packet runtime using the existing H3
opt-in can send a UDP packet to one fixed target, receive a target datagram when
there is no new local TUN packet, and then continue sending on that association.
The carrier must be the scheduler-selected, authenticated legacy-H3 path with
the MAC-verified selected mode-negotiation bit and an exact flags-one duplex
acknowledgement. This is a bounded local TUN consumer result, not a general UDP,
real-network, product, game, voice, or release result.

**Confirmed source gap.** T025b made the TUN runtime target-aware and able to
poll an independent receive, but `MaverickTunConnector` still implements only
the old serial `open_udp`. Reusing `SocksUdpAssociation::open_with_pool` would
incorrectly import the SOCKS-only actual-H3 flags-zero setup deadline into TUN.
The new TUN path therefore needs its own crate-private pooled association
selection while preserving the existing generic and TUN flags-zero wait.

**Scope.** Hard-limit the complete card to five files: `ROADMAP.md`,
`STATUS.md`, `crates/maverick-client/src/udp.rs`,
`crates/maverick-client/src/tun_runtime.rs`, and
`crates/maverick-tests/tests/tun_packet_runtime.rs`. Behavioral red may change
only the roadmap and the TUN integration test; it must not change production or
`STATUS.md`. Preserve the TUN public traits established by T025b, every server,
core, SOCKS, DNS, TCP, direct-v3, manifest, dependency, feature, `Cargo.lock`,
protocol/frame/config/profile version, and published Beta.4 artifact.

**Pooled open contract.** The existing `FlowConnector::open_udp` path remains
unchanged. Only `open_udp_for_target` may acquire one existing client flow
permit and call `ClientTunnelPool::open` once. An actual legacy-H3 tunnel whose
MAC-verified selected mask contains the mode-negotiation bit opens flags-one
duplex for the exact target. An actual H2, WebSocket, or legacy-H3 tunnel
without that bit opens the existing flags-zero serial association on the same
already-open tunnel, without the SOCKS-only fresh acknowledgement deadline. A
pre-request H3 connection failure may still produce the existing same-open H2
fallback. Once an authenticated H3 duplex request starts, failure is terminal
for that TUN association: no second pool open, fallback, replay, resend, or
automatic reopen.

**Adapter lifecycle.** Keep one connector flow object, one association owner,
and the existing TUN flow permit. The duplex `exchange` submits one fixed-target
payload and then receives the next same-target datagram; this ordering does not
promise request correlation. `receive_unsolicited` polls the same receive half
without a send. The T025b runtime must drop a pending cancellation-safe receive
before it borrows the association for `exchange`. Cancellation during a send
or close remains fail-closed through the existing duplex poison/abort owner;
pending receive cancellation remains reusable. Clean remote close returns
`Ok(None)`. Any malformed, wrong-flow, wrong-target, transport, send, receive,
or close failure that leaves the adapter maps to an existing fixed TUN error
category and releases the sole owner. The adapter adds no log category or raw
value. A pre-request H3 connection failure may retain the transport scheduler's
existing diagnostic before its existing H2 fallback.

Do not add a production task, channel, queue, lock, map, buffer, pending
response, retry, replay, correlation identifier, config, counter, public type,
public method, or public error. H2, WebSocket, flags-zero H3, the old generic
`UdpAssociation`, SOCKS, DNS port 53, TCP, and direct-v3 retain their existing
paths and behavior.

**Behavioral red.** Add one final-shape real-loopback test based on parent
`f28dd39fd5d7b6d016b234946bac6ce4a23787e2`. Start the normal client with both
H3 and TUN runtime opt-ins and a real loopback UDP target. Send local packet A;
the target must receive it and return A on one observed server UDP source. With
no new local packet, send one push from the target to that exact source and
capture the current absence as data rather than propagating a timeout. On the
future green branch, require the push through the packet runtime, then send C,
require the target to receive C from the same source, and return C.

Before one fixed RED panic, require an H3 candidate with no cooldown, zero H2
pool activity, one opened and no failed TUN UDP association, bounded quiescent
shutdown, exact source reclamation, and clean fixture shutdown. The parent must
complete A but miss the push, then fail only at fixed panic
`normal TUN legacy-H3 UDP target push stayed unavailable`, producing exit 101.
A compile error, H2 or direct public-API path, timeout as the test error, target
contact failure, different panic, leaked owner/task/buffer, forced shutdown, or
second association is not an accepted red. Freeze the exact command, output,
changed files, diff check, privacy scan, and binary diff hash, then stop for
independent green authorization.

**Evidence and compatibility.** Green must use the same real test to prove A,
one target push without local input, C after the push, one exact target/source,
actual H3 selection, zero H2 pool use, no cooldown, and bounded cleanup. Source
review must separately prove one pool-open call, selected-bit branching,
unchanged flags-zero TUN setup, and no replay or second owner. Re-run the TUN
runtime and client matrices, the relevant H2/WS/flags-zero regressions, the
all-features workspace suite, strict Clippy, warning-denied Rustdoc,
`user-smoke.sh`, and `local-harness.sh` before updating `STATUS.md`.

This loopback result does not prove blocked-send concurrent receive, malicious
peer behavior, packet ordering, fairness, no loss, request correlation,
multi-target reuse, physical H3 connection reuse, IPv6 target support, games or
voice suitability, a real TUN device, real-network behavior, product readiness,
or release authorization. Changing the normal public `start_client` TUN
runtime behavior is SemVer-observable, although this card changes no public
Rust signature, package version, wire number or encoding, manifest, dependency,
or Beta.4 artifact. Any future publication requires a new prerelease and must
not rewrite Beta.4.

**Stop conditions.** Stop if implementation needs a sixth file, a public API or
wire/config/version change, any server/core/SOCKS/connection-manager/transport
edit, a second live owner, a production task/channel/queue/lock/map/buffer,
another pending response, a retry or replay, or a SOCKS-only timeout in TUN.
Also stop if selected-H3 failure can fall back after the UDP request starts, if
flags-zero H2/WS/H3 behavior changes, if pending receive cannot be cancelled and
reused safely, or if the result must be described beyond the bounded local TUN
consumer claim above.

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
