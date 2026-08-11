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

### T024a-1 — Give each OpenUdp flow one active target slot

**User result.** Consecutive packets in one authenticated `OpenUdp` flow that
name the same `TargetAddr` and port must reuse one connected operating-system
UDP socket and therefore one source address. A packet naming a different target
must first drop the old socket and then open a new one. The slot holds at most
one target and belongs only to that flow.

This connects the private `ConnectedUdpTarget` foundation to the existing H2
and legacy `feature = "h3"` `OpenUdp` flow handlers. It does not add
CONNECT-UDP, QUIC Datagram, pipelined requests, concurrent receives, multiple
active targets, or a product-readiness result.

The preserved exchange is serial: send one packet, then receive at most one
packet. Its positive reuse tests require the target to return exactly one timely
reply for each sent packet. The wire carries no request-response correlation,
so a delayed, duplicate, or unsolicited target datagram may be observed by
a later exchange; that traffic is neither supported nor verified in this
slice. This is not a general-purpose SOCKS UDP contract or evidence of
suitability for games or voice.

**Scope.** Change only `ROADMAP.md`, `STATUS.md`,
`crates/maverick-server/src/relay.rs`,
`crates/maverick-server/src/server.rs`, and
`crates/maverick-tests/tests/tcp_relay.rs`. Keep the target owner crate-private,
preserve the public `relay_udp_packet` signature as the unchanged one-shot
compatibility path for a bare initial `UdpPacket`, and preserve all existing
frame, config, timeout, egress-policy, rate-limit, and error-code contracts.
`STATUS.md` may receive one narrow current-truth update only after the green
implementation and all required local gates pass. Keep core, client, CLI, SDK,
manifests, `Cargo.lock`, and every other file unchanged.

**Behavioral red.** Add one real-loopback H2 integration test using the public
`UdpAssociation`. Open one association, send fixed packet A to one real UDP
target, receive its fixed reply, and record the target-observed source. Before
sending fixed packet B through that same association to that same target, try
to bind the exact first source: if the old one-shot server path has already
released it, retain that bound socket so the kernel cannot accidentally reuse
the port. The target must receive and reply to packet B. One fixed assertion
must require both live ownership of the first source and equality of the two
observed sources. The current implementation must fail that assertion with
exit status 101, not by compilation failure or timeout. Use bounded positive
operations, not a mock, source scan, fixed sleep, or timeout-only silence.

**Green implementation.** Give each H2 and legacy-H3 `OpenUdp` handler one
lexically scoped optional connected-target owner. Reuse it only when both the
`TargetAddr` and port equal the active target. On a target change, drop the old
owner before resolving or opening the replacement. If target opening, send,
receive, or its bounded receive timeout fails, drop the slot before returning
the existing per-packet error. `CloseFlow`, request EOF, idle timeout, handler
error, task cancellation, and normal handler return must release the slot by
ordinary Rust ownership. Do not add a manual `Drop` implementation.

**Acceptance.** The red H2 test must turn green and prove both replies, stable
same-target source ownership while the association is open, and exact-source
rebind after explicit association close. Legacy H3 reports local request
completion before the peer handler's return, so its reclamation check must
obtain the exact rebind within one fixed total bound, treat only `AddrInUse` as
pending, fail every other bind error immediately, and require a successful bind
as positive evidence. Add the smallest server-local tests needed to prove
target switching without broadening the API. One receive-timeout test must
prove that the request reached the real target, the timeout cleared the slot,
and the exact old source can rebind. Preserve bare `UdpPacket` one-shot behavior
and existing H2 UDP close/EOF, flow-limit, SOCKS UDP, and legacy-H3 UDP tests.
Run focused tests first, then the relevant server and integration suites under
no-default, `h3`, and all-features matrices, formatting, strict Clippy,
Rustdoc, `user-smoke.sh`, and `local-harness.sh` locally.

**Out of scope and stop conditions.** Do not change the client, core, frame or
wire formats, protocol/config/schema versions, manifests, lockfile, feature
graph, DNS relay, metrics, logging, limits, CLI, SDK, TUN, direct-v3/quiche H3,
or any machine network setting. Do not add a background task, lock, queue, map,
manager, actor, watchdog, retry, pipeline, target pool, or more than one active
target per flow. Stop and re-adjudicate if correct ownership needs a sixth file,
a public type, concurrent request/response handling, or changed bare-packet
semantics.

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
