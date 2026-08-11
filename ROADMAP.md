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

### T025a-1 — Keep one connected UDP target owner

**User result.** Consecutive packets sent by one logical server-side UDP relay
owner to one resolved target must reuse one connected operating-system UDP
socket and therefore one source address. Replies must be received in arrival
order from that target only, and the source address must remain owned until the
owner is dropped and then become reusable.

This closes the smallest server-local lifetime gap in the existing UDP packet
relay. It is foundation work only: it does not add H3 Datagram, CONNECT-UDP, a
client-visible UDP session, or a product-readiness result.

**Scope.** Change only `ROADMAP.md` and
`crates/maverick-server/src/relay.rs`. Add one module-private
`ConnectedUdpTarget` owner while preserving the existing public
`relay_udp_packet` signature and its one-packet send/receive behavior. The
wrapper remains responsible for the 65,535-byte receive allocation and the
existing timeout/error context; the private owner receives into a
caller-supplied buffer. Keep `STATUS.md`, `server.rs`, core, client, manifests,
and `Cargo.lock` unchanged.

**Behavioral red.** First extract the current lifecycle mechanically: opening
the owner only resolves and stores the allowed target; every `send(&mut self, …)`
still binds, connects, and sends through a fresh socket before replacing the
owner's latest socket; a short send fails with one fixed generic error; `recv`
reads from that latest socket into its caller's buffer without allocating or
owning a timeout; and `relay_udp_packet` creates one owner, sends once, then
performs the original bounded receive into its original-size buffer. The
existing UDP relay test must remain green after this extraction.

Then add the complete real-loopback test
`t025a1_connected_udp_owner_reuses_source_and_receives_arrival_order`. With one
owner, send fixed packet A and packet B before receiving. The real target must
receive both and record each source alongside its payload. The mechanically
preserved implementation must fail the direct same-source assertion with exit
status 101, not a timeout. Record that exact red before changing the lifecycle.
Do not use a mock, source scan, fixed sleep, or timeout-only silence.

**Green implementation.** Let the owner create and connect its socket once and
reuse that same socket for every successful send and receive. Keep target
resolution and egress policy unchanged, keep the wrapper's externally visible
one-packet behavior and existing errors unchanged, and let ordinary ownership
release the socket when the owner is dropped.

**Acceptance.** The same real test must prove that both target datagrams came
from one source. A foreign socket must first send a fixed forged datagram to
that source; the real target must then reply in the fixed B/A order; and the
owner must receive exactly B then A, so target filtering is demonstrated by
positive traffic rather than silence alone. While the owner lives, binding its
exact source must fail with `AddrInUse`; after drop, that exact address must
rebind. The target address must likewise rebind after its socket is dropped.
Each positive receive must use a fixed 64-byte caller buffer, carry its own
positive timeout, and compare only the returned slice. Preserve the existing
UDP relay test, then run the focused server test, the complete server suite,
formatting, strict Clippy, Rustdoc, `user-smoke.sh`, and `local-harness.sh`
locally.

**Out of scope and stop conditions.** Do not change an H2 or H3 caller, wire or
flow semantics, DNS relay, public API, feature graph, config/schema/protocol
version, capacity, metrics, or logging. Do not add a task, lock, queue, map,
cloneable owner, global state, manager, actor, or watchdog. Stop and
re-adjudicate if the fix requires another file, a new public type, caller
changes, more than one target per owner, or any machine network setting.

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
