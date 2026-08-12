# Maverick Datagram Semantic Contract

Date: 2026-08-13
Status: **Accepted architecture contract; implementation and public API remain unproven**

## Purpose

This contract defines what a Maverick datagram association means before a new
implementation is written. It prevents reliable H2/H3 framing and future
native QUIC Datagram behavior from being hidden behind one ambiguous API.

It is an architecture contract, not evidence that the current product already
implements owned associations, native Datagram, CONNECT-UDP, multi-target
SOCKS, server fairness, or real-network UDP.

QRET-1/QRET-2 supersession (2026-08-13): config-v1 Quinn H3 is retired from the
product, and its implementation, dependencies, feature, and loopback test are
removed from the current source tree. References below to legacy H3 DATA
preserve the accepted, backend-neutral reliable-framing semantics and immutable
historical oracle only; they do not describe a runnable product path. The Quinn
product adapter planned for D-004 is stopped. Any future reliable H3 DATA
adapter must be implemented and validated independently on qualified quiche
through complete, runnable, and migratable Product Config v2. This note does
not alter the API, wire, resource, ownership, or acceptance requirements in
this contract.

## Terms

| Term | Meaning |
|---|---|
| association | One bounded lifetime that carries datagrams under one policy and one authoritative supervisor |
| compatibility delivery | Reliable, ordered outer transport that carries UDP-shaped messages but can introduce retransmission and head-of-line blocking |
| native delivery | Unreliable, unordered datagrams whose individual loss does not trigger reliable retransmission |
| fixed target | Every packet in the association belongs to one target and port |
| per-datagram target | Each compatibility message may name its own target |
| child per target | A bounded manager gives each target its own fixed-target child association |
| accepted | The carrier-specific adapter accepted the datagram under its current send contract; it does not mean the target received it |

## Current and future capability mapping

| Path | Delivery | Target model | Unsolicited receive | Native Datagram |
|---|---|---|---:|---:|
| H2 serial compatibility | reliable ordered compatibility | per-datagram target | no | no |
| legacy H3 DATA duplex framing (contract/historical oracle) | reliable ordered compatibility | fixed target | yes | no |
| future CONNECT-UDP over HTTP/3 Datagram | unreliable unordered | fixed target per child | yes | yes |
| SOCKS UDP manager | determined by each child | child association per target | determined by child | determined by child |
| TUN five-tuple | determined by adapter | fixed target | determined by adapter | determined by adapter |

The phrase `legacy_h3_reliable_duplex_udp_framing` is the unambiguous name for
this backend-neutral semantic category. It must not be shortened in a way that
implies a current product path or RFC 9221, RFC 9297, or RFC 9298 support.

## Association shape

The implementation direction is conceptually:

```rust
struct OwnedDatagramAssociation {
    tx: DatagramTx,
    rx: DatagramRx,
    control: DatagramControl,
    capabilities: DatagramCapabilities,
}
```

These names are explanatory, not a frozen public Rust API.

- `DatagramTx` is an owned producer handle. Cloneability, if ever allowed,
  must be explicitly bounded and cannot multiply the association owner.
- `DatagramRx` is an owned, single-consumer receive handle.
- Both data handles are `Send + 'static` and may be moved into different tasks.
  This is an internal semantic requirement, not a frozen public signature.
- `DatagramControl` owns cancel, graceful close, terminal state, and bounded
  join behavior. It cannot be confused with a data queue.
- One supervisor owns the transport, target owner, policy state, and the only
  terminal transition.

Archived Quinn history used borrowed legacy-H3 halves internally. Those removed
shapes are provenance, not a public or `'static` API requirement. Any future
qualified quiche adapter must establish its own independent lifetime boundary;
history does not authorize restoring a Quinn product adapter.

## Mandatory invariants

### Ownership and progress

- A pending send does not stop transport receive polling or delivery to the
  inbound queue.
- A pending receive does not stop outbound progress or control handling.
- No transport is placed behind `Arc<Mutex<_>>` as the concurrency model.
- No task is created per datagram.
- A send future that is already in progress is pinned and retained; a new
  polling round must not silently recreate, cancel, retry, replay, or duplicate
  it.
- Exactly one supervisor performs the terminal transition and releases the
  transport, target owner, queues, and join state.

### Resource bounds

- Packet count and byte count are both bounded on outbound and inbound data.
- Actor tasks, target owners, sockets, child associations, and lifetime are
  included in explicit local and global budgets.
- Control and terminal signals cannot be starved behind a data queue.
- A queue limit is not a protocol constant. Initial numeric candidates must be
  frozen by tests and reviewed separately before production use.
- Native delivery may use an explicit drop/expiry policy. Reliable
  compatibility uses backpressure unless a separately documented terminal
  policy applies.

### Send completion

Submitting to the outbound queue alone is not success. Each command carries a
private completion signal; the send future completes only after the selected
carrier adapter reports its defined acceptance point.

| Carrier | A successful send means | It never means |
|---|---|---|
| H2 compatibility | the complete frame was accepted into the reliable tunnel send path | target delivery, low latency, native UDP |
| legacy H3 DATA framing | the complete frame was accepted into the reliable H3 stream send path | QUIC Datagram delivery, absence of HOL |
| native H3 Datagram | the bottom adapter accepted or queued the datagram under the current bounded budget | delivery, retransmission, ordering |

Metrics and errors must preserve these categories. A single unqualified
`sent` result must not combine them.

### Cancellation

- Cancellation before queue acceptance has no carrier effect.
- After the supervisor accepts a command, dropping the caller's wait future
  does not authorize retry, replay, or carrier fallback.
- The supervisor finishes or terminates the already-owned carrier operation
  according to the adapter contract and records one fixed outcome.
- Legacy reliable sends may have to fail the complete association closed when
  lower transport cancellation makes stream state ambiguous.
- A canceled receive wait does not consume or poison the association; a later
  receive wait remains valid unless the association is terminal.

### Close and error

- Graceful close stops new sends, follows the carrier's bounded terminal
  exchange, optionally drains only the contractually allowed inbound data,
  and joins within a fixed deadline.
- Immediate cancel stops work without pretending to be a graceful peer close.
- A hard close deadline forces cancellation and releases all local owners.
- Fatal send and receive errors lead to one terminal state. Both public
  directions eventually observe that fixed category.
- Error categories are fixed, bounded, and privacy safe. They do not contain a
  target, endpoint, path, credential, identifier, packet content, or raw
  backend error.

### Compatibility and security

- No failed auth, send, receive, or close automatically selects another auth
  protocol, carrier, target, or TrustRoute.
- User data is never dual-sent or replayed across carriers.
- Target resolution, egress policy, authentication, and resource admission
  remain in their existing fail-closed order.
- Payload budget is a typed capability. Oversized native datagrams are not
  silently moved to a reliable stream.

## Deterministic D-003 proof

The first proof uses a private fake adapter and an explicit barrier, not sleep:

1. Send `A` enters the adapter and remains incomplete behind the barrier.
2. The test proves that the same send operation is still pinned, called once,
   and not completed.
3. Receive packet `B` is injected while that barrier remains closed.
4. The independent receive handle returns `B` before send `A` completes.
5. Releasing the barrier completes send `A` exactly once.
6. Close releases the fake transport, supervisor, queues, completion signals,
   and owner counters.

The current-main old-API RED may manually poll the existing TUN UDP worker.
Current main exposes only request/response `exchange(&mut self)`, so its fake
`exchange(A)` enters a deliberately pending send stage and holds `B` behind an
explicit barrier. The old worker cannot produce `B` until that barrier is
released. The later cumulative branch's separate submit/receive methods are an
oracle, not a current-main API. The accepted RED fails only at the explicit
post-observation assertion and then completes cleanup; a timeout, leak, compile
failure, or scheduler race is not evidence.

D-003 proves ownership and progress only against the fake adapter. Its
backend-neutral write-backpressure, UDP source/socket release, and carrier
cleanup requirements remain accepted, but the D-004 Quinn product adaptation
is stopped by the QRET-1/QRET-2 supersession above. A future quiche adapter must
prove
those requirements independently. Test scaffolding must not be promoted into
a real transport or product claim.

## Consumer model

- A TUN five-tuple opens one fixed-target association. Outbound and inbound
  consumers may run independently under the same control owner.
- One SOCKS UDP ASSOCIATE owns a bounded child-association map. Each target has
  one fixed-target child; admission rate, LRU/idle eviction, egress policy, DNS,
  socket, and quota are per child.
- H2 per-datagram target behavior remains a distinct compatibility adapter; it
  does not define native CONNECT-UDP semantics.
- An SDK consumer reads the same capabilities, typed send acceptance, typed
  terminal errors, and close/cancel outcomes. It cannot assume a carrier,
  target model, unsolicited receive, or native delivery from one generic
  success value.

## Explicit non-goals for D-001 through D-003

- no change to existing public `DatagramFlow` or `FlowConnector`, and no
  restoration of removed borrowed legacy-H3 shapes;
- no production TUN, SOCKS, H2, H3, server, or SDK migration;
- no config, auth, frame, wire, version, Auto, retry, or fallback change;
- no CONNECT-UDP, QUIC DATAGRAM, PMTU, IPv6 evidence expansion, multi-target
  runtime, or server fairness implementation;
- no new public test-support API;
- no release, deployment, real-network, human-user, or product-readiness claim.

## Acceptance boundary

This contract can become Accepted after OD-03 is explicitly ratified and an
independent review confirms that the contract is unambiguous for each carrier
and for TUN, SOCKS, and SDK consumers, without requiring an unbounded resource,
hidden retry/replay, public test-only seam, or ambiguous send-success meaning.
Acceptance is architectural only; implementation remains unproven. Numeric
resource values and the production public API require later, separately
reviewed evidence.
