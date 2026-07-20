# Product TUN Packet Adapter Contract

Status: Phase 1 and the separately approved Phase 2 IPv4 matrix completed on
2026-07-12. The experimental `maverick-tun` crate embeds pinned `smoltcp 0.13.1`,
accepts only caller-supplied packet I/O, and maps bounded TCP, DNS, and UDP work
into the existing Maverick client. It does not create a real TUN device or
change routes, DNS, interfaces, firewalls, proxies, or VPN state; the Phase 2
evidence runner owns the separate Linux attachment boundary. This is no
product-readiness claim.

## Goal

Define the smallest boundary that lets a proven userspace TCP/IP engine feed
TCP, DNS, and UDP work into Maverick without learning Maverick wire details and
without owning operating-system network configuration.

The implemented Phase 1 path is:

```text
application or test
    -> pre-opened packet stream
    -> selected packet engine adapter
    -> narrow Maverick flow connector
    -> existing flow limits and H2 connection pool
    -> existing Maverick TCP, DNS, and UDP frames
```

The privileged path remains separate:

```text
operator approval
    -> TunRoutePlan and TunRuntimePlan
    -> narrow platform helper
    -> open device plus route/DNS apply and rollback
    -> unprivileged packet stream handoff
```

## Reused Code

- `TunRoutePlan`, `TunApplySafetyDecision`, `TunProductionPolicyDecision`, and
  `TunRuntimePlan` own planning and apply/rollback policy.
- `ClientTunnelPool` owns bounded H2 connection reuse and carrier identity.
- the current SOCKS5 and HTTP CONNECT paths already translate TCP streams into
  `OpenTcp`, `TcpData`, `TcpFin`, and reset/close behavior;
- the DNS path already maps bounded queries to `DnsQuery` and `DnsResponse`;
- `UdpAssociation` already maps bounded datagrams to `OpenUdp` and
  `UdpPacket`;
- the SDK already owns config validation, client lifecycle, profile metadata,
  secret references, and redacted diagnostics.

The implementation extracts `MaverickTunConnector` inside `maverick-client`.
It reuses one `ClientTunnelPool`, the existing shared flow semaphore,
`open_tcp_tunnel`, DNS exchange, and `UdpAssociation`; it does not copy auth,
transport, or frame logic into the packet engine.

## Ownership Boundary

| concern | owner |
| --- | --- |
| TUN or packet-flow creation | platform application or privileged helper |
| route, DNS, interface, and rollback | existing TUN planning and helper boundary |
| TCP/IP state machine | selected external packet engine |
| Maverick auth and carrier selection | existing client runtime |
| H2 connection reuse | existing `ClientTunnelPool` behavior |
| TCP, DNS, and UDP frame mapping | narrow Maverick flow connector |
| app lifecycle and secret references | `maverick-sdk` and product application |
| packet-engine choice | internal adapter, never ordinary UI configuration |
| public diagnostics | coarse, bounded, and redacted snapshots |

The packet engine must not receive credentials, certificate pins, auth tags, or
raw Maverick configuration. The privileged helper must not receive packet
payloads or Maverick credentials.

## Implemented Interfaces

`maverick-tun` exposes engine-neutral packet and flow boundaries:

- `PacketReader::receive` returns `PacketRead::Packet(length)` or explicit
  `PacketRead::Eof`; an empty packet is not confused with end-of-stream;
- `PacketWriter::send` returns one complete IP packet at a time;
- `PacketIo::new` combines an independently owned reader and writer;
- `FlowConnector` exposes `open_tcp`, `exchange_dns`, `open_udp`, and a bounded
  `FlowConnectorSnapshot`;
- `start_packet_runtime` returns a cloneable `PacketRuntimeHandle` with
  `snapshot` and idempotent `shutdown`;
- `PacketRuntimeSnapshot` exposes only engine identity, coarse state/failure,
  counts, queue depths, task counts, and buffered-byte bounds.

The API deliberately accepts packets rather than a TUN crate, file descriptor,
or platform handle. Linux, Apple, Windows, and synthetic adapters remain outside
the engine crate and must implement the same packet boundary. `maverick-tun`
uses `#![forbid(unsafe_code)]` and contains no process-launch or host-network
setup API.

## Required Configuration

The engine receives only packet-runtime policy:

- MTU plus IPv4 and IPv6 enablement;
- separate maximums for TCP flows, UDP targets, UDP associations, and DNS
  queries;
- bounded packet/event queues, per-flow channels, socket buffers, datagram
  payloads, and a combined 256 MiB engine-plus-connector capacity ceiling;
- connect, idle, DNS, and shutdown timeouts;
- DNS interception limited to disabled or destination port 53.

It must not receive:

- server credentials or raw secret references;
- transport selection knobs intended only for internal policy;
- route, DNS resolver, interface, firewall, or service-manager commands;
- a callback that can launch arbitrary processes;
- unbounded queue or buffer values.

## Lifecycle Contract

The Phase 1 lifecycle is ordered and bounded:

```text
validated packet I/O plus connector
  -> running
  -> draining
  -> stopped or failed
```

Rules:

1. No packet is accepted before the flow connector and all limits exist.
2. Invalid limits or an inconsistent, active, or previously used connector
   resource snapshot fail before a runtime task starts; every run begins with
   fresh peak accounting, and platform rollback remains outside this crate.
3. Shutdown stops new flows, cancels DNS/UDP work, gives active TCP flows a
   bounded drain window, then forces closure.
4. The H2 pool shuts down after packet flows stop opening and before the final
   product state becomes disconnected.
5. Repeated shutdown is idempotent at the runtime and SDK boundaries.
6. A crashed unprivileged engine cannot leave route or DNS rollback ownership
   ambiguous; the helper journal remains authoritative.

## TCP Contract

- The packet engine owns SYN, retransmission, sequence, window, FIN, and RST
  behavior.
- The connector opens exactly one bounded Maverick TCP flow for each accepted
  engine TCP stream.
- Successful remote open is reported before ordinary stream relay begins.
- Local half-close maps to Maverick `TcpFin`; remote close/reset maps back to
  the engine stream without hanging the peer.
- Backpressure must propagate in both directions. Neither side may buffer an
  unbounded stream while the other is stalled.
- Cancellation, idle timeout, and engine reset release the H2 stream lease and
  flow permit.

## DNS And UDP Contract

- DNS interception policy belongs to the platform/product layer; query relay
  uses Maverick's existing bounded DNS exchange.
- Raw DNS payloads and queried names do not appear in ordinary diagnostics.
- UDP mapping reuses `UdpAssociation` semantics and its idle timeout.
- UDP responses must match the exact association endpoint; oversized or
  mismatched responses are dropped before entering the event queue.
- DNS and UDP payload maxima are validated before responses are queued.
- Unsupported ICMP behavior is explicit. It must not be silently reported as
  working full-device connectivity.

## Limits And Backpressure

The Phase 1 implementation has explicit bounds for:

- accepted TCP flows;
- UDP associations and queued datagrams;
- DNS queries in flight;
- packet ingress and egress queues;
- per-flow read/write buffers;
- reassembly state and fragmented packets;
- pending engine events;
- shutdown drain time;
- diagnostics cardinality.

The effective TCP, DNS, and UDP-association limit is clamped to the existing
client `max_concurrent_flows` limit. All packet-originated work acquires the same
shared flow semaphore used by local proxy inputs. Engine and connector task and
duplex-buffer usage are combined in one snapshot; the two directions of every
duplex buffer are both included in capacity accounting.

The connector contribution is deliberately conservative: each active TCP
relay counts its full duplex capacity rather than attempting to inspect Tokio's
internal occupancy. Combined peak task and byte values add the independently
observed engine and connector peaks, so they are safe upper bounds and are not
claims that both component peaks occurred at the same instant.

Ingress and egress queue snapshots report bounded-channel occupancy and never
exceed the configured packet queue depth. A receiver may free a channel slot
just before its actor-side gauge is decremented, so snapshot normalization uses
the channel's hard capacity instead of exposing that transient handoff as an
impossible extra queue entry.

The selected engine build fixes one 1500-byte reassembly slot, a 1500-byte
fragmentation buffer, and four assembler segments. Startup rejects a binary
whose `smoltcp` build-time constants differ. These small fixed buffers are
included in the payload-buffer budget. The Phase 2 matrix exercised its recorded
IPv4 fragmentation cases, but larger, concurrent, and adversarial fragment
cases remain later blockers. IPv6 is unscheduled.

`configured_buffer_capacity_bytes` is a payload-buffer budget for the packet
engine and connector adapter. It is not a whole-process memory ceiling: shared
H2 pool state, task metadata, protocol bookkeeping, allocator overhead, and
other client allocations are outside that counter. Phase 2 therefore recorded
operating-system RSS alongside runtime snapshots without inferring RSS from
this capacity value; later product tests must retain the same separation.

## Error And Diagnostic Contract

Public error classes are coarse:

- configuration rejected;
- packet device unavailable;
- engine startup failed;
- remote connection failed;
- DNS exchange failed;
- resource limit reached;
- timed out;
- cancelled;
- rollback or cleanup required.

Ordinary logs may include counts, durations, protocol family, coarse state, and
reason class. They must not include packet payloads, queried names, destination
addresses, credential ids, certificate paths, private host labels, or raw
platform command output.

If debug packet capture is added later, it must be a separate explicit
test-only facility, disabled by default, stored only in private evidence, and
never emitted by the SDK diagnostics snapshot.

## Evaluated Modes

### Black-Box Bridge

This remained a comparison option and was not selected for the final Phase 1
path.

Purpose:

- quickly test packet correctness and lifecycle without changing Maverick
  internals;
- compare candidates against the same current runtime;
- reject unsuitable engines before extracting a new client API.

This is not the preferred final architecture because it adds another parser and
local hop.

### Embedded Connector

This is the implemented Phase 1 path. The connector remains crate-private while
the SDK exposes only packet I/O, bounded config, lifecycle, and snapshots.

Purpose:

- reuse one H2 pool and one flow-limit path;
- remove duplicated SOCKS parsing;
- give SDK lifecycle one shutdown tree;
- provide bounded engine-specific diagnostics.

M6 was accepted before this runtime code was implemented. The earlier M6 binary
evidence does not cover this later packet runtime.

## Compatibility Rules

- The adapter does not change the frozen v1 wire or authentication formats.
- Packet-engine types do not become public config or stable SDK types.
- Replacing an engine must remain possible behind the same internal contract.
- Existing SOCKS5, HTTP CONNECT, and DNS listeners remain available and tested.
- Product TUN stays explicit and experimental after the narrow Phase 2 matrix;
  a namespace pass is not daily-use or cross-platform lifecycle evidence.

## Phase 1 Closeout

Phase 1 complete evidence is local and unprivileged:

- exact `smoltcp 0.13.1` feature pin and comparison package checks pass;
- `maverick-tun` has 21 tests: two config units and nineteen packet/lifecycle
  runtime tests; `maverick-client` adds two feature-gated connector close/reset
  tests;
- the feature-gated Maverick integration has two loopback tests proving the
  runtime gate and reuse of real auth, H2 pooling, TCP, DNS, and UDP paths;
- packet read/write failure, reader/flow-task panic, EOF queue drain,
  half-close, reset/refusal, DNS connector failure, failure counters,
  backpressure, forced shutdown, admission, oversized response, family gate,
  and quiescence cases are covered;
- default client builds do not link the packet runtime and stable mode rejects
  its runtime flag.

Phase 2 closeout is explicit: the approved-host IPv4 matrix covered real TUN
packet I/O, namespace route/DNS selection, control-plane preservation, failure
recovery, IPv4 fragmentation and ICMP policy, RSS/CPU sampling, and residue
checks. IPv6/extension-header cases were policy-blocked and are unscheduled;
sustained throughput, broader coexistence, and product-client lifecycle
evidence remain open. None may be inferred from Phase 1 or the narrower
accepted matrix.
