# Transport Architecture

Status: H2/TLS remains the default transport and now uses backward-compatible,
runtime-scoped connection reuse. H3/QUIC is an off-by-default experimental
carrier. A Cloudflare-fronted WebSocket carrier also exists for explicit
approved-host origin experiments and remains off by default. Noise is only a
feature-gated core session harness for research and is not selected by the
client transport scheduler.

## Purpose

The transport layer should let Maverick add optional future carriers without
changing the user-facing protocol identity or authentication transcript.

Current user-facing modes remain policy labels:

- `auto`
- `stable`
- `private`

They are not direct transport selectors.

## Current Implementation

`crates/maverick-client/src/transport.rs` defines:

- `TransportKind`;
- `TunnelTransport`;
- `H2Transport`;
- `transport::connect`.

`crates/maverick-client/src/scheduler.rs` defines scheduler policy state for
`auto`, `stable`, and `private` transport decisions. H3 can be selected only
when the binary is built with the `h3` feature and `advanced.experimental_h3`
is enabled. Runtime H3 connection failures are recorded in a per-server
cooldown map and fall back to H2.

`transport_debug_snapshot` maps scheduler state into the core
`GuiTransportDebugSnapshot` model for explicit local diagnostics. Ordinary
GUI/tray snapshots keep transport details hidden behind policy mode and coarse
status.

`crates/maverick-client/src/tunnel.rs` owns the shared ClientHello /
ServerHello tunnel setup path. SOCKS5 CONNECT, HTTP CONNECT, DNS, and UDP relay
paths reuse this helper so auth behavior stays consistent as transports evolve.

`crates/maverick-client/src/connection_manager.rs` owns one pool per
`start_client` runtime. For the default H2 carrier it caches at most one
TLS/H2 connection and opens one current Maverick tunnel flow on each H2 request
stream. The pool never accepts a second config, so server identity, certificate
policy, credential, mode, transport, and channel-binding settings cannot cross
runtime boundaries.

The existing client `max_concurrent_flows` semaphore bounds local work. The H2
peer's concurrent-stream setting adds a second bound. `connect_timeout_ms`
covers connection creation, stream admission, and the per-stream Maverick
handshake. `idle_timeout_secs` retires an unused cached connection. Closed or
GOAWAY connections are replaced once for H2 transport errors; authentication
or protocol failures are not retried.

`ClientHandle::h2_connection_pool_snapshot` exposes aggregate counters for
created connections, opened and reused streams, reconnects, readiness/stream
open failures, handshake timeouts, idle/closed retirements, active streams,
cached state, and shutdown state. It contains no server identity, address,
credential, or secret.

`H2Transport` delegates to the existing TLS 1.3 + HTTP/2 implementation in
`h2_transport`. The H3 path uses quinn + h3 + h3-quinn, binds UDP only for the
client/server endpoints involved, and keeps 0-RTT disabled. The Cloudflare
WebSocket path uses TLS 1.3 with HTTP/1.1 WebSocket upgrade and carries ordinary
Maverick frames as binary messages for explicitly enabled Cloudflare-origin
experiments.

`ClientTunnel` abstracts H2, H3, and Cloudflare WebSocket request streams so
SOCKS5, HTTP CONNECT, DNS, UDP, and test helper paths share the same
frame-level behavior where the carrier supports the flow type.

H3 and Cloudflare WebSocket remain per-flow connections. An initial H3 failure
may fall back to one unpooled H2 flow; later H2 selections during H3 cooldown
use the runtime H2 pool. This scope is explicit and is not a claim of universal
carrier pooling.

`maverick_core::noise` provides the research-only Noise XX session harness:
static-key checks, prologue/transport-context binding, length-prefixed
encrypted envelopes, and encrypted Maverick frame round trips. It is not a
user-facing carrier.

## Phase 2 Guardrails

- H2/TLS remains mandatory and test-covered.
- The frozen v1 frame and authentication formats are unchanged. Connection
  reuse is H2 request-stream reuse, not multiple Maverick `flow_id` values
  multiplexed inside one request stream.
- No 0-RTT.
- No auth transcript change in the first abstraction step.
- H3 dependencies remain optional and feature-gated.
- Cloudflare WebSocket remains explicit, off by default, and not a native ECH
  implementation. It is the current workaround for deployments that want
  Cloudflare edge ECH while native Maverick server-side ECH remains blocked
  upstream.
- No user-facing transport choice required for ordinary use.

## Standing Follow-Up Rules

`docs/PLAN_POST_V1.md` decides when any new transport work is active.

1. Keep H2 fallback working in every integration test profile.
2. Prioritize active-probing and fallback behavior checks before adding new
   carriers.
3. Expand stress coverage beyond loopback TCP relay when testing on a dedicated
   VM or explicitly approved host.

See [H3_QUIC_PLAN.md](H3_QUIC_PLAN.md) for the H3 implementation guardrails and
slice plan.
