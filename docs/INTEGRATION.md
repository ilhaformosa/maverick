# Proxy integration

This describes the current source implementation, not the immutable RC.2
binary. Maverick remains experimental Beta. No field qualification or
cross-language interoperability is claimed by the loopback tests.

## Use the Rust SDK

Depend on `crates/maverick-sdk` from a reviewed checkout/revision. Default
features support H2 with the browser TLS profile. Opt into the SDK's
`experimental-h3` feature for H3, native UDP and automatic TCP/UDP selection. New generated direct YAML explicitly enables
auto/dual and `allow_reliable`; omitted runtime fields remain false/None. The tested browser TLS/H3 platforms are
macOS arm64 and Linux x86_64. An explicit `--no-default-features` SDK build
retains rustls H2; it does not provide H3.

`ProxyConnector::new(config)` must run inside a Tokio runtime. It validates the
configuration and creates a reusable pool, without binding local proxy/DNS/TUN
listeners or contacting the server. Keep one connector per configured endpoint
instead of creating one per request. YAML, complete builder `auth`/`advanced`
options, custom `ca_cert`, origin protection and stored-profile restoration all
use the existing configuration and trust checks.

```rust
use maverick_sdk::{ProxyConnector, TargetAddr};
use tokio::io::{AsyncRead, AsyncWrite};

async fn forward<S>(proxy: &ProxyConnector, input: S,
                    host: String, port: u16) -> anyhow::Result<()>
where S: AsyncRead + AsyncWrite + Unpin {
    let session = proxy.connect_tcp(TargetAddr::Domain(host), port).await?;
    // TLS, Maverick authentication and remote target admission have succeeded.
    // A SOCKS/HTTP front end can now send its own success response.
    session.relay(input).await
}
```

The caller owns I/O and task scheduling. `TcpSession::carrier()` reports the
actual chosen transport without implying remote application health. `TcpSession::relay` preserves both
half-close directions and returns I/O errors and remote resets. Configured idle
expiry follows the existing relay close policy; a successful return is not an
application delivery acknowledgment. Drop its future to cancel
the flow; drop an unopened session to release it. Open cancellation, rejection
and drop release the connector's shared `max_concurrent_flows` permit.
`close()` rejects new opens and releases idle H2 pool ownership. Already
returned sessions remain caller-owned; close does not terminate them. Cancel
their relay futures or drop them when the embedding application shuts down.
Opens already in progress remain caller-owned too.

For persistent UDP, set `config.advanced.udp_policy` to
`Some(UdpPolicy::NativeRequired)` or `Some(UdpPolicy::AllowReliable)` and call
`open_udp(target, port)`. The official core selects and admits the session before
returning. It owns shared reachability avoidance/retry and uses the same policy
for SOCKS; integrators own user policy/UI, not a separate selection algorithm.

```rust
use maverick_sdk::{Bytes, ProxyConnector, TargetAddr};

async fn datagrams(proxy: &ProxyConnector, target: TargetAddr,
                   port: u16) -> anyhow::Result<()> {
    let mut session = proxy.open_udp(target, port).await?;
    let _selected = session.carrier();
    let _limit = session.max_payload();
    // This API is independent send/receive, not request/response pairing.
    if !session.send(Bytes::from_static(b"example"))? { return Ok(()); }
    let _first = session.recv().await?;
    let _second = session.recv().await?;
    session.close().await
}
```

`send` true means queued, not delivered; false means oversize/queue-full drop.
`recv` receives independent replies, including empty packets. Each session
retains one carrier and target and accepts replies only from that target; errors/target silence never replay data or move
it to another carrier. `max_payload` is at most 65507 for reliable H2 or 1200
for native H3, also subject to actual path/socket limits. SOCKS encapsulation
reduces the local usable payload. H2 may add retransmission delay; it is not
native unreliable delivery. Close/drop releases session resources and the SDK
flow slot. Keep returned sessions caller-owned when closing the connector.

`UdpCapabilityUnsupported` is a typed authenticated capability-absence result.
Only pre-response H3 network unavailability, or authenticated capability absence
before data, may select H2 under auto + `allow_reliable`. Identity, auth, protocol,
target and admission failures are terminal. Fixed H3 never selects H2;
`native_required` never does. Protected intermediaries remain fixed H2.

`open_native_udp` remains a strict native convenience API. With omitted policy,
`exchange_udp` retains old H2 request/response or H3 native behavior; with an
explicit policy it uses the selected session for one exchange. Use `open_udp`
for general bidirectional application traffic. No performance ranking,
background probes or live-session migration are provided.

`MaverickClient::start` remains available for software that wants local
SOCKS5/HTTP listeners, and `MaverickServer::start` embeds a server. Those APIs
do not install process signal handlers. `GuiClientRuntime` still distinguishes
local listening from remote connectivity; a listener is not a health probe.

## Implement the wire protocol independently

Use TLS/HTTP implementations with certificate-chain, hostname, leaf pin and
TLS exporter support. Reuse the implementation and checked vectors as the
source of truth: [authentication](../crates/maverick-core/src/auth.rs),
[frames](../crates/maverick-core/src/frame.rs),
[gRPC envelopes](../crates/maverick-core/src/grpc.rs), and
[conformance vectors](../conformance/vectors). Do not copy test credentials or
nonces into live configurations. Authentication, configuration and framing
versions are separate; runnable YAML remains version 1.

### Carrier and trust

| Carrier | HTTP request/body | Trust and lifecycle |
|---|---|---|
| Direct H2 | TLS ALPN `h2`; POST to configured tunnel path; `content-type: application/grpc`, `te: trailers`; gRPC-enveloped Maverick frames | Verify origin TLS and optional leaf pin before authentication. Multiple requests may share one H2 connection. |
| Protected intermediary H2 | Outer POST `application/octet-stream`; body is an inner TLS 1.3 byte stream, then inner H2 with the preceding gRPC framing | Inner CA/hostname and mandatory independent leaf pin; bind authentication to the inner exporter. See [protection contract](END_TO_END_PROTECTION.md). |
| Direct H3 | QUIC TLS ALPN `h3`; POST to configured tunnel path; `content-type: application/octet-stream`; raw Maverick frames in request DATA | One request (stream 0) per QUIC connection, with one target. No gRPC prefix. Verify origin TLS/pin and use that QUIC TLS exporter. |

HTTP DATA boundaries are not frame boundaries. Buffer partial frames and parse
coalesced frames. H2 responses must complete with successful `grpc-status: 0`
trailers; H3 uses HTTP stream completion. Neither HTTP 200 nor a local listener
establishes successful Maverick authentication or target admission.

Never retry failed origin protection as an unprotected session. Current H3
does not support TLS-terminating fronting. For configured auto selection, use the
[selection contract](NATIVE_UDP_AND_SELECTION.md): only pre-response network
unavailability permits H2, never TLS, pin, authentication or protocol failure.
UDP additionally permits authenticated capability absence under
`allow_reliable`, before data. Application TCP and UDP remain distinct; existing
flows never migrate.

### Frame header and connection sequence

All integers are big-endian. A frame is `type:u8 | flags:u8 | flow_id:u64 |
payload_length:u32 | payload`. Length counts payload only. Before negotiation,
use the 65536-byte payload limit; accept the server's supported negotiated range
65536 through 1048576. Reject oversized/incomplete/malformed frames rather than
allocating from unchecked lengths. In H2, each frame is one uncompressed gRPC
message: `0:u8 | message_length:u32 | frame`. HTTP body fragmentation is free;
compression and extra bytes inside a gRPC message are rejected.

1. Client sends `ClientHello` (`0x01`, flow 0, flags 0).
2. Verify `ServerHello` (`0x02`, flow 0), including its MAC, selected auth
   version/features and limits. No target/data is sent before verification.
3. Send `OpenTcp` (`0x03`, flow 1) or native `OpenUdp` (`0x07`, flags 1,
   flow 1), then wait for the matching `WindowUpdate` (`0x0c`) admission.
4. TCP uses `TcpData` (`0x04`) and `TcpFin` (`0x05`). FIN closes only its
   direction; a response can follow upload FIN, and upload can follow remote
   FIN. `CloseFlow` (`0x09`), `Error` (`0x0d`) and resets end the flow. Ignore
   `Padding` (`0x10`) as application data. A reset/error is not graceful EOF.
5. Consume response completion/trailers and release the stream/session. The
   minimal interoperable model is one target per HTTP request, with fresh
   authentication per request; H3 does not pool multiple target requests.

`OpenTcp` payload: address type `0x01` + four IPv4 octets, `0x04` + sixteen IPv6
octets, or `0x03` + `length:u16` + UTF-8 domain; then `port:u16`,
`initial_data_length:u32`, and initial data. Current clients send empty initial
data. TCP admission has an empty WindowUpdate payload.

Native UDP uses the same address payload with empty initial data. Its admission
is flags 1 with a two-byte maximum payload, positive and at most 1200. QUIC
DATAGRAM and peer H3 Datagram settings must be negotiated. HTTP Datagrams carry
Quarter Stream ID 0 followed by the unmodified UDP payload, with no Maverick
frame header or gRPC wrapper. For example `0068656c6c6f` carries `hello`, and
`00` carries an empty datagram. No fragmentation or application retransmission.
The checked [open](../conformance/vectors/native_udp_open_domain.json) and
[admission](../conformance/vectors/native_udp_admission.json) vectors give exact
control bytes. This is a Maverick extension, not standard CONNECT-UDP.

Reliable fixed-target H2 UDP requires authenticated feature bit 62 in the
ClientHello offer and ServerHello selection (auth v1/v2 MACs already cover these
fields). New-policy peers lacking the capability are unsupported; don't send
extension requests to them. Native UDP under the new policy uses the same
capability, while the legacy native API retains the earlier handshake behavior.

H2 `OpenUdp` flags 2 uses the same fixed-target address/port payload with empty
initial data. `WindowUpdate` flags 2 carries a two-byte positive limit <=65507.
`UdpPacket` flags 2 carries raw data for that target; the frame flow ID is 1.
`CloseFlow` flags 0, empty payload, ends the session with successful gRPC
completion. Reject invalid IDs, flags or oversized payloads. See checked
[open](../conformance/vectors/reliable_udp_open_domain.json) and
[admission](../conformance/vectors/reliable_udp_admission.json) vectors.

Legacy H2 UDP uses flags 0 `OpenUdp` with `idle_timeout_ms:u64`, then framed
`UdpPacket` (`0x08`) request/response messages containing destination and data.
Use its existing vectors; do not mix those messages with native datagrams.

### Authentication encodings and MACs

The secret is the **full UTF-8 `mv1_...` string**, not its base64-decoded suffix.
Use secure random 32-byte client/server nonces. Timestamps are signed 64-bit
Unix seconds. Credential identifiers/hints are nonempty and at most 512 bytes.
String/hint lengths below count UTF-8/raw bytes. Session IDs are 1–32 bytes.
Mode byte values are Auto=0, Stable=1, Private=2; Auto alone does not enable
carrier selection. Preserve configured mode and policy; do not infer a stronger
peer privacy guarantee from a successful legacy auth-v1 handshake.

| Payload | Fields in wire order (last field is the 32-byte MAC) |
|---|---|
| ClientHello v1 | `version:u16=1, nonce[32], timestamp:i64, id_length:u16, id, mode:u8, features:u64, mac[32]` |
| ServerHello v1 | `version:u16=1, nonce[32], session_length:u8, session_id, max_frame:u32, max_flows:u32, features:u64, mac[32]` |
| ClientHello v2 | `version:u16=2, epoch:u64, nonce[32], timestamp:i64, hint_length:u16, hint, mode:u8, features:u64, rotation_flags:u32, mac[32]` |
| ServerHello v2 | `version:u16=2, epoch:u64, nonce[32], session_length:u8, session_id, max_frame:u32, max_flows:u32, features:u64, rotation_window_secs:u32, mac[32]` |

For v1 the HMAC-SHA256 key is the full secret string. For v2 derive 32-byte keys
with HKDF-SHA256: IKM is that same string; salt is ASCII `Maverick auth v2 epoch`
followed by the epoch as u64; info is `Maverick auth v2 client mac` for ClientHello
or `Maverick auth v2 server mac` for ServerHello. Current clients use credential
ID UTF-8 bytes as the hint and zero rotation flags. Epoch/rotation acceptance
must match server configuration; never retry auth failure on an older version.

MAC transcripts are concatenations without separators or terminating NULs:

- Client v1: ASCII `Maverick v1 client hello`, version, client nonce, timestamp,
  u16-length-prefixed ID, u16-length-prefixed tunnel path, mode, features, binding.
- Client v2: ASCII `Maverick v2 client hello`, version, epoch, client nonce,
  timestamp, u16-length-prefixed hint, u16-length-prefixed tunnel path, mode,
  features, rotation flags, binding.
- Server v1: ASCII `Maverick v1 server hello`, client nonce, server nonce,
  u8-length-prefixed session ID, selected version, max frame, max flows,
  selected features, binding.
- Server v2: ASCII `Maverick v2 server hello`, client nonce, server nonce,
  u8-length-prefixed session ID, selected version, selected epoch, max frame,
  max flows, selected features, rotation window seconds, binding.

Feature bit 63 denotes TLS channel binding. When it is set, `binding` is ASCII
`maverick tls channel binding v1` followed by 32 exporter bytes, exported from
the authenticated TLS connection with that same label and no context. It is
not an extra Hello wire field. For protected H2 use the inner TLS exporter.
When binding is required, reject its absence; never substitute the outer relay
exporter, zeros or values sent by the peer. Compare MACs in constant time and
retain server replay/timestamp checks. Existing JSON auth vectors exercise the
non-binding transcript; live exporter behavior is covered by local/CI TLS tests.

## Integration acceptance

Check actual request/response bytes, authentication and pin rejection, both TCP
half-close orders, cancellation and flow-slot reuse. For native UDP also check
independent replies, empty/oversized packets and the negotiated cap. For auto,
check no security-error downgrade and no live-flow migration. SDK tests use
only public SDK APIs and loopback targets; they include stored protected
profiles, direct H2/H3/auto and native/legacy UDP. Run:

```sh
cargo test --locked -p maverick-core --test conformance_vectors
cargo test --locked -p maverick-sdk --test connector
cargo test --locked -p maverick-sdk --features experimental-h3 --test connector
```

External proxy software should pin a reviewed source revision and run its own
interop checks before field use. No changes to another client's repository are
required or included in this delivery.
