# Maverick Protocol Specification

Status: frozen narrow v1.0 scope for the `maverick-tls-h2-cli-v1`
engineering release. This is not a production, formal-audit, anonymity,
censorship-resistance, browser-fingerprint-equivalence, or standardization
claim.

Maverick is a single-protocol privacy proxy design with a small v1 mandatory
feature set. Ordinary users should only need a server address, credential, and
mode: `auto`, `stable`, or `private`.

## Stable v1.0 Target Scope

The only intended `v1.0.0` stabilization target is
`maverick-tls-h2-cli-v1`, matching `docs/STABLE_SCOPE_CANDIDATE.md`.

Included in that target:

- Rust reference client and server managed by the `maverick` CLI.
- TLS 1.3 plus HTTP/2 as the stable transport.
- Auth v1 and Auth v2 ClientHello / ServerHello behavior.
- Replay cache behavior.
- Static or reverse-proxy fallback for ordinary requests and unauthenticated
  tunnel-like requests.
- TCP relay, DNS relay, and documented UDP relay behavior.
- Per-user flow limits, optional byte pacing, global/per-source connection caps,
  pre-auth admission limits, fallback concurrency caps, failed-auth rate
  limiting, and loopback-only metrics.
- Config version `1`, Auth v1 `protocol_version = 1`, and explicit Auth v2
  `protocol_version = 2`.

Excluded from that target:

- Native server-side ECH.
- Cloudflare-fronted WebSocket as a stable transport.
- H3/QUIC as a stable transport.
- TUN system apply behavior.
- GUI or app runtime behavior.
- Post-quantum or Noise experimental handshakes.
- Strong anonymity, traffic-analysis resistance, or censorship-proof claims.
- Production binary distribution for every platform.

The v1.0 wire/auth/fallback surface is frozen only for this narrow target:
Maverick frames are carried over authenticated TLS/H2 tunnel requests;
ClientHello and ServerHello transcript inputs stay compatible with the current
Auth v1/v2 definitions; unauthenticated or failed pre-auth tunnel-like requests
route through fallback behavior without protocol-specific error strings.
Anything outside this list stays experimental and default-off.

## Goals

- Provide a maintainable TLS 1.3 + HTTP/2 proxy tunnel prototype.
- Authenticate users inside the encrypted HTTP/2 body.
- Reject replayed ClientHello messages.
- Fall back to normal website behavior for unauthenticated requests.
- Keep room for future transports without changing the core flow semantics.

## Non-Goals

- Production security claims.
- Browser-grade TLS fingerprint mimicry.
- MASQUE, WebTransport, or native Noise transport in the current prototype.
- Native server-side ECH in the `v1.0.0` target scope.
- GUI/App runtime or TUN system apply behavior in the `v1.0.0` target scope.
- Advanced traffic shaping in v1.
- Guidance targeted at any specific country, firewall, or censorship system.

## Transport

Maverick v1 runs over TLS 1.3 with ALPN `h2`. The v2 baseline adds an optional
H3/QUIC carrier behind build-time `h3` plus runtime
`advanced.experimental_h3`. H2 remains mandatory and is still the default path.
H3/QUIC is outside the `maverick-tls-h2-cli-v1` stable target.

The client opens an HTTP/2 `POST` request to the configured `tunnel_path` with
`content-type: application/octet-stream`. Maverick frames are carried in DATA
frames in both directions.

The default implementation uses rustls. v1 does not claim Chromium or browser
TLS fingerprint parity. Client `private` mode rejects the default rustls
fingerprint and requires a browser-mimic TLS backend when that mode is used.

## Session Lifecycle

1. Client establishes TCP, TLS, and HTTP/2.
2. Client sends `CLIENT_HELLO` as the first Maverick frame.
3. Server validates credential id, HMAC tag, timestamp, version, and replay nonce.
4. On success, server returns `SERVER_HELLO`.
5. Client sends `OPEN_TCP`, `DNS_QUERY`, or `OPEN_UDP`.
6. Server connects the target TCP endpoint, performs the requested DNS query, or
   opens a bounded UDP relay flow.
7. Both sides exchange `TCP_DATA`, `TCP_FIN`, `TCP_RESET`, `DNS_RESPONSE`,
   `UDP_PACKET`, or `ERROR`.

The current prototype creates one tunnel request per SOCKS CONNECT, DNS query,
or SOCKS5 UDP ASSOCIATE control flow. UDP datagrams on one association reuse
the same authenticated UDP flow until idle timeout or close.

## Authentication

Auth v1 `CLIENT_HELLO` contains:

- `protocol_version = 1`
- `client_nonce` of 32 random bytes
- `timestamp_unix`
- `credential_id`
- `mode`
- `feature_flags`
- `auth_tag = HMAC-SHA256(secret, transcript)`

The transcript label is `Maverick v1 client hello` and includes the tunnel path
so a token for one deployment path cannot be replayed to another path.

Auth v1 `SERVER_HELLO` returns selected v1 parameters and a server HMAC tag
bound to the client nonce, server nonce, session id, and selected parameters.

When the `FEATURE_TLS_CHANNEL_BINDING` bit is requested and selected, both
ClientHello and ServerHello HMAC transcripts also include the 32-byte TLS
exporter value for the current direct TLS connection. This does not change the
wire payload shape; it only changes the authenticated transcript. Required
channel binding is a direct H2/WebSocket transport setting and is not used for
experimental H3 or TLS-terminating fronted deployments.

Auth v2 is an explicit opt-in compatibility path for credential rotation. It
uses `protocol_version = 2` in `CLIENT_HELLO_V2` and
`SERVER_HELLO_V2`; see `docs/AUTH_V2_SPEC.md` for transcript fields and rollout
rules. Auth v1 remains the default unless both client and server configs enable
Auth v2.

## Replay Protection

The server rejects ClientHello messages when:

- timestamp is outside the configured replay window;
- the same `credential_id + client_nonce` has already been seen in the window;
- the per-credential entry cache or per-shard credential-key cache remains full
  after expired entries are cleaned.

Replay failure is treated like unauthenticated remote behavior and falls back to
ordinary website response behavior.

## Fallback Semantics

For non-tunnel requests and failed unauthenticated tunnel attempts, the server
routes the original method and path/query through the configured fallback
handler. It must not return strings such as `bad password`, `invalid user`, or
`Maverick error` to untrusted remote clients. For failed tunnel attempts, the
request body may already have been consumed by the protocol sniffer and is not
forwarded to a reverse-proxy fallback.

## Error Semantics

Before authentication succeeds, no Maverick `ERROR` frame is sent.

After authentication succeeds, `ERROR` payloads may use coarse error codes:

- `TARGET_CONNECT_FAILED`
- `FLOW_NOT_FOUND`
- `FLOW_LIMIT_EXCEEDED`
- `PROTOCOL_ERROR`
- `INTERNAL_ERROR`

Payloads must not include secrets, tokens, target payload bytes, or verbose
operator-only diagnostics.

## Versioning

The v1.0 target supports only the current Auth v1 and Auth v2 hello versions:

- Auth v1 `protocol_version = 1`;
- Auth v2 `protocol_version = 2`.

Other hello versions fall back at the remote behavior layer. Future version
negotiation should stay inside authenticated and encrypted protocol state where
possible.

## Implemented v1.1 Items

- HTTP CONNECT local inbound.
- DNS relay over tunnel frames.
- Basic UDP relay through SOCKS5 UDP ASSOCIATE.
- Reverse-proxy fallback for ordinary web requests.
- Loopback-only metrics endpoint.

## Implemented v2 Items

- Internal transport abstraction.
- Optional H3/QUIC carrier behind feature and runtime gates.
- Runtime H3 fallback/cooldown to H2.
- Explicit `OPEN_UDP` / `UDP_PACKET` flow mapping with bounded idle timeout.
- H2/H3 local relay and concurrency coverage.

## Future Extensions

- v3: stronger shaping, deployment profile derivation, ECH when practical,
  anonymous credential lookup, credential rotation, mobile bindings.
- v3.5 and later: shape regression lab, platform integrations, crypto agility,
  conformance, and governance.
