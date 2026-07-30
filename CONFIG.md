# Maverick Configuration

All config files use YAML and `version: 1`.

## Canonical v1 YAML readers

`ClientConfig::from_yaml_str` and `ServerConfig::from_yaml_str` are the
canonical core readers. The CLI and SDK YAML entry points use these readers.
Each canonical reader first inspects the root `version` with one private,
duplicate-safe discriminator, then dispatches version `1` to the existing
strict v1 reader. Any other integer version returns a fixed
unsupported-version error before v1 deserialization. Missing, duplicate, or
non-integer version metadata and a non-mapping root fail closed without echoing
the untrusted version value. This routing foundation does not define or accept
config v2.

After version dispatch, the v1 reader still parses the original YAML. It
recursively rejects unknown mapping keys before validation or startup;
unknown keys are not an extension mechanism and are never corrected or allowed
to select a default silently.

Every documented v1 field and its existing default keeps the same meaning.
Adding a future field requires an explicit, versioned compatibility decision.
Stored-profile serialization is a separate boundary; this contract makes no
claim about stored-profile JSON.

## Stored client-profile JSON

The SDK fully understands and supports two usable stored-profile
representations: published Beta.1 flat JSON containing exactly its known fields
for explicit migration, and the current schema-1 envelope. This is an
intentional, observable compatibility tightening from the published Beta.1
reader. Exact known-field Beta.1 flat profiles remain readable and explicitly
migratable. A profile carrying extra mapping keys that the old reader accepted
and ignored is now intentionally rejected. Those extras were never preserved
by migration or rewriting and were never a supported extension mechanism.

At the `StoredClientProfile` deserialization boundary, every mapping node in
both supported representations recursively rejects unknown keys. Rejection uses
the fixed error `invalid stored client profile metadata`; an unknown key or
value is never treated as an extension, corrected, or echoed. When returned by
`serde_json::from_str`, this fixed text may be followed only by numeric line and
column coordinates added by `serde_json`.

Only a `StoredClientProfile` whose `compatibility_status()` is `Current` can be
serialized by that top-level type into a schema-1 envelope. A schema-1 profile
is rejected with `invalid stored client profile metadata` when channel binding
is disabled but required, or when required channel binding is combined with
H3, the legacy CDN-fronting flag, or first-class TLS-terminating CDN fronting.
Legacy and unsupported schemas retain the existing current-schema-only
serialization error, and schema-1 metadata missing channel binding retains its
existing missing-data error. Legal `Current` envelope content and ordering are
unchanged.

`Current` describes stored-metadata compatibility only. It does not prove that
the complete client configuration or referenced secrets are valid, or that a
runtime connection will succeed. This top-level guard also cannot prevent a
caller from hand-writing equivalent JSON outside `StoredClientProfile`, and it
is not an atomic file-persistence guarantee. Direct top-level serialization of
contradictory metadata rejects before calling its writer, but an enclosing
serializer, a caller that truncates a file first, or a downstream writer failure
while serializing a legal profile can still leave partial or empty output.
Maverick does not currently provide an atomic stored-profile file API.

The direct generic Serde behavior of the public nested SDK and core types is a
separate compatibility surface and is not the stored-profile reader. A future
stored-profile field requires an explicit stored-schema and reader
compatibility decision. An envelope declaring a newer schema can report typed
`UnsupportedSchema` only when its payload otherwise has the shape understood
by the current reader; a payload containing future-only fields can be rejected
during deserialization before that status is available.

## Client

```yaml
version: 1
mode: auto

local:
  socks5:
    listen: "127.0.0.1:1080"
  dns: null
  http_connect:
    enabled: false
    listen: "127.0.0.1:18080"

server:
  address: "example.com:443"
  server_name: "example.com"
  tunnel_path: "/assets/upload"
  credential_id: "u_example"
  secret: "mv1_base64url_high_entropy_secret"
  ca_cert: null
  cert_pin: null

auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false
  rotation:
    active_epoch: null
    next_credential_id: null
    auto_switch: false
    next: null

log:
  level: "info"
  redact: true

advanced:
  connect_timeout_ms: 10000
  idle_timeout_secs: 300
  max_concurrent_flows: 256
  padding: "auto"
  experimental_h3: false
  experimental_cloudflare_ws: false
  udp_idle_timeout_ms: 30000
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
  stealth:
    tls_fingerprint: "browser_mimic"
    active_probe_resistance: true
    cdn_fronting:
      enabled: false
      provider: "cloudflare"
      carrier: "h2"
      trusted_tls_terminating_provider: false
  allow_non_loopback_listeners: false
  experimental_ech: false
  experimental_tun: false
  ech_fallback_policy: "fail_closed"
```

Client local listeners must stay on loopback addresses by default. Setting a
SOCKS5, DNS, or HTTP CONNECT listener to `0.0.0.0` or a LAN address is rejected
unless `advanced.allow_non_loopback_listeners: true` is set explicitly.

`local.dns` is an optional UDP DNS relay. Firefox using a SOCKS5 proxy with
**Proxy DNS when using SOCKS v5** enabled sends hostname lookups through SOCKS
and does not need this separate UDP listener. Generated and example configs
therefore use `local.dns: null`.

Software that specifically needs a local UDP DNS port can opt in with an unused
loopback port:

```yaml
local:
  dns:
    enabled: true
    listen: "127.0.0.1:15353"
```

`log.redact` is a safety gate in this prototype. It must remain `true`;
`log.redact: false` is rejected instead of acting like a supported unsafe mode.

## Server

```yaml
version: 1
listen: "0.0.0.0:443"

tls:
  cert_path: "./certs/fullchain.pem"
  key_path: "./certs/privkey.pem"

maverick:
  tunnel_path: "/assets/upload"
  mode_default: "auto"
  replay_window_secs: 120
  replay_cache_entries_per_credential: 16384
  replay_cache_max_credentials_per_shard: 1024
  max_concurrent_flows_per_user: 128

users:
  - id: "u_example"
    name: "alice"
    secret: "mv1_base64url_high_entropy_secret"
    enabled: true
    rate_limit:
      bytes_per_second: 1048576
    max_concurrent_flows: 128
    rotation: null

fallback:
  type: "static"
  static_dir: "./public"
  index: "index.html"

# Alternative:
# fallback:
#   type: "reverse_proxy"
#   upstream: "http://127.0.0.1:8080"

log:
  level: "info"
  redact: true

auth:
  channel_binding:
    enabled: true
    require: false
  v2:
    enabled: false

advanced:
  idle_timeout_secs: 300
  tcp_connect_timeout_ms: 10000
  handshake_timeout_ms: 10000
  max_concurrent_connections: 2048
  max_concurrent_connections_per_source: 256
  pre_auth_max_concurrent: 512
  fallback_max_concurrent: 512
  h2_max_concurrent_streams: 256
  h2_max_concurrent_reset_streams: 50
  h2_max_pending_accept_reset_streams: 20
  h2_max_local_error_reset_streams: 1024
  auth_failure_window_secs: 60
  max_auth_failures_per_window: 24
  auth_failure_cache_max_entries: 4096
  max_frame_size: 65536
  experimental_h3: false
  experimental_cloudflare_ws: false
  udp_idle_timeout_ms: 30000
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
  experimental_ech: false
```

Server `log.redact` follows the same rule as the client: it must remain `true`.
The prototype does not support a non-redacted operational logging mode.

## Modes

- `auto`: default v1 behavior.
- `stable`: stable policy label whose outer carrier is H2/TCP.
- `private`: stricter privacy posture and future reserved fields.

On a separately prepared Linux server, the server-sent half of all three
modes' normal H2/TCP carrier uses the host's configured `fq` or `fq_codel` plus
stock BBR (commonly called BBRv1). Both qdiscs are equally supported, and an
existing approved selection is preserved. This is an operating-system policy,
not a YAML mode setting. `stable` always keeps its outer carrier on H2/TCP. If
experimental H3/QUIC is explicitly enabled in `auto` or `private`, that UDP
carrier uses its userspace congestion controller rather than Linux TCP BBR; H2
fallback and the server-sent half of server-to-target TCP connections still use
the host TCP policy.

Maverick does not expose transport internals as ordinary user choices. Supported
default builds and generated client configs use
`advanced.stealth.tls_fingerprint: browser_mimic`. The BoringSSL-backed path is
browser-like, not browser-identical. The currently evidence-backed targets are
macOS arm64 and Linux x86_64; other targets use or require the explicit
`rustls_default` compatibility path until matching build and fingerprint
evidence exists. `private` mode rejects `rustls_default`.

## Transport

H2/TLS is mandatory and remains the default. H3/QUIC is experimental and runs
only when the binary is built with the `h3` feature and both client and server
set:

```yaml
advanced:
  experimental_h3: true
```

If runtime H3 setup fails, the client falls back to H2 and records a short
cooldown for that server. 0-RTT remains disabled.

The owner-pilot fronting path is browser-like TLS/H2 to a Cloudflare edge, with
H2 forwarded to the origin. It is off by default, rejected in `stable` mode,
and does not enable native Maverick server-side ECH. Enable it on both client
and server only after accepting that the provider terminates TLS and can observe
Maverick authentication and tunnel payload:

```yaml
advanced:
  stealth:
    cdn_fronting:
      enabled: true
      provider: cloudflare
      carrier: h2
      trusted_tls_terminating_provider: true
```

The older `carrier: web_socket` path remains available with
`tls_fingerprint: rustls_default`; `experimental_cloudflare_ws: true` is its
legacy selector. Browser mimicry is supported only by the H2 carrier. The
normal direct transport remains H2/TLS while fronting is disabled. Loopback
coverage alone does not prove that a real provider configuration accepts
sustained bidirectional H2. The first owner pilot exercised the path through a
real provider and network; `STATUS.md` records the bounded success and open
usability failures.

The H2 carrier uses gRPC message envelopes for Maverick frames. A complete
response ends with a `grpc-status: 0` trailer; a reset, incomplete message, or
transport failure must not be presented as a successful gRPC response. The
client drains and validates that trailer while remaining compatible with
Alpha.3 servers that ended terminal DATA without trailers.

## Fallback

Maverick supports static fallback and bounded HTTP reverse-proxy fallback.
Reverse-proxy fallback currently supports `http://` upstreams through Hyper's
HTTP/1 client. Ordinary fallback requests preserve the method, path/query, safe
request headers, and body. Rejected tunnel-like requests preserve the exact
authentication-stage body bytes already read by the server without waiting for
the client to close its stream. Fixed and `Connection`-nominated hop-by-hop
headers are stripped, chunked responses are decoded, upstream response bodies
are capped at 1 MiB, and upstream failures become a generic `502 Bad Gateway`.

Fallback bodies remain bounded and buffered rather than streamed end to end.
Upstream HTTPS and request/response trailer forwarding are not supported yet.
These are explicit active-probe residuals, not origin-equivalence claims.

## DNS

DNS relay is implemented over authenticated tunnel frames. Client DNS listens
on UDP locally when enabled; server DNS sends UDP queries to the configured
upstream.

## UDP

UDP relay is implemented through SOCKS5 UDP ASSOCIATE using authenticated
`OpenUdp` / `UdpPacket` flows. One UDP ASSOCIATE control connection owns one
lazy Maverick UDP association and reuses it for later datagrams. The timeout is
bounded by:

```yaml
advanced:
  udp_idle_timeout_ms: 30000
```

UDP remains experimental and does not claim high performance for games,
realtime voice, or loss-sensitive workloads.

## Experimental Packet Runtime

`advanced.experimental_tun` defaults to `false`. It is a second runtime gate in
addition to the optional client/SDK build feature `tun-runtime`:

```yaml
advanced:
  experimental_tun: true
```

The flag alone does not create a TUN interface or change routes, DNS, firewall,
proxy, or VPN state. An embedding application must supply already-open packet
I/O through the SDK. `stable` mode rejects the flag, and a client build without
`tun-runtime` rejects startup when it is enabled. The experimental runtime has
synthetic/loopback evidence and an accepted approved-host Phase 2 IPv4 matrix
through a separate namespace-local TUN runner. That runner is not a product
network helper. IPv6 is not scheduled, and platform integration remains open.

## Auth v2 and Rotation

Auth v2 is disabled by default. Runtime authentication uses the v1
ClientHello/ServerHello path unless `auth.v2.enabled` is explicitly enabled.
Credential rotation fields are parsed and validated so migrations can be staged
without printing secret material. Server-side Auth v2 requires
`auth.v2.require=true` when `auth.v2.enabled=true`, so a v2-enabled server does
not silently keep accepting v1 ClientHello messages.

TLS channel binding is enabled by default for direct TLS transports. When both
sides have end-to-end TLS exporter material, the client requests the
`FEATURE_TLS_CHANNEL_BINDING` auth flag and both ClientHello and ServerHello
HMACs bind to that TLS connection. Set `auth.channel_binding.require: true` on
both client and server only for transports that support this direct TLS
binding; required channel binding is rejected for experimental H3 and
TLS-terminating CDN fronting. Fronted H2/WebSocket disables exporter binding
because the client-edge and edge-origin TLS connections have different
exporters.

Client rotation metadata:

```yaml
auth:
  v2:
    enabled: false
  rotation:
    active_epoch: "2026-07"
    next_credential_id: null
    auto_switch: false
    next: null
```

Clients can opt in to local next-credential switching by carrying the next
credential material and an RFC3339 activation time:

```yaml
auth:
  rotation:
    next_credential_id: "u_example_2026_08"
    auto_switch: true
    next:
      id: "u_example_2026_08"
      secret: "mv1_next_redacted_example"
      not_before: "2026-07-15T00:00:00Z"
```

When `auto_switch` is false, the client always uses `server.credential_id` and
`server.secret`. When it is true, the client switches only after
`auth.rotation.next.not_before`. The next secret is sensitive and diagnostic
commands must redact it.

Server previous credentials are bounded and time-windowed:

```yaml
users:
  - id: "u_example"
    secret: "mv1_current_redacted_example"
    rotation:
      previous:
        - id: "u_example_2026_06"
          secret: "mv1_previous_redacted_example"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-15T00:00:00Z"
      next:
        id: "u_example_2026_08"
        not_before: "2026-07-15T00:00:00Z"
```

Validation rejects short rotated secrets, duplicate active/previous/next ids,
more than four previous credentials per user, invalid RFC3339 timestamps,
client `auto_switch` without next credential material, mismatched client next
ids, and previous windows whose `not_after` is not after `not_before`.

## Shaping Budgets

Shaping is disabled by default. When enabled, the current runtime applies
bounded client-side padding, server-side padding, client-side batching, and
bounded delay according to these budgets:

```yaml
advanced:
  shaping:
    enabled: false
    max_padding_bytes_per_frame: 256
    max_overhead_ratio: 0.25
    max_delay_ms: 20
    max_batch_bytes: 65536
    cover_traffic: false
    cover_traffic_operator_approved: false
    cover_traffic_window_ms: 1000
```

Validation rejects zero padding caps, non-finite or out-of-range overhead
ratios, delay caps above 1000 ms, batch caps above 1 MiB, cover traffic without
`enabled: true`, cover traffic without
`cover_traffic_operator_approved: true`, and cover traffic windows outside
1-60000 ms. Runtime cover traffic is disabled by default and emits only bounded
`Padding` frames tied to observed payload budget; it does not generate idle
background traffic.

## ECH Gate

Native Maverick server-side ECH is not implemented. The config surface and
readiness diagnostics are present only to enforce future defaults and
fail-closed policy:

```yaml
advanced:
  experimental_ech: false
  ech_fallback_policy: "fail_closed"
```

`experimental_ech: true` is rejected until native server-side TLS stack support,
ECH config distribution, and controlled integration coverage are ready. In
`private` mode, `ech_fallback_policy: "allow_plain_sni"` is rejected even when
ECH itself is disabled. The Cloudflare-fronted H2 carrier and older WebSocket
carrier are provider-fronted experiments and do not enable this native ECH
flag. The browser-like client currently sends ECH GREASE only; it does not load
a real ECHConfig or establish that ECH was accepted. Treat the H2 path as a
`provider-fronted workaround`, not ECH. The current plan tracks upstream rustls
server-side ECH work and does not fork rustls or vendor an unmerged ECH patch.

## Metrics

Server metrics can be enabled with a loopback-only listener:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:19090"
```

The endpoint is `GET /metrics` and returns process-lifetime aggregate JSON
counters only. Target-opening diagnostics include:

- `target_resolution_timeouts`: hostname resolution exceeded
  `advanced.tcp_connect_timeout_ms`;
- `target_resolution_failures`: hostname resolution returned an error, excluding
  timeouts and egress-policy rejection;
- `target_connect_timeouts`: resolution succeeded, but the target TCP connection
  exceeded `advanced.tcp_connect_timeout_ms`; and
- `target_connect_failures`: resolution succeeded, but the target TCP connection
  returned an error before the timeout.

These resolution counters cover hostnames carried by ordinary SOCKS5 TCP flows.
They are separate from the optional UDP DNS relay's existing `dns_queries`
counter. An address rejected by the server egress policy is intentionally not
counted as either a DNS or target-connect failure.

Metrics have a fixed, unlabeled numeric schema. They do not contain domains, IP
addresses, ports, URLs, flow identifiers, user identifiers, credentials,
browsing content, error strings, or per-event timestamps. The metrics listener
is disabled unless configured and must remain loopback-only; Maverick does not
upload or persist these counters.

On a controlled client shutdown, Maverick also logs one fixed aggregate H2 pool
summary containing only the existing integer and boolean connection-pool
snapshot fields. It never includes the server address, a destination, a
credential, an error string, browsing content, or any user-provided string.
The process-lifetime connection and stream counts are still activity-volume
metadata and should be handled accordingly.

## Certificate Pinning

`server.cert_pin` is optional. When set, Maverick first performs normal TLS CA
and hostname validation, then verifies the leaf certificate DER SHA-256 digest.
The format is:

```yaml
cert_pin: "sha256/<base64url-no-pad>"
```

Generate the value from a PEM certificate:

```sh
maverick pin-cert --cert certs/fullchain.pem
```

## User Limits

`users[].max_concurrent_flows` overrides the server default for that user.
When the limit is reached, authenticated sessions receive a coarse
`FLOW_LIMIT_EXCEEDED` error frame and local clients surface a connection
failure.

`users[].rate_limit.bytes_per_second` enables a simple per-user shared byte
pacer across TCP, DNS, and UDP relay paths. It is intended as an operator safety
control, not a precise billing-grade traffic shaper.

## Validation

```sh
maverick check-config --kind client -c client.yaml
maverick check-config --kind server -c server.yaml
maverick migrate-config --kind client -c client.yaml
maverick migrate-config --kind server -c server.yaml
```

`advanced.connect_timeout_ms` on the client bounds the full server connection
setup path: TCP connect, TLS handshake, and H2 handshake. Timeout values must be
greater than zero.

`advanced.max_concurrent_flows` on the client limits simultaneous local TCP
proxy flows opened through SOCKS5 CONNECT and HTTP CONNECT. When the limit is
reached, new local TCP proxy attempts fail before opening a Maverick tunnel.

Server `advanced.max_concurrent_connections` and
`advanced.max_concurrent_connections_per_source` limit accepted TCP/TLS
connections globally and per source IP. Server `advanced.pre_auth_max_concurrent`
limits concurrent unauthenticated handshake and tunnel-sniffing work across
H2/H3/WebSocket carriers. Server `advanced.fallback_max_concurrent` bounds
ordinary static or reverse-proxy fallback work. Server
`advanced.h2_max_concurrent_streams` advertises the HTTP/2 concurrent stream
limit per connection and is also used as the experimental H3 bidirectional
stream cap. `advanced.h2_max_concurrent_reset_streams`,
`advanced.h2_max_pending_accept_reset_streams`, and
`advanced.h2_max_local_error_reset_streams` make HTTP/2 reset-stream defense
limits explicit instead of relying on library defaults. Server
`advanced.max_auth_failures_per_window`,
`advanced.auth_failure_window_secs`, and
`advanced.auth_failure_cache_max_entries` bound repeated failed tunnel
authentication attempts by source IP. Ordinary failed authentication attempts
still receive fallback behavior; repeated failures beyond the configured window
keep receiving fallback-shaped behavior when active-probing resistance is on and
increment `auth_rate_limit_rejections`.

`migrate-config` is currently a dry-run report. It validates config and reports
missing defaults such as `advanced.experimental_h3=false` and
`advanced.experimental_cloudflare_ws=false`,
`advanced.experimental_tun=false`,
`advanced.udp_idle_timeout_ms=30000`,
`advanced.max_concurrent_connections=2048`,
`advanced.max_concurrent_connections_per_source=256`,
`advanced.pre_auth_max_concurrent=512`,
`advanced.fallback_max_concurrent=512`,
`advanced.auth_failure_window_secs=60`,
`advanced.max_auth_failures_per_window=24`,
`advanced.auth_failure_cache_max_entries=4096`,
`advanced.shaping.enabled=false`,
`advanced.experimental_ech=false`, `advanced.ech_fallback_policy=fail_closed`,
and `auth.v2.enabled=false` without rewriting files or printing secrets.
