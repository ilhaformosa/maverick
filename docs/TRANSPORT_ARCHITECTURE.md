# Maverick Architecture

Status: compact description of the active product path.

## Data Path

```text
local application
  -> loopback SOCKS5 / HTTP CONNECT / DNS listener
  -> Maverick client
  -> TLS 1.3 + HTTP/2 connection
  -> authenticated Maverick frames
  -> Maverick server
  -> policy-checked target connection
```

The client reuses a bounded H2 connection across local flows. Authentication is
inside the encrypted carrier and can bind to TLS exporter material. The server
checks authentication and replay state before opening a relay target.

## Default TLS Path

On supported macOS arm64 and Linux x86_64 builds, the default client enables the
BoringSSL-backed browser-like H2 profile. It uses GREASE, extension
permutation, exporter channel binding, and pinned browser-reference TLS/H2
settings. Known differences remain; the profile is not browser-identical.

The rustls path remains available through an explicit config selection or a
`--no-default-features` build. It is a compatibility/debug path, not the
preferred pilot path.

## CDN-Fronted H2 Pilot Path

The primary field candidate carries the same browser-like client TLS/H2 path to
a Cloudflare edge and forwards H2 to the origin. Both configs must explicitly
enable `cdn_fronting`, select `carrier: h2`, and acknowledge the
TLS-terminating provider. The provider can observe tunnel content.

TLS exporter channel binding is disabled on this path because the client-edge
and edge-origin connections have different exporters. Direct H2 keeps exporter
binding. The fronted path is loopback-tested but has not yet passed a real
provider or restricted-network pilot.

## Unauthenticated Requests

Requests without valid Maverick authentication receive configured static or
reverse-proxy fallback behavior. They must not receive protocol-specific error
details. This reduces obvious active-probe signals but does not prove perfect
indistinguishability.

## Boundaries

- The core owns config, authentication, frames, replay, padding, and metrics.
- The client owns local listeners, transport connection management, and relay
  sessions.
- The server owns TLS/H2 acceptance, authentication gates, fallback, egress
  policy, and target relay.
- The CLI owns operator commands and the local product smoke.
- Optional H3, ECH, TUN, experimental cryptography, GUI, and governance tracks
  are outside the first user pilot.

## Local Verification

`scripts/user-smoke.sh` is the human-readable product check. It runs the real
server/client path on loopback with OS-assigned ephemeral ports, proves a
correct credential relay, and proves a wrong credential is rejected.

`scripts/local-harness.sh` adds formatting, Clippy, and the Rust test suite.
Neither check changes host network settings or proves real-network usability.
