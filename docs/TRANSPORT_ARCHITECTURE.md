# Maverick Architecture

Status: compact description of the active product path.

## Data Path

```text
local application
  -> loopback SOCKS5 / HTTP CONNECT / DNS listener
  -> Maverick client
  -> client-facing TLS + HTTP/2 connection
  -> authenticated Maverick frames
  -> Maverick server
  -> policy-checked target connection
```

The direct Maverick origin accepts and uses TLS 1.3 with H2. A
TLS-terminating provider-facing outer H2 leg may negotiate TLS 1.2 or TLS 1.3.
The pool's shutdown-only diagnostics can classify the actual outer-TLS version
and negotiated key-exchange group for each installed physical H2 generation.
This client-facing observation does not describe provider-to-origin TLS,
destination TLS, end-to-end security, post-quantum policy, or a security proof.

The client reuses a bounded H2 connection across local flows. Authentication is
inside the encrypted carrier and can bind to TLS exporter material. The server
checks authentication and replay state before opening a relay target.

## Default TLS Path

On supported macOS arm64 and Linux x86_64 builds, the default client enables the
BoringSSL-backed browser-like H2 profile. It uses TLS and ECH GREASE, extension
permutation, exporter channel binding, and pinned browser-reference TLS/H2
settings. ECH GREASE provides protocol cover but does not encrypt the
ClientHello without a real ECHConfig. Known differences remain; the profile is
not browser-identical.

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
binding. This provider-dependent path works around the absence of native
server-side ECH by placing a reverse proxy in front of the origin. Its project
name is `provider-fronted workaround`; it is not ECH and is not equivalent to
native ECH. It hides the origin address and delegates client-facing TLS to the
provider; the first pilot did not load a real ECHConfig or demonstrate ECH
acceptance. The current plan tracks upstream rustls server-side ECH work without
forking rustls or vendoring an unmerged patch.

The fronted path is loopback-tested and completed one owner-only real-provider,
real-network pilot. General browsing was smooth, but video playback, large-image
loading, and weak-network completion behavior exposed open usability problems.
`STATUS.md` is authoritative for the result and claim boundary.

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
- Config-v1 Quinn H3 is retired from the product. QRET-2 removes its code,
  feature, dependencies, and loopback oracle from the current source tree;
  immutable Git and archived material preserve provenance. Any future product
  H3 is a separately qualified quiche implementation reached through complete,
  runnable, and migratable Product Config v2.
- ECH, TUN, experimental cryptography, GUI, and governance tracks are outside
  the first user pilot.

## Local Verification

`scripts/user-smoke.sh` is the human-readable product check. It runs the real
server/client path on loopback with OS-assigned ephemeral ports, proves a
correct credential relay, and proves a wrong credential is rejected.

`scripts/local-harness.sh` adds formatting, Clippy, and the Rust test suite.
Neither check changes host network settings or proves real-network usability.
