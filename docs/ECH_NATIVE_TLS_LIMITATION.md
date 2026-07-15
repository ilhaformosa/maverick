# ECH Native TLS Limitation

Status: active blocker explanation, current as of 2026-06-29.

This document explains the ECH blocker in plain language.

## Short Version

Maverick has two different ECH paths:

- Cloudflare-fronted ECH: Cloudflare handles ECH at the public edge, then
  forwards traffic to Maverick as an origin service.
- Native Maverick server-side ECH: Maverick's own Rust server handles ECH
  directly during the TLS handshake.

The first path can be tested and shipped as an edge-fronted mode if the carrier
works through Cloudflare. The second path cannot be honestly marked complete
while Maverick's server TLS library lacks server-side ECH support.

The immediate workaround is documented in `docs/ECH_WORKAROUND.md`: use the
Cloudflare-fronted WebSocket carrier and keep native
`advanced.experimental_ech` rejected.

Native server-side ECH is still a core long-term tracking item, recorded in
`docs/NATIVE_ECH_TRACKING.md`.

## What rustls Blocks

Maverick's Rust server uses `rustls` for TLS. rustls currently exposes
client-side ECH APIs that Maverick can track in a local feature harness, but
server-side ECH support is still tracked upstream in:

```text
https://github.com/rustls/rustls/issues/1980
```

As of a public GitHub API check on 2026-06-28, that issue was open:

```text
state: open
title: Server-side Encrypted Client Hello (ECH) support
updated_at: 2026-03-17T01:33:47Z
```

A public GitHub HTML check on 2026-06-29 still showed issue 1980 as `Open`.

That means Maverick can verify that a client can attempt ECH against
Cloudflare edge, but Maverick cannot yet be the server that directly decrypts
and accepts ECH.

## Why Cloudflare-Fronted Is Different

With Cloudflare-fronted ECH:

1. The user's client connects to Cloudflare.
2. Cloudflare handles the public TLS/ECH handshake.
3. Cloudflare opens a separate connection to Maverick origin.

This can reduce client-facing SNI exposure, because the public handshake is
with Cloudflare. It does not prove that Maverick's own server can process ECH,
because the ECH part ends at Cloudflare.

Cloudflare must be treated as fully trusted in this mode. It terminates the
client-facing TLS session and can observe the Maverick origin request, auth
frames, and tunnel payload carried over the fronted WebSocket connection. This
mode can be useful for controlled experiments, but it does not provide native
server-side ECH privacy against the fronting provider.

## Current Cloudflare Runtime Result

The current approved VM smoke shows:

- Cloudflare edge ECH preflight passed for a dedicated test hostname that is
  redacted from public docs.
- Cloudflare can reach the approved origin on TCP/443.
- Ordinary GET and finite POST requests reach Maverick origin through
  Cloudflare.
- The real bidirectional Maverick H2/gRPC tunnel still receives Cloudflare
  `400 Bad Request`.
- The Cloudflare-fronted WebSocket carrier successfully carries one SOCKS5 TCP
  echo flow through the private Cloudflare-fronted test hostname.

This remained true after:

- enabling Cloudflare gRPC for the zone;
- sending `application/grpc` and `te: trailers`;
- wrapping Maverick H2 body frames in gRPC message envelopes;
- using a gRPC-shaped tunnel path.

The practical Cloudflare-fronted engineering path is therefore WebSocket rather
than another operator-side DNS or dashboard change.

## How We Handle This

Maverick should keep two separate gates:

- Native ECH gate: stays blocked until a reviewed server-side ECH TLS backend
  exists. The conservative default is to track rustls upstream and not replace
  TLS stacks casually.
- Cloudflare-fronted gate: can move forward with WebSocket while documenting
  that this is not native server-side ECH.

Do not mark `advanced.experimental_ech` as accepted until the native ECH gate
passes. A Cloudflare-fronted mode should have a separate config name and a
separate capability claim.

The current recommendation remains to track rustls upstream rather than switch
Maverick's TLS backend casually. A TLS-stack replacement would be a separate
research spike requiring API, security, operational, and conformance review.

## Full vs Full Strict

Cloudflare Full mode is acceptable for the current temporary smoke because the
script generates a short-lived self-signed origin certificate.

Full (Strict) is the better long-term setting. It should be used only after the
origin serves a certificate Cloudflare can validate, such as a Cloudflare Origin
CA certificate or a public CA certificate for the test hostname. Switching to
Full (Strict) too early can cause Cloudflare origin validation failures.
