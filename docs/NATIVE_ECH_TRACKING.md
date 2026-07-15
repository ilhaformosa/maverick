# Native ECH Tracking

Status: core tracking item, not an active initial-release blocker.

Native Maverick server-side ECH remains strategically important for the
protocol because it would let a Maverick server process Encrypted ClientHello
directly instead of relying on a TLS-terminating fronting provider. The current
roadmap is not blocked by this work because the Cloudflare-fronted WebSocket
carrier is the immediate workaround, but native ECH must stay visible in major
project status documents.

## Current Position

- Native server-side ECH is not implemented in Maverick.
- `advanced.experimental_ech` remains rejected for runtime use.
- The immediate workaround is Cloudflare-fronted WebSocket, where Cloudflare
  handles client-facing ECH and Maverick runs as the origin.
- This workaround is useful for the current prototype but is not native
  server-side ECH and must not be described as provider-independent ECH.

## Why This Remains Important

Native server-side ECH would reduce reliance on a fronting provider for the
client-facing ECH handshake. It is relevant to long-term protocol independence,
deployment flexibility, and future private-mode design. It is also high risk:
ECH lives inside the TLS handshake, so Maverick should not ship a custom or
casually swapped TLS implementation just to force the feature.

## Current Dependency

Maverick's server TLS backend is rustls. rustls server-side ECH support is still
tracked upstream and is not currently a reviewed Maverick integration point.

Source tracked by this project:

```text
https://github.com/rustls/rustls/issues/1980
```

## Accepted Workaround

The accepted near-term workaround is documented in `docs/ECH_WORKAROUND.md`:

```text
client -> Cloudflare ECH edge -> Maverick origin -> WebSocket carrier
```

This path keeps Maverick development moving, but it changes the trust model:
Cloudflare is a trusted TLS-terminating front and can observe origin request
metadata and the Maverick tunnel stream it proxies.

## Promotion Criteria

Native ECH can move from tracked item to active implementation only after:

- a reviewed server-side ECH TLS backend exists;
- Maverick can obtain ECHConfig from a standard source or explicit operator
  config without hard-coding provider state;
- certificate validation, ALPN, and fallback behavior are covered;
- private mode fails closed instead of silently exposing plain SNI;
- an approved-host native runtime smoke passes without mutating the developer
  workstation network;
- docs and diagnostics clearly distinguish native ECH from provider-fronted
  ECH.

## Tracking Cadence

Re-check upstream rustls server-side ECH status before any public milestone
that changes ECH claims, private-mode behavior, or TLS backend selection. If
upstream support lands, open a focused integration slice rather than enabling
runtime ECH by default.

## Non-Claims

This document is not a production, audit, stable-release, censorship-
resistance, or anonymity claim. Cloudflare-fronted ECH is not native Maverick
server-side ECH.
