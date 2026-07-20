# ECH Workaround

Status: immediate workaround for the native server-side ECH upstream dependency.

Native Maverick server-side ECH is not currently available because Maverick's
server TLS backend is `rustls`, and rustls server-side ECH support is still an
upstream dependency. This document defines the supported workaround so ECH no
longer blocks the broader Maverick roadmap.

Native ECH remains a core tracking item in `docs/NATIVE_ECH_TRACKING.md`.

## Decision

Use the Cloudflare-fronted WebSocket carrier as the immediate ECH workaround.

In this mode:

1. The client connects to a configured Cloudflare-fronted Maverick hostname.
2. Cloudflare handles the public TLS/ECH handshake at the edge.
3. Cloudflare forwards the request to the Maverick origin.
4. Maverick carries tunnel frames through the explicit WebSocket carrier.

This path has already passed approved-host smoke coverage: ordinary Cloudflare
front-door GET, finite POST preflight, and one SOCKS5 TCP echo flow through the
Cloudflare-fronted WebSocket carrier.

## What This Solves

For the client-facing public connection, ECH is handled by Cloudflare. That can
avoid exposing the origin-like Maverick hostname in the public TLS ClientHello
to passive network observers between the user and Cloudflare.

This is the practical workaround available today without replacing Maverick's
TLS stack or implementing custom ECH.

## What This Does Not Solve

This is not native Maverick server-side ECH.

Cloudflare terminates the public TLS/ECH connection and must be treated as a
trusted fronting provider in this mode. Cloudflare can observe the origin
request metadata and the encrypted Maverick tunnel stream as it is proxied to
the origin. Maverick itself does not decrypt or process the ECH extension.

Do not use this mode to claim:

- native server-side ECH;
- provider-independent ECH;
- audited censorship resistance;
- browser-equivalent privacy;
- stable or production-ready ECH support.

## Configuration Boundary

The workaround uses the first-class CDN-fronted WebSocket carrier:

```yaml
advanced:
  stealth:
    cdn_fronting:
      enabled: true
      provider: cloudflare
      carrier: web_socket
      trusted_tls_terminating_provider: true
```

Both endpoints must opt in to the Cloudflare-fronted WebSocket carrier. The
older `advanced.experimental_cloudflare_ws: true` flag remains a compatibility
alias, but new configs should use `advanced.stealth.cdn_fronting.enabled`. The
stable default remains direct H2/TLS. The `trusted_tls_terminating_provider`
acknowledgement is required because the CDN edge terminates client-facing TLS
before forwarding the WebSocket carrier to the Maverick origin.

`advanced.experimental_ech` remains rejected for native runtime ECH until all
native gates pass:

- server-side TLS backend support;
- native ECHConfig source;
- controlled DNS/config distribution;
- approved-host native runtime smoke;
- runtime config acceptance.

## Operational Boundary

The existing approved-host smoke is the current proof point:

```sh
MAVERICK_ECH_CF_RUNTIME_APPROVED=1 \
MAVERICK_ECH_CF_DOMAIN=REPLACE_WITH_ECH_TEST_HOSTNAME \
MAVERICK_ECH_CF_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
  ./scripts/approved-vm-ech-cloudflare-fronted-runtime-smoke.sh REPLACE_WITH_APPROVED_ORIGIN_SSH_HOST
```

Run approved-host smokes only on hosts where the operator has explicitly
approved temporary listeners and cleanup checks. Do not mutate a workstation's
system proxy, DNS, route, firewall, VPN, or other network-service settings.

## Future Native ECH

Native server-side ECH can be revisited when a reviewed server-side ECH TLS
backend exists. The conservative path is to track rustls upstream. A TLS-stack
replacement would be a separate research spike and must not be merged simply to
clear a blocker.
