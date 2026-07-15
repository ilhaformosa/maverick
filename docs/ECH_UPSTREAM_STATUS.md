# ECH Upstream Status

Status: current as of 2026-06-29. This is an implementation-readiness note,
not a protocol commitment.

Maverick keeps ECH behind build and runtime gates. `experimental_ech: true`
continues to be rejected because a safe Maverick deployment needs both client
and server support, controlled ECH config distribution, fallback policy, and VM
integration tests. Operator diagnostics are local-only and report unsupported
status without encouraging plain-SNI fallback.
`docs/history/manifests/ech-runtime-approval.json` separates completed local/Cloudflare-fronted
evidence from the native server-side ECH gates. It records that the local
client API smoke and Cloudflare-fronted WebSocket smoke are not native Maverick
server-side ECH support and that no native ECH network activity is approved by
the default harness. `docs/history/manifests/ech-runtime-blockers.json` records the blocker-first
execution plan for local client API tracking, fallback-policy tests,
approved-host readiness, Cloudflare DNS preparation, Cloudflare-fronted
runtime smoke, and server TLS backend blockers.
`docs/ECH_NATIVE_TLS_LIMITATION.md` gives the non-technical explanation of the
native server-side ECH blocker.
`docs/NATIVE_ECH_TRACKING.md` is the core tracking index for future native ECH
work.

## Current Findings

- `rustls` 0.23.41 exposes client-side ECH types such as
  `rustls::client::EchConfig` and `rustls::client::EchMode`.
- Maverick's `ech` feature harness now includes a compile-time API smoke for
  `rustls::client::EchConfig`, `rustls::client::EchMode`,
  `rustls::client::EchStatus`, `rustls::pki_types::EchConfigListBytes`, and
  the client builder `with_ech` API.
- The rustls client API expects ECH config list bytes from DNS HTTPS records,
  with the `ech` parameter base64-decoded into `EchConfigListBytes`.
- rustls server-side ECH support is tracked upstream in issue 1980. A public
  GitHub API check on 2026-06-28 reported the issue state as `open`, title
  `Server-side Encrypted Client Hello (ECH) support`, and latest update
  `2026-03-17T01:33:47Z`. A public HTML check on 2026-06-29 still showed the
  issue as `Open`. It is not a stable Maverick server integration point yet.
- Quinn/H3 ECH behavior should not be wired until rustls server-side support
  and a controlled DNS/test-host story are available.
- Cloudflare edge ECH has been used for a controlled DNS/client preflight on a
  dedicated subdomain. That validates Cloudflare edge behavior rather than
  native Maverick server-side ECH.
- A Cloudflare-fronted origin reachability probe now passes after the approved
  origin allowed TCP/443 and Cloudflare Full SSL/TLS mode was configured.
- A Cloudflare-fronted runtime smoke now passes with WebSocket as the
  Cloudflare-compatible carrier. GET and finite POST preflights reach the
  Maverick origin through Cloudflare, and one SOCKS5 TCP echo flow succeeds
  through the private Cloudflare-fronted test hostname.
- The earlier bidirectional streaming H2/gRPC tunnel attempt remains useful
  negative evidence: it received Cloudflare `400 Bad Request` even after
  Cloudflare gRPC was enabled, Maverick used gRPC headers, Maverick wrapped H2
  body frames in gRPC message envelopes, and the smoke used a gRPC-shaped path.

## Local Readiness Gate

`maverick-core::ech::EchReadinessSnapshot` records the current native ECH
implementation boundary mechanically. It also records that the
Cloudflare-fronted WebSocket smoke is ready, but that field does not make
native Maverick server-side ECH runtime-ready. Native runtime ECH remains
blocked until all native readiness inputs are true:

- build feature enabled;
- client TLS backend API tracked;
- server TLS backend ready;
- ECH config source ready;
- controlled integration ready;
- runtime config accepted.

The current snapshot is intentionally not native-runtime-ready. Its blockers
include missing server TLS backend support, missing ECH config distribution,
and rejected runtime config.

`scripts/check-ech-runtime-approval.py` also keeps the approval boundary
explicit: completed local gates, the approved host, controlled Cloudflare DNS
evidence, and the Cloudflare-fronted WebSocket smoke may be marked complete,
but server TLS backend and native ECHConfig distribution remain blocked and
runtime config acceptance remains deferred before native runtime handshakes.

`scripts/check-ech-runtime-blockers.py` tracks the execution plan separately:
client API tracking and fallback-policy tests can be marked complete locally,
`approved-linux-vm` is recorded as the approved integration host, and the
Cloudflare DNS, edge-only preflight, origin reachability, and fronted WebSocket
runtime slices can be marked complete while native runtime ECH remains
disabled.
It also records the Cloudflare origin reachability slice and the
Cloudflare-fronted WebSocket runtime smoke as complete on the approved host.

## Sources

- rustls `EchConfig` docs: https://docs.rs/rustls/latest/rustls/client/struct.EchConfig.html
- rustls ECH client example: https://github.com/rustls/rustls/blob/main/examples/src/bin/ech-client.rs
- rustls server-side ECH tracking issue: https://github.com/rustls/rustls/issues/1980
- Cloudflare ECH docs: https://developers.cloudflare.com/ssl/edge-certificates/ech/
- Cloudflare gRPC docs: https://developers.cloudflare.com/network/grpc-connections/
- RFC 9849, TLS Encrypted ClientHello: https://www.rfc-editor.org/rfc/rfc9849
- RFC 9848, Bootstrapping TLS ECH with DNS Service Bindings:
  https://www.rfc-editor.org/rfc/rfc9848

## Local Harness Policy

`scripts/ech-harness.sh` runs `cargo test --workspace --features ech`. It checks
that the feature-gated code path remains buildable, that the rustls client ECH
API surface is still present, and that config/readiness gates continue to reject
runtime enablement. It must not perform DNS lookups, open WAN connections, or
mutate system proxy, DNS, route, firewall, VPN, or other network-service settings.
