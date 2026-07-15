# Maverick Interop Matrix

Status: v2.5 local interoperability baseline plus v6 implementation-registry
metadata.

All entries are local harness results unless noted otherwise.
Machine-readable implementation metadata lives in
`conformance/implementation-registry.json`.

| Client | Server | Transport | Feature Flags | Coverage | Status |
| --- | --- | --- | --- | --- | --- |
| Maverick Rust | Maverick Rust | H2/TLS | default | TCP, DNS, SOCKS5 UDP, HTTP CONNECT, fallback, replay | Passing |
| Maverick Rust | Maverick Rust | H3/QUIC | `h3`, `advanced.experimental_h3` | TCP, DNS, SOCKS5 UDP, auth fallback, replay | Passing |
| Maverick Rust | Maverick Rust | H3 fail to H2 | client `experimental_h3`, server H2-only | runtime fallback/cooldown | Passing |
| Maverick Rust approved remote client VM | Maverick Rust approved remote server VM | H2/TLS public TCP | explicit `scripts/public-tcp-smoke.sh` | one SOCKS5 TCP echo flow over an approved public port, temporary remote processes | Passing on 2026-06-27 |
| Approved remote client VM | Approved remote server VM | UDP reachability | explicit `scripts/public-udp-probe.sh` | one UDP datagram and reply over an approved public port; network check only | Passing on 2026-06-27 |
| Maverick Rust approved remote client VM | Maverick Rust approved remote server VM | H3/QUIC public UDP | explicit `scripts/public-h3-smoke.sh`, `h3`, `advanced.experimental_h3` | one SOCKS5 TCP echo flow over approved public QUIC port plus authenticated H3 server-log check | Passing on 2026-06-27 |
| Approved remote client VM | Cloudflare edge | ECH edge preflight | explicit `scripts/approved-vm-ech-edge-preflight.sh` | HTTPS/SVCB `ech` parameter present and rustls TLS 1.3 client handshake reports `EchStatus::Accepted` for a dedicated Cloudflare ECH test hostname redacted from public docs | Passing on 2026-06-27 |
| Approved origin VM plus approved probe VM | Cloudflare front door and approved origin | Origin reachability for Cloudflare-fronted runtime | explicit `scripts/approved-vm-ech-cloudflare-origin-probe.sh` | Direct TCP/80 and TCP/443 origin work; Cloudflare reaches temporary HTTPS origin | Passing on 2026-06-28 |
| Approved remote client VM | Cloudflare-fronted Maverick origin | Cloudflare-fronted WebSocket runtime smoke | explicit `scripts/approved-vm-ech-cloudflare-fronted-runtime-smoke.sh` | GET and finite POST preflights pass; one SOCKS5 TCP echo flow succeeds through Cloudflare WebSocket carrier | Passing on 2026-06-28 |
| Python verifier | Conformance vectors | N/A | standard library only | frames, Auth v1/v2, replay sequence, DNS, `OpenTcp`, `OpenUdp`, `UdpPacket`, error codes | Passing |

## Current Limits

- The Python verifier is a read-only conformance oracle, not a separate
  protocol runtime.
- H3 is experimental and off by default.
- Default tests bind only loopback addresses and ephemeral ports.
- Public TCP smoke is explicit, temporary, and operator-approved; it is not part
  of the default or extended harness.
- Public UDP probe is a reachability check only; it is not H3 or Maverick
  runtime interop.
- Public H3 smoke is explicit, temporary, and operator-approved; it requires a
  remote client host so the local workstation only orchestrates over SSH.
- ECH edge preflight validates controlled Cloudflare edge ECH behavior only. It
  is not Maverick server-side ECH interop and does not enable runtime ECH.
- Cloudflare-fronted origin probing validates whether an edge-fronted experiment
  can reach the origin. The runtime smoke additionally checks Maverick's
  full-duplex WebSocket tunnel shape through Cloudflare. Earlier H2/gRPC
  tunnel attempts remain blocked by Cloudflare `400 Bad Request` after the
  available gRPC adaptations and are not the active Cloudflare-fronted carrier.
- Local-origin public tests reflect the local workstation's effective egress
  path and may include proxy exits. Prefer remote-client mode for WAN evidence.
- TUN, GUI, config URI, and SDK interop have v4 design docs but no runtime
  implementation yet.
