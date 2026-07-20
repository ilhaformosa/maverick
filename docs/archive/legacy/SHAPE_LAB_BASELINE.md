# Maverick Shape Lab Baseline

Status: loopback-only engineering diagnostics, not an anonymity claim.

- Commit: `1a32c37`
- Generated UTC: `2026-07-08T10:17:34Z`
- Scope: direct TCP echo vs Maverick SOCKS relay on localhost across shaping scenarios.
- Network safety: loopback listeners and OS-assigned ephemeral ports only.
- Private mode is excluded from the default shape lab because it rejects
  `rustls_default`, while `browser_mimic` requires the non-default
  `browser-tls` feature.

## Summary

| scenario | payload_bytes | mode | client_shaping | server_shaping | direct_tcp_roundtrip_ms | maverick_socks_roundtrip_ms | overhead_ratio |
| --- | ---: | --- | --- | --- | ---: | ---: | ---: |
| auto-unshaped | 256 | auto | false | false | 1.280 | 31.114 | 24.312 |
| stable-shaped-gated | 256 | stable | true | true | 1.505 | 29.621 | 19.688 |
| auto-shaped | 256 | auto | true | true | 1.206 | 75.676 | 62.770 |
| auto-unshaped | 1024 | auto | false | false | 1.256 | 29.919 | 23.817 |
| stable-shaped-gated | 1024 | stable | true | true | 1.272 | 29.474 | 23.177 |
| auto-shaped | 1024 | auto | true | true | 1.314 | 75.204 | 57.220 |
| auto-unshaped | 16384 | auto | false | false | 1.279 | 30.693 | 23.999 |
| stable-shaped-gated | 16384 | stable | true | true | 1.240 | 31.113 | 25.100 |
| auto-shaped | 16384 | auto | true | true | 1.251 | 73.829 | 59.004 |
| auto-unshaped | 65536 | auto | false | false | 1.365 | 30.112 | 22.065 |
| stable-shaped-gated | 65536 | stable | true | true | 1.157 | 30.683 | 26.529 |
| auto-shaped | 65536 | auto | true | true | 1.339 | 142.660 | 106.512 |

## Raw Trace

```text
==> scenario=auto-unshaped payload_bytes=256
payload_bytes: 256
concurrency: 1
mode: auto
client_shaping: false
server_shaping: false
direct_tcp_roundtrip_ms: 1.280
maverick_socks_roundtrip_ms: 31.114
overhead_ratio: 24.312
maverick_socks_avg_per_flow_ms: 31.114

==> scenario=stable-shaped-gated payload_bytes=256
payload_bytes: 256
concurrency: 1
mode: stable
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.505
maverick_socks_roundtrip_ms: 29.621
overhead_ratio: 19.688
maverick_socks_avg_per_flow_ms: 29.621

==> scenario=auto-shaped payload_bytes=256
payload_bytes: 256
concurrency: 1
mode: auto
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.206
maverick_socks_roundtrip_ms: 75.676
overhead_ratio: 62.770
maverick_socks_avg_per_flow_ms: 75.676

==> scenario=auto-unshaped payload_bytes=1024
payload_bytes: 1024
concurrency: 1
mode: auto
client_shaping: false
server_shaping: false
direct_tcp_roundtrip_ms: 1.256
maverick_socks_roundtrip_ms: 29.919
overhead_ratio: 23.817
maverick_socks_avg_per_flow_ms: 29.919

==> scenario=stable-shaped-gated payload_bytes=1024
payload_bytes: 1024
concurrency: 1
mode: stable
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.272
maverick_socks_roundtrip_ms: 29.474
overhead_ratio: 23.177
maverick_socks_avg_per_flow_ms: 29.474

==> scenario=auto-shaped payload_bytes=1024
payload_bytes: 1024
concurrency: 1
mode: auto
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.314
maverick_socks_roundtrip_ms: 75.204
overhead_ratio: 57.220
maverick_socks_avg_per_flow_ms: 75.204

==> scenario=auto-unshaped payload_bytes=16384
payload_bytes: 16384
concurrency: 1
mode: auto
client_shaping: false
server_shaping: false
direct_tcp_roundtrip_ms: 1.279
maverick_socks_roundtrip_ms: 30.693
overhead_ratio: 23.999
maverick_socks_avg_per_flow_ms: 30.693

==> scenario=stable-shaped-gated payload_bytes=16384
payload_bytes: 16384
concurrency: 1
mode: stable
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.240
maverick_socks_roundtrip_ms: 31.113
overhead_ratio: 25.100
maverick_socks_avg_per_flow_ms: 31.113

==> scenario=auto-shaped payload_bytes=16384
payload_bytes: 16384
concurrency: 1
mode: auto
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.251
maverick_socks_roundtrip_ms: 73.829
overhead_ratio: 59.004
maverick_socks_avg_per_flow_ms: 73.829

==> scenario=auto-unshaped payload_bytes=65536
payload_bytes: 65536
concurrency: 1
mode: auto
client_shaping: false
server_shaping: false
direct_tcp_roundtrip_ms: 1.365
maverick_socks_roundtrip_ms: 30.112
overhead_ratio: 22.065
maverick_socks_avg_per_flow_ms: 30.112

==> scenario=stable-shaped-gated payload_bytes=65536
payload_bytes: 65536
concurrency: 1
mode: stable
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.157
maverick_socks_roundtrip_ms: 30.683
overhead_ratio: 26.529
maverick_socks_avg_per_flow_ms: 30.683

==> scenario=auto-shaped payload_bytes=65536
payload_bytes: 65536
concurrency: 1
mode: auto
client_shaping: true
server_shaping: true
direct_tcp_roundtrip_ms: 1.339
maverick_socks_roundtrip_ms: 142.660
overhead_ratio: 106.512
maverick_socks_avg_per_flow_ms: 142.660

```

## Interpretation Rules

- Compare reports by payload size and commit, not by a single run.
- Compare unshaped and shaped scenarios as coarse runtime diagnostics only.
- Treat private-mode shape as a separate browser-tls evidence task, not a
  default CI smoke scenario.
- Treat large CI or laptop variance as a signal to rerun before drawing conclusions.
- This lab does not capture packets and does not prove traffic-analysis resistance.
