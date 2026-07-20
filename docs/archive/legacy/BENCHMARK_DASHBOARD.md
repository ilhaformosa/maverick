# Maverick Benchmark Dashboard

Status: loopback-only engineering dashboard.

- Commit: `556969d`
- Generated UTC: `2026-07-01T07:15:35Z`
- Scope: direct TCP echo vs Maverick SOCKS relay on localhost.

## Latest Run

```text
Maverick loopback benchmark baseline
commit: 556969d
date_utc: 2026-07-01T07:15:35Z
cargo_profile: release
concurrency_set: 1 4

==> payload_bytes=65536 concurrency=1
payload_bytes: 65536
concurrency: 1
mode: auto
client_shaping: false
server_shaping: false
direct_tcp_roundtrip_ms: 0.138
maverick_socks_roundtrip_ms: 26.919
overhead_ratio: 195.003
maverick_socks_avg_per_flow_ms: 26.919

==> payload_bytes=65536 concurrency=4
payload_bytes: 65536
concurrency: 4
mode: auto
client_shaping: false
server_shaping: false
direct_tcp_roundtrip_ms: 0.198
maverick_socks_roundtrip_ms: 27.248
overhead_ratio: 137.559
maverick_socks_avg_per_flow_ms: 6.812

```

## Notes

- Results are local diagnostics, not production throughput claims.
- Keep historical generated files or release attachments for trend review.
