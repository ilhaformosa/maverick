# Maverick v0.1.0-alpha.1 Release Notes

Status: initial pre-publication private source snapshot.

This is an experimental as-is prototype release. It is not audited, not
production-ready, not a stable protocol freeze, not a standardization proposal,
not an anonymity claim, and not a censorship-resistance guarantee.

## Highlights

- Rust workspace split into core, client, server, CLI, SDK, and integration
  harness crates.
- TLS 1.3 + HTTP/2 default tunnel transport.
- HMAC-authenticated ClientHello / ServerHello tunnel sessions.
- Replay protection, static fallback, reverse-proxy fallback, TCP relay, DNS
  relay, and SOCKS5 UDP ASSOCIATE relay.
- Optional feature-gated H3/QUIC carrier with H2 fallback.
- Experimental Cloudflare-fronted WebSocket carrier for Cloudflare edge ECH
  experiments. This is not native Maverick server-side ECH.
- Config generation, validation, migration dry-run, credential rotation dry-run,
  redacted key inventory, and secret-free profile URI/QR export.
- Loopback-only local harness, H3 harness, conformance vectors, fuzz smoke, and
  benchmark scripts.
- One-hour approved-host TCP/H2 runtime smoke evidence for the narrow
  stable-scope path, with private infrastructure details redacted from public
  docs.

## Known Limitations

- No native server-side ECH.
- No formal third-party human security audit.
- No stable protocol freeze or compatibility guarantee.
- No production packaging or service manager release artifact.
- No multi-day production long-haul deployment evidence. The one-hour
  approved-host smoke is useful alpha evidence, not a production-readiness
  claim.
- No GUI or mobile client in this repository.
- Experimental crypto, TUN, and advanced traffic shaping paths are default-off
  or gated.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
```

Record the final commit hash in the GitHub release body.

## Upgrade Notes

This is the first pre-publication source snapshot. Future alpha releases may change
config fields, protocol details, and experimental gates. Use the migration
tools and `MIGRATIONS.md` for later updates.
