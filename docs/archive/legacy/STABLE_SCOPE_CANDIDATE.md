# Stable Scope Candidate

Status: candidate definition. Not a stable release claim.

This document defines the narrow scope Maverick may stabilize first.

## Candidate Name

`maverick-tls-h2-cli-v1`

## Included

- Rust reference client and server.
- CLI-managed configuration and lifecycle.
- TLS 1.3 plus HTTP/2 transport.
- Auth v1 and Auth v2 ClientHello / ServerHello behavior.
- Replay cache behavior.
- Static or reverse-proxy fallback for non-tunnel and unauthenticated
  tunnel-like requests.
- TCP relay.
- DNS relay.
- UDP relay as documented in `docs/UDP_RELAY.md`.
- Per-user flow limits and optional byte pacing.
- Global/per-source connection caps, pre-auth admission limits, fallback
  concurrency caps, and failed-auth rate limiting.
- Loopback-only metrics endpoint.
- Config version `1` with migration dry-run coverage.
- Auth v1 hello protocol version `1` and explicit Auth v2 hello protocol
  version `2`.

## Excluded

- Native server-side ECH.
- Cloudflare-fronted WebSocket runtime as a stable transport.
- H3/QUIC as a stable transport.
- TUN system apply behavior.
- GUI/App runtime behavior.
- Post-quantum or Noise experimental handshakes.
- Strong anonymity, traffic-analysis resistance, or censorship-proof claims.
- Production binary distribution for every platform.

## Compatibility Rule

For this candidate scope, compatible changes may:

- add new optional config fields with safe defaults;
- add new frame types only when old peers can reject or ignore them safely;
- add metrics counters;
- tighten validation for values that were already invalid in practice;
- improve fallback behavior without revealing protocol detail.

Breaking changes include:

- changing frame byte encoding;
- changing Auth v1/v2 transcript inputs;
- changing default tunnel path semantics;
- changing fallback response behavior for unauthenticated tunnel-like requests;
- rejecting previously valid config without a migration note;
- changing stable-scope CLI command behavior without a release note.

## Candidate Gate

Before tagging a stable-scope candidate:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

The release also needs approved-host long-haul evidence:

```sh
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=<approved-client-host> \
MAVERICK_LONGHAUL_DURATION_SECS=86400 \
./scripts/approved-vm-detached-tcp-longhaul.sh <approved-server-host>
```

A one-hour detached approved-host run passed on 2026-07-01; see
`docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_01.md`. A 24-hour detached
approved-host baseline passed on 2026-07-03; see
`docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_03.md`. These results support
pre-stable and narrow stable-candidate readiness for the TCP/H2 runtime path,
but they do not cover production rollout or stronger privacy/anonymity claims.

The candidate also has process-level failure-injection evidence for server
restart, client restart, upstream target failure, and upstream stall or timeout;
see `docs/history/evidence/APPROVED_HOST_FAILURE_INJECTION_EVIDENCE_2026_07_03.md`. Packet loss,
latency impairment, and host-level network impairment remain production-scope
inputs unless a future stable candidate explicitly claims them.

If no second approved client host is available, the candidate must remain
pre-stable.
