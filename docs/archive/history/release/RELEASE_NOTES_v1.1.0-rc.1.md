# Maverick v1.1.0-rc.1 Release Notes

Status: backward-compatible post-v1 release candidate for the narrow
`maverick-tls-h2-cli-v1` engineering scope.

Maverick v1.1.0-rc.1 combines the completed M1-M8 post-v1 work into one frozen
candidate before v1.1.0. It remains a GitHub Pre-release and is not a
production-readiness, formal-audit, anonymity, censorship-resistance,
browser-fingerprint-equivalence, or standardization claim.

## Included

- Runtime-scoped H2 connection reuse for SOCKS5, HTTP CONNECT, DNS, and UDP,
  with bounded acquisition, reconnect, idle retirement, and shutdown behavior.
- Reproducible TLS/H2 fingerprint and active-probe measurement baselines.
- Optional BoringSSL browser-TLS path with exporter channel binding and pinned
  Chrome-reference evidence; known fingerprint differences remain explicit.
- Hyper-backed fallback response handling, bounded bodies, preserved request
  bytes, generic upstream failures, and machine-checked response-shape gates.
- Accepted layered two-host M6 evidence for the tested direct TLS/H2 path,
  including long-haul, impairment, failure recovery, resources, and cleanup.
- Accepted architecture decision retaining direct H2 as the v1.x default and
  keeping handshake-layer changes in the v2 research track.
- Default-off experimental TUN packet runtime with pinned `smoltcp 0.13.1`,
  bounded resources, shared Maverick flow paths, lifecycle tests, and accepted
  approved-host IPv4 namespace-local real-TUN evidence.
- CI path scoping that preserves the core gate while avoiding unrelated H3,
  ECH, browser-TLS, and shaping jobs on ordinary changes.

## Compatibility

- software/package version: `1.1.0-rc.1`;
- default Auth v1 protocol version: `1`, unchanged;
- explicit Auth v2 protocol version: `2`, unchanged;
- config version: `1`, unchanged;
- default transport: TLS 1.3 plus HTTP/2, unchanged;
- no mandatory migration from `v1.0.0`;
- existing valid v1.0.0 client and server configs continue to validate.

H3, browser-TLS, CDN-fronted WebSocket, experimental cryptography, and TUN stay
behind their existing build/runtime/operator gates. TUN remains default-off and
does not create interfaces or change host networking by itself.

## Address-Family Scope

Current product and release support is IPv4-only. IPv6 is not scheduled in the
short-term, medium-term, or current long-term plan. Existing experimental IPv6
code and synthetic tests remain in the source tree, but they are not a support
promise or release claim. Future IPv6 work requires a new explicit decision.

## Evidence Boundary

- M6 evidence covers the tested direct TLS/H2 source revision recorded in
  `docs/history/evidence/APPROVED_HOST_POST_V1_M6_EVIDENCE_2026_07_11.md`.
- M8 Phase 2 evidence covers only the accepted approved-host IPv4 matrix
  recorded in `docs/TUN_PHASE2_EXECUTION_GATE.md`.
- Later TUN code is not retroactively covered by M6 binaries.
- IPv6 cases were not exercised and are not counted as passes.

## Known Limitations

- No formal independent security audit has been completed.
- This is not a production deployment recommendation.
- Native Maverick server-side ECH is not implemented.
- Browser-TLS mode does not exactly match every browser fingerprint detail.
- H3 and CDN-fronted WebSocket remain experimental and default-off.
- The TUN runner is evidence tooling, not a shipped platform network helper or
  daily-use reference client.
- No IPv6, GUI/App, cross-platform, anonymity, traffic-analysis-resistance,
  censorship-resistance, or standardization claim is made.

## Public Feedback

The existing public community-review request remains open as an ongoing
`help wanted` invitation. It had no public comments or unresolved reported
finding at the RC freeze. It is not represented as a formal audit or as proof
that additional review is unnecessary.

## Verification

The exact tagged commit must pass:

```sh
cargo fmt --all -- --check
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/conformance.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/browser-tls-harness.sh
./scripts/release-artifacts.sh
./scripts/benchmark-baseline.sh 65536
```

The published release must be a GitHub Pre-release, must not be marked latest,
and must attach exact-commit artifacts with `BUILDINFO`, `SHA256SUMS`, a detached
checksum signature, and the public allowed-signers file.
