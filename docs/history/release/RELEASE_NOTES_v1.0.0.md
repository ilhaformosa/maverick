# Maverick v1.0.0 Release Notes

Status: narrow stable engineering release for the
`maverick-tls-h2-cli-v1` scope.

Maverick v1.0.0 stabilizes only the CLI-managed Rust client/server path using
TLS 1.3 + HTTP/2, authenticated tunnel frames, TCP/DNS/UDP relay, fallback
behavior, replay protection, resource bounds, loopback metrics, and the current
config/protocol boundary.

This release is not production-ready, formally audited, anonymous,
censorship-resistant, standardized, browser-fingerprint equivalent, or a GUI/App
runtime release.

## Stable Scope

Included:

- Rust reference client and server managed by the `maverick` CLI.
- TLS 1.3 + HTTP/2 default transport.
- Auth v1 default path and explicit opt-in Auth v2.
- TCP relay, DNS relay, and SOCKS5 UDP ASSOCIATE relay over authenticated
  tunnel frames.
- Static and reverse-proxy fallback behavior for non-tunnel or failed pre-auth
  requests.
- Replay protection, connection/resource bounds, failed-auth pacing, fallback
  overload bounds, and loopback-only metrics.
- Frozen conformance-vector metadata for the narrow release scope.

Excluded:

- Native Maverick server-side ECH.
- H3/QUIC as a stable transport.
- Cloudflare-fronted WebSocket as a stable transport.
- TUN system apply behavior.
- GUI/App runtime behavior.
- Browser-grade TLS fingerprint equivalence.
- Strong anonymity, traffic-analysis resistance, or censorship-resistance
  claims.
- Formal independent security-audit sign-off.
- Production deployment recommendation.

## Version Boundaries

- software release tag: `v1.0.0`;
- package version: `1.0.0`;
- default Auth v1 `protocol_version: 1`, unchanged;
- explicit Auth v2 `protocol_version: 2`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-beta.2`, `v0.1.0-rc.1`, or
  `v0.1.0-rc.2`.

## Evidence Boundary

Runtime evidence:

- `docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`

Review and freeze evidence:

- `docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`
- `docs/history/review/COMPREHENSIVE_SECURITY_AUDIT_REMEDIATION_2026_07_08.md`
- `conformance/freeze-readiness.json`
- `conformance/implementation-registry.json`
- `conformance/frozen-releases.json`

Together, these records support only the recorded
`maverick-tls-h2-cli-v1` scope. They do not prove production readiness,
anonymity, censorship resistance, native server-side ECH, GUI/App behavior,
H3/QUIC stability, exact browser fingerprint equivalence, or behavior outside
the recorded profiles.

## Verification

Before tagging, run:

```sh
cargo fmt --all -- --check
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/conformance.sh
./scripts/release-artifacts.sh
```

The release artifact must include `BUILDINFO`, `SHA256SUMS`, and published
checksum verification instructions. For signed checksums, publish
`SHA256SUMS.sig` and verify it with
`docs/release-signing/allowed_signers`.
