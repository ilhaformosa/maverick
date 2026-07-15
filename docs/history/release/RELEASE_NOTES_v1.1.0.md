# Maverick v1.1.0 Release Notes

Status: backward-compatible stable engineering release for the narrow
`maverick-tls-h2-cli-v1` scope.

Maverick v1.1.0 promotes the verified v1.1.0-rc.1 implementation without a
runtime, wire-format, authentication-version, or config-schema change. It is
not a production-readiness, formal-audit, anonymity, censorship-resistance,
browser-fingerprint-equivalence, or standardization claim.

## Included

- Runtime-scoped H2 connection reuse with bounded acquisition, reconnect, idle
  retirement, and shutdown behavior.
- Reproducible TLS/H2 fingerprint and active-probe measurement baselines.
- Optional browser-TLS exporter channel binding and pinned browser-reference
  evidence with remaining differences documented.
- Hyper-backed fallback handling and machine-checked response-shape gates.
- Accepted M6 long-haul, impairment, failure-recovery, resource, and cleanup
  evidence for the tested direct TLS/H2 path.
- Accepted architecture decision retaining direct H2 as the v1.x default.
- Default-off experimental TUN packet runtime with accepted IPv4 Phase 2
  namespace-local real-TUN evidence.
- Budget-aware CI path scoping with explicit full-run support.

## Compatibility

- software/package version: `1.1.0`;
- default Auth v1 protocol version: `1`, unchanged;
- explicit Auth v2 protocol version: `2`, unchanged;
- config version: `1`, unchanged;
- default transport: TLS 1.3 plus HTTP/2, unchanged;
- no mandatory migration from `v1.0.0`.

H3, browser-TLS, CDN-fronted WebSocket, experimental cryptography, and TUN stay
behind their existing gates or default-off. TUN does not create interfaces or
change host networking by itself.

## Address-Family Scope

Product and release support is IPv4-only. IPv6 is not scheduled in the
short-term, medium-term, or current long-term plan. Existing experimental code
is not a support promise. Future IPv6 work requires a new explicit decision.

## Evidence Boundary

- M6 evidence covers only its recorded direct TLS/H2 source revision.
- M8 Phase 2 evidence covers only its recorded approved-host IPv4 matrix.
- The stable promotion changes package version, release documents, and the
  matching documentation-hygiene rule only, so those accepted runtime evidence
  layers are not rerun or overstated.
- IPv6 was not exercised and is not counted as a pass.

## Known Limitations

- No formal independent security audit has been completed.
- This is not a production deployment recommendation.
- Native Maverick server-side ECH is not implemented.
- Browser-TLS mode does not exactly match every browser fingerprint detail.
- H3, CDN-fronted WebSocket, and TUN remain experimental and default-off.
- The TUN evidence runner is not a shipped platform helper or reference client.
- No GUI/App, cross-platform, anonymity, traffic-analysis-resistance,
  censorship-resistance, IPv6, or standardization claim is made.

## Verification

The exact tagged commit must pass:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/conformance.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/browser-tls-harness.sh
./scripts/release-artifacts.sh
./scripts/benchmark-baseline.sh 65536
```

The stable GitHub release must contain exact-commit artifacts with `BUILDINFO`,
`SHA256SUMS`, a detached checksum signature, and the public allowed-signers
file. Downloaded assets must be independently reverified after publication.
