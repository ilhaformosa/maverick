# Post-Release Audit - v1.1.0

Status: pre-publication private stable engineering release with exact-commit
CI, signed artifacts, independent download verification, and privacy checks
accepted.

This audit verifies the private pre-publication tag, GitHub release state, exact-commit CI,
release artifacts, detached signature, binary version, benchmark record,
privacy checks, compatibility boundary, and IPv4-only product scope. It is not
a production-readiness or formal security-audit claim.

## Release State

- release tag: `v1.1.0`
- release title: `Maverick v1.1.0`
- historical release id: `v1.1.0` (private pre-publication record; URL not
  migrated)
- GitHub state: published, not draft, not Pre-release, Latest
- published: `2026-07-12T13:39:20Z`
- tagged commit: `e5875977c8947be109147735d82b2edadf742ff2`
- package version: `1.1.0`
- target: `aarch64-apple-darwin`
- features: default

## Attached Assets

- `maverick-1.1.0-aarch64-apple-darwin.tar.gz`
- `maverick-1.1.0-aarch64-apple-darwin.tar.gz.sha256`
- `maverick-1.1.0-aarch64-apple-darwin-SHA256SUMS`
- `maverick-1.1.0-aarch64-apple-darwin-SHA256SUMS.sig`
- `maverick-1.1.0-allowed_signers`
- `maverick-1.1.0-benchmark.txt`
- `maverick-1.1.0-benchmark.txt.sha256`

GitHub-reported asset digests:

```text
sha256:a3060bfae5052e63bcf595d90eb15784dfc53bb77a9d6ea451e0406df679c296  maverick-1.1.0-aarch64-apple-darwin-SHA256SUMS
sha256:519f38bc196d781e8b679e75ae0cf520540bee0cfea53b10949d2dd53bb760ec  maverick-1.1.0-aarch64-apple-darwin-SHA256SUMS.sig
sha256:83a1e8174af8f77335658cd7927f73ebdf8629150495c3d9f7e8ac463029881c  maverick-1.1.0-aarch64-apple-darwin.tar.gz
sha256:9bcccba955e418acf97c5d52e5be5e1c886575c0d1d7a3e949d1adb61752f5ef  maverick-1.1.0-aarch64-apple-darwin.tar.gz.sha256
sha256:8a69787232cf2a03d1b305a64b9539f5f27b49d5c708b68da1087d7863085c32  maverick-1.1.0-allowed_signers
sha256:aba152d4fac8844992a630d3150db1e831e21883372ff2ee3a44e1e933debaee  maverick-1.1.0-benchmark.txt
sha256:77c0390da76528eb2cf91e7a3ed8b2abe97bcf485c5d40f0b56a138c0a8e2337  maverick-1.1.0-benchmark.txt.sha256
```

## Independent Verification

All seven assets were downloaded into a new temporary directory after
publication. The archive and benchmark checksum files verified. The downloaded
OpenSSH signature verified the downloaded `SHA256SUMS` with the published
`maverick-release` signer. The extracted internal manifest verified:

```text
BUILDINFO: OK
CHANGELOG.md: OK
LICENSE: OK
README.md: OK
SECURITY.md: OK
maverick: OK
```

The downloaded binary reported:

```text
maverick 1.1.0
```

The downloaded `BUILDINFO` recorded version `1.1.0`, the default feature set,
the Apple Silicon target, and exact tagged commit
`e5875977c8947be109147735d82b2edadf742ff2`.

The extracted text and binary were scanned for local home/repository paths,
private identity strings, credentials, private-key markers, private host
labels, and infrastructure identifiers. No private value was found. Embedded
addresses were limited to documented loopback, wildcard, public DNS, and
standards-reserved example values.

## Gates

The exact release tree passed locally:

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

Automatic exact-commit CI passed:

- historical Actions run: `29194461997` (private pre-publication record)
- result: success
- covered: local harness, H3, ECH, browser-TLS, and shaping

Docs hygiene also passed for the release commit:

- historical Actions run: `29194462000` (private pre-publication record)
- result: success

No duplicate manual full CI run was dispatched because the automatic run
already executed every relevant release job for the exact commit.

## Compatibility And Evidence Boundary

- Auth v1 protocol version remains `1`.
- Explicit Auth v2 protocol version remains `2`.
- Config version remains `1`.
- No mandatory migration from `v1.0.0` exists.
- TLS 1.3 plus HTTP/2 remains the mandatory default path.
- TUN, H3, browser-TLS, CDN-fronted WebSocket, and experimental cryptography
  remain behind their documented gates or default-off.
- Product and release support remains IPv4-only; IPv6 is unscheduled.
- The stable promotion changed package metadata, release documents, and their
  matching documentation-hygiene rule, not proxy runtime behavior.
- Accepted M6 and M8 runtime evidence remains limited to its recorded source,
  binary, host matrix, and non-claims; it is not overstated as new coverage.

The community-review issue remained open with no public comments or unresolved
reported finding at publication. That is not represented as a formal audit.

## Result

`v1.1.0` is correctly published as the signed Latest stable engineering
release. All exact-commit gates and downloaded assets verified. The next active
release-development milestone is `v1.2.x`, focused on one IPv4 reference client
and sustained product lifecycle evidence without changing the v1 protocol.
