# Post-Release Audit - v1.1.0-rc.1

Status: published backward-compatible Pre-release with its evidence-based
candidate gate accepted. The original fixed 24-hour wait was superseded by the
private-stage evidence policy recorded below.

This audit verifies the private pre-publication tag, GitHub release state, exact-commit CI,
release artifacts, detached signature, binary version, benchmark record,
privacy checks, compatibility boundary, and current IPv4-only product scope.
It is not a production-readiness or formal security-audit claim.

## Release State

- release tag: `v1.1.0-rc.1`
- release title: `Maverick v1.1.0-rc.1`
- historical release id: `v1.1.0-rc.1` (private pre-publication record; URL
  not migrated)
- GitHub state: published, not draft, Pre-release
- Latest stable release remains: `v1.0.0`
- published: `2026-07-12T12:25:55Z`
- tagged commit: `ead22708a0215fff6be8ca5f6c5dc5d82149613c`
- package version: `1.1.0-rc.1`
- target: `aarch64-apple-darwin`
- features: default

## Attached Assets

- `maverick-1.1.0-rc.1-aarch64-apple-darwin.tar.gz`
- `maverick-1.1.0-rc.1-aarch64-apple-darwin.tar.gz.sha256`
- `maverick-1.1.0-rc.1-aarch64-apple-darwin-SHA256SUMS`
- `maverick-1.1.0-rc.1-aarch64-apple-darwin-SHA256SUMS.sig`
- `maverick-1.1.0-rc.1-allowed_signers`
- `maverick-1.1.0-rc.1-benchmark.txt`
- `maverick-1.1.0-rc.1-benchmark.txt.sha256`

GitHub-reported asset digests:

```text
sha256:a51afbab959112e8aaaad61862ea625600883e2cf8fcf20cda62ee6621047e31  maverick-1.1.0-rc.1-aarch64-apple-darwin.tar.gz
sha256:64da49559e8982613cc686f8cda6c4cf80d232b2943c0037762b6f98b5a89869  maverick-1.1.0-rc.1-aarch64-apple-darwin.tar.gz.sha256
sha256:f4072ecee98f249c12e88ece654cac2bb5919e86d5b9a7583c2c1cab20dd8fd7  maverick-1.1.0-rc.1-aarch64-apple-darwin-SHA256SUMS
sha256:7379c21fc8bb74c4faa4f3a09b08139b19132763226b7d3f7ee7254d625c6529  maverick-1.1.0-rc.1-aarch64-apple-darwin-SHA256SUMS.sig
sha256:8a69787232cf2a03d1b305a64b9539f5f27b49d5c708b68da1087d7863085c32  maverick-1.1.0-rc.1-allowed_signers
sha256:020aa71a7a5fa5e5915f7df75b2be5bc3da567f077e938b05242d52228f77a1f  maverick-1.1.0-rc.1-benchmark.txt
sha256:3238fc88e1255f0a04113e624b771fa677c6bf83fec0b5ea11d2e7a9849f8c67  maverick-1.1.0-rc.1-benchmark.txt.sha256
```

The downloaded archive and benchmark checksum files verified. The downloaded
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
maverick 1.1.0-rc.1
```

The downloaded `BUILDINFO` recorded the expected version, default feature set,
tagged commit, Apple Silicon target, and release toolchain. No local path or
private infrastructure value was present.

## Gates Run Before Tagging

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

The local harness, advisory/license/source policy, first-party unsafe inventory,
conformance, default-off carrier gates, browser-TLS gate, signed artifact build,
benchmark, and artifact privacy scans passed.

The loopback-only benchmark recorded 64 KiB payloads at concurrency 1 and 4.
It is an engineering diagnostic, not a production throughput claim.

## GitHub CI

Automatic full CI passed for the tagged commit:

- historical Actions run: `29191975326` (private pre-publication record)
- result: success

The explicit manual full CI gate also passed for the same commit:

- historical Actions run: `29192299208` (private pre-publication record)
- result: success

Both full runs covered local harness, H3, ECH, browser-TLS, and shaping jobs.
Docs hygiene also passed for the release commit.

## Compatibility And Scope

- Auth v1 protocol version remains `1`.
- Explicit Auth v2 protocol version remains `2`.
- Config version remains `1`.
- No mandatory migration from `v1.0.0` exists.
- TLS 1.3 plus HTTP/2 remains the mandatory default path.
- TUN, H3, browser-TLS, CDN-fronted WebSocket, and experimental cryptography
  remain behind their documented gates or default-off.
- Product and release support is IPv4-only. IPv6 is not scheduled in the
  short-term, medium-term, or current long-term plan; future support requires a
  new explicit decision.

The public community-review issue remains open as an ongoing `help wanted`
invitation. It had no public finding at freeze and is not represented as a
formal audit.

## Gate Follow-Up

This audit originally recorded a fixed 24-hour observation window ending at
`2026-07-13T12:25:55Z`. On 2026-07-12, that rule was superseded for the private
development stage because no software, deployment, scheduled job, or external
user observation was active during the wait. Elapsed time alone could not add
evidence.

Before stable promotion, the evidence-based gate requires:

- recheck release and asset availability;
- recheck open public issues for a release blocker or security finding;
- confirm the tag and downloaded assets still verify;
- confirm no runtime source changed after the RC tag;
- if runtime source changed or a blocker appears, publish another RC and rerun
  the tests affected by that change;
- if only package version, release documents, and matching
  documentation-hygiene rules change, prepare `v1.1.0` without rerunning
  unaffected remote M6/M8 evidence.

## Result

`v1.1.0-rc.1` is correctly published as a signed GitHub Pre-release and does
not replace `v1.0.0` as latest stable. All release assets and exact-commit gates
verified. Its evidence-based candidate gate is accepted; stable `v1.1.0`
requires only its own exact-commit build, CI, signature, publication, and
post-release verification gates.
