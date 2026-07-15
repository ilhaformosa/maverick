# Post-Release Audit - v1.0.0

Status: post-release hygiene snapshot for the narrow stable engineering release
of `maverick-tls-h2-cli-v1`.

Maverick v1.0.0 is a narrow stable engineering release. This audit verifies the
private pre-publication tag, GitHub release state, release artifacts, signed checksums, binary
version, S2/S3 evidence boundary, release-note non-claims, and GitHub CI
result. It is not a production-readiness or formal security-audit claim.

## Release State

- release tag: `v1.0.0`
- release title: `Maverick v1.0.0`
- historical release id: `v1.0.0` (private pre-publication record; URL not
  migrated)
- GitHub state: published release, not draft, not Pre-release
- published: `2026-07-09T11:05:56Z`
- tagged commit: `98c5d7c85991618d322d6cd4240fae5c7dec1598`
- package version: `1.0.0`
- target: `aarch64-apple-darwin`
- features: default

## Attached Assets

- `maverick-1.0.0-aarch64-apple-darwin.tar.gz`
- `maverick-1.0.0-aarch64-apple-darwin.tar.gz.sha256`
- `maverick-1.0.0-aarch64-apple-darwin-SHA256SUMS`
- `maverick-1.0.0-aarch64-apple-darwin-SHA256SUMS.sig`
- `maverick-1.0.0-allowed_signers`

Published tarball checksum:

```text
30b15f7b34f951fa1ae6347de966492889a3675eae24f3ad75d89d66c1f7d896  maverick-1.0.0-aarch64-apple-darwin.tar.gz
```

GitHub asset digests reported:

```text
sha256:30b15f7b34f951fa1ae6347de966492889a3675eae24f3ad75d89d66c1f7d896  maverick-1.0.0-aarch64-apple-darwin.tar.gz
sha256:80ad79a068dc2fb9dab7767be8b5a9100b045d829185b43f5a4169b8e86bc615  maverick-1.0.0-aarch64-apple-darwin.tar.gz.sha256
sha256:48417f549c721be4025e09595cb581f1276748df0966457f53ef4132fbbfc479  maverick-1.0.0-aarch64-apple-darwin-SHA256SUMS
sha256:a8d815e731edd9d4b99fb40e372c74ff4e304865e573e367acb5aeab0e81198a  maverick-1.0.0-aarch64-apple-darwin-SHA256SUMS.sig
sha256:8a69787232cf2a03d1b305a64b9539f5f27b49d5c708b68da1087d7863085c32  maverick-1.0.0-allowed_signers
```

The downloaded `.sha256` file verified the downloaded tarball:

```text
maverick-1.0.0-aarch64-apple-darwin.tar.gz: OK
```

The downloaded OpenSSH signature verified the downloaded `SHA256SUMS` file:

```text
Good "maverick-release" signature for maverick-release with ED25519 key SHA256:XUecjxlGXpdqieNDN1haGSmeRFwEutb8lDi5+zLR6pQ
```

Internal `SHA256SUMS` verification passed after download and extraction:

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
maverick 1.0.0
```

The downloaded `BUILDINFO` recorded:

```text
name: maverick-1.0.0-aarch64-apple-darwin
version: 1.0.0
target: aarch64-apple-darwin
features: default
git_revision: 98c5d7c85991618d322d6cd4240fae5c7dec1598
built_at_utc: 2026-07-09T11:04:00Z
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Gates Run Before Tagging

The S4 stable gate passed for the tagged commit:

```sh
cargo fmt --all -- --check
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/conformance.sh
./scripts/release-artifacts.sh
```

The final artifact command used the project release-signing key path and
verified the generated signature with `docs/release-signing/allowed_signers`.
The release-signing private key and passphrase were not committed.

Additional published-asset checks passed after download:

```sh
shasum -a 256 -c maverick-1.0.0-aarch64-apple-darwin.tar.gz.sha256
ssh-keygen -Y verify -f maverick-1.0.0-allowed_signers -I maverick-release -n maverick-release -s maverick-1.0.0-aarch64-apple-darwin-SHA256SUMS.sig <maverick-1.0.0-aarch64-apple-darwin-SHA256SUMS
shasum -a 256 -c SHA256SUMS
maverick --version
```

The local artifact directory, tarball contents, release body, and binary were
scanned for developer-private paths, local usernames, private infrastructure
aliases, bearer/API-key patterns, generated Maverick secrets, and private-key
blocks before upload. The downloaded artifact contents were verified again
after publication. No matches were found.

## GitHub CI

GitHub full CI passed for the v1.0.0 commit.

- historical Actions run: `29013281869` (private pre-publication record)
- run result: success
- head SHA: `98c5d7c85991618d322d6cd4240fae5c7dec1598`

Successful jobs:

- `fuzz-smoke`
- `ech-harness`
- `h3-harness`
- `conformance`
- `local-harness`
- `shape-lab-smoke`

GitHub docs hygiene also passed:

- historical Actions run: `29013281849` (private pre-publication record)
- run result: success

GitHub reported Node.js 20 deprecation annotations for `actions/checkout@v4`.
Those annotations are not release blockers, but they should be watched as part
of routine workflow maintenance.

## Evidence Boundary

S2 runtime evidence:

- `docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`

S3 review/freeze records:

- `docs/history/review/S3_REVIEW_HANDOFF_2026_07_08.md`
- `docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`
- `docs/history/review/COMPREHENSIVE_SECURITY_AUDIT_REMEDIATION_2026_07_08.md`
- `conformance/freeze-readiness.json`
- `conformance/implementation-registry.json`
- `conformance/frozen-releases.json`
- `docs/CONFORMANCE_SUITE.md`
- `security-review-package.json`

Reviewed S4 state:

- The fixed RC.2 soak window ended before S4 tagging.
- No public `release-blocker` issue was open before the stable release.
- Current two-host, impairment, and failure-injection evidence stays scoped to
  the recorded `maverick-tls-h2-cli-v1` claims.
- Anonymous review input was triaged and closed for the frozen scope.
- Frozen conformance metadata is gate-enforced by `./scripts/conformance.sh`.
- Public docs preserve the no-formal-audit and no-production-readiness
  boundaries.

## Scope And Non-Claims

This release supports only the recorded `maverick-tls-h2-cli-v1` narrow stable
engineering scope. It does not prove:

- production readiness;
- formal independent security audit completion;
- anonymity or traffic-analysis resistance;
- censorship resistance;
- native Maverick server-side ECH;
- GUI/App runtime readiness;
- H3/QUIC stability outside the optional harness;
- exact browser fingerprint equivalence;
- standardization or second-implementation maturity.

## Result

`v1.0.0` is correctly published as a real GitHub release, not a Pre-release.
The release has signed checksums, downloadable public signer material, verified
artifacts, green CI, and scoped claim language for the narrow stable engineering
release. Future work should move to post-v1 roadmap items without widening
what this release claims to prove.
