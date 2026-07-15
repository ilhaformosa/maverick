# Post-Release Audit - v0.1.0-rc.1

Status: post-release hygiene snapshot for the first release candidate in the
`maverick-tls-h2-cli-v1` release train.

Maverick remains experimental. This audit verifies the private pre-publication tag, GitHub
Pre-release state, release artifacts, checksum files, binary version, S3
review/freeze boundary, and release-note non-claims. It is not a
production-readiness or formal security-audit claim.

## Release State

- release tag: `v0.1.0-rc.1`
- release title: `Maverick v0.1.0-rc.1`
- historical release id: `v0.1.0-rc.1` (private pre-publication record;
  URL not migrated)
- GitHub state: published Pre-release, not draft
- latest state: GitHub's latest-release endpoint returned no stable latest
  release; the release list shows this tag as a Pre-release
- tagged commit: `e044d42c9d0a2aaae2b8b1637e95f96fbdf91f78`
- package version: `0.1.0-rc.1`
- target: `aarch64-apple-darwin`
- features: default

## Attached Assets

- `maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz.sha256`

Published tarball checksum:

```text
24f2a492968472f6c8a1da4a3c64cfda93f432bcc436131ecb5a32032a14349d  maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz
```

GitHub asset digests reported:

```text
sha256:24f2a492968472f6c8a1da4a3c64cfda93f432bcc436131ecb5a32032a14349d  maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz
sha256:2ea5dd51394198aec0551575e37c6067d0eaba137650dde60aa0d2742e8b6b5e  maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz.sha256
```

The downloaded `.sha256` file verified the downloaded tarball:

```text
maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz: OK
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
maverick 0.1.0-rc.1
```

The downloaded `BUILDINFO` recorded:

```text
name: maverick-0.1.0-rc.1-aarch64-apple-darwin
version: 0.1.0-rc.1
target: aarch64-apple-darwin
features: default
git_revision: e044d42c9d0a2aaae2b8b1637e95f96fbdf91f78
built_at_utc: 2026-07-08T10:09:11Z
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Gates Run Before Tagging

The RC.1 gate passed before tagging:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
python3 scripts/check-security-review-package.py
./scripts/release-artifacts.sh
```

Additional artifact checks passed for the tagged commit:

```sh
shasum -a 256 -c maverick-0.1.0-rc.1-aarch64-apple-darwin.tar.gz.sha256
shasum -a 256 -c SHA256SUMS
maverick --version
```

The local artifact directory, tarball contents, release body, and binary were
scanned for developer-private paths, local usernames, private infrastructure
aliases, bearer/API-key patterns, generated Maverick secrets, and private-key
blocks before upload. The downloaded artifact contents were scanned again after
publication. No matches were found. Public loopback examples such as
`127.0.0.1` are expected and are not private environment details.

## S3 Evidence Boundary

S2 runtime evidence remains:
`docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`

S3 review/freeze records:

- `docs/history/review/S3_REVIEW_HANDOFF_2026_07_08.md`
- `docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`
- `docs/history/review/COMPREHENSIVE_SECURITY_AUDIT_REMEDIATION_2026_07_08.md`
- `conformance/freeze-readiness.json`
- `conformance/implementation-registry.json`
- `docs/CONFORMANCE_SUITE.md`
- `security-review-package.json`

Reviewed S3 state:

- Anonymous review input was triaged against the frozen
  `maverick-tls-h2-cli-v1` scope.
- High, medium, and low findings imported into the comprehensive remediation
  record are either fixed or explicitly recorded as residual-risk
  defense-in-depth items for the narrow RC scope.
- Candidate conformance/freeze metadata is ready and gate-enforced by
  `./scripts/conformance.sh`.
- `SECURITY.md` preserves the disclosure path and explicitly says prior review
  input is not stable or production security sign-off.

## S3 Reviewer Audit

Reviewer audit result: pass for the S3 gate.

- Review scope: the closure record covers auth transcript, replay, fallback
  behavior, resource bounds, TLS channel binding, dependency policy, unsafe
  code, and key-lifecycle residual risk.
- Frozen vectors: `./scripts/conformance.sh` passed and reported freeze
  readiness as ready with zero blocking criteria.
- Claim hygiene: release notes and public status text do not claim formal
  audit, production readiness, anonymity, censorship resistance, native
  server-side ECH, exact browser fingerprint equivalence, standardization, or a
  stable non-prerelease release.
- CI budget: the pushed RC code/version change should run the full CI gate;
  follow-up documentation-only audit work should use the lighter docs-hygiene
  workflow path filter.

## Post-Publish CI Follow-Up

After RC.1 was published, GitHub full CI for the RC.1 commit failed in the
`shape-lab-smoke` job. The failure was a source-level CI harness issue, not an
artifact checksum or binary-version mismatch: the default shape lab included a
private-mode scenario that correctly rejects `rustls_default`, while the
browser-mimic private-mode path requires the non-default `browser-tls` feature.

The fix landed after the RC.1 tag, so RC.1 is not the active soak baseline.
`v0.1.0-rc.2` supersedes it for the fixed RC soak window.

## RC Soak Window

Original RC.1 soak window:

- start: `2026-07-08T10:11:26Z`
- end: `2026-07-09T10:11:26Z`
- Asia/Shanghai and Singapore time: `2026-07-08 18:11:26` to
  `2026-07-09 18:11:26`

This window was replaced by the RC.2 soak window because RC.1's post-publish
full CI did not stay green. During the active RC.2 window, only bugfix-level
changes should land on the RC path. S4 `v1.0.0` consideration starts only
after that window ends, CI is green, no release-blocking issue is open, and
any bugfixes are recorded with their verification.

## Scope And Non-Claims

This RC supports only the recorded `maverick-tls-h2-cli-v1` release-candidate
scope. It does not prove:

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

`v0.1.0-rc.1` is correctly published as a GitHub Pre-release for the S3
review/freeze gate, but it is superseded as the active soak candidate by
`v0.1.0-rc.2` because the RC.1 post-publish full CI run did not stay green.
