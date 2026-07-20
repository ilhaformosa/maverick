# Post-Release Audit - v0.1.0-rc.2

Status: post-release hygiene snapshot for the active release candidate in the
`maverick-tls-h2-cli-v1` release train.

Maverick remains experimental. This audit verifies the private pre-publication tag, GitHub
Pre-release state, release artifacts, checksum files, binary version, S3
review/freeze boundary, release-note non-claims, and GitHub CI result. It is
not a production-readiness or formal security-audit claim.

## Release State

- release tag: `v0.1.0-rc.2`
- release title: `Maverick v0.1.0-rc.2`
- historical release id: `v0.1.0-rc.2` (private pre-publication record;
  URL not migrated)
- GitHub state: published Pre-release, not draft
- latest state: GitHub's latest-release endpoint returned no stable latest
  release; this tag is a Pre-release
- tagged commit: `be299e13ff39ec5a9d20f19d903b4633f9eb3703`
- package version: `0.1.0-rc.2`
- target: `aarch64-apple-darwin`
- features: default

## Why RC.2 Supersedes RC.1

`v0.1.0-rc.1` was published and its attached artifacts verified, but the
post-publish GitHub full CI run for the RC.1 commit failed in the
`shape-lab-smoke` job. The failure was a source-level CI harness issue: the
default shape lab included a private-mode scenario that intentionally rejects
`rustls_default`, while private browser-mimic evidence requires a non-default
`browser-tls` build.

`v0.1.0-rc.2` contains the follow-up source fix, keeps private-mode shape
evidence outside the default CI smoke path, and is now the active fixed RC soak
baseline.

## Attached Assets

- `maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz.sha256`

Published tarball checksum:

```text
568a9dfc84e018e4b9e3e125242d0d45a80e51f8c6380b7d3aec796fc700afcf  maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz
```

GitHub asset digests reported:

```text
sha256:568a9dfc84e018e4b9e3e125242d0d45a80e51f8c6380b7d3aec796fc700afcf  maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz
sha256:1c12143dc9a74ce44783c2a733752f8fecc85d75fc875f3841d627e892caa4d7  maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz.sha256
```

The downloaded `.sha256` file verified the downloaded tarball:

```text
maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz: OK
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
maverick 0.1.0-rc.2
```

The downloaded `BUILDINFO` recorded:

```text
name: maverick-0.1.0-rc.2-aarch64-apple-darwin
version: 0.1.0-rc.2
target: aarch64-apple-darwin
features: default
git_revision: be299e13ff39ec5a9d20f19d903b4633f9eb3703
built_at_utc: 2026-07-08T10:28:24Z
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Gates Run Before Tagging

The RC.2 gate passed before tagging:

```sh
./scripts/docs-hygiene.sh
./scripts/conformance.sh
python3 scripts/check-security-review-package.py
./scripts/shape-lab.sh /tmp/maverick-rc2-shape-lab.md 256 1024
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/release-artifacts.sh
```

Additional artifact checks passed for the tagged commit:

```sh
shasum -a 256 -c maverick-0.1.0-rc.2-aarch64-apple-darwin.tar.gz.sha256
shasum -a 256 -c SHA256SUMS
maverick --version
```

The local artifact directory, tarball contents, release body, and binary were
scanned for developer-private paths, local usernames, private infrastructure
aliases, bearer/API-key patterns, generated Maverick secrets, and private-key
blocks before upload. The downloaded artifact contents were scanned again after
publication. No matches were found.

## GitHub CI

GitHub full CI passed for the RC.2 commit.

- historical Actions run: `28935807295` (private pre-publication record)
- run result: success
- head SHA: `be299e13ff39ec5a9d20f19d903b4633f9eb3703`
- completed: `2026-07-08T10:34:23Z`

Successful jobs:

- `fuzz-smoke`
- `ech-harness`
- `h3-harness`
- `conformance`
- `local-harness`
- `shape-lab-smoke`

GitHub reported Node.js 20 deprecation annotations for `actions/checkout@v4`.
Those annotations are not release blockers, but they should be watched as part
of routine workflow maintenance.

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

## RC Soak Window

Fixed RC.2 soak window:

- start: `2026-07-08T10:29:23Z`
- end: `2026-07-09T10:29:23Z`
- Asia/Shanghai and Singapore time: `2026-07-08 18:29:23` to
  `2026-07-09 18:29:23`

During this window, only bugfix-level changes should land on the RC path. S4
`v1.0.0` consideration starts only after the window ends, CI is green, no
release-blocking issue is open, and any bugfixes are recorded with their
verification.

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

`v0.1.0-rc.2` is correctly published as a GitHub Pre-release and supersedes
`v0.1.0-rc.1` as the active S3 fixed-RC soak baseline. The next release-train
step is to complete the fixed RC.2 soak window with only bugfix-level changes
before considering the S4 `v1.0.0` stable gate.
