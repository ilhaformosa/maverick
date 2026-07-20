# Post-Release Audit - v0.1.0-alpha.4

Status: post-release hygiene snapshot for the alpha.4 pre-publication private
source release.
This is not a stable-release claim, production-readiness claim,
security-audit result, anonymity claim, censorship-resistance claim, or
protocol-freeze claim.

## Scope

This audit records a follow-up pass after the `v0.1.0-alpha.4` GitHub
Pre-release was published privately. It checks that the private tag, release body,
attached artifact, checksum file, and binary version match the alpha release
boundary.

The audit did not change release assets, release tags, GitHub issues, system
proxy, DNS, route, firewall, VPN, TUN settings, or other host network-service
settings.

## Release State

- release tag: `v0.1.0-alpha.4`
- tag commit: `83f68f7d4b6f2c0b515c9c61dc472a62d741922e`
- release title: `Maverick v0.1.0-alpha.4`
- release state: published GitHub Pre-release
- draft: false
- prerelease: true
- published at: `2026-07-05T18:31:58Z`
- historical release id: `v0.1.0-alpha.4` (private pre-publication record;
  URL not migrated)

The release body includes:

- the experimental as-is alpha status;
- package version `0.1.0-alpha.4`;
- commit `83f68f7d4b6f2c0b515c9c61dc472a62d741922e`;
- unchanged default `protocol_version: 1`;
- unchanged config `version: 1`;
- no mandatory migration from `v0.1.0-alpha.3`;
- browser-like TLS, active-probing, and CDN-fronted WebSocket scope;
- verification commands;
- artifact names and checksum;
- native ECH non-claim and CDN-fronted workaround boundary.

The default latest-release lookup did not return this tag. That matches the
alpha/beta rule that Pre-releases must not be marked latest.

## Release Assets

Published assets:

- `maverick-0.1.0-alpha.4-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-alpha.4-aarch64-apple-darwin.tar.gz.sha256`

Downloaded checksum verification passed:

```text
maverick-0.1.0-alpha.4-aarch64-apple-darwin.tar.gz: OK
```

The published tarball SHA-256 is:

```text
929ad37ec4af836e5aed17b51b6fe1734588e93fbe2ae7d7b23522a966b43f59  maverick-0.1.0-alpha.4-aarch64-apple-darwin.tar.gz
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

The release binary reported:

```text
maverick 0.1.0-alpha.4
```

`BUILDINFO` recorded:

```text
name: maverick-0.1.0-alpha.4-aarch64-apple-darwin
version: 0.1.0-alpha.4
target: aarch64-apple-darwin
features: default
git_revision: 83f68f7d4b6f2c0b515c9c61dc472a62d741922e
```

## Local Gates

Local release gates passed before tagging:

```sh
cargo fmt --all -- --check
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
cargo clippy -p maverick-client --features browser-tls --all-targets -- -D warnings
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
./scripts/release-artifacts.sh
```

Artifact verification passed before upload:

```sh
shasum -a 256 -c SHA256SUMS
```

## Privacy Scan

The expanded artifact, release checksum file, release body, and release binary
were scanned for:

- local repository paths;
- home-directory paths;
- local developer username strings;
- known private approved-host labels;
- known private approved-host addresses;
- cloud-provider operational strings;
- PEM private-key headers;
- bearer-token shaped strings;
- generated Maverick secret strings.

No matching private strings were found in the published artifact set.

## Post-Release Status

No urgent alpha.4 release correction was identified.

Future work should remain separate from this release:

- collect repeatable fingerprint evidence before making any stronger browser
  equivalence claim;
- extend active-probing shape coverage beyond the current H2 baseline;
- continue stable-candidate evidence work for rollout, rollback, abuse and
  denial-of-service behavior, observability, deployment hardening, and
  incident response;
- keep native Maverick server-side ECH as a tracked item only until a reviewed
  server-side TLS backend path exists.
