# Post-Release Audit - v0.1.0-alpha.2

Status: post-release hygiene snapshot for the alpha.2 pre-publication private
source release.
This is not a stable-release claim, production-readiness claim, security-audit
sign-off, anonymity claim, censorship-resistance claim, or protocol-freeze
claim.

## Scope

This audit records a read-only follow-up pass after the `v0.1.0-alpha.2`
GitHub Pre-release was published privately. It checks that the private tag, release body,
and attached artifact still match the alpha release policy.

The audit did not change source files, release assets, tags, GitHub issues,
system proxy settings, DNS, routes, firewall state, VPN settings, or other
network-service settings.

## Tag And Release

- release tag: `v0.1.0-alpha.2`
- tag type: annotated Git tag
- tag object: `5e0674fd36d62e5fbd0e0ce6caa28c2dcb501aea`
- tagged commit: `1ede9226134019f9b7dab5e41c812f6f7d931d76`
- release title: `Maverick v0.1.0-alpha.2`
- release state: published GitHub Pre-release
- draft: false
- published UTC: `2026-07-04T15:12:16Z`

The release body includes:

- experimental alpha status and non-production wording;
- commit hash;
- package version `0.1.0-alpha.2`;
- unchanged default `protocol_version: 1`;
- unchanged config `version: 1`;
- no mandatory migration from `v0.1.0-alpha.1`;
- Native Maverick server-side ECH non-implementation status;
- Cloudflare-fronted WebSocket workaround boundary;
- verification commands;
- artifact name and checksum.

## Artifact

Attached assets observed:

- `maverick-0.1.0-alpha.2-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-alpha.2-aarch64-apple-darwin.tar.gz.sha256`

Outer checksum verification passed:

```text
maverick-0.1.0-alpha.2-aarch64-apple-darwin.tar.gz: OK
```

The tarball contained only:

- `BUILDINFO`
- `CHANGELOG.md`
- `LICENSE`
- `README.md`
- `SECURITY.md`
- `SHA256SUMS`
- `maverick`

Internal checksum verification passed:

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
maverick 0.1.0-alpha.2
```

`BUILDINFO` recorded:

```text
name: maverick-0.1.0-alpha.2-aarch64-apple-darwin
version: 0.1.0-alpha.2
target: aarch64-apple-darwin
features: default
git_revision: 1ede9226134019f9b7dab5e41c812f6f7d931d76
built_at_utc: 2026-07-04T15:09:40Z
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Privacy Scan

The expanded artifact and release binary string output were scanned for:

- local home or repository paths;
- known approved-host labels from prior private runs;
- known approved-host addresses from prior private runs;
- PEM private-key headers;
- bearer-token shaped strings.

No matches were found in this follow-up pass.

## Public Feedback Snapshot

Open GitHub issues checked after publication:

```text
[]
```

Open GitHub pull requests checked after publication:

```text
[]
```

This means there was no public issue or pull request to triage at the time of
this snapshot. Future alpha.3 work should not claim public feedback was handled
unless matching issues, pull requests, or private reports are recorded.

## Follow-Up Decision

No urgent alpha.2 release correction was identified. The next alpha can stay
small and focus on:

- documenting alpha.2 post-release hygiene;
- keeping public feedback triage ready;
- keeping protocol and config versions unchanged unless a later change
  explicitly updates compatibility and migration docs;
- tightening stable-candidate evidence tracking without expanding release
  claims.
