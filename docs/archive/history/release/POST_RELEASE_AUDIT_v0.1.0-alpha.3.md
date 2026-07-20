# Post-Release Audit - v0.1.0-alpha.3

Status: post-release hygiene snapshot for the alpha.3 pre-publication private
source release.
This is not a stable-release claim, production-readiness claim, security-audit
sign-off, anonymity claim, censorship-resistance claim, or protocol-freeze
claim.

## Scope

This audit records a follow-up pass after the `v0.1.0-alpha.3` GitHub
Pre-release was published privately. It checks that the private tag, release body, attached
artifact, checksum file, and public feedback queue match the alpha release
policy.

The audit did not change release assets, release tags, GitHub issues, system
proxy settings, DNS, routes, firewall state, VPN settings, or other
network-service settings.

## Tag And Release

- release tag: `v0.1.0-alpha.3`
- tag type: annotated Git tag
- tag object: `dec9c4ec2d1c2e05964da3fb494b07842e56d4be`
- tagged commit: `45d88614b0d4a1a341f3782e26314941eeba8ac1`
- release title: `Maverick v0.1.0-alpha.3`
- release state: published GitHub Pre-release
- draft: false
- latest: false
- published UTC: `2026-07-04T16:09:57Z`
- historical release id: `v0.1.0-alpha.3` (private pre-publication record;
  URL not migrated)

The release body includes:

- experimental alpha status and non-production wording;
- commit hash;
- package version `0.1.0-alpha.3`;
- unchanged default `protocol_version: 1`;
- unchanged config `version: 1`;
- no mandatory migration from `v0.1.0-alpha.2`;
- Native Maverick server-side ECH non-implementation status;
- Cloudflare-fronted WebSocket workaround boundary;
- verification commands;
- artifact name and checksum.

## Artifact

Attached assets observed:

- `maverick-0.1.0-alpha.3-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-alpha.3-aarch64-apple-darwin.tar.gz.sha256`

Outer checksum verification passed:

```text
maverick-0.1.0-alpha.3-aarch64-apple-darwin.tar.gz: OK
```

Tarball checksum:

```text
517c2197219aed11f25ae22266e52126bfc9b487ca5b3e58bc11346ff1df5a19  maverick-0.1.0-alpha.3-aarch64-apple-darwin.tar.gz
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
maverick 0.1.0-alpha.3
```

`BUILDINFO` recorded:

```text
name: maverick-0.1.0-alpha.3-aarch64-apple-darwin
version: 0.1.0-alpha.3
target: aarch64-apple-darwin
features: default
git_revision: 45d88614b0d4a1a341f3782e26314941eeba8ac1
built_at_utc: 2026-07-04T16:04:02Z
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Verification

Local release gates passed before tagging:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
./scripts/release-artifacts.sh
```

GitHub CI passed for the tagged commit:

```text
run: 28711797073
status: completed
conclusion: success
```

GitHub reported the release as a Pre-release and not a Draft. The default latest
release lookup did not return this tag, and the release list showed the tag as a
Pre-release.

## Privacy Scan

The expanded artifact, release checksum file, release body, and release binary
string output were scanned for:

- local home or repository paths;
- local developer usernames;
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
this snapshot. Later public feedback should still be handled through
`docs/PUBLIC_FEEDBACK_PROCESS.md`.

## Follow-Up Decision

No urgent alpha.3 release correction was identified.

The next useful work should stay small unless a real public report changes the
priority:

- triage any new public feedback without inventing feedback that does not
  exist;
- keep protocol and config version changes out of the default path unless a
  later release explicitly updates compatibility and migration docs;
- continue stable-candidate evidence work for rollout, rollback, abuse and
  denial-of-service handling, observability, deployment hardening, and incident
  response;
- continue Native server-side ECH tracking upstream without making it part of
  the default release path.
