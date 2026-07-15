# Post-Release Audit - v0.1.0-beta.2

Status: post-release hygiene snapshot for the second beta release in the
`maverick-tls-h2-cli-v1` release train.

Maverick remains experimental. This audit verifies the private pre-publication tag, GitHub
Pre-release state, release artifacts, checksum files, binary version,
S2 evidence boundary, and release-note non-claims. It is not a
production-readiness or security-audit claim.

## Release State

- release tag: `v0.1.0-beta.2`
- release title: `Maverick v0.1.0-beta.2`
- historical release id: `v0.1.0-beta.2` (private pre-publication record;
  URL not migrated)
- GitHub state: published Pre-release, not draft
- latest state: GitHub's latest-release endpoint returned no stable latest
  release; the release list shows this tag as a Pre-release
- tagged commit: `8c39985dd77e8f00c5c695093f919daac0b6c27a`
- package version: `0.1.0-beta.2`
- target: `aarch64-apple-darwin`
- features: default

## Attached Assets

- `maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz.sha256`

Published tarball checksum:

```text
6519cf215c93d18fb8db7939cae2bf4638b11781a6f9012b4b005b8a6f33f31c  maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz
```

GitHub asset digests reported:

```text
sha256:6519cf215c93d18fb8db7939cae2bf4638b11781a6f9012b4b005b8a6f33f31c  maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz
sha256:3927610d5af2969fe6c067882f59809af8647111bb3e4faab0a0fcfd6048c710  maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz.sha256
```

The downloaded `.sha256` file verified the downloaded tarball:

```text
maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz: OK
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
maverick 0.1.0-beta.2
```

The downloaded `BUILDINFO` recorded:

```text
name: maverick-0.1.0-beta.2-aarch64-apple-darwin
version: 0.1.0-beta.2
target: aarch64-apple-darwin
features: default
git_revision: 8c39985dd77e8f00c5c695093f919daac0b6c27a
built_at_utc: 2026-07-07T18:44:29Z
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Gates Run Before Tagging

The beta.2 gate passed before tagging:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

Additional artifact checks passed for the tagged commit:

```sh
shasum -a 256 -c maverick-0.1.0-beta.2-aarch64-apple-darwin.tar.gz.sha256
shasum -a 256 -c SHA256SUMS
maverick --version
```

The local artifact directory, tarball contents, release body, and binary were
scanned for developer-private paths, local usernames, private infrastructure
aliases, bearer/API-key patterns, generated Maverick secrets, and private-key
blocks before upload. The downloaded artifact contents were scanned again after
publication. No matches were found.

## S2 Evidence Boundary

Public evidence report:
`docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`

Reviewed evidence:

- 24-hour two-host TCP/H2 long-haul: 288/288 iterations passed, zero unexpected
  failures.
- 8-hour bounded netem impairment: 96/96 iterations passed across the recorded
  latency, jitter, loss, combined, rough, and recovery-baseline scenarios.
- Failure injection v2: 15 recorded checks covering restart/reconnect,
  upstream echo failure, upstream stall/timeout, and reverse-proxy
  fallback-origin failure/recovery.

The detailed raw logs remain outside the public repository because they include
host-specific runtime context. The committed S2 report is the redacted public
summary.

## S2 Reviewer Audit

Reviewer audit result: pass for the S2 gate.

- Approved-host boundary: the long-haul and impairment runs used approved
  remote hosts and not the developer workstation as the client evidence host.
- Local network safety: the developer workstation's system proxy, DNS, route
  table, firewall, VPN, and network-service settings were not changed.
- Impairment safety: remote impairment was confined to the approved client VM
  test namespace/veth setup, and the evidence recorded cleanup with no remote
  residue.
- Evidence scope: the release notes claim only the recorded TLS 1.3 plus HTTP/2
  CLI-managed path, the approved remote topology, and the listed
  latency/loss/failure profiles.
- Claim hygiene: release notes and public reports do not claim production
  readiness, formal audit, stable protocol freeze, anonymity, censorship
  resistance, native server-side ECH, GUI runtime readiness, or behavior beyond
  the recorded profiles.

## Scope And Non-Claims

The release body keeps beta.2 bounded:

- beta means the S2 independent-evidence gate has current approved-host
  evidence;
- not production-ready;
- not audited;
- no stable protocol freeze;
- no anonymity claim;
- no censorship-resistance claim;
- no native server-side ECH;
- no GUI/App runtime claim in this repository;
- S3 still requires independent or community security review and protocol
  freeze work before an RC can be tagged.
