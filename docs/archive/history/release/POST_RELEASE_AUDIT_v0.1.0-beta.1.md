# Post-Release Audit - v0.1.0-beta.1

Status: post-release hygiene snapshot for the first beta release in the
`maverick-tls-h2-cli-v1` release train.

Maverick remains experimental. This audit verifies the private pre-publication tag, GitHub
Pre-release state, release artifacts, checksum files, binary version, and
release-note non-claims. It is not a production-readiness or security-audit
claim.

## Release State

- release tag: `v0.1.0-beta.1`
- release title: `Maverick v0.1.0-beta.1`
- historical release id: `v0.1.0-beta.1` (private pre-publication record;
  URL not migrated)
- GitHub state: published Pre-release, not draft
- tagged commit: `c2820247ca3fd8af44f0e72c9c488ef631338b5d`
- package version: `0.1.0-beta.1`
- target: `aarch64-apple-darwin`
- features: default

## Attached Assets

- `maverick-0.1.0-beta.1-aarch64-apple-darwin.tar.gz`
- `maverick-0.1.0-beta.1-aarch64-apple-darwin.tar.gz.sha256`

Published tarball checksum:

```text
f2d7cc9091ddc2eec7fb58618282da1bbfb0395b308ec1233de959a73767494a  maverick-0.1.0-beta.1-aarch64-apple-darwin.tar.gz
```

The downloaded `.sha256` file verified the downloaded tarball:

```text
maverick-0.1.0-beta.1-aarch64-apple-darwin.tar.gz: OK
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
maverick 0.1.0-beta.1
```

The downloaded `BUILDINFO` recorded:

```text
name: maverick-0.1.0-beta.1-aarch64-apple-darwin
version: 0.1.0-beta.1
target: aarch64-apple-darwin
features: default
git_revision: c2820247ca3fd8af44f0e72c9c488ef631338b5d
rustc: rustc 1.96.0 (ac68faa20 2026-05-25)
```

## Gates Run Before Tagging

The S1 gate passed before tagging:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

Additional artifact checks passed for the tagged commit:

```sh
shasum -a 256 -c SHA256SUMS
maverick --version
```

The local artifact directory and binary were scanned for developer-private
paths, local usernames, private infrastructure aliases, bearer/API-key patterns,
generated Maverick secrets, and private-key blocks before upload. No matches
were found.

## Scope And Non-Claims

The release body keeps beta.1 bounded:

- beta means scope frozen and runtime hardening started;
- not production-ready;
- not audited;
- no stable protocol freeze;
- no anonymity claim;
- no censorship-resistance claim;
- no native server-side ECH;
- S2 still requires independent approved-client-host evidence before RC work.

## S1 Reviewer Audit

Reviewer audit result: pass for the S1 gate.

- Probe/error shape: loopback tests cover bad-auth fallback shape,
  rate-limited fallback shape, global connection-cap rejection, per-source
  connection-cap rejection, fallback overload, and active-flow metrics. The new
  fallback-overload path returns generic HTTP `503 Service unavailable` text
  without Maverick/auth/tunnel protocol detail.
- Secret and PII hygiene: log-hygiene tests reject logging of secrets, raw
  payload/body data, auth tags, credential identifiers, nonces, and replay keys.
  New server pressure logs avoid printing full peer addresses.
- Metrics hygiene: loopback metrics expose counters and gauges for auth,
  fallback load, active flows, active connections, pre-auth work, and overload
  pressure, without secrets or payload bytes.
- Compatibility: package version advanced to `0.1.0-beta.1`; protocol version
  and config version remain unchanged at `1`. New overload config fields have
  defaults, so existing configs keep parsing.

No S1 blocker remains open.

## Result

No urgent beta.1 release correction was identified.
