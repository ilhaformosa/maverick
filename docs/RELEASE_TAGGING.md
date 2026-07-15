# Release Tagging Strategy

Status: public `main` targets `v1.2.0`. Pre-publication `v1.1.0` is the latest
completed stable engineering boundary. `docs/PLAN_POST_V1.md` owns current
mapping and gates; alpha, beta, and historical RC sections below retain the
completed private release-train rules.

Maverick separates source publication from stable or production claims. See
`docs/PUBLIC_HISTORY_BOUNDARY.md` for the sanitized public starting point.

## Version Layers

Maverick uses three separate version layers:

1. Software release version: Git tags, GitHub Releases, source snapshots,
   release artifacts, and changelog entries use SemVer-style tags. The
   completed first train used `v0.1.0-alpha.1` through `v1.0.0`; future tags
   follow the post-v1 release mapping.
2. Protocol / wire version: handshake and wire-format compatibility are tracked
   by explicit protocol constants such as `PROTOCOL_VERSION`. This version
   changes only when wire encoding, transcript inputs, or peer compatibility
   actually change.
3. Config version: config files use their own schema version, currently
   `version: 1`. Config version changes are tied to migration behavior, not to
   every software release.

Do not describe an alpha software tag as a stable protocol version. For example,
`v0.1.0-alpha.1` is a software release tag, while the current protocol and
config versions remain independently documented in `COMPATIBILITY.md` and
`MIGRATIONS.md`.

## Historical Initial Pre-Publication Source Snapshot

Use:

```text
v0.1.0-alpha.1
```

This tag means:

- experimental as-is source snapshot;
- no stable protocol freeze;
- no formal human security audit;
- no production-ready claim;
- no native server-side ECH claim;
- no anonymity or censorship-resistance guarantee.

This tag is a private historical identifier and is not recreated in the
sanitized public Git history.

## Historical Alpha Tags

Use `v0.1.0-alpha.N` while the protocol and config surface can still change.
Alpha tags may include experimental features if they remain documented as
default-off or explicitly gated.

Before each alpha tag:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/release-artifacts.sh
```

If release notes mention benchmarks, also run:

```sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
```

## GitHub Pre-Releases

Publish alpha and beta GitHub Releases as Pre-releases. Do not mark them as
`latest`, do not use stable-looking titles, and do not imply a protocol freeze.

Each GitHub Pre-release body should include:

- the matching release notes document;
- exact verification commands that passed for the tagged commit;
- the commit hash;
- compatibility and migration notes;
- known limitations and non-claims;
- Native ECH status and the Cloudflare-fronted workaround boundary when ECH is
  mentioned;
- artifact names and checksums when artifacts are attached.

Attach artifacts only from `dist/` output generated for the exact tagged commit,
and include `BUILDINFO` plus `SHA256SUMS`. Do not attach artifacts from a dirty
tree or from a different commit.

## Historical Beta Tags

Use `v0.1.0-beta.N` only for the S1/S2 gates in
`docs/PLAN_SHORT_TERM_TO_V1.md` and `docs/RELEASE_TRAIN.md`.

Before beta tags, confirm:

- public config fields have migration coverage;
- protocol compatibility notes are current;
- frozen-scope default-path blockers are closed or explicitly scoped out;
- release notes list every experimental feature and non-claim;
- the exact S1 or S2 gate has passed for the tag.

Beta still does not imply audited, stable, production-ready, or censorship-
resistant status.

## Historical Release Candidate Tags

Use `v0.1.0-rc.N` only for the S3 review/freeze gate in
`docs/PLAN_SHORT_TERM_TO_V1.md` and `docs/RELEASE_TRAIN.md`.

Release candidates are still GitHub Pre-releases and must not be marked
`latest`. They mean the narrow scope is in soak and review, not that Maverick is
formally audited, production-ready, anonymous, or censorship-resistant.

## Post-v1 Release Candidates

Use `vX.Y.Z-rc.N` for a frozen, backward-compatible post-v1 candidate before a
stable minor release. Publish it as a GitHub Pre-release with `--latest=false`.
It must preserve the documented protocol/config boundary unless its release
notes and migration plan explicitly say otherwise.

`v1.1.0-rc.1` froze the compatible M1-M8 implementation and evidence scope
before stable promotion. It kept Auth v1/v2 and config version 1 unchanged,
kept experimental TUN default-off, made no IPv6 support commitment, and did not
widen production, audit, anonymity, or censorship-resistance claims.

The first release from sanitized public history must use a version never
assigned in the private history. The planned first public candidate is
`v1.2.0-alpha.1`, subject to the applicable release gates.

The exact `v1.2.0-alpha.1`, `v1.2.0-beta.1`, `v1.2.0-rc.1`, and `v1.2.0`
prerequisites are in `docs/RELEASE_GATES_V1_2.md`. A tag is not authorized by a
document change or elapsed time. It requires coordinator approval and a passing
ledger state for that stage.

## Stable Tags

The completed `v1.0.0` tag passed the S4 gate recorded in
`docs/PLAN_SHORT_TERM_TO_V1.md` and `docs/RELEASE_TRAIN.md`. A future stable
patch or minor tag must pass the applicable milestone and release mapping in
`docs/PLAN_POST_V1.md` for its exact commit.

Stable means only that the documented narrow scope is expected to preserve
compatibility and operator behavior. It still does not imply formal audit,
production use, anonymity, or censorship resistance unless those claims are
separately documented and evidenced.

## Tag Mechanics

Recommended command sequence:

```sh
git status --short --branch
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
python3 scripts/check-production-readiness.py
git tag -s vX.Y.Z -m "Maverick vX.Y.Z"
git push origin vX.Y.Z
```

Create GitHub release notes from `CHANGELOG.md` and the relevant release notes
document. Attach artifacts only from `dist/` output generated for the exact
commit being tagged, including `BUILDINFO` and `SHA256SUMS`. Choose prerelease
and latest flags from the version policy; never make an experimental tag look
stable.

New `v1.2.0` train tags use a GitHub-verifiable signature. If signing cannot be
verified, stop before tagging; do not fall back to an unsigned public tag.
