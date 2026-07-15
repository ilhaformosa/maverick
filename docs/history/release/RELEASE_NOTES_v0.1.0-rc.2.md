# Maverick v0.1.0-rc.2 Release Notes

Status: release-candidate source snapshot for the frozen
`maverick-tls-h2-cli-v1` release train.

Maverick remains an experimental as-is prototype. RC.2 replaces RC.1 as the
active soak candidate because RC.1's post-publish GitHub full CI run found a
shape-lab smoke harness failure. RC.2 keeps the same narrow S2/S3 evidence
boundary, fixes that source-level CI issue, and does not expand the stable
scope.

RC.2 does not mean production-ready, formally audited, anonymous,
censorship-resistant, standardized, or browser-fingerprint equivalent.

## Why RC.2 Exists

The RC.1 release artifacts and checksums verified after publication, but the
GitHub full CI run for the RC.1 commit failed in the `shape-lab-smoke` job. The
failure came from the default shape lab trying to run a private-mode scenario
with the default `rustls_default` TLS fingerprint. Private mode intentionally
rejects that fingerprint, while the browser-mimic path requires a non-default
`browser-tls` build.

RC.2 keeps private-mode shape evidence as a separate browser-TLS task and keeps
the default CI shape lab on scenarios that can run in the default build.

## Highlights

- Supersedes RC.1 as the active soak baseline so the candidate under soak is
  based on a green full CI commit.
- Keeps the S3 review-input closure, freeze metadata, and S2 two-host evidence
  from RC.1.
- Fixes only release-train source metadata and shape-lab smoke behavior; no
  protocol, config, or stable-scope expansion is included.
- Regenerates the shape-lab baseline for the default non-private scenarios.

## Version Boundaries

- software release tag: `v0.1.0-rc.2`;
- package version: `0.1.0-rc.2`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-beta.2` or `v0.1.0-rc.1`.

## Evidence Boundary

The S2 runtime evidence remains
`docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`.
The S3 review-input closure remains
`docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`.

Together, these records support only the recorded
`maverick-tls-h2-cli-v1` release-candidate scope. They do not prove production
readiness, anonymity, censorship resistance, native server-side ECH, GUI/App
behavior, H3/QUIC stability, exact browser fingerprint equivalence, or behavior
outside the recorded profiles.

## Known Limitations

- No formal independent security audit.
- No production-ready claim.
- No native server-side ECH.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
- Browser-like TLS fingerprinting remains optional and does not claim exact
  browser equivalence.
- Private-mode browser-mimic shape evidence remains separate from the default
  CI smoke path because it needs a non-default `browser-tls` build.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/conformance.sh
python3 scripts/check-security-review-package.py
./scripts/release-artifacts.sh
```

Record the final tagged commit hash, release artifact names, checksums, and
GitHub CI result in the GitHub Pre-release body. Publish this tag as a GitHub
Pre-release with `--latest=false`.
