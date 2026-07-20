# Maverick v0.1.0-alpha.3 Release Notes

Status: third pre-publication private alpha source snapshot.

Maverick remains an experimental as-is prototype. Alpha.3 is not
production-ready, not a stable protocol freeze, not a stable or production
security sign-off, not a standardization proposal, not an anonymity claim, and
not a censorship-resistance guarantee.

## Highlights

- Post-alpha.2 release follow-up: record tag, release body, artifact checksum,
  binary version, `BUILDINFO`, and privacy-scan results.
- Public feedback readiness: keep triage classes and privacy scrub rules ready
  while accurately recording that no open public issue or pull request existed
  at the checked snapshot.
- Compatibility clarity: preserve default `protocol_version: 1` and config
  `version: 1` unless an accepted alpha.3 item explicitly changes the protocol
  or config boundary.
- Stable-candidate tracking: keep `maverick-tls-h2-cli-v1` evidence gaps
  visible without expanding alpha claims.
- Native ECH tracking: continue to wait for reviewed server-side TLS backend
  support before any native runtime ECH path is considered.

## Version Boundaries

- software release tag: `v0.1.0-alpha.3`;
- package version: `0.1.0-alpha.3`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-alpha.2`.

## Native ECH Status

Native Maverick server-side ECH is not planned for this alpha. The accepted
near-term workaround remains the Cloudflare-fronted WebSocket carrier, where
Cloudflare handles client-facing ECH and Maverick runs as the origin. This is
not native Maverick server-side ECH, not provider-independent ECH, and not a
censorship-resistance guarantee.

## Known Limitations

- No native server-side ECH.
- No stable protocol or config freeze.
- No production-ready claim.
- No production packaging claim.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
- Public feedback handling should cite only actual recorded public issues, pull
  requests, or private reports.
- Approved-host evidence supports only the explicitly tested scope and does not
  generalize to every deployment topology, region, provider, platform, or
  network condition.
- Broader production claims still require separate operator rollout/rollback,
  abuse/DoS, observability, deployment hardening, and incident-response
  evidence.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/release-artifacts.sh
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
```

Run conformance checks if alpha.3 changes spec, wire format, compatibility
wording, or conformance vectors:

```sh
./scripts/conformance.sh
```

This draft does not cite benchmark numbers. Do not attach benchmark artifacts
or quote benchmark results unless the matching benchmark commands are run for
the final tagged commit.

Record the final tagged commit hash, release artifact names, and checksums in
the GitHub Pre-release body.

## Upgrade Notes

No mandatory migration is required from `v0.1.0-alpha.2`.

Operators should still review `COMPATIBILITY.md`, `MIGRATIONS.md`, and
`docs/RELEASE_TAGGING.md` before upgrading. This alpha may still change config
fields, protocol details, and experimental gates in later releases.
