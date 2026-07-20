# Maverick v0.1.0-alpha.2 Release Notes

Status: second pre-publication private alpha source snapshot.

This is an experimental as-is prototype release. It has alpha review input, but
it is not audited, not production-ready, not a stable protocol freeze, not a
stable or production security sign-off, not a standardization proposal, not an
anonymity claim, and not a censorship-resistance guarantee.

## Highlights

- Public feedback process, issue triage classes, and privacy scrub rules for
  public reports.
- GitHub Pre-release and exact-tag artifact policy for alpha/beta snapshots.
- Issue-template privacy prompts for bug reports, feature requests, and docs
  questions.
- Compatibility and migration notes preserving `protocol_version: 1` and config
  `version: 1`.
- Alpha review remediation covering H2 flow-control release and send
  backpressure, bounded UDP ASSOCIATE waits, resilient listener accept loops,
  fallback behavior, reserved egress blocking, safer config URI import,
  generated-config hygiene, config permission startup gates, and secret
  redaction.
- Approved-host 24-hour TCP/H2 long-haul baseline evidence for the narrow
  stable-scope runtime path.
- Approved-host process-level failure-injection evidence for server restart,
  client restart, upstream target failure, and upstream stall or timeout.
- Approved-host packet-loss and latency evidence for the tested TCP/H2 profiles:
  the diagnostic 8-hour netem rerun passed 96/96 iterations.
- Release hygiene gates for dependency advisories, first-party unsafe-code
  inventory, issue templates, network-safety hygiene, claim hygiene, and
  release artifact checksums.

## Version Boundaries

- software release tag: `v0.1.0-alpha.2`;
- package version: `0.1.0-alpha.2`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-alpha.1`.

## Native ECH Status

Native Maverick server-side ECH is not implemented in this release.
`advanced.experimental_ech` remains rejected for native runtime ECH.

The accepted near-term workaround remains the Cloudflare-fronted WebSocket
carrier, where Cloudflare handles client-facing ECH and Maverick runs as the
origin. This is not native Maverick server-side ECH, not provider-independent
ECH, and not a censorship-resistance guarantee.

## Known Limitations

- No native server-side ECH.
- No stable protocol or config freeze.
- No production-ready claim.
- No production packaging claim.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
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

This release does not cite benchmark numbers, so benchmark artifacts are not
part of the alpha.2 release claim.

Record the final tagged commit hash, release artifact names, and checksums in
the GitHub Pre-release body.

## Upgrade Notes

No mandatory migration is required from `v0.1.0-alpha.1`.

Operators should still review `COMPATIBILITY.md`, `MIGRATIONS.md`, and
`docs/RELEASE_TAGGING.md` before upgrading. This alpha may still change config
fields, protocol details, and experimental gates in later releases.
