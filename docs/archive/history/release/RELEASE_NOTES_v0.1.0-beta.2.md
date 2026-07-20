# Maverick v0.1.0-beta.2 Release Notes

Status: second beta source snapshot for the frozen `maverick-tls-h2-cli-v1`
release train.

Maverick remains an experimental as-is prototype. Beta.2 means the S2
independent-evidence gate has current approved-host evidence. It does not mean
production-ready, audited, stable protocol freeze, anonymity, or
censorship-resistance.

## Highlights

- Independent two-host evidence: the S2 report records a 24-hour detached
  TCP/H2 long-haul from a second approved client host, with 288/288 passing
  iterations and zero unexpected failures.
- Network impairment evidence: the approved-host netem profile ran for 8 hours
  across baseline, latency, packet loss, combined latency/loss, rough loss, and
  recovery-baseline scenarios, with 96/96 passing iterations and zero
  unexpected failures.
- Failure injection: the process-level pack now covers server restart, client
  restart/reconnect, upstream echo failure, upstream stall/timeout, and
  reverse-proxy fallback-origin failure/recovery.
- Evidence tooling: S2 collectors retain detailed client/server logs while
  keeping public reports redacted and free of private hostnames, IP addresses,
  provider details, paths, and generated secrets.

## Version Boundaries

- software release tag: `v0.1.0-beta.2`;
- package version: `0.1.0-beta.2`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-beta.1`.

## Evidence Boundary

The public S2 evidence report is
`docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`.

The evidence supports only the recorded TLS 1.3 plus HTTP/2 CLI-managed path,
approved remote host topology, and listed latency/loss/failure profiles. It
does not prove production readiness, anonymity, censorship resistance, native
server-side ECH, GUI/App behavior, H3/QUIC stability, or behavior outside the
recorded profiles.

## Known Limitations

- No native server-side ECH.
- No stable protocol freeze.
- No formal security audit.
- No production-ready claim.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
- S3 still requires independent or community security review and protocol
  freeze work before the release train can move toward RC.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

Record the final tagged commit hash, release artifact names, and checksums in
the GitHub Pre-release body. Publish this tag as a GitHub Pre-release with
`--latest=false`.
