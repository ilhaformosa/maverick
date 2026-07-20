# S3 Review Handoff - 2026-07-08

Status: reviewer handoff for Phase S3. This is not a completed review,
security audit, production-readiness claim, stable protocol freeze, anonymity
claim, or censorship-resistance claim.

## Purpose

Phase S3 needs a credible independent or community review of the frozen
`maverick-tls-h2-cli-v1` scope plus confirmation that conformance-vector
freeze controls are enforced. The reviewer should use this handoff together
with `docs/SECURITY_REVIEW_PLAN.md` and `security-review-package.json`.

## Baseline

- latest beta tag: `v0.1.0-beta.2`
- S2 public evidence:
  `docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`
- package manifest: `security-review-package.json`
- release train authority: `docs/PLAN_SHORT_TERM_TO_V1.md`
- S3 tag target after review/freeze closure: `v0.1.0-rc.1`
- community review request: private pre-publication issue `1` (not migrated)

The exact reviewed commit must be recorded by the reviewer or maintainer in a
separate findings/triage document before S3 can be marked complete.

## Review Scope

Review only the narrow `maverick-tls-h2-cli-v1` scope:

- TLS 1.3 plus HTTP/2 default transport;
- CLI-managed Rust client and server;
- TCP, DNS, and documented UDP relay;
- Auth v1/v2 transcript binding, replay protection, and credential rotation;
- static and reverse-proxy fallback behavior;
- resource bounds, overload controls, and loopback metrics;
- config parsing, secret redaction, logging, and CLI import/export hygiene;
- conformance vectors, freeze-readiness policy, and frozen-vector immutability.

Out of scope for S3 completion unless separately approved:

- native server-side ECH;
- stable H3/QUIC;
- GUI/App runtime readiness;
- TUN product runtime readiness;
- anonymity, traffic-analysis resistance, or censorship-resistance claims;
- tests that mutate a developer workstation's proxy, DNS, route table,
  firewall, VPN, or other host network-service settings.

## Commands To Reproduce

Run from a clean checkout:

```sh
./scripts/local-harness.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/conformance.sh
python3 scripts/check-security-review-package.py
```

Optional release-surface checks:

```sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

These commands should not change system proxy, DNS, route, firewall, VPN, or
other host network-service settings.

## Requested Findings Format

For each finding, record:

- reviewed commit or tag;
- affected file/function or document section;
- severity: critical, high, medium, low, or informational;
- whether exploitation requires authentication;
- whether exploit details should stay private;
- reproduction steps using loopback or approved-host placeholders only;
- recommended fix or accepted-risk rationale.

S3 can be closed only after high and critical findings are fixed or explicitly
accepted as residual risk, and after public docs reflect the remaining limits.

## Known Non-Claims

Maverick still does not claim:

- formal security audit completion;
- production readiness;
- stable protocol standardization;
- anonymity;
- censorship resistance;
- native server-side ECH;
- GUI/App runtime readiness.
