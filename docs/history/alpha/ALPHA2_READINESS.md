# Alpha.2 Readiness Tracker

Status: release-cut tracker for `v0.1.0-alpha.2`. This is not a stable-scope
claim, production-readiness claim, or audit result.

`v0.1.0-alpha.2` remains a small alpha focused on public feedback, release
hygiene, privacy hygiene, compatibility clarity, audit remediation, and
approved-host evidence tracking. The default runtime claim remains the same as
`v0.1.0-alpha.1`.

## Local Alpha.2 Scope

Locally actionable items before an alpha.2 tag:

- keep public issue intake aligned with `docs/PUBLIC_FEEDBACK_PROCESS.md`;
- publish alpha/beta GitHub Releases as Pre-releases only;
- attach artifacts only from the exact tagged commit;
- keep release notes, changelog, compatibility notes, and migration notes in
  sync;
- keep example and operator docs free of real domains, addresses, account
  names, certificate paths, generated secrets, and local private paths;
- run local conformance, release-artifact, and hygiene checks before tagging;
- record any benchmark or approved-host evidence without expanding claims.

## Candidate Work Items

| Area | Alpha.2 action | Local status | Stable-scope impact |
| --- | --- | --- | --- |
| Public feedback | Document triage classes and privacy scrub rules | Documented locally | Helps issue quality; not stable evidence |
| Issue templates | Require safety confirmations and scoped reproduction data | Updated and covered by hygiene checker | Reduces public secret leakage risk |
| GitHub Pre-release | Document pre-release body and artifact attachment policy | Documented locally | Prevents alpha from looking stable |
| Release artifacts | Keep exact-commit artifact and checksum rules visible | Documented and smoke-tested locally | Supports future stable candidate gate |
| Compatibility | State that alpha.2 does not plan protocol/config changes | Documented locally | Avoids accidental compatibility claim drift |
| Migration | State that alpha.2 has no planned mandatory migration | Documented locally | Keeps config `version: 1` policy explicit |
| Operator docs | Reinforce support-data redaction and rollback boundaries | Documented locally | Helps future rollout evidence quality |
| Conformance | Run `./scripts/conformance.sh` before tagging if vectors or spec wording change | Passed locally on 2026-07-02 | Supports freeze-readiness later |
| Benchmarks | Run benchmark scripts only when release notes cite benchmark results | Not run; alpha.2 release notes cite no benchmark numbers | Trend evidence only |
| Long-haul | Keep 24-hour approved-host run as stable evidence, not alpha blocker | 24-hour baseline completed on 2026-07-03 | Supports stable-candidate evidence; not production evidence |
| Failure injection | Track restart, reconnect, upstream timeout, packet loss, and rollback evidence | Process-level pack completed on 2026-07-03; diagnostic approved-host netem rerun passed 96/96 on 2026-07-04 | Supports stable-candidate evidence; production rollout remains separate |

## Verification Before Tagging

Minimum local alpha.2 gates:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/release-artifacts.sh
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
```

Run this when spec, wire, or conformance vectors change:

```sh
./scripts/conformance.sh
```

Run these only when alpha.2 release notes cite benchmark results:

```sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
```

Approved-host evidence must be collected only on explicitly approved hosts and
must be redacted before being committed. The developer workstation must not be
used for system proxy, DNS, route, firewall, VPN, or TUN mutation tests.

## Local Verification Snapshot

Local alpha.2 preparation checks passed on 2026-07-02:

```sh
git diff --check
./scripts/conformance.sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/release-artifacts.sh
python3 scripts/claim-hygiene.py
python3 scripts/issue-template-hygiene.py
python3 scripts/network-safety-hygiene.py
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
```

The generated release artifact checksums also verified locally. Release-cut
artifacts must still be regenerated from the exact tagged alpha.2 commit before
GitHub Pre-release attachment.

## Approved-Host Runtime Evidence Snapshot

A detached 24-hour approved-host TCP/H2 long-haul baseline passed on
2026-07-03:

- runtime binary version: `maverick 0.1.0-alpha.1`;
- duration: 86400 seconds;
- interval: 300 seconds;
- iterations: 288;
- passed: 288;
- failed: 0;
- client PASS sequence: continuous `PASS 1` through `PASS 288`;
- server authenticated sessions: 288;
- echo target connections: 288;
- suspicious log matches: 0;
- test ports and temporary credential material cleaned after audit.

See `docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_03.md`.

This is useful stable-scope baseline evidence, but it is not alpha.2 artifact
evidence because the run used a remote source snapshot without `.git` metadata
and the runtime binary reported `0.1.0-alpha.1`.

## Approved-Host Failure-Injection Snapshot

A process-level approved-host TCP/H2 failure-injection smoke passed on
2026-07-03:

- tested commit: `d2ae6bc`;
- runtime binary version: `maverick 0.1.0-alpha.1`;
- checks: 11;
- pass results: 8;
- controlled connect failures: 2;
- controlled stall results: 1;
- covered server restart, client restart, upstream echo target failure, and
  upstream stall or timeout;
- did not mutate host proxy, DNS, routes, firewall, VPN, interfaces, or
  traffic-control settings;
- test ports and temporary credential material cleaned after audit.

See `docs/history/evidence/APPROVED_HOST_FAILURE_INJECTION_EVIDENCE_2026_07_03.md`.

## Non-Goals

Do not use alpha.2 to claim or ship:

- native Maverick server-side ECH;
- stable protocol or config freeze;
- audited, production-ready, anonymity, or censorship-resistance status;
- GUI/App runtime behavior;
- production binary distribution for every platform;
- workstation network-service mutation tests.

## External Gates

These remain outside local alpha.2 completion unless approved hosts or external
review are explicitly supplied:

- failure-injection evidence for restart, reconnect, upstream timeout, packet
  loss, fallback target failure, and rollback beyond the completed
  process-level pack;
- independent or community security review;
- native server-side ECH integration evidence after upstream TLS support exists.
