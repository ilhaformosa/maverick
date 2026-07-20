# Alpha.3 Readiness Tracker

Status: completed release tracker for the `v0.1.0-alpha.3` snapshot. This is not a
stable-scope claim, production-readiness claim, security-audit result,
anonymity claim, censorship-resistance claim, or protocol-freeze claim.

`v0.1.0-alpha.3` remains a small alpha focused on post-alpha.2 release hygiene,
public-feedback readiness, compatibility clarity, migration clarity, and
stable-candidate evidence tracking. The default release posture remains
experimental and as-is.

## Current Boundary

- software release tag: `v0.1.0-alpha.3`;
- package version: `0.1.0-alpha.3`;
- default `protocol_version: 1` remains unchanged;
- config `version: 1` remains unchanged;
- no mandatory migration is planned;
- Native Maverick server-side ECH remains a long-term tracking item, not an
  alpha.3 default release path.

## Alpha.2 Follow-Up Snapshot

The alpha.2 post-release follow-up pass found no urgent correction:

- `v0.1.0-alpha.2` points to commit
  `1ede9226134019f9b7dab5e41c812f6f7d931d76`;
- the GitHub Release is published as a Pre-release;
- attached artifact checksum verification passed;
- internal artifact `SHA256SUMS` verification passed;
- the artifact binary reported `maverick 0.1.0-alpha.2`;
- `BUILDINFO` recorded the alpha.2 commit;
- artifact privacy scans found no local repository path, home path, known
  private approved-host label, known private approved-host address, PEM private
  key header, or bearer-token shaped string.

See `docs/history/release/POST_RELEASE_AUDIT_v0.1.0-alpha.2.md`.

## Alpha.3 Release Snapshot

The alpha.3 release follow-up pass found no urgent correction:

- `v0.1.0-alpha.3` points to commit
  `45d88614b0d4a1a341f3782e26314941eeba8ac1`;
- the GitHub Release is published as a Pre-release and not a Draft;
- the release was not returned by the default latest-release lookup;
- attached artifact checksum verification passed;
- internal artifact `SHA256SUMS` verification passed;
- the artifact binary reported `maverick 0.1.0-alpha.3`;
- `BUILDINFO` recorded the alpha.3 commit;
- artifact and release-body privacy scans found no local repository path, home
  path, local developer username, known private approved-host label, known
  private approved-host address, PEM private-key header, or bearer-token shaped
  string;
- open public issues and pull requests remained empty after publication.

See `docs/history/release/POST_RELEASE_AUDIT_v0.1.0-alpha.3.md`.

## Public Feedback Snapshot

Open public issues and pull requests were checked before and after the alpha.3
release cut. No open issue or pull request was present at either snapshot.

Alpha.3 should therefore avoid claiming that public feedback has already been
handled. The current useful work is keeping triage ready for future reports:

- classify new reports with `docs/PUBLIC_FEEDBACK_PROCESS.md`;
- move sensitive security reports out of public issues;
- scrub private infrastructure details before reproduction;
- prefer loopback-only reproduction steps or separately approved hosts;
- keep public issue responses inside the experimental alpha scope.

## Candidate Work Items

| Area | Alpha.3 action | Local status | Stable-scope impact |
| --- | --- | --- | --- |
| Public feedback | Keep issue triage ready and record whether any public reports exist | Snapshot shows no open public issue or PR | Prevents invented feedback claims |
| Release follow-up | Record tag, release body, artifact, checksum, version, and privacy-scan results for alpha.2 | Documented in post-release audit | Keeps future release checks repeatable |
| Compatibility | Preserve default protocol version `1` and config version `1` | Documented here | Reduces accidental version drift |
| Migration | Preserve no-mandatory-migration posture | Documented here | Keeps config `version: 1` policy explicit |
| Stable candidate | Track remaining evidence without broadening claims | Needs ongoing work | Helps separate stable-scope and production-scope claims |
| Native ECH | Continue upstream tracking only | Deferred | Avoids forcing a risky TLS-stack change into alpha.3 |

## Stable-Candidate Gaps

The first narrow candidate remains `maverick-tls-h2-cli-v1`. Alpha.3 can help
that path by making evidence easier to review, but it should not claim stable
or production status.

High-signal remaining gaps:

- operator rollout and rollback evidence for the exact deployment scope being
  claimed;
- abuse and denial-of-service evidence for auth attempts, connection caps,
  memory pressure, and fallback load;
- redacted observability evidence for metrics and logs;
- deployment hardening evidence for service users, file permissions,
  certificates, restart behavior, and rollback;
- incident-response and vulnerability-handling readiness;
- refreshed approved-host evidence if runtime crates or stable-scope behavior
  change after alpha.2.

Network-impairment evidence exists for the tested TCP/H2 latency and loss
profiles, but that evidence should not be generalized to every provider,
region, platform, topology, or production rollout model.

## Verification Before Tagging

Minimum local alpha.3 gates:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/release-artifacts.sh
python3 scripts/check-roadmap-blockers.py roadmap-blockers.json
python3 scripts/check-security-review-package.py security-review-package.json
```

Run this if spec, wire format, conformance vectors, or compatibility wording
changes:

```sh
./scripts/conformance.sh
```

Run benchmark scripts only if alpha.3 release notes cite benchmark results:

```sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
```

Approved-host evidence must be collected only on explicitly approved hosts and
must be redacted before being committed. The developer workstation must not be
used for system proxy, DNS, route, firewall, VPN, TUN, or other
network-service mutation tests.

## Non-Goals

Do not use alpha.3 to claim or ship:

- native Maverick server-side ECH;
- stable protocol or config freeze;
- audited, production-ready, anonymity, or censorship-resistance status;
- GUI/App runtime behavior;
- production binary distribution for every platform;
- workstation network-service mutation tests.
