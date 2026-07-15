# Production Audit Evidence Index

Status: pre-freeze index. It lists required evidence classes, not accepted
results.

## Public Review Inputs

| class | public input | current meaning |
| --- | --- | --- |
| production scope | `docs/PRODUCTION_SCOPE.md` | claim target only |
| readiness state | `production-readiness.json` | current machine-readable No-Go |
| protocol | `SPEC.md`, `WIRE_FORMAT.md`, `COMPATIBILITY.md`, `MIGRATIONS.md` | documented v1 boundary |
| threats | `THREAT_MODEL.md`, `SECURITY.md` | server/SDK threats and reporting boundary |
| operations | `docs/OPERATIONS.md`, `docs/INCIDENT_RESPONSE.md`, `SUPPORT.md` | operator process, not runtime proof |
| keys | `docs/CREDENTIAL_ROTATION.md`, `docs/KEY_LIFECYCLE.md` | rotation and recovery process |
| release | `RELEASE_CHECKLIST.md`, `docs/RELEASE_GATES_V1_2.md`, `docs/RELEASE_ARTIFACTS.md` | release rules, not released artifacts |
| CI | `docs/CI_AND_RELEASE_GATES.md`, `.github/workflows/ci.yml`, `.github/workflows/release-candidate.yml` | public-source checks, not private package or platform proof |
| audit process | `docs/INDEPENDENT_AUDIT_PACKAGE.md`, `docs/AUDIT_REMEDIATION_POLICY.md` | reviewer and finding rules |
| prior review | `security-review-package.json`, `docs/history/review/` | historical review input only |
| public cutover | `docs/OPEN_SOURCE_CUTOVER_AUDIT_2026_07_16.md` | history/privacy cutover only |

The separate reference-client review input must include its public threat model,
packaging gate, credential-root gate, package-publication gate, sustained gate,
transition/process-recovery gate definitions, and power-loss gate definition at
the exact frozen commit.

Public Actions results may be used for public Maverick source and artifact
checks. They must not be presented as reference-client build evidence, formal
Ubuntu fixture evidence, independent audit evidence, or production approval.

## Phase 3-B Candidate Input Contract

The coordinator-accepted Phase 3-B manifest must provide:

- full Maverick release, Maverick SDK, and reference-client commit hashes, plus
  proof that the reference-client SDK pin equals the recorded SDK commit;
- software, protocol, Auth v1, Auth v2, config, helper IPC, and recovery-journal
  versions as separate fields;
- package name, version, format, architecture, platform, artifact size, SHA-256,
  OpenSSH release-signature result, and public signer fingerprint;
- local harness, dependency, license, source, unsafe-code, privacy, and
  deterministic-build results for both repositories;
- hashes for evidence runner, collector, analyzer, renderer, cleanup, verifier,
  and watchdog inputs;
- a source-change impact table that says which earlier evidence can or cannot be
  reused;
- every unresolved blocker and a candidate recommendation.

The formal supported-platform evidence must be produced in a source-bound
disposable Ubuntu 24.04 LTS `amd64` VM or fixture. A different physical host may
exercise orchestration or isolation tooling, but its operating-system result is
not accepted as Ubuntu target-platform evidence.

Phase 3-C imports only the accepted manifest SHA-256 and public redacted summary
paths into the public ledger.

## Phase 3-A Evidence Input Contract

The coordinator-accepted Phase 3-A manifest must provide, for the same frozen
hashes:

- gate identifiers and status for sustained/daily use, network transitions,
  process recovery, abrupt power loss and boot recovery, credential-root,
  package install/upgrade/failure/rollback/purge, APT publication, and residue;
- exact artifact and evidence-tool hashes used by every run;
- unique run IDs, bounded watchdog results, expected and observed sample counts,
  and analyzer/verifier status;
- collection-before-cleanup confirmation;
- cleanup manifest and fresh-session independent zero-residue result;
- rejected or partial runs kept separate from accepted results;
- redacted public summaries that state the tested platform and every non-claim.

Phase 3-C imports only the accepted manifest SHA-256 and public redacted summary
paths into the public ledger. Raw logs, aliases, addresses, private paths,
credentials, and infrastructure details never enter this repository.

## External Audit Input Contract

The audit record must provide:

- reviewer identity and independence statement;
- exact frozen hashes and audit dates;
- report SHA-256 and optional auditor signature;
- finding inventory and severity counts;
- remediation commits, rebuilt artifact hashes, and retest results;
- explicit excluded tests and residual risks;
- final scoped conclusion without expanding the production claim.

## Evidence Change Rule

| change | minimum action |
| --- | --- |
| docs only, no claim or procedure change | docs/privacy gates and impact note |
| checker, analyzer, collector, or schema change | rerun affected evidence-tool fixtures and affected evidence layer |
| package script, helper, credential, route, DNS, recovery, or runtime change | new candidate impact decision and rerun affected formal gates |
| dependency or toolchain change | dependency review, rebuild, artifact rebinding, and affected regression gates |
| scope, platform, architecture, address family, carrier, or default change | new scope decision and new matching evidence/audit plan |
| fix after audit | auditor or independent retester rechecks the affected finding and regression surface |

Accepted evidence is never combined across candidates to hide a failed or
missing layer.
