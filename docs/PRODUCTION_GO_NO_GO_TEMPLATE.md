# Production Go/No-Go Record Template

Status: unused template. The current decision remains the machine-readable
`NO_GO` in `production-readiness.json`.

Copy this template for one frozen candidate. Do not overwrite it with raw logs
or private infrastructure data.

## Candidate Identity

- Scope ID:
- Maverick release commit:
- Maverick SDK commit:
- Reference-client commit:
- Reference-client SDK pin and verification evidence:
- Software version:
- Protocol/Auth/config versions:
- Helper IPC/recovery versions:
- Server artifact name and SHA-256:
- Client package name/version/platform/architecture and SHA-256:
- Release/artifact signature verification:
- Candidate freeze record date:
- Public PR CI result:
- Release-candidate CI stage, run identity, and control commit:

## Required Inputs

- Phase 3-B accepted manifest SHA-256:
- Phase 3-B redacted public summaries:
- Phase 3-A accepted manifest SHA-256:
- Phase 3-A redacted public summaries:
- Independent audit report SHA-256:
- Auditor identity and independence statement:
- Remediation closure record:

## Five Readiness Questions

| question | result | evidence | blocker or residual risk |
| --- | --- | --- | --- |
| code-complete |  |  |  |
| evidence-complete |  |  |  |
| audit-complete |  |  |  |
| deployable |  |  |  |
| production-ready |  |  |  |

## Operations Checks

- Monitoring thresholds and escalation owner recorded:
- Certificate expiry and renewal rehearsal passed:
- Credential rotation and compromise recovery passed:
- Signing/archive-key loss and rotation plan verified:
- Install, upgrade, failure, rollback, purge, and zero residue accepted:
- Route/TUN/DNS leak and power-loss recovery accepted:
- Incident-response tabletop completed:
- Support, compatibility, migration, and end-of-support wording current:
- APT publication and client verification accepted, if packages are distributed:

## Finding Summary

- Critical open:
- High open:
- Medium open and accepted:
- Low open and scheduled:
- Excluded tests and unproven claims:

## Decision

- Decision: `GO` or `NO_GO`
- UTC time:
- Approver:
- Exact reason codes:
- Next review or expiry:

`GO` is valid only when `production-readiness.json` passes its checker with all
five dimensions complete, every release prerequisite satisfied, and no blocker.
Otherwise record `NO_GO`.
