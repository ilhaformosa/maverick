# Maverick Roadmap

Status: fast iteration

Date: 2026-08-20

`STATUS.md` says what is true now. This file says what we do now, next, and
later. Git commits, pull requests, Actions runs, releases, and archived
documents preserve history; Maverick does not need another planning framework.

## Working Rule

- Keep exactly one primary user-visible milestone active.
- Prefer one PR per observable outcome, including its focused tests and truth
  update. Do not routinely split authorization, implementation, evidence, and
  post-merge truth into separate PRs.
- Verification grows with risk. Documentation does not need release-grade
  ceremony; release, dependency, wire, auth, config, and artifact changes do.
- A week is a timebox for learning, not a promise to call unfinished work done.
- If a task runs for three days without a runnable result, needs more than
  three prerequisites, or creates more process than product, shrink or defer it.

## Now — Direct-H2 `v1.2.0-rc.1`

**User result:** a real prerelease candidate that a technical owner can install,
use, inspect, and roll back without enabling H3 or changing the published v1
protocol/config/profile formats.

**Scope:** Direct browser-like TLS 1.3 + HTTP/2 only. Provider-fronted H2 remains
Beta. H3, native Datagram, auth v3, Config v2, Auto H3, TUN migration, new
provider work, and broad refactoring are not prerequisites.

1. Prepare one exact RC commit, package version, release note, and Direct-H2
   scope. Do not publish it yet.
2. Run focused compatibility and product checks, then `user-smoke` and
   `local-harness` on that exact candidate.
3. Close the exact candidate's dependency/security review, supported-target
   archives, checksums, native/static verification, SBOMs, public CI, and
   independent review.
4. Make one explicit go/no-go decision. If green, publish RC.1 as a
   prerelease/non-Latest release. If red, fix only the failing gate and produce
   RC.2 when needed.
5. Run the owner field/rollback check. Stable is considered only after the RC
   field and rollback gates pass.

The complete release gate reference remains
`docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`. It does not create another work queue.

## Four-Week Direction

| Timebox | Intended visible result |
|---|---|
| Week 1 | Exact Direct-H2 RC candidate exists and passes local product gates |
| Week 2 | Required review, public CI, artifacts, checksums, and SBOMs close; publish RC.1 only if green |
| Week 3 | Owner installs, uses, observes, and tests rollback of the exact RC |
| Week 4 | Promote to Stable only if every Stable gate is green; otherwise ship a narrowly fixed RC.2 or keep Beta |

This table is enough for weekly control: at the start of each week, take the
first incomplete result; at the end, update the corresponding truth in
`STATUS.md`. Do not invent subprojects to make a red result look busy.

## Next — One Small H3 Go/No-Go

After the RC milestone, allow at most three to five working days for one
product-shaped quiche experiment: one local client/server connection, one H3
request/response, the single Boring 5 closure, bounded resources, no product
default, and no real-network claim.

- Reuse the completed B-001/B-002 candidate work only where it directly helps
  this runnable slice.
- Resolve old P1/P2/P3 patch questions inside the selected candidate decision,
  not through another chain of policy, evidence, and truth-only PRs.
- If the slice cannot produce a maintainable runnable result inside the
  timebox, keep H3 disabled and park it for at least 90 days. Do not revive
  Quinn or create a second backend.

## Later, Only After Observed Need

- Public Datagram APIs, real carrier adapters, consumer migration,
  CONNECT-UDP, and native QUIC Datagram.
- Auth v3, Config v2, schema migrations, Auto H3, TUN work, and additional
  provider integrations.
- Paid audit, provenance/attestation, signing, and reproducible-build work for
  an exact release candidate when those controls are actually needed.

## Explicitly Stopped

- Phase 3 recovery or a renamed replacement.
- Giant branch convergence, long-lived dual H3 backends, or H3 in Auto.
- New receipt, seal, registry, watchdog, evidence schema, coordination layer,
  successor playbook, or parallel active status document.
- Routine policy-only, authorization-only, or post-merge truth-only PR chains.
- Network-setting changes, unapproved provider/spending actions, private data
  in git, or production-readiness claims derived from local tests.

## Owner Participation

No owner action is needed while Codex prepares and verifies the local RC
candidate. The owner becomes necessary for the ordinary-use/72-hour field
observation, rollback experience, personal/legal attestations, publication
approval where explicitly required, and any paid or provider resource decision.
