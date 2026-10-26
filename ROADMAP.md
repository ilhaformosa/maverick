# Maverick Roadmap

Status: fast iteration

Date: 2026-10-27

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

## Completed — Direct-H2 `v1.2.0-rc.2`

RC.2 is published as an immutable prerelease/non-Latest release. The exact
candidate passed local checks, independent source/file review, public CI,
Apple/Linux artifact and SBOM verification, and native Beta.4 rollback drills.
The public files match the reviewed qualification artifacts.

## Deferred by Owner — RC.2 field validation and Stable

The owner deferred field validation on 2026-10-27. Installation in a named
owner-controlled environment, 72 hours of ordinary use, and owner field
rollback remain incomplete. Stable cannot proceed on automated evidence alone.
A future gate-changing product fix requires another RC rather than changing
RC.2. The fixed rollback partner remains Beta.4.

The release-policy reference remains
`docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`.

## Now — One Small Local H3 Go/No-Go

With RC.2 released and field work deferred, allow at most three to five working
days for one product-shaped quiche experiment: one certificate-validated local
client/server connection, one H3 request/response over real loopback UDP, the
single Boring 5 closure, bounded resources, no product default, and no
real-network claim. Existing in-memory candidate tests are supporting evidence,
not this runnable result.

- Reuse completed B-001/B-002 work only where it directly helps this slice.
- Use the selected upstream candidate without creating a second backend or
  silently adopting a private patch. Keep product adoption blocked until its
  applicable qualification and fork-budget requirements pass.
- Resolve P1/P2/P3 patch questions inside the selected candidate decision,
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

- Remove the duplicate `product-ci` run on pushes to `main`: main requires
  up-to-date PRs and squash merges, so the PR run already tests the merged
  tree. Only together with enforcing branch protection for administrators
  and a weekly scheduled `product-ci` run (deferred by the owner, 2026-10-14).

## Explicitly Stopped

- Phase 3 recovery or a renamed replacement.
- Giant branch convergence, long-lived dual H3 backends, or H3 in Auto.
- New receipt, seal, registry, watchdog, evidence schema, coordination layer,
  successor playbook, or parallel active status document.
- Routine policy-only, authorization-only, or post-merge truth-only PR chains.
- Network-setting changes, unapproved provider/spending actions, private data
  in git, or production-readiness claims derived from local tests.

## Owner Participation

No owner action is needed for the bounded loopback-only experiment. Owner
field observation and rollback are deferred. Personal/legal attestations and
any paid or provider resource decision still require the owner.
