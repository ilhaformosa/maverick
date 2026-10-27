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

## Completed — One Small Local H3 Experiment

The opt-in lab command now performs one certificate-validated local connection
and H3 request/response over real loopback UDP, with one Boring 5 closure and
bounded resources. Identity-rejection, deadline, and cleanup tests accompany
the executable. This completes the small runnable slice, not H3 adoption.

## Completed — Upstream TLS and Authentication Feasibility

The isolated upstream test package runs the shared client TLS settings and
authentication v1/v2 over loopback H3 through the official Boring integration.
The shipping H2 dependency graph is unchanged. This proves a usable TLS API
route and authentication binding, not a product carrier or browser equivalence.

## Completed — One Local Authenticated H3 TCP Carrier

The opt-in local executable connects SOCKS5 through real H3 to the server's
credential/replay/admission checks and TCP egress. Authentication v1/v2 each
carry 512 KiB in both directions and preserve client half-close. Negative tests
cover credentials, binding, epochs, replay, concurrent-flow limits, and egress.
The shipping H2 graph and default route remain unchanged.

## Completed — H3 TCP Lifecycle Before Integration

Both directions now progress independently, either side may half-close first,
and activity in one direction keeps the connection alive. The local tests
reproduce and fix server-first upload truncation, false download idle timeouts,
and rejecting a valid GOAWAY. Reset/EOF behavior and flow-slot release after
disconnect are covered without changing the default H2 path.

## Next — Decide the Upstream Carrier's Adoption Gaps

Use this working local TCP carrier to resolve the remaining P1/P2/P3 behavior
and platform/dependency requirements. GOAWAY handling is covered; strict peer-push
policy and the selected upstream logging surface still need a concrete disposition. Keep the next implementation
small and driven by an observed gap. Before moving quiche into shipping
packages, verify one shared Boring closure and H2 compatibility. H3 remains
default-off; field use is still deferred.

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
