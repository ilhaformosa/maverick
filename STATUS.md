# Maverick Status

Date: 2026-08-21

This is Maverick's only active current-truth document. It answers what exists,
what is safe to claim, what is blocked, and what currently needs owner
participation. `ROADMAP.md` controls execution order. Git history, pull
requests, Actions runs, releases, archived documents, and the retired recovery
playbook preserve detail without becoming parallel status ledgers.

## At a Glance

| Area | Current truth |
|---|---|
| Development stage | **Beta**; experimental and not production-ready |
| Published release | Immutable `v1.2.0-rc.1` prerelease; not Latest; Beta.4 remains the fixed rollback partner |
| Supported product route | Direct browser-like TLS 1.3 + HTTP/2 |
| Provider-fronted route | Implemented and Beta; not part of the first Stable support claim |
| H3/UDP product | Disabled; no current H3 product backend or Auto path |
| Future H3 direction | quiche only, subject to later qualification; Quinn product code is retired |
| Protocol/config/profile schema | Version `1`; existing authentication and frame wire formats unchanged |
| Current milestone | Week 3 owner install, ordinary use, 72-hour observation, and field rollback of exact `v1.2.0-rc.1` |
| Stable readiness | **RED**; exact-RC field use and later Stable gates remain incomplete |

Progress means a real user-visible result. Tests, hashes, policy documents, and
candidate experiments are quality controls, not product progress by themselves.

## Product That Exists

- The Rust core, client, server, CLI, SDK, loopback integration suite, local
  configuration generator, and release-artifact tooling are implemented.
- The default supported route uses browser-like TLS 1.3 and HTTP/2. Local
  `user-smoke` proves that a correct credential relays data and a wrong
  credential does not establish a proxy flow.
- The provider-fronted H2 workaround has carried an owner-only field pilot. It
  is not native ECH or provider-independent privacy. The provider terminates
  TLS and can observe authentication information and tunnel traffic.
- The older WebSocket carrier remains a compatibility path.
- `v1.2.0-beta.4` is the current public prerelease and fixed rollback partner.
  Its Apple Silicon and x86-64 Linux archives, checksums, and target-aware SBOMs
  were published and independently reverified.
- The owner completed a fresh-origin install and an owner-only real-network
  observation. The install path beat five minutes in later trials, and the
  observation ran for 72 hours 18 minutes. This is one pilot, not proof of
  anonymity, maturity, broad censorship resistance, or universal reliability.
- The 2026-07-21 independent security audit reported no open findings for its
  exact historical revision. Later revisions and a future RC require their own
  review and do not inherit that result.

## Claims Maverick Does Not Make

Maverick does not claim production readiness, anonymity, exact browser
fingerprint equivalence, provider independence, native ECH, native QUIC
Datagram support, broad censorship resistance, or safe use by at-risk third
parties. Beta.4 and its field evidence do not automatically qualify a later RC.

## Current Milestone: Direct-H2 RC.1

The sole active product milestone is exact Direct-H2-only candidate
`cf89428e7c7ff885b765374ef21833ddd822e411` for `v1.2.0-rc.1`. Local product
gates, fresh dependency policy, attempt-1 CodeQL/product/supply-chain checks,
Apple/Linux archives and SBOMs, native Beta.4-to-RC.1-to-Beta.4 drills, and an
independent exact-byte security review pass with no Critical, High, or lower
finding. The earlier High release-integrity issue is closed: publication now
downloads the reviewed main-run artifacts instead of rebuilding different
bytes. The explicit RC.1 publication decision is **GO** for this commit and
these bytes only, as a prerelease that is not Latest. Attempt-1 release run
`32487704448` published immutable GitHub Release `v1.2.0-rc.1`; its six public
assets are byte-for-byte identical to the independently reviewed files. Week 2
is complete. No deployment, field result, or Stable result follows. H3, native
Datagram, auth v3, Config v2, Auto H3, TUN migration, and new provider work
remain paused.

The RC was published only after its candidate scope, versions, release note,
local product checks, locked dependency closure, supported-target artifacts,
SBOMs, required public CI, and independent review agreed on the exact
candidate. Stable remains a later decision after Week 3 field evidence.

### RC/Stable Gate Board

| Gate | State |
|---|---|
| Exact RC commit, package version, release note, and candidate scope | **GREEN — `cf89428`, version/note `1.2.0-rc.1`, and Direct-H2-only scope agree** |
| Direct-H2-only route and v1 compatibility matrix | **GREEN — 64 loopback tests and native Apple/Linux Beta.4-to-RC.1 preflights pass on the exact candidate** |
| Local `user-smoke` and `local-harness` on exact candidate | **GREEN** |
| Dependency, advisory, license, source, and first-party `unsafe` review | **GREEN — `h2` 0.4.16; fresh checks pass for 299 locked dependencies** |
| Apple/Linux archives, checksums, native/static verification, and SBOMs | **GREEN — exact run `32484952095`, artifact IDs `9447915168` and `9448107911`, both non-expired and independently reverified** |
| Exact-head public CI and CodeQL | **GREEN — attempt-1 runs `32484951717`, `32484952095`, and `32485010025` pass for `cf89428` without rerun or cancellation** |
| Independent exact-RC security review; no unresolved Critical/High | **GREEN — P0/P1/P2 are all zero; the earlier High exact-byte publication finding is closed** |
| Fresh-origin Direct-H2 field run and 72-hour owner use | **RED — not performed** |
| Native RC-to-Beta.4 rollback on Apple Silicon and x86-64 Linux | **GREEN for qualification — both exact-candidate drills pass; owner field rollback remains later** |
| RC.1 prerelease/non-Latest publication | **GREEN — immutable Release `v1.2.0-rc.1` was published by attempt-1 run `32487704448`; the six public assets match the reviewed bytes** |
| Stable publication and Latest classification | **BLOCKED** |

The full release safety contract remains
`docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`. It is a gate reference, not a second
roadmap.

## Completed Recovery and Architecture Decisions

- The v1.3 cumulative experiment was preserved through immutable archive refs,
  a one-time merge inventory, an exact-head Draft CI baseline, and an accepted
  convergence decision. The 77-commit experimental tree was not merged as a
  giant product change.
- Phase 3 and every renamed recovery/certification continuation are retired.
- Config-v1 experimental Quinn H3 fails closed, and the unpublished
  Quinn/hyperium-H3 product implementation and dependencies were removed.
- quiche is the only possible future H3/UDP product direction. This is a
  direction decision, not adoption evidence.
- The Datagram semantic contract is accepted. A private fake-adapter prototype
  deterministically proved that receive can progress while send remains
  blocked, with bounded cleanup. No public Datagram API, consumer migration,
  CONNECT-UDP, native QUIC Datagram, or product result follows from that proof.
- Release tag and artifact verifiers accept canonical positive Beta/RC inputs
  while deliberately rejecting Stable. They do not create an RC candidate or
  authorize publication.

## Paused Research and Candidate Evidence

### B-001 — quiche qualification

**RED.** The neutral local-only observation contract and bounded parser exist,
but equal quiche and Chrome adapters do not. No complete TLS/QUIC/H3,
fingerprint, weak-network, exporter, CONNECT, Datagram, maintenance, platform,
or supply-chain comparison exists. A failed qualification leaves H3 disabled.

### B-002 — old quiche patch dispositions

**PARTIAL / RED.** Historical source reconstruction, the byte-only verifier,
the candidate dependency boundary, Linux/macOS candidate tests, logging tests,
and one narrow peer-push patch candidate were completed. They are candidate
evidence only.

P1, P2, and P3 remain `UNRESOLVED`. Missing work includes selected-candidate
dispositions, replay, upstream route or a still-valid exception where
required, exact product-shaped qualification, shared-Boring security review,
supported-target product closure/SBOM/final artifact evidence, security-update
response proof, and independent final-delta review. No private quiche patch or
runtime may enter the product until the applicable fork budget passes.

This work is paused during the Direct-H2 RC milestone. It will resume only as a
short, product-shaped go/no-go experiment, not by continuing the old sequence
of policy, evidence, and truth-update PRs.

## Execution Model

- Exactly one primary user-visible milestone may be active.
- One observable outcome normally uses one PR containing implementation,
  focused tests, and any needed STATUS/ROADMAP update.
- A separate authorization PR or post-merge truth PR is not required for
  ordinary reversible work.
- Verification is proportional to risk:
  - documentation-only: diff and privacy checks;
  - ordinary product change: focused tests, `user-smoke`, and public CI;
  - auth, wire, config, dependency, release, or rollback boundary:
    `local-harness`, independent review, and the applicable exact-candidate
    gate.
- Exact hashes and multi-host supply-chain proofs are reserved for releases,
  vendored/upstream source, dependencies, security-sensitive evidence, and
  artifacts where byte identity matters.
- If work takes more than three days without a runnable result, creates more
  than three prerequisite tasks, needs a new coordination framework, or
  produces more management machinery than product value, stop and either
  shrink or defer it.

## Safety and Privacy Boundaries

- Never change this Mac's system proxy, DNS, routes, firewall, VPN, or network
  interfaces. Local work uses `127.0.0.1` and OS-assigned ephemeral ports.
- Never commit real endpoints, credentials, private paths, identities,
  infrastructure names, packet captures, key logs, or environment-specific
  output.
- Authentication, trust-route, target admission, resource budgets, and failure
  behavior remain fail closed. No failure may silently retry, replay, dual-send,
  cross a trust route, or move partial application data to another carrier.
- No queue, task, socket, target map, or association may be unbounded.
- A release, real-network task, provider resource, paid action, destructive
  cleanup, or Stable claim requires its own exact prerequisites and recorded
  go/no-go decision.

## Authorization and Owner Participation

The owner has delegated ordinary technical prioritization and repository-local
execution to Codex. That delegation does not turn missing evidence green or
authorize network-setting changes, spending, destructive actions, or personal
attestations. The owner's instruction to execute Week 2, combined with the
now-green exact gates above, authorizes only the recorded RC.1
prerelease/non-Latest publication. It does not authorize a different candidate,
Stable/Latest, a provider resource, or a field task.

No owner action was needed for local RC preparation and publication. The owner
is now needed for the exact-RC install, ordinary-use/72-hour field task, field
rollback experience, and any personal or legal attestation. If a new
paid/provider resource is actually required, the exact team, resource, region,
lifetime, cost cap, and cleanup must be confirmed before creation or
modification. Full-access provider tokens stay in macOS Keychain and are never
printed or stored in repository configuration.

## Evidence and History

Detailed historical timelines belong to Git commits, merged pull requests,
GitHub Actions, release records, and `docs/archive/`. They are not copied into
this file. When current truth changes, update the affected paragraph in the
same PR instead of appending another chronological evidence block.
