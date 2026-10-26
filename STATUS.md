# Maverick Status

Date: 2026-10-27

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
| Unreleased dependency maintenance | RC.2 contains dependency and browser-TLS decompression fixes; published RC.1 is unchanged |
| Supported product route | Direct browser-like TLS 1.3 + HTTP/2 |
| Provider-fronted route | Implemented and Beta; not part of the first Stable support claim |
| H3/UDP product | Disabled; no current H3 product backend or Auto path |
| Future H3 direction | quiche only, subject to later qualification; Quinn product code is retired |
| Protocol/config/profile schema | Version `1`; existing authentication and frame wire formats unchanged |
| Current milestone | Qualify and publish Direct-H2 `v1.2.0-rc.2` as a security-maintenance prerelease |
| Stable readiness | **RED**; RC.2 qualification and exact-RC field use remain incomplete |

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
- `v1.2.0-beta.4` is the earlier public prerelease and fixed rollback partner.
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

## Unreleased Dependency Security Maintenance

The current source resolves RUSTSEC-2026-0346 through RUSTSEC-2026-0349,
RUSTSEC-2026-0381, RUSTSEC-2026-0382, and the RUSTSEC-2026-0386 soundness warning
with rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots 1.0.10, and Tokio
1.53.3. Direct dependency minimums exclude the older affected versions;
rustls-webpki is fixed in the product lockfile. Auxiliary lockfiles contain
none of these dependencies. No advisory is ignored or suppressed.

The default browser TLS certificate decompressor also had the large-window
behavior described by RUSTSEC-2026-0348. It now uses strict RFC 7932 decoding,
retains the caller's output bound, and rejects incomplete or trailing data.
Four focused regression tests pass; the large-window rejection test failed
against the old callback. The Linux-only TUN test harness uses Tokio's explicit
registration API with the existing owned-file lifetime preserved.

`security-dependency-inventory.sh`, `user-smoke.sh`, `local-harness.sh`, and the
supported no-default CLI/SDK/test-target build pass locally. The modified Linux
registration module passes a Linux-target Clippy check; no TUN device was run.
The complete no-default relay suite now passes 62 of 62 tests. The private-mode
success test is restricted to its required browser-TLS build, and both build
variants explicitly test rejection of a private client using the rustls
fingerprint. The configuration safety rule is unchanged; CI now runs the
complete no-default relay suite instead of only two selected tests.

These are source-level maintenance results, not a new release or field result.
The immutable public RC.1 artifacts do not contain these fixes. The owner has
authorized completing the compatibility fix, repository integration, and the
subsequent release work autonomously. This does not authorize a field task,
provider resource, spending, or changes to this machine's network settings.

## Current Milestone: Direct-H2 RC.2

The sole active product milestone is a Direct-H2-only `v1.2.0-rc.2` candidate
containing the maintenance above and the configuration-parser changes merged
after RC.1. The immutable RC.1 release remains historical evidence for its own
commit and bytes; it cannot qualify the changed RC.2 source or dependencies.
H3, native Datagram, auth v3, runnable Config v2, Auto H3, TUN migration, and
new provider work remain paused.

RC.2 publication is conditional on one exact reviewed commit, passing local
and public checks, reviewed Apple/Linux artifacts and SBOMs, and native
Beta.4-to-RC.2-to-Beta.4 drills. The release workflow must publish the qualified
main-run files without rebuilding them. An explicit final go/no-go must bind
the selected commit and files before the annotated tag is pushed. Stable
remains a later decision after exact-RC field evidence.

### RC/Stable Gate Board

This board concerns RC.2 only. RC.1's prior qualification is not carried over.

| Gate | State |
|---|---|
| Exact RC commit, package version, release note, and candidate scope | **PENDING — RC.2 version, note, and Direct-H2 scope prepared; final commit not yet frozen** |
| Direct-H2-only route and v1 compatibility matrix | **GREEN locally — 65 default and 62 rustls relay tests pass; native artifact drills remain separately required** |
| Local `user-smoke` and `local-harness` on exact candidate | **GREEN on the RC.2 candidate source** |
| Dependency, advisory, license, source, and first-party `unsafe` review | **GREEN locally — fresh advisory/policy checks pass for 307 locked dependencies with no advisory exceptions** |
| Apple/Linux archives, checksums, native/static verification, and SBOMs | **PENDING** |
| Exact-head public CI and CodeQL | **PENDING** |
| Independent exact-RC security review; no unresolved Critical/High | **PENDING** |
| Fresh-origin Direct-H2 field run and 72-hour owner use | **RED — not performed** |
| Native RC-to-Beta.4 rollback on Apple Silicon and x86-64 Linux | **PENDING — both exact-RC.2 qualification drills and owner field rollback remain incomplete** |
| RC.2 prerelease/non-Latest publication | **PENDING — no final go/no-go recorded** |
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
attestations. The owner's latest instruction delegates completion of the
security fixes, compatibility-test repair, commits, pushes, integration, and
release decisions.
Codex has selected RC.2 as the narrowly scoped maintenance candidate. That
authorization permits prerelease/non-Latest publication only after the exact
candidate gates pass and the final go/no-go is recorded. It does not authorize
Stable/Latest, a provider resource, spending, or a field task.

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
