# Maverick Roadmap

Date: 2026-10-30

[STATUS.md](STATUS.md) records current capabilities and evidence. This file
contains the execution order, not a second history of completed pull requests.

## Delivered — Configuration Generation and Handoff

The explicit H3 generator, paired-output preflight, accurate version capability
list and rejection of lossy URI exports are implemented with public-command,
generated-config and existing quality checks. H2 remains the default. Current
behavior and evidence are in [STATUS.md](STATUS.md#configuration-handoff).

## Delivered — Default H2 Startup and Duplex Progress

TLS/user initialization now finishes before a server start succeeds. Reproduced
client and server backpressure stalls were corrected with independent client
directions and one bounded pending server write. Deterministic regressions
preserve progress deadlines, half-close, full-close and trailer behavior.
See [STATUS.md](STATUS.md#default-h2-startup-and-duplex-relay) for the scope.

## Delivered — SDK Readiness and Pinned CI Tool Cache

Local SDK lifecycle is now `Listening` with remote transport `Unverified`;
configuration and selector diagnostics cannot establish remote readiness.
Existing enum tokens and the deprecated local-only method remain compatible,
with explicit migration guidance. No background probe or observer was added.

The supply-chain job verifies and reuses pinned tool binaries using an exact
compatible cache key. It preserves every scan and saves reusable caches only
from successful main runs. Verify actual cold/warm behavior through existing
workflow dispatch, without adding a new recurring job or weakening checks.

## Next — Remaining Usage and Build-Cost Evidence

Before adding transport features, prioritize concrete failures in ordinary
client/SDK use. A future remote-status capability needs a defined observation,
freshness and failure meaning; local listeners or cumulative counters alone
must not become a health claim.

If SDK H3 becomes a delivery requirement, add its explicit feature and builder
entry with one real SDK forwarding test. H3 pooling, automatic carrier choice
and further CPU work need a concrete requirement or measured problem.
Measure remaining product-cache restore/build costs before changing cache
contents. Retain equivalent test, security, native artifact and rollback
coverage; a quicker noncritical job need not shorten the whole PR.

## Deferred — Exact-Candidate Field Validation and Stable

The owner has deferred named-environment installation, 72-hour ordinary use and
field rollback. These gate the first Direct-H2 Stable release, not local H3
development. A changed release needs a new RC and the applicable exact-candidate
security, compatibility, artifact, supply-chain and native rollback evidence;
do not replace RC.2 assets or count older evidence as a newer candidate's pass.
See the [release contract](docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md).

Native Datagram/CONNECT-UDP, Auto H3, complete runnable Config v2/migration,
auth v3, TUN and additional providers remain separate future capabilities.
Browser equivalence, field performance and production claims need evidence for
those claims. Paid audit, signing or provenance work belongs to a specific
approved release need.

## Execution Discipline

- Deliver one observable user result with its implementation, relevant tests
  and documentation. Measure time to verified usefulness, not PR count.
- Use the shared local/CI entry and preserve every required quality check.
  Review before the first push; continue independent work during CI and resolve
  failed main checks before dependent integration.
- Evaluate actual target-cache restore costs before changing CI further.
  Measure the whole critical path; a shorter noncritical job does not necessarily shorten PR completion. Keep
  every scan and native artifact/rollback check.
- Repeat a passing long test only for a relevant runtime change or unresolved
  failure. Use focused regressions first, including native checks for OS-sensitive
  fixtures, before expensive workloads.
- Keep this task's builds/profiling out of performance runs, record anonymous
  host context and report incomparable conditions honestly. Other projects
  continue running; background load never turns a failing assertion into a pass.
- Keep H3 default-off and field validation deferred. Phase 3 recovery, giant
  convergence, policy-only prerequisite chains and new receipt/registry/watchdog
  systems remain stopped.
