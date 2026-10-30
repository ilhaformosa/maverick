# Maverick Roadmap

Date: 2026-10-31

[STATUS.md](STATUS.md) records current capabilities and evidence. This file
contains the execution order, not a second history of completed pull requests.

## Delivered — Reliable Local Startup and Handoff

Configuration generation/handoff, H2 server initialization and duplex progress,
and explicit SDK local-state reporting are delivered; [STATUS.md](STATUS.md)
records their behavior and limits. Client startup now also completes all local
binds before spawning tasks. A later listener conflict releases earlier sockets
before returning, permitting immediate corrected startup through the SDK.
Regression coverage includes DNS/HTTP conflicts, explicit H3 and shutdown.

The pinned security-tool cache has already been verified cold and warm on the
same revision: the supply-chain job took 410 and 42 seconds respectively, with
every scan retained. Do not repeat that completed experiment without a relevant
change. See [cold](https://github.com/ilhaformosa/maverick/actions/runs/40947204197)
and [warm](https://github.com/ilhaformosa/maverick/actions/runs/40948666434) evidence.

## Delivered — Evidence-Based Product Cache Preparation

PR #90's product workflow took 719 seconds and its main run 671 seconds.
Linux was the critical path; restoring its approximately 4.98 GB compressed
cache took 188/118 seconds. Parallel macOS and CodeQL finished earlier.
These observed runs justify examining cache contents, not dropping checks.

A hosted before/after inventory and a reproduction of the pinned cache action
showed that parent-directory tar recursion bypassed the existing child
exclusions. Product cache v2 therefore uses Cargo's workspace-scoped cleanup
after successful checks and artifact upload, preserving reusable dependencies.
Root, isolated fixture and pilot build directories are covered; no local shared
cache is cleaned. The same paths can restore v1 during migration, while only
successful main runs save v2. See [STATUS.md](STATUS.md#sdk-readiness-and-ci-tool-reuse)
and the associated PR for baseline and warm-run evidence.

## Delivered — H3 Address Selection

The H3 client previously discarded every resolved server address after the
first. It now tries subsequent addresses after a failed QUIC/TLS attempt,
within the original total connection budget. Focused loopback regressions cover
TLS/frame transfer, certificate-pin rejection, timeout and socket release;
ordinary CLI authentication and forwarding coverage remains in the shared gates.

This does not add parallel dialing or promise recovery when a silent first
address consumes the entire budget. H3 remains explicit and default-off.

## Next — Follow Concrete Ordinary-Use Evidence

Judge further CI changes by restore, rebuild and whole-workflow time together.
A smaller archive alone does not establish a faster PR; runner variation and
parallel CodeQL/macOS work can limit the benefit. Do not repeat the completed
cache experiment without a relevant change or unresolved failure, or add a
recurring benchmark. Preserve every quality check.

Concrete ordinary-use failures still take priority. H3 pooling, automatic
carrier choice and further CPU work need a measured problem. A remote-status
capability needs defined observations and freshness; local listeners or
cumulative counters cannot establish health. Add an explicit SDK H3 feature
and builder only when that becomes the chosen delivery entry, with a real SDK
forwarding test; it is not required to keep the existing CLI H3 path working.

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
- Measure the whole CI critical path and preserve every scan and native
  artifact/rollback check. A faster noncritical job need not shorten completion.
- Repeat a passing long test only for a relevant runtime change or unresolved
  failure. Use focused regressions first, including native checks for OS-sensitive
  fixtures, before expensive workloads.
- Keep this task's builds/profiling out of performance runs, record anonymous
  host context and report incomparable conditions honestly. Other projects
  continue running; background load never turns a failing assertion into a pass.
- Keep H3 default-off and field validation deferred. Phase 3 recovery, giant
  convergence, policy-only prerequisite chains and new receipt/registry/watchdog
  systems remain stopped.
