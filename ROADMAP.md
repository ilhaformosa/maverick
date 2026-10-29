# Maverick Roadmap

Date: 2026-10-29

`STATUS.md` records current capabilities and evidence. This file records
execution order; historical work belongs to Git, PRs, Actions and release records.

## Working Approach

- Deliver one observable user result at a time, including implementation,
  relevant tests and necessary documentation in the same change.
- Use existing authentication, configuration, tools and transport primitives.
- While CI runs, continue independent authorized work; failures take priority
  before dependent merges. Do not repeat passing checks without a relevant change.
- Measure time to a verified usable result, not the number of PRs.

## Completed Foundations

Direct-H2 RC.2 is published. CI platforms now run in parallel with all prior
checks retained, and approved CodeQL alert dispositions are recorded per alert.
The local H3 work established verified TLS, real authentication/TCP forwarding,
independent directions, half-close, resource cleanup and upstream control/logging
boundaries. Those foundations are reused by the configured carrier.

## Completed — Configured H3 TCP in Ordinary Client and Server Commands

The bounded integration uses `advanced.quiche_h3`, default false, plus the
optional `experimental-h3` build feature. It reuses runnable config v1 and
ordinary commands; it does not revive the retired H3 flag or require the whole
future Config v2 migration project. Real dialing/listening, certificate loading,
the shared Boring dependency graph, existing authentication/egress policy and
separate-process loopback tests are implemented. H2 remains the default and
both native platforms are checked. Field use remains deferred.

## Completed — Local H2/H3 Comparison and Observed Corrections

The release-mode CLI comparison and bounded CI stability test cover connection
setup, bulk transfers, concurrency and interrupted-flow recovery. The observed
H2 target-first half-close truncation was corrected, and the repeatable H3
receive-window improvement retained. Scope and limits are recorded in `STATUS.md`.

## Completed — Longer Local Sessions and Resource Measurements

Use the same configured path for repeated sustained/churn load, idle periods,
local cancellation and client-process recovery. Observe CPU time, resident
memory, file descriptors and the existing server metrics before expanding
transport behavior. H2's pooled-connection admission and H3's per-flow admission
must be interpreted separately. Short CI cases cover lifecycle correctness;
long resource measurements remain explicit local runs.

Connection reuse needs a concrete workload and benefit; local throughput alone
does not justify automatic carrier switching, new scheduling machinery or a
browser/network performance claim.

## Completed — Shared Checks and Measured H3 CPU Work

Use the shared local/CI check entry and install only missing CI tools. Retain
all platform, compatibility, historical candidate, security and release checks.
Calibrate workloads with a short preflight, finish focused review before the
first CI push, and keep this task's builds out of resource measurements.

The bounded receive-queue change reduces measured server CPU and packet counts
under the same controlled workload. The local before/after/control runs and
their limits are recorded in `STATUS.md`.

## Completed — Client CPU Measurement and Lifecycle Update

The existing bounded receive turn now includes packets already available at
the client socket. Local A/B/A measurements observed fewer client packets and
a modest lower mean CPU cost; a fourth resource run without counters passed.
Scope and measurement limits are in `STATUS.md`.
Qualification continues through the shared H3 and product checks; H3 remains
default-off and field validation deferred.

Wait for observed client-exit cleanup instead of a fixed sleep, and exercise
both H2 and H3 process recovery in normal CI. Keep the same cleanup deadline
and per-phase idle observations; do not remove checks to improve run time.

## Completed — Local Qualification at Higher Concurrency

For higher-concurrency validation, use 32 sustained flows on the configured
client/server path, with 30 minutes of H3 load and 10 minutes of H2 reference
load. Run a short preflight and relevant
shared local checks first, then overlap remote CI with the long local run.
Keep this task's builds and profiling separate, record whole-host context, and
do not assume unrelated projects are idle. Review before
the first push, and merge only after both the long run and all CI checks pass.

Record achieved transfer rate, CPU, sampled memory and resource cleanup against
the tested revision in the PR validation report; repeat a passed long run only
for a relevant change or unresolved result. Change product behavior only for problems supported by
the measurements; preserve default-off H3, deferred field validation and every
existing quality check.

## Completed — Burst Ingress and Shared-Socket Send Work

Use short, controlled local runs to distinguish pre-auth transport drops from
application rejection before changing policy. The observed burst timeout led to
a bounded listener receive-buffer request; the measured shared-send cost led to
serialization of that socket's flushes. Retain existing packet/admission limits,
thread defaults and authentication deadlines. Scope and controlled results are
recorded in `STATUS.md`.

Finish source review and shared checks before the final uninstrumented long run,
and overlap that run with remote CI on the same candidate. Keep stack sampling
separate from quantitative runs. A macOS background-policy run changes network
I/O as well as CPU scheduling and cannot isolate CPU cost. Temporary diagnostics
must not replace or weaken the final ordinary-command checks.

## Completed — Local Reliability and Measurement Context

Qualify selected packet loss/delay, slow-reader isolation and server restart on
the ordinary H3 CLI path. Reuse existing fixture and cleanup checks. Record host
load and platform memory context without process names or command lines; separate
correctness and loaded-host observations from quantitative performance claims.
Background activity is neither proof of a product defect nor a reason to dismiss
a failure. No automatic skip or relaxed deadline follows from a busy host.

Use short focused tests first, then shared checks and existing PR/main gates.
Repeat long runs for relevant runtime changes or unresolved failures, not for
every edit to test/documentation code. Keep performance runs separate from this
task's own builds/profiling, but do not require unrelated projects to stop.

## Completed — H3 Progress and Idle Semantics

Distinguish slowly advancing TCP writes from actual stalls on the client and
server relay paths. Reproduce timing errors with paused-clock, bounded-stream
tests, then make the smallest correction without changing configured deadlines.
Keep QUIC network-idle and policy-induced wire silence distinct from application
write progress; do not add keepalive or rate-scheduling machinery for this fix.

Retain all shared and native CI checks. For this timer correction, use the
existing 32-flow resource/recovery workload for three 60-second H3 phases and
three 20-second H2 reference phases after focused tests. The paused-clock cases
exercise the failure directly; repeat the prior 42-minute run only if a new
failure or a broader runtime change justifies it. For OS-sensitive fixtures,
confirm native test results before starting a costly long run. Record host
context and avoid performance claims from incomparable background conditions.

## Completed — Explicit Local H3 Self-Check

Expose the existing H3 path through `user-smoke --quiche-h3`, with H2 remaining
the default and unsupported builds rejecting the explicit option. Reuse the
local certificate/credential and payload checks instead of another test harness.
Exercise the public command in both build variants through shared checks.

This entry-point change does not alter relay or transport behavior. Retain the
existing integration/lifecycle and native CI coverage; a new long performance
run needs a relevant runtime change or failure. Self-check timings remain
diagnostic when other development tasks are active.

## Next — Remaining H3 Cost and Integration Quality

Keep using the configured client/server path and shared checks. Further CPU
changes need a measured benefit and preserved transfer/lifecycle behavior;
the remaining client/UDP cost does not by itself justify connection pooling,
automatic carrier switching or a new scheduler. Keep performance runs separate
from builds, review code and documentation before the first push, and preserve
all required CI checks while improving preparation and diagnostics.

## Deferred — Field Validation and Stable

The owner continues to defer named-environment RC installation, 72-hour ordinary
use and field rollback. H3 local development can continue independently;
neither CI success nor a local H3 result makes Stable ready. A future changed
release needs a new exact RC, not replacement of RC.2's immutable assets.

## Later, With Their Own Concrete Requirement

Native Datagram/CONNECT-UDP, Auto H3, full runnable Config v2 and migration,
auth v3, TUN and additional providers are separate capabilities. Broad browser
fingerprint equivalence, real-network performance and production claims require
evidence for those claims. Paid audit, signing or provenance work belongs to a
specific approved release need.

A later CI change may revisit duplicate main work and historical reference
experiments after defining equivalent coverage, artifact provenance and branch
protection. This iteration retains all checks and does not authorize bypasses.

Phase 3 recovery, giant convergence, policy-only prerequisite chains and new
receipt/registry/watchdog systems remain stopped.
