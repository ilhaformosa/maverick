# Maverick Roadmap

Date: 2026-10-28

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
first CI push, and keep other local builds out of resource measurements.

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
