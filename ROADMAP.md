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

## Current — Configured H3 TCP in Ordinary Client and Server Commands

The bounded integration uses `advanced.quiche_h3`, default false, plus the
optional `experimental-h3` build feature. It reuses runnable config v1 and
ordinary commands; it does not revive the retired H3 flag or require the whole
future Config v2 migration project. Include real dialing/listening, certificate
loading, the shared Boring dependency graph, existing authentication and egress
policy, and separate-process loopback tests. Preserve the H2 default and both
native platform checks. Field use remains deferred.

## Next — Measure the Integrated Path Before Adding Complexity

Use controlled local H2/H3 comparisons to identify concrete connection,
concurrency, resource-use or interruption problems. Add connection reuse or
other performance work only when measured behavior requires it. No automatic
carrier switching, speculative scheduler or new coordination framework is a
prerequisite for the explicit TCP path.

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
