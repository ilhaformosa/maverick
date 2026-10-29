# Maverick Roadmap

Date: 2026-10-30

[STATUS.md](STATUS.md) records current capabilities and evidence. This file
contains the execution order, not a second history of completed pull requests.

## Delivered — Configuration Generation and Handoff

The explicit H3 generator, paired-output preflight, accurate version capability
list and rejection of lossy URI exports are implemented with public-command,
generated-config and existing quality checks. H2 remains the default. Current
behavior and evidence are in [STATUS.md](STATUS.md#configuration-handoff).

## Next — Default H2 Startup and SDK Readiness

Prioritize the default user path before adding more transport features:

1. Reproduce the H2 server's startup result when TLS certificate/key loading
   fails. It currently initializes TLS inside the spawned serving task; the
   SDK can receive a handle first. Make confirmed startup errors synchronous
   and verify that failure leaves no listener, using the existing fixtures.
2. Verify H2 duplex progress when upload capacity or a local reader blocks.
   Static inspection found waits inside one select branch, not a reproduced
   failure. Add a focused reproduction first; fix only an established problem.
3. Clarify SDK local-listener readiness versus authenticated remote connectivity.
   If SDK H3 becomes a delivery requirement, add its explicit feature and builder
   entry with one real SDK forwarding test; do not imply it exists today.

Choose one observable behavior and finite acceptance checks before implementing
that follow-up. No new supervisor or generic relay framework is needed in advance.
H3 pooling, automatic carrier selection and further CPU work need a concrete
user requirement or measured problem.

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
- Evaluate fixed-version security-tool binary caching and actual target-cache
  restore costs before changing CI further. Measure the whole critical path;
  a shorter noncritical job does not necessarily shorten PR completion. Keep
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
