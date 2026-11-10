# Maverick Roadmap

Date: 2026-11-10

[STATUS.md](STATUS.md) records current capabilities and evidence. This file
contains the execution order, not a second history of completed pull requests.

## Delivered — Reliable Local Startup and Handoff

Configuration generation/handoff, H2 server initialization and duplex progress,
and explicit SDK local-state reporting are delivered; [STATUS.md](STATUS.md)
records their behavior and limits. Client startup now also completes all local
binds before spawning tasks. A later listener conflict releases earlier sockets
before returning, permitting immediate corrected startup through the SDK.
Regression coverage includes DNS/HTTP conflicts, explicit H3 and shutdown.

Server frame-size configuration now shares the existing client negotiation
limits. Configuration checking rejects unsupported values before startup;
ordinary H3 forwarding is covered at the supported upper limit as well as the
default. No larger protocol limit or automatic value adjustment is introduced.

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

## Delivered — H3 Connection Setup

The H3 client previously discarded every resolved server address after the
first. It now tries subsequent addresses after a pre-response network failure,
within the original total connection budget. Focused loopback regressions cover
TLS/frame transfer, certificate-pin rejection, timeout and socket release;
ordinary CLI authentication and forwarding coverage remains in the shared gates.

This does not add parallel dialing or promise recovery when a silent first
address consumes the entire budget. At that delivery H3 was explicit/default-off; new generation follows the active contract below.

Mismatched tunnel paths now receive an explicit rejection before authentication.
Local regressions distinguish the rejection from an authentication timeout;
the CLI cases check target isolation, admission release and successful forwarding
with corrected configurations. Normal authentication and timeout policy remain.

Target setup also observes transport loss so a disconnected H3 session releases
its user-flow slot while resolution or connection is pending. Keep normal TCP
half-close behavior covered alongside cancellation and subsequent slot reuse.
Established relays waiting for target response data likewise end on transport
loss, including after upload FIN, while retaining target-first half-close.
Client relays waiting for local upload after response completion also end on
transport loss. Keep normal half-close in both directions covered alongside it.
SOCKS UDP now uses the native datagram path below; admission, control-close
cleanup and subsequent TCP reuse remain covered.

Explicit server-handle shutdown cancels unfinished setup and notifies active
H3 peers before joining their drivers. Keep same-endpoint restart and subsequent
TCP use covered, with forced process termination distinct from this API path.

## Delivered — Protected Generation, Native UDP and New Connections

The authorized sequence is implemented: generated intermediary configurations
require owner-verified origin protection; direct H3 carries native UDP; an
opt-in dual server shares policy/admission across H2/H3; automatic clients choose
only for new TCP connections. TLS/authentication/protocol failures never cause
fallback, and native UDP never silently becomes reliable H2 UDP. The earlier
opt-in generation is superseded by the active candidate contract below. See the [protection contract](docs/END_TO_END_PROTECTION.md) and
[UDP/selection contract](docs/NATIVE_UDP_AND_SELECTION.md).

## Delivered — Integration and Deployment Preparation

The owner prioritized proxy integration and deployability on 2026-11-10, while
keeping field use deferred. This source delivery now provides:

1. An explicit SDK H3 feature, complete builders and protected-profile roundtrip;
   a listener-free connector reusing the existing pooled TCP and native UDP paths.
2. A current wire integration guide with checked native UDP frame examples.
3. A Linux service template and deployment runbook, with normal CLI stop signals
   releasing server sessions/listeners and tests running only on loopback/CI.
4. Local/CI coverage through the existing native artifact, rollback, dependency
   and scanning gates.

## Delivered — RC.3 Complete Transport Candidate

The owner's decision supersedes the earlier Direct-H2-only Stable scope
and generated-direct H2 default. PR #109 delivered the following together at
`2aeaaf9`, with applicable local/CI and exact native archive evidence:

1. Persistent fixed-target H2 UDP sessions: independent upload/download, stable
   target socket/source port, multiple replies, bounded resources and cleanup.
   Preserve the legacy wire path for configurations omitting the new policy.
2. Core-owned selection for new TCP connections and UDP sessions, with bounded
   reachability avoidance/retry and explicit `native_required` / `allow_reliable`
   UDP policy. Authenticate capability decisions; never replay application data.
3. Public SDK and SOCKS integration using those same sessions and selection rules;
   configuration, protocol vectors and integration documentation.
4. A new versioned candidate with H2/H3 built in. Newly generated direct configs
   use dual servers and automatic clients; fixed H2/H3 remain explicit choices.
   Protected intermediary configurations stay H2 with origin protection required.
5. All applicable product, rustls, H3, retained candidate, security, dependency,
   compatibility, native artifact/SBOM and upgrade/rollback checks, and preserved
   exact-source archives/evidence. No field deployment or public release.

See [the implementation contract](docs/NATIVE_UDP_AND_SELECTION.md). Current
completion/evidence lives in STATUS.md; a passing earlier revision does not
qualify this candidate. Reuse existing implementations and add no new crypto,
configuration framework, FFI layer or automatic host provisioning.

## RC.4 — Independent Review Corrections

The owner authorized independent RC.3 security review and correction of actual
findings, while keeping field work and publication deferred. The complete
RC.2-to-RC.3 review identified two reproduced resource issues; its immutable
record remains bound to `2aeaaf9`. See [review scope and outcomes](docs/RC3_SECURITY_REVIEW.md).

1. Keep reliable UDP task ownership through cancellable close, retaining normal
   completion, timeout and bounded cleanup behavior.
2. Reserve shared connection/source capacity before QUIC setup and hold it
   through transport completion; retain separate pre-authentication limits.
3. Independently review the replacement patch, run all applicable local/CI,
   dependency and native artifact/SBOM/rollback gates, and preserve exact-source
   RC.4 packages and updated delivery records. Do not overwrite RC.3 evidence.

This is a correction candidate with the existing full transport scope, not
new protocol functionality. No further speculative hardening is required by
the findings. Actual failures take priority over unrelated optimization.

Performance-based selection is frozen until explicitly unfrozen: no scoring,
continuous speed tests, background ranking or preparatory framework. Keep
existing necessary checks. Active-session migration and seamless cross-carrier
resumption are permanently out of scope, with no reserved future design.

External client development, endpoint/IP-block recovery, node distribution and relay infrastructure
management are outside scope. Field trials remain deferred. Ordinary resolved
address attempts and connection cleanup remain product work. Do not restore
archived prerequisite chains or add a new crypto framework.

## Continuing Execution Discipline

Judge further CI changes by restore, rebuild and whole-workflow time together.
A smaller archive alone does not establish a faster PR; runner variation and
parallel CodeQL/macOS work can limit the benefit. Do not repeat the completed
cache experiment without a relevant change or unresolved failure, or add a
recurring benchmark. Preserve every quality check.

Concrete ordinary-use failures still take priority. H3 pooling and further CPU
work need a measured problem. New-connection selection is authorized above. A remote-status
capability needs defined observations and freshness; local listeners or
cumulative counters cannot establish health. The SDK entry now has explicit H3
support and real forwarding tests. Additional language bindings or adapters
need a concrete consuming application requirement.

## Deferred — Exact-Candidate Field Validation and Stable

The owner has deferred named-environment installation, ordinary use and field
rollback. Stable must cover H2/H3 and TCP/UDP and the supported protected H2
intermediary route; field evidence must cover that matrix. The historical
Direct-H2-only qualification is insufficient. A changed release needs a new RC and the applicable exact-candidate
security, compatibility, artifact, supply-chain and native rollback evidence;
do not replace RC.2 assets or count older evidence as a newer candidate's pass.
See the [release contract](docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md).

Standard CONNECT-UDP, complete runnable Config v2/migration, auth v3, TUN
and additional providers are not
automatic prerequisites for this work.
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
- Preserve existing configuration meanings and keep field validation deferred.
  New direct generation uses dual/auto as authorized above. Phase 3 recovery, giant
  convergence, policy-only prerequisite chains and new receipt/registry/watchdog
  systems remain stopped.
