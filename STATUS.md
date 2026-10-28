# Maverick Status

Date: 2026-10-28

This is the current product-state record. `ROADMAP.md` gives execution order;
Git, pull requests, Actions and release records retain historical evidence.

## Current Product

| Area | Current state |
|---|---|
| Stage | Experimental Beta; not production-ready |
| Published release | Immutable `v1.2.0-rc.2`, prerelease/non-Latest, Direct H2 |
| Default source build and configuration | Browser-like TLS 1.3 + HTTP/2; H3 disabled |
| Explicit H3 source capability | Ordinary client/server commands can use quiche for TCP when both the build feature and new configuration switch are enabled |
| Configuration/authentication | Runnable config v1; existing authentication v1/v2 and frame formats retained |
| Field validation | Deferred by the owner; no new real-network trial authorized |
| Stable | Not published; exact-RC field use and owner rollback remain incomplete |

The CLI, SDK, client/server, local configuration generator and artifact tooling
are implemented. The provider-fronted H2 and older WebSocket paths remain Beta
compatibility routes, outside the first Direct-H2 Stable claim. A TLS-terminating
provider can observe authentication and tunnel traffic; that route is not ECH
or provider-independent privacy.

## Published RC.2

[RC.2](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.0-rc.2) contains
the dependency, certificate-decompression, certificate-distrust and configuration
compatibility maintenance from source `966d29966d05287bc2eef6401c6297582db605f6`.
Its six public files were verified against the reviewed Apple/Linux artifacts;
native upgrade and rollback to the fixed Beta.4 partner passed. Publication does
not substitute for the deferred 72-hour owner trial and field rollback.

Subsequent source changes, including the shared Boring update and H3 integration,
are not in those immutable files. Publishing a changed candidate requires a new
RC and the applicable exact-candidate checks in
`docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md`.

## Explicit H3 TCP Integration

Build the ordinary CLI with `--features experimental-h3` and set
`advanced.quiche_h3: true` on both ends. The default is false; generated default
configs omit it. The old `advanced.experimental_h3: true` flag remains retired
with its original rejection. Config v2 remains a policy parser, not a runnable
configuration or a prerequisite for this bounded v1 extension.

The configured path uses real UDP dialing and a shared server listener. It
loads configured certificates and CA roots, checks hostname and optional
certificate pin, then uses the existing exporter-bound authentication v1/v2,
replay cache, user/flow limits, egress policy, shaping and TCP relay. SOCKS TCP
and HTTP CONNECT use the same connection path. One QUIC connection and one H3
request carry one TCP flow; there is no pool, automatic H3 selection or carrier
fallback.

The optional `maverick-quiche` crate owns the shared UDP/QUIC/H3 driver. Existing
isolated proxy tests call this same implementation. The listener bounds packet
queues and active connections, checks per-source capacity, and transfers the
existing pre-auth semaphore permit from TLS acceptance to authentication.
Normal closure preserves queued data and waits for the upstream stream's
acknowledged completion; cancellation and shutdown release the associated tasks.

The source dependency graph aligns Boring 5.2.0, boring-sys 5.3.0 and
tokio-boring 5.2.0. The product H3 carrier uses upstream quiche 0.30.0 with its
official Boring integration. The retained 0.29.3 reference and private-patch
tests use the updated shared TLS closure; their original historical environment
remains in Git. No private quiche patch enters the product.

This TLS dependency update also affects the default H2 build. Its default and
rustls compatibility checks remain required; H3 being disabled does not imply
that the H2 dependency graph is unchanged.

### Supported scope and retained limits

- Explicit, direct H3/TCP only. Fronting/WebSocket combinations, local DNS/TUN,
  the rustls fingerprint selection and SOCKS UDP associations are rejected.
- Existing Profile URI export rejects H3 configs rather than silently losing
  the explicit transport choice. v1-to-v2 policy projection reports its H3
  blocker instead of presenting the configuration as H2.
- P1: upstream rejects actual pushed streams. Ignored push controls/promises
  are not application frames and cannot create a target connection. The private
  push-rejection patch is not adopted.
- P2: ordinary request-priority hints are consumed; GOAWAY is interpreted for
  the sole current request. There are no additional application streams or
  native Datagram consumers.
- P3: `log` has a process-wide compile-time Debug cap; qlog is disabled. Debug
  and release tests check H3/QPACK silence with verbose host loggers. This is
  not an exhaustive audit of every logging mechanism.

quiche 0.30.0 ignores some push metadata instead of enforcing every RFC 9114
push-ID rule. This remains documented and tested, not a full HTTP/3 conformance
claim. Supporting actual push would require revisiting the decision.

Broad B-001 comparison against Chrome, weak-network/field measurements, native
Datagram and CONNECT-UDP remain incomplete. They apply to their corresponding
future capabilities and claims, not as repeated prerequisites for each local
TCP change. No browser equivalence, anonymity, broad censorship resistance,
production readiness or H3 performance advantage is claimed.

### Verification

The isolated suite covers TLS/auth, control metadata, replay/egress/flow limits,
512 KiB transfers in both directions, either half-close order, simultaneous
traffic, activity timeouts and connection cleanup. The configured CLI test runs
separate ordinary client/server processes on `127.0.0.1` and ephemeral ports:
auth v1/v2, SOCKS and HTTP CONNECT, sequential/concurrent flows, a small server
connection budget, malformed UDP input, and rejection of wrong credentials,
CA, hostname and pin without contacting the target.

Both native CI jobs retain these checks, release-mode logging checks, default
H2/rustls verification, dependency checks, artifact/SBOM checks and upgrade/
rollback drills. Relevant local commands remain `scripts/user-smoke.sh`,
`scripts/local-harness.sh`, the H3 fixture tests, and
`cargo test --locked -p maverick-cli --features experimental-h3 --test h3_product`.

## Local H2/H3 Comparison

On 2026-10-28, release-mode ordinary CLI processes were compared on one macOS
arm64 host with Rust 1.99.0. Both paths used equivalent TLS/auth v2 settings,
verified certificates/pins, SOCKS TCP and the same payload checks. A start
marker prevents the target from pre-buffering downloads during SOCKS setup.
Each bulk result is the median of three 8 MiB transfers per direction; duplex
throughput adds both directions. The following ranges cover two final runs.

| Observation | H2 | Explicit H3 |
|---|---:|---:|
| Subsequent connection p50 | 0.264–0.303 ms | 0.791–0.819 ms |
| Subsequent connection p95 | 0.466–0.524 ms | 1.177–1.246 ms |
| Upload | 1778–2006 MiB/s | 134–150 MiB/s |
| Download | 1350–1492 MiB/s | 135–137 MiB/s |
| Duplex, aggregate | 1295–1325 MiB/s | 139–140 MiB/s |

H2 reuses its existing TLS connection; H3 still creates one per flow. These
numbers describe the current implementations on loopback, not intrinsic
protocol limits, Linux performance or an H3 advantage on real networks.

The comparison exposed H2 truncating an upload when the target sent its FIN
first. Client and server now keep the upload open after the response ends,
while still validating gRPC trailers. A deterministic regression waits for the
target FIN before uploading 512 KiB; both carriers also cover 4 MiB uploads,
downloads and simultaneous traffic in the normal CLI test run.

For H3, raising stream receive credit from 8 to 64 KiB and connection credit
from 64 to 128 KiB improved the controlled download/duplex measurements by
25–33%; upload improvement varied from 7–20%. The old-window control used the
same corrected H2 code and measurement method. Credit remains bounded; no new
configuration knobs, connection pool or automatic carrier choice were added.

Each final run also completed 30 seconds of eight-way traffic, with a 100 ms
pause between batches, eight interrupted flows and successful subsequent
transfers. Both runs had zero transfer errors: 4336 sustained H2 flows and
3584 sustained H3 flows in total. This is bounded local evidence, not a soak
test or proof of leak freedom. The initial unpaced test exhausted local TCP
ephemeral ports; the measurement now reuses its target listener and bounds
offered load without changing host settings or product admission limits.

CI runs the deterministic half-close and bounded concurrent/recovery cases
on both native platforms. The manual timing comparison is explicitly opt-in
and has no speed thresholds. All existing checks remain; H3 is still default-off
and field validation remains deferred.

## Longer Local Stability and Resource Observation

The 2026-10-28 release-mode run completed in 1316.76 seconds on one macOS arm64
host. H2 ran three 100-second reference phases; H3 ran three 300-second phases.
Each phase kept eight bidirectional flows active, sending a 64 KiB block per
direction every 100 ms, while four short flows per second exercised connection
turnover. Actual byte counts were checked in both directions. H2 transferred
2.93 GiB over long flows plus 1200 short flows; H3 transferred 8.79 GiB over long
flows plus 3600 short flows. Cancellation, target interruption, active-client
termination and restart recovery all passed without unexpected transfer errors.

Resource observations use cumulative process CPU time differences, RSS and
numeric file-descriptor counts. CPU percentages treat one fully used core as
100%; the client and server are measured separately. Restarted clients begin
new counters. The following ranges cover the three phases of each carrier.

| Observation, client / server | H2 | H3 |
|---|---|---|
| Average CPU during load | 3.6–3.8% / 3.4–3.6% | 22.0–23.1% / 52.1–61.0% |
| RSS after 15 seconds idle | 13.2–13.9 / 12.6–13.3 MiB | 16.8–17.5 / 16.7–17.1 MiB |
| File descriptors after idle | 11 / 11 | 11 / 11 |

Active flow counts returned to zero after each phase. H2 retains a
connection-level admission permit while its pooled TLS connection is alive;
that is expected rather than a leaked unauthenticated request. After the idle
interval both carriers returned to zero active connections and baseline file
descriptor counts. RSS grew modestly across phases; the observations do not
establish a memory leak or prove leak freedom. They are periodic samples, not
instantaneous peaks. The long run was isolated from local builds and profiling.

H3's CPU cost under this workload remains substantially higher than H2's.
A separate three-second stack sample showed UDP send/receive paths prominently
among non-wait locations. It identifies a follow-up profiling target; it does
not establish CPU attribution or a specific implementation defect. No transport
redesign or host-network tuning was introduced on that evidence.

The ordinary H3 server now reports its enabled local metrics listener address,
matching H2 and allowing the existing metrics to be observed with ephemeral
ports. A normal CLI regression keeps traffic alive beyond the configured idle
timeout, checks admission release and verifies recovery after terminating an
active H3 client. The long resource run is manual; CI has no RSS/CPU thresholds.
H3 remains default-off, and field validation remains deferred.

## Measured H3 Receive-Queue Improvement

The server driver now consumes already queued packets before processing H3 and
flushing QUIC output. One turn handles at most the existing 64-packet queue
capacity, including the first packet. It does not wait to fill a batch, increase
buffers or change authentication, TLS, flow-control limits or default settings.
This avoids flushing a separate acknowledgement after every queued packet.

On 2026-10-28, four release-mode runs used the same local workload without
concurrent local builds: three 10-second H2 reference phases and three 30-second
H3 phases per run. Each H3 run transferred 900 MiB over eight sustained
bidirectional flows plus 360 short flows, followed by the existing cancellation,
idle, active-client termination and restart checks. All four runs passed.
The following values are the means of the three H3 phases; 100% is one core.

| Run, in execution order | Client CPU | Server CPU |
|---|---:|---:|
| Original driver A | 25.4% | 64.3% |
| Queued receive B | 23.8% | 47.1% |
| Original driver A again | 22.9% | 55.2% |
| Final queued receive, without temporary counters | 21.3% | 35.4% |

The instrumented B run used 15–27% less server CPU than the two instrumented
controls. The final run confirmed the direction of improvement; host scheduling
and measurement variation prevent a fixed speedup claim. Client CPU varied
enough that this experiment does not establish an independent client-side gain.
H3 still uses substantially more CPU than H2 under this workload.

Temporary numeric end-of-connection counters in the first three runs showed
server packets for the 24 long flows falling from 782774/782991 in the controls
to 448812 (about 43% fewer). Client stream retransmission fell from
1535476/855749 bytes to 386463 bytes. Application byte counts stayed identical.
These counters and their output are absent from the final product. File
descriptors returned to 11 per process after idle; connection/flow gauges
returned to zero. The final run's post-idle RSS remained approximately 16–17 MiB
for the client and 17–18 MiB for the server. These are local observations, not
field-performance or leak-freedom claims. Existing lifecycle and transfer tests
cover the changed server path; no timing threshold was added to CI.

## Measured H3 Client Receive Improvement

The same bounded receive turn now includes datagrams already available on the
client's UDP socket before flushing QUIC output. It retains the 64-packet
per-turn bound and existing peer/packet-size checks, without waiting for more
packets or increasing queue/flow-control buffering. It adds no dependencies or
configuration. The server's existing queued-receive behavior remains in the
shared driver.

On 2026-10-28, four release-mode runs compared the original client path, the
change, the original path again, and the final change without counters on the
same local host. Each run used three 10-second H2 reference phases and three
30-second H3 phases, with the same eight sustained bidirectional flows and four
short flows per second. Each H3 run transferred 900 MiB plus 360 short flows.
All four runs passed transfer, cancellation, admission-release,
client-termination and restart checks. CPU values below are means of the three
H3 phases; 100% is one fully used core.

| Run, in execution order | Client CPU | Server CPU | Client packets for 24 long flows |
|---|---:|---:|---:|
| Original client path A | 19.61% | 32.25% | 768485 |
| Read available packets B | 17.71% | 31.22% | 550054 |
| Original client path A again | 19.31% | 32.87% | 768898 |
| Final receive change, without counters | 18.48% | 35.50% | Not sampled |

The observed client mean was 8–10% lower in B, with about 28% fewer client
packets for identical application byte counts. The final client mean also
remained below both original-path means, but individual CPU phase ranges
overlap. The final H2 client/server reference was 5.09%/4.79%, versus
3.99–4.29%/3.79–4.06% in the earlier runs. Host and measurement variation limit
these observations to a modest local mean decline, not a fixed or universal
CPU gain. They do not establish an independent server-side improvement. Only
A/B/A used the same temporary numeric counters at connection end; the final
run and product implementation have none. All four timed runs excluded
concurrent builds and profiling. After idle, both processes returned to 11 file
descriptors; H3 connection, flow and admission gauges returned to zero. These local results do
not establish wireless or field performance, or prove leak freedom. H3 remains
default-off; field validation remains deferred.

A separate final release-mode CLI comparison passed connection setup, 8 MiB
upload/download/duplex cases, 30-second eight-way concurrent runs for both
carriers and interrupted-flow recovery; it was not a controlled before/after
throughput comparison.

The lifecycle test now waits for target EOF immediately after stopping the
client, retaining the former total 15-second target-release allowance. It then
requires closed connections and released admission before restarting. This
removes the fixed 12-second sleep and lets normal CI cover process termination
and recovery for both H2 and H3. The per-phase idle observation and every
existing quality check remain; CPU/RSS thresholds are still absent from CI.

## Local Concurrency and Duration Coverage

The existing resource test now accepts `MAVERICK_SOAK_CONCURRENCY`, defaulting
to eight sustained bidirectional flows. The documented 32-flow recipe uses
three 600-second H3 phases and three 200-second H2 reference phases, with four
short flows per second, idle observations, cancellation and process recovery.
It takes about 42 minutes. A 32-flow fixture allows 64 connections so the short
flows have admission headroom; this changes only the test configuration.

Each phase records its concurrency, verified long-flow byte count and elapsed
transfer time through long-flow completion, before recovery checks. The ratio
is an achieved rate under the paced workload, not maximum throughput. CPU
comparisons use the first load sample through the drained sample for each
phase; RSS and descriptor observations remain samples rather than peaks.
Exact long-run measurements belong with the tested revision and workload in
the PR validation report.

The existing normal lifecycle test now uses 32 sustained flows for 12 seconds
per carrier. It retains H2/H3 transfer, interruption, admission-release and
process-restart checks without adding another test or CPU/RSS thresholds.
Production code and configuration defaults are unchanged. H3 remains
default-off, and field validation remains deferred.

## CI and Security Alert Maintenance

Linux CI installs a build/verification package only when a required command is
missing. Existing runner tools are retained. `scripts/check.sh` is the shared
local/CI entry for product, rustls, H3 and the retained quiche candidate checks;
Linux and macOS use the same H3/candidate scripts. The candidate script preserves
the prior platform-specific dependency graph selection and isolated patch
verification. Four negative dependency assertions now explicitly fail the
script instead of relying on Bash `errexit` after `!`. Native artifact, SBOM,
upgrade/rollback, security and both PR/main checks remain in CI.

[PR #75](https://github.com/ilhaformosa/maverick/pull/75) runs Linux and macOS in
parallel after scope classification. The required `public-pr-gate` now requires
both applicable platform jobs to succeed. All prior checks and both PR/main
runs remain. The official cache action stores compiler-keyed dependencies and
tools from successful main runs; first-party outputs are rebuilt.

The first successful cold-cache PR run took 17 minutes, compared with 42 minutes
26 seconds for PR #74. Both platforms and CodeQL passed. This is an observed
whole-run improvement, not a measured warm-cache speedup or an isolated causal
benchmark. Its first main run also passed in 23 minutes 11 seconds and saved
both platform caches (about 4.02 GiB total). Warm-cache reuse is measured by later
runs, not inferred from saving a cache. Independent development can continue
while CI runs; a failed main check takes priority over dependent integration.

On 2026-10-28 the owner approved dispositions for the 15 existing CodeQL alerts.
Each GitHub alert records its own source revision, code evidence and reason:
#27-33 are test-only nonce samples; #16-22 are non-secret/redacted output or
explicit operator preview false positives; #15 is intentional `gen-user` secret
delivery to its operator. That behavior is retained, and its output remains
sensitive. Scanner rules and tests are unchanged. This per-alert static review
is not a new exhaustive security audit or proof of zero future findings.

## Authorization and History

The owner approved CI parallelism/cache work with all quality checks retained,
per-alert dispositions, simplification of conflicting planning/configuration
requirements, and continued default-off H3 integration. Routine technical,
commit and PR decisions are delegated. Field trials remain deferred; network
settings, spending, provider resources and Stable publication are not authorized
by this development work. Applicable boundaries remain in `AGENTS.md` and
`SECURITY.md`.

Phase 3 recovery, giant experimental-branch convergence and the Quinn product
backend remain retired. Prior Beta.4 field observations and exact-revision
audits remain historical evidence and do not qualify newer source or releases.
