# Maverick Status

Date: 2026-10-31

This is the current product-state record. [ROADMAP.md](ROADMAP.md) gives the
next deliverables. Git, pull requests, Actions and release records retain
historical evidence; a result applies to its tested revision and workload.

## Current Product

| Area | Current state |
|---|---|
| Stage | Experimental Beta; not production-ready |
| Published release | Immutable `v1.2.0-rc.2`, prerelease/non-Latest, Direct H2 |
| Default source build and configuration | Browser-like TLS 1.3 + HTTP/2; H3 disabled |
| Explicit H3 | Ordinary client/server commands support direct TCP through SOCKS5 and HTTP CONNECT when the build feature and both configurations enable it |
| Configuration/authentication | Runnable config v1; existing authentication v1/v2 and frame formats retained; config v2 is policy-only |
| SDK | Client/server wrappers and profile tooling; local startup is distinguished from unverified remote connectivity; no dedicated H3 feature entry |
| Field validation | Deferred by the owner; no new real-network trial authorized |
| Stable | Not published; exact-RC field use and owner rollback remain incomplete |

The provider-fronted H2 and older WebSocket routes remain Beta compatibility
paths, outside the first Direct-H2 Stable claim. A TLS-terminating provider can
observe Maverick authentication and tunnel traffic; this is not native ECH or
provider-independent privacy. Prior provider-pilot browsing observations and
video/large-image usability problems are historical, not validation of current
source.

## Configuration Handoff

The CLI provides a consistent path from generating a configuration to checking
and using it, while preserving default H2 behavior:

- An explicit `gen-config --quiche-h3` option requires an H3-enabled build and
  selects H3 in both generated v1 files. Default generation remains H2.
- Generation checks whether either output already exists before writing the
  pair. Existing configurations and secret-file permissions remain protected.
- `version` describes compiled carrier support, separately from the default
  carrier and runtime configuration.
- Profile URI v1 export rejects connection, authentication or trust settings
  that its format cannot preserve, instead of silently changing their meaning.

The old-code custom-CA loss and partial-pair cases were reproduced before their
fixes. Local validation passed the complete shared product/rustls/H3/candidate
checks and dependency inventory. Six public-command handoff cases run in each
build variant; an additional ordinary-process H3 case uses the generated pair
for SOCKS/HTTP payloads, half-close and cleanup. PR/main quality gates remain
required. This does not add a configuration version, change transport defaults
or update the immutable public RC.2 artifacts.

## Default H2 Startup and Duplex Relay

H2 server startup loads and validates TLS material and the user/runtime state
before binding listeners or reporting readiness. The SDK start call returns
initialization errors directly; the CLI does not announce a listening server
or metrics endpoint when TLS initialization fails. This describes server
startup, not remote connectivity from a client.

The client H2 relay polls upload and download independently while retaining
one connection-pool lease and the existing framing, shaping and gRPC response
checks. The server keeps at most one pending target-write frame while its
response direction continues. A blocked H2 request window, paused local reader
or blocked target write no longer holds the opposite direction in the same
await. Existing flow/admission limits, rate-limiter policy and timeout values
are retained; this does not redesign rate-limit scheduling.

TCP FIN ends only its direction. Full CloseFlow/Error stops further upload
before response trailers are drained. Partial writes report activity while
individual send/write stalls still return their existing errors. No unbounded
queue, extra background relay task or new transport framework is introduced.

Old-code regressions reproduced delayed startup errors and all three blocking
paths. SDK/CLI cases cover missing/malformed certificates and mismatched keys,
initialization before bind, corrected startup and listener release. In-memory
H2/duplex tests use a paused clock to check directional progress, slow writes,
true stalls, FIN/trailers and full-close ordering without host-speed thresholds.
Shared product/rustls/H3/candidate checks and dependency inventory passed
locally. Native CI retains its platform coverage; bounded resource runs
complement these regressions and record shared-host context.

## SDK Readiness and CI Tool Reuse

Client startup binds every enabled local listener before spawning listener or
pool tasks. A DNS/HTTP bind failure releases the earlier sockets before returning,
so corrected startup can retry immediately. Deterministic current-thread tests
reproduced the old retained-port failure in the client and public SDK; coverage
includes DNS and HTTP conflicts, explicit H3, successful retry and shutdown.
No retry loop, background supervisor or new timeout is introduced.

The GUI-facing SDK wrapper reports `Listening` / `Unverified` after local
startup, rather than manufacturing `Connected` / `Ready` from a listener handle.
Local start errors remain `Error`; configuration/debug snapshots provide no
remote verification. `is_listening()` names the local lifecycle explicitly,
while deprecated `is_connected()` preserves its old local-only boolean for
compatibility. New/old enum token handling and migration are documented in
[CONFIG.md](CONFIG.md#sdk-diagnostics-and-local-lifecycle). No automatic remote
probe, connection-health observer or GUI product-readiness change is added.

Regression tests reproduce the former false state, exercise an unavailable and
a rejecting loopback peer, and verify local bind failure, cleanup, redaction,
legacy tokens and no unsolicited connection. These checks have no performance
threshold and do not require unrelated development tasks to stop.

The supply-chain workflow caches only its pinned audit/deny/CycloneDX binaries,
keyed by OS/architecture, compiler and installer content. It verifies tool
versions after restoration and installs only missing or mismatched tools.
Only successful main runs save the reusable cache; every advisory, dependency
policy and SBOM check still runs. Cold and warm hosted-run results belong to
the associated PR/Actions evidence, not a claim that all CI waits disappear.

For PR #90, the complete product workflow took 719 seconds; its main run took
671 seconds. Linux was the critical path, including 188/118 seconds restoring
the same approximately 4.98 GB compressed cache. The macOS job and CodeQL ran
in parallel and completed earlier. These observations identified cache contents
as a measurement target, not a fixed speedup promise.

The subsequent hosted baseline found 3.42 GB of restored project-output bytes
rewritten on Linux and 321 MB on macOS (logical sizes per path, not compressed
cache savings). The pinned cache action selects parent directories and tar
recursively archives them, so the old child-glob exclusions did not remove
those outputs. A small reproduction against the pinned action confirmed this.

Product cache v2 uses Cargo's workspace selection after every check and native
artifact upload has succeeded. It removes generated workspace artifacts from
the runner's root, isolated fixture and pilot build directories, retaining
dependency artifacts. The fixture's Maverick path dependencies are selected
through the root workspace. The Mac's shared development cache is untouched.
Only successful main jobs save; an exact cache hit skips preparation and save.
The unchanged path list allows v1 restoration during migration. Read-only
inventories distinguish rewritten from unchanged files; unchanged metadata does
not prove reuse. Warm-cache size, restore, rebuild and whole-workflow results
are recorded with [PR #92](https://github.com/ilhaformosa/maverick/pull/92).
All existing checks remain, and no fixed speedup is promised.

## Explicit H3 TCP

Build with `--features experimental-h3` and set `advanced.quiche_h3: true` on
both endpoints. Omission keeps H2; the retired `advanced.experimental_h3` flag
still rejects. Existing endpoint, certificate, credential and timeout fields
are reused. One QUIC connection and one H3 request carry one TCP flow; there is
no connection pool, automatic H3 selection or carrier fallback.

The H3 dialer tries resolved server addresses in order after a QUIC/TLS
connection error, instead of discarding every address after the first.
Resolution and all attempts share the original connection timeout. A silent
first address may still consume it; parallel dialing is not implemented.
TLS server-name/trust checks apply to each attempt, and the first established
connection must pass the existing certificate pin check before authentication.
The old first-address failure was reproduced on loopback; regressions cover
transfer through the next address, pin rejection before application data and
the original timeout releasing its socket without contacting a later address.

The optional `maverick-quiche` crate supplies the shared UDP/QUIC/H3 driver.
The ordinary client/server path verifies CA, hostname and optional certificate
pin, then applies existing exporter-bound authentication v1/v2, replay checks,
user/flow limits, egress policy and shaping. The server retains bounded packet
queues, global/per-source admission and the pre-auth permit through authentication.
Fronting/WebSocket, local DNS/TUN, rustls selection and SOCKS UDP associations
are rejected. H3 authentication failures close the session without H2 fallback
content. Profile URI v1 cannot represent H3; v1-to-v2 policy projection also
reports the unsupported choice.

Product H3 uses upstream quiche 0.30.0 and its official Boring integration,
with Boring 5.2.0, boring-sys 5.3.0 and tokio-boring 5.2.0 aligned across H2/H3.
No private quiche patch enters the product. This shared TLS update also affects
default H2, so its default/rustls compatibility checks remain required.

The retained private-patch decisions are narrow: actual pushed streams are
rejected; ignored push metadata cannot create proxy flows (P1); ordinary
priority controls and GOAWAY are handled for the sole request (P2); a
process-wide compile-time Debug log cap and disabled qlog limit the tested
H3/QPACK logging surface (P3). This is neither full push-ID conformance nor an
exhaustive logging audit. Old fork-qualification documents retain their
historical results, not a second current adoption decision.

## Local Evidence and Limits

The shared checks cover configured CLI processes, TLS/auth v1/v2, wrong
credential/CA/hostname/pin rejection before target access, sequential and
concurrent TCP flows, both half-close orders, duplex payload integrity,
admission cleanup and restart. Later cases cover selected packet loss/delay,
slow-reader isolation/resume/cancellation, partial-write idle progress and
configured shaping. These are bounded local scenarios, not field qualification.

| Evidence | Result and scope |
|---|---|
| [Configured carrier, #76](https://github.com/ilhaformosa/maverick/pull/76) | Ordinary client/server integration, shared TLS closure and default-off configuration |
| [Comparison and half-close, #77](https://github.com/ilhaformosa/maverick/pull/77) | H2 target-first FIN correction; H3 stream/connection credit of 64/128 KiB; local throughput observations |
| [Resource baseline, #78](https://github.com/ilhaformosa/maverick/pull/78), [receive work, #79](https://github.com/ilhaformosa/maverick/pull/79), [client work, #80](https://github.com/ilhaformosa/maverick/pull/80) | Sustained/churn traffic, cleanup and measured bounded receive batching; one receive turn handles at most 64 packets |
| [Concurrency, #81](https://github.com/ilhaformosa/maverick/pull/81), [CI calibration, #82](https://github.com/ilhaformosa/maverick/pull/82), [burst/send correction, #83](https://github.com/ilhaformosa/maverick/pull/83) | 32 sustained flows, four short flows/s, 30 minutes H3 plus 10 minutes H2 reference; observed ingress loss and shared-send cost corrected |
| [Reliability/context, #84](https://github.com/ilhaformosa/maverick/pull/84), [partial writes, #85](https://github.com/ilhaformosa/maverick/pull/85) | Cancellation after upload FIN and premature idle expiry reproduced and corrected without widening deadlines |
| [Self-check, #86](https://github.com/ilhaformosa/maverick/pull/86), [shaping, #87](https://github.com/ilhaformosa/maverick/pull/87) | Explicit H3 smoke; Auto/Stable shaping configuration and payload/cleanup coverage |

The shared UDP listener requests a 2 MiB receive buffer, preserves larger
existing values and permits OS caps; one asynchronous lock serializes its
flushes. It changes only the process-owned socket, not host network settings.
A permanently blocked kernel send can still delay other flushes. The manual
32-flow workload offers 40 MiB/s aggregate traffic; the normal 12-second CI
lifecycle case uses smaller blocks for 10 MiB/s. These are paced workloads,
not maximum-capacity measurements. H3 still costs more CPU than H2 in the
observed loopback workloads; no general H3 performance advantage is claimed.

Earlier A/B/A runs excluded this task's own builds/profiling but did not record
all background work. Their gains are observations, not fixed speedups. Current
manual runs record anonymous whole-host load and platform-specific memory
context without process names or command lines. Load averages are not CPU
percentages; available parallelism is not idle-core count. macOS pressure/swap
activity and Linux available-memory/swap occupancy have different meanings.
Resource samples are not peaks or proof of leak freedom. Context never skips
an assertion, changes a deadline or excuses a failure. Comparisons require
matched workloads and sufficiently comparable conditions; other projects need
not stop. Long runs are repeated only for relevant changes or unresolved results.

## Release and Quality Gates

[RC.2](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.0-rc.2) contains
dependency, certificate and configuration maintenance from
`966d29966d05287bc2eef6401c6297582db605f6`. Its six public files were verified
against reviewed Apple/Linux artifacts, with native upgrade/rollback to the
fixed Beta.4 partner. Later source changes are absent from those immutable files.

A changed release requires a new exact RC, its applicable compatibility,
independent security, supply-chain, native artifact/SBOM and rollback checks.
The first Stable claim remains Direct H2 and additionally requires the exact
candidate's authorized 72-hour owner trial and field rollback, followed by
Stable publication checks. Local H3 success cannot replace these gates. See the
[release contract](docs/V1_2_RC_STABLE_RELEASE_CONTRACT.md).

[CI parallelism/cache, #75](https://github.com/ilhaformosa/maverick/pull/75) and
the shared `scripts/check.sh` entry retain all product, rustls, H3, historical
candidate, security, native artifact/SBOM and upgrade/rollback checks on the
applicable platforms. Product CI installs only missing tools; the separate
supply-chain job now reuses its compatible pinned-tool binary cache. PR and main checks
remain. Linux runs the full workspace/rustls matrix; macOS runs H3/candidate
and native artifact/rollback gates, not the identical full matrix.
Independent development can continue while CI runs, with failed main checks
taking priority over dependent integration.

The 15 existing CodeQL alerts received owner-approved, individually recorded
dispositions on 2026-10-28: #27–33 are test-only nonce samples; #16–22 are
non-secret/redacted output or explicit operator previews; #15 is intentional
`gen-user` credential delivery to its operator. That behavior and the scanner
rules remain. This was per-alert review, not a new exhaustive security audit.

## Authorization and Deferred Scope

Routine technical, commit and PR decisions are delegated, including focused
configuration handoff and default-off H3 development. Field trials remain
deferred. Network-setting changes, spending, provider resources and Stable
publication are not authorized by this development work. [AGENTS.md](AGENTS.md)
and [SECURITY.md](SECURITY.md) retain their applicable boundaries.

Native Datagram/CONNECT-UDP, Auto H3, runnable Config v2/migration, auth v3,
TUN and additional providers need their own concrete requirement. Broad Chrome
qualification and weak-network/field evidence apply to their corresponding
claims, not every local TCP edit. Phase 3 recovery, giant branch convergence and
the Quinn product backend remain retired. Historical audits and Beta.4 field
observations do not qualify newer source or releases.
