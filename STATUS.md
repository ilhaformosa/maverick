# Maverick Status

Date: 2026-11-11

This is the current product-state record. [ROADMAP.md](ROADMAP.md) gives the
next deliverables. Git, pull requests, Actions and release records retain
historical evidence; a result applies to its tested revision and workload.

## Current Product

The latest owner decision requires full H2/H3 and TCP/UDP support for Stable,
not a Direct-H2-only claim. The full-transport goal was delivered as RC.3 at
`2aeaaf9` through PR #109, with all applicable local gates, PR 8/8 and main 6/6
checks and both native candidate packages. Independent review then corrected
two reproduced resource issues in RC.4 `d12c6a6` through PR #110. All applicable
local checks, PR 8/8 and merged main 6/6 passed, including both native candidate
archives, full SBOMs and Beta.4 upgrade/rollback. Field trials,
actual deployment and publication remain deferred. The table describes the current source implementation, not
Stable qualification. Focused implementation evidence is
recorded below. A distributable candidate must also have the complete gates
and exact artifact evidence for its SOURCE.txt revision; see the associated
Git/PR/Actions records, not results from a different commit.

| Area | Current state |
|---|---|
| Stage | Experimental Beta; not production-ready |
| Published release | Immutable `v1.2.0-rc.2`, prerelease/non-Latest, Direct H2 |
| Current candidate | RC.4 `d12c6a6`, independently reviewed fixes and complete applicable local/CI qualification; field qualification remains deferred |
| Build/configuration defaults | Full candidate packages include H2/H3; new direct generation uses dual/auto with `allow_reliable`; omitted existing settings retain their prior meaning |
| Protected H2 intermediary | Explicit origin-pinned inner TLS 1.3; local terminating-relay validation; not published |
| Explicit H3 | Direct TCP through SOCKS5/HTTP CONNECT and native UDP through SOCKS5 or the Rust fixed-target API |
| Dual/automatic transport | H2/H3 on one port; core-owned new TCP/UDP selection, shared temporary avoidance/retry and explicit UDP policy; active sessions never migrate |
| Configuration/authentication | Runnable config v1; existing authentication v1/v2; native H3 UDP adds an explicit control-frame extension; config v2 is policy-only |
| SDK | Listener-free TCP/UDP connector; persistent selected UDP sessions expose carrier, payload cap, independent send/receive and close; local listener state is not remote health |
| Field validation | Deferred by the owner; no new real-network trial authorized |
| Stable | Not published; exact-RC field use and owner rollback remain incomplete |

The historical provider-fronted H2 without inner TLS and older WebSocket routes
remain legacy compatibility paths, outside the supported protected-route claim. A TLS-terminating provider can
observe Maverick authentication and tunnel traffic; this is not native ECH or
provider-independent privacy. Prior provider-pilot browsing observations and
video/large-image usability problems are historical, not validation of current
source.

## Integration and Service Delivery

### SDK integration handoff

This source adds a runnable public-SDK consumer and integration guidance,
without changing runtime code, API, wire policy or dependencies. The example
uses ephemeral loopback servers and generated test trust; its TCP and persistent
UDP checks join the existing product/rustls/H3 gates. Fixed H2 (browser TLS and
rustls), fixed H3 and auto with both supported UDP policies pass focused local
execution. The associated PR/Actions records qualify the complete handoff;
those checks retain all prior security, native artifact/SBOM and rollback gates.
See the [runnable example and consumer guide](docs/INTEGRATION.md).
The qualified
RC.4 runtime remains `d12c6a6`; a later example/documentation commit does not
replace those archive bytes or retroactively change the independent review.

### Independent RC.3 review and RC.4 corrections

The [review record](docs/RC3_SECURITY_REVIEW.md) covers published RC.2 through
RC.3 `2aeaaf9`: independent model reviewers inspected all 69 changed source/tool
files plus 35 tests/fixtures/locks, with a separate architecture review; the
parent checked the remaining 20 documentation/deployment files and validated
the findings. Ordinary models were used when Daybreak was unavailable.

Two issues were reproduced on unchanged RC.3 runtime code: a Medium shared
connection-limit bypass during QUIC setup, and Low resource retention when a
pending reliable UDP close is canceled. No Critical or High finding was found
in this reviewed scope. This is not a paid human or exhaustive dependency audit.

Current code reserves shared H2/H3 connection capacity before QUIC allocation
and retains it through transport completion. Reliable UDP close retains task
ownership across its await so cancellation runs the existing abort cleanup.
Focused regressions pass for both arrival orders, global/source limits,
capacity recovery, UDP cancellation, timeout and successful forwarding. The
replacement patch review and full local/CI artifact/SBOM/rollback evidence are
kept separately from the immutable original scan; only results for the exact
replacement source/bytes qualify RC.4. See [candidate notes](docs/releases/v1.2.0-rc.4.md).

No UDP policy, authentication, configuration or wire semantics changed. The
original RC.3 packages and review records remain preserved; field use and
publication remain deferred.

Exact RC.4 qualification: [PR #110](https://github.com/ilhaformosa/maverick/pull/110),
[merged-main product/native checks](https://github.com/ilhaformosa/maverick/actions/runs/42834991677),
and [Rust/Actions CodeQL](https://github.com/ilhaformosa/maverick/actions/runs/42834991406).
The replacement review at `4db613a` and merged `d12c6a6` have the same source
tree. Existing CodeQL alert #36 is intentional public-certificate fingerprint
output, reviewed as not secret logging; its state/rule was not suppressed.

### RC.3 implementation and qualification boundaries

Scope: general H2 UDP sessions; core/SDK selection for new TCP/UDP sessions;
explicit native-required or reliable-compatible UDP policy; full-featured
candidate packages and new direct dual/auto configuration defaults. Omitted
policy retains existing behavior. New protected relay configs require inner
origin TLS and use H2 only. TLS-terminating H3 fronting is not supported.

The protocol owns wire/security/compatibility rules; the official client core
and SDK own selection, reachability avoidance/retry and sessions; the server
owns dual entry and target sockets. Integrators supply user policy and UI, not
a replacement selector. Performance ranking is frozen. Active session migration
is excluded permanently. See ROADMAP.md and the UDP/selection contract.

Baseline `3b1db6a` passed local checks, final PR 8/8 and main 6/6, including native
artifact/SBOM/rollback checks. Those H2-only archives do not qualify RC.3.
The new implementation uses authenticated capability bit 62 and fixed-target
H2 UDP (OpenUdp/UdpPacket flags 2), with one connected target socket per session.
Legacy flags 0 and configuration omission retain request/response behavior.

Focused local tests pass for continuous/multiple UDP messages, stable source
ports, empty/maximum packets, native and reliable carriers, protected H2,
SOCKS multi-target/control cleanup, idle cleanup, shared TCP/UDP avoidance and
actual 30-second retry, security rejection without H2 contact, and authenticated
capability absence versus malformed protocol. A terminating relay test covers
UDP confidentiality with auth v1/v2. These are local observations, not field
qualification or universal application interoperability. The complete shared
local/CI and exact RC.3 artifact/SBOM/rollback results are required for candidate
delivery and retained with its revision-specific evidence. Field qualification
and public release remain outstanding regardless of those results.

A maximum-packet test reproduced macOS's default UDP socket send-buffer limit.
Only the new owned session/SOCKS socket buffers were bounded to 131072 bytes;
no host network setting changed. `socket2` reuses the already locked version.

The owner prioritized integration and deployability on 2026-11-10. The public
SDK now offers `ProxyConnector`, which reuses the existing H2 pool and H3/auto
selector without binding local proxy listeners. `connect_tcp` completes target
admission before returning a session that relays caller-owned async I/O.
Shared flow admission, cancellation, both half-close directions and pool reuse
remain enforced. `open_udp` offers persistent native or reliable sessions under
explicit policy; legacy H2 exchange APIs remain available with omitted policy.
Closing the connector stops new opens; returned/in-progress sessions remain
caller-owned, with cancellation controlled by their owners.

The SDK's default-off `experimental-h3` feature enables client/server H3;
builders accept complete auth/advanced settings and custom trust roots.
Stored profiles now preserve required inner exporter binding for protected
fronting, fixing a metadata check that incorrectly treated it as unsupported.
SDK loopback coverage exercises actual forwarding after profile restoration.

The CLI server handles SIGTERM/SIGINT through the existing server-handle stop
path for H2, H3 and dual listeners. The prepared Linux systemd unit and runbook
cover private files, source/build identity, low-port binding, startup, stop and
matched binary/config rollback. They do not install a host or change its
network settings. Native Linux CI validates unit syntax; CLI loopback tests
verify process exit, peer closure and restart. Field deployment remains deferred.
See [integration](docs/INTEGRATION.md) and [deployment](docs/DEPLOYMENT.md).

## Origin-pinned H2 Intermediary Protection

The protected source path carries existing Maverick H2 sessions inside a
separate TLS 1.3 connection through an outer H2 POST. Clients verify independent
origin CA/hostname trust and a mandatory leaf certificate pin before sending
Maverick authentication or proxy requests. Authentication uses the inner TLS
exporter. The server requires the protected envelope when configured, and a
protected client never retries as an unprotected session. Direct defaults and
published RC.2 are unchanged. H3 stays direct; new generated direct pairs use
auto/dual, while protected intermediary pairs remain H2.

Seven local integration cases cover auth v1/v2, both half-close
orders, concurrent transfers, encrypted-body observations, wrong inner identity,
handshake/record tampering, replay, pool reuse, shutdown cleanup and protection
mismatch. The default product suite, rustls suite, H3 checks, retained candidate
checks and dependency inventory passed locally; PR/main gates remain required.
No new registry dependency version was introduced. This is not an independent
release security review, a real-CDN qualification or a native Datagram claim.

Low-level public carrier APIs also reject incompatible protection before
opening a socket or emitting authentication; callers cannot bypass this by
constructing a config directly instead of using ordinary startup. A regression
reproduced ignored protection through the legacy WebSocket tunnel API. Explicit
H3 frame-channel and server constructors reject the H2-only envelope as well.

The intermediary still sees outer metadata, origin ClientHello/SNI, timing and
volume and can deny service. Historical unprotected trusted-provider routes
remain separate compatibility modes. See [configuration](CONFIG.md#origin-pinned-end-to-end-h2)
and [protocol boundaries](docs/END_TO_END_PROTECTION.md).

## Configuration Handoff

The CLI provides a consistent path from generating a configuration to checking
and using it, while preserving omitted settings in existing files:

- An explicit `gen-config --quiche-h3` option requires an H3-enabled build and
  selects H3 in both generated v1 files. Bare generation in full builds now
  selects dual/auto; `--h2` explicitly selects H2.
- Generation checks whether either output already exists before writing the
  pair. Existing configurations and secret-file permissions remain protected.
- `version` describes compiled carrier support, separately from the default
  carrier and runtime configuration.
- Server `advanced.max_frame_size` is checked against the existing client
  range, 65536 through 1048576 bytes. Unsupported values fail configuration
  checking and startup instead of advertising a limit the client will reject.
- Profile URI v1 export rejects connection, authentication or trust settings
  that its format cannot preserve, instead of silently changing their meaning.

The old-code custom-CA loss and partial-pair cases were reproduced before their
fixes. Local validation passed the complete shared product/rustls/H3/candidate
checks and dependency inventory. Public-command handoff cases run in each
build variant; an additional ordinary-process H3 case uses the generated pair
for SOCKS/HTTP payloads, half-close and cleanup. PR/main quality gates remain
required. This does not add a configuration version, change transport defaults
or update the immutable public RC.2 artifacts.

## Native UDP and New-Connection Selection

`gen-config --relay --origin-name NAME --origin-cert CERT` now requires
owner-supplied origin identity and generates protected H2 on both sides. An
optional `--origin-ca` supplies private roots. Bare generation now selects direct dual/auto with `udp_policy: allow_reliable`.
`--auto-h3` remains an explicit alias. In existing files, omitted carrier and
policy fields retain their earlier behavior.

The dual server binds TCP and UDP on the same port before announcing readiness,
with shared replay, authentication, connection and user-flow budgets. A failed
second bind releases the first. Normal shutdown stops both carriers.

For new TCP flows, automatic selection gives H3 at most one second (or half the
configured connection budget). Only a typed network failure before a peer
response permits H2; a 30-second negative cache avoids repeated blocked-UDP
probes. The next connection after expiry tries H3 again. Every TLS, pin,
authentication or protocol failure is terminal. Existing flows stay on their
original carrier. `native_required` never falls back; `allow_reliable` may select
H2 for a new UDP session on eligible network failure or authenticated capability
absence before data. Target silence, security/protocol/target errors and
post-send failures never cause replay or a carrier change.

Local product regressions cover independent UDP replies, multiple targets,
empty/maximum/oversized payloads, packet loss/reordering, egress/auth rejection,
single-slot admission, idle/control cancellation and TCP reuse. Selection tests
exercise shared dual limits, atomic bind/restart, H3 preference, cached H2
selection with an existing H3 flow still active, H3 recovery after cache expiry,
and no H2 contact after identity,
authentication or protocol failures. Existing shared checks remain required.
See [the wire and selection contract](docs/NATIVE_UDP_AND_SELECTION.md).

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

## Explicit H3 TCP and Native UDP

Build with `--features experimental-h3` and set `advanced.quiche_h3: true` on
both endpoints. Omission keeps H2; the retired `advanced.experimental_h3` flag
still rejects. Existing endpoint, certificate, credential and timeout fields
are reused. One QUIC connection and one H3 request carry one TCP flow or one
fixed-target native UDP association; there is no H3 connection pool.
`auto_h3` (client) and `dual_h2_h3` (server) stay false when omitted from an old
configuration; new direct generation explicitly enables them.

The H3 dialer tries resolved server addresses in order after a network
failure before any peer response, instead of discarding every address after the first.
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
Fronting/WebSocket, local DNS/TUN and rustls selection are rejected. SOCKS UDP
uses authenticated fixed-target HTTP Datagrams over QUIC, independently in both
directions. Payloads are capped at 1200 bytes and the negotiated path limit;
full queues/oversized packets drop, with no application retransmission.
H3 authentication failures close the session without H2 fallback
content. Profile URI v1 cannot represent H3; v1-to-v2 policy projection also
reports the unsupported choice.

Requests whose HTTP method or tunnel path does not match the H3 endpoint are
actively closed before application processing. On receiving this rejection,
the client terminates its authentication wait instead of leaving it to expire.
The existing rejection, admission and target-access rules remain unchanged.

If the H3 transport disappears while the server is resolving or connecting to
a target, the session stops waiting and releases its connection and user-flow
permits. A request-side TCP FIN does not cancel target setup or its response.
An operating-system DNS lookup already submitted may still finish independently;
the cancelled session no longer continues from that result to TCP connection.
Established relays also observe transport loss while waiting for target data,
including after upload FIN or while an upload is blocked on a target write.
They release the target and user-flow slot without waiting for idle expiry.
Target-first FIN continues to permit upload until the client finishes it.
After the response ends, the client also releases its local connection when
the transport closes while it waits for more upload. A normal upload FIN
continues to permit the remaining response.

Explicit server-handle shutdown cancels unfinished setup and notifies active
H3 peers through the existing QUIC close path before joining their drivers.
It ends active TCP transfers and releases local listeners for restart. Close
delivery remains best effort; forced process termination or datagram loss can
still leave peers waiting for failure or idle detection.

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
Stable requires H2/H3, TCP/UDP, both UDP policies and supported protected H2
routes. Its exact candidate additionally requires authorized field use,
72-hour observation and rollback across that scope, followed by publication
checks. Local success cannot replace these gates. See the
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

The latest owner decision authorizes a persistent goal for complete TCP/UDP,
new-connection/session H2/H3 selection, reachability avoidance/retry, and explicit
native-required/reliable-compatible UDP policy. It includes the core/SDK,
protocol/config/integration/release documentation, full candidate packages and
all applicable local/CI gates. Routine technical, commit and PR actions remain
authorized. Candidate completion does not publish Stable.

New direct configurations default to dual/auto; fixed H2/H3 remain available.
Omitted existing settings retain their meaning. Protected relay generation
requires inner origin TLS and stays on H2. TLS-terminating H3 relays, new crypto
architectures, external client/Atlas development, endpoint/IP-block recovery
and new infrastructure are excluded. Field use, deployment and public release
remain deferred. Mac network and Surge settings are never changed.

Performance-based selection is frozen until explicitly unfrozen, including
background scoring/testing and preparatory frameworks. Existing necessary
checks remain. Active-session migration and seamless cross-carrier continuation
are permanently excluded, with no future reserved design. Standard CONNECT-UDP,
runnable Config v2/migration, auth v3, TUN and additional providers are not
prerequisites. Historical Beta/audit/field results do not qualify RC.3.
