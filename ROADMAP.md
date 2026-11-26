# Maverick Roadmap

Date: 2026-11-27

[STATUS.md](STATUS.md) records current capabilities and evidence. This file
contains the execution order, not a second history of completed pull requests.

## Development after 1.2.3

Start from the published `69a3cc8`. The 1.2.3 archive can already compare two
private configurations at a chosen time. The next operator tasks are to
preview an import accurately and to carry a staged credential change through
a running client and server. The package jobs currently stop at 1.2.2.

| Priority | Deliverable | Offline or loopback acceptance |
|---|---|---|
| 1 | Make profile URI import previews usable before creating a private YAML file. In 1.2.3 the default secret-free export passes a dry run with an output path, although the write fails. Clipboard preview also consumes its input. | Preview without an output may inspect a secret-free profile. With an output, preview and import reject missing credentials, occupied destinations (including dangling links) and missing parent directories. A valid preview creates nothing, preserves clipboard input and omits the secret. An actual import creates a private runnable YAML and clears an explicitly used clipboard after success. |
| 2 | Document and rehearse a complete routine credential rollover using the packaged CLI. | On fixed H2, compare the offline verdict with fresh connections using the original credential, both clients during overlap, and each client after retirement. Positive cases must verify bidirectional TCP and independent UDP replies. Verify that a rejected old credential cannot reach the test target, then restore the original private YAML byte for byte and recheck transfer. Use loopback, fresh credentials and staged windows without changing the clock. |
| 3 | Include the installed 1.2.3 release in regular native upgrade and recovery checks. Share one pinned list between both CI jobs. | On Apple Silicon macOS and native Linux x86_64, check archive digests and source revisions for all four published Stable baselines. Run six routes and five phases per baseline, the packaged configuration suite once per candidate, the rollover drill and the separate Beta.4 rollback. Preserve the two-archive offline entry point. |

Provider behavior, public-network performance and the 72-hour field soak
still require a separately authorized environment. A new release decision
depends on the impact on installed clients and servers and the results above.

## 1.2.3 native package qualification

1.2.3 delivers the offline configuration and rotation work from `fbb6db1`.
The [first candidate run](https://github.com/ilhaformosa/maverick/actions/runs/45881026669)
tested the actual installation archives at `3985c4f`. Each native runner
extracted its CLI and used it for the configuration tests. For each Stable
baseline, all six TCP/UDP routes were exercised with the original programs,
each mixed client/server combination, both upgraded and both restored.

| Native runner | Archived CLI configuration tests | With published 1.2.2 | Across 1.2.0, 1.2.1 and 1.2.2 |
|---|---|---|---|
| [Apple Silicon macOS](https://github.com/ilhaformosa/maverick/actions/runs/45881026669/job/140120144192) | 21/21 | 30/30 | 90/90 |
| [Linux x86_64](https://github.com/ilhaformosa/maverick/actions/runs/45881026669/job/140120143846) | 21/21 | 30/30 | 90/90 |

Both jobs checked saved program and YAML contents on restoration, followed
by bidirectional TCP data and EOF and four independent UDP replies on each
route. The separate Beta.4 direct-H2 rollback passed on both platforms.
The release workflow takes its six files from the successful run for the
tagged main revision. [Release notes](docs/releases/v1.2.3.md).

## Offline rotation and current-release qualification

At `fe7dfce`, the previous three items were complete. Checking a replacement
origin certificate still required a handshake, and a credential change could
only be checked at the current time. The package matrix covered upgrades from
1.2.0 and 1.2.1. This phase adds tests for all three gaps.

| Priority | Deliverable | Offline or loopback acceptance |
|---|---|---|
| 1 ([verified](STATUS.md#development-rotation-and-upgrade-checks)) | Before restarting a protected H2 origin, check its staged public certificate chain with the client's inner trust settings. | Verify the configured CA, hostname, validity period and leaf pin using the live inner TLS verifier. Accept the original, renewed and restored matching pairs. Reject a stale pin, a wrong CA or name, an expired leaf and an unusable chain. Keep outer trust separate, read no server private key and omit private values from diagnostics. Cross-check the result against a protected H2 TCP/UDP loopback rotation. |
| 2 ([verified](CONFIG.md#compare-a-client-and-server-configuration-offline)) | Let an operator check a staged client/server credential rotation at a specified time. | With two unchanged YAML files and no clock change, check immediately before and at the client switch, during the server overlap and at its exclusive end. Show the selected credential slot without its ID or secret. Reject a missing or disabled credential and an invalid timestamp. Preserve the existing check when no time is supplied. |
| 3 ([native PR checks](https://github.com/ilhaformosa/maverick/pull/140/checks)) | Qualify upgrades from the published 1.2.2 archives on native macOS and Linux x86_64. | Pin each public archive digest and its source revision. On each platform run the existing six-route, five-phase TCP/UDP matrix with 1.2.2, including both mixed directions, two-sided upgrade and byte-checked restoration. Keep the 1.2.0, 1.2.1 and separate Beta.4 gates. Identify same-version development builds by source revision. |

Public-network reliability, provider interoperability and the 72-hour field
soak need an authorized environment. Transport tuning remains deferred until
an observed workload gives it a measurable goal.

## Development after 1.2.2

The plan starts from the 1.2.1 route and rollback results. The baseline for that phase was
[1.2.2](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.2),
which delivers the dependency fix with the same CLI and transport behavior. The following items address failures an operator can identify or
recover from without access to a field environment. Keep the dependency
inventory green as maintenance work throughout.

| Priority | Deliverable and reason | Offline or loopback acceptance |
|---|---|---|
| 1 ([implemented in development](STATUS.md#development-server-tls-file-check)) | Add an opt-in server TLS file check to `check-config`. In 1.2.2 a valid YAML file can pass even when renewal left the service with an unusable certificate or key. | From the service working directory, load the configured certificate chain and private key through each selected TLS backend. Accept matching pairs for H2, protected H2, fixed H3 and dual mode in a capable build. Reject missing, malformed or mismatched files and H3 in an H2-only build, with private-safe output. Run the check with the service port occupied. Existing plain checks still accept a valid configuration before certificates exist. |
| 2 ([verified in development](STATUS.md#offline-client-and-server-configuration-comparison)) | Compare both private configuration files before handoff using `check-pair`. Separate TCP and UDP carrier results identify a partial match. | Start with the generated 1.2.1 direct and protected pairs. Report the shared carriers and whether the selected credential ID and secret match an enabled server credential. Change one field at a time to cover a disabled user, a wrong secret, a carrier mismatch and a protected client with protection disabled at the origin. Keep both files byte-identical and omit credentials and endpoints from every report. Confirm one matching pair by transferring TCP and UDP over loopback. |
| 3 ([verified by offline replay](docs/STABLE_RELEASE_TOOLING.md#validation-without-publication)) | Tolerate the GitHub success-index delay seen during 1.2.1 publication by checking completion and success on the run itself. | Replay saved-shape API responses locally, including a completed first-attempt run absent from the success-filtered listing. Require one successful push run on main for the exact commit and workflow, with both expected artifacts. Reject pending, failed, duplicate, wrong-commit and expired-artifact cases. Use the existing publication stand-in to verify that rejected cases cannot publish. |

Real-provider behavior, application performance across public networks and the
72-hour field soak still require an authorized environment. The local short-flow
study does not establish a production need for H3 pooling or carrier ranking.

## 1.2.2 dependency patch

[1.2.2](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.2) at
`04049de` distributes the `url` repair from [PR #135](https://github.com/ilhaformosa/maverick/pull/135).
The release candidate passed 60/60 loopback cases on each native platform,
30 with published 1.2.1 and 30 with 1.2.0. Each baseline exercises six routes,
both mixed client/server directions, upgrade and restoration of the saved
programs and private configurations. The distinct Beta.4 direct-H2 drill
is also retained. [macOS candidate](https://github.com/ilhaformosa/maverick/actions/runs/45306317238/job/138150963596)
and [Linux candidate](https://github.com/ilhaformosa/maverick/actions/runs/45306317238/job/138150963591).

The [tagged main run](https://github.com/ilhaformosa/maverick/actions/runs/45308849245)
qualifies the final archives. Each platform has a checksum and a full
CycloneDX runtime inventory with `url` 2.5.9 and `form_urlencoded` 1.2.3.
Field acceptance remains deferred for this dependency patch.

## 1.2.1 package qualification

The [1.2.1 release](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.1)
comes from `e9c3673`, based on `810e39f`. These are the final installation
archives tested against [published 1.2.0](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.0).
Both native jobs performed upgrades and rollbacks with staged executables.

| Native platform | Final 1.2.1 archive SHA-256 | Loopback result |
|---|---|---|
| [Apple Silicon macOS](https://github.com/ilhaformosa/maverick/actions/runs/44840213099/job/136646479126) | `fa4b06f000402a6b2707de05bb9bb68e828a230e31c4bfb2176c9829fba60238` | 30/30 passed |
| [Linux x86_64](https://github.com/ilhaformosa/maverick/actions/runs/44840213099/job/136646479131) | `683383108b2281989222ca7265c1f3d5446cef243e64c76d72aa1f0625ca1b84` | 30/30 passed |

The six routes were fixed H2, fixed H3, automatic with reliable UDP
allowed, automatic with native UDP required, automatic with an H2-only
origin, and origin-protected H2 through a TLS-terminating intermediary.
Every route passed with the original pair, each mixed-version direction,
both upgraded roles, and both restored roles. After copying back the
original executables and private YAML, the test checked the installed
files, restarted on the same origin port, verified TCP contents and EOF
in both directions, and received four independent UDP replies over one
association. Both platforms also passed the separate Beta.4 direct-H2 drill.

A local repeat with the downloaded `3ba824f` macOS archive encountered one
code-signature termination after the drill overwrote a previously executed
file. Both original archive binaries passed static code-signature verification.
Subsequent in-place attempts did not reproduce the failure. The drill now
stages a fresh executable in the installation directory and renames it into
place on upgrade and rollback. It checks that the file identity changes.
Three complete macOS runs with those same archive binaries passed all 90
cases using this procedure. The bundled guide includes the manual steps.

The release workflow selects the [tagged revision’s qualification run](https://github.com/ilhaformosa/maverick/actions/runs/44840213099).
The [publication workflow](https://github.com/ilhaformosa/maverick/actions/runs/44843087555)
stopped before upload on its first attempt because the Actions success filter
temporarily omitted that completed run. The same tag was retried when the
query returned the unique run. Both native packages came from its first attempt.
Each platform has an archive, its checksum and a CycloneDX software bill of
materials. The two archive digests above identify the tested download for
each platform. Field interoperability and the 72-hour soak remain deferred.

## Delivered after 1.2.0

Plan for a prolonged period without real-network testing. Use the published
[1.2.0 packages](https://github.com/ilhaformosa/maverick/releases/tag/v1.2.0)
as the comparison point. Each development step needs a user-visible outcome
that can be checked with offline files, controlled loopback processes or the
existing CI. Keep evidence tied to its build, configuration and workload.

| Order | Deliverable | Acceptance |
|---|---|---|
| 1 (in source) | Explain a configuration offline with `check-config --explain`. Align the examples and bug report form with the supported routes. | Old v1 files retain their route and omitted UDP policy. Newly generated client/server pairs describe fixed, automatic/dual and protected configurations correctly. Report the binary's compiled transports and keep private values out of the explanation. |
| 2 (development build verified on both platforms) | Published 1.2.0 and development revision `599d02a` passed both mixed-version directions, two-sided upgrade and restoration on Apple Silicon macOS and native Linux x86_64. | All six routes transferred TCP and UDP after restoration on each platform. See the [results](STATUS.md#local-120-interoperability-and-rollback) and [Linux Actions run](https://github.com/ilhaformosa/maverick/actions/runs/44796735752/job/136498106065). The [1.2.1 package qualification](#121-package-qualification) extends release classification, the installation guide and H2/H3 archive verification to the selected patch. Retain the Beta.4 direct-H2 drill. |
| 3 ([CLI diagnostics on main](https://github.com/ilhaformosa/maverick/pull/129)) | Inspect an actual SOCKS UDP session with [`client --diagnose-udp`](CONFIG.md#observe-socks-udp-sessions). | The client reports the configured choices, admitted carrier and first observed target reply. Controlled loopback applications separately verify receipt. The regression covers reliable fallback, native-only failure, wrong identity and target silence. |
| 4 (loopback verified) | [Rotate and restore a protected H2 origin certificate](docs/DEPLOYMENT.md#rotate-the-origin-certificate-for-a-protected-h2-intermediary) using the existing pin and restart commands. | The real CLI passed the original, replacement and restored pairs for TCP and reliable UDP. Both mismatched pins were rejected before target access. A persistent regression checks the inner pin failure. The tested coordinated restart needs no new rotation mechanism. [Verification record](STATUS.md#protected-h2-origin-certificate-rotation-and-rollback). |

All four development items above have loopback or offline evidence. The
[matched short-request comparison](STATUS.md#direct-h2-and-h3-on-short-tcp-requests)
is also complete. Pooled H2 used one underlying connection for 128 fresh TCP
flows. Direct H3 used 128. When the application reused a single TCP flow,
both carriers served all 128 exchanges through one connection. A future
H3 pooling proposal would need a workload that requires independent short
flows and a compatibility design for peers that accept only stream 0. The
current results support keeping the existing transport choices.

Reproducible transfer, cancellation, resource-release or upgrade defects take
priority when observed. The 1.2.1 package results are recorded above. Provider buffering, public-network application behavior
and the 72-hour field soak require an authorized environment. A future release
decision needs evidence for its own candidate. The owner deferred field testing separately
for 1.2.0 and 1.2.1.

The [field plan](#proposed-field-acceptance--discussion-only) is available if
an owner-controlled environment is separately authorized. The sections below
record earlier deliveries and decisions. The development-after-1.2.2 section sets the active order.

## Delivered — Bounded Local Handshake Research

The owner-authorized empirical feedback, outer TLS fragmentation and observation
followed by a selected QUIC layout candidate are implemented in the existing
test package. Default product behavior remains unchanged; complete local gates
pass, using only loopback/ephemeral ports and full identity/authentication/transfer
checks. The existing product, rustls and H3 gates include the new tests. No online
search system or private transport fork is introduced. Outcomes and limits live in
[STATUS.md](STATUS.md) and [the experiment report](docs/HANDSHAKE_EXPERIMENTS.md).

This bounded research precedes any decision about production integration.
Field work remains deferred; it adds no Stable prerequisite and does not unfreeze
unrelated protocol/SDK development, performance ranking or active-session
migration. The existing release/field-acceptance sequence below is preserved.

## Delivered — Comprehensive Review and Maintenance

The 2026-11-16 review is complete through PR #115. Qualified RC.6 `9adc014`
retains the Rust 1.100.0 migration and frozen protocol/SDK scope. Compatible
active dependencies/tools are updated; explicit libc and YAML compatibility
holds and immutable historical samples are documented in [STATUS.md](STATUS.md).

Three independent ordinary-model reviews, concrete reproductions, focused
repairs and independent patch follow-ups are complete. All applicable local and
CI checks, both native candidate packages, full SBOMs, historical RC.5 SBOM
compatibility, fixed Beta.4 rollback and private Stable-format rehearsals passed.
Passing fuzz evidence is reused only for demonstrably unchanged inputs. Preserve
original failures, provisional packages and qualified replacement evidence.

The next decision is the field-acceptance proposal below, still deferred. Do not
add protocol/SDK features, performance ranking, active-session migration, Atlas
work or endpoint/IP-block recovery. The owner subsequently authorized the
RC.6 checkpoint tag/prerelease, published from the unchanged qualified bytes.
The separately approved two-path build-cache cleanup is complete; source,
Git history and all delivery/validation evidence remain preserved. Provisioning,
deployment and Stable publication remain deferred.

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

## Delivered — RC.4 Independent Review Corrections

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

RC.4 `d12c6a6` passed all applicable local gates, PR #110's 8 checks and the
merged main's 6 checks. Both native candidate archives, SBOMs and Beta.4
upgrade/rollback passed. The exact source and artifacts remain preserved;
the independent review and two corrections are complete, not a pending queue.

## SDK Integration Handoff

This bounded delivery makes the completed core easier to integrate:

1. A runnable public-SDK example owns its application I/O, performs
   TCP half-close and persistent UDP with independent replies, reports the
   selected carrier/packet cap, and closes its sessions. It uses generated test
   trust, loopback and ephemeral ports only; keep setup separate from real
   consumer configuration.
2. The integration guide documents Cargo dependency/feature setup, ownership
   and error handling, links the full example, and distinguishes this source
   companion from the qualified RC.4 archives. No runtime/API/dependency changes.
3. The example executes in the existing product/rustls/H3 gates, including fixed
   H2, fixed H3 and auto with both supported UDP policies. Keep all current CI,
   security, artifact/SBOM and rollback checks; record exact revisions/results.

Acceptance is real SDK forwarding and clean completion in each supported
example mode, applicable local/CI success and a preserved integration handoff.
Failure/recovery, security rejection and protected-route coverage remain in
the existing regression suites; the example is not another selection engine
or a substitute for those tests. Field work and Stable publication remain deferred.

Performance-based selection is frozen until explicitly unfrozen: no scoring,
continuous speed tests, background ranking or preparatory framework. Keep
existing necessary checks. Active-session migration and seamless cross-carrier
resumption are permanently out of scope, with no reserved future design.

External client development, endpoint/IP-block recovery, node distribution and relay infrastructure
management are outside scope. Field trials remain deferred. Ordinary resolved
address attempts and connection cleanup remain product work. Do not restore
archived prerequisite chains or add a new crypto framework.

## Continuing Execution Discipline

Protocol/SDK functionality remains frozen. PR #112 completed the authorized
[Stable release tooling](docs/STABLE_RELEASE_TOOLING.md), independent review,
all applicable local checks, PR 8/8 and exact-main 6/6. RC.5 `e4a21e2` includes
only the required rustix 1.1.6 dependency correction beyond the existing
runtime scope; both native packages/SBOMs, Beta.4 rollback and Stable-format
rehearsals passed. The standalone H3 fixture version correction is included.
Do not repeat this tooling work or introduce new protocol/SDK features.

The owner separately authorized an RC.5 checkpoint tag and prerelease on
2026-11-11, plus explicitly allowlisted local cache/duplicate-output cleanup.
The checkpoint preserves the reviewed source and exact qualification bytes;
its current publication state is in STATUS.md. Field deployment and Stable
publication are still deferred. Documentation after this source commit does
not relabel or rebuild the frozen RC.5 checkpoint.

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

## Proposed Field Acceptance — Discussion Only

This is the field plan proposed before the one-release waiver. A future trial
requires a fresh choice of candidate and environment. The original candidate was the
published RC.6 checkpoint at `9adc014`, replacing the earlier RC.5 field
proposal. Obtain its exact CI-qualified Release assets and independently verify
them. No infrastructure or client application work is silently included.
Private environment identifiers and credentials stay outside the repository.
Do not change the development Mac's network or Surge settings.

1. **Agree the environment and limits.** Name an owner-controlled, fresh Linux
   x86_64 test origin, an Apple Silicon client/test device, an owner-controlled
   intermediary test route, duration, traffic/cost cap, operator and stop/cleanup
   decision. Follow the existing host preparation policy only after explicit
   authorization; no provider, region, host purchase or network change is assumed.
   A missing intermediary environment leaves that matrix cell unqualified.
2. **Freeze and install the exact files.** Obtain both qualified RC.6
   sets, independently verify digests/source identity, prepare private
   credentials, valid certificates/origin pins and matched rollback backups,
   and check actual
   service start/stop/restart on the named host. Use explicit test-client
   endpoints or a separately approved test device, not a Mac system-proxy change.
3. **Exercise each route with the RC.6 clients.** On the separate Apple Silicon
   test Mac, run the packaged CLI with `maverick client -c client.generated.yaml`.
   Point a dedicated browser profile at its local SOCKS5 listener for browsing,
   video and downloads. Use a SOCKS5 UDP ASSOCIATE client for application UDP.
   For individual TCP/UDP measurements, use a caller of the matching Rust SDK
   configured for the same route and a controlled remote target. The bundled
   SDK example and CLI `user-smoke` both create their own loopback environments.

   | Route | Test client and configuration | Carrier evidence for a successful session | Pass criteria |
   |---|---|---|---|
   | Direct H2 | CLI and SDK with the fixed pair from `gen-config --h2` | Verified transfer through the H2-only origin. SDK reports TCP `H2` and UDP `H2Reliable`. | TCP content matches in both directions. Persistent UDP with `allow_reliable` delivers independent replies through the same target-facing source port. A fixed H2 configuration with `native_required` is rejected. |
   | Direct H3 | CLI and SDK with `gen-config --quiche-h3`. Exercise each UDP policy. | Verified transfer through the H3-only origin. SDK reports TCP `H3` and UDP `H3Native`. | TCP content matches. Both UDP policies deliver native datagrams within the session's reported limit (at most 1200 bytes). An oversized send is rejected or dropped. Native delivery allows loss and reordering. |
   | Direct auto | CLI and SDK with the default dual server and auto client. Open fresh sessions under each UDP policy. | For TCP, correlate the CLI selection line below with completed data transfer. The SDK reports the actual TCP and UDP carrier for each admitted session. | With H3 healthy, fresh sessions use H3. During a verified pre-response H3 outage, new TCP uses H2, `allow_reliable` UDP uses `H2Reliable`, and `native_required` UDP fails to open. After recovery and cooldown, new sessions use H3 again. |
   | Protected intermediary H2 | CLI and SDK with the protected pair from `gen-config --relay` and the independently verified origin identity. Route both through the test intermediary. | The intermediary terminates outer TLS and forwards to the protected origin. The SDK reports TCP `H2` and UDP `H2Reliable`. Verify inner origin authentication separately. | TCP and reliable UDP deliver synthetic markers in both directions. Inspect the decrypted outer body at the intermediary for the synthetic authentication identifier, proxy target and payload markers. All must remain unreadable. A wrong inner CA, name or pin must fail before target access. |

   Use the [configuration recipes](docs/DEPLOYMENT.md#prepare-private-configuration)
   for the fixed carrier, UDP policy and protected origin settings. For each auto
   policy, keep the same CLI process or SDK connector across outage and recovery
   so that new sessions exercise its 30-second avoidance window.

   **Reading the carrier.** For an isolated auto TCP request, start the CLI with
   `RUST_LOG=maverick_client::connection_manager=debug` in its process
   environment. Match `automatic selection chose H2 for new TCP connection`
   or its H3 counterpart to that request. The line precedes target admission,
   so require the target's verified response. For auto UDP through the CLI,
   isolate one SOCKS association and correlate its known transfer with sustained
   bidirectional TCP (H2) or QUIC/UDP (H3) traffic on the origin's Maverick
   port. An initial probe alone cannot identify the carrier that delivered data.
   If attribution is ambiguous, record the CLI carrier as unverified. For an
   SDK session, read [the returned session's carrier and UDP limit](docs/INTEGRATION.md#integration-acceptance)
   directly. An SDK result applies only to that SDK session.

   **Recording a pass.** Record attempts and completions per route, client and
   policy. For a failure record the last observed stage (connection, identity,
   authentication, target admission or transfer) and mark unknowns explicitly.
   Compare synthetic TCP bytes at both ends. For each UDP route, check packet
   boundaries, repeated independent replies, source-port continuity, the reported
   size limit and resource release on close. For the [intermediary check](docs/END_TO_END_PROTECTION.md#acceptance),
   use a synthetic target that receives the marker in plaintext after Maverick
   decryption. Keep the origin key only at the origin. Record marker checks as
   present or absent without retaining bodies or credentials. The intermediary
   can still see the origin TLS name, timing and traffic volume.

4. **Check failure and recovery before the soak.** In the authorized test
   environment, make the H3 path unreachable and restore it; verify TCP and
   eligible reliable-UDP new sessions can select H2, native-required UDP cannot,
   and later opens retry after the existing 30-second avoidance expires. Do not
   mutate the Mac's networking. Wrong credentials, certificate/name/pin and
   malformed protocol must not trigger fallback. UDP target silence must not
   classify the tunnel as dead or replay data. Existing sessions keep their
   carrier and may fail on disruption; seamless migration is not an acceptance
   criterion. Observe session cleanup and bounded resource use with existing
   tools. Check existing configurations with omitted transport or UDP settings
   against their [documented behavior](docs/NATIVE_UDP_AND_SELECTION.md#scope-and-defaults).
5. **Exercise real rollback, then perform ordinary use and a 72-hour soak.**
   Validate both native platforms' installation/config restore. Beta.4 only
   supports the older direct-H2 route: use an isolated, explicit matching
   binary/config pair for that drill and then restore RC.6. Never weaken an
   origin-protected configuration or pretend Beta.4 restores H3/protected-route
   functionality. After functional/fault/rollback tests, freeze the accepted
   RC.6 configuration for the soak and ordinary browsing/video/download plus
   intended UDP application use within the agreed traffic budget. A runnable
   SDK example alone does not establish proxy-app interoperability.
6. **Record the go/no-go.** Every required matrix cell must have attributable
   evidence; TCP transfers must preserve content; UDP must obey its documented
   delivery/size semantics; there must be no unresolved security bypass,
   unexplained crash, persistent resource growth or blocking intended-use failure.
   Keep failures and uncertainties visible. A runtime/dependency fix creates a
   replacement RC and repeats affected exact-candidate gates; do not silently
   change the checkpoint or broaden scope. Only after owner acceptance perform
   the narrow Stable version/note promotion review, final package qualification
   and a separately authorized Stable publication.

The practical order is a short functional/fault/rollback session followed by
three days of normal use/soak and final review. Exact dates, applications and
budgets remain to be agreed. Paid audit, extra platforms, FFI bindings, new
providers, performance ranking and active-session migration are not added as
new mandatory work.

## Historical field prerequisites before the November 19 waiver

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
