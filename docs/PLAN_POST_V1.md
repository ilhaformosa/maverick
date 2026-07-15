# Post-v1 Execution Plan

Status: active highest-priority plan after the `v1.0.0` stable engineering
release. The completed v1 release train remains historical evidence in
`docs/PLAN_SHORT_TERM_TO_V1.md`.

## Direction

Near-term objective:

> Make Maverick's default path measurably harder to distinguish, reduce repeated
> handshakes, and collect evidence from real remote paths before expanding the
> product surface.

Long-term objective:

> Publish a useful open protocol that can support independent implementations,
> standardization work, and community governance after real usage and external
> review justify those structures.

The long-term objective is retained, not cancelled. It is deliberately sequenced
after stealth evidence, operational use, and a practical client path so the
project does not standardize untested behavior.

This plan does not claim that Maverick is formally audited, production-ready,
anonymous, censorship-resistant, browser-fingerprint-equivalent, or already a
standard.

## Address-Family Position

Current product and release work is IPv4-only. IPv6 is not scheduled in the
short-term, medium-term, or current long-term plan. Existing experimental IPv6
code and synthetic tests remain available to avoid unnecessary regression and
rework, but they are not a support promise, release gate, or product-readiness
claim. Future IPv6 work requires a new explicit decision, scope, and evidence
plan.

## Execution Order

Work proceeds in this order:

1. post-v1 plan, documentation truth, and CI economy;
2. TLS/H2 fingerprint and active-probe measurement baseline;
3. backward-compatible H2 connection reuse;
4. browser TLS correctness and evidence gate;
5. broader active-probe differential coverage and fallback hardening;
6. layered two-host network evidence;
7. handshake/fallback architecture decision;
8. product TUN plus ecosystem, standardization, and governance preparation.

Items 1-3 form the first implementation group. Items 4-6 begin only after that
group has a reviewed baseline. Items 7-8 depend on the evidence produced by the
earlier groups.

Documentation-only M7/M8 decisions may be drafted while a detached M6 run is in
progress. They must not change the tested runtime, interfere with approved
hosts, or claim that later code was covered by the running evidence.

## Current Progress

| item | status | evidence |
| --- | --- | --- |
| 1 | complete | canonical plan, documentation cleanup, and scoped CI are active |
| 2 | complete with recorded gaps | loopback labs and compact baselines exist; real-browser/channel-binding work remains item 4 |
| 3 | complete | one runtime-scoped H2 pool passes concurrency, timeout, reconnect, idle, shutdown, and carrier-boundary gates |
| 4 | complete | exporter channel binding, pinned Chrome evidence, fail-closed target support, and Linux/macOS gates pass |
| 5 | complete | 13 response-shape gates, Hyper fallback, H2/H3 body preservation, residual registry, and CI pass |
| 6 | complete | diagnostic/regression layers are accepted; milestone 24-hour, 8-hour impairment, and failure closure share tested source commit `b3a1793` |
| 7 | accepted | direct H2 remains the v1.x default, CDN WebSocket stays explicit, and handshake-layer work is gated to v2 research |
| 8 | Phase 3 bounded safety, package lifecycle, and sustained gate accepted; maturation gates active | Phase 2 IPv4 evidence is accepted. Exact reference commit `2978aa0` retains the accepted installed traffic, route-isolation, failure, package-lifecycle, signing, purge, and zero-residue evidence. SDK commit `0511522` and reference-client runtime commit `2f46f18` form the integrated sustained candidate with stricter IPC/recovery, credential policy, packet-FD coverage, deterministic APT snapshot tooling, and per-interface compatibility handling. One corrected formal eight-hour run is accepted with 481 aligned resource/route samples, 97 complete probe cycles, stable product processes, zero restarts, bounded resources, exact route isolation, and zero runtime residue. A duplicate formal run is not required merely as insurance. Production credential-root, power loss, broader transition/leak, package publication, and daily-use gates remain open; IPv6 is unscheduled |

## 1. Planning Truth And CI Economy

Deliverables:

- make this file the single active post-v1 execution plan;
- keep `ROADMAP.md` as a concise public overview instead of a second detailed
  plan;
- mark the old v1 release train as completed history;
- keep active contributor reading paths short while retaining historical
  evidence;
- remove duplicate GitHub Actions work;
- run H3, ECH, and shape-lab jobs only when relevant files change or when a full
  manual run is requested;
- keep weekly supply-chain and parser-fuzz workflows;
- keep the local pre-commit harness broader than ordinary CI.

Exit gate:

- one canonical post-v1 plan exists;
- current status and roadmap link to it;
- normal CI still runs format, Clippy, tests, conformance, fuzz smoke, config
  checks, and hygiene without running conformance/fuzz twice;
- explicit manual full CI remains available;
- documentation and release evidence are not deleted.

## 2. Measurement Baseline

Two detection surfaces must be measured independently:

- passive identification: what a network observer sees from the Maverick client;
- active probing: what an unauthenticated probe sees from the Maverick server.

Deliverables:

- a loopback-safe capture harness for the current rustls path, the
  `browser-tls` path, and a pinned real-browser reference capture;
- normalized TLS observations including protocol versions, cipher suites,
  extensions, supported groups, signature algorithms, ALPN, and JA3/JA4 inputs;
- normalized H2 observations including SETTINGS values/order, window behavior,
  and request metadata that the selected capture tool can reliably expose;
- a direct-origin versus Maverick fallback comparison matrix;
- machine-readable output plus a concise Markdown report;
- explicit redaction rules so packet captures, hostnames, addresses, secrets,
  and private infrastructure never enter public artifacts accidentally.

The implemented labs and usage boundary are documented in
`docs/STEALTH_MEASUREMENT.md`. Initial compact, redacted summaries are stored in
`test-vectors/stealth/`.

Exit gate:

- the same input produces a repeatable report;
- missing capture tools produce a clear skip/block result rather than false
  success;
- the report records observed differences without making a browser-equivalence
  or censorship-resistance claim.

## 3. Backward-Compatible H2 Connection Reuse

The first reuse step keeps the frozen v1 frame and authentication formats. One
TLS/H2 connection may carry multiple H2 request streams, while each request
stream still carries one current Maverick flow.

Deliverables:

- a bounded client-side H2 connection manager;
- concurrent stream acquisition without opening a new TCP/TLS connection for
  every local SOCKS5 or HTTP CONNECT flow;
- clean GOAWAY, closed-connection, timeout, and reconnect handling;
- no reuse across incompatible server identity, certificate, credential, mode,
  or channel-binding configuration;
- metrics/tests for connection creation, reuse, concurrent flows, reconnect,
  idle retirement, and shutdown;
- H2/H3/WebSocket behavior remains explicit; this step does not silently claim
  reuse for carriers that have not implemented it.

Exit gate:

- concurrent local TCP flows pass over fewer TLS handshakes;
- a broken pooled connection is replaced without wedging new flows;
- resource bounds and existing replay/auth checks remain effective;
- local harness, extended H2 tests, and compatibility checks pass.

True in-stream flow multiplexing remains a later protocol decision. Existing
`flow_id` fields make it possible, but they do not by themselves provide a safe
multi-flow dispatcher.

The runtime-scoped implementation and its carrier boundaries are documented in
`docs/TRANSPORT_ARCHITECTURE.md`. It uses existing timeout and flow-limit
configuration rather than adding a new wire or config version.

## 4. Browser TLS Correctness And Evidence

Deliverables:

- choose and record one browser family, version, and platform as the first
  comparison target;
- implement TLS exporter channel binding for the BoringSSL path;
- measure and correct ClientHello, ALPN, and H2 SETTINGS differences that are
  controllable without a protocol rewrite;
- build and test browser-TLS artifacts on explicitly supported targets;
- add a path-scoped or scheduled browser-TLS CI gate;
- make `private` mode select only an evidence-backed browser profile, or fail
  closed when the required backend is unavailable.

The global `auto` default does not change merely because the feature compiles.
It changes only after the evidence report and compatibility gate pass.

## 5. Active-Probe And Fallback Hardening

Deliverables:

- compare direct-origin and Maverick responses for methods, paths, queries,
  headers, bodies, malformed requests, rate limits, and admission exhaustion;
- cover TLS/ALPN behavior, HTTP response metadata, H2 behavior, WebSocket, gated
  H3 paths, and timing distributions where repeatable;
- replace or contain hand-written reverse-proxy parsing with maintained HTTP/TLS
  components;
- evaluate HTTPS upstreams, streaming bodies, trailers, timeout behavior, and
  upstream failure shape;
- keep protocol-specific errors hidden before authentication.

Exit gate:

- known response-shape regressions are mechanically reproducible;
- remaining differences are documented and threat-scoped;
- no claim of perfect origin indistinguishability is made.

## 6. Layered Two-Host Evidence

Use approved remote client and server hosts. The developer machine performs SSH
orchestration only and is not part of the data path.

Run layers:

1. 10-30 minute diagnostic run;
2. 2-8 hour regression run after meaningful transport changes;
3. 24-hour run only for a release or milestone gate that needs long-haul
   evidence;
4. bounded impairment and failure injection as separate runs;
5. a real restricted-network path only when such a client path is actually
   available and explicitly approved.

Evidence must retain detailed private logs, timestamps, failure reasons,
resource metrics, and capture provenance. Public reports contain redacted
summaries and hashes, not raw private infrastructure data.

Exit gate:

- the diagnostic, regression, and milestone long-haul layers required for the
  tested change have accepted evidence tied to the exact source commit, binary
  version, and binary hashes on both roles;
- the milestone 24-hour run completes its configured duration with every probe
  accounted for and no unexplained failure;
- latency counts and distribution, client/server resource samples, timestamp
  coverage, and every sampling gap are analyzed rather than reduced to a
  pass/fail summary;
- impairment and failure injection run separately from the clean long-haul,
  record the intended fault window, show bounded recovery, and retain detailed
  failure-stage diagnostics;
- system inventory, temporary-firewall state, process ownership, port state,
  run configuration, launch provenance, and cleanup results are retained in
  private evidence;
- cleanup removes every run-owned process, port, file, temporary firewall rule,
  namespace, veth, qdisc, and journal, while checks confirm unrelated host
  services and permanent networking were not changed;
- `scripts/s2-evidence-audit.py --require-accepted` accepts the final collected
  evidence after cleanup, with no secret or private-infrastructure material in
  public artifacts;
- any unexpected failure, evidence gap, provenance mismatch, or cleanup residue
  remains an explicit blocker until diagnosed and rerun at only the affected
  layer;
- restricted-network evidence remains optional until an actual restricted
  client path is available and explicitly approved, and no claim may imply that
  synthetic impairment proves that environment.

M6 closed on 2026-07-11. The accepted package ties the 24-hour clean run,
eight-hour namespace-scoped impairment run, and independent failure-injection
run to tested source commit `b3a1793`; it includes detailed private analysis,
strict cleanup records, accepted audits, and complete SHA-256 manifests. The
redacted public summary is
`docs/history/evidence/APPROVED_HOST_POST_V1_M6_EVIDENCE_2026_07_11.md`.

## 7. Handshake And Fallback Architecture Decision

Produce an architecture decision record comparing:

- continued application-layer fallback;
- an explicitly trusted CDN-fronted WebSocket path;
- TLS handshake-layer forwarding or a Reality/ShadowTLS-like split.

The decision must cover trust, certificate ownership, channel binding, replay,
active-probe behavior, deployment complexity, migration, and compatibility.
Any wire-incompatible or handshake-semantic change belongs in a major-version
track rather than a silent `v1.x` change.

The accepted decision is recorded in
`docs/HANDSHAKE_FALLBACK_DECISION.md`: direct TLS/H2 remains the mandatory v1.x
path, CDN-fronted WebSocket remains an explicit trusted-provider option, and
handshake-layer work has a separate v2 research entry gate. The decision is
accepted: M6 closed without changing its assumptions.

## 8. Product TUN And Ecosystem

Product TUN begins only after connection reuse and lifecycle behavior are
stable. It uses a reviewed existing packet-processing engine or adapter rather
than a new hand-written TCP/IP stack. Real route, DNS, interface, and leak tests
remain restricted to explicitly approved disposable hosts.

After real usage exists, choose the ecosystem path:

- a first-party client application;
- integration with an established proxy-client ecosystem;
- or a small SDK/transport boundary that supports both.

Long-term standardization and governance gates:

- public wire documentation remains accurate;
- at least one credible independent implementation or adopter exists;
- compatibility and migration behavior has real-world evidence;
- contribution volume justifies governance beyond a maintainer-led project;
- security claims have matching evidence and independent review.

The implementation sequence and entry gates are recorded in
`docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md`. It selects an engine-boundary-first path,
one reference client before broad platform expansion, and demand-backed
ecosystem integration before governance or standardization growth.

The preparation package is complete in `docs/TUN_ENGINE_RESEARCH.md`,
`docs/TUN_PACKET_ADAPTER_CONTRACT.md`,
`docs/TUN_SYNTHETIC_TEST_MATRIX.md`, and
`docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`. The completed Phase 0 comparison
in `docs/TUN_ENGINE_COMPARISON.md` selects `smoltcp 0.13.1` only for the
unprivileged Phase 1 adapter. Phase 1 is now complete behind build gate
`tun-runtime` and runtime gate `advanced.experimental_tun`: it accepts only
caller-supplied packet I/O, reuses existing auth/H2/TCP/DNS/UDP behavior, and
keeps resource/lifecycle snapshots bounded. Phase 2 received explicit approval
for one disposable external Linux system on 2026-07-12. Its feature-gated
evidence runner attaches to one pre-created TUN through a reviewed single-file
Linux ioctl boundary and records bounded runtime snapshots. The approved-host
IPv4 matrix is accepted: TCP, DNS, UDP, MTU/fragmentation, bounded concurrency,
failure recovery, resource sampling, host-state preservation, cleanup, and an
independent residue check passed. IPv6-family cases were explicitly blocked
because the host's pre-existing policy disabled IPv6, so they were not counted
as exercised passes. IPv6 is not a current or scheduled product milestone. This
remains experimental namespace evidence, not a product-readiness or
cross-platform claim. The exact execution and acceptance record is in
`docs/TUN_PHASE2_EXECUTION_GATE.md`.

Phase 3 is active in a separate private reference-client project so privileged
platform code and packaging do not enter the protocol repository. Its Linux
implementation includes an ordinary-user controller and service, a default-off
privileged mutation gate, peer-authorized bounded Unix IPC, single-operation
locking and replay handling, a durable recovery journal, fixed IPv4
TUN/route/DNS transactions, exact one-descriptor TUN transfer, systemd
credential references, and candidate service/sysusers/tmpfiles assets.

Earlier global-capture revisions passed bounded disposable-host route/DNS,
failure recovery, helper-to-SDK lifecycle, process-recovery, installed
TCP/UDP/DNS, package lifecycle, failed-upgrade recovery, and release-signature
gates. An attempted sustained run then exposed that the global capture rule
could intercept unrelated management and service traffic. Those results remain
historical regression evidence but do not accept the corrected implementation.
The current plan uses a distinct packaged capture UID so ordinary users, SSH,
the client control process, and unrelated services continue to use the main
route table. A later capture-UID `prohibit` rule prevents fallback if the TUN
route disappears. Captured foreground applications run in connection-bound
transient units with a private read-only DNS file; a session lock blocks
rollback until those applications stop. Legacy global-capture and earlier
scoped-without-guard journals remain decodeable only for exact rollback; new
apply operations cannot create them. A root-only credential command consumes
non-terminal standard input, uses fixed systemd encryption, and atomically
installs only the fixed active or next credential name. The ordinary service
also checks the SDK packet-runtime state every second and fails with rollback
when a background packet reader, writer, engine, or task stops being healthy.
The controller behavior, real asynchronous packet-reader failure, and local
service build gates pass. The fresh bounded current-plan gate on exact reference
commit `2978aa0` also accepts installed TCP/UDP/DNS, route separation,
connection-bound capture/private DNS, active-session rollback refusal,
TUN-loss restart, route-loss fail-closed behavior, default-inactive package
install, purge, credential host-key posture, and independent zero residue.
The same exact source now also accepts reproducible current-package artifacts,
project release-key signing with independent Linux verification, active-capture
upgrade rollback, downgrade rejection, an injected half-configured failure with
clean network state and preserved operator data, valid higher-version retry,
post-retry connection, purge, and independent zero residue. No package or apt
repository was published. A later exact integrated candidate separately passes
the bounded sustained-resource gate. Production credential-root, power loss,
broader transition/leak, package publication, and daily-use gates remain open.

The current integrated development candidate is Maverick SDK commit `0511522`
plus reference-client runtime commit `2f46f18`. It adds fail-closed
uncertain-operation recovery, exact one-frame helper exchanges, explicit
credential key policy and bounded encryption subprocesses,
cancellation/backpressure packet-FD coverage, deterministic unsigned APT
snapshot build/verification, and strict per-interface compatibility handling.
Its complete local harness, dependency policy, APT tests, privacy gate,
repeated packet-FD tests, signed package, and bounded sustained gates pass.
These results do not transfer unrelated privileged claims from older sources.

One eight-hour sustained attempt on the historical source completed 28,800
connected seconds, 97 probes, and 481 aligned resource samples with stable
processes and no recorded TUN errors or drops. It remains permanently rejected:
all route samples omitted the device values needed to prove route isolation,
the host-memory producer and analyzer used incompatible schemas, and strict
host-state equality observed unrelated dynamic firewall churn. The full private
collection, forensic analysis, exact cleanup, and independent zero-residue
verification are retained. No partial result from that run may satisfy a gate.

The corrected sustained replacement used a fail-before-long-run entry gate. The
exact sealed candidate passed a same-environment short canary, then one formal
28,800-second run completed with 481 aligned one-minute route/resource sample
sets, 97 complete TCP/UDP/DNS probe cycles, stable product PIDs, zero restarts,
bounded memory and descriptors, exact capture-route isolation, and zero runtime
residue. Its sealed analyzer accepted all 31 checks and its supplemental audit
accepted all 19 checks. One outer fixture cleanup mismatch was retained,
diagnosed as a forwarding-baseline restoration defect, corrected exactly, and
independently verified with zero residue.

This accepts the bounded sustained-resource, repeated-probe, route-isolation,
and cleanup claims for runtime commit `2f46f18` and SDK commit `0511522`. It does
not accept Daily Gate D, transition Gates T1/T2, abrupt power loss, production
credential-root protection, package publication, production readiness, IPv6,
or portability across Linux environments. A second eight-hour run is not
required merely as insurance. Another long run needs a distinct written
compatibility, regression, release, or long-haul purpose; rejected layers are
rerun only after their exact defect is diagnosed. Partial runs are never
combined.

## Release Mapping

- `v1.1.0-rc.1`: pre-publication private feature freeze containing the
  completed compatible M1-M8 work, including H2 reuse,
  browser-TLS/fallback hardening, accepted M6 evidence, and default-off
  experimental IPv4 TUN work.
- `v1.1.0`: pre-publication private stable engineering release after
  exact-commit release-artifact, migration, compatibility, CI, signature,
  privacy, and post-release gates passed without a blocker.
- `v1.2.0`: one IPv4 reference-client path, sustained product lifecycle and
  resource evidence, and demand-backed ecosystem work without changing the v1
  wire or authentication formats.
- No incompatible major release is planned. Wire-incompatible multiplexing,
  handshake-layer fallback, or another material protocol semantic change would
  require a separate compatibility, migration, and security decision.

Version numbers are release promises, not names for incomplete internal design
tracks.

The sanitized public repository does not recreate these private historical
tags. Its first release must use a previously unused version; the planned
first public candidate is `v1.2.0-alpha.1` after its applicable gates pass.
See `docs/PUBLIC_HISTORY_BOUNDARY.md`.

## v1.1 Candidate And Stable Gate

Status: complete in the pre-publication private repository. `v1.1.0-rc.1` was
published there at `2026-07-12T12:25:55Z` and passed its exact-commit CI,
artifact, signature, compatibility, privacy, and post-release audit gates. The
earlier fixed 24-hour wait was superseded on 2026-07-12 because no software or
deployment was running during that interval and elapsed time alone could not
produce additional evidence. Stable `v1.1.0` was published privately at
`2026-07-12T13:39:20Z`; its signed assets and exact-commit CI were independently
reverified and recorded in
`docs/history/release/POST_RELEASE_AUDIT_v1.1.0.md`.

`v1.1.0-rc.1` may be published only from a clean exact commit after the local
harness, dependency/security inventory, conformance, H3, ECH, browser-TLS,
artifact, signature, benchmark, privacy, and full manually dispatched CI gates
pass. It must be a GitHub Pre-release and must not replace `v1.0.0` as latest.

The stable `v1.1.0` gate requires no unresolved release blocker, successful
re-download and verification of every published RC asset, a committed
post-release audit, exact-commit local/CI verification, signed stable artifacts,
and independent verification of the published stable assets. If runtime source
changes after the RC, publish another RC and rerun the tests affected by that
change. If only the package version, release documents, and matching
documentation-hygiene rules change, the accepted M6/M8 runtime evidence remains
scoped as documented and no remote long-haul rerun is required.

During private development, a time-based observation gate is used only when
software is actually running and producing relevant evidence, or when external
users, deployments, scheduled jobs, or time-sensitive behavior can reveal new
information. Waiting without an active evidence source is not a release gate.

The active release-development milestone is now `v1.2.0`: select and build one
IPv4 reference-client path, then collect sustained lifecycle and resource
evidence without changing the v1 wire or authentication formats.

## Standing Rules

- Keep the `v1.0.0` frozen release artifacts immutable.
- Keep the H2/TLS compatibility path tested throughout post-v1 work.
- Never enable experimental cryptography by default.
- Do not mutate this development machine's proxy, DNS, routes, firewall, VPN,
  interfaces, or other network-service state.
- Keep generated credentials and private evidence out of git.
- Before every commit, scan staged changes and artifacts for private identity,
  infrastructure, account, path, hostname, address, and secret data.
- Stronger public claims require matching reproducible evidence.
