# Changelog

Maverick uses explicit release notes for public tags. This project is currently
an experimental as-is prototype; entries below are not stable or
production-ready release claims.

## Unreleased

- Set the public workspace software version to `1.2.0-alpha.1` for the first
  planned public candidate. This names the source version only; it does not
  freeze a commit, create a tag, publish an artifact, or make a readiness claim.
- Completed the sanitized public-source cutover from a single audited root,
  without importing private Git history, historical tags, releases, or Actions
  records. The cutover created no software release or production-readiness
  claim.
- Defined the sanitized public-history boundary: pre-publication tags,
  releases, Actions runs, and private Git objects are not imported or
  recreated; public development continues toward a previously unused
  `v1.2.0` release version.
- Hardened public-source preparation gates for workflow pinning, replay-cache
  cleanup, fuzz corpus containment, approved-host validation, rollback journal
  ownership, remote evidence cleanup, and secret/log scanning. These changes do
  not authorize remote or privileged tests.
- Added the `v1.1.0` post-release audit after independently downloading and
  verifying every published asset.
- Selected a Linux CLI/service as the first experimental IPv4 reference-client
  path for `v1.2.0`, while keeping platform code outside the protocol
  repository and privileged tests separately gated.
- Added a coarse SDK platform-recovery snapshot that reports reconnect as
  disallowed when a helper journal requires cleanup, rejects inconsistent
  states, and exposes no journal path or raw platform error.
- Added the version-1 platform-helper IPC data contract with bounded JSON,
  fixed operations, fixed journal location, strict request identifiers,
  unknown-field rejection, and coarse response errors.
- Added an unprivileged reference-client controller with replaceable helper and
  packet-runtime adapters, ordered connect/disconnect/recovery, fail-closed
  response matching, rollback after partial failure, and redacted coarse state.
  An uncertain `apply` transport or protocol result now blocks reconnect until
  rollback, while a validated clean rejection remains immediately reusable.
  A packet-runtime stop error also blocks reconnect, even after helper rollback,
  until a later recovery proves both local stop and rollback succeeded.
  Interrupted connect and disconnect futures retain recoverable transitional
  state so explicit recovery can retry stop and idempotent rollback.
- Added connected-state packet-runtime health reconciliation so a later TUN
  reader, writer, engine, or task failure can stop the runtime and roll back
  platform state instead of leaving a falsely healthy reference service. An
  immediately unhealthy runtime is also rejected before the controller enters
  connected state.
- Added checked-in platform-helper IPC version-1 compatibility vectors and
  machine-enforced accepted/rejected message tests. Boundary vectors cover every
  operation, outcome, and coarse error class, and an `applied` response now
  rejects rollback-failed state as a protocol error instead of allowing the
  controller to start, while preserving the explicit recovery path.

## v1.1.0 - 2026-07-12

- Promoted the verified `v1.1.0-rc.1` implementation to a stable engineering
  release without changing runtime behavior, wire formats, authentication
  versions, or config version 1.
- Replaced the private-stage fixed 24-hour wait with an evidence-based release
  gate. Time windows are required only when software is actually running and
  producing relevant long-duration evidence, or when external deployment and
  user observation make elapsed time meaningful.
- Preserved the accepted M6 long-haul, impairment, failure-injection, and M8
  IPv4 real-TUN evidence because the stable promotion changes only package
  version, release documentation, and its matching documentation-hygiene rule.
- Kept TUN, H3, browser-TLS, CDN-fronted WebSocket, and experimental
  cryptography behind their existing gates or default-off.
- Kept product and release support IPv4-only. IPv6 remains unscheduled, with
  future support possible only through a new explicit decision.

## v1.1.0-rc.1 - 2026-07-12

- Added a single post-v1 execution plan that prioritizes measurable stealth,
  backward-compatible H2 connection reuse, remote evidence, and later
  TUN/ecosystem work while retaining standardization and community governance as
  long-term goals.
- Replaced the old internal v1-v6 roadmap labels with a concise post-v1 roadmap
  and clarified that semantic versions describe real releases.
- Reduced ordinary GitHub Actions usage by removing duplicate conformance/fuzz
  jobs, path-scoping H3/ECH/shape jobs, preserving manual full runs, and caching
  downloaded Cargo dependencies.
- Added a privilege-free loopback TLS/H2 fingerprint lab that records repeated
  rustls and feature-gated BoringSSL ClientHello/H2 observations, compact JSON
  summaries, explicit real-browser evidence gaps, and no stronger privacy claim.
- Expanded the deterministic loopback active-probe lab to 13 response-shape
  comparisons across methods, paths, queries, headers, bodies, authentication
  failures, auth-rate limiting, upstream failure, and repeated timing samples.
- Replaced hand-written reverse-proxy response parsing with Hyper, preserved
  authentication-stage request bytes across H2/H3 fallback, stripped nominated
  hop-by-hop headers, bounded upstream bodies, and normalized upstream failures
  to a generic `502 Bad Gateway` response.
- Added a machine-checkable active-probe baseline that pins all 13 comparable
  response shapes, nine measured/residual coverage states, repeated timing
  diagnostics, and explicit non-claims.
- Expanded detached two-host long-haul evidence with binary hashes, system
  inventory, resource/network samples, per-probe elapsed time, detailed failure
  context, and explicit completed/failed markers.
- Added backward-compatible, runtime-scoped H2 connection reuse for local
  SOCKS5, HTTP CONNECT, DNS, and UDP flows, including bounded acquisition,
  handshake timeouts, closed-connection replacement, idle retirement, shutdown,
  and public aggregate counters. H3 and WebSocket remain explicitly unpooled.
- Added BoringSSL TLS exporter channel binding, Chrome-reference TLS/H2
  settings, CLI/SDK browser-tls feature propagation, a loopback real-browser
  capture path, and budget-aware browser-tls CI. Residual ALPS and newer
  signature-algorithm differences remain explicit non-equivalence evidence.
- Added a five-sample pinned Chrome reference baseline and a machine-checkable
  gate for channel binding, normalized TLS/H2 hashes, residual explanations,
  supported build targets, and non-claim boundaries.
- Added the post-release audit record for `v1.0.0`.
- Marked the short-term v1 release-train plan as completed after the stable
  GitHub release was published.
- Completed the M8 fixed packet-engine comparison, selected exact
  `smoltcp 0.13.1`, recorded explicit `ipstack`/`tun2proxy` and gVisor-sidecar
  rejections, and added machine checks for pins, licenses, features, resource
  bounds, unsafe boundaries, and redacted evidence.
- Added a default-off `tun-runtime` Phase 1 packet crate and SDK/client boundary
  with caller-supplied packet I/O, shared auth/H2/TCP/DNS/UDP paths, bounded
  task/queue/buffer accounting, coarse diagnostics, lifecycle/failure tests,
  and real Maverick loopback integration.
- Accepted the M8 Phase 2 approved-host IPv4 matrix through a namespace-local
  real TUN, including MTU/fragmentation, bounded concurrency, failure recovery,
  resource sampling, host invariants, hash-verified private evidence, and
  independent zero-residue cleanup. IPv6 remained policy-blocked and is not an
  exercised pass or product-readiness claim.
- Froze `v1.1.0-rc.1` as a backward-compatible candidate. Software version
  changes, while Auth v1/v2 protocol versions and config version 1 remain
  unchanged. IPv6 has no current release or product milestone; future support
  remains possible only through a new explicit decision.

## v1.0.0 - Narrow Stable Engineering Release

- Added the post-release audit record for `v0.1.0-rc.2`.
- Promoted only the narrow `maverick-tls-h2-cli-v1` scope to the stable
  engineering release track after the fixed RC.2 soak window completed.
- Updated public README, status, compatibility, migration, and conformance
  wording for the narrow v1.0.0 scope while preserving the no-formal-audit,
  no-production-readiness, no-anonymity, no-censorship-resistance,
  no-native-ECH, and no-GUI boundaries.
- Added the v1.0.0 release notes and a frozen v1.0.0 conformance-vector
  snapshot for the stable release gate.
- Added public release-signing verification material and Keychain-backed
  signing support for stable checksum signatures.
- Advanced the package version to `1.0.0` without changing the default Auth v1
  protocol version, explicit Auth v2 protocol version, or config version.

## v0.1.0-rc.2 - Green CI Soak Candidate

- Added the post-release audit record for `v0.1.0-rc.1`.
- Superseded `v0.1.0-rc.1` as the active soak candidate after the
  post-publish GitHub full CI run found a shape-lab smoke harness failure.
- Fixed the default shape-lab smoke scenario list so private-mode
  browser-mimic evidence remains a separate `browser-tls` task instead of
  failing the default CI gate with a deliberately rejected `rustls_default`
  fingerprint.
- Regenerated the shape-lab baseline with the default non-private scenarios.
- Advanced the package version to `0.1.0-rc.2` without changing the default
  protocol version or config version.

## v0.1.0-rc.1 - Review And Freeze Candidate

- Added the post-release audit record for `v0.1.0-beta.2`.
- Updated public status wording from beta-stage to release-candidate-stage
  while preserving the no-formal-audit and no-production-readiness boundaries.
- Added the S3 review handoff for independent/community review of the frozen
  `maverick-tls-h2-cli-v1` scope.
- Opened a public S3 community security review request.
- Refreshed security reporting, support, public feedback, and review-package
  inputs for the beta/RC phase without claiming a completed audit or stable
  protocol freeze.
- Clarified the S3 protocol/config boundary: config version `1`, Auth v1 hello
  protocol version `1`, and explicit Auth v2 hello protocol version `2`.
- Updated freeze-readiness metadata to point at the S3 review handoff while
  keeping external review completion blocked.
- Added an S3 findings triage template and made the security-review package
  checker require the active S3 review handoff artifacts.
- Added a budget-aware docs-hygiene workflow and CI path filters so
  docs/metadata changes use a light gate while code, protocol, conformance,
  script, and workflow changes still run the full CI gate.
- Closed the S3 review-input gate for the narrow
  `maverick-tls-h2-cli-v1` RC candidate by triaging and remediating the
  imported anonymous review bundle.
- Hardened fallback behavior so direct and reverse-proxy fallback paths better
  preserve ordinary HTTP method, path, headers, and body handling.
- Bound direct rustls H2/WebSocket authentication to the TLS exporter channel
  binding where available.
- Added reset/admission bounds and task-drain handling for H2 streams and split
  replay-cache accounting.
- Replaced YAML parsing with `serde_yaml_ng`, added `cargo deny` policy, added
  a weekly supply-chain workflow, and forbade first-party unsafe Rust.
- Reduced secret cloning in service auth paths and documented the remaining
  limits of in-memory secret lifetime hardening.
- Advanced the package version to `0.1.0-rc.1` without changing the default
  protocol version or config version.

## v0.1.0-beta.2 - Independent Evidence Beta

- Added the S2 independent evidence report for the `v0.1.0-beta.2` gate:
  24-hour two-host long-haul, 8-hour bounded netem impairment, and updated
  failure-injection evidence.
- Hardened S2 evidence collection so client/server log directories are copied
  efficiently and top-level client log files are retained.
- Extended failure injection to cover reverse-proxy fallback-origin failure and
  recovery without making production-readiness, anonymity, or
  censorship-resistance claims.
- Added a post-release audit record for `v0.1.0-beta.1` covering tag, release
  state, artifact checksum, binary version, `BUILDINFO`, release status, and
  artifact privacy-scan results.
- Advanced the package version to `0.1.0-beta.2` without changing the default
  protocol version or config version.

## v0.1.0-beta.1 - Runtime Hardening Beta

- Froze the active v1.0 target as `maverick-tls-h2-cli-v1` and moved old
  alpha/readiness/evidence snapshots under `docs/history/`.
- Added server global and per-source connection caps, fallback concurrency
  admission, active connection/fallback/flow metrics, and loopback tests for
  the new overload paths.
- Expanded log-hygiene checks so default gates reject logging of secrets,
  raw payload/body data, auth tags, credential identifiers, nonces, and replay
  keys.
- Updated operator docs for metrics, overload settings, systemd hardening,
  rollback expectations, and beta release boundaries.
- Advanced the package version to `0.1.0-beta.1` without changing the default
  protocol version or config version.

## v0.1.0-alpha.4 - Direction A Stealth Controls

- Added a post-release audit record for `v0.1.0-alpha.3` covering tag, release
  state, artifact checksum, binary version, `BUILDINFO`, CI status, public
  issue/PR snapshot, and artifact privacy-scan results.
- Added optional `browser-tls` support for the H2 client. The `browser_mimic`
  mode now has a BoringSSL client path with GREASE, extension permutation, and
  H2 ALPN, while rustls remains the default path.
- Hardened active-probing behavior so bad-auth, malformed, rate-limited, and
  H2 stream-admission exhaustion paths continue returning fallback-shaped
  responses when active-probe resistance is enabled.
- Promoted CDN-fronted WebSocket selection to first-class config through
  `advanced.stealth.cdn_fronting.enabled`, while keeping
  `advanced.experimental_cloudflare_ws` as a compatibility alias.
- Added alpha.4 release notes and readiness tracking for the Direction A
  stealth-control release.
- Advanced the package version to `0.1.0-alpha.4` without changing the default
  protocol version or config version.

## v0.1.0-alpha.3 - Post-Release Hygiene Baseline

- Added alpha.3 readiness tracking for public feedback, release follow-up,
  compatibility boundaries, migration posture, stable-candidate gaps, and
  Native ECH tracking.
- Added a post-release audit record for `v0.1.0-alpha.2` covering tag,
  release body, artifact checksum, binary version, `BUILDINFO`, public
  issue/PR snapshot, and artifact privacy-scan results.
- Added `v0.1.0-alpha.3` release notes that preserve experimental status,
  `protocol_version: 1`, config `version: 1`, no mandatory migration, and the
  native server-side ECH boundary.
- Advanced the package version to `0.1.0-alpha.3` without changing the default
  protocol version or config version.

## v0.1.0-alpha.2 - Alpha Hygiene And Evidence

- Public repository polish: issue templates, release notes, tag strategy, and
  stable/production readiness criteria.
- Public feedback triage and alpha release selection process.
- `v0.1.0-alpha.2` release notes focused on feedback handling and release
  hygiene.
- Alpha.2 readiness tracker for local gates and external stable-candidate
  evidence gaps.
- Issue-template privacy prompts aligned with the public feedback process.
- Issue-template hygiene checker in the local harness.
- GitHub Pre-release guidance for alpha and beta snapshots.
- Release artifact guidance for exact-commit GitHub Pre-release attachments.
- Compatibility and migration notes documenting no planned alpha.2 protocol or
  config version change.
- Failure-injection evidence plan for restart, reconnect, target failure,
  timeout, and network-impairment scenarios.
- Pre-release dependency advisory and first-party unsafe-code inventory gate.
- Public-safe approved-host evidence and ECH harness templates that redact
  private test infrastructure details.
- 24-hour approved-host TCP/H2 long-haul baseline evidence for the narrow
  stable-scope runtime path, without making a production-readiness claim.
- Approved-host process-level failure-injection evidence for server restart,
  client restart, upstream target failure, and upstream stall or timeout.
- External audit remediation: H2 flow-control release and send backpressure,
  bounded UDP ASSOCIATE waits, resilient listener accept loops, tighter fallback
  behavior, reserved egress blocking, safer config URI import, config permission
  startup gates, generated-config hygiene, and `SecretString` default serde
  redaction.
- Approved-host netem impairment harness for production-scope latency/loss
  evidence collection, plus an exploratory 2026-07-04 run recorded as
  inconclusive and a diagnostic 8-hour rerun that passed 96/96 iterations for
  the tested TCP/H2 latency/loss profiles.

## v0.1.0-alpha.1 - Initial Public Source Snapshot

First public source snapshot.

Scope:

- TLS 1.3 + HTTP/2 default tunnel prototype.
- Local SOCKS5, DNS relay, optional HTTP CONNECT inbound, and TCP/UDP relay
  test coverage.
- Optional feature-gated H3/QUIC carrier with H2 fallback.
- Experimental Cloudflare-fronted WebSocket carrier for Cloudflare edge ECH
  experiments. This is not native Maverick server-side ECH.
- Config generation, validation, migration dry-runs, profile URI import/export,
  redacted key inventory, and local benchmark harnesses.
- One-hour approved-host TCP/H2 smoke evidence for the narrow stable-scope
  runtime path, without making a production-readiness claim.
- TUN, Noise, Native ECH, and GUI/App tracks remain scoped as experimental or
  non-blocking future tracks.

Release boundary:

- Not audited.
- Not production-ready.
- No stable protocol freeze.
- No native server-side ECH support.
- No anonymity or censorship-resistance guarantee.
