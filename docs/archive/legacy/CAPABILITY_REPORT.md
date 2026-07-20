# Maverick Capability Report

Status: current as of the harness-safety baseline. For the short current claim
boundary, start with `STATUS.md`.

## Current Capabilities

- Rust workspace split into core, client, server, CLI, and integration tests.
- TLS 1.3 + HTTP/2 tunnel carrier through rustls and h2. H2 client and server
  configs pin TLS 1.3, with loopback coverage rejecting a TLS 1.2-only client.
- Optional, feature-gated H3/QUIC tunnel carrier through quinn, h3, and
  h3-quinn when `advanced.experimental_h3` is enabled on both sides.
- SOCKS5 CONNECT inbound.
- Optional local HTTP CONNECT inbound.
- TCP relay over authenticated tunnel frames.
- DNS relay over authenticated tunnel frames.
- SOCKS5 UDP ASSOCIATE relay over authenticated `OpenUdp` / `UdpPacket` flows
  with bounded idle timeout.
- Static fallback and Hyper-backed HTTP reverse-proxy fallback with bounded
  bodies, hop-by-hop filtering, H2/H3 auth-stage body preservation, and generic
  upstream failure responses.
- Multi-user credentials with high-entropy secret validation.
- ClientHello/ServerHello HMAC authentication.
- Timestamp and nonce replay protection.
- Per-user server flow limits and simple byte pacing.
- Client-side local TCP flow limits.
- Client connection timeout covering TCP, TLS, and H2 setup.
- Optional certificate pinning after normal certificate validation.
- Loopback-only metrics endpoint.
- Loopback-only metrics include aggregate shaping padding counters without
  destination or user labels.
- Loopback-only benchmark command and release-mode baseline script for 64 KiB,
  1 MiB, and 10 MiB payloads with single-flow and concurrent-flow runs.
- Criterion parser-regression benchmark target and smoke/baseline/compare
  script for local parser performance tracking.
- Local harness for format, Clippy, tests, generated config validation, and
  hygiene scans.
- Local log hygiene scan rejects direct logging of secrets, auth tags,
  credential hints, and credential ids.
- Local claim hygiene scan requires key docs to preserve explicit non-audit,
  non-production, non-anonymity, and non-standardization disclaimers.
- Local network safety hygiene scan rejects Rust source, script, and CI workflow
  content that would mutate system proxy, DNS, route, firewall, VPN, network
  interface, or other network-service settings.
- Extended local harness aggregates the default harness, H3/ECH feature
  harnesses, parser benchmark smoke, temporary shape-lab smoke, and loopback
  benchmark smoke.
- Remote VM harness can sync the workspace to an explicit SSH host and run the
  default or extended harness there with bounded Cargo jobs.
- Optional public TCP smoke harness can run one explicit H2/TLS SOCKS5 TCP
  relay flow against an approved remote VM using temporary remote processes and
  operator-supplied certificate paths. The client data plane can run on a
  separate SSH host so local proxy or split-routing software does not affect
  WAN interpretation.
- Optional two-host UDP reachability probe can check one datagram and reply
  between approved SSH hosts before H3/WAN experiments. It is a port/network
  check, not a Maverick protocol test.
- Optional two-host public H3/QUIC runtime smoke can build feature-gated H3
  binaries on approved SSH hosts, run one SOCKS5 TCP echo flow over QUIC, and
  verify the server authenticated an H3 session rather than silently succeeding
  through H2 fallback.
- H2 and feature-gated H3 concurrent TCP relay regression coverage.
- Config migration dry-run report.
- CI split for default local harness and optional H3 harness.
- Benchmark dashboard template and local interop matrix.
- Loopback-only shape lab script, baseline report, and CI smoke job.
- Shape lab can compare auto baseline with stable/auto/private bounded runtime
  shaping scenarios.
- v3 planning documents for Auth v2, credential rotation, shaping, and ECH.
- Auth v2 core data structures, config gates, unit tests, and explicit opt-in
  H2/H3-compatible runtime baseline with accepted-epoch and replay regression
  coverage.
- Auth v2 rejects client epochs outside the configured rotation window before
  tunnel setup.
- Malformed unauthenticated H2/H3 tunnel-like requests return fallback-like
  content rather than Maverick protocol errors.
- Credential rotation config parsing, validation, and v1-compatible runtime
  selection for bounded previous-credential overlap windows.
- Explicit opt-in client next-credential switching after `not_before` when
  next credential material is configured locally.
- Redacted credential rotation dry-run lint for expired previous credentials,
  next credentials ready for promotion, and disabled users with rotation state.
- Shaping config validation, core budgeted padding policy, client-side outbound
  runtime padding frames, server-side outbound runtime padding frames,
  aggregate shaping padding metrics, and bounded pacing delay with
  server/client skip handling.
- Core bounded shaping batcher decisions for byte-cap, time-cap, and
  FIN/reset/control-frame bypass, wired into client runtime tunnel writes for
  eligible outbound frames.
- Cover-traffic budget planning, operator-decision model, and minimal
  client/server runtime wiring behind explicit config and operator approval.
  Runtime cover traffic emits only bounded padding frames tied to observed
  payload budget; it does not emit idle background traffic.
- Aggregate cover-traffic padding metrics are exposed without target or user
  labels.
- `stable` mode disables optional padding, pacing, and batching decisions.
- `log.redact: false` is rejected for client and server configs instead of
  acting like a supported non-redacted logging mode.
- ECH feature/config/readiness gates that reject enablement until TLS support,
  config distribution, and controlled integration evidence are present.
- ECH feature harness compiles and tests `--features ech` without DNS, WAN, or
  system network changes, including a rustls client ECH API smoke.
- ECH runtime approval manifest/checker records completed local/external gates
  and the Cloudflare-fronted runtime smoke separately from native server-side
  ECH. Server TLS backend and native ECHConfig distribution remain blocked,
  runtime config acceptance remains deferred, and network activity stays
  disallowed before native runtime handshakes.
- ECH runtime blocker registry/checker tracks local-complete preparation
  slices, pins the approved ECH host to `approved-linux-vm`, records the
  completed Cloudflare subdomain plus edge-only preflight, adds an approved-host
  Cloudflare origin reachability probe, records the Cloudflare-fronted runtime
  WebSocket smoke as completed on approved hosts, and keeps native runtime ECH
  blocked on server-side TLS support. `docs/ECH_NATIVE_TLS_LIMITATION.md`
  explains why Cloudflare-fronted ECH and native server-side ECH are separate
  gates.
- Native server-side ECH is a core long-term tracking item recorded in
  `docs/NATIVE_ECH_TRACKING.md`. It is not an active initial-release blocker,
  but it must remain visible before future private-mode, TLS-backend, or ECH
  claim changes.
- ECH diagnostics report disabled/unsupported status, fallback policy, and
  private-mode plain-SNI blocking plus readiness blockers without downgrade
  advice.
- v4 platformization design docs for TUN mode, config URI, SDK, and GUI/tray.
- Config URI export, import dry-run, and explicit output materialization with
  secret redaction in command output.
- Config URI import accepts single-URI QR/clipboard text payloads with
  surrounding whitespace and rejects multi-URI payloads.
- Config URI export can render secret-free terminal QR and rejects
  secret-bearing QR export.
- Config URI import can explicitly read the OS clipboard; automated coverage
  uses a fake provider and does not read the developer machine's clipboard.
- Redacted key inventory command for client/server credential material.
- Local-only TUN route-plan model, apply safety-gate decision model, and
  synthetic packet classifier tests; no system network mutation.
- Approved-VM TUN apply smoke for temporary Linux TUN device creation,
  documentation-prefix route apply/rollback, namespace-scoped DNS
  apply/rollback, and residue checks. This is an explicit SSH harness and is
  not part of the local default harness.
- CLI `tun-helper-smoke` implements a gated Linux Phase A helper smoke for
  approved hosts. It creates a temporary TUN device, assigns `10.255.0.1/30`,
  adds and probes an RFC 5737 documentation-prefix route, rolls route/device
  changes back, writes and removes a structured rollback journal, and verifies
  residue plus unchanged default-route and global-DNS baselines. It does not
  touch default routes, global DNS, or firewall rules.
- CLI `tun-helper-rollback` consumes a retained Phase A rollback journal on an
  approved Linux host, idempotently removes the recorded documentation-prefix
  route and TUN device when present, removes the journal after successful
  cleanup, and verifies residue plus unchanged default-route and global-DNS
  baselines.
- TUN runtime-readiness diagnostics now separate completed helper and Phase 2
  evidence from product readiness. Helper preflight, rollback-journal,
  retained-recovery, network-baseline checks, approved-VM namespace runtime
  smoke, approved-VM default-route/DNS policy smoke, service-manager lifecycle
  smoke, leak/coexistence smoke, full-helper aggregate smoke, and the accepted
  Phase 2 IPv4 real-TUN matrix are recorded. IPv6 is unscheduled, and
  product-client readiness remains blocked.
- M8 Phase 1 now provides a default-off `maverick-tun` packet runtime with exact
  `smoltcp 0.13.1` features, caller-supplied packet I/O, bounded dual-stack TCP
  plus DNS and UDP mapping, shared client flow/H2 limits, coarse resource
  snapshots, SDK build/runtime gates, and synthetic plus real-Maverick loopback
  tests. It cannot create a TUN device or mutate host networking.
- TUN runtime plan model builds reversible abstract apply/rollback actions for
  approved include-route, exclude-route, default-route, and DNS plans behind a
  production policy gate. It does not execute OS commands.
- CLI `tun-plan` reports local-only dry-run steps, safety blockers, and
  optional abstract runtime actions with `system_apply: false`.
- CLI `tun-helper-preflight` performs read-only approved-host readiness checks
  for the Phase A helper scope: Linux platform, `ip`, noninteractive
  privileges, existing test device/route state, and rollback journal path
  availability.
- CLI `tun-helper-smoke` dry-run/refusal paths are part of the local harness;
  real apply remains approved-host-only and requires
  `MAVERICK_TUN_HELPER_APPROVED=1`. The helper refuses apply when the rollback
  journal path is unavailable.
- CLI `tun-helper-rollback` dry-run/refusal paths are part of the local
  harness; real recovery remains approved-host-only and requires the same
  explicit approval environment.
- TUN helper approval manifest/checker records which mutation slices are
  approved-host-only, keeps local-machine system apply and host-level global
  DNS mutation blocked, and requires rollback/residue checks for approved-host
  slices.
- TUN runtime blocker execution manifest/checker records Phase B namespace
  runtime smoke plus Phase C namespace default-route/DNS policy smoke,
  service-manager lifecycle smoke, and leak/coexistence smoke as completed on
  an approved VM. It also records the full-helper aggregate integration smoke
  as completed for the current prototype scope.
- Approved-VM TUN Phase B runtime smoke has exercised temporary namespace,
  veth data path, namespace-local TUN, namespace policy route,
  namespace-scoped DNS, leak sentries, rollback, residue checks, and unchanged
  host default-route/global-DNS baselines.
- Approved-VM TUN service-manager lifecycle smoke has exercised transient
  systemd success and failure cleanup paths, namespace/TUN residue checks, and
  unchanged host default-route/global-DNS baselines.
- Approved-VM TUN leak/coexistence smoke has exercised TUN-selected
  default/DNS route probes, preserved control-plane routing, host listener
  baseline checks, rollback, residue checks, and unchanged host
  default-route/global-DNS baselines.
- Approved-VM TUN full-helper aggregate smoke has chained helper runtime, policy,
  service-manager, and leak/coexistence smokes with preflight/final residue
  checks for the current prototype scope. This is not a production full-device
  TCP/IP relay claim and does not make the product TUN runtime ready.
- Approved-VM TUN Phase C policy smoke has exercised preserved control-plane
  routing, namespace-local default route to TUN, DNS route selection to TUN,
  rollback, residue checks, and unchanged host default-route/global-DNS
  baselines.
- Rust SDK start/stop wrapper and builder/profile baseline for embedded
  client/server runtimes.
- GUI/tray diagnostics snapshot model with redaction tests, GUI runtime
  readiness diagnostics, debug-only H2/H3/cooldown transport diagnostics, UI
  scope decision, and macOS-first platform target decision; no GUI app runtime.
- v5 crypto agility registry and `advanced.crypto` policy validation baseline;
  HPKE/Noise/ML-KEM entries are declared but disabled.
- Operator-safe crypto policy diagnostics report suite status, feature/runtime
  gates, stable foundation presence, and default-claim exclusions without
  downgrade advice or secret/key material.
- Pre-runtime crypto descriptor tests require disabled experimental suites to
  declare gates, Maverick transcript labels, and future vector paths.
- Source-tracked HPKE and ML-KEM official subset vector files are checked in for
  future implementation-backed KATs; Noise now has a Snow-backed deterministic
  XX25519/ChaChaPoly/SHA256 transcript/prologue vector and transport smoke
  case.
- Noise runtime readiness diagnostics record candidate implementation,
  implementation-vector, transcript-test, downgrade-test, runtime-session
  harness, and runtime-config readiness while keeping product transport config
  exposure disabled.
- Noise runtime approval manifest/checker keeps implementation selection,
  implementation-backed vectors, transcript/prologue tests, downgrade tests,
  runtime session harness status, product config exposure, and security-claim
  review boundaries explicit before runtime use.
- Feature-gated Noise XX core session harness for native no-domain research:
  expected remote static-key checks, prologue/transport-context mismatch
  rejection, length-prefixed encrypted message envelopes, and encrypted
  Maverick frame round trips.
- v5 HPKE/Noise, ML-KEM hybrid, and key lifecycle design docs.
- v6 spec freeze, conformance, multi-implementation, and governance design
  docs.
- Conformance vector baseline for frames, Auth v1 hello payloads, replay cache
  semantics, DNS query/response frames, `OpenTcp`, `OpenUdp`, `UdpPacket`, and
  error-code payloads.
- Optional cargo-fuzz targets for frame decoding and Auth v1/v2 hello decoding.
- Fuzz seed corpus generation from conformance vectors plus local/manual-CI fuzz
  smoke and a manually triggered bounded parser-fuzz workflow.
- Conformance vector generation check that requires checked-in JSON to match
  deterministic wire values exactly.
- Spec/wire alignment checker that verifies frame type assignments across Rust,
  `WIRE_FORMAT.md`, and the Python verifier.
- Pre-freeze conformance vector manifest checks SHA-256 hashes and catches
  unregistered or stale JSON vectors.
- Freeze-readiness policy checker records candidate/frozen blockers with
  evidence paths and prevents a ready status while blockers remain.
- Security review plan baseline plus third-party AI review triage; formal human
  audit is deferred for this as-is personal prototype and remains a future
  requirement before stronger public safety claims.
- Security review package manifest and checker record required reviewer inputs
  without claiming audit completion.
- Frozen-release conformance policy checker validates the current immutable
  conformance vector snapshot and rejects vector hash drift or unsafe snapshot
  paths.
- Implementation-registry policy checker records the Rust prototype plus the
  no-network Python verifier, requires evidence paths, and rejects normative or
  standardization claims.
- No-network Python conformance verifier smoke test.
- Dedicated CI conformance job for Rust exact-match vectors and the Python
  verifier.
- Experimental track status matrix, core registry, CLI listing, and promotion
  criteria.
- Roadmap blocker registry and local checker for remaining external-review,
  approved-host, upstream-support, runtime-review, and deferred product gates.

## Current Risk Register

- Experimental prototype, not audited.
- Default TLS uses rustls and does not mimic a browser fingerprint. The
  optional BoringSSL path has exporter channel binding and a pinned Chrome
  comparison, but measured ALPS and signature-algorithm differences remain.
- UDP relay has flow mapping and timeout bounds, but is not optimized for lossy
  networks or real-time workloads.
- Client-side padding, server-side padding, pacing, and runtime batching exist
  as bounded runtime baselines. None of these are strong traffic-analysis or
  anonymity protection claims.
- `private` mode rejects rustls, plain-SNI ECH fallback, and disabled active
  probing resistance. It requires an explicit browser-mimic profile in a
  browser-tls build and does not silently downgrade.
- Credential lookup uses explicit credential ids; anonymous or blinded lookup
  is future work.
- Benchmarking, dashboard generation, and shape lab reports are local
  diagnostics, not production performance or anonymity claims.
- H3/QUIC remains experimental and off by default; scheduler fallback/cooldown
  behavior has a local baseline but needs broader operational hardening before
  wider use.
- Auth v2 remains explicit opt-in and uses explicit credential hints; blinded
  lookup is research-only. Servers can require v2 after migration with
  `auth.v2.require`, but this is still not anonymous credential lookup.
- Default server egress policy blocks loopback, private, shared, link-local,
  multicast, unspecified, IPv4-mapped IPv6, deprecated IPv4-compatible IPv6,
  and well-known NAT64-embedded internal relay targets. Authenticated proxy
  egress remains a sensitive deployment surface if operators relax those
  defaults.
- ECH handshakes remain pending behind explicit readiness blockers. Runtime
  cover traffic is experimental, off by default, and not a traffic-analysis
  resistance claim.
- A controlled approved-VM TUN/route/namespaced-DNS apply rollback smoke has
  passed, and a core runtime plan model plus read-only CLI plan reporting and
  approval-boundary manifest exist. Namespace-scoped default-route/DNS policy
  smoke, service-manager lifecycle smoke, and leak/coexistence smoke have also
  passed. Full-helper aggregate smoke has passed for the current prototype
  scope, but this remains an experimental prototype and not a production
  full-device TCP/IP relay.
- GUI/tray app runtime remains behind explicit runtime-readiness diagnostics
  and `docs/history/manifests/gui-runtime-blockers.json`; the initial scope is macOS-first local
  loopback client control, and the SDK now includes a loopback-only GUI
  lifecycle wrapper, native profile secret storage backend, and read-only TUN
  readiness diagnostics. A headless local GUI-facing SDK smoke is covered by
  the harness, but no shipped GUI application lives in this repository. The GUI
  scope still forbids system proxy, DNS, route, firewall, VPN, other
  network-service settings, or privileged TUN mutation.
- HPKE, Noise, and ML-KEM are disabled registry entries and are not default
  transport choices. Noise now has a feature-gated core runtime session
  harness, but product config exposure remains deferred until a separate
  product transport decision explicitly exposes it.
- Redacted key inventory is diagnostic only; it does not validate external
  secret-manager state or prove that deployed secrets were rotated correctly.
- Rotation lint is read-only and does not generate, distribute, or safely store
  replacement client secrets. Client next-credential switching only selects
  already configured local material and does not distribute secrets or rewrite
  config files.
- Only the narrow `maverick-tls-h2-cli-v1` scope is frozen for v1.0.0. The
  implementation registry and frozen conformance metadata do not make a
  production, formal-audit, anonymity, censorship-resistance, standardization,
  or browser-fingerprint-equivalence claim.
- The security review package manifest only validates review input paths and
  disclaimers; it is not a completed review.
- Experimental tracks other than H3, the approved-host Cloudflare WebSocket
  carrier, the default-off Phase 1 product TUN runtime, and the feature-gated
  core Noise session harness are design-only or config-gated; the CLI listing
  is diagnostic and does not enable them.
- Remaining external or deferred roadmap blockers are tracked historically in
  `roadmap-blockers.json`; its checker is metadata validation, not runtime
  proof, and is no longer part of the default local gate.
- Hygiene scans are guardrails for this repository, not a substitute for
  external review of dependencies, release artifacts, or deployment scripts.
- Remote VM harness coverage is still loopback-only by default. Optional public
  probes are explicit and temporary; local-origin public tests only prove the
  local workstation's effective egress path and may include proxy exits.
  Broader public-port, WAN, UDP, DNS, TUN, or service-manager tests require
  separate per-test approval.

## Standing Maintenance Checklist

This is not a second execution plan. Current milestone order and new
development work come only from `docs/PLAN_POST_V1.md`.

1. Keep H2 fallback covered after any transport, auth, or shaping change.
2. Keep runtime cover traffic off by default and review budget/metrics behavior
   before broader private-mode claims; add native ECH handshake support only
   when server-side TLS support is practical, and use a separately named
   Cloudflare-fronted mode for the WebSocket carrier.
3. Keep shape-lab output loopback-only and diagnostic until runtime shaping is
   implemented and separately reviewed.
4. Keep TUN testing synthetic locally; use approved VMs for any actual TUN
   device, route, or DNS mutation.
5. Keep all crypto experiments behind build/runtime gates and require known
   test vectors before runtime use.
6. Build conformance vectors before making any frozen spec or standardization
   claim.
7. Keep `maverick experimental list` aligned with
   `docs/EXPERIMENTAL_TRACKS.md` as experiments move between research,
   config-gated, and runtime states.
8. Keep claim and host-network-safety hygiene current when adding scripts, CI,
   or Rust code that launches external commands.
9. Use the remote VM harness before moving any experimental transport or
   platform work from local-only baselines toward externally reachable tests.
