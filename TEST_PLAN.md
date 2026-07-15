# Maverick Test Plan

This file describes what the default CI/local harness actually verifies.
Current product claims live in `STATUS.md`.

## Default Local Gate

Run:

```sh
./scripts/local-harness.sh
```

The default gate is local-only. It must not change system proxy, DNS, route,
firewall, VPN, interface, or other host network-service settings.

## What The Gate Runs

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p maverick-client --features tun-runtime --lib`
- `cargo test -p maverick-tests --features tun-runtime --test tun_packet_runtime`
- `cargo check -p maverick-tests --features tun-phase2 --bin maverick-tun-phase2`
- `./scripts/conformance.sh`
- `./scripts/fuzz-smoke.sh`
- generated client/server config validation
- config migration dry-runs
- credential-rotation dry-run
- config URI export/import dry-runs
- local TUN plan/helper dry-run checks
- machine-checked TUN engine pins, license/resource decisions, isolated feature
  set, and redacted aggregate comparison records
- machine-checked Phase 1 packet-runtime dependency, gate, API, safety, test,
  and documentation boundaries
- machine-checked Phase 2 Linux TUN ioctl isolation, exact dependency, feature
  gate, device-name validation, timestamped events, and exhaustive runtime
  snapshot surface
- repo hygiene scans for log secrecy, public claims, issue templates, and
  host-network safety

## Core Unit Coverage

- frame encode/decode, malformed lengths, unknown types, fuzz corpus smoke
- Auth v1/v2 hello encode/decode, transcript binding, TLS channel-binding
  feature-flag HMAC coverage, credential hint bounds, accepted epochs, replay
  windows, and downgrade gates
- config validation for loopback defaults, log redaction, Auth v2 require mode,
  shaping budgets, ECH gates, CDN-fronted carrier gates, browser TLS feature
  gates, crypto policy, TUN safety, and egress policy
- replay cache per-credential entry bounds, out-of-order expiration, and
  per-shard credential-key bounds
- padding, pacing, batching, and cover-padding budget decisions
- TUN route planning, safety gates, synthetic packet classification, and
  readiness blockers
- isolated dual-stack packet-engine primitives for TCP/UDP mapping, malformed
  input, checksums, MTU and queue admission, half-close/reset/timeout,
  retransmission, reordering, duplicate suppression, backpressure, UDP
  saturation, and the explicit 100-flow bound
- selected packet-runtime config validation plus dual-stack TCP, DNS/generic
  UDP, half-close/reset/refusal, backpressure, forced shutdown, read/write
  failure, EOF/panic, family/MTU/admission, response-size, connector-resource,
  queue/task/buffer, and quiescence coverage
- full-duplex TCP relay regression with an echoed payload larger than both
  directional buffers, proving upload and download backpressure cannot
  deadlock each other
- packet queue snapshot normalization proving current and peak ingress/egress
  depths never exceed the underlying bounded-channel capacity
- client transport scheduling, tunnel handshake boundaries, session frame
  handling, UDP response handling, SOCKS5 parsing, HTTP CONNECT parsing, and
  DNS flow-limit behavior
- client H2 connection-pool shutdown state and bounded maintenance intervals
- server fallback behavior, reverse-proxy method/path/body/header preservation,
  rate limiting, user lookup, egress policy, relay idle timeout, IPv6 relay
  paths, connection caps, H2 concurrent stream caps, fallback overload
  handling, and H2 acceptor ALPN
- SDK builders, profile metadata, loopback runtime lifecycle, GUI diagnostics,
  read-only GUI TUN state, and coarse helper-journal recovery state with
  reconnect eligibility and serialization redaction
- versioned platform-helper IPC message bounds, fixed operations and journal
  path, strict identifiers, top-level and nested unknown-field rejection, and
  response-state consistency
- unprivileged reference-client lifecycle ordering, 32-cycle repetition,
  retained-journal recovery, partial-start rollback, stop/rollback failure,
  startup-health rejection, connected runtime-health rollback, response-ID
  mismatch, uncertain apply transport/protocol recovery, authoritative clean
  rejection, runtime-stop failure blocking reconnect until a successful retry,
  cancelled connect/disconnect recovery before and after runtime or rollback
  effects, invalid applied/recovery protocol state, invalid transition, and
  coarse-error redaction
- platform-helper IPC version-1 compatibility vectors with unique case names,
  every operation, outcome, and coarse error class, request-ID boundaries, plus
  rejected schema, version, path, recovery-reason, state, and error-shape drift;
  the finite recovery matrix covers all 4 valid and all 14 invalid combinations
  of status, reason, and helper-journal presence
- CLI config URI, key inventory, migration, rotation lint, experimental list,
  certificate pin, and TUN helper command parsing
- owner-only, host-bound, and device-bound rollback journals, including
  symlink and loose-permission rejection

## Repository Tooling Coverage

- approved-host resolution rejects aliases that resolve to loopback, a local
  interface, or the development machine before SSH is allowed
- remote evidence run identifiers, temporary paths, process ownership,
  firewall cleanup provenance, and bounded durations reject unsafe inputs
- fuzz corpus synchronization keeps every generated seed inside the target
  corpus directory
- imported cryptographic vectors must match pinned upstream document digests
- workflow actions use full commit pins and Cargo-installed CI tools use exact,
  locked versions
- source and log secrecy scans cover generic tokens, event macros, paths,
  addresses, and optional untracked private-marker input without reflecting a
  matched value; a complete credential is allowed only when it is the canonical
  public test value in its exact conformance-vector paths

## Integration Coverage

All default integration tests use `127.0.0.1` plus ephemeral ports.

- SOCKS5 TCP relay through local client, H2 tunnel, server, and echo target
- HTTP CONNECT relay
- DNS relay through fake loopback resolver
- SOCKS5 UDP ASSOCIATE relay and association reuse
- Auth v2 accepted/unaccepted/expired epoch behavior
- credential rotation active/next/previous windows
- fallback-like behavior for bad auth, malformed hello, disabled users, and
  replayed hello
- active-probing baseline checks that compare ordinary static fallback and
  reverse-proxy fallback behavior against bad-auth, malformed, and rate-limited
  tunnel-like H2 paths without protocol-specific error strings
- per-user and client-side flow limits
- global and per-source server connection limits
- fallback overload returning generic HTTP behavior without protocol detail
- TLS 1.2 rejection by the H2 server
- direct H2 authentication succeeds when client and server require TLS channel
  binding
- loopback metrics endpoint and aggregate shaping metrics
- client/server runtime padding, batching, and cover-padding semantics
- H2 window and idle-timeout regressions
- one runtime-scoped H2 connection shared across concurrent flows and local
  SOCKS5, HTTP CONNECT, DNS, and UDP frontends
- H2 pool stream-capacity timeout, server-close replacement, client idle
  retirement, authentication-failure non-retry, and aggregate counter behavior
- Cloudflare-fronted WebSocket loopback carrier behavior when explicitly
  enabled through either the compatibility flag or the first-class
  `advanced.stealth.cdn_fronting.enabled` setting
- feature-gated packet I/O through generated auth/TLS/H2 and real Maverick TCP,
  DNS, and UDP loopback paths, including one-connection H2 reuse and the
  explicit runtime-off gate

## Feature/External Gates

Feature or external-host checks are not default product claims:

- H3/QUIC has a separate feature harness and remains off by default.
- ECH is gated and native runtime ECH remains disabled.
- Browser-like TLS has a separate `browser-tls` build feature. It compiles a
  BoringSSL client path for H2 with exporter channel binding and measured
  Chrome-reference settings. `scripts/browser-tls-harness.sh` runs only for
  browser-relevant CI paths; it is not proof of exact browser equivalence.
- Approved-host TUN helper evidence is external historical safety evidence. The
  Phase 1 packet runtime has synthetic/loopback evidence, and the separate
  Phase 2 approved-host IPv4 matrix is accepted under
  `docs/TUN_PHASE2_EXECUTION_GATE.md`. Native IPv6 cases were policy-blocked and
  not exercised. This narrow namespace result does not prove product,
  cross-platform, or production readiness.
- Reference-client sustained evidence requires a fail-before-long-run canary on
  each of two approved Linux hosts using the exact sealed artifact, runner,
  analyzer, and cleanup tools intended for the formal run. Both canaries must
  prove non-empty route identity fields, exact producer/analyzer table schemas,
  complete and aligned resource rows, expected probes, provenance, and zero
  residue before an eight-hour timer may start. Independent formal runs are
  checked after 5, 15, and 30 minutes, evaluated separately, and never combined
  from partial evidence. A second-run failure may be disregarded only after it
  is proven host-specific and unrelated to product behavior, instrumentation,
  provenance, or cleanup.
- Approved-host long-haul runs retain per-iteration stage/elapsed logs, binary
  hashes, system inventory, resource/network-counter samples, full client/server
  logs, port-availability preflight results, and explicit completion markers in
  ignored private evidence storage. When explicitly enabled, the harness opens
  only an initially closed test port through an auto-expiring firewalld runtime
  rule and records that mutation in `firewall.log`.
- Approved-host netem and failure-injection runners accept the same
  commit-bound prebuilt Linux artifact path, retain binary hashes and system
  inventory, and record resource samples. Netem impairment remains limited to
  its temporary namespace/veth pair; failure injection may stop only processes
  whose recorded command belongs to that run's temporary directory.
- `scripts/s2-evidence-audit.py` reconciles summaries with event/log counts,
  verifies client/server binary provenance, checks cleanup fields and completion
  markers, validates complete and monotonic resource samples, checks long-haul
  time coverage and sampling gaps, scans for secret-like material, and writes a
  reproducible SHA-256 manifest. New runners declare child-process sampling and
  must include Maverick process rows where that declaration applies. Failed or
  incomplete collections remain available as diagnostics but cannot pass
  `--require-accepted`.
- Final acceptance also requires a successful record from
  `scripts/s2-evidence-cleanup.sh`. The cleanup tool refuses unknown temporary
  directory prefixes, unrelated or reused PIDs, active test-port listeners, and
  remaining netem namespace/veth state.
- The loopback fingerprint lab records normalized ClientHello and initial H2
  preface/SETTINGS observations without privileged packet capture. The default
  harness smokes the rustls path; browser-TLS and real-browser reference samples
  remain explicit evidence tasks.
- `scripts/check-browser-tls-baseline.py` validates the pinned five-sample
  Chrome target, expected H2 match, explained TLS residuals, supported build
  targets, and optional current browser-mimic hashes.
- The active-probe lab compares 13 deterministic H2 fallback shapes and records
  a 12-sample loopback timing distribution. H3 preserved-body fallback remains
  in the feature harness; WebSocket, HTTPS-upstream, buffering, and trailer
  differences remain explicit rather than being treated as parity.
- `scripts/check-active-probe-baseline.py` pins the scenario outcomes, coverage
  statuses, residual explanations, timing non-claim, and loopback safety scope.
- GUI smoke is GUI-facing SDK coverage only; it is not a shipped GUI app.
- blocker, approval, and review-package JSON checkers are metadata checks, not
  product behavior proofs; run them only when changing those historical
  manifests.
- Noise, HPKE, ML-KEM, blinded lookup, no-domain mode, multi-hop, governance,
  and spec-freeze work are experimental, design-only, or disabled unless a
  specific feature gate says otherwise.

## Manual Evidence

Approved-host and long-haul evidence belongs in status/release notes, not in
the default test gate. It must name what was run, where it ran, what it did not
prove, and whether it touched any host networking.
