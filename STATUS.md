# Maverick Status

Status: public `main` is development toward `v1.2.0` and the workspace reports
software version `1.2.0-alpha.1`. The pre-publication `v1.1.0` release is the
latest completed stable engineering boundary for the compatible
`maverick-tls-h2-cli-v1` scope; its private Git objects were not imported into
public history.

## Public Description

```text
Experimental Rust privacy proxy protocol; public main targets v1.2.0 and is not audited or production-ready.
```

Do not describe Maverick as audited, production-ready, anonymous,
censorship-resistant, browser-fingerprint-equivalent, or standardized.

The frozen and parked production claim candidate is
`maverick-linux-h2-ipv4-v1`: Ubuntu 26.04 LTS `amd64`, IPv4, the `maverick`
server/CLI, the `maverick-reference-client` Debian service package, and the
stable TLS 1.3 plus HTTP/2 path. It is a target, not a completed claim. The
machine-readable result in `production-readiness.json` is the final Phase 3
No-Go.

## Working Now

- Local SOCKS5, DNS, HTTP CONNECT, TCP relay, and SOCKS5 UDP ASSOCIATE over
  authenticated tunnel frames.
- TLS 1.3 + HTTP/2 default carrier.
- Runtime-scoped H2 connection reuse across local SOCKS5, HTTP CONNECT, DNS,
  and UDP flows, with bounded stream admission, idle retirement, and reconnect.
- Optional feature-gated H3 and explicit Cloudflare-fronted WebSocket
  experiments, both off by default.
- Auth v1 default path, explicit opt-in Auth v2, replay protection, credential
  rotation staging, certificate pinning, fallback behavior, and loopback-only
  metrics.
- Static fallback and Hyper-backed HTTP reverse proxy with bounded bodies,
  preserved H2/H3 authentication-stage request bytes, and generic upstream
  failure responses.
- Server global/per-source connection caps, pre-auth admission bounds, fallback
  overload bounds, and source-IP failed-auth rate limiting.
- Stealth policy guards for active-probing resistance, unsupported
  browser-fingerprint mimicry, and explicit CDN-fronting acknowledgement.
- Bounded padding, batching, pacing, and cover-padding baselines. These are
  engineering diagnostics, not anonymity guarantees.
- Local-only harness, conformance checks, fuzz smoke, hygiene scans, and
  loopback integration tests.
- Three-layer verification is defined: local preflight, a public PR gate with
  unconditional core/docs jobs and path-scoped optional jobs, and a manual
  exact-commit release-candidate gate. The candidate gate is checks-only and
  does not tag, publish, or access the private reference client.
- Optional `tun-runtime` Phase 1 packet adapter with pinned `smoltcp 0.13.1`,
  caller-supplied packet I/O, experimental dual-stack TCP plus bounded DNS/UDP
  mapping,
  shared H2 flow limits, coarse snapshots, and synthetic/loopback tests. It is
  off by default and has no platform network-setup API.
- A separate experimental Linux reference-client project now combines the SDK
  controller with authenticated helper IPC, journaled capture-UID IPv4 TUN,
  route and private-DNS ownership, connection-bound capture, encrypted service
  credentials, and signed package transactions. Bounded installed traffic,
  crash/recovery, route/TUN fault, upgrade/rollback, purge, and independent
  zero-residue evidence is accepted for exact revisions. It is not shipped or
  production-ready.
- M8 Phase 2 approved-host IPv4 evidence through a namespace-local real TUN,
  including bounded resources, failure recovery, host-state preservation, and
  zero-residue cleanup. IPv6 was policy-blocked, was not exercised, and is not
  scheduled for product support.
- S2 approved-host runtime evidence, S3 anonymous review-input closure, and
  frozen conformance metadata for the narrow `maverick-tls-h2-cli-v1` release
  train.

## Not Ready

- No formal independent security audit has been completed.
- The frozen candidate identity is release train `1.2.0`, tag
  `v1.2.0-alpha.1`, Maverick and reference-client software
  `1.2.0-alpha.1`, and Debian package `1.2.0~alpha.1-1`. The Maverick workspace
  now reports that software version. The exact Maverick release/SDK commit,
  reference-client commit and SDK pin, package hash, and accepted Phase 3-B
  summary are recorded in `production-readiness.json`. Phase 3-A, audit,
  deployability, and production approval remain incomplete.
- Formal Ubuntu 26.04 LTS `amd64` platform evidence must come from a source-bound
  disposable target fixture; results from a physical host with another OS do not
  satisfy that gate.
- Exact-source post-freeze release-candidate CI passed, but an Ubuntu Actions
  runner is not a substitute for target-fixture and private package evidence.
- Phase 3 closed incomplete after its final bounded server rehearsal stopped at
  a controller readiness race before client package installation. Positive
  traffic, expected rejection, restart recovery, purge, and the follow-up
  engineering acceptance were not completed. This is neither a demonstrated
  protocol/package failure nor a product pass.
- The separate recovery route's readiness component passed locally, but its
  first whole execution package was then rejected before external action
  because fixed stage executables were missing. A corrected executable
  revision now passes local actual-entrypoint, partial-state, interruption,
  cleanup, destruction, and strict four-way classification checks. Its one
  authorized integration run then stopped during read-only provider preflight:
  a truncated response escaped the adapter's safe GET-retry path. No resource
  was created, no product step ran, no money was spent, and no replacement run
  is authorized.
- Native Maverick server-side ECH is not implemented.
- The Phase 2 evidence runner is not a shipped network helper or reference
  client. The separate Linux reference client has a platform route/DNS
  implementation, but sustained resources, daily use, broader transition/leak
  recovery, abrupt power loss, production credential-root protection, package
  publication, and cross-platform integration remain open. IPv6 is not a
  current milestone.
- No shipped GUI app lives in this repository. Existing GUI work is SDK,
  diagnostics, and smoke coverage only.
- Browser-like TLS fingerprinting is optional, not default. The
  `browser_mimic` mode requires a `browser-tls` build and uses a BoringSSL
  client path with exporter channel binding and pinned Chrome-reference H2
  settings. ALPS and newer signature-algorithm differences remain, so this is
  not a claim of exact browser equivalence.
- Real traffic-analysis resistance is not implemented.
- Noise, HPKE, ML-KEM, blinded credential lookup, no-domain mode, multi-hop,
  governance, and spec-freeze work remain experimental, disabled, or design
  only unless a specific feature gate says otherwise.

## Near-Term Priority

1. Preserve the accepted M6 direct TLS/H2 evidence as a regression boundary.
2. Keep the accepted handshake/fallback decision aligned with new evidence.
3. Preserve the completed fixed engine comparison and Phase 1 packet-runtime
   boundary as machine-checked regressions.
4. Preserve pre-publication `v1.1.0` as the compatible M1-M8 regression
   boundary without recreating its tag on a different public commit.
5. Preserve the Phase 3 incomplete closeout and frozen candidate without
   relabelling partial server runs as product evidence.
6. Keep remote integration work stopped. The separate Integration Recovery
   Program consumed its single run before resource creation. Any return now
   requires a new project-level decision, corrected and requalified tooling,
   fresh exact owner authorization, and harmless calibration on both fresh
   hosts before product upload.
7. Keep the production ledger at No-Go until a future project establishes
   accepted platform evidence, an independent audit, deployability, and final
   approval for one exact candidate.

See `docs/PLAN_POST_V1.md` for the governing execution order,
`docs/PHASE3_CLOSEOUT_AND_RECOVERY.md` for the Phase 3 closeout and conditional
successor boundary,
`docs/IRP_CONTROLLER_QUALIFICATION.md` for the local-only controller result,
`docs/PUBLIC_HISTORY_BOUNDARY.md` for the repository-history boundary, and
`docs/STEALTH_PRIORITY.md` for the focused stealth technical queue.

## Deprioritized

- Native server-side ECH until upstream server-side TLS support is practical.
- Post-quantum hybrids until upstream TLS support and review justify them.
- Broad TUN product/platform expansion until one reference client passes its
  selection and lifecycle gates.
- Standardization and governance work until there is a real second
  implementation or external user base. These remain explicit long-term goals,
  not abandoned tracks.

## Process Notes

- JSON blocker/approval manifests are evidence indexes, not proof of runtime
  behavior by themselves. They are not part of the default local gate.
- `TEST_PLAN.md` now describes the default gate and major coverage areas rather
  than every historical test.
- `docs/CAPABILITY_REPORT.md` is the long inventory.
- `ROADMAP.md` is a concise direction map, not evidence that a milestone is
  complete. `docs/PLAN_POST_V1.md` owns active milestone gates.
