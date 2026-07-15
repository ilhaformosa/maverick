# Maverick Roadmap

Status: public `main` targets `v1.2.0`. Pre-publication `v1.1.0` is the latest
completed stable engineering boundary, and the active execution source is
`docs/PLAN_POST_V1.md`.

## Current Direction

Maverick's next work is depth before breadth:

1. measure client TLS/H2 fingerprint differences and server active-probe
   differences;
2. reuse H2 connections without changing the frozen v1 frame/auth formats;
3. improve browser TLS and fallback behavior only against measured baselines;
4. collect detailed two-host evidence;
5. decide whether application fallback, a trusted CDN path, or handshake-layer
   forwarding is the right architecture;
6. advance from the accepted narrow IPv4 TUN evidence to one gated IPv4
   reference client before broader ecosystem integration.

The long-term destination remains an open protocol with independent
implementations, standardization work, and community governance. Those tracks
follow real usage and external review rather than preceding them.

## Current Release Truth

The shipped `v1.1.0` scope remains `maverick-tls-h2-cli-v1`:

- CLI-managed Rust client and server;
- TLS 1.3 plus HTTP/2 as the default carrier;
- local SOCKS5, DNS, and HTTP CONNECT inputs;
- authenticated TCP, DNS, and documented UDP relay;
- replay protection, resource bounds, fallback behavior, and loopback metrics;
- optional experimental carriers and cryptography remain outside the default
  release claim.

Maverick is not formally audited or production-ready. It does not claim
anonymity, censorship resistance, browser-fingerprint equivalence, perfect
active-probe indistinguishability, or standardization.

Only the narrow `maverick-tls-h2-cli-v1` scope is stable. Published releases
remain immutable while later behavior evolves through explicit
compatibility and release decisions.

## Narrow v1.2.0 Production Candidate

The smallest production claim Maverick may try to earn is
`maverick-linux-h2-ipv4-v1`: the `maverick` server/CLI and
`maverick-reference-client` Debian service package on Ubuntu 24.04 LTS `amd64`,
IPv4, using TLS 1.3 plus HTTP/2.

The candidate is not frozen or approved. Formal platform evidence must come from
a source-bound disposable Ubuntu 24.04 fixture, not from a physical host running
another OS. `production-readiness.json` separately tracks code-complete,
evidence-complete, audit-complete, deployable, and production-ready states; the
current decision is No-Go.

## Active Milestones

The detailed gates are in `docs/PLAN_POST_V1.md`:

- M1: planning truth and budget-aware CI;
- M2: reproducible fingerprint and active-probe measurement;
- M3: backward-compatible H2 connection reuse;
- M4: browser TLS correctness and evidence;
- M5: active-probe and fallback hardening;
- M6: layered two-host evidence accepted for the tested direct TLS/H2 path;
- M7: handshake/fallback decision accepted after M6 closure;
- M8: Phase 2 is accepted for the tested approved-host IPv4 matrix. Phase 3's
  separate Linux CLI/service project has the SDK/controller, strict helper
  boundary, journaled IPv4 platform transactions, encrypted service
  credentials, packaging, and historical lifecycle evidence. An attempted
  sustained run exposed that the earlier global-capture policy could intercept
  unrelated management and service traffic. The corrected local implementation
  scopes capture to a second dedicated UID, adds a fail-closed fallback guard,
  runs captured applications in connection-bound units with private DNS, and
  blocks rollback through an application-session lock. Root-only atomic
  systemd-credential import and connected SDK/TUN health rollback are also
  complete. Legacy journals remain recovery-only. Exact reference commit
  `2978aa0` passes the fresh bounded installed traffic, route isolation,
  TUN-loss restart, route-loss fail-closed, package install/purge,
  credential-host-key posture, and zero-residue matrix. Its current package also
  passes release-key signing, independent verification, active upgrade,
  downgrade rejection, failed-upgrade containment, valid retry, reconnect,
  purge, and independent zero residue. The current integrated SDK/reference
  runtime candidate adds stricter IPC/recovery, credential policy, packet-FD
  coverage, deterministic APT snapshot tooling, and per-interface compatibility
  handling. Its exact signed package passes one corrected formal eight-hour
  sustained gate with complete route/resource samples, probes, stable product
  processes, bounded resources, and zero runtime residue. The broken earlier
  attempt remains rejected and contributes no partial acceptance. A duplicate
  formal run is not required merely as insurance. Production credential-root,
  power loss, broader transitions, package publication, daily-use,
  cross-platform clients, and production readiness remain open. IPv6 is not
  scheduled.

M1-M3 are the first implementation group. M4-M6 follow after review of that
baseline. M7-M8 depend on measured results.

## Deprioritized Until Evidence Justifies Them

- HPKE, Noise, and ML-KEM runtime expansion;
- native no-domain mode;
- multi-hop;
- WebTransport-like carriers;
- plugin-system expansion;
- native server-side ECH work beyond upstream tracking;
- new governance or standardization machinery before external adoption.

Existing design documents and disabled code are retained for reference. They do
not become active merely because they already exist.

## Invariants

- Preserve the project and protocol name Maverick.
- Preserve H2/TLS as a tested compatibility path.
- Never use 0-RTT for authenticated tunnel setup.
- Keep experimental carriers and cryptography feature-gated.
- Keep secrets, authentication tags, payloads, TLS key material, and private
  evidence out of logs and public artifacts.
- Keep memory, buffers, replay caches, connections, streams, and flows bounded.
- Do not mutate the development machine's proxy, DNS, routes, firewall, VPN,
  interfaces, or other network-service state.
- Do not strengthen a security or privacy claim without matching reproducible
  evidence and appropriate review.

## Version Policy

- `v1.1.x` is maintenance-only and preserves the completed backward-compatible
  M1-M8 implementation and evidence scope.
- The current `main` branch targets `v1.2.0`: one IPv4 reference client and
  broader product lifecycle evidence without changing protocol,
  authentication, or config version 1.
- No incompatible major release is currently planned. Any future proposal
  would require a separate compatibility, migration, and security decision.
- The public train is gated in order as `v1.2.0-alpha.1`,
  `v1.2.0-beta.1`, `v1.2.0-rc.1`, and `v1.2.0`; stages do not pass merely
  because time elapsed. See `docs/RELEASE_GATES_V1_2.md`.

IPv6 has no short-term, medium-term, or current long-term milestone. Existing
experimental code may remain, and future support can be reconsidered through a
new explicit decision.

The old v1-v6 labels in earlier revisions described internal experimental
baselines, not shipped semantic versions. Git history, `docs/CAPABILITY_REPORT.md`,
and focused design documents retain that engineering history without presenting
it as the current release plan.
