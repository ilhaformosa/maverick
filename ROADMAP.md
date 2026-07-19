# Maverick Roadmap

Status: public `main` contains the frozen `v1.2.0-alpha.1` development
candidate, but that candidate is parked after Phase 3 closed incomplete with a
final `NO_GO` decision. Pre-publication `v1.1.0` remains the latest completed
stable engineering boundary. The active execution source is
`docs/PLAN_POST_V1.md`.

## Current Direction

Maverick's current direction is preservation and a bounded integration reset:

1. preserve the completed `v1.1.0` engineering boundary and accepted narrow
   post-v1 evidence;
2. keep the frozen `v1.2.0-alpha.1` candidate and Phase 3 records immutable;
3. do not resume paid server work under the Phase 3 name;
4. preserve the passed local-only Integration Recovery Program controller gate
   without treating it as a product result;
5. return to servers only through a new exact owner decision with fresh inputs,
   limits, resources, acceptance rules, and harmless calibration on both hosts
   before product upload;
6. defer broader ecosystem, audit, deployability, and production work until a
   complete integration result justifies it.

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
`maverick-reference-client` Debian service package on Ubuntu 26.04 LTS `amd64`,
IPv4, using TLS 1.3 plus HTTP/2.

The candidate is frozen, parked, and not approved. Phase 3 closed without an
accepted two-host product result. Formal platform evidence would still need to
come from a source-bound disposable Ubuntu 26.04 fixture, not from a physical
host running another OS. `production-readiness.json` separately tracks
code-complete, evidence-complete, audit-complete, deployable, and
production-ready states; the final Phase 3 decision is No-Go.

Its planned identity is release train `1.2.0`, release tag
`v1.2.0-alpha.1`, Maverick and reference-client software
`1.2.0-alpha.1`, and Debian package `1.2.0~alpha.1-1`. Those names do not
freeze commits, the SDK pin, a package hash, evidence, or approval.

## Phase 3 Closeout

Phase 3 ended incomplete on 2026-07-19. Its final bounded rehearsal built the
rehearsal server and verified the signed client package, but stopped at a
controller readiness race before client installation. The positive path,
expected rejection, restart recovery, and purge path were not exercised, and
the planned follow-up acceptance did not start.

This is a tool-sequencing failure, not a demonstrated protocol or package
failure. It is also not a product pass. The frozen candidate remains No-Go; no
tag, package publication, production audit, deployment approval, or release is
authorized. See `docs/PHASE3_CLOSEOUT_AND_RECOVERY.md` for the preserved
evidence boundary and the conditions for any separate successor program.

The independent IRP-0 local controller gate has since passed delayed-start,
never-ready, early-exit, interruption, cleanup, strict classification, and
unreached-transition checks. No server action is authorized by that tool
result. See `docs/IRP_CONTROLLER_QUALIFICATION.md`.

## Active Milestones

The detailed gates are in `docs/PLAN_POST_V1.md`:

- M1: planning truth and three-layer public CI;
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
  cross-platform clients, and production readiness remain open. Phase 3 itself
  is now closed incomplete: its server-first engineering rehearsal did not
  reach client installation or the product smoke path, and no follow-up
  acceptance started. The separate IRP-0 local tool gate has passed, but any
  future server work still requires a fresh exact owner decision. IPv6 is not
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
