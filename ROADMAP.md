# Maverick Roadmap

Status: the frozen `v1.2.0-alpha.1` development candidate is archived after
Phase 3 closed incomplete with a final `NO_GO` decision. On 2026-07-20 the
project retired every Phase 3 recovery route instead of starting another
server attempt. Pre-publication `v1.1.0` remains the latest completed stable
engineering boundary. The active execution source is `docs/PLAN_POST_V1.md`.

## Current Direction

Maverick's current direction is preservation after the terminal Phase 3
closeout:

1. preserve the completed `v1.1.0` engineering boundary and accepted narrow
   post-v1 evidence;
2. keep the frozen `v1.2.0-alpha.1` candidate and Phase 3 records immutable;
3. do not resume server work under the Phase 3 name or any recovery alias;
4. preserve the closed Integration Recovery Program, transport-recovery,
   remote-first, and remote-controller results without treating them as product
   results;
5. treat any future return to servers as a new candidate with a new roadmap,
   not as completion, recovery, or evidence for the frozen Phase 3 candidate;
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

The candidate is frozen, archived, and not approved. It is no longer an active
release target. Phase 3 closed without an accepted two-host product result.
`production-readiness.json` preserves code-complete, evidence-complete,
audit-complete, deployable, and production-ready as separate historical states;
the final Phase 3 decision is No-Go.

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
evidence boundary and terminal decision.

The later IRP, ITR, IRF, remote-controller, server-resource, and project-server
runs are retained only as closed history. The last project-server run created
two disposable hosts and passed both login preflights plus one harmless host
calibration. It then stopped before source upload because a root-owned mode-0600
receipt could not be read by the named login user. Exact destruction confirmed
zero hosts and keys. No recovery run reached the complete product path.

The owner and coordinator therefore retired the recovery program on
2026-07-20. There is no active Phase 3 milestone, server proposal, or successor
gate. A future productization effort must start from a newly named candidate and
roadmap and cannot retroactively change this Phase 3 result.

## Completed And Historical Milestones

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
  acceptance started. The first recovery execution package was rejected
  locally; its corrected executable revision passed the local tool gate, but
  its single integration run stopped during provider preflight before resource
  creation. A new project-level transport-recovery package was requalified
  locally, but its own single run also stopped during read-only provider
  preflight after exhausting one safe GET retry. It created no resource, ran no
  product, spent no money, and has no authorized successor. A later
  remote-first successor created exactly two disposable hosts, then stopped
  after two readiness-poll disconnects before SSH or product upload. Delayed
  exact destruction confirmed zero hosts and keys. That single run is also
  consumed with no authorized successor. IPv6 is not scheduled.

M1-M8 are retained as completed or historical records. None is an active Phase
3 or server-recovery milestone.

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
- The frozen `v1.2.0-alpha.1` candidate is archival and does not advance to
  beta, RC, stable, audit, deployment, or production work.
- No incompatible major release is currently planned. Any future proposal
  would require a separate compatibility, migration, and security decision.
- Any future release train requires a new explicit roadmap and version
  decision. Historical `v1.2.0` gates remain documented but blocked.

IPv6 has no short-term, medium-term, or current long-term milestone. Existing
experimental code may remain, and future support can be reconsidered through a
new explicit decision.

The old v1-v6 labels in earlier revisions described internal experimental
baselines, not shipped semantic versions. Git history, `docs/CAPABILITY_REPORT.md`,
and focused design documents retain that engineering history without presenting
it as the current release plan.
