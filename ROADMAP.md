# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Execution Order

1. **Close the named pilot decisions.** Use the hypothesis and unresolved owner
   decisions in `STATUS.md`; do not duplicate them here.
2. **Shrink the maintenance surface.** Keep eight active document entry points.
   Archive historical plans, release governance, production ledgers, Python
   coordination tools, and remote evidence runners without deleting history.
3. **Prove the product locally.** Maintain one shell entry point under 200 lines
   that runs the real loopback server/client path, proves a correct credential
   relays data, and proves a wrong credential is rejected.
4. **Maintain the selected default TLS path.** Its current implementation and
   limitations are recorded only in `STATUS.md` and the transport reference.
5. **Activate the handshake-hiding primary path.** Follow the candidate and
   trust boundary recorded in `STATUS.md`. Loopback coverage does not complete
   real-provider validation.
6. **Make a five-minute pilot artifact.** Publish one standalone CLI binary and
   short guide through the channel named in `STATUS.md`. Generate fresh configs
   on the user's machine, then ask a fresh user to time the install; developer
   rehearsal does not satisfy this step.
7. **Run one person for one day.** Only after the remaining owner decisions in
   `STATUS.md` are closed, run ordinary browsing and record usability,
   disconnects, blocks, and probe observations under that authorization.
8. **Choose the next transport change from field evidence.** If the pilot shows
   direct TLS/H2 fingerprint or probing failure, prioritize handshake-layer
   forwarding or a clearly trusted fronted path. Do not choose it from abstract
   roadmap preference.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work before the first pilot.
- No production-readiness relabeling from local tests or disposable-VM package
  installation.
- No remote, paid, privileged, or host-network action without a separately
  named owner authorization.

## After the First Pilot

Use the shortest failure-driven next step:

- install failed -> simplify the artifact;
- daily use failed -> fix reliability/usability;
- TLS fingerprint was blocked -> improve the default TLS/handshake path;
- active probe distinguished the server -> harden handshake/fallback behavior;
- pilot passed -> repeat with one additional consenting user before widening
  platform, protocol, packaging, or governance scope.

`protocol_version` and config `version` remain `1` during this reset. Any future
wire or config change requires an explicit compatibility decision based on
observed user need.
