# Maverick Roadmap

Status: user-first reset.

## Only Milestone

One real person installs Maverick, uses it for a normal day from a real network,
and records usability plus any network-specific block or probe behavior.

Everything before that milestone is preparation. Tests and safety gates protect
the work but do not substitute for the result.

## Execution Order

1. **Name the pilot hypothesis.** Keep the first user to the owner, state the
   access-network adversary model, define the simple artifact, and list the
   field threats. The current hypothesis is in `STATUS.md`.
2. **Shrink the maintenance surface.** Keep eight active document entry points.
   Archive historical plans, release governance, production ledgers, Python
   coordination tools, and remote evidence runners without deleting history.
3. **Prove the product locally.** Maintain one shell entry point under 200 lines
   that runs the real loopback server/client path, proves a correct credential
   relays data, and proves a wrong credential is rejected.
4. **Use browser-like TLS by default.** The default supported client build and
   generated config use the BoringSSL-backed browser-like H2 path. Residual
   differences remain explicit; no browser-equivalence claim is allowed.
5. **Activate the handshake-hiding primary path.** The technical candidate is
   browser-like TLS over CDN-fronted H2; the old WebSocket carrier remains the
   rustls compatibility path. Before real restricted-network use, name the
   provider and accept its TLS-termination trust tradeoff in the pilot envelope.
   If that trust is rejected, replace it with owner-controlled handshake
   forwarding. Loopback coverage does not complete real-provider validation.
6. **Make a five-minute pilot artifact.** Produce one standalone CLI binary,
   two minimal configs, and one short start/check guide. Ask a fresh user to
   time the install; developer rehearsal does not satisfy this step.
7. **Run one person for one day.** Only after a single plain-language pilot
   envelope names the person, environment, provider or server, budget, expiry,
   allowed network changes, and handshake-hiding path, run ordinary browsing
   and record usability, disconnects, blocks, and probe observations. Do not
   require per-run hash approval.
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
