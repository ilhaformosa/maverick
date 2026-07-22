# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Execution Order

1. **Confirm the private targets.** Privately confirm the exact provider team,
   neutral origin name, region, containing Cloudflare zone, dedicated pilot
   hostname, and access method for the owner-controlled pilot laptop. Keep
   these details out of git.
2. **Prepare the authorized route.** Within the envelope in `STATUS.md`, create
   the single origin, dedicated proxied DNS record, and H2 route, generate fresh
   credentials and configs locally, enable only the specifically authorized zone
   gRPC capability, and verify the route without changing existing DNS records,
   the zone-wide SSL mode, or host-wide networking.
3. **Time the clean install.** On the spare laptop, start from the published
   prerelease and guide. The owner performs the final timed attempt without
   developer intervention; rehearsal does not satisfy the milestone.
4. **Run the 24-hour pilot.** Use ordinary non-sensitive browsing on the named
   client path and record usability, disconnects, blocks, and probe observations
   without publishing private network or account details.
5. **Choose the next change from field evidence.** Fix the shortest observed
   failure first. Do not choose a new transport from abstract roadmap preference.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work before the first pilot.
- No production-readiness relabeling from local tests or disposable-VM package
  installation.
- No remote, paid, privileged, or host-network action outside the current
  authorization recorded in `STATUS.md`.

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
