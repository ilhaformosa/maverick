# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Execution Order

1. **Diagnose the field symptoms.** Reproduce the video-playback failure, slow
   image loading, and lingering page-load completion locally. Do not assume a
   provider or protocol cause.
2. **Remove setup friction.** Simplify the artifact or guide enough to beat the
   measured five-minute target.
3. **Make the smallest evidence-backed fix.** Change only the component shown
   to cause the problem.
4. **Track native server-side ECH upstream.** Keep the current provider-fronted
   path labeled as a workaround, not ECH. Do not fork rustls or vendor an
   unmerged ECH patch in the current plan.
5. **Request a new bounded field run only if needed.** The completed pilot does
   not automatically authorize another live test.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work before the first pilot.
- No production-readiness relabeling from local tests or disposable-VM package
  installation.
- No rustls fork or vendored unmerged server-ECH patch in the current execution
  plan.
- No remote, paid, privileged, or host-network action outside the current
  authorization recorded in `STATUS.md`.

## Failure-Driven Follow-Up

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
