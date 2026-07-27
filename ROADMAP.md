# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Execution Order

1. **Decide whether to publish the local Alpha.5 candidate.** If approved, use
   one pull request, only the required CI gates, and one release workflow. Do
   not start duplicate or speculative GitHub Actions runs.
2. **Request one short, bounded Alpha.5 owner retest.** Re-time a clean install,
   collect only the documented aggregate diagnostics, and check video playback,
   slow images, and lingering page-load completion. A new live run, provider
   change, origin, or spend requires new explicit authorization.
3. **Choose only the next evidence-supported reliability fix.** Use the retest
   and aggregate counters to decide whether another bounded change is justified.
   Do not bundle a multi-connection H2 pool or every remaining hypothesis
   without evidence.
4. **Decide whether Beta is justified.** Enter Beta only if a clean default
   install beats five minutes and the important browsing failures are either
   gone or understood with an acceptable documented boundary. Otherwise remain
   Alpha and fix only the next reproduced cause.
5. **Track native server-side ECH upstream.** Keep the current provider-fronted
   path labeled as a workaround, not ECH. Do not fork rustls or vendor an
   unmerged ECH patch in the current plan.

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
