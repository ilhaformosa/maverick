# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Execution Order

1. **Remain Alpha and fix the confirmed install default.** Disable the optional
   local DNS listener in newly generated configs, make listener failures identify
   the responsible setting, and preserve compatibility with existing configs.
2. **Add privacy-safe failure-class diagnostics.** Distinguish target DNS,
   target connection, H2 acquisition/stall/reset, and graceful-close outcomes
   without recording domains, addresses, URLs, credentials, or browsing
   content. Correct any confirmed provider-carrier protocol-completion defect
   needed to make those results trustworthy.
3. **Choose only an evidence-supported reliability fix.** Use local
   reproductions and the new aggregate counters to decide whether the next
   bounded change is target-address connection handling, a small multi-connection
   H2 pool, or another narrower cause. Do not bundle every hypothesis.
4. **Publish a later Alpha prerelease only after repository review.** Run local
   gates first, then use the minimum required GitHub checks and one release
   workflow. Do not replace or mutate the published `alpha.3` release.
5. **Request one new short, bounded owner retest.** Re-time a clean install and
   check video playback, slow images, and lingering page-load completion. A new
   live run, provider change, origin, or spend requires new explicit
   authorization.
6. **Decide whether Beta is justified.** Enter Beta only if a clean default
   install beats five minutes and the important browsing failures are either
   gone or understood with an acceptable documented boundary. Otherwise remain
   Alpha and fix only the next reproduced cause.
7. **Track native server-side ECH upstream.** Keep the current provider-fronted
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
