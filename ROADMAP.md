# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Execution Order

1. **Complete one bounded Alpha.6 replacement diagnostic field run.** The first
   origin was rejected after its basic browsing gate failed, so its video result
   is inconclusive. A further live run, origin, provider change, or spend beyond
   the single decided replacement requires separate owner authorization. Use
   Ubuntu 26.04 LTS first; Ubuntu 24.04 LTS is an explicitly justified fallback.
   Apply every offered package and default-kernel update, reboot when Ubuntu
   requires it, and pass the host verifier before Maverick starts. Require the
   stock Ubuntu kernel's native BBR implementation (commonly called BBRv1) and
   preserve either `fq` or `fq_codel` without preferring one. Reject every other
   qdisc; do not install or maintain a custom BBRv3 kernel or run a
   congestion-control A/B. If Codex creates the replacement through a provider
   API, reject and delete that exact new resource before deployment when its
   public IPv4 first octet is `64`, then retry only inside the already approved
   resource and spend boundary. Stop and ask the owner if that boundary cannot
   produce an acceptable address. An owner-created replacement follows the
   separately communicated manual path.
2. **Isolate the remaining major-video failure with one-variable tests.** First
   compare the current Firefox profile, Troubleshoot Mode, and a clean profile;
   then record only privacy-safe player/media response categories. If needed,
   compare a separately authorized SSH SOCKS path on the same exit, followed
   by a separately authorized direct carrier. A different exit is later, not
   the first diagnosis. Do not retain signed media URLs, cookies, request
   headers, addresses, or browsing content. Any live run, origin, direct path,
   provider change, or spend requires explicit authorization.
3. **Validate recovery with measurements, not guesses.** In the next authorized
   field run, check ordinary use plus one sleep/resume cycle and collect only
   the fixed destination-free summaries. Use those numbers to decide whether
   any additional connection-health mechanism is justified. Do not add a
   second outer H2 pool or periodic heartbeat without field evidence.
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
