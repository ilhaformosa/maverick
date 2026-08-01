# Maverick Roadmap

Status: user-first reset.

## Current Milestone

The sole milestone and its pass conditions live in `STATUS.md`. This document
only orders work; it does not restate current completion or audit status.

## Planning Input Rule

Design drafts and reconciliation notes are non-authoritative planning inputs.
When they conflict, `STATUS.md` alone controls current truth and authorization,
while `ROADMAP.md` controls execution order. Only a minimal slice placed here
enters execution; every other proposal remains deferred, neither automatically
adopted nor automatically rejected.

## Current Repository-Local Queue

The only queued repository-local slice is the local Beta.3 release candidate:

- audit the actual Beta.2-to-current-source net change and write one public,
  version-specific release note;
- update only the workspace package version and its two lockfile copies;
- make the tag-driven release workflow reject a missing, mismatched, unsafe, or
  invalid version-specific release note; and
- complete local gates plus one ignored Apple Silicon candidate-artifact check,
  then stop on a clean local branch for independent review.

This slice changes no product behavior, protocol, config, authentication,
frame, URI, or stored-profile schema. Local checks and candidate output do not
change the product truth in `STATUS.md`.

## Execution Order

1. **Prepare and independently review the local Beta.3 candidate.** Complete
   only the release-only queue above and stop after the local candidate is
   clean and reviewable.
2. **Require a new owner decision before publication.** This stage does not
   authorize push, pull request creation or update, Ready status, merge, tag,
   release, upload, deployment, or any real-network or system-network action.
   A formal tag and release require the owner to give explicit authorization in
   the parent task after independent review.
3. **Keep stronger supply-chain claims deferred.** Provenance and attestation
   need an explicit identity and remote-permission design; signatures need a
   trust-root and key-custody decision; reproducible builds need a separate
   byte-for-byte build experiment. An SBOM is not any of those things.

## Work Explicitly Stopped

- No Phase 3 recovery, replacement, or renamed certification loop.
- No new receipt, seal, registry, watchdog, evidence schema, or dynamic
  orchestration framework.
- No HPKE, Noise, ML-KEM, multi-hop, no-domain, governance, standardization, or
  broad ecosystem work without a reproduced Beta need and an explicit
  compatibility and security decision.
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
- Beta baseline passed -> accept privacy-safe feedback, but do not recruit
  another user or widen platform, protocol, packaging, or governance scope
  without a separate owner decision.

The Maverick protocol version, config version, and stored-profile schema
version remain `1` for the published Beta.2 release; existing authentication
and frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
