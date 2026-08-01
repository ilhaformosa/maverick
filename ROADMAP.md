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

No product-code slice is queued.

The failed Beta.3 release-only transition is no longer queued. The sole queued
slice is the minimal recovery diagnostic authorized in `STATUS.md`: first merge
this two-document governance record, then use a separate diagnostic PR to add
privacy-safe fixed failure-stage classifications to the existing CycloneDX SBOM
generator, cover them with regression tests, and obtain exact SBOM-generation
evidence in ordinary macOS pull-request CI. This is an execution queue, not a
completion ledger, and it does not create a receipt, seal, registry,
coordinator, or successor release framework.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Merge the recovery authorization alone.** Use a two-document governance
   PR and merge only its exact checked head.
2. **Use a separate diagnostic PR.** Make only the authorized fixed-stage and
   regression changes, obtain ordinary macOS CI evidence for exact SBOM
   generation, and merge only after independent review finds no blocker.
3. **Decide from the real failure stage.** Use the newly visible fixed stage to
   decide the smallest correction; do not guess that the failure was transient
   or deterministic. If correction requires source or workflow changes, the
   existing Beta.3 tag cannot move, and any future publication requires a new,
   separately owner-authorized version decision, with Beta.4 only a candidate.
   This slice does not authorize that publication.
4. **Keep stronger supply-chain claims deferred.** Provenance and attestation
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
