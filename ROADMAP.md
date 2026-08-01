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

The active queue is the owner-authorized Beta release recovery. It first
records the widened verifier scope, then completes and merges the existing
diagnostic PR, and only after exact-main verification prepares one separately
reviewed Beta.4 candidate. This is an execution order, not evidence that a
release already exists, and it does not create a receipt, seal, registry,
coordinator, or successor release framework.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Merge the widened authorization alone.** Use a two-document governance PR
   containing only `STATUS.md` and `ROADMAP.md`.
2. **Complete PR #25.** Add only the authorized shared-verifier correction and
   focused regression coverage. Obtain ordinary PR CI and independent review,
   then merge only the exact reviewed head when no blocker remains.
3. **Reverify exact main.** Require the repaired macOS SBOM path and all
   existing required main checks to pass. CI remains quality evidence, not a
   release or user result.
4. **Prepare Beta.4 separately.** Because the fixed Beta.3 tag cannot move,
   prepare the minimal version, lockfile, current-truth, roadmap, and
   version-specific release-note changes for `1.2.0-beta.4` in a separate PR.
   Do not add product or release-workflow changes.
5. **Publish once, fail closed.** After the Beta.4 candidate merges and every
   pre-tag fact is proved, create one annotated `v1.2.0-beta.4` tag directly on
   the exact reviewed candidate merge commit while it is current main, push
   only that tag, and allow the existing workflow to publish the digest-bound
   release note and exact six assets. Never move a failed tag, rerun its failed
   workflow, or create or replace its Release or assets.
6. **Verify before recording success.** Independently download and verify the
   public tag, release metadata, exact assets, checksums, SBOMs, source
   revisions, targets, and native artifacts. Only afterward update `STATUS.md`
   to record a successful Beta.4 publication.
7. **Stop for alternatives if needed.** Any unresolved repair, candidate, tag,
   workflow, or public-asset failure stops without an automatic Beta.5 or a
   different publication mechanism.
8. **Keep stronger supply-chain claims deferred.** Provenance and attestation
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
