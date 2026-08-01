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

The active queue is only the owner-authorized Beta.4 candidate, publication,
independent public verification, and final fact update. The immutable failed
Beta.3 tag is not retried or reused. This is an execution order, not evidence
that Beta.4 already exists, and it does not create a receipt, seal, registry,
coordinator, or successor release framework.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Prepare and review Beta.4.** Validate the minimal six-file candidate:
   workspace version, root and fuzz lockfiles, `STATUS.md`, `ROADMAP.md`, and
   the complete version-specific release note. Push it through one Draft pull
   request, all required checks, and independent review, then merge only the
   exact reviewed head. Do not add product or release-workflow changes.
2. **Publish once, fail closed.** After the Beta.4 candidate merges and every
   pre-tag fact is proved, create one annotated `v1.2.0-beta.4` tag directly on
   the exact reviewed candidate merge commit while it is current main, push
   only that tag, and allow the existing workflow to publish the digest-bound
   release note and exact six assets. Never move a failed tag, rerun its failed
   workflow, or create or replace its Release or assets.
3. **Verify before recording success.** Independently download and verify the
   public tag, release metadata, exact assets, checksums, SBOMs, source
   revisions, targets, and native artifacts. Only afterward update `STATUS.md`
   to record a successful Beta.4 publication.
4. **Record only proved facts.** If public verification succeeds, use one final
   two-document pull request to record Beta.4 as current published truth and
   clear the release queue. Do not turn local or CI evidence into a user result.
5. **Stop for alternatives if needed.** Any unresolved candidate, tag,
   workflow, or public-asset failure stops without an automatic Beta.5 or a
   different publication mechanism.
6. **Keep stronger supply-chain claims deferred.** Provenance and attestation
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
version remain `1` in both the published Beta.2 release and the Beta.4
candidate; existing authentication and frame wire formats are unchanged. Any
future version or wire-format change requires an explicit compatibility
decision based on observed user need.
