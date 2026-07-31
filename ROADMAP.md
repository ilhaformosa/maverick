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

### T019d — Verify Linux published-artifact upgrade and rollback parity

- **User result:** The exact published x86-64 Linux Beta.1 and Beta.2 archives
  receive the same upgrade and rollback exercise as the published Apple
  Silicon archives, on their native supported platform.
- **Scope:** Reuse the existing N-1 drill with target-bound archive sizes and
  SHA-256 identities. Download only the four public Linux release files in the
  one-time pull-request-only read-only Ubuntu job, then exercise them with GNU
  tar and native execution in an isolated private temporary root.
- **Acceptance:** Verify both checksum layers, source/version/target metadata,
  x86-64 ELF identity, `version`, loopback-only `user-smoke`, known version-1
  configurations, the Beta.1-permissive/Beta.2-strict unknown-key boundary,
  failed-preflight selection preservation, Beta.1 to Beta.2 upgrade, Beta.1
  rollback, unchanged inputs and fixtures, bounded processes, and cleanup.
  The unchanged default invocation must still pass the published macOS drill.
- **Claim boundary:** This is published-artifact compatibility evidence, not a
  source build, candidate artifact, installer, updater, service manager,
  deployment, product or user result, release result, or broad Linux support
  claim.
- **Stop conditions:** Stop on any tag, release, asset, size, checksum, source
  revision, architecture, published behavior, or baseline drift. Stop if the
  drill needs a secret, write permission, release workflow, asset upload,
  product-code change, or host-network change.

## Execution Order

1. **Finish and independently review T019d locally.** Keep the change to the
   shared drill, this execution order, and one temporary read-only pull-request
   workflow.
2. **Produce the native Linux evidence once.** Only after the separate review
   gate, push the exact cumulative branch and create the separately authorized
   Draft PR. The workflow must hard-check that exact same-repository head
   branch and commit before downloading the four fixed public release files.
3. **Remove the temporary trigger after review.** A separate owner instruction
   is required before the cleanup commit deletes the one-time workflow. Do not
   mark Ready, merge, tag, publish, upload an asset, deploy, or change a host
   network as part of T019d. Every future run needs new owner authorization;
   this ordering grants no standing remote permission.
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
