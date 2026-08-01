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

The sole queued slice is the fail-closed Beta.3 release-only transition
authorized in `STATUS.md`: merge the two-document governance record, verify the
resulting exact `main`, create and push its direct annotated Beta.3 tag, let the
existing release workflow run, independently reverify the public release, and
then record only the facts that actually passed. Any failure empties this queue
and stops for a new owner decision; it does not authorize a substitute source,
tag, asset, workflow, or retry.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Merge the authorization record alone.** Use a two-document governance PR
   and merge only its exact checked head.
2. **Bind the release to final `main`.** Re-run the local and required public
   gates on the resulting exact commit before creating any tag.
3. **Create one direct annotated tag.** Create and push only
   `v1.2.0-beta.3`, directly targeting that exact `main` commit.
4. **Use the existing fail-closed workflow.** Let `pilot-release` publish only
   the digest-bound version-specific note and the exact six authorized assets.
5. **Independently reverify the public result.** Check the tag, release state,
   note bytes, asset set, digests, archives, and target-aware SBOMs. Stop on any
   failure or fact that cannot be proved.
6. **Record facts after they exist.** If publication and re-verification pass,
   use a separate two-document PR to update current truth and empty the release
   queue. This order is not a completion ledger.
7. **Keep stronger supply-chain claims deferred.** Provenance and attestation
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
