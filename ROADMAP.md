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

### T018b-2 — Gate target-aware CycloneDX sidecars

- **User result:** A future pilot release can carry one CycloneDX JSON 1.5
  sidecar for each shipped target. Each sidecar describes the actual
  `maverick-cli` default-release runtime dependency closure for that target,
  instead of pretending that one workspace-wide list fits both binaries.
- **Scope:** Pin `cargo-cyclonedx` 0.5.9 and generate two deterministic files:
  `maverick-<version>-pilot-x86_64-unknown-linux-gnu.cdx.json` and
  `maverick-<version>-pilot-aarch64-apple-darwin.cdx.json`. Run the stock tool
  in a private identity-neutral `git archive` snapshot, select the single
  `maverick` binary document by its JSON identity and target, normalize all
  references together, reject private paths, and compare the result with
  locked offline Cargo metadata. The package declares Apache-2.0; its upstream
  derived-MIT acknowledgement remains part of the tool's governance history.
- **Acceptance:** Each target generates twice byte-for-byte identically; the
  structural verifier checks the minimal CycloneDX 1.5 contract without
  claiming full JSON Schema validation; full verification proves the locked
  normal/runtime closure has no dev, build, test, or unrelated workspace
  component. The sidecars stay outside the unchanged seven-entry archive.
  A future release gate accepts exactly two archives, two archive checksums,
  and two sidecars, rechecks all six byte identities, and never executes a
  downloaded binary in the publish job.
- **Claim boundary:** This slice does not rewrite published Beta.1 or Beta.2,
  complete all of T018, prove that dependencies are vulnerability-free, prove
  link-time composition or complete native/C/C++/system/toolchain coverage,
  attest provenance, make the binary reproducible, or provide a cryptographic
  signature. It adds no archive-digest property: matching version, target, and
  revision plus the exact six-file release gate bind each archive to its
  sidecar.
- **Stop conditions:** Stop if the stock tool cannot isolate the shipped CLI
  runtime closure, if a manifest or lock must change, if the archive contract
  must change, if a permission or remote action is needed, or if the bounded
  implementation needs an eighth file.

## Execution Order

1. **Finish T018b-2 locally.** Add and verify only the target-aware CycloneDX
   generator, shared verifier, focused negative tests, and the two existing
   release workflows plus local harness wiring described above.
2. **Run T019d Linux published-artifact parity separately.** A native Linux
   published-artifact drill still needs its own owner authorization for push
   and GitHub Actions dispatch. This roadmap item grants neither.
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
