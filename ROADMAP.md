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

### T013b-2 — production direct auth-v3 core primitive

- **User result:** Give future client, server, H2, and H3 runtime slices one
  shared production core primitive for the frozen 256-byte `ClientControl` and
  320-byte `ServerConfirmation`, so they cannot grow separate codecs or treat
  wire claims as trusted connection facts.
- **Scope:** Add one stateless `maverick-core` auth-v3 module with fixed-length
  encoding, strict parsing, and verification against an independent trusted
  direct-connection context and exact locally provisioned credential tuple.
  Export the minimal additive API from `maverick-core`; its input structs use
  constructors instead of public field literals, and its public enums are
  non-exhaustive so callers keep a fallback match arm as trusted facts and
  fixed categories evolve. Extend the existing conformance test so its
  independent T013b-1 oracle remains the external ruler for all four golden
  vectors and the complete negative matrix. Change exactly `ROADMAP.md`,
  `crates/maverick-core/src/auth_v3.rs`,
  `crates/maverick-core/src/lib.rs`, and
  `crates/maverick-core/tests/conformance_vectors.rs`.
- **Acceptance:** The production encoder equals all four checked-in JSON
  messages byte for byte; production parse/verify passes all four positives and
  rejects malformed, unknown, mismatched-context, wrong-credential, unsafe
  time/expiry/limit, changed-transcript, replacement-exporter, and legacy
  inputs. The independent oracle remains separate. Existing v1/v2 bytes and
  their legacy exporter label remain unchanged. Locked offline core tests,
  formatting, strict core lint, warning-free core docs, user smoke, local
  harness, final file audit, and privacy gates pass; `STATUS.md`, Cargo files,
  the frozen specification, and all four auth-v3 JSON files remain unchanged.
- **Out of scope:** Runtime enablement or dispatch; atomic generation slots;
  duplicate-control, close, no-state-transfer, or no-fallback enforcement;
  connection/admission expiry timers; revocation; session, reconnect, target,
  flow, or data-plane work; credential provisioning, registry construction, or
  trusted local exact-profile selection; fronted authentication; release scope;
  CI, publication, remote, or real-network work. Wire-driven profile selection
  and trying multiple PSKs are forbidden. Direct H2/H3 runtime integration
  remains blocked until the later T013c-1 trusted provisioning/selection slice
  is complete. A production core primitive is not runtime enablement, a
  peer-confirmed product result, release scope, or PQ proof. T015/PQ remains
  `DEFER`.
- **Stop conditions:** Stop if this needs a fifth file, Cargo or lockfile change,
  new dependency, specification or vector change, v1/v2 reinterpretation,
  runtime wiring/state, a second client/server codec, loss of the independent
  test oracle, a protocol contradiction that cannot be resolved inside the
  four-file slice, or private data in the diff.

This slice is not tied to a release version and does not define release scope.

Public CI provides quality evidence only. In particular, Linux/GNU-tar checks
can close a platform-evidence gap, but they are not a product result, user
result, release result, or publication authorization.

## Execution Order

1. **Wait for a concrete input.** Accept privacy-safe Beta feedback, a
   reproduced failure, or an explicit owner-defined minimal task. Do not infer
   a new product, release, deployment, or real-network authorization.
2. **Define one smallest slice.** Before implementation, put its user result,
   file scope, acceptance checks, out-of-scope boundary, and stop conditions in
   this queue. Preserve `STATUS.md` as the sole current-truth and authorization
   source.
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
version remain `1` in the published Beta.4 release; existing authentication and
frame wire formats are unchanged. Any future version or wire-format change
requires an explicit compatibility decision based on observed user need.
