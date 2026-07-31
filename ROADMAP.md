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

### T018b-1 — Pin the ordinary Rust toolchain

- **User result:** Ordinary local development, product CI, pilot release, and
  supply-chain jobs select Rust `1.97.1` exactly instead of following a moving
  `stable` toolchain. The scheduled parser-fuzz job remains an explicit,
  isolated exception on `nightly-2026-07-21` with `cargo-fuzz 0.13.2`.
- **Scope:** Add one minimal root toolchain file with Rust `1.97.1`, `rustfmt`,
  and Clippy; select that exact toolchain in every ordinary Rust installation
  step; make toolchain changes trigger the supply-chain pull-request job; and
  make every fuzz Rust and Cargo command explicitly select its pinned nightly.
  This repository-local slice is not tied to a release version.
- **Acceptance:** The repository root resolves `rustc` and Cargo to `1.97.1`;
  all existing root and fuzz locks remain unchanged under locked offline
  metadata; formatting, builds, tests, Clippy, rustdoc, product smoke, the
  complete Beta.2 ↔ Beta.1 compatibility matrix, and both bounded fuzz targets
  pass on their selected toolchains. Static workflow checks prove the existing
  action SHAs and permissions are preserved, ordinary jobs do not float on
  `stable`, supply-chain paths cover the toolchain file, and fuzz commands
  cannot inherit the root pin.
- **Out of scope:** An MSRV declaration, `rust-version`, dependency or lock
  changes, source formatting fixes, product/API/schema/version changes,
  release assets, SBOM, provenance, signatures, CI dispatch, publication,
  deployment, and any claim that all of T018 is complete.
- **Stop conditions:** Stop if Rust `1.97.1` or its required components are
  unavailable, the selected toolchain requires a source or lock change, the
  fuzz nightly or `cargo-fuzz` pin is unavailable, a gate can pass only through
  a scope expansion, or completion requires release, secret, permission,
  product, network, or host changes.

## Execution Order

1. **Fix only reproduced Beta failures.** After Beta.2, use the smallest local
   reproduction and repair for a failure that a Beta user or an authorized
   field run actually observes. Preserve destination-free diagnostics and the
   existing privacy boundaries. Do not add speculative transports, tuning,
   orchestration, or connection-health machinery merely because Beta has
   started. A product-binary change requires a new reviewed Beta artifact; a
   documentation-only clarification must not pretend to be a product fix.
2. **Validate the Stable candidate on a fresh origin.** Before any Stable
   decision, obtain separate authorization for one freshly provisioned clean
   temporary origin and repeat artifact verification, from-scratch installation,
   ordinary browsing, and the applicable reliability and compatibility checks
   using the exact Stable-candidate artifact. The origin must pass the current
   host policy and every recorded stop rule. A retained reference origin or
   Beta result cannot replace this clean-origin gate, and this roadmap item does
   not itself authorize a server, provider change, spending, network change, or
   Stable claim.
3. **Track native server-side ECH upstream.** Keep the current provider-fronted
   path labeled as a workaround, not ECH. Do not fork rustls or vendor an
   unmerged ECH patch in the current plan.

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
