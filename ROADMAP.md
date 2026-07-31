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

### T019c — Drill the published macOS Beta upgrade and rollback

- **User result:** A local Apple Silicon Mac can exercise the exact published
  Beta.1 → Beta.2 → Beta.1 artifact lifecycle before a later release decision.
  An incompatible config blocks the upgrade while Beta.1 remains selected; a
  compatible config permits the switch and an explicit rollback restores
  Beta.1. This is a local quality drill, not a product, user, release,
  deployment, or Stable result.
- **Scope:** Add one Bash 3.2-compatible, network-free script that accepts only
  four local Apple Silicon release inputs, pins both published identities,
  verifies Beta.2 through the current native artifact verifier, narrowly
  adapts the exact fixed Beta.1 packaging, and runs the bounded private
  config/preflight/upgrade/rollback lifecycle through an isolated-directory
  selector. This selector drill is not an installer, updater, or system
  installation. The execution-only validation may download only these four
  public GitHub release assets into a private directory outside the repository;
  the script itself never downloads:
  - `https://github.com/ilhaformosa/maverick/releases/download/v1.2.0-beta.1/maverick-1.2.0-beta.1-pilot-aarch64-apple-darwin.tar.gz`
  - `https://github.com/ilhaformosa/maverick/releases/download/v1.2.0-beta.1/maverick-1.2.0-beta.1-pilot-aarch64-apple-darwin.tar.gz.sha256`
  - `https://github.com/ilhaformosa/maverick/releases/download/v1.2.0-beta.2/maverick-1.2.0-beta.2-pilot-aarch64-apple-darwin.tar.gz`
  - `https://github.com/ilhaformosa/maverick/releases/download/v1.2.0-beta.2/maverick-1.2.0-beta.2-pilot-aarch64-apple-darwin.tar.gz.sha256`
- **Acceptance:** The script verifies the fixed outer and inner release
  identities, native `version` and `user-smoke`, known-field config
  compatibility, Beta.2's fail-closed unknown-key upgrade preflight, both
  versions' rejection of config version 2, selection preservation after one
  predictable preflight failure, the successful Beta.2 selection, explicit
  Beta.1 rollback, immutable fixture and backup hashes, bounded process
  cleanup, and no retained selector or temporary directory. Linux parity stays
  deferred until a native Linux host or authorized CI can run it.
- **Out of scope:** Stored-profile migration work already covered by Rust
  tests; a stored-profile result, migration API, framework, or downgrade
  writer; installer, updater, service manager, or atomic-switch claim; system
  installation or services; Linux success inferred from macOS; real users,
  live networks, publication, tag, release, upload, deployment, Stable
  decision, receipt, ledger, watchdog, evidence schema, Python coordination,
  and changes to current product truth.
- **Stop conditions:** Stop if either input differs from its exact published
  identity, the host is not native Apple Silicon macOS, Beta.2 cannot pass the
  unchanged native verifier, Beta.1 requires an adapter broader than its fixed
  digest, the lifecycle needs a product or third-file change, or any gate needs
  network, credential, system-network, service, release, CI, or host changes.

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
