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

### T016b — Verify Beta.2 ↔ Beta.1 direct-H2 process compatibility

- **User result:** A maintainer can run one local command that establishes
  direct-H2 compatibility only when processes built from the exact published
  Beta.2 and Beta.1 source identities complete both client/server directions,
  auth v1 and auth v2, and both supported TLS backends. An incomplete run makes
  no incompatibility claim.
- **Scope:** Export the two local annotated tags with `git archive`, verify
  their fixed tag-object IDs, direct commit targets, tag names, package
  versions, and locks with Git replace objects disabled, then archive only the
  pinned commits and build their CLI processes with `cargo --offline --locked`.
  Run same-version positive controls before the cross-version matrix. Use only
  `127.0.0.1`, OS-assigned ephemeral ports, private temporary files, anonymous
  test credentials and certificates, and direct H2. Test the default
  browser-TLS build and the explicit `--no-default-features` rustls build.
- **Acceptance:** Beta.2 client → Beta.1 server and Beta.1 client → Beta.2
  server both relay an exact payload for auth v1 and auth v2 on each TLS
  backend. Before those eight cross-version cells run, the corresponding eight
  same-version cells pass and all four historical binaries pass build, version,
  and config preflights. Environment, toolchain, identity, build, config, or
  same-version failures stop without being mislabeled as incompatibility.
  Any other non-completing process case reports only that the matrix did not
  complete and compatibility was not established; a direct incompatibility
  claim requires separate typed protocol evidence.
  Protocol, config, auth, frame, stored-profile, and Profile URI versions remain
  unchanged.
- **Out of scope:** H3 or H3 fallback, WebSocket, provider-fronted paths,
  historical release archives, remote networks, providers, other platforms,
  product runtime changes, public APIs, manifests, dependencies, auth v3, PQ
  policy, SBOM or signature work, rollback rehearsal, release work, and product
  or Live results. Existing strict YAML and stored-profile rejection, explicit
  Beta.1 flat-profile migration, and new-envelope rejection by the old reader
  remain intentional. T017 is already complete and is not repeated here.
- **Stop conditions:** Stop if the exact local tag identities are unavailable,
  a build needs network access, a historical same-version control is unhealthy,
  or safe completion requires a sixth file, a manifest or lock change, product
  code, a wire/schema/version change, a current-tip binary standing in for a
  release, a remote action, or any host-network mutation.

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
