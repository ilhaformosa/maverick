# Maverick v1.2 RC/Stable Release Contract

Status: owner-approved policy; implementation and release gates remain closed

Decision date: 2026-08-12

## Purpose

This record freezes the minimum contract for moving the better-proven v1.2 H2
train from Beta toward its first RC and Stable release. It is a policy record,
not evidence that any RC or Stable gate has passed.

The contract does not itself make a tag, GitHub Release, publication, provider
resource, field run, paid audit, or Stable claim ready. Under the standing
decision delegation in `STATUS.md`, Codex may decide those later tasks without
another owner choice, but only after recording and passing their exact gates.

## Owner decisions R1 through R4

| ID | Approved decision |
|---|---|
| R1 | The first Stable support claim covers **Direct H2 only**. Provider-fronted H2 remains Beta. |
| R2 | An RC is a GitHub prerelease and is not Latest. Stable is a non-prerelease GitHub Release and is Latest. |
| R3 | The exact rollback partner for the first v1.2 RC/Stable line is immutable `v1.2.0-beta.4`. |
| R4 | The exact RC requires an independent security review, supply-chain checks, and no unresolved Critical or High finding. A new paid third-party formal audit is optional, not mandatory. |

## Supported H2 route

The first Stable support matrix has one Stable cell:

| Route | First v1.2 Stable status | Contract |
|---|---|---|
| Direct client-to-Maverick TLS/H2 | Stable candidate | Must pass every exact-candidate, field, security, compatibility, rollback, artifact, and publication gate below. |
| Provider-fronted TLS/H2 | Beta | May remain explicitly available as Beta, but is excluded from the Stable claim and cannot satisfy a Direct H2 gate. |

Direct and provider-fronted H2 are different trust routes. The Direct H2 path
must not silently fall through to the provider-fronted path, and evidence from
one route must not be credited to the other. Release notes and user guidance
must identify the provider-fronted route as Beta even when its code is present
in the same binary.

This decision does not change the current protocol, config, stored-profile, or
authentication/frame wire versions. Any such change needs its own compatibility
decision before it can enter this release train.

## Tag and GitHub Release behavior

The later release tooling must enforce this matrix deterministically and fail
closed on every other combination:

| Channel | Tag shape | GitHub classification | Latest |
|---|---|---|---|
| Beta | `v1.2.0-beta.N` | prerelease | no |
| RC | `v1.2.0-rc.N` | prerelease | no |
| Stable | `v1.2.0` | non-prerelease | yes |

All release tags must be annotated, resolve directly to the reviewed candidate
commit, match the Rust package version, and remain immutable. The exact files
selected for upload must be reverified immediately before publication.

RLC-001 is merged at `main` commit
`9423bff57818da199c9b1141edfeb89e03c801a1`. Its release-tag verifier accepts
Beta and RC while continuing to reject Stable. This completed only the bounded
tag-verifier slice and did not authorize an RC tag.

Authorized **RLC-001b** is the next smallest local tooling slice. It must make
the artifact verifier accept only canonical positive Beta and RC versions
while Stable stays a tested rejection. Its fixtures must prove the archive
filename, source and version metadata, inner and outer checksums, architecture,
and native binary version all agree; RC must pass static inspection and native
verification on the current matching host. Static tests must also lock the
unchanged workflow's sole `gh release create` to prerelease/non-Latest and prove
that final tag, exact six-file, checksum, digest, and release-note rechecks occur
before creation. RLC-001b must not change the workflow or create a release.

RLC-001b still does not make the complete RC publication pipeline ready. No
exact-RC package version, release note, archive, SBOM, tag, or publication input
exists. A later separately queued exact-RC candidate-preparation slice must
close those RED gates before any RC tag is created. Stable classification stays
fail-closed until one exact RC completes every gate in this contract and Codex
records a go/no-go decision for **RLC-002**, which implements and tests the
Stable row. No tooling slice by itself authorizes a tag.

## Exact-candidate rule

An exact RC is one named commit plus the archives, checksums, target-aware
SBOMs, and release note built from that commit. Quality evidence belongs only
to that candidate and those bytes.

Beta.4 field, security-audit, CI, and artifact results do not become RC results.
They may establish historical context and the integrity of the rollback
artifact only. Public CI is supporting quality evidence; it is not an
independent security sign-off, a field result, or release authorization.

Except for the narrow Stable promotion described next, a change to product
code, runtime behavior, locked dependencies, build inputs, or published
artifact bytes after an RC gate passes requires a new RC and repetition of the
affected exact-candidate gates. Stable promotion may differ from the passing RC
only by the reviewed version, release note, and RLC-002 release-classification
tooling. RLC-002 receives its own independent review and affected gates are
repeated. Any product, runtime, dependency, config, auth, or wire change sends
the candidate back through RC.

## Required gates before Stable

### 1. Candidate and compatibility

- The exact RC commit, annotated tag, package version, and release-note version
  agree.
- Direct H2 is the tested and supported Stable route; no hidden
  provider-fronted or H3 fallback crosses the trust-route boundary.
- The supported v1 config/profile behavior and the Beta.4 rollback path are
  tested as an N/N-1 pair. A migration must preserve the original input and
  fail closed instead of silently changing authentication or trust policy.
- Any incompatibility is documented before the exact RC go/no-go decision.

### 2. Product, artifact, and supply chain

- `./scripts/user-smoke.sh` and `./scripts/local-harness.sh` pass locally for
  the exact candidate.
- `./scripts/security-dependency-inventory.sh` passes and its actual dependency,
  advisory, license, source, and first-party `unsafe` output is reviewed.
- The `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` target closures are
  locked; each archive, checksum, and target-aware CycloneDX SBOM passes the
  applicable native, static, structural, and full-closure verification.
- Required exact-head public CI and CodeQL checks pass. Any rerun and its reason
  are recorded; a skipped job or different commit is not candidate evidence.

### 3. Exact-RC security review

- A reviewer independent from the implementation performs a security-focused
  review bound to the exact RC commit and its locked dependency closure.
- The review covers the actual diff and affected authentication, TLS/H2,
  configuration, logging/privacy, resource-bound, release, and rollback
  boundaries.
- No known Critical or High finding remains unresolved. Lower-severity findings
  and unknowns are recorded with an explicit disposition rather than hidden.
- A fix that changes the candidate invalidates the old exact-head review and
  requires review of the replacement RC.

The 2026-07-21 formal audit remains a point-in-time historical result. A new
paid third-party formal audit is optional and would require a recorded scope,
cost cap, and go/no-go decision; it is not a substitute for the exact-RC
independent review above.

### 4. Exact-RC field evidence

- After the field task's exact origin, lifetime, cost cap, cleanup, and go/no-go
  decision are recorded, the independently downloaded exact RC artifact is
  deployed to a fresh owner-controlled origin and used only on the Direct H2
  route covered by the Stable claim.
- Fresh-origin validation, a 72-hour soak, and owner-controlled ordinary daily
  use complete on that exact candidate. Failures and unknowns remain visible.
- The run follows the current privacy and network boundaries. It does not reuse
  old Beta.4 field evidence and does not authorize a provider resource, host
  change, or field session merely because this contract names the gate.

### 5. Rollback

The fixed rollback partner is annotated tag `v1.2.0-beta.4`, whose tag object
`18f18eee87f8a89c662356334ae3f85d80bc577e` directly targets commit
`5109d89bdddc23a2830eda2c0c56a954d3b214a9`.

Before Stable, the exact public Beta.4 rollback artifacts must be independently
reverified, the configuration/profile backup and restore steps must be clear,
and authorized rollback exercises for `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu` must prove that the RC can be removed and Beta.4
restored without silently reusing incompatible state. The tag, release, and
assets must not be moved or replaced.

For each target, the matching Beta.4 archive, checksum, and target-aware SBOM
and the matching exact-RC set must be independently reverified. The rollback
exercise must run natively on Apple Silicon macOS for
`aarch64-apple-darwin` and on x86-64 Linux for
`x86_64-unknown-linux-gnu`; one platform's static inspection does not replace
the other platform's native exercise. The current
`scripts/test-n-minus-one-release-drill.sh` is fixed to Beta.4 as the rollback
partner and accepts only an exact RC candidate identity. A platform cell closes
only when that exact candidate passes the native drill and independent review.

### 6. Publication

After every gate above passes for one exact RC, Codex records the RLC-002 and
Stable-promotion go/no-go decisions. The Stable candidate receives a fresh
exact-file verification, the independent RLC-002 review, and the narrow
promotion-diff review. Only then may `v1.2.0` be published as a non-prerelease
and Latest.

Passing this contract still does not justify claims of maturity, production
readiness, anonymity, broad censorship resistance, provider independence, or
exact browser equivalence.

## Execution order

1. Preserve this merged policy-only contract as the release-policy boundary.
2. Preserve merged RLC-001 as current truth. Complete independent exact-hash
   review, exact-head public checks, privacy review, and merge for authorized
   RLC-001b. Its artifact verifier accepts Beta and RC while deliberately
   continuing to reject Stable; exact-RC candidate inputs remain RED.
3. Prepare and independently review one exact Direct H2 RC candidate.
4. After a recorded exact-candidate publication go/no-go, publish that RC as
   prerelease/non-Latest.
5. After recording each task's exact boundaries and go/no-go, complete
   exact-RC field, security, compatibility, supply-chain, artifact, and Beta.4
   rollback gates.
6. Stop and cut a replacement RC if any gate-changing fix is needed.
7. Only after every gate is complete on one exact RC, record the RLC-002 and
   later Stable-publication go/no-go decisions. RLC-002 must implement and test
   non-prerelease/Latest classification, review the promotion-only diff, and
   reverify the exact files before publication.
