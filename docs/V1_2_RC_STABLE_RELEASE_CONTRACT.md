# Maverick v1.2 RC/Stable Release Contract

Status: owner-approved release policy; current completion state is in STATUS.md

Decision date: 2026-08-12; support scope superseded by owner decision 2026-11-10

Tooling preparation authorized: 2026-11-11. The owner permits implementing,
independently reviewing and testing Stable tooling before field qualification,
while freezing protocol/SDK scope. This does not move the publication decision
or authorize a release tag, deployment or GitHub Release.

## Owner decision for patch 1.2.5

The owner authorized 1.2.5 from `bdaaf0c` after qualification of the native
Apple Silicon macOS and Linux x86_64 installation archives. Use each
packaged CLI to verify file permissions, overlapping listeners and restart
after correction. Exercise both mixed directions with published 1.2.4,
two-sided upgrade and fresh TCP and UDP transfers after restoring the
saved programs and private configurations. Merge the reviewed PR and use
the annotated tag and exact-commit approval to publish the six files from
the qualified main revision. Field trials and the 72-hour soak remain deferred.

## Owner decision for patch 1.2.4

The owner authorized delivery of the profile import preview fix from
`fae7fa3` after qualifying the packaged CLI on Apple Silicon macOS and
native Linux x86_64. Exercise import previews, credential rollover and
mixed peers with published 1.2.3, then upgrade and restore saved programs
and private configurations and verify TCP and UDP traffic on loopback.
Merge the reviewed PR and publish the six files from the qualified main
commit using the existing exact-commit approval and annotated tag.
Real-network trials and the 72-hour field soak remain deferred.

## Owner decision for patch 1.2.3

On November 27 the owner authorized a 1.2.3 release from `fbb6db1` after
native macOS and Linux x86_64 package qualification, PR merge and exact-commit
verification. Exercise the offline configuration and rotation commands using
the executable extracted from each candidate archive. Use published 1.2.2
for mixed peers, upgrade and restoration on loopback. Retain the earlier
Stable and Beta.4 drills. The decision covers the annotated tag and publication
of the six verified files. Field operation and the 72-hour soak remain deferred.

## Owner decision for dependency patch 1.2.2

On November 24 the owner delegated the decision to release the dependency fix.
1.2.2 ships the repaired CLI dependency closure for both supported platforms.
The same exact-commit approval and native package gates apply. Exercise both
published Stable baselines (1.2.0 and 1.2.1), retain the Beta.4 rollback, and
verify the fixed versions in both actual runtime SBOMs. The available evidence
is offline or loopback. Field trials and the 72-hour soak remain deferred.

## Owner decision for patch 1.2.1

Starting from main `810e39f`, the owner authorized a 1.2.1 release after
native macOS and Linux x86_64 package verification on loopback, PR review
and merge. The comparison is published 1.2.0 in both mixed directions,
a two-sided upgrade and restoration of both saved binaries and configurations.
The release uses the successful main qualification's exact packages. Real
networks, provider behavior, operational rollback and the 72-hour soak
remain unverified. This decision applies to 1.2.1.

## Owner decision for v1.2.0 only — 2026-11-19

The owner authorized a Stable/Latest release after review, repair of confirmed
defects and automated qualification. For v1.2.0 only, section 4 and the field
portion of section 5 are deferred. Fresh-host installation, real networks,
ordinary application use, deployment rollback and the 72-hour soak carry no
passing result. Future releases can reinstate those gates. The Linux and macOS
native package and Beta.4 rollback drills below still apply. This decision
supersedes earlier statements deferring Stable publication or requiring a
second owner decision for this version. It authorizes setting the exact-SHA
approval for the qualified Stable revision and publishing its six verified
files. It grants no infrastructure or deployment authorization.

## Purpose

This record freezes the minimum contract for moving the v1.2 H2/H3 TCP/UDP
train from Beta toward RC and Stable release. It is a policy record,
not evidence that any RC or Stable gate has passed.

The contract does not itself authorize a tag, GitHub Release, publication,
provider resource, field run, paid audit, or Stable claim. The November 19 decision above supplies publication authorization for v1.2.0.

## Owner decisions R1 through R4

| ID | Approved decision |
|---|---|
| R1 | Stable must support **H2/H3 and TCP/UDP**, both UDP policies, new-session selection and protected H2 intermediary confidentiality. Unprotected intermediary paths do not satisfy this claim. |
| R2 | An RC is a GitHub prerelease and is not Latest. Stable is a non-prerelease GitHub Release and is Latest. |
| R3 | The exact rollback partner for the first v1.2 RC/Stable line is immutable `v1.2.0-beta.4`. |
| R4 | The exact RC requires an independent security review, supply-chain checks, and no unresolved Critical or High finding. A new paid third-party formal audit is optional, not mandatory. |

## Supported routes

The required Stable support matrix is:

| Route | First v1.2 Stable status | Contract |
|---|---|---|
| Direct H2 TCP and reliable UDP | Stable candidate | Full bidirectional sessions; all applicable gates below. |
| Direct H3 TCP and native UDP | Stable candidate | Native datagram limits explicit; all applicable gates below. |
| Direct dual/auto with both UDP policies | Stable candidate | New-session selection/avoidance/retry; no security downgrade or payload replay. |
| Origin-protected intermediary H2 TCP/reliable UDP | Stable candidate | Inner origin verification and confidentiality; route-specific validation. |
| Unprotected intermediary H2/WS | Legacy, excluded | Cannot satisfy mandatory intermediary confidentiality. |
| TLS-terminating intermediary H3 | Unsupported, excluded | No new relay or encryption architecture authorized. |

Direct and provider-fronted H2 are different trust routes. The Direct H2 path
must not silently fall through to the provider-fronted path, and evidence from
one route must not be credited to the other. Release notes and user guidance
must identify each supported/protected route and explicitly exclude unsupported
or unprotected legacy routes even if compatibility code is present.

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
Beta and RC while rejecting Stable at that historical revision. This completed only the bounded
tag-verifier slice and did not authorize an RC tag.

Current [Stable tooling preparation](STABLE_RELEASE_TOOLING.md) adds Stable
classification and an exact-revision publication approval that is unset by
default. Preparing these tools or passing a private packaging rehearsal does
not satisfy the field or publication gates below.

The historical RLC-001/RLC-001b tooling and RC preparation steps have been
completed. They are not new prerequisites or a separate active work queue.
RC.2 is published as an immutable prerelease; `STATUS.md` links its exact source
and evidence. Stable remains deferred until the current candidate satisfies the
applicable requirements below. A completed historical gate does not qualify a
changed candidate.

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
- Every supported matrix cell is tested; no hidden carrier or intermediary
  fallback crosses its trust boundary. Full packages include H2/H3, generated
  direct configs use dual/auto, and omitted old settings preserve their meaning.
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
  deployed to a fresh owner-controlled origin and used on the supported routes and TCP/UDP policy combinations covered by the
  Stable claim. A Direct-H2-only run cannot qualify H3/native UDP or protected
  intermediary use.
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
partner and accepts RC.4 through RC.7 and Stable 1.2.0. The default
candidate version comes from the workspace. A platform cell closes
only when that exact candidate passes the native drill and independent review.

### 6. Publication

After every gate above passes for one exact RC, Codex records the Stable-promotion
go/no-go decision; the RLC-002 tooling may be prepared and reviewed earlier under
the 2026-11-11 authorization. The Stable candidate receives a fresh
exact-file verification, the independent RLC-002 review, and the narrow
promotion-diff review. Only then may `v1.2.0` be published as a non-prerelease
and Latest.

Passing this contract still does not justify claims of maturity, production
readiness, anonymity, broad censorship resistance, provider independence, or
exact browser equivalence.

## Applying this contract

Use `STATUS.md` for current release state and `ROADMAP.md` for execution order.
Do not repeat completed RLC tooling tasks or create policy-only prerequisite PRs.
For a future release, select one exact candidate and apply the compatibility,
security, supply-chain, artifact, rollback and publication rules above. A
candidate-changing fix requires a replacement RC. Stable/Latest still requires
its explicit implementation, exact-file verification, completed field evidence
and publication decision; publishing RC.2 does not satisfy those conditions.

## Current development boundary

The active development goal delivers candidate functionality, SDK, protocol
material and deployable archives with local/CI evidence. Field use, deployment
and public/Stable publication remain deferred by the owner. Performance-based
selection is frozen; active-session migration is permanently excluded. The
72-hour requirement remains a field gate, not permission to start a field task.
