# Open Source Cutover Audit

Date: 2026-07-16

Scope: verification of the sanitized public-source cutover. This record does
not authorize a deployment, production-readiness claim, new release, tag, or
privileged test.

## Result

The source-publication cutover is accepted.

- The public history began at root commit
  `058893f784fd3966c0ffd300ef325a54aa0e0901`.
- The root tree is
  `af9f49c482149b65b6693cb1901a432e9612c5d8` and exactly matches the audited
  Phase 1 source tree.
- The repository opened with one root commit, one branch, no tags, no releases,
  no issues, and no imported private Git objects.
- Pre-publication tags, releases, pull requests, Actions records, and other
  private repository state were not imported or recreated.
- The public repository uses a neutral description and provides private
  vulnerability reporting, dependency security updates, secret scanning, and
  push protection.
- No GitHub Actions workflow ran during repository migration or visibility
  change.

The companion reference-client source dependency was moved to the sanitized
public root before publication was finalized. Existing remote evidence remains
bound to its original exact source revisions and was not relabeled.

## Independent Verification

A fresh unauthenticated clone from the public repository confirmed:

- the expected root commit and tree;
- one root commit and zero tags;
- absence of the final private-history commit object;
- a clean working tree; and
- successful completion of `./scripts/local-harness.sh`.

The dependency inventory also passed for 301 Rust dependencies: no applicable
RustSec advisory was reported, dependency policy passed, and the first-party
`unsafe` inventory remained within its reviewed boundary.

## Claim Boundary

This audit proves that the intended source tree was published without importing
the rejected private history. It does not prove that Maverick is formally
audited, anonymous, censorship-resistant, production-ready, or safe for an
operator's particular deployment.

Opening the source is not a software release. Versions through `v1.1.0` remain
pre-publication historical identifiers and must not be recreated as public
tags. The first public release candidate is planned for the previously unused
`v1.2.0` line and remains subject to its own release gates.
