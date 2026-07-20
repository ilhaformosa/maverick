# Open Source Cutover Audit

Date: 2026-07-16

Scope: verification of the sanitized public-source cutover. This record does
not authorize a deployment, production-readiness claim, new release, tag, or
privileged test.

## Result

The source-publication cutover is accepted.

- The public history began at root commit
  `fd9073b0fa43b8c258bdf95bce846343b3c90cc2`.
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

## Identity Attribution Correction

On 2026-07-16, the neutral snapshot and cutover author identities were checked
against GitHub's email-based contributor attribution. Neutral-looking
`users.noreply.github.com` addresses had been associated with unrelated GitHub
accounts. The history was corrected once so the two project roles use reserved
`.invalid` addresses that cannot identify a person.

The role names, commit messages, dates, root tree, and source trees were
preserved. Commit hashes necessarily changed because Git commit hashes include
author metadata. GitHub signatures on descendant pull-request commits could not
be carried across the parent-hash change. At the time of correction there was
no public tag, release, frozen candidate, or published package. The corrected
source passed the local harness, dependency inventory, and CodeQL analysis.
Future frozen candidate and release commits remain subject to the signature
requirements in `docs/MAINTAINER_IDENTITY_AND_SIGNING.md`.

## Claim Boundary

This audit proves that the intended source tree was published without importing
the rejected private history. It does not prove that Maverick is formally
audited, anonymous, censorship-resistant, production-ready, or safe for an
operator's particular deployment.

Opening the source is not a software release. Versions through `v1.1.0` remain
pre-publication historical identifiers and must not be recreated as public
tags. The first public release candidate is planned for the previously unused
`v1.2.0` line and remains subject to its own release gates.
