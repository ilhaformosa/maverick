# Open Source Phase 1 Go/No-Go

Date: 2026-07-15. Cutover-boundary addendum: 2026-07-16.

Scope: source-publication safety only. This review does not authorize a
deployment, production-readiness claim, remote-host test, privileged test, new
release, tag, or visibility change.

## Decision

- **NO-GO: expose the existing private repository directly.** Older committed
  records and tagged trees contain developer-environment metadata. A visibility
  change would also publish automatic source archives made from those trees.
- **CONDITIONAL GO: publish a new single-root source snapshot.** The candidate
  must contain only the audited tree represented by the commit that contains
  this report. It must not import old commits, tags, releases, pull requests,
  Actions logs, or other private repository state.
- **NO NEW TAG REQUIRED.** Opening source code and publishing a software release
  are separate decisions.
- **NO HISTORICAL TAG RECREATION.** Versions through `v1.1.0` remain private
  historical identifiers. A first public release must use a version that was
  not assigned in the private history.

## Audit Coverage

The Phase 1 review checked:

- the full working tree and full Git object/history inventory;
- commit and tag author metadata;
- current version, protocol/authentication/config versions, branches, tags,
  release records, and repository visibility;
- repository metadata, community files, workflow permissions, action pins, and
  branch-policy availability;
- attached release assets, digests, checksums, signatures, and automatic source
  archive exposure;
- dependency advisories, dependency policy, first-party unsafe Rust, source
  secrecy, generated credentials, logs, evidence tooling, and build outputs;
- security, support, compatibility, contribution, release, governance, and
  operations documentation.

Attached release assets and the available workflow logs passed the privacy
checks. That does not make older tagged source trees safe to expose.

## Fixes Included In The Candidate

- Workflow actions and Cargo-installed CI tools are pinned and machine-checked.
- Replay expiration handles out-of-order timestamps.
- Fuzz corpus sync rejects path escape.
- Privileged-helper approval accepts only the exact supported operation set.
- Rollback journals are private, owner-bound, host-bound, and device-bound.
- Approved-host scripts validate that a target is not the development machine
  before any SSH command can run.
- Remote evidence run identifiers, temporary state, process ownership, and
  cleanup provenance are validated before mutation.
- Source, log, network-safety, and evidence scanners cover the newly identified
  bypass cases without embedding private markers in tracked files.
- The bounded packet-engine comparison now exercises the real flow allocator.

No remote host was contacted and no development-machine network setting was
changed during this work.

## Remaining Owner Gates

Before an irreversible public entry is opened, the owner must choose the public
repository account or organization and approve the clean-snapshot approach.
The public entry must then be configured with:

- a neutral description and topics;
- private vulnerability reporting;
- protected default-branch rules;
- the checked-in contribution, conduct, security, support, and issue templates;
- a final comparison proving that its root tree exactly matches the audited
  snapshot.

Before the old repository name is reused, every source dependency pinned to an
old private commit must be migrated or temporarily redirected to the private
archive. Historical release and Actions URLs must also be labeled as private
pre-publication records so they are not mistaken for public objects.

Recommended path: retain and rename the existing private repository as an
archive, then create the public canonical repository from the audited
single-root snapshot. Do not rewrite or reveal the private archive merely to
preserve old public URLs.
