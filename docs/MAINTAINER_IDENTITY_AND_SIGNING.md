# Maintainer Identity And Signing Policy

Status: active for public-history work. Accepted commits are not rewritten
except to correct a proven attribution or privacy error before a release.

## Public Identity

The public maintainer identity is GitHub user `@ilhaformosa`. `MAINTAINERS.md`
and `.github/CODEOWNERS` use only that public handle.

Git author email must use the maintainer's current GitHub-provided `noreply`
address when email privacy is enabled. The exact address is taken from the
maintainer's GitHub email settings and is not hard-coded in repository docs.
Before a public commit, verify that the staged diff, author, committer, and
commit message contain no private email, path, host, account, or infrastructure
string.

The sanitized root and the public cutover audit commit use neutral project role
names with reserved `.invalid` email addresses. A neutral role must never use a
GitHub `noreply` address unless the project intentionally attributes the commit
to that exact account. The two migration identities were corrected once after
their original addresses were found to map to unrelated accounts; the semantic
roles and source trees were preserved. That correction is recorded in
`docs/OPEN_SOURCE_CUTOVER_AUDIT_2026_07_16.md`.

These commits are now accepted history and must not be amended, replaced, or
rewritten merely to apply a newer identity policy.

## Commit Signatures

- Ordinary development commits should use a GitHub-verifiable SSH or GPG
  signature when the maintainer's signing configuration is available.
- A frozen release-candidate commit, release commit, and annotated release tag
  must be signed and show a valid verification result before publication.
- A missing or unverifiable signature blocks RC/stable publication; it does not
  justify weakening verification or rewriting earlier neutral commits.
- A signature proves key possession, not code correctness, independence, or
  production readiness.

Commit/tag signatures and release-artifact signatures are separate controls.
Release checksum signing follows `docs/RELEASE_ARTIFACTS.md`. A future APT
repository uses its own OpenPGP archive key and must not reuse the OpenSSH
release-artifact key.

## Key Rotation Or Loss

Publish the replacement public signer through the same reviewed project channel,
retain old public keys for historical verification, and record the last trusted
commit/tag. If a signing key might be compromised, stop releases, rotate the key,
reverify affected artifacts, and follow `docs/INCIDENT_RESPONSE.md`. Never amend
old commits only to replace their signature.
