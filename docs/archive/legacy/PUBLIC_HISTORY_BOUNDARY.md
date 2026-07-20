# Public History Boundary

Status: current boundary for the sanitized public repository.

## Public Starting Point

The public Maverick repository starts from one sanitized root commit. It does
not contain the earlier private Git history, tags, releases, pull requests,
issues, Actions runs, or repository settings.

The source tree at that root is reviewed and compared with the final private
candidate tree. The missing history is intentional privacy protection, not an
attempt to present the root commit as the beginning of the project.

## Pre-Publication Releases

Versions through `v1.1.0` were completed in the pre-publication private
repository. Historical release notes, audit records, commit identifiers, and
run identifiers remain useful evidence references, but they are not objects in
the sanitized public Git history and might not resolve as public links.

Do not recreate an old tag on a different public commit. The first public
release must use a version that was never assigned to a pre-publication
release. The active development line is `v1.2.0`; its first public candidate
may use `v1.2.0-alpha.1` only after the applicable release gates pass.

The later public maintainer identity and signature policy does not amend or
replace the neutral sanitized root or the accepted cutover audit commit. Both
remain immutable public-history facts.

## Evidence And Compatibility

Historical exact-commit evidence remains scoped to the historical commit it
names. It does not automatically prove the behavior of the sanitized root or a
later public commit. New evidence and releases must bind to public commit and
artifact identifiers.

This repository-history boundary does not change the protocol,
authentication, or config versions. Their compatibility rules remain in
`COMPATIBILITY.md` and `MIGRATIONS.md`.

## Development Rule

After cutover, the public repository is the only writable Maverick source
mainline. The private repository is a read-only historical archive. Private
deployment data, credentials, and raw evidence remain outside the public
repository.
