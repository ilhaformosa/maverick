# Release Artifacts

Maverick release artifacts are generated locally and written under `dist/`.
`dist/` is ignored by git.

## Default Local Build

```sh
./scripts/release-artifacts.sh
```

The script builds the `maverick` CLI in release mode, copies public release
documents, writes `BUILDINFO`, and generates `SHA256SUMS`. Release builds
remap local source paths before publishing and fail if the generated artifact
still contains the local repository path or home directory.

## Optional Target Or Features

```sh
MAVERICK_RELEASE_TARGET=x86_64-unknown-linux-gnu ./scripts/release-artifacts.sh
MAVERICK_RELEASE_FEATURES=h3 ./scripts/release-artifacts.sh
MAVERICK_RELEASE_VERSION=X.Y.Z ./scripts/release-artifacts.sh
```

Only publish targets that were built and smoke-tested for that release.

For the narrow `v1.2.0` candidate, the named target is Ubuntu 26.04 LTS `amd64`.
Its formal artifact and runtime evidence must come from a source-bound disposable
target fixture. A build or run on another host OS does not create Ubuntu support.

## Release-Candidate CI Artifact Check

After freeze, `.github/workflows/release-candidate.yml` checks the full
`maverick_release_commit` on one `ubuntu-24.04` Actions runner. That runner is
public CI infrastructure, not the formal target. The job builds the public
Maverick artifact, verifies `BUILDINFO` and `SHA256SUMS`, and writes the hashes
plus the separate Ubuntu 26.04 target boundary to the run summary. It does not
upload an artifact, create a tag, publish a package, or create a GitHub Release.

The workflow reads the frozen ledger from its public control checkout and then
builds the release source from a separate exact-commit checkout. This avoids the
impossible idea that a commit can contain its own future hash. Record both the
control commit and the frozen release commit, but tag only the approved release
commit.

This public artifact check does not build the private reference-client Debian
package and does not replace its signed package or publication evidence.
For the planned alpha, its software version is `1.2.0-alpha.1` and its Debian
package version is `1.2.0~alpha.1-1`; the exact package hash remains a separate
freeze input.

## GitHub Release Attachment Rule

Use a GitHub Pre-release for an explicitly prerelease version and a normal
release only after its stable gate passes. Attach artifacts only after the
exact commit has passed the release checks. Do not mark prereleases as
`latest`, and do not attach artifacts from:

- a dirty working tree;
- a different commit than the tag;
- a local rebuild after the tag was created;
- a target or feature set that was not smoke-tested for the release.

The GitHub release body should list the artifact name, target, feature set,
commit hash, and checksum verification command.

## Stable Checksum Signing

Stable releases should publish the generated `SHA256SUMS` file and a detached
`SHA256SUMS.sig` signature from a project release-signing key.

Maverick uses OpenSSH file signatures for this release artifact signature path:

```sh
MAVERICK_RELEASE_SIGNING_KEY=/path/to/maverick-release-signing-key \
MAVERICK_RELEASE_ALLOWED_SIGNERS=docs/release-signing/allowed_signers \
./scripts/release-artifacts.sh
```

On macOS, an encrypted private key can read its passphrase from Keychain:

```sh
MAVERICK_RELEASE_SIGNING_KEY=/path/to/maverick-release-signing-key \
MAVERICK_RELEASE_SIGNING_KEYCHAIN_SERVICE=maverick-release-signing-passphrase \
MAVERICK_RELEASE_SIGNING_KEYCHAIN_ACCOUNT=maverick-release-signing-ed25519-2026 \
MAVERICK_RELEASE_ALLOWED_SIGNERS=docs/release-signing/allowed_signers \
./scripts/release-artifacts.sh
```

The signature namespace defaults to `maverick-release`. Verification uses:

```sh
ssh-keygen -Y verify \
  -f docs/release-signing/allowed_signers \
  -I maverick-release \
  -n maverick-release \
  -s SHA256SUMS.sig <SHA256SUMS
```

Do not commit release-signing private keys. If no project release-signing key
exists, do not claim signed checksums; publish only SHA256 checksums and record
the gap in the release audit.

## Reference Client Package Publication

The `maverick` release bundle and the `maverick-reference-client` Debian/APT
publication are separate artifact systems. The reference package must record its
own version, architecture, SHA-256, OpenSSH package-set signature, installed
binary hashes, and source/SDK bindings.

An APT repository additionally requires a dedicated OpenPGP archive key,
repository-scoped `Signed-By`, signed and expiring metadata, by-hash indices,
atomic publication, rotation overlap, tamper/failure tests, and independent
client verification. The OpenSSH release-artifact key must not be reused as the
APT archive key. A local unsigned APT snapshot or signed `.deb` alone is not
package-publication acceptance.

Before any package is published, the frozen public reference-client commit must
pass its `docs/PACKAGE_PUBLICATION_GATE.md`, and Phase 3-A must provide the
coordinator-accepted redacted result. Provider, account, domain, region, and
spending choices require a separate operator decision and never belong in public
evidence.

Release signing keys may be rotated by appending a new public signer to
`docs/release-signing/allowed_signers`. Keep old public signer lines for old
release verification. If a private key or passphrase is lost, old signatures
remain verifiable, but future releases must be signed with a new key.

## Verification

On macOS:

```sh
cd dist/maverick-<version>-<target>
shasum -a 256 -c SHA256SUMS
```

On Linux:

```sh
cd dist/maverick-<version>-<target>
sha256sum -c SHA256SUMS
```

## Release Rule

Do not attach release artifacts unless these have passed for the exact commit:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
python3 scripts/check-production-readiness.py
```

Also require the accepted public PR result and exact-stage release-candidate CI
record defined in `docs/CI_AND_RELEASE_GATES.md`.

For a post-v1 stable-scoped release, also attach the evidence required by
`docs/PLAN_POST_V1.md`. The completed `docs/PLAN_SHORT_TERM_TO_V1.md` and
`docs/RELEASE_TRAIN.md` remain the evidence sources for the `v1.0.0` train.
The stable artifact set should include `SHA256SUMS.sig` when a project release
signing key exists.
Historical public alpha snapshots may cite the one-hour and 24-hour pre-stable
evidence in
`docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_01.md` and
`docs/history/evidence/APPROVED_HOST_RUNTIME_EVIDENCE_2026_07_03.md`, plus
process-level failure evidence in
`docs/history/evidence/APPROVED_HOST_FAILURE_INJECTION_EVIDENCE_2026_07_03.md`.
They must not present that evidence as a production-readiness claim.
