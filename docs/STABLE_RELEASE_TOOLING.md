# Stable release tooling preparation

Owner authorization: 2026-11-11. Protocol and SDK functionality are frozen.
This task prepares and independently reviews release tooling with local/CI
verification. It does not authorize field use, deployment, a release tag, a
GitHub Release, or setting a publication approval.

## Small implementation boundary

The package version in the actual checkout remains RC.4. Product Rust source,
dependencies, wire/auth/configuration semantics and client selection do not
change. The qualified runtime candidate remains `d12c6a6`. These tooling
changes are not a new independent qualification of a different candidate.

`release-channel.sh` accepts only `1.2.0-beta.N`, `1.2.0-rc.N` (positive integers
without leading zeros) and `1.2.0`. The tag verifier still requires an annotated
tag directly targeting the checked-out commit on main. Classification never
creates a tag or authorizes publication.

| Version | GitHub prerelease | Latest | Extra publication condition |
|---|---|---|---|
| Beta | true | false | Existing exact-tag/commit/artifact checks |
| RC | true | false | Existing exact-tag/commit/artifact checks |
| Stable `1.2.0` | false | true | Repository variable `MAVERICK_STABLE_APPROVED_SHA` exactly equals the selected commit |

The Stable approval is absent by default. Only a later explicit owner decision,
after the required field acceptance and independent promotion review, may set
it for one exact commit. No wildcard, branch name or older candidate approval
is accepted. The publication workflow checks it before qualification and again
in the publishing job immediately before producing the release arguments.
It is an operator authorization gate, not machine evidence that field use
happened. To stop an already running release, cancel that run; changing a
repository variable is not an in-flight revocation protocol.

All existing six-file selection, source/target/digest matching, privacy checks,
release-note snapshot/recheck, tag/main recheck and immutable release handling
remain. The workflow consumes the successful exact-commit CI archives; it does
not rebuild during publication. Existing artifact names retain `pilot` and
the internal `rc-candidate` job labels for compatibility. File contents and
SOURCE.txt identify the exact version and revision.

Stable package verification requires the full H2/H3 feature profile and both
TCP/UDP native smoke modes. Its SBOM must match that full locked dependency
graph. The stable installation guide retains experimental/non-production
limitations while avoiding a false prerelease label. Legacy Beta/RC archive
profiles remain unchanged. The rollback drill defaults to RC.4 and additionally
accepts explicit `--candidate-version 1.2.0`; the pinned Beta.4 partner and its
digests never change.

## Validation without publication

The existing release gate suite tests valid/invalid versions, annotation/main
checks, artifact tampering and H3/UDP omissions. It also executes the workflow's
actual publication-argument block using a local `gh` stand-in. Missing/wrong
Stable approval must never reach that stand-in; approved Stable, Beta and RC
must pass exactly the expected arguments and six files. Existing workflow hash
and mutation checks remain. Synthetic annotated markers exist only in isolated
test repositories, not in the Maverick repository or on GitHub.

`test-stable-release-rehearsal.sh` creates a private source snapshot with no
remote or tags, changes only workspace package versions to `1.2.0`, and records
the actual source commit separately from its local synthetic fixture commit.
It builds a real full-feature binary, verifies its native H2/H3 TCP/UDP behavior,
generates and verifies full SBOMs, runs the existing SBOM negative suite, and
performs native Beta.4 upgrade/rollback. Both CI platforms run it after the
ordinary candidate checks. Rehearsal files are not uploaded as release assets.
Local output is preserved for evidence; the script does not clean shared caches.

```sh
./scripts/test-stable-release-rehearsal.sh \
  --previous-dir /path/to/verified-beta4-files \
  --output /path/to/new-private-rehearsal-directory
```

The output must be new; source must be clean; the host must be one of the two
supported native targets. Inputs are the existing pinned Beta.4 archive and
checksum for that host. The script needs the same Rust/native tools and pinned
SBOM generator as ordinary candidate verification. `REHEARSAL.txt` distinguishes
test artifacts from releasable files. This is packaging/tooling evidence,
not exact-candidate security sign-off, field evidence or Stable publication.

## Later authorized promotion

After field acceptance, choose the exact passing candidate and perform the
narrow version/release-note/tooling promotion review under the
[release contract](V1_2_RC_STABLE_RELEASE_CONTRACT.md). Generate and qualify the
actual Stable archives/SBOMs, review the exact files and publication decision,
then configure the matching approval and create the annotated release tag only
when explicitly authorized. Existing local rehearsal files are never promoted.
Changing runtime code or dependencies still requires a replacement RC.

CI qualification artifacts currently expire after seven days. Plan promotion
while the exact run's files are available; local copies preserve evidence but
do not bypass the workflow's exact-run artifact selection. If they expire,
resolve qualification deliberately under the contract rather than disabling
selection or uploading different bytes.
