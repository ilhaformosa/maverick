# CI And Release Gates

Status: available checks-only design with no active release candidate. The
workflows do not authorize a push, a
manual dispatch, a tag, a package publication, or a GitHub Release.

Maverick uses three verification layers. Each layer answers a different
question, so the project does not run a large operating-system or Rust-version
matrix without a real support claim behind it.

## 1. Local Preflight

Before a pull request, run from a clean checkout:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
```

The local harness is the broad developer gate. It checks formatting, Clippy,
tests, generated configs, conformance, fuzz smoke, documentation, CI structure,
and privacy/hygiene rules. It stays loopback-only and must not change host
proxy, DNS, routes, firewall, VPN, or interfaces.

## 2. Public Pull-Request CI

`.github/workflows/ci.yml` runs automatically for every public pull request:

- documentation hygiene and the core harness always run and must both succeed;
- H3, ECH, shape-lab, and browser-TLS jobs run only when their own inputs
  change;
- the path classifier is loaded from the pull request's base commit, not from
  the proposed tree, so a pull request cannot weaken its own classification;
- `public-pr-gate` requires every selected optional job to succeed and every
  unselected optional job to be skipped; a selected job that is skipped fails
  the gate;
- jobs use an `ubuntu-24.04` CI runner image and one stable Rust toolchain, with
  no platform or version matrix; this runner choice is not a product-support
  claim;
- permissions are read-only, checkout credentials are not retained, and no
  repository or infrastructure secret is required.

A feature-specific job is not wasteful duplication: it exercises behavior the
always-running core harness does not cover. Running the same generic suite
across unsupported systems or many Rust versions would not establish a
supported product claim, so that matrix is intentionally absent.

Scheduled supply-chain and parser-fuzz workflows remain maintenance signals.
They do not replace the pull-request gate or a frozen-candidate result.

## 3. Release-Candidate CI

`.github/workflows/release-candidate.yml` is a manual, checks-only gate. It may
be dispatched only after the coordinator approves an exact frozen candidate.
The operator supplies:

- the full `maverick_release_commit`; and
- one release stage: `v1.2.0-alpha.1`, `v1.2.0-beta.1`, `v1.2.0-rc.1`, or
  `v1.2.0`.

The workflow first checks the public control record and then checks out the
release commit into a separate directory. One `ubuntu-24.04` CI runner job:

1. verifies the ledger binding, release-stage order, separate version fields,
   and reference-client SDK pin evidence;
2. requires the ledger release tag to equal the requested stage;
3. requires both software versions to equal the tag without `v`, and requires
   the exact Debian mapping for alpha, beta, RC, or stable;
4. verifies that the exact source commit and Cargo software version match the
   requested stage;
5. reruns the local harness because the frozen release commit can differ from
   the pull-request merge test commit;
6. runs dependency, source, license, and first-party unsafe-code gates;
7. builds the public Maverick `x86_64-unknown-linux-gnu` artifact and verifies
   `BUILDINFO` plus `SHA256SUMS`.

The workflow does not tag, push, upload a package, publish a release, or mark a
ledger gate as passed. Its run identity and checksums are inputs for coordinator
review. A later public control-record change may record the accepted result
without changing the frozen release commit.

The stable candidate check is allowed while `production_ready` is still
blocked. Its accepted result is one input to the final Go/No-Go decision; it
cannot logically require that final decision in advance.

## Private Reference-Client Boundary

The public workflows never clone, build, or name private infrastructure for the
reference-client project. They also make no assumption that Actions usage for a
private repository is free or available. The private project may use local or
separately approved compute. Maverick imports only coordinator-accepted,
redacted manifest hashes and public summary paths.

The public release-candidate workflow validates that
`reference_client_sdk_pin` equals `maverick_sdk_commit` in the accepted record.
It does not rebuild the private Debian package. Package lifecycle, signing, APT
publication, and residue evidence remain Phase 3-A/3-B inputs.

## Ubuntu Evidence Boundary

Using an `ubuntu-24.04` Actions runner catches public-source portability
problems, but it is only CI infrastructure and does not establish the formal
supported-platform claim. Formal evidence must come from the source-bound
disposable Ubuntu 26.04 LTS `amd64` VM or fixture defined in
`docs/PRODUCTION_SCOPE.md`, including the exact private package and accepted
lifecycle evidence. An Actions result bound to Ubuntu 24.04 must never be
relabeled as Ubuntu 26.04 target-platform evidence.

Approved test systems may be rebuilt or destroyed by their authorized owner,
but aliases, addresses, provider data, regions, account details, raw logs, and
other infrastructure facts remain private. Phase 3-C does not access them.

## Required Result And Change Rule

After coordinator review, repository settings may require
`public-pr-ci / public-pr-gate`. This document does not claim that setting is
already enabled.

| change | required CI |
| --- | --- |
| prose only | local docs/privacy preflight plus unconditional public core/docs gate |
| public code, config, workflow, checker, dependency, or artifact script | full local preflight plus selected public PR jobs |
| frozen alpha/beta/RC/stable source | accepted public PR gate plus exact release-candidate CI |
| private helper, package, credential, route, DNS, or recovery behavior | private project gates and accepted Phase 3-A/3-B evidence in addition to public gates |
| scope, target platform, architecture, carrier, or address family | new scope and matching evidence/audit plan; no matrix can substitute for it |

No CI result is an independent security audit or a production approval.
