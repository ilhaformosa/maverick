# Release Train

Status: completed v1 release-train summary. `v1.0.0` was published on
2026-07-09 for the narrow `maverick-tls-h2-cli-v1` scope. The detailed source
of truth is `docs/PLAN_SHORT_TERM_TO_V1.md`.

Maverick moves from alpha to `v1.0.0` through four named gates. Do not widen
the stable scope to make a tag happen.

## Stable Scope

The only `v1.0.0` target is `maverick-tls-h2-cli-v1`:

- TLS 1.3 plus HTTP/2.
- CLI-managed Rust client and server.
- TCP, DNS, and documented UDP relay.
- Static or reverse-proxy fallback.
- Auth v1/v2, replay protection, resource bounds, and loopback metrics.
- No native server-side ECH, no stable H3/QUIC, no TUN system apply, no GUI,
  no anonymity claim, and no censorship-resistance claim.

## S0: Scope Freeze And Process Debt

No tag.

Gate:

```sh
./scripts/local-harness.sh
```

Exit means `SPEC.md` names the frozen v1.0 scope, old readiness/evidence files
are under `docs/history/`, active docs are indexed, and inactive
blocker/approval manifests are removed from the root gate surface.

## S1: Runtime Hardening

Tag target: `v0.1.0-beta.1` as a GitHub Pre-release with `--latest=false`.

Gate:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

Exit means abuse/DoS controls, redacted observability, and deployment hardening
are covered by tests/docs for the frozen TLS/H2 path.

## S2: Independent Evidence

Tag target: `v0.1.0-beta.2` as a GitHub Pre-release with `--latest=false`.

Gate:

```sh
MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR=<approved-server-public-address> \
MAVERICK_PUBLIC_SMOKE_SERVER_NAME=<approved-server-name> \
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=<approved-client-ssh-host> \
MAVERICK_PUBLIC_SMOKE_GENERATE_TEST_CERT=1 \
MAVERICK_NETEM_IMPAIRMENT_APPROVED=1 \
./scripts/s2-evidence-preflight.sh <approved-server-ssh-host>

MAVERICK_PUBLIC_SMOKE_CLIENT_HOST=<approved-client-host> \
MAVERICK_PUBLIC_SMOKE_TEMP_FIREWALL=1 \
MAVERICK_LONGHAUL_DURATION_SECS=86400 \
./scripts/approved-vm-detached-tcp-longhaul.sh <approved-server-host>

./scripts/s2-evidence-collect.sh \
  <approved-client-ssh-host> \
  /tmp/maverick-detached-longhaul-client-<run-id> \
  longhaul

MAVERICK_S2_CLEANUP_APPROVED=1 \
./scripts/s2-evidence-cleanup.sh \
  <approved-client-ssh-host> \
  /tmp/maverick-detached-longhaul-client-<run-id> \
  <approved-server-ssh-host> \
  /tmp/maverick-detached-longhaul-server-<run-id> \
  | tee runtime-evidence/s2-longhaul-<collected-at>/PRIVATE_FINAL_CLEANUP.log

python3 scripts/s2-evidence-audit.py \
  runtime-evidence/s2-longhaul-<collected-at> \
  --require-accepted

./scripts/s2-evidence-report.py \
  --longhaul runtime-evidence/s2-longhaul-<collected-at> \
  --netem runtime-evidence/s2-netem-<collected-at> \
  --failure-injection runtime-evidence/s2-failure-injection-<collected-at> \
  --output runtime-evidence/s2-independent-evidence-draft.md
```

Run only on approved hosts, not on the developer workstation. Exit means
two-host long-haul, bounded impairment, and failure-injection evidence match
the exact release claims. Review and redact the draft before moving any S2
evidence document into `docs/history/evidence/`. Temporary firewall mode
requires an unused, initially closed test port and creates only an expiring
runtime rule; it does not alter the permanent firewall configuration. Run the
audit gate for every long-haul, netem, and failure-injection collection before
generating the combined report. Collection happens before remote cleanup so all
logs are retained; rerun the audit after adding `PRIVATE_FINAL_CLEANUP.log` so
the manifest covers the final zero-residue record. Current runners also declare
child-process sampling; acceptance checks Maverick process rows plus complete,
monotonic resource samples. Long-haul evidence additionally must cover the
declared run window without excessive sampling gaps.

## S3: Review And Freeze

Tag target: `v0.1.0-rc.1` as a GitHub Pre-release with `--latest=false`.

Gate:

```sh
./scripts/local-harness.sh
./scripts/conformance.sh
python3 scripts/check-security-review-package.py
```

Exit means a credible independent or community review covered the frozen scope,
blocker findings are closed or publicly accepted as residual risk, conformance
vectors are frozen for the target scope, and `SECURITY.md` has a real
disclosure path.

## S4: Stable

Tag target: `v1.0.0` as a real GitHub release, not a Pre-release.

Gate:

```sh
cargo fmt --all -- --check
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/conformance.sh
./scripts/release-artifacts.sh
```

Exit also requires current two-host evidence, closed review, published
checksums, migration notes, and claim language that says exactly what the
narrow stable release does and does not prove.

## Honesty Rules

- Do not say audited, production-ready, anonymous, censorship-resistant, or
  standardized unless that exact evidence exists.
- Alpha and beta releases are Pre-releases and must not be marked latest.
- Protocol and config versions are separate from Git tags.
- Historical evidence belongs under `docs/history/`; active release decisions
  after v1.0.0 belong in `docs/PLAN_POST_V1.md` and the release-specific notes.
