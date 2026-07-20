# Maverick Release Checklist

Use this checklist for experimental releases and internal milestones.

## Scope

- For post-v1 releases, confirm the target milestone and evidence gate in
  `docs/PLAN_POST_V1.md`.
- For the historical `v1.0.0` train, use `docs/PLAN_SHORT_TERM_TO_V1.md`,
  `docs/RELEASE_TRAIN.md`, and `docs/STABLE_SCOPE_CANDIDATE.md` as the frozen
  release record.
- Confirm `STATUS.md`, `README.md`, `SPEC.md`, `CONFIG.md`, `SECURITY.md`, and
  `THREAT_MODEL.md` reflect current behavior.
- Confirm `CHANGELOG.md` and `docs/RELEASE_TAGGING.md` are current.
- Confirm `docs/PUBLIC_FEEDBACK_PROCESS.md` reflects how public issues were
  triaged for this release.
- Confirm any post-release follow-up record under `docs/history/release/` does
  not require a corrective release before the next tag.
- Confirm `docs/RELEASE_ARTIFACTS.md` matches the artifact policy for the
  target release.
- Confirm new features are documented as experimental when appropriate.
- If the optional product TUN packet runtime changed, confirm exact engine
  pins/features, `tun-runtime` plus `advanced.experimental_tun` gates, Phase 1
  checker/tests, accepted Phase 2 scope, and remaining non-claims remain
  current.
- Confirm the current address-family decision is accurate: product and release
  support is IPv4-only, IPv6 has no scheduled milestone, and future IPv6 work
  requires a new explicit decision.
- Confirm `docs/NATIVE_ECH_TRACKING.md`, `docs/ECH_WORKAROUND.md`, and
  `docs/ROADMAP_BLOCKERS.md` distinguish native server-side ECH from the
  Cloudflare-fronted WebSocket workaround.
- Confirm `docs/DOCS_INDEX.md` keeps historical readiness, evidence, and review
  snapshots out of the contributor entry path.
- For the `v1.2.0` train, confirm the exact stage in
  `docs/RELEASE_GATES_V1_2.md`, the narrow target in
  `docs/PRODUCTION_SCOPE.md`, and the current machine result in
  `production-readiness.json`.
- Keep Maverick release commit, Maverick SDK commit, reference-client commit,
  and reference-client SDK pin separate. Verify the pin equals the ledger's SDK
  commit.
- Record release train, release tag, Maverick software, reference-client
  software, Debian package, protocol, Auth v1, Auth v2, config, helper IPC,
  recovery-journal, and platform-plan versions separately. For the first
  candidate they are `1.2.0`, `v1.2.0-alpha.1`, `1.2.0-alpha.1`,
  `1.2.0-alpha.1`, and `1.2.0~alpha.1-1` before the independent numeric
  protocol/configuration versions.
- Confirm formal Ubuntu 26.04 LTS `amd64` evidence came from a source-bound
  disposable target fixture, not from a physical host running another OS.
- Confirm the three layers in `docs/CI_AND_RELEASE_GATES.md`: local preflight,
  `public-pr-ci / public-pr-gate`, and an accepted exact-commit
  `release-candidate-ci` run for the requested stage.
- Confirm the release-candidate workflow used the ledger's full
  `maverick_release_commit`. Record the workflow control commit separately; a
  later ledger/control-record commit must not be confused with release source.
- Do not dispatch release-candidate CI until the coordinator approves the
  frozen inputs. A passing run does not authorize a tag, package publication,
  or GitHub Release.

## Safety

- Default release checks must not change host proxy, DNS, route, firewall, VPN,
  or other network-service settings.
- Do not commit generated credentials or private keys.
- Do not expose non-loopback listeners in tests.
- Do not run real TUN, route, DNS, interface, firewall, or VPN tests without a
  separately approved disposable external system and the
  `docs/TUN_PHASE2_EXECUTION_GATE.md` evidence/cleanup gate.
- Verify pre-auth failures return fallback behavior rather than protocol detail.

## Verification

Run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/release-artifacts.sh
./scripts/benchmark-baseline.sh 65536
./scripts/benchmark-dashboard.sh docs/BENCHMARK_DASHBOARD.md 65536
python3 scripts/check-production-readiness.py
python3 scripts/check-security-review-package.py
```

Confirm:

- formatting passes;
- Clippy passes with `-D warnings`;
- all tests pass;
- generated configs validate;
- config migration dry-runs validate;
- hygiene scans pass;
- optional H3 harness passes when releasing H3 work;
- dependency and source policy checks pass with `cargo audit` and
  `cargo deny check advisories bans licenses sources`;
- first-party unsafe-code inventory is empty, or every unsafe construct is
  documented and reviewed before release;
- release artifacts include `BUILDINFO` and `SHA256SUMS`, and checksum
  verification passes on the generated `dist/` directory;
- stable release artifacts include `SHA256SUMS.sig` when a project release
  signing key is available;
- artifact privacy checks pass, including no local repository path or home
  directory in the generated release files;
- benchmark output is recorded or attached to release notes.
- the readiness ledger is internally consistent and stays No-Go unless all five
  dimensions and final approval are complete;
- independent audit status names the frozen candidate honestly; Codex, AI,
  maintainer, and earlier scoped review input is not called the formal audit;
- public maintainer identity, `noreply` email privacy, commit/tag signatures,
  and staged privacy checks follow `docs/MAINTAINER_IDENTITY_AND_SIGNING.md`.
- public PR CI uses one `ubuntu-24.04` runner lane only as public CI
  infrastructure, plus change-relevant experimental jobs; release-candidate CI
  uses one exact-source lane rather than a support matrix;
- public workflows do not clone the private reference client or contain private
  host, address, provider, account, path, credential, or raw-evidence data;
- an Ubuntu 24.04 Actions result is not relabeled as formal Ubuntu 26.04
  supported-platform evidence without the source-bound fixture and exact
  private package gates.

`cargo-geiger` was evaluated for unsafe-code inventory, but the current local
tooling repeatedly fails to parse `signal-hook-registry 1.4.8` in this
workspace dependency graph. Until that upstream/tooling gap is resolved,
`scripts/security-dependency-inventory.sh` is the release gate for dependency
advisories plus first-party unsafe-code inventory.

## Compatibility

- Review `COMPATIBILITY.md`.
- Review `MIGRATIONS.md`.
- Review `docs/INTEROP_MATRIX.md`.
- Verify old v1/v1.1 example configs still validate or document why not.
- Confirm public feedback since the previous tag was triaged as
  security-private, release-blocker, active-milestone-candidate,
  docs-clarification, future-track, or out-of-scope.
- For stable-scope candidates, review `docs/FAILURE_INJECTION_PLAN.md` and
  attach completed approved-host evidence for any claimed failure-recovery
  behavior.

## Release Notes

Release notes must include:

- feedback handled since the previous tag, if any;
- experimental status;
- implemented features;
- known limitations;
- Native ECH tracking status and the Cloudflare-fronted workaround boundary;
- test command used;
- benchmark command used;
- upgrade or migration notes;
- commit hash.
- separate release, SDK, reference-client, package, and version bindings for the
  `v1.2.0` train;
- the exact named platform and permanent non-claims;
- current audit and production-readiness state without turning a temporary
  blocker into a permanent scope statement.

Historical alpha-through-v1.0 release notes live under
`docs/history/release/`. New post-v1 release notes follow the active milestone
and release mapping in `docs/PLAN_POST_V1.md`. The completed release train and
short-term plan remain the evidence source only for `v1.0.0` and its earlier
prereleases.
