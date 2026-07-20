# S0 Scope And Process-Debt Audit

Date: 2026-07-06

Status: Phase S0 reviewer sign-off for `docs/PLAN_SHORT_TERM_TO_V1.md`. This
is not a stable-release, production-readiness, anonymity, censorship-resistance,
or formal-audit claim.

## Reviewed Scope

The S0 implementation ratifies `maverick-tls-h2-cli-v1` as the only intended
`v1.0.0` target in `SPEC.md`, matching `docs/STABLE_SCOPE_CANDIDATE.md`.

Included scope confirmed:

- Rust reference client and server managed by the CLI.
- TLS 1.3 plus HTTP/2 stable transport.
- Auth v1/v2 ClientHello and ServerHello behavior.
- Replay cache behavior.
- Static or reverse-proxy fallback for ordinary and unauthenticated
  tunnel-like requests.
- TCP, DNS, and documented UDP relay behavior.
- Per-user flow limits, optional byte pacing, pre-auth admission limits,
  failed-auth rate limiting, loopback-only metrics, config version `1`, and
  protocol version `1`.

Excluded scope confirmed:

- Native server-side ECH.
- Cloudflare-fronted WebSocket as a stable transport.
- H3/QUIC as a stable transport.
- TUN system apply behavior.
- GUI/App runtime behavior.
- Post-quantum or Noise experimental handshakes.
- Strong anonymity, traffic-analysis resistance, censorship-proof, audited, or
  production-ready claims.

Audit result: no scope creep found.

## Process-Debt Reduction

Before S0, `docs/` had 63 top-level files and no history directory. After S0,
`docs/` has 47 top-level files, and 24 historical files live under
`docs/history/`.

Historical files moved:

- Alpha readiness trackers: `docs/history/alpha/`.
- Approved-host runtime, failure-injection, and impairment evidence snapshots:
  `docs/history/evidence/`.
- Old public/stable readiness snapshots: `docs/history/readiness/`.
- Alpha release notes and post-release audits: `docs/history/release/`.
- Dated security-review prompts and triage records:
  `docs/history/review/`.

Root blocker/approval JSON files were removed from the root gate surface. The
only root-level JSON manifests left are `roadmap-blockers.json` and
`security-review-package.json`. Long-term experimental blocker/approval
manifests now live under `docs/history/manifests/` and are not `v1.0.0`
release-train gates.

Audit result: doc and manifest reduction is real.

## Active Entry Path

New active entry documents:

- `docs/DOCS_INDEX.md`: short contributor path plus active/history inventory.
- `docs/RELEASE_TRAIN.md`: one-page alpha -> beta -> rc -> stable gate
  summary.

`README.md`, `RELEASE_CHECKLIST.md`, `docs/RELEASE_TAGGING.md`, and
`docs/RELEASE_ARTIFACTS.md` now point release planning at
`docs/PLAN_SHORT_TERM_TO_V1.md` and `docs/RELEASE_TRAIN.md` instead of old
alpha/stable readiness snapshots.

Audit result: contributor entry path is shorter.

## Verification

Passed:

```sh
git diff --check
python3 scripts/claim-hygiene.py
python3 scripts/check-security-review-package.py
python3 scripts/check-roadmap-blockers.py
python3 scripts/check-ech-runtime-approval.py
python3 scripts/check-ech-runtime-blockers.py
python3 scripts/check-gui-runtime-blockers.py
python3 scripts/check-noise-runtime-approval.py
python3 scripts/check-tun-helper-approval.py
python3 scripts/check-tun-runtime-blockers.py
./scripts/local-harness.sh
```

`./scripts/local-harness.sh` completed formatting, Clippy, workspace tests,
conformance, fuzz smoke, generated config validation, and repo hygiene with
`local harness OK`.

## Sign-Off

S0 is complete. The next phase is S1 runtime hardening for
`v0.1.0-beta.1`. Do not begin S1 by expanding scope; begin with abuse/DoS
controls, redacted observability, and deployment hardening for the frozen
TLS/H2 path.
