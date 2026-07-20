# Short/Mid-Term Plan: Alpha to Stable v1.0.0

Status: completed release-train record. `v1.0.0` was published on
2026-07-09 as a real GitHub release for the narrow
`maverick-tls-h2-cli-v1` scope. Keep this document as the v1 planning and gate
history; future work belongs in `docs/PLAN_POST_V1.md`.

## Objective

Ship a real open-source `v1.0.0` for the **narrow, frozen scope**
`maverick-tls-h2-cli-v1` (see `docs/STABLE_SCOPE_CANDIDATE.md`):
TLS 1.3 + HTTP/2, CLI-managed Rust client/server, TCP/DNS/UDP relay, no native
ECH, no anonymity claim, no GUI. Everything else stays experimental and
default-off. Stabilize the small path first; do not widen scope to reach 1.0.

## Honest Reframe (read before executing)

Unreserved advice, not bound by prior decisions in this repo:

1. **The narrow 1.0 scope excludes the reason to use the tool.** The frozen
   scope deliberately drops stealth/indistinguishability and anonymity. That
   makes 1.0 *reachable*, but a TLS/H2 proxy that is trivially fingerprintable
   is not clearly better than existing options. Do not ship a 1.0 whose headline
   is "we froze the easy part." Either (a) accept 1.0 as an honest *engineering*
   release of a plumbing layer and say exactly that, or (b) pull the first
   stealth-evidence milestone (`PLAN_LONG_TERM.md` Track A.1: reproducible
   JA3/JA4 + capture deltas) into this train as an S1/S2 gate. Recommendation:
   (b) if the goal is adoption; (a) only if 1.0 is explicitly a personal
   milestone.

2. **Protocol freeze before users is likely freezing the wrong things.** S3
   freezes the wire before anyone external has run it at scale. Freeze *follows*
   usage; freezing first locks in mistakes you can't yet see. Prefer: publish
   the wire format, keep a "may change until X real deployments / second
   implementation" caveat, and freeze at 1.1+ once feedback exists.

3. **Do not hard-gate 1.0 on a formal audit that may never come.** A paid
   third-party audit is unlikely for a solo, unfunded project. Decide now what
   "reviewed" honestly means for 1.0: make the code auditable, solicit
   community/adversarial review, fix and publish findings — and label 1.0
   "community-reviewed, not formally audited." Blocking 1.0 on an audit with no
   funding path just means no 1.0.

4. **The process/doc debt is a symptom, not a chore.** ~60 docs, dozens of JSON
   manifests, and per-alpha "post-release audits" for a zero-user prototype mean
   effort is going into ceremony instead of the hard problem (stealth) and the
   scarce resource (users + adversarial attention). S0 is not cleanup; it is
   redirecting effort. Weight every new artifact against this.

The rest of this plan is still valid *if* the owner consciously chooses the
narrow-scope 1.0 with these caveats made explicit in the release notes.

## Guiding Constraints

- Do not expand stable scope to hit a deadline. New transports/crypto/TUN/GUI
  remain out of 1.0.
- Preserve all `ROADMAP.md` invariants (H2 fallback, no 0-RTT, feature gates,
  no host-network mutation on this machine, bounded resources).
- Reduce process/doc weight as a first-class task (`STATUS.md` near-term item 5):
  every phase should retire more manifests/docs than it adds.
- Honesty gates: no "audited / production / anonymous / censorship-resistant"
  language until the specific evidence exists.

## Phase Overview

| Phase | Tag target | Theme | Exit = reviewer sign-off on |
| --- | --- | --- | --- |
| S0 | (no tag) | Freeze scope + cut process debt | frozen scope + slimmed docs |
| S1 | `v0.1.0-beta.1` | Runtime hardening (abuse/DoS, observability) | hardening coverage + beta tag |
| S2 | `v0.1.0-beta.2` | Second-host + impairment evidence | reproducible external evidence |
| S3 | `v0.1.0-rc.1` | External security review + protocol freeze | review closed + frozen vectors |
| S4 | `v1.0.0` | Release + docs/announcement | full v1.0.0 gate |

Each phase is independently shippable. Do not begin a phase until the prior
phase gate has a recorded reviewer audit.

---

## Phase S0: Freeze Scope and Cut Process Debt

Goal: lock what 1.0 is and shrink the maintenance surface before hardening.

Tasks:
1. Ratify `maverick-tls-h2-cli-v1` in `SPEC.md` as the single v1.0 target;
   state the frozen frame/auth/fallback surface explicitly.
2. Inventory `docs/` (currently ~60 files) and `*.json` manifests. Classify
   each as: keep, merge, or archive. Move historical audits/readiness/evidence
   snapshots under `docs/history/`. Target: top-level docs a new contributor
   must read drop to a short, named set.
3. Collapse the JSON blocker/approval manifests that are no longer active
   gates. Keep only checkers still wired into a phase gate.
4. Write a one-page `docs/RELEASE_TRAIN.md` describing the alpha -> beta -> rc
   -> stable train and which gate each tag needs (supersedes scattered
   readiness docs).

Acceptance:
- `SPEC.md` names the frozen v1.0 scope and exclusions.
- Historical docs relocated; contributor entry path is short.
- `./scripts/local-harness.sh` still green.

Reviewer audit: confirm scope wording matches `STABLE_SCOPE_CANDIDATE.md`, no
scope creep, and doc reduction is real (net fewer active docs/manifests).

---

## Phase S1: Runtime Hardening (`v0.1.0-beta.1`)

Goal: make the frozen path safe to run unattended on the public internet.

Tasks:
1. Abuse / DoS controls, with tests:
   - failed-auth pacing/rate-limit already exists — add explicit per-source and
     global connection caps, pre-auth memory/time budgets, and fallback-load
     behavior under flood. Verify no unique error signal leaks (must look like
     fallback site).
2. Observability:
   - redacted structured logs and the loopback metrics endpoint must expose
     enough for an operator to see auth failures, fallback rate, active flows,
     and resource pressure — without secrets/payload. Add log-hygiene test
     coverage for the new fields.
3. Deployment hardening:
   - finalize systemd examples, least-privilege user, file permissions, cert
     renewal, and a documented rollback. Keep in `docs/OPERATIONS.md`.
4. Move from `alpha` to `beta` naming: beta means "scope frozen, still
   collecting evidence," not "feature-adding."

Acceptance:
- New abuse/observability/hardening behavior is covered by loopback tests in
  the default gate.
- `./scripts/local-harness.sh`, `security-dependency-inventory.sh`,
  `release-artifacts.sh` green.
- `v0.1.0-beta.1` tagged as GitHub pre-release with honest notes.

Reviewer audit: attempt to find a probe/error that distinguishes tunnel from
fallback under the new limits; confirm no secret/PII in new logs/metrics;
confirm no stable-scope behavior changed incompatibly.

---

## Phase S2: Independent Evidence (`v0.1.0-beta.2`)

Goal: satisfy the evidence blocker that currently forces "pre-stable."

Tasks:
1. Second approved client host: `STABLE_SCOPE_CANDIDATE.md` says the candidate
   must stay pre-stable without a second approved client host. Provision one
   (approved VM, not this machine) and run the 24h detached TCP/H2 long-haul
   from a distinct host.
2. Network impairment: extend the netem profiles beyond the current diagnostic
   set to the latency/loss conditions 1.0 will actually claim; record what is
   and is not covered.
3. Failure injection: keep the process-level pack current; add reconnect and
   fallback-target-failure cases if any beta.1 change touched them.
4. Record all evidence under `docs/history/` with what ran, where, and what it
   did not prove.

Acceptance:
- Two-host long-haul evidence exists and is reproducible via the scripts.
- Impairment evidence matches the exact conditions 1.0 will claim (no more).
- `v0.1.0-beta.2` tagged.

Reviewer audit: verify evidence host is not the dev machine, no host-network
mutation occurred locally, and claims in notes are bounded by the evidence.

---

## Phase S3: External Review + Protocol Freeze (`v0.1.0-rc.1`)

Goal: the two hardest 1.0 prerequisites for a privacy proxy. See Honest Reframe
points 2 and 3 first — both of these gates are premature-ceremony risks. Treat
"review" as community/adversarial review with published findings unless funding
for a formal audit appears, and prefer a soft freeze (published wire + change
window) over a hard freeze before real usage exists.

Tasks:
1. External security review:
   - use `docs/SECURITY_REVIEW_PLAN.md` and the security-review package as
     input; get at least one credible independent review of the frozen scope
     (auth transcript, replay, fallback indistinguishability, resource bounds,
     TLS config).
   - triage findings; fix blockers; record accepted-risk items publicly.
2. Protocol freeze:
   - run `SPEC_FREEZE_PROCESS.md` for the frozen scope; snapshot conformance
     vectors; enable the frozen-vector immutability checker as a release gate.
   - freeze config `version` and `protocol_version` for 1.0; document any
     migration.
3. Vulnerability handling: confirm `SECURITY.md` has a real disclosure/response
   process before public 1.0.
4. Tag `v0.1.0-rc.1`; announce a fixed RC soak window.

Acceptance:
- Independent review completed; no open blocker findings for the frozen scope.
- Frozen conformance vectors recorded and gate-enforced.
- `SECURITY.md` disclosure process is real and reachable.

Reviewer audit: confirm review actually covered the frozen scope (not just
metadata manifests); confirm frozen vectors are immutable in CI; confirm no
overclaim entered docs.

---

## Phase S4: Stable Release (`v1.0.0`)

Goal: the real open-source stable release for the narrow scope.

Tasks:
1. Only bugfix-level changes after `rc.1`; no scope changes.
2. Final v1.0.0 gate:
   ```sh
   cargo fmt --all -- --check
   ./scripts/local-harness.sh
   ./scripts/security-dependency-inventory.sh
   ./scripts/conformance.sh
   ./scripts/release-artifacts.sh
   ```
   plus current two-host long-haul evidence and closed review.
3. Rewrite `README.md`/`STATUS.md` claim language for the audited, frozen,
   narrow-stable scope — still explicitly no anonymity, no native ECH, no GUI.
4. `v1.0.0` as a real (non-prerelease) GitHub release with signed checksums,
   changelog, and migration notes from the last beta/rc.
5. Post-release audit (as with prior tags) recorded under `docs/history/`.

v1.0.0 exit criteria (all required):
- Frozen scope shipped; nothing outside scope claimed.
- Independent review closed with no open blockers.
- Two-host long-haul + bounded impairment evidence current.
- Abuse/DoS, observability, deployment hardening covered by tests/docs.
- Default gate + artifact gate green; checksums published.
- Claim language honest and scoped.

Reviewer audit (final gate): independently reproduce the gate, verify checksums,
diff public claims against evidence, and sign off or block.

Completion record:

- historical release id: `v1.0.0` (private pre-publication record; URL not
  migrated)
- post-release audit: `docs/history/release/POST_RELEASE_AUDIT_v1.0.0.md`
- tagged commit: `98c5d7c85991618d322d6cd4240fae5c7dec1598`

---

## Cadence

This is the recurring loop the owner runs: plan phase -> engineers implement ->
AI reviewer audits the phase gate -> proceed or iterate. Long-term evolution
after 1.0 is in `docs/PLAN_POST_V1.md`.
