# Security Review Plan

Status: review-input reference with a machine-readable package manifest.
Third-party AI review, scoped alpha review, and the v1 anonymous review bundle
were triaged and remediated for their recorded scopes. Post-v1 M6 evidence is
separate and accepted for its recorded direct TLS/H2 engineering scope. This is
not a formal independent security audit.

This plan defines what Maverick should provide to an external reviewer before a
future production-audited, production-ready, or strong security claim. It is
not an audit result, an active roadmap by itself, or a security endorsement.

The formal production-audit process is now prepared separately in
`docs/INDEPENDENT_AUDIT_PACKAGE.md` and `docs/AUDIT_EVIDENCE_INDEX.md`. It cannot
start until the coordinator freezes separate Maverick release, Maverick SDK, and
reference-client commits, verifies the reference-client SDK pin, and records the
exact package and evidence-tool hashes.

## Review Goals

- Validate authentication transcript binding, replay protection, fallback
  behavior, and credential rotation.
- Review parser and frame handling for malformed input, bounds, and resource
  exhaustion risks.
- Review logging, diagnostics, config import/export, and key inventory for
  secret leakage.
- Review experimental feature gates so H3, ECH, shaping, TUN, and crypto
  experiments cannot become default paths accidentally.
- Review conformance vectors and spec/wire alignment before any freeze claim.

## Required Inputs

The machine-readable package manifest is `security-review-package.json`; it can
be validated by `scripts/check-security-review-package.py` when changing review
inputs. It is metadata validation, not a default runtime gate or completed
review.

- `SPEC.md`, `WIRE_FORMAT.md`, `COMPATIBILITY.md`, `MIGRATIONS.md`,
  `THREAT_MODEL.md`, `SECURITY.md`.
- `STATUS.md`, `ROADMAP.md`, `docs/CAPABILITY_REPORT.md`, and
  `docs/EXPERIMENTAL_TRACKS.md`.
- `docs/ROADMAP_BLOCKERS.md`, `docs/BLOCKER_RESOLUTION_PLAN.md`, and
  `docs/MACOS_APP_BOUNDARY.md`.
- `docs/AUTH_V2_SPEC.md`, `docs/CREDENTIAL_ROTATION.md`,
  `docs/SHAPING_ENGINE.md`, and `docs/ECH_FEATURE_GATE.md`.
- `docs/CRYPTO_AGILITY.md`, `docs/HPKE_NOISE_EXPERIMENTS.md`,
  `docs/ML_KEM_HYBRID.md`, and `docs/KEY_LIFECYCLE.md`.
- Conformance vectors and runners under `conformance/`.
- Local harness scripts under `scripts/`.
- `docs/PRODUCTION_SCOPE.md`, `production-readiness.json`,
  `docs/INDEPENDENT_AUDIT_PACKAGE.md`, `docs/AUDIT_EVIDENCE_INDEX.md`, and
  `docs/AUDIT_REMEDIATION_POLICY.md` for the production-scoped review.

## AI-Assisted Review

Third-party AI reviews are useful for additional static-analysis passes and
prompt variance. For Maverick's current personal as-is prototype phase, they
are acceptable evidence to drive engineering fixes and to defer the formal
human-audit blocker out of the active development path.

AI review still must not be represented as a formal audit, certification,
production sign-off, or proof of censorship resistance. Treat AI reports as
review input: record the model/tool, the reviewed commit, the prompt, commands
run, limitations, and then triage every finding against the codebase before
changing blocker status.

For the current release posture, the minimum requirement is honest wording:
Maverick may describe third-party AI review, scoped alpha review input, beta
approved-host evidence, and local harness results, but it must not imply a
formal audit, stable security certification, or production security
certification.

The current AI-review handoff prompt is
`docs/history/review/AI_SECURITY_REVIEW_PROMPT_2026_06_28.md`.

## Pre-Review Gates

Run and record:

```sh
./scripts/local-harness.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/conformance.sh
python3 scripts/check-security-review-package.py
```

Reviewers may run loopback-only tests on a local machine. Tests must not change
system proxy, DNS, route, firewall, VPN, or other host network-service settings.

## Out-of-Scope Without Separate Host

The following require a separate VM or explicitly approved test machine:

- real TUN device creation;
- route, DNS, firewall, VPN, or system proxy mutation;
- WAN ECH handshake testing with controlled DNS records;
- no-domain, multi-hop, or censorship-resilience experiments;
- load tests that could disrupt the developer's daily connectivity.

## Review Phases

1. Documentation and threat-model review.
2. Parser, auth, replay, fallback, and logging code review.
3. Config, CLI, SDK, and diagnostic redaction review.
4. Experimental gate review for H3, ECH, shaping, TUN, and crypto agility.
5. Loopback harness reproduction and conformance vector review.
6. Findings triage, fix verification, and residual-risk sign-off.

## Finding Handling

Security findings should be tracked privately until triaged. Public release
notes should describe fixed impact classes without publishing working exploit
details before users have a reasonable update path.

## Completion Criteria

A scoped human or community review can be marked complete only when:

- reviewed commit or tag is recorded;
- reviewer scope and exclusions are documented;
- high and critical findings are fixed or explicitly deferred with rationale;
- `./scripts/local-harness.sh` and `./scripts/conformance.sh` pass after fixes;
- residual risks are reflected in `SECURITY.md`, `THREAT_MODEL.md`, and
  `docs/CAPABILITY_REPORT.md`.

That scoped review completion is not automatically the independent production
audit. The production audit additionally requires the independence, frozen
binding, target-platform, report-hash, remediation, and final-deliverable rules
in `docs/INDEPENDENT_AUDIT_PACKAGE.md`.
