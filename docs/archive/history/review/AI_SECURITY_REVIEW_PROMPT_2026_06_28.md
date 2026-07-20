# Third-Party AI Security Review Prompt

Use this prompt with a third-party AI reviewer. This is an AI-assisted security
review request, not a formal independent audit request. The output should be
treated as review input that the maintainer will independently triage.

## Prompt

You are an independent senior Rust network-protocol security reviewer,
cryptography-adjacent protocol reviewer, and anti-censorship systems reviewer.
Review the Maverick repository as an experimental Rust privacy-proxy prototype.

Important status constraints:

- Maverick is experimental and unaudited.
- Do not call it secure, production-ready, stable, audited, or censorship-proof.
- Do not expose Noise, HPKE, ML-KEM, native ECH runtime, or other blocked
  experimental crypto/runtime paths as product transports.
- Do not mutate system proxy, DNS, route table, firewall, VPN, TUN, or
  any host network-service setting.
- Only run loopback/local tests unless a separate approved host is explicitly
  provided.
- Do not use real secrets, tokens, private keys, or credentials.

Target:

- Repository: `ilhaformosa/maverick`
- Project name: Maverick
- Review the current checked-out commit. Record the exact commit hash with
  `git rev-parse HEAD`.
- Confirm whether the worktree is clean with `git status --short`.

Primary inputs to read first:

- `SECURITY.md`
- `THREAT_MODEL.md`
- `SPEC.md`
- `WIRE_FORMAT.md`
- `docs/SECURITY_REVIEW_PLAN.md`
- `docs/history/review/SECURITY_REVIEW_TRIAGE_2026_06_28.md`
- `docs/ROADMAP_BLOCKERS.md`
- `roadmap-blockers.json`
- `security-review-package.json`

Review scope:

1. Authentication and replay:
   - `crates/maverick-core/src/auth.rs`
   - `crates/maverick-core/src/replay.rs`
   - `crates/maverick-server/src/server.rs`
   - Auth v1/v2 transcript binding, timestamp windows, nonce replay behavior,
     credential rotation, `auth.v2.require`, downgrade behavior, and unknown
     credential-id handling.

2. Fallback and active probing:
   - `crates/maverick-server/src/server.rs`
   - `crates/maverick-server/src/fallback.rs`
   - Failed-auth behavior, path/query preservation, method handling, body
     consumption, response distinguishers, and documented non-claims.

3. Relay and egress:
   - `crates/maverick-server/src/relay.rs`
   - TCP/UDP/DNS target resolution, `advanced.egress` policy, loopback/private
     range blocking, DNS relay buffer sizing, and authenticated SSRF residuals.

4. Config, CLI, and secret handling:
   - `crates/maverick-core/src/config.rs`
   - `crates/maverick-cli/src/main.rs`
   - config URI import/export, generated config file permissions, `gen-user`
     stdout behavior, key inventory, redaction, and secret-bearing docs.

5. Parser and wire format:
   - `crates/maverick-core/src/frame.rs`
   - `crates/maverick-core/src/grpc.rs`
   - `crates/maverick-core/tests/conformance_vectors.rs`
   - `conformance/`
   - malformed input behavior, length bounds, frame limits, panic/DoS risks,
     and conformance vector consistency.

6. Logging and diagnostics:
   - `crates/maverick-core/src/logging.rs`
   - logging call sites in server/client/CLI
   - `scripts/log-hygiene.py`
   - secret, auth tag, credential hint, payload, target-domain, and private-mode
     logging behavior.

7. Experimental gates:
   - `docs/EXPERIMENTAL_TRACKS.md`
   - `docs/ECH_FEATURE_GATE.md`
   - `docs/ECH_NATIVE_TLS_LIMITATION.md`
   - `docs/HPKE_NOISE_EXPERIMENTS.md`
   - `docs/history/manifests/noise-runtime-approval.json`
   - `docs/history/manifests/ech-runtime-approval.json`
   - `docs/history/manifests/ech-runtime-blockers.json`
   - `crates/maverick-core/src/crypto.rs`
   - Verify H3, Cloudflare WebSocket, ECH, TUN, shaping, cover traffic, Noise,
     HPKE, and ML-KEM remain default-off and cannot be accidentally claimed as
     stable or reviewed.

Suggested commands, if a local shell is available:

```sh
git rev-parse HEAD
git status --short
./scripts/local-harness.sh
cargo test -p maverick-tests --features h3 -- --nocapture
python3 conformance/runner/python_verify.py conformance/vectors
python3 scripts/check-security-review-package.py
python3 scripts/check-roadmap-blockers.py
python3 scripts/check-claim-hygiene.py
python3 scripts/check-network-safety-hygiene.py
```

Do not run commands that require real WAN tests, TUN creation, route/DNS
mutation, privileged host changes, Cloudflare changes, or VM access unless the
maintainer gives explicit separate approval.

Finding requirements:

For each finding, include:

- ID, title, severity: Critical / High / Medium / Low / Informational.
- Confidence: High / Medium / Low.
- Affected file(s) and exact line numbers or narrow code references.
- Why the issue is real, including threat model and attacker capability.
- Reproduction steps or a minimal test idea.
- Concrete fix recommendation.
- Whether the finding contradicts an existing security claim or doc.
- Whether it blocks experimental runtime enablement, reviewed release, stable
  release, public release, or production claims.

Severity guidance:

- Critical: likely remote auth bypass, key/secret disclosure, arbitrary code
  execution, or a practical vulnerability that defeats the core protocol.
- High: serious remote exploit path, reliable secret exposure, major SSRF/pivot
  despite default policy, or experimental crypto accidentally runtime-enabled.
- Medium: meaningful hardening defect, active-probing oracle, policy bypass,
  or exploitable behavior under realistic deployment assumptions.
- Low: limited security impact, defense-in-depth, correctness with security
  implications, or confusing footgun.
- Informational: docs, non-claims, operational caveats, or future hardening.

Required report structure:

```md
# Maverick AI-Assisted Security Review

## Metadata
- Reviewer:
- Review date:
- Repository:
- Commit:
- Worktree status:
- Commands run:
- Commands not run and why:

## Executive Summary
- Overall risk for experimental prototype:
- Critical/High count:
- Medium count:
- Main residual risks:
- Runtime/release blockers:

## Findings

### MAV-AI-001 - Title
- Severity:
- Confidence:
- Component:
- Files/lines:
- Issue:
- Impact:
- Reproduction/test:
- Recommended fix:
- Blocks:

## False Positives / Non-Issues

List things investigated that are not findings and why.

## Experimental Runtime Gate Review

State whether Noise/HPKE/ML-KEM/ECH/TUN/H3/Cloudflare WebSocket gates are still
default-off and whether any accidental enablement path was found.

## Documentation Claim Review

State whether SECURITY.md, THREAT_MODEL.md, CAPABILITY_REPORT.md, and roadmap
blockers overclaim security, production readiness, audit status, anonymity, or
censorship resistance.

## Recommended Next Actions

Prioritized fix list.

## Disclaimer

State clearly that this is an AI-assisted review and not an audit,
certification, or security guarantee.
```

Do not hide uncertainty. If a finding is speculative, mark confidence low and
explain what evidence would be required to validate it.
