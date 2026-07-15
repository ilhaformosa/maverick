# Documentation Index

Status: active contributor map. Historical release and evidence records remain
available without being part of the everyday reading path.

## Read First

1. `README.md`: project overview and local quick start.
2. `STATUS.md`: current capability and claim boundary.
3. `docs/PLAN_POST_V1.md`: active execution plan and milestone gates.
4. `ROADMAP.md`: concise public direction and sequencing.
5. `SPEC.md` and `WIRE_FORMAT.md`: protocol and frame behavior.
6. `CONFIG.md`: client/server configuration and operator behavior.
7. `SECURITY.md` and `THREAT_MODEL.md`: security boundaries and non-claims.
8. `TEST_PLAN.md` and `docs/HARNESS_ENGINEERING.md`: verification rules.

## Active Operational References

- `docs/OPERATIONS.md`: deployment and service operation.
- `COMPATIBILITY.md` and `MIGRATIONS.md`: upgrade behavior.
- `RELEASE_CHECKLIST.md`, `docs/RELEASE_ARTIFACTS.md`, and
  `docs/RELEASE_TAGGING.md`: release gates and artifact verification.
- `SUPPORT.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`: support,
  contribution, and community boundaries.
- `docs/OPEN_SOURCE_PHASE1_GO_NO_GO_2026_07_15.md`: source-publication audit
  boundary and owner gates.
- `docs/PUBLIC_HISTORY_BOUNDARY.md`: sanitized public root, private historical
  release, tag, and evidence boundaries.
- `docs/CAPABILITY_REPORT.md`: detailed implementation inventory.

## Focused Technical References

Read these only when working on the named area:

- stealth and transport: `docs/STEALTH_PRIORITY.md`,
  `docs/STEALTH_MEASUREMENT.md`, `docs/TRANSPORT_ARCHITECTURE.md`,
  `docs/HANDSHAKE_FALLBACK_DECISION.md`, `docs/H3_QUIC_PLAN.md`,
  `docs/ECH_FEATURE_GATE.md`, `docs/NATIVE_ECH_TRACKING.md`, and
  `docs/SHAPING_ENGINE.md`;
- authentication and keys: `docs/AUTH_V2_SPEC.md`,
  `docs/CREDENTIAL_ROTATION.md`, and `docs/KEY_LIFECYCLE.md`;
- platform/client work: `docs/TUN_MODE_DESIGN.md`,
  `docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md`, `docs/CONFIG_URI.md`,
  `docs/TUN_ENGINE_RESEARCH.md`, `docs/TUN_ENGINE_COMPARISON.md`,
  `docs/TUN_PACKET_ADAPTER_CONTRACT.md`, `docs/TUN_PHASE2_EXECUTION_GATE.md`,
  `docs/TUN_SYNTHETIC_TEST_MATRIX.md`, `docs/SDK_PLAN.md`,
  `docs/PLATFORM_HELPER_IPC.md`,
  `docs/REFERENCE_CLIENT_CONTROLLER.md`,
  `docs/REFERENCE_CLIENT_SELECTION.md`,
  `docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`,
  `docs/GUI_TRAY_ARCHITECTURE.md`, and `docs/MACOS_APP_BOUNDARY.md`;
- experimental crypto: `docs/CRYPTO_AGILITY.md`,
  `docs/HPKE_NOISE_EXPERIMENTS.md`, and `docs/ML_KEM_HYBRID.md`;
- conformance/ecosystem: `docs/CONFORMANCE_SUITE.md`,
  `docs/SPEC_FREEZE_PROCESS.md`, `docs/INTEROP_MATRIX.md`, and
  `docs/GOVERNANCE.md`;
- benchmarks/evidence tooling: `docs/BENCHMARK_BASELINE.md`,
  `docs/BENCHMARK_DASHBOARD.md`, `docs/SHAPE_LAB_BASELINE.md`, and
  `docs/FAILURE_INJECTION_PLAN.md`.

Experimental crypto, no-domain, multi-hop, WebTransport, plugin, native ECH,
standardization, and governance expansion are currently frozen unless
`docs/PLAN_POST_V1.md` explicitly reactivates them.

## Completed Plans And History

- `docs/PLAN_SHORT_TERM_TO_V1.md`: completed alpha-to-v1 release plan.
- `docs/RELEASE_TRAIN.md`: completed v1 gate summary.
- `docs/STABLE_SCOPE_CANDIDATE.md`: historical v1 frozen-scope decision.
- `docs/PLAN_LONG_TERM.md`: long-term direction reference; execution order now
  comes from `docs/PLAN_POST_V1.md`.
- `docs/history/alpha/`: alpha readiness records.
- `docs/history/evidence/`: approved-host runtime and impairment evidence.
- `docs/history/evidence/APPROVED_HOST_POST_V1_M6_EVIDENCE_2026_07_11.md`:
  accepted redacted post-v1 M6 evidence summary.
- `docs/history/readiness/`: superseded readiness snapshots.
- `docs/history/release/README.md`: boundary for the pre-publication private
  release notes and post-release audits in that directory; identifiers are
  historical and are not public Git objects.
- `docs/history/review/`: dated security-review and remediation records.
- `docs/history/manifests/`: inactive experimental approval/blocker snapshots.

## Machine-Checked Metadata

Active protocol/release inputs:

- `conformance/` frozen releases, manifests, implementation registry, and
  vectors;
- `fuzz/seed-manifest.json`;
- `test-vectors/`;
- `roadmap-blockers.json`;
- `security-review-package.json`;
- `spikes/tun-engine-comparison/` plus
  `scripts/check-tun-engine-comparison.py`;
- Phase 1 packet-runtime source/docs plus
  `scripts/check-tun-packet-runtime.py`.

Historical manifests are evidence indexes, not permission to run privileged or
remote mutation tests. Any future reactivation must update the relevant plan,
checker, and approval boundary together.
