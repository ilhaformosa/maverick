# Maverick v0.1.0-rc.1 Release Notes

Status: first release-candidate source snapshot for the frozen
`maverick-tls-h2-cli-v1` release train.

Maverick remains an experimental as-is prototype. RC.1 means the S3
review-input and protocol-freeze readiness gates have current evidence for the
narrow CLI-managed TLS 1.3 plus HTTP/2 scope. It does not mean
production-ready, formally audited, anonymous, censorship-resistant,
standardized, or browser-fingerprint equivalent.

## Highlights

- S3 review-input closure: the imported anonymous review bundle was triaged,
  remediated, and recorded in
  `docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`.
- Security remediation: the RC includes fallback-preservation fixes, TLS
  exporter channel binding for direct rustls H2/WebSocket authentication, H2
  reset/admission bounds, task-drain handling, split replay-cache accounting,
  constant-time certificate pin comparison, and reduced secret cloning in
  service auth paths.
- Supply-chain and unsafe-code gates: YAML parsing now uses `serde_yaml_ng`;
  the repository has a `cargo deny` policy, weekly supply-chain workflow, and
  first-party `#![forbid(unsafe_code)]` coverage.
- Freeze readiness: `conformance/freeze-readiness.json` is ready for the
  narrow RC scope, and `conformance/implementation-registry.json` tracks the
  candidate implementation without claiming a standard or second
  implementation.
- CI budget control: code, protocol, conformance, script, and workflow changes
  still run the full CI gate; documentation and metadata-only changes use the
  lighter docs-hygiene gate.

## Version Boundaries

- software release tag: `v0.1.0-rc.1`;
- package version: `0.1.0-rc.1`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-beta.2`.

## Evidence Boundary

The S2 runtime evidence remains
`docs/history/evidence/APPROVED_HOST_S2_INDEPENDENT_EVIDENCE_2026_07_08.md`.
The S3 review-input closure is
`docs/history/review/S3_REVIEW_CLOSURE_2026_07_08.md`.

Together, these records support only the recorded
`maverick-tls-h2-cli-v1` release-candidate scope. They do not prove production
readiness, anonymity, censorship resistance, native server-side ECH, GUI/App
behavior, H3/QUIC stability, exact browser fingerprint equivalence, or behavior
outside the recorded profiles.

## Known Limitations

- No formal independent security audit.
- No production-ready claim.
- No native server-side ECH.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
- Browser-like TLS fingerprinting remains optional and does not claim exact
  browser equivalence.
- Some defense-in-depth items are mitigated but not completely eliminated,
  especially full-process secret lifetime control and end-to-end browser-grade
  fallback indistinguishability.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/h3-harness.sh
./scripts/ech-harness.sh
./scripts/conformance.sh
python3 scripts/check-security-review-package.py
./scripts/release-artifacts.sh
```

Record the final tagged commit hash, release artifact names, and checksums in
the GitHub Pre-release body. Publish this tag as a GitHub Pre-release with
`--latest=false`.
