# Crypto Agility Framework

Status: v5 registry/policy baseline implemented. `maverick-core` contains a
suite registry, `advanced.crypto` validation, and pre-runtime descriptor tests
for experimental suite gates, Maverick transcript labels, and vector files.
HPKE and ML-KEM include official imported subset vectors for future KAT work.
Noise has a deterministic prologue context model, a Snow 0.10.0 backed
XX25519/ChaChaPoly/SHA256 H2 transcript vector, a feature-gated core runtime
session harness, and a mechanical runtime readiness gate. Noise also has a
machine-readable runtime approval manifest that records completed evidence and
runtime-harness gates while keeping product transport config exposure deferred.
Operator-safe crypto policy diagnostics report suite status, gates, and
default-claim exclusions without downgrade advice. Only `tls13` is accepted by
runtime config today; HPKE, Noise, and ML-KEM entries are declared but disabled.

Crypto agility is the ability to introduce, test, deprecate, and remove
cryptographic mechanisms without breaking existing safe defaults. Maverick must
not replace TLS with custom cryptography or make experimental cryptography a
default path.

## Sources

- RFC 9180, Hybrid Public Key Encryption: https://datatracker.ietf.org/doc/rfc9180/
- NIST FIPS 203, ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- Noise Protocol Framework: https://noiseprotocol.org/noise.html
- Snow crate: https://crates.io/crates/snow/0.10.0

## Goals

- Keep TLS 1.3 as the production security foundation.
- Add experimental suites only behind build and runtime gates.
- Version every suite and transcript.
- Keep downgrade behavior explicit and test-covered.
- Require known-answer tests and interop vectors before runtime use.

## Non-Goals

- Replacing TLS security with a Maverick-specific unaudited handshake.
- Enabling post-quantum or Noise paths by default.
- Hiding experimental status from users or operators.
- Mixing key material without a reviewed KDF and transcript design.

## Suite Registry

Experimental suites are registered in one place:

```text
suite_id: u16
name: string
status: disabled | experimental | deprecated | removed
feature_gate: string
runtime_flag: string
transcript_label: string
test_vector_file: string
```

Default clients should offer only stable suites. Experimental clients may offer
additional suites only when explicitly configured.

Implemented baseline:

- `CryptoSuiteId` and descriptor registry in `maverick-core`;
- default `advanced.crypto.offered_suites: ["tls13"]`;
- duplicate and empty suite rejection;
- required TLS 1.3 foundation for every policy;
- `stable` mode rejection for experimental crypto policy settings;
- disabled HPKE, Noise, and ML-KEM entries that fail config validation before
  any runtime use.
- pre-runtime tests requiring disabled experimental suites to declare gates,
  Maverick transcript labels, and known-answer vector file paths.
- source-tracked HPKE and ML-KEM official subset vector files under
  `test-vectors/`, plus a Snow-backed Noise vector with a canonical Maverick
  prologue context.
- `NoisePrologueContext` defines the deterministic length-prefixed context that
  Noise transcript tests must mix into the prologue.
- `NoiseReadinessSnapshot` records candidate implementation, implementation
  vector, transcript-test, downgrade-test, runtime-session-harness, and
  runtime-config readiness.
- `maverick_core::noise` provides a feature-gated Noise XX runtime session
  harness for encrypted Maverick frame round trips.
- `docs/history/manifests/noise-runtime-approval.json` records the pre-runtime approval boundary. Its
  checker is metadata validation and is not part of the default local gate.
- `crypto_policy_diagnostics` produces a read-only report for operator
  diagnostics: offered suites, stable foundation presence, feature/runtime
  gates, default-enabled status, and whether each suite is excluded from
  default security claims.

## Downgrade Policy

- Stable mode refuses experimental crypto.
- Auto mode may try experimental crypto only when explicitly enabled and must
  fall back to TLS/H2 without changing auth security.
- Private mode should fail closed if an explicitly required experimental crypto
  suite cannot be used.

## Test Requirements

- Known-answer tests for every primitive and suite.
- Transcript mismatch tests.
- Downgrade rejection tests.
- Cross-feature build tests.
- No secret, key, shared-secret, or transcript-key logging.

Current registry tests enforce descriptor preconditions, imported vector file
presence, canonical Noise prologue context metadata, Snow-backed Noise
transcript vectors, Noise runtime-session harness behavior, and Noise
runtime-readiness blockers. Diagnostics tests verify that reports do not emit
downgrade advice or secret/key material.

## Current Decisions

- `maverick-core` owns the suite registry, config policy, diagnostics, and
  descriptor tests. The Noise runtime session harness lives behind the
  `noise-experimental` feature. Product transport exposure remains separate
  from the core harness.
- No experiment can move out of disabled-by-default status without
  implementation-backed known-answer tests, downgrade tests, an explicit
  runtime approval update, and community or independent review evidence before
  any stable or strong security claim.
