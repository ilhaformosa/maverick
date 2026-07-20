# ML-KEM Hybrid Experiment

Status: v5 design complete. A disabled registry entry exists in the crypto
agility baseline, with pre-runtime descriptor tests for feature/runtime gates,
Maverick transcript labels, and a source-tracked NIST ACVP ML-KEM-768 subset
vector file. ML-KEM runtime behavior is not implemented.

ML-KEM is standardized by NIST FIPS 203. Maverick may experiment with hybrid
key establishment only behind explicit gates and only in addition to existing
classical security, not as a replacement for TLS.

## Source

- NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard:
  https://csrc.nist.gov/pubs/fips/203/final

## Goals

- Track post-quantum migration work without changing safe defaults.
- Keep experiments hybrid with existing classical security.
- Use reviewed implementations and official test vectors.
- Preserve downgrade safety.

## Non-Goals

- Shipping ML-KEM as default.
- Replacing rustls/TLS certificate validation.
- Advertising quantum-safe production security before review.
- Implementing ML-KEM primitives by hand.

## Candidate Gate

```toml
[features]
ml-kem-hybrid = []
```

```yaml
advanced:
  experimental_ml_kem_hybrid: false
```

## Parameter Policy

FIPS 203 defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024. The first Maverick
experiment should start with ML-KEM-768 only after a reviewed Rust
implementation and test vector story are selected.

## Hybrid Composition

Any hybrid output must combine classical and ML-KEM shared secrets through a
reviewed KDF with domain separation:

```text
hybrid_secret = KDF(
  label = "Maverick experimental hybrid",
  classical_secret,
  ml_kem_secret,
  transcript_hash
)
```

This is a design placeholder, not an approved construction.

## Required Tests

- Official ML-KEM known-answer tests.
- KDF domain separation tests.
- Downgrade and feature-gate tests.
- Failure-path tests that do not leak which decapsulation step failed.
- Build tests proving the experiment is absent by default.

Implemented pre-runtime baseline:

- the disabled ML-KEM registry entry declares feature/runtime gates;
- the descriptor has a Maverick-domain transcript label ending in `v1`;
- the descriptor declares a JSON known-answer vector path;
- `test-vectors/ml-kem-768-hybrid-v1.json` imports a NIST ACVP FIPS203
  ML-KEM-768 keyGen and encapsulation subset for future implementation-backed
  KATs.
