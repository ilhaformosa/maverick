# HPKE and Noise Experiment Design

Status: v5 design complete. Registry entries are declared through the crypto
agility baseline, with pre-runtime descriptor tests for feature gates, runtime
gates, vector files, and Noise prologue context labels. HPKE has an imported
official subset vector file; Noise has a deterministic Maverick prologue
context model plus a Snow 0.10.0 backed XX25519/ChaChaPoly/SHA256 H2 transcript
vector. `maverick-core` also includes a feature-gated Noise XX runtime session
harness for native no-domain research. A machine-readable Noise runtime
approval manifest records completed evidence and harness gates while keeping
product transport config exposure deferred. HPKE runtime behavior is not
implemented.

HPKE and Noise are candidates for future experiments, not replacements for the
current TLS-based tunnel.

## Sources

- RFC 9180, Hybrid Public Key Encryption: https://datatracker.ietf.org/doc/rfc9180/
- Noise Protocol Framework: https://noiseprotocol.org/noise.html
- Snow crate: https://crates.io/crates/snow/0.10.0

## HPKE Track

HPKE can be useful for sealed configuration bundles, server-published metadata,
or one-shot encrypted profile transfer. It should not be used to replace the
TLS tunnel without a separate protocol review.

Candidate feature gate:

```toml
[features]
hpke-experimental = []
```

Candidate runtime gate:

```yaml
advanced:
  experimental_hpke: false
```

Required work:

- choose a reviewed Rust HPKE implementation;
- import RFC 9180 test vectors;
- bind Maverick context into HPKE info strings;
- reject unauthenticated downgrade;
- keep secrets redacted in config import/export tooling.

## Noise Track

Noise may be useful for a future native no-domain mode or non-TLS research
transport. The current implementation is a core research harness, not a
user-facing transport.

Candidate feature gate:

```toml
[features]
noise-experimental = ["dep:snow"]
```

Constraints:

- do not expose Noise as an ordinary user transport choice;
- use a standard Noise pattern and standard library implementation;
- bind Maverick protocol identity into the prologue;
- keep 0-RTT disabled for authenticated tunnel setup unless separately
  reviewed;
- require a dedicated product transport decision before exposing it through
  ordinary client/server config.

`NoiseReadinessSnapshot` keeps product transport exposure blocked until all
readiness inputs are true:

- feature build enabled;
- candidate implementation selected;
- implementation-backed vectors present;
- transcript/prologue tests ready;
- downgrade tests ready;
- runtime session harness ready;
- runtime config accepted for product transport exposure.

`docs/history/manifests/noise-runtime-approval.json` is the review boundary for moving beyond the
pre-runtime state. It requires:

- a standard candidate implementation selection;
- implementation-backed transcript/prologue vectors;
- transcript/prologue tests binding Maverick protocol identity;
- downgrade tests;
- a feature-gated runtime session harness;
- product runtime config exposure only after a separate product decision;
- community or independent review evidence before any stable or strong
  security claim.

## Shared Test Requirements

- Known-answer vectors from upstream specs or libraries.
- Transcript binding tests.
- Downgrade tests against TLS/H2 fallback.
- Fuzz or property tests for envelope parsers.
- No runtime enablement unless CI covers feature builds.

Implemented pre-runtime baseline:

- disabled HPKE and Noise registry entries declare feature/runtime gates;
- HPKE and Noise entries declare JSON vector paths;
- HPKE has a source-tracked official CFRG subset vector file;
- Noise has a source-tracked Snow-backed deterministic transcript/prologue
  vector and transport smoke case;
- the disabled Noise descriptor binds Maverick, Noise, XX25519, ChaChaPoly,
  SHA256, and v1 into its transcript/prologue label;
- `NoisePrologueContext` defines a deterministic length-prefixed prologue
  context for future Noise_XX_25519_ChaChaPoly_SHA256 use, binding suite,
  protocol name, version, initiator/responder roles, transport context, and
  research-runtime purpose.
- `crates/maverick-core/src/noise.rs` provides a feature-gated Noise XX session
  harness with expected remote static-key checks, transport-context mismatch
  rejection, length-prefixed encrypted envelopes, and encrypted Maverick frame
  round trips.
- `NoiseReadinessSnapshot` reports concrete blockers and remains
  non-product-transport-ready because ordinary config still rejects Noise.
- `docs/history/manifests/noise-runtime-approval.json` plus
  `scripts/check-noise-runtime-approval.py` prevent accidental runtime
  product exposure or unsupported security claims.
