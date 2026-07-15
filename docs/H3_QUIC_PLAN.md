# H3 / QUIC Implementation Plan

Status: Phase 3 complete as an experimental local baseline. Feature-gated H3
build skeleton, loopback smoke harness, Maverick tunnel-over-H3 prototype,
runtime H2 fallback/cooldown, debug-only transport diagnostics, and H3
concurrent TCP relay coverage are implemented. Broader operational policy
remains future hardening work.

This document records the guardrails for adding an optional H3/QUIC carrier to
Maverick. H2/TLS remains mandatory and must keep passing the local harness.

## Candidate Rust Stack

- `quinn`: QUIC endpoint and connection implementation.
- `h3`: HTTP/3 protocol layer, documented as experimental by the crate.
- `h3-quinn`: adapter between `h3` and `quinn`.
- `rustls`: TLS stack already used by Maverick; QUIC config must stay aligned
  with rustls-supported QUIC APIs.

References:

- https://docs.rs/crate/h3/latest
- https://docs.rs/crate/h3-quinn/latest
- https://docs.rs/crate/quinn/latest

## Non-Negotiable Guardrails

- H3 must be optional and feature-gated.
- H2 fallback must remain the default path until H3 has full local harness
  coverage.
- 0-RTT must remain disabled.
- Auth transcripts must not change in the first H3 carrier implementation.
- H3 failures must fall back or cool down through scheduler policy.
- H3 tests must bind only to `127.0.0.1` and ephemeral UDP ports.
- H3 must not expose transport selection as a normal user-facing setting.

## Implementation Slices

### Slice 1: Feature Gate and Build Skeleton

Status: implemented. The `h3` feature compiles optional H3/QUIC dependencies
and keeps default builds H2-only.

- Add a non-default Cargo feature for H3.
- Add optional dependencies only under that feature.
- Add an H3 transport module that compiles behind the feature.
- Keep default builds H2-only.

Acceptance:

- `./scripts/local-harness.sh` passes without H3 feature.
- `./scripts/h3-harness.sh` passes once the feature exists.

### Slice 2: Loopback H3 Handshake Harness

Status: implemented as a feature-gated integration test.

- Add a loopback QUIC server/client smoke test.
- Use temporary self-signed certificates in the same style as current H2 tests.
- Verify ALPN and H3 request setup without Maverick auth first.

Acceptance:

- H3 smoke test uses only `127.0.0.1`.
- No system networking changes.

### Slice 3: Maverick Tunnel Over H3

Status: implemented as a feature-gated prototype.

- Carry the same Maverick frames in H3 request/response bodies.
- Reuse the existing ClientHello/ServerHello validation path where possible.
- Keep H2 integration tests unchanged and passing.

Acceptance:

- TCP relay roundtrip works over H3 in a feature-gated test.
- Auth failure still falls back without pre-auth protocol details.
- Replay protection remains identical.
- DNS relay and SOCKS5 UDP ASSOCIATE paths have feature-gated H3 regression
  coverage.

### Slice 4: Scheduler Integration

Status: implemented as a runtime baseline. H3 remains disabled unless the
binary is built with `h3` and `advanced.experimental_h3` is enabled at runtime.
When H3 connection setup fails, the client marks the server in cooldown and
falls back to H2.

- Enable scheduler H3 candidate only when the feature and runtime config allow
  it.
- Add cooldown on H3 failure.
- Ensure `stable` mode remains H2-first.

Acceptance:

- Scheduler unit tests cover H3 success, failure, cooldown, and H2 fallback.
- H2 is always selected when H3 is not compiled or not enabled.

### Slice 5: Operational Diagnostics

Status: implemented as a reusable diagnostic model. Ordinary GUI/tray
snapshots expose policy mode and coarse status only. Explicit debug snapshots
can expose active transport, H2 fallback, H3 candidate enablement, and cooldown
state for local operator troubleshooting.

- Keep H3 out of ordinary first-screen state and profile controls.
- Use explicit debug mode for H2/H3/cooldown fields.
- Keep diagnostics free of target hosts, credential ids, secrets, and payload
  sizes.

Acceptance:

- Core unit tests prove ordinary serialized and Debug snapshots do not contain
  H2/H3/cooldown terms.
- Debug snapshots can serialize H2/H3/cooldown fields only when requested.
- Client transport diagnostics read scheduler state without opening network
  listeners or changing system settings.

## Current Deployment Decisions

- H2 remains the mandatory fallback and ordinary default. H3 deployment profiles
  should keep the UDP listener explicit; using the same public port number as
  H2 is an operator/deployment choice, not a protocol requirement.
- The current H3 runtime keeps one request per flow, matching the H2 behavior.
  Longer-lived H3 multiplexing is deferred until the existing per-flow model
  has broader operational evidence and a reviewed resource-bound design.
