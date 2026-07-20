# Conformance Suite Plan

Status: v6 conformance baseline implemented for frames, Auth v1 hello payloads,
replay cache semantics, DNS query/response frames, `OpenTcp`, `OpenUdp`,
`UdpPacket`, and error-code payloads. Rust tests now also regenerate checked-in
vectors from wire/cache types and require exact JSON matches. A no-network
Python standard-library verifier provides the first non-Rust conformance smoke
test. The manually triggered CI workflow can run the dedicated conformance job
for the Rust exact-match checks, spec/wire alignment check, vector manifest
hash check, implementation-registry check, and Python verifier. A
freeze-readiness policy file records current
candidate/frozen release blockers and is checked by the conformance script.

The conformance suite should let independent implementations verify wire
compatibility without requiring access to private credentials or live network
services.

## Scope

Initial vectors:

- frame encode/decode;
- ClientHello and ServerHello auth transcripts;
- replay cache semantics;
- DNS query/response frames;
- `OpenTcp` and `OpenUdp` payloads;
- error-frame codes after authentication;
- fallback behavior expectations for pre-auth failures.

## Format

Candidate layout:

```text
conformance/
  vectors/
    frame_roundtrip.json
    auth_v1.json
    auth_v2.json
    udp_payload.json
  runner/
    README.md
```

Each vector should include:

- vector id;
- protocol version;
- input bytes or structured fields;
- expected output bytes;
- expected error class;
- notes about whether secrets are synthetic test-only values.

Implemented baseline:

- `conformance/vectors/frame_tcp_data.json`
- `conformance/vectors/frame_padding.json`
- `conformance/vectors/auth_v1_client_hello.json`
- `conformance/vectors/auth_v1_server_hello.json`
- `conformance/vectors/auth_v2_client_hello.json`
- `conformance/vectors/auth_v2_server_hello.json`
- `conformance/vectors/frame_dns_query.json`
- `conformance/vectors/frame_dns_response.json`
- `conformance/vectors/open_tcp_domain.json`
- `conformance/vectors/open_udp.json`
- `conformance/vectors/replay_window.json`
- `conformance/vectors/udp_packet_ipv4.json`
- `conformance/vectors/error_code_flow_limit.json`
- `conformance/vector-manifest.json`
- `conformance/implementation-registry.json`
- `conformance/freeze-readiness.json`
- `conformance/frozen-releases.json`
- `crates/maverick-core/tests/conformance_vectors.rs`
- `conformance/runner/check_implementation_registry.py`
- `conformance/runner/check_vector_manifest.py`
- `conformance/runner/check_spec_wire_alignment.py`
- `conformance/runner/check_freeze_readiness.py`
- `conformance/runner/check_frozen_releases.py`
- `conformance/runner/test_check_implementation_registry.py`
- `conformance/runner/test_check_freeze_readiness.py`
- `conformance/runner/test_check_spec_wire_alignment.py`
- `conformance/runner/test_check_frozen_releases.py`
- `conformance/runner/python_verify.py`
- `scripts/conformance.sh`
- CI `conformance` job

The runner auto-discovers JSON files in `conformance/vectors`, so new parser
or semantics vectors do not require manual registration in Rust tests.

The generation check builds the current parser-vector JSON from Maverick wire
types and deterministic test-only auth transcripts, then compares each generated
document byte-for-byte against the checked-in file. A protocol or vector-format
change must therefore update the generator and the vector file in the same
review.

The manifest check records SHA-256 values for every checked-in vector file and
fails when a JSON vector is changed, added, or removed without updating the
manifest in the same review. The manifest status is `pre-freeze`; it is a
compatibility tripwire, not a spec-freeze claim.

The spec/wire alignment check verifies that Rust `FrameType` assignments,
`WIRE_FORMAT.md`, and the Python verifier's frame map agree. This catches
documentation drift such as implemented frame types missing from the public wire
format draft.

The implementation-registry check validates
`conformance/implementation-registry.json`. It records the Rust prototype and
the no-network Python verifier, requires evidence paths, keeps
parser/verifier entries no-network, and keeps standardization claims disabled.
The current `frozen` status applies only to the narrow release train; the
listed implementations remain non-normative.

The freeze-readiness check validates `conformance/freeze-readiness.json`. The
current status is `ready` for the narrow `maverick-tls-h2-cli-v1` release
train after S3 review-input closure and conformance-vector snapshotting. This
is RC/stable release-train metadata only: it is not a formal audit,
production-readiness, anonymity, censorship-resistance, standardization, or
browser-fingerprint-equivalence claim. The checker fails if the file is marked
`ready` while partial or blocked criteria remain.

The frozen-release policy records immutable conformance vector byte snapshots.
The v1.0.0 snapshot freezes test-vector bytes for the narrow
`maverick-tls-h2-cli-v1` scope only; it is not a production, formal-audit,
anonymity, censorship-resistance, browser-fingerprint-equivalence, or
standardization claim. The checker validates the snapshot hash, each frozen
vector hash, duplicate release names, and path confinement so frozen vectors
cannot be silently rewritten.

## Runner Requirements

- No real network required for parser vectors.
- Loopback-only integration mode for TCP, DNS, and UDP vectors.
- No system proxy, DNS, route, firewall, VPN, or other network-service settings changes.
- Redacted output by default.

## Acceptance

- Rust implementation passes all vectors.
- Checked-in parser vectors match generated wire values.
- Rust, docs, and Python verifier frame type assignments match.
- Vector manifest hashes match checked-in JSON files with no unregistered
  vector files.
- Implementation registry lists at least one client/server implementation and
  one no-network parser/verifier, both with evidence paths and no normative
  claims.
- Freeze-readiness status has explicit evidence paths and cannot be marked
  ready while blockers remain.
- Frozen-release policy checks pass, meaning registered manifest snapshots and
  vector hashes remain immutable.
- The manual CI workflow can run `scripts/conformance.sh` as a dedicated
  conformance gate; local `./scripts/local-harness.sh` remains the default
  pre-push gate.
- At least one non-Rust parser or verifier passes parser vectors before spec
  freeze. The current Python verifier satisfies parser-vector smoke coverage
  only; it is not full protocol implementation coverage.
- Vectors are versioned and never silently rewritten after a frozen release.
