# Conformance Runner

This directory contains local, no-network conformance smoke checks for
checked-in Maverick parser vectors.

```sh
python3 conformance/runner/check_vector_manifest.py conformance/vector-manifest.json
python3 conformance/runner/check_implementation_registry.py conformance/implementation-registry.json
python3 conformance/runner/check_spec_wire_alignment.py .
python3 conformance/runner/check_freeze_readiness.py conformance/freeze-readiness.json
python3 conformance/runner/check_frozen_releases.py conformance/frozen-releases.json
python3 conformance/runner/test_check_spec_wire_alignment.py
python3 conformance/runner/test_check_implementation_registry.py
python3 conformance/runner/test_check_freeze_readiness.py
python3 conformance/runner/test_check_frozen_releases.py
python3 conformance/runner/python_verify.py conformance/vectors
```

The manifest checker and Python verifier intentionally use only their
standard libraries. The manifest checker verifies SHA-256 hashes and detects
unregistered or stale vector files. The implementation-registry checker
verifies that the current implementation claim is limited to the Rust prototype
plus a no-network Python parser/verifier, has evidence paths, and makes no
normative or standardization claim. The spec/wire checker verifies frame type
assignments across Rust, `WIRE_FORMAT.md`, and the Python verifier. The
freeze-readiness checker validates that the current blocked freeze status has
explicit criteria, evidence paths, and blockers. The frozen-release checker
currently validates registered immutable conformance manifest snapshots. The
Python verifier parses checked-in JSON vectors, decodes the wire bytes,
verifies replay semantics, and verifies Auth v1 HMAC tags with synthetic
test-only secrets.
