#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi

"$cargo_bin" test -p maverick-core --test conformance_vectors

python_bin="${PYTHON_BIN:-python3}"
"$python_bin" conformance/runner/check_spec_wire_alignment.py .
"$python_bin" conformance/runner/check_vector_manifest.py conformance/vector-manifest.json
"$python_bin" conformance/runner/check_implementation_registry.py conformance/implementation-registry.json
"$python_bin" conformance/runner/check_freeze_readiness.py conformance/freeze-readiness.json
"$python_bin" conformance/runner/check_frozen_releases.py conformance/frozen-releases.json
"$python_bin" conformance/runner/test_check_spec_wire_alignment.py
"$python_bin" conformance/runner/test_check_implementation_registry.py
"$python_bin" conformance/runner/test_check_freeze_readiness.py
"$python_bin" conformance/runner/test_check_frozen_releases.py
"$python_bin" conformance/runner/python_verify.py conformance/vectors
