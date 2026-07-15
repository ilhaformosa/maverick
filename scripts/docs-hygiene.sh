#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python_bin="${PYTHON_BIN:-python3}"

echo "==> docs and metadata hygiene"
"$python_bin" scripts/test-claim-hygiene.py
"$python_bin" scripts/claim-hygiene.py
"$python_bin" scripts/test-issue-template-hygiene.py
"$python_bin" scripts/issue-template-hygiene.py
"$python_bin" scripts/test-roadmap-blockers.py
"$python_bin" scripts/check-roadmap-blockers.py
"$python_bin" scripts/test-security-review-package.py
"$python_bin" scripts/check-security-review-package.py
"$python_bin" scripts/test-ech-runtime-approval.py
"$python_bin" scripts/check-ech-runtime-approval.py
"$python_bin" scripts/test-ech-runtime-blockers.py
"$python_bin" scripts/check-ech-runtime-blockers.py
"$python_bin" scripts/test-gui-runtime-blockers.py
"$python_bin" scripts/check-gui-runtime-blockers.py
"$python_bin" scripts/test-noise-runtime-approval.py
"$python_bin" scripts/check-noise-runtime-approval.py
"$python_bin" scripts/test-tun-helper-approval.py
"$python_bin" scripts/check-tun-helper-approval.py
"$python_bin" scripts/test-tun-runtime-blockers.py
"$python_bin" scripts/check-tun-runtime-blockers.py
"$python_bin" scripts/test-network-safety-hygiene.py
"$python_bin" scripts/network-safety-hygiene.py

echo "docs hygiene OK"
