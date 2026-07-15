#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo_bin="${CARGO_BIN:-cargo}"
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  cargo_bin="$HOME/.cargo/bin/cargo"
fi
python_bin="${PYTHON_BIN:-python3}"

echo "==> formatting"
"$cargo_bin" fmt --all -- --check

echo "==> clippy"
"$cargo_bin" clippy --workspace --all-targets -- -D warnings

echo "==> tests"
"$cargo_bin" test --workspace

echo "==> experimental TUN packet runtime"
"$cargo_bin" test -p maverick-client --features tun-runtime --lib
"$cargo_bin" test -p maverick-tests --features tun-runtime --test tun_packet_runtime
"$cargo_bin" check -p maverick-tests --features tun-phase2 --bin maverick-tun-phase2

echo "==> conformance"
./scripts/conformance.sh

echo "==> fuzz smoke"
./scripts/fuzz-smoke.sh

echo "==> generated config validation"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
(
  cd "$tmpdir"
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- gen-config >/dev/null
  chmod 600 client.generated.yaml server.generated.yaml
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- check-config --kind client -c client.generated.yaml >/dev/null
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- check-config --kind server -c server.generated.yaml >/dev/null
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- migrate-config --kind client -c client.generated.yaml >/dev/null
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- migrate-config --kind server -c server.generated.yaml >/dev/null
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- rotate-credential --server server.generated.yaml --dry-run >/dev/null
  experimental_report="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- experimental list)"
  if [[ "$experimental_report" != *"track: h3_quic_carrier"* || "$experimental_report" != *"track: cloudflare_fronted_ws_carrier"* || "$experimental_report" != *"track: ech"* || "$experimental_report" != *"track: product_tun_runtime"* ]]; then
    echo "experimental registry report is missing expected tracks" >&2
    exit 1
  fi
  if [[ "$experimental_report" == *"default: on"* ]]; then
    echo "experimental registry report contains a default-on track" >&2
    exit 1
  fi
  profile_uri="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- config-uri export --client client.generated.yaml)"
  if [[ "$profile_uri" == *"mv1_"* ]]; then
    echo "config-uri export leaked a secret" >&2
    exit 1
  fi
  profile_qr="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- config-uri export --client client.generated.yaml --qr)"
  if [[ "$profile_qr" == *"maverick://"* || "$profile_qr" == *"mv1_"* ]]; then
    echo "config-uri QR export leaked raw profile text or a secret" >&2
    exit 1
  fi
  if "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- config-uri export --client client.generated.yaml --include-secret --qr >/dev/null 2>&1; then
    echo "config-uri QR export accepted a secret-bearing URI" >&2
    exit 1
  fi
  fingerprint_dir="$tmpdir/fingerprint-lab"
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-tests --bin fingerprint-lab -- \
    --output-dir "$fingerprint_dir" --profile all --samples 2 >/dev/null
  rg -q '"name": "rustls_default"' "$fingerprint_dir/fingerprint-summary.json"
  rg -q '"status": "not_provided"' "$fingerprint_dir/fingerprint-report.json"
  active_probe_dir="$tmpdir/active-probe-lab"
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-tests --bin active-probe-lab -- \
    --output-dir "$active_probe_dir" >/dev/null
  "$python_bin" "$repo_root/scripts/check-active-probe-baseline.py" \
    --baseline "$repo_root/test-vectors/stealth/active-probe-baseline.json" \
    --current-summary "$active_probe_dir/active-probe-summary.json"
  "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- config-uri import --uri "$profile_uri" --dry-run >/dev/null
  tun_plan="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- tun-plan --include-route 10.0.0.0/8 --abstract-runtime-plan)"
  if [[ "$tun_plan" != *"system_apply: false"* || "$tun_plan" != *"abstract_runtime_plan: available"* ]]; then
    echo "tun-plan did not produce the expected local-only abstract plan" >&2
    exit 1
  fi
  if [[ "$tun_plan" == *"sudo"* || "$tun_plan" == *" ip "* ]]; then
    echo "tun-plan output unexpectedly contains system apply commands" >&2
    exit 1
  fi
  preflight_journal="$tmpdir/tun-helper-preflight-rollback.json"
  tun_preflight="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- tun-helper-preflight --approved-host-label approved-linux-vm --rollback-journal "$preflight_journal")"
  if [[ "$tun_preflight" != *"system_apply: false"* || "$tun_preflight" != *"rollback_journal:"* || "$tun_preflight" != *"preflight_ready:"* ]]; then
    echo "tun-helper-preflight did not produce the expected read-only report" >&2
    exit 1
  fi
  if [[ "$tun_preflight" == *"sudo"* || "$tun_preflight" == *" ip "* ]]; then
    echo "tun-helper-preflight output unexpectedly contains system apply commands" >&2
    exit 1
  fi
  tun_helper="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- tun-helper-smoke --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked)"
  if [[ "$tun_helper" != *"system_apply: false"* || "$tun_helper" != *"rollback_journal:"* || "$tun_helper" != *"runtime_plan: blocked"* ]]; then
    echo "tun-helper-smoke dry run did not stay blocked and local-only" >&2
    exit 1
  fi
  if [[ "$tun_helper" == *"sudo"* || "$tun_helper" == *" ip "* ]]; then
    echo "tun-helper-smoke dry run unexpectedly contains system apply commands" >&2
    exit 1
  fi
  if "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- tun-helper-smoke --apply --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked >/dev/null 2>&1; then
    echo "tun-helper-smoke apply unexpectedly succeeded without approval env" >&2
    exit 1
  fi
  rollback_journal="$tmpdir/tun-helper-rollback.json"
  cat >"$rollback_journal" <<'JSON'
{
  "version": 2,
  "scope": "phase_a_temporary_tun_documentation_route",
  "status": "pending_rollback",
  "device": "mavtun0",
  "device_identity": "maverick-tun-helper:local-harness",
  "include_route": "192.0.2.0/24",
  "tun_addr": "10.255.0.1/30",
  "route_probe": "192.0.2.1",
  "route_metric": "4271",
  "approved_host_label": "approved-linux-vm",
  "default_route": "not_touched",
  "global_dns": "not_touched",
  "firewall": "not_touched"
}
JSON
  chmod 600 "$rollback_journal"
  tun_rollback="$("$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- tun-helper-rollback --rollback-journal "$rollback_journal" --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked)"
  if [[ "$tun_rollback" != *"system_apply: false"* || "$tun_rollback" != *"rollback: idempotent_cleanup"* ]]; then
    echo "tun-helper-rollback dry run did not stay blocked and local-only" >&2
    exit 1
  fi
  if [[ "$tun_rollback" == *"sudo"* || "$tun_rollback" == *" ip "* ]]; then
    echo "tun-helper-rollback dry run unexpectedly contains system apply commands" >&2
    exit 1
  fi
  if "$cargo_bin" run -q --manifest-path "$repo_root/Cargo.toml" -p maverick-cli -- tun-helper-rollback --apply --rollback-journal "$rollback_journal" --approved-host-label approved-linux-vm --proxy-vpn-conflict-checked >/dev/null 2>&1; then
    echo "tun-helper-rollback apply unexpectedly succeeded without approval env" >&2
    exit 1
  fi
)

echo "==> repo hygiene"
bash -n \
  scripts/s2-evidence-preflight.sh \
  scripts/s2-evidence-collect.sh \
  scripts/s2-evidence-cleanup.sh \
  scripts/approved-vm-detached-tcp-longhaul.sh \
  scripts/approved-vm-netem-impairment-smoke.sh \
  scripts/approved-vm-failure-injection-smoke.sh \
  scripts/active-probe-lab.sh \
  scripts/browser-tls-harness.sh \
  scripts/fingerprint-lab.sh
"$python_bin" scripts/test-log-hygiene.py
"$python_bin" scripts/test-fuzz-sync-corpus.py
"$python_bin" scripts/test-import-crypto-vector-subsets.py
"$python_bin" scripts/test-workflow-pins.py
"$python_bin" scripts/check-workflow-pins.py
"$python_bin" scripts/test-source-secret-hygiene.py
"$python_bin" scripts/source-secret-hygiene.py
"$python_bin" scripts/log-hygiene.py
"$python_bin" scripts/test-ci-change-scope.py
"$python_bin" scripts/test-active-probe-baseline.py
"$python_bin" scripts/check-active-probe-baseline.py
"$python_bin" scripts/test-approved-vm-longhaul.py
"$python_bin" scripts/test-approved-host-guard.py
"$python_bin" scripts/test-approved-vm-tun-safety.py
"$python_bin" scripts/test-approved-vm-ech-origin-probe.py
"$python_bin" scripts/test-approved-vm-s2-runners.py
"$python_bin" scripts/test-browser-tls-baseline.py
"$python_bin" scripts/check-browser-tls-baseline.py
if [[ "${MAVERICK_SKIP_DOCS_HYGIENE:-0}" != "1" ]]; then
  ./scripts/docs-hygiene.sh
fi
"$python_bin" scripts/test-ci-gates.py
"$python_bin" scripts/check-ci-gates.py
"$python_bin" scripts/test-s2-evidence-collect.py
"$python_bin" scripts/test-s2-evidence-cleanup.py
"$python_bin" scripts/test-s2-evidence-audit.py
"$python_bin" scripts/test-s2-evidence-preflight.py
"$python_bin" scripts/test-s2-evidence-report.py
"$python_bin" scripts/test-tun-engine-comparison.py
"$python_bin" scripts/check-tun-engine-comparison.py
"$python_bin" scripts/test-tun-packet-runtime.py
"$python_bin" scripts/check-tun-packet-runtime.py
"$python_bin" scripts/test-tun-phase2-bridge.py
"$python_bin" scripts/check-tun-phase2-bridge.py
"$python_bin" scripts/test-production-readiness.py
"$python_bin" scripts/check-production-readiness.py

legacy_name_pattern='Mosaic'
legacy_name_pattern+='Flow|mosaic'
legacy_name_pattern+='flow|Mosaic[[:space:]]Flow|mf'
legacy_name_pattern+='1_'
if rg -n "$legacy_name_pattern" -S . -g '!target' -g '!Cargo.lock'; then
  echo "unexpected legacy project name or prefix found" >&2
  exit 1
fi

echo "local harness OK"
