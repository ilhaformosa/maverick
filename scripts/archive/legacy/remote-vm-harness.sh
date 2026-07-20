#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

host="${1:-${MAVERICK_REMOTE_HOST:-}}"
mode="${2:-${MAVERICK_REMOTE_MODE:-local}}"
remote_dir="${MAVERICK_REMOTE_DIR:-maverick-remote-lab}"
jobs="${MAVERICK_REMOTE_CARGO_JOBS:-1}"

if [[ -z "$host" ]]; then
  echo "usage: $0 <ssh-host> [local|extended]" >&2
  echo "or set MAVERICK_REMOTE_HOST" >&2
  exit 2
fi

case "$mode" in
  local)
    remote_script="./scripts/local-harness.sh"
    ;;
  extended)
    remote_script="./scripts/extended-harness.sh"
    ;;
  *)
    echo "usage: $0 <ssh-host> [local|extended]" >&2
    exit 2
    ;;
esac

echo "==> sync workspace to $host:$remote_dir"
rsync -az --delete \
  --exclude ".git/" \
  --exclude "target/" \
  --exclude "target-public-h3/" \
  --exclude ".DS_Store" \
  "$repo_root/" "$host:$remote_dir/"

echo "==> run remote $mode harness"
ssh -o BatchMode=yes "$host" \
  "set -euo pipefail; cd '$remote_dir'; PATH=\"\$HOME/.cargo/bin:\$PATH\" CARGO_BUILD_JOBS='$jobs' '$remote_script'"
