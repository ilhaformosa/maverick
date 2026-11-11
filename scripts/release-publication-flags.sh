#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Print one gh flag per line. This helper never calls gh or changes Git refs.
fail() { echo "release publication approval failed" >&2; exit 1; }
[[ $# -eq 2 ]] || fail
version="$1"
revision="$2"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || fail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
channel="$("$script_dir/release-channel.sh" "$version" 2>/dev/null)" || fail
if [[ "$channel" == stable ]]; then
  [[ "${MAVERICK_STABLE_APPROVED_SHA:-}" == "$revision" ]] || fail
  printf '%s\n' --prerelease=false --latest=true
else
  printf '%s\n' --prerelease --latest=false
fi
