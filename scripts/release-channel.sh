#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Classification is not publication authorization. Stable additionally needs
# an exact-revision owner approval in the publication workflow.
[[ $# -eq 1 ]] || { echo "release channel verification failed" >&2; exit 1; }
version="$1"
if [[ "$version" == "1.2.0" ]]; then
  echo stable
elif [[ "$version" =~ ^1\.2\.0-beta\.[1-9][0-9]*$ ]]; then
  echo beta
elif [[ "$version" =~ ^1\.2\.0-rc\.[1-9][0-9]*$ ]]; then
  echo rc
else
  echo "release channel verification failed" >&2
  exit 1
fi
