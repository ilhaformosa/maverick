#!/usr/bin/env bash
set -euo pipefail

# Keep installed runner tools. Only apt-get packages whose commands are missing.
missing=()
for package in binutils clang cmake file ripgrep shellcheck; do
  case "$package" in
    binutils) commands=(readelf strings) ;;
    ripgrep) commands=(rg) ;;
    *) commands=("$package") ;;
  esac
  for tool in "${commands[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$package")
      break
    fi
  done
done

if [[ ${#missing[@]} -eq 0 ]]; then
  echo "Linux build and verification tools are already available"
else
  sudo apt-get update
  sudo apt-get install -y "${missing[@]}"
fi
