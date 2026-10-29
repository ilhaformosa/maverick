#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
subject="$repo_root/scripts/inspect-project-cache.sh"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/maverick-cache-test.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT
export MAVERICK_CACHE_FIXTURE="$fixture_root"
export CARGO_BIN="$fixture_root/cargo"
export CARGO_TARGET_DIR="$fixture_root/shared target"
mkdir -p "$CARGO_TARGET_DIR/debug/deps" "$fixture_root/workspace"

fail() { printf 'project-cache inspection test failed: %s\n' "$1" >&2; exit 1; }

cat >"$CARGO_BIN" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 8 && "$1" == metadata && "$2" == --locked && "$3" == --offline && "$4" == --no-deps && "$5" == --format-version && "$6" == 1 && "$7" == --manifest-path ]] || exit 97
case "$8" in
  */fixtures/quiche-tls-auth/Cargo.toml) metadata="$MAVERICK_CACHE_FIXTURE/fixture.json" ;;
  *) metadata="$MAVERICK_CACHE_FIXTURE/root.json" ;;
esac
jq --arg target "${CARGO_TARGET_DIR:-$MAVERICK_CACHE_FIXTURE/absent}" '.target_directory = $target' "$metadata"
FAKE
chmod 0755 "$CARGO_BIN"

jq -n --arg root "$fixture_root/workspace" '{workspace_root: $root, workspace_members: ["first"], packages: [
  {id: "first", name: "first", targets: [
    {name: "tool", kind: ["bin"], src_path: ($root + "/src/main.rs")},
    {name: "life-cycle", kind: ["test"], src_path: ($root + "/tests/lifecycle.rs")},
    {name: "speed", kind: ["bench"], src_path: ($root + "/benches/speed.rs")},
    {name: "first", kind: ["lib"], src_path: ($root + "/src/lib.rs")}]},
  {id: "third", name: "third", targets: [
    {name: "foreign", kind: ["bin"], src_path: ($root + "/third.rs")}]}]}' >"$fixture_root/root.json"
jq -n --arg root "$fixture_root/workspace" '{workspace_root: $root, workspace_members: ["fixture"], packages: [
  {id: "fixture", name: "fixture", targets: [
    {name: "proxy", kind: ["test"], src_path: ($root + "/tests/proxy.rs")},
    {name: "tool", kind: ["bin"], src_path: ($root + "/src/main.rs")}]}]}' >"$fixture_root/fixture.json"

artifact() {
  local path="$CARGO_TARGET_DIR/$1" source="$2"
  mkdir -p "$(dirname "$path")"
  printf 'fixture' >"$path"
  chmod 0755 "$path"
  printf '%s: %s\n' "$path" "$source" >"$path.d"
}
artifact debug/tool "$fixture_root/workspace/src/main.rs"
artifact debug/deps/tool-aabb src/main.rs
artifact debug/deps/life_cycle-abcd tests/lifecycle.rs
artifact debug/deps/speed-1234 benches/speed.rs
artifact debug/deps/proxy-abcd tests/proxy.rs
# Same name, wrong source; libraries, build scripts and non-hash files stay out.
artifact debug/deps/life_cycle-ffff /registry/other/tests/lifecycle.rs
artifact debug/deps/liblife_cycle-abcd tests/lifecycle.rs
artifact debug/deps/first-abcd src/lib.rs
artifact debug/deps/life_cycle-build tests/lifecycle.rs
artifact debug/foreign "$fixture_root/workspace/third.rs"
artifact debug/build/first/build-script-build src/build.rs
mkdir -p "$CARGO_TARGET_DIR/debug/tool.dSYM/Contents/Resources/DWARF"
printf 'symbols' >"$CARGO_TARGET_DIR/debug/tool.dSYM/Contents/Resources/DWARF/tool"
mkdir -p "$CARGO_TARGET_DIR/debug/deps/life_cycle-ffff.dSYM/Contents"
printf 'foreign symbols' >"$CARGO_TARGET_DIR/debug/deps/life_cycle-ffff.dSYM/Contents/Info.plist"

# Check all target content before/after capture, including excluded files.
find "$CARGO_TARGET_DIR" -type f -exec cksum {} \; | LC_ALL=C sort >"$fixture_root/checksums-before"
"$subject" capture "$fixture_root/before.json"
find "$CARGO_TARGET_DIR" -type f -exec cksum {} \; | LC_ALL=C sort >"$fixture_root/checksums-after"
cmp "$fixture_root/checksums-before" "$fixture_root/checksums-after" || fail target-was-modified
jq -e '.files | length == 6 and all(.[]; .root == "target-0")' "$fixture_root/before.json" >/dev/null || fail classification-or-deduplication
jq -e '[.files[] | select(.kind == "dsym")] | length == 1' "$fixture_root/before.json" >/dev/null || fail symbol-classification
if grep -F "$fixture_root" "$fixture_root/before.json"; then fail private-path-output; fi

# Changed size, replacement inode, timestamp-only change, removal and creation.
printf 'rewritten payload' >"$CARGO_TARGET_DIR/debug/tool"
printf 'fixture' >"$fixture_root/replacement"
chmod 0755 "$fixture_root/replacement"
mv "$fixture_root/replacement" "$CARGO_TARGET_DIR/debug/deps/tool-aabb"
touch -t 200001010000 "$CARGO_TARGET_DIR/debug/deps/speed-1234"
rm "$CARGO_TARGET_DIR/debug/deps/life_cycle-abcd"
artifact debug/deps/life_cycle-abce tests/lifecycle.rs
"$subject" capture "$fixture_root/after.json"
"$subject" compare "$fixture_root/before.json" "$fixture_root/after.json" >"$fixture_root/comparison"
awk -F '\t' '$1 == "TOTAL" { ok = ($2 == 6 && $3 == 42 && $4 == 6 && $5 == 52 && $6 == 3 && $7 == 2 && $8 == 1 && $9 == 1 && $10 == 21 && $11 == 14 && $12 == 7) } END { exit !ok }' "$fixture_root/comparison" || fail change-counts
if grep -F "$fixture_root" "$fixture_root/comparison"; then fail private-comparison-path; fi

CARGO_TARGET_DIR="$fixture_root/missing" "$subject" capture "$fixture_root/missing.json"
jq -e '.files == []' "$fixture_root/missing.json" >/dev/null || fail missing-target
"$subject" compare "$fixture_root/missing.json" "$fixture_root/missing.json" >"$fixture_root/empty-comparison"
grep -F $'TOTAL\t0\t0\t0\t0\t0\t0\t0\t0' "$fixture_root/empty-comparison" >/dev/null || fail empty-comparison

echo 'project-cache inspection focused tests OK'
