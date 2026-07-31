#!/usr/bin/env bash
set -euo pipefail

umask 077
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

readonly MAX_ARCHIVE_BYTES=67108864
readonly MAX_TAR_BYTES=134217728
readonly MAX_BINARY_BYTES=67108864
readonly MAX_TEXT_BYTES=1048576
readonly MAX_SMALL_TEXT_BYTES=4096
readonly NATIVE_TIMEOUT_SECONDS=8
readonly FEATURES_LINE="features: tls13,h2,browser-tls-default,cdn-fronted-h2,socks5,http-connect,tcp-relay,dns-relay,udp-relay,static-fallback,reverse-proxy-fallback,local-metrics,config-uri,key-inventory,rotation-lint,user-smoke"
readonly START_HERE_SHA256="cd1c7d86b743455e00678105241a625b13f143c1d6dd2234fc6d5ea9bea76738"

private_tmp=""

cleanup() {
  case "$private_tmp" in
    /tmp/maverick-pilot-verify.*)
      if [[ -d "$private_tmp" ]]; then
        find "$private_tmp" -depth -delete >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

fail() {
  echo "pilot artifact verification failed" >&2
  exit 1
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

file_size() {
  local measured
  measured="$(wc -c <"$1" 2>/dev/null | tr -d '[:space:]')" || fail
  [[ "$measured" =~ ^[0-9]+$ ]] || fail
  printf '%s\n' "$measured"
}

sha256_file() {
  local digest
  if command -v shasum >/dev/null 2>&1; then
    digest="$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}')" || fail
  elif command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$1" 2>/dev/null | awk '{print $1}')" || fail
  else
    fail
  fi
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail
  printf '%s\n' "$digest"
}

field_hex() {
  dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null |
    od -An -tx1 -v |
    tr -d ' \n'
}

zero_hex() {
  local count="$1"
  local output=""
  while [[ "$count" -gt 0 ]]; do
    output="${output}00"
    count=$((count - 1))
  done
  printf '%s\n' "$output"
}

padded_ascii_hex() {
  local value="$1"
  local width="$2"
  local output
  local padding
  output="$(printf '%s' "$value" | od -An -tx1 -v | tr -d ' \n')"
  padding=$((width - ${#value}))
  [[ "$padding" -ge 0 ]] || fail
  while [[ "$padding" -gt 0 ]]; do
    output="${output}00"
    padding=$((padding - 1))
  done
  printf '%s\n' "$output"
}

field_is_zero() {
  [[ "$(field_hex "$1" "$2" "$3")" == "$(zero_hex "$3")" ]]
}

block_is_zero() {
  od -An -tu1 -v "$1" 2>/dev/null |
    awk '{ for (i = 1; i <= NF; i++) if ($i != 0) bad = 1 }
         END { exit bad }'
}

parse_octal_field() {
  local header="$1"
  local offset="$2"
  local width="$3"
  local digits
  digits="$(
    dd if="$header" bs=1 skip="$offset" count="$width" 2>/dev/null |
      od -An -tu1 -v |
      awk '
        BEGIN { seen = 0; ended = 0; bad = 0; text = "" }
        {
          for (i = 1; i <= NF; i++) {
            byte = $i
            if (byte >= 48 && byte <= 55) {
              if (ended) bad = 1
              seen = 1
              text = text sprintf("%c", byte)
            } else if (byte == 0 || byte == 32) {
              if (seen) ended = 1
              else if (byte == 0) bad = 1
            } else {
              bad = 1
            }
          }
        }
        END {
          if (bad || !seen) exit 1
          print text
        }'
  )" || fail
  parsed_octal=$((8#$digits))
}

verify_zero_device_field() {
  local header="$1"
  local offset="$2"
  local width="$3"
  if field_is_zero "$header" "$offset" "$width"; then
    return
  fi
  parse_octal_field "$header" "$offset" "$width"
  [[ "$parsed_octal" -eq 0 ]] || fail
}

archive_path=""
expected_version=""
expected_revision=""
expected_target=""
verification_level=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive)
      [[ $# -ge 2 && -z "$archive_path" ]] || fail
      archive_path="$2"
      shift 2
      ;;
    --expected-version)
      [[ $# -ge 2 && -z "$expected_version" ]] || fail
      expected_version="$2"
      shift 2
      ;;
    --expected-revision)
      [[ $# -ge 2 && -z "$expected_revision" ]] || fail
      expected_revision="$2"
      shift 2
      ;;
    --expected-target)
      [[ $# -ge 2 && -z "$expected_target" ]] || fail
      expected_target="$2"
      shift 2
      ;;
    --verification-level)
      [[ $# -ge 2 && -z "$verification_level" ]] || fail
      verification_level="$2"
      shift 2
      ;;
    *)
      fail
      ;;
  esac
done

[[ -n "$archive_path" && -n "$expected_version" && -n "$expected_revision" ]] || fail
[[ -n "$expected_target" && -n "$verification_level" ]] || fail
[[ "$expected_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]] || fail
[[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]] || fail
case "$expected_target" in
  aarch64-apple-darwin | x86_64-unknown-linux-gnu) ;;
  *) fail ;;
esac
case "$verification_level" in
  static | native) ;;
  *) fail ;;
esac

archive_basename="${archive_path##*/}"
expected_basename="maverick-${expected_version}-pilot-${expected_target}.tar.gz"
[[ "$archive_basename" == "$expected_basename" ]] || fail
checksum_path="${archive_path}.sha256"
[[ -f "$archive_path" && ! -L "$archive_path" ]] || fail
[[ -f "$checksum_path" && ! -L "$checksum_path" ]] || fail
source_archive_bytes="$(file_size "$archive_path")"
[[ "$source_archive_bytes" -gt 0 && "$source_archive_bytes" -le "$MAX_ARCHIVE_BYTES" ]] ||
  fail
source_checksum_bytes="$(file_size "$checksum_path")"
[[ "$source_checksum_bytes" -gt 0 && "$source_checksum_bytes" -le 512 ]] || fail

private_tmp="$(mktemp -d /tmp/maverick-pilot-verify.XXXXXX 2>/dev/null)" || fail
[[ -d "$private_tmp" && ! -L "$private_tmp" ]] || fail
chmod 0700 "$private_tmp" >/dev/null 2>&1 || fail
input_dir="$private_tmp/input"
extract_dir="$private_tmp/extract"
native_home="$private_tmp/home"
native_tmp="$private_tmp/runtime"
mkdir "$input_dir" "$extract_dir" "$native_home" "$native_tmp" >/dev/null 2>&1 || fail
chmod 0700 "$input_dir" "$extract_dir" "$native_home" "$native_tmp" >/dev/null 2>&1 || fail

archive_copy="$input_dir/$archive_basename"
checksum_copy="$input_dir/$archive_basename.sha256"
cp "$archive_path" "$archive_copy" >/dev/null 2>&1 || fail
cp "$checksum_path" "$checksum_copy" >/dev/null 2>&1 || fail
chmod 0600 "$archive_copy" "$checksum_copy" >/dev/null 2>&1 || fail

archive_bytes="$(file_size "$archive_copy")"
[[ "$archive_bytes" -gt 0 && "$archive_bytes" -le "$MAX_ARCHIVE_BYTES" ]] || fail
checksum_bytes="$(file_size "$checksum_copy")"
[[ "$checksum_bytes" -gt 0 && "$checksum_bytes" -le 512 ]] || fail
[[ "$(wc -l <"$checksum_copy" 2>/dev/null | tr -d '[:space:]')" == "1" ]] || fail
IFS= read -r checksum_line <"$checksum_copy" || fail
checksum_digest="${checksum_line%% *}"
[[ "$checksum_digest" =~ ^[0-9a-f]{64}$ ]] || fail
[[ "$checksum_line" == "$checksum_digest  $archive_basename" ]] || fail
expected_outer_checksum="$private_tmp/expected-outer-checksum"
printf '%s  %s\n' "$checksum_digest" "$archive_basename" >"$expected_outer_checksum"
cmp -s "$checksum_copy" "$expected_outer_checksum" || fail
[[ "$(sha256_file "$archive_copy")" == "$checksum_digest" ]] || fail

tar_copy="$private_tmp/archive.tar"
set +o pipefail
gzip -dc "$archive_copy" 2>/dev/null |
  head -c $((MAX_TAR_BYTES + 1)) >"$tar_copy" 2>/dev/null
pipeline_status=("${PIPESTATUS[@]}")
gzip_status=${pipeline_status[0]}
head_status=${pipeline_status[1]}
set -o pipefail
[[ "$head_status" -eq 0 ]] || fail
tar_bytes="$(file_size "$tar_copy")"
[[ "$tar_bytes" -gt 0 && "$tar_bytes" -le "$MAX_TAR_BYTES" ]] || fail
[[ "$gzip_status" -eq 0 ]] || fail
[[ $((tar_bytes % 512)) -eq 0 ]] || fail
total_blocks=$((tar_bytes / 512))

seen_root=0
seen_license=0
seen_sums=0
seen_source=0
seen_guide=0
seen_version=0
seen_binary=0
members=0
block=0
found_end=0
header_file="$private_tmp/header"

while [[ "$block" -lt "$total_blocks" ]]; do
  dd if="$tar_copy" of="$header_file" bs=512 skip="$block" count=1 2>/dev/null || fail
  [[ "$(file_size "$header_file")" == "512" ]] || fail
  if block_is_zero "$header_file"; then
    [[ $((block + 1)) -lt "$total_blocks" ]] || fail
    dd if="$tar_copy" of="$header_file" bs=512 skip=$((block + 1)) count=1 \
      2>/dev/null || fail
    block_is_zero "$header_file" || fail
    if [[ $((block + 2)) -lt "$total_blocks" ]]; then
      dd if="$tar_copy" bs=512 skip=$((block + 2)) 2>/dev/null |
        od -An -tu1 -v |
        awk '{ for (i = 1; i <= NF; i++) if ($i != 0) bad = 1 }
             END { exit bad }' || fail
    fi
    found_end=1
    break
  fi

  [[ "$(field_hex "$header_file" 257 6)" == "757374617200" ]] || fail
  [[ "$(field_hex "$header_file" 263 2)" == "3030" ]] || fail
  field_is_zero "$header_file" 345 155 || fail
  field_is_zero "$header_file" 157 100 || fail
  field_is_zero "$header_file" 265 32 || fail
  field_is_zero "$header_file" 297 32 || fail
  field_is_zero "$header_file" 500 12 || fail
  verify_zero_device_field "$header_file" 329 8
  verify_zero_device_field "$header_file" 337 8
  parse_octal_field "$header_file" 136 12

  name="$(dd if="$header_file" bs=1 count=100 2>/dev/null | tr -d '\000')"
  [[ "$(field_hex "$header_file" 0 100)" == "$(padded_ascii_hex "$name" 100)" ]] || fail
  type_hex="$(field_hex "$header_file" 156 1)"

  expected_mode=0
  size_limit=0
  case "$name" in
    maverick-pilot/)
      [[ "$seen_root" -eq 0 && "$type_hex" == "35" ]] || fail
      seen_root=1
      expected_mode=493
      size_limit=0
      ;;
    maverick-pilot/LICENSE)
      [[ "$seen_license" -eq 0 && ( "$type_hex" == "30" || "$type_hex" == "00" ) ]] || fail
      seen_license=1
      expected_mode=420
      size_limit=$MAX_TEXT_BYTES
      ;;
    maverick-pilot/SHA256SUMS)
      [[ "$seen_sums" -eq 0 && ( "$type_hex" == "30" || "$type_hex" == "00" ) ]] || fail
      seen_sums=1
      expected_mode=420
      size_limit=$MAX_SMALL_TEXT_BYTES
      ;;
    maverick-pilot/SOURCE.txt)
      [[ "$seen_source" -eq 0 && ( "$type_hex" == "30" || "$type_hex" == "00" ) ]] || fail
      seen_source=1
      expected_mode=420
      size_limit=$MAX_SMALL_TEXT_BYTES
      ;;
    maverick-pilot/START_HERE.txt)
      [[ "$seen_guide" -eq 0 && ( "$type_hex" == "30" || "$type_hex" == "00" ) ]] || fail
      seen_guide=1
      expected_mode=420
      size_limit=$MAX_TEXT_BYTES
      ;;
    maverick-pilot/VERSION.txt)
      [[ "$seen_version" -eq 0 && ( "$type_hex" == "30" || "$type_hex" == "00" ) ]] || fail
      seen_version=1
      expected_mode=420
      size_limit=$MAX_SMALL_TEXT_BYTES
      ;;
    maverick-pilot/maverick)
      [[ "$seen_binary" -eq 0 && ( "$type_hex" == "30" || "$type_hex" == "00" ) ]] || fail
      seen_binary=1
      expected_mode=493
      size_limit=$MAX_BINARY_BYTES
      ;;
    *)
      fail
      ;;
  esac

  parse_octal_field "$header_file" 100 8
  [[ "$parsed_octal" -eq "$expected_mode" ]] || fail
  parse_octal_field "$header_file" 108 8
  [[ "$parsed_octal" -eq 0 ]] || fail
  parse_octal_field "$header_file" 116 8
  [[ "$parsed_octal" -eq 0 ]] || fail
  parse_octal_field "$header_file" 124 12
  entry_size="$parsed_octal"
  [[ "$entry_size" -le "$size_limit" ]] || fail
  if [[ "$name" == "maverick-pilot/" ]]; then
    [[ "$entry_size" -eq 0 ]] || fail
  fi
  parse_octal_field "$header_file" 148 8
  expected_header_sum="$parsed_octal"
  actual_header_sum="$(
    od -An -tu1 -v "$header_file" 2>/dev/null |
      awk '
        {
          for (i = 1; i <= NF; i++) {
            if (position >= 148 && position < 156) sum += 32
            else sum += $i
            position++
          }
        }
        END {
          if (position != 512) exit 1
          print sum
        }'
  )" || fail
  [[ "$actual_header_sum" -eq "$expected_header_sum" ]] || fail

  data_blocks=$(((entry_size + 511) / 512))
  [[ $((block + 1 + data_blocks)) -le "$total_blocks" ]] || fail
  padding_bytes=$((data_blocks * 512 - entry_size))
  if [[ "$padding_bytes" -gt 0 ]]; then
    dd if="$tar_copy" bs=1 skip=$(((block + 1) * 512 + entry_size)) \
      count="$padding_bytes" 2>/dev/null |
      od -An -tu1 -v |
      awk '{ for (i = 1; i <= NF; i++) if ($i != 0) bad = 1 }
           END { exit bad }' || fail
  fi
  block=$((block + 1 + data_blocks))
  members=$((members + 1))
done

[[ "$found_end" -eq 1 && "$members" -eq 7 ]] || fail
[[ "$seen_root" -eq 1 && "$seen_license" -eq 1 && "$seen_sums" -eq 1 ]] || fail
[[ "$seen_source" -eq 1 && "$seen_guide" -eq 1 && "$seen_version" -eq 1 ]] || fail
[[ "$seen_binary" -eq 1 ]] || fail

tar_version="$(tar --version 2>/dev/null)" || fail
case "$tar_version" in
  *bsdtar*)
    COPYFILE_DISABLE=1 tar \
      --no-same-owner --no-same-permissions --no-acls --no-fflags --no-xattrs \
      -xf "$tar_copy" -C "$extract_dir" >/dev/null 2>&1 || fail
    ;;
  *"GNU tar"*)
    tar --extract --file="$tar_copy" --directory="$extract_dir" \
      --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-selinux \
      --delay-directory-restore >/dev/null 2>&1 || fail
    ;;
  *)
    fail
    ;;
esac

payload_root="$extract_dir/maverick-pilot"
[[ -d "$payload_root" && ! -L "$payload_root" ]] || fail
for payload_file in LICENSE SHA256SUMS SOURCE.txt START_HERE.txt VERSION.txt maverick; do
  [[ -f "$payload_root/$payload_file" && ! -L "$payload_root/$payload_file" ]] || fail
done
[[ "$(find "$extract_dir" -mindepth 1 -print 2>/dev/null | wc -l | tr -d '[:space:]')" == "7" ]] || fail

inner_file="$payload_root/SHA256SUMS"
[[ "$(wc -l <"$inner_file" 2>/dev/null | tr -d '[:space:]')" == "5" ]] || fail
inner_license=0
inner_source=0
inner_guide=0
inner_version=0
inner_binary=0
while IFS= read -r inner_line; do
  inner_digest="${inner_line%% *}"
  [[ "$inner_digest" =~ ^[0-9a-f]{64}$ ]] || fail
  inner_name="${inner_line#"$inner_digest  "}"
  [[ "$inner_line" == "$inner_digest  $inner_name" ]] || fail
  case "$inner_name" in
    LICENSE) [[ "$inner_license" -eq 0 ]] || fail; inner_license=1 ;;
    SOURCE.txt) [[ "$inner_source" -eq 0 ]] || fail; inner_source=1 ;;
    START_HERE.txt) [[ "$inner_guide" -eq 0 ]] || fail; inner_guide=1 ;;
    VERSION.txt) [[ "$inner_version" -eq 0 ]] || fail; inner_version=1 ;;
    maverick) [[ "$inner_binary" -eq 0 ]] || fail; inner_binary=1 ;;
    *) fail ;;
  esac
  [[ "$(sha256_file "$payload_root/$inner_name")" == "$inner_digest" ]] || fail
done <"$inner_file"
[[ "$inner_license" -eq 1 && "$inner_source" -eq 1 && "$inner_guide" -eq 1 ]] || fail
[[ "$inner_version" -eq 1 && "$inner_binary" -eq 1 ]] || fail
expected_inner_file="$private_tmp/expected-inner-checksums"
for inner_name in LICENSE SOURCE.txt START_HERE.txt VERSION.txt maverick; do
  printf '%s  %s\n' "$(sha256_file "$payload_root/$inner_name")" "$inner_name"
done >"$expected_inner_file"
cmp -s "$inner_file" "$expected_inner_file" || fail

expected_source_file="$private_tmp/expected-source"
printf '%s\n' \
  "repository: https://github.com/ilhaformosa/maverick" \
  "git_revision: $expected_revision" \
  "source_state: clean" \
  "version: $expected_version" \
  "target: $expected_target" >"$expected_source_file"
cmp -s "$expected_source_file" "$payload_root/SOURCE.txt" || fail

expected_version_file="$private_tmp/expected-version"
printf '%s\n' \
  "maverick $expected_version" \
  "protocol_version: 1" \
  "$FEATURES_LINE" >"$expected_version_file"
cmp -s "$expected_version_file" "$payload_root/VERSION.txt" || fail
cmp -s "$repo_root/LICENSE" "$payload_root/LICENSE" || fail
[[ "$(sha256_file "$payload_root/START_HERE.txt")" == "$START_HERE_SHA256" ]] || fail

binary_file="$payload_root/maverick"
file_description="$(file -b "$binary_file" 2>/dev/null)" || fail
case "$expected_target" in
  aarch64-apple-darwin)
    [[ "$(field_hex "$binary_file" 0 4)" == "cffaedfe" ]] || fail
    [[ "$(field_hex "$binary_file" 4 4)" == "0c000001" ]] || fail
    [[ "$(field_hex "$binary_file" 12 4)" == "02000000" ]] || fail
    [[ "$file_description" == *"Mach-O"* && "$file_description" == *"arm64"* ]] || fail
    [[ "$file_description" != *"universal"* && "$file_description" != *"fat"* ]] || fail
    ;;
  x86_64-unknown-linux-gnu)
    [[ "$(field_hex "$binary_file" 0 7)" == "7f454c46020101" ]] || fail
    elf_type="$(field_hex "$binary_file" 16 2)"
    [[ "$elf_type" == "0200" || "$elf_type" == "0300" ]] || fail
    [[ "$(field_hex "$binary_file" 18 2)" == "3e00" ]] || fail
    [[ "$file_description" == *"ELF"* && "$file_description" == *"x86-64"* ]] || fail
    if command -v readelf >/dev/null 2>&1; then
      readelf_tool="$(command -v readelf 2>/dev/null)" || fail
    elif command -v greadelf >/dev/null 2>&1; then
      readelf_tool="$(command -v greadelf 2>/dev/null)" || fail
    else
      echo \
        "pilot artifact verification failed: required tool not found (readelf or greadelf)" \
        >&2
      exit 1
    fi
    readelf_header="$("$readelf_tool" -h "$binary_file" 2>/dev/null)" || fail
    printf '%s\n' "$readelf_header" | grep -Eq 'Class:[[:space:]]+ELF64' || fail
    printf '%s\n' "$readelf_header" | grep -Eq 'Data:[[:space:]]+2.s complement, little endian' || fail
    printf '%s\n' "$readelf_header" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' || fail
    case "$elf_type" in
      0200)
        [[ "$file_description" == *"executable"* ]] || fail
        printf '%s\n' "$readelf_header" |
          grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]' || fail
        ;;
      0300)
        [[ "$file_description" == *"pie executable"* ]] || fail
        printf '%s\n' "$readelf_header" |
          grep -Eq 'Type:[[:space:]]+DYN.*Position-Independent Executable' || fail
        ;;
    esac
    ;;
esac

command -v strings >/dev/null 2>&1 || fail
privacy_pattern='/U''sers/[^/[:space:]]+|/ho''me/[^/[:space:]]+|fi''le://([^/[:space:]]+/[^[:space:]]+|/+[^/[:space:]]+/[^[:space:]]+)|ssh''-rsa|BE''GIN (RSA |EC |OPENSSH )?PRI''VATE KEY|mv''1_[A-Za-z0-9_-]{43,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-(proj-|svcacct-)?[A-Za-z0-9_-]{40,}|dop_v1_[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|Bearer[[:space:]]+[A-Za-z0-9._-]{20,}|OPENAI_''API_KEY|DIGITALOCEAN_''API_TOKEN|AWS_SECRET_''ACCESS_KEY'
archive_strings="$private_tmp/archive-strings"
binary_strings="$private_tmp/binary-strings"
strings "$archive_copy" >"$archive_strings" 2>/dev/null || fail
strings "$tar_copy" >>"$archive_strings" 2>/dev/null || fail
strings "$binary_file" >"$binary_strings" 2>/dev/null || fail
privacy_status=0
grep -E -i -q "$privacy_pattern" "$archive_strings" "$binary_strings" \
  "$payload_root/LICENSE" "$payload_root/SHA256SUMS" "$payload_root/SOURCE.txt" \
  "$payload_root/START_HERE.txt" "$payload_root/VERSION.txt" 2>/dev/null ||
  privacy_status=$?
case "$privacy_status" in
  0) fail ;;
  1) ;;
  *) fail ;;
esac

verify_input_unchanged() {
  [[ -f "$archive_path" && ! -L "$archive_path" ]] || fail
  [[ -f "$checksum_path" && ! -L "$checksum_path" ]] || fail
  [[ "$(file_size "$archive_path")" == "$archive_bytes" ]] || fail
  [[ "$(file_size "$checksum_path")" == "$checksum_bytes" ]] || fail
  cmp -s "$archive_path" "$archive_copy" || fail
  cmp -s "$checksum_path" "$checksum_copy" || fail
  [[ "$(sha256_file "$archive_path")" == "$(sha256_file "$archive_copy")" ]] || fail
  [[ "$(sha256_file "$checksum_path")" == "$(sha256_file "$checksum_copy")" ]] || fail
}

if [[ "$verification_level" == "static" ]]; then
  verify_input_unchanged
  echo "pilot artifact static verification OK"
  exit 0
fi

host_os="$(uname -s 2>/dev/null)" || fail
host_cpu="$(uname -m 2>/dev/null)" || fail
case "$expected_target" in
  aarch64-apple-darwin)
    [[ "$host_os" == "Darwin" && "$host_cpu" == "arm64" ]] || fail
    ;;
  x86_64-unknown-linux-gnu)
    [[ "$host_os" == "Linux" && "$host_cpu" == "x86_64" ]] || fail
    ;;
esac

run_bounded() {
  local output_file="$1"
  local timeout_driver
  shift
  timeout_driver="$(command -v perl 2>/dev/null)" || fail
  # The following single-quoted program is interpreted by Perl.
  # shellcheck disable=SC2016
  (
    cd "$native_tmp" || exit 1
    ulimit -f 2048 || exit 1
    env -i \
      PATH="/usr/bin:/bin" \
      HOME="$native_home" \
      TMPDIR="$native_tmp" \
      LC_ALL=C \
      "$timeout_driver" -e \
        'my $limit = shift;
         my $pid = fork();
         exit 127 unless defined $pid;
         if ($pid == 0) { exec @ARGV; exit 127; }
         $SIG{ALRM} = sub {
           kill "TERM", $pid;
           select undef, undef, undef, 0.2;
           kill "KILL", $pid;
           waitpid($pid, 0);
           exit 124;
         };
         alarm $limit;
         waitpid($pid, 0);
         alarm 0;
         exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);' \
        "$NATIVE_TIMEOUT_SECONDS" "$@"
  ) >"$output_file" 2>&1 || fail
}

native_version_output="$private_tmp/native-version"
run_bounded "$native_version_output" "$binary_file" version
[[ "$(file_size "$native_version_output")" -le "$MAX_SMALL_TEXT_BYTES" ]] || fail
cmp -s "$native_version_output" "$payload_root/VERSION.txt" || fail

native_smoke_output="$private_tmp/native-smoke"
run_bounded "$native_smoke_output" "$binary_file" user-smoke
[[ "$(file_size "$native_smoke_output")" -le "$MAX_TEXT_BYTES" ]] || fail
[[ "$(grep -Fxc 'wrong_credential_rejected: PASS' "$native_smoke_output" 2>/dev/null)" == "1" ]] ||
  fail
[[ "$(grep -Fxc 'correct_credential_roundtrip: PASS' "$native_smoke_output" 2>/dev/null)" == "1" ]] ||
  fail
smoke_failure_status=0
grep -Eq ': FAIL$' "$native_smoke_output" 2>/dev/null || smoke_failure_status=$?
case "$smoke_failure_status" in
  0) fail ;;
  1) ;;
  *) fail ;;
esac

verify_input_unchanged
echo "pilot artifact native verification OK"
