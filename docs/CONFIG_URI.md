# Config URI Design

Status: v4 CLI baseline implemented. Export, terminal QR rendering for
secret-free profile URIs, import dry-run, explicit `--output` client-config
materialization, stdin import with `--uri -`, explicit OS clipboard import,
best-effort clipboard clearing, and QR/clipboard text-payload normalization
tests are implemented. Automated tests use a fake clipboard provider and do not
read the developer machine's real clipboard.

Config URIs should make importing a Maverick client profile less error-prone
without embedding secrets in logs, screenshots, or crash reports.

## Goals

- Encode client connection metadata in a portable form.
- Keep secrets redacted in ordinary display and diagnostics.
- Support QR codes and clipboard import with a shared text payload parser
  tolerant of copied/scanned leading and trailing whitespace.
- Version the format from the first release.

## URI Shape

Proposed scheme:

```text
maverick://profile/v1?server=example.com%3A443&name=example.com&path=%2Fassets%2Fupload&mode=auto
```

Secret-bearing imports should use an encrypted bundle or a one-time local file,
not a plain URI by default.

Optional secret-bearing form for controlled local use:

```text
maverick://profile/v1?...&credential_id=u_example&secret=mv1_redacted
```

The CLI and GUI must redact `secret` when printing parsed URIs.

## Required Fields

- server address;
- server name;
- tunnel path;
- mode.

Optional fields:

- credential id;
- secret;
- certificate pin;
- CA bundle reference;
- DNS and HTTP CONNECT local listener preferences;
- experimental flags, all disabled unless explicitly present.

## Validation

- Reject unknown URI versions.
- Reject non-HTTPS-like tunnel paths that do not start with `/`.
- Reject short secrets through existing `SecretString` validation.
- Reject non-loopback local listeners unless explicitly allowed after import.
- Reject experimental flags that are not supported by the current binary.

## CLI Workflow

Implemented commands:

```sh
maverick config-uri export --client client.yaml
maverick config-uri export --client client.yaml --qr
maverick config-uri export --client client.yaml --include-secret
maverick config-uri import --uri 'maverick://profile/v1?...' --dry-run
maverick config-uri import --uri - --dry-run
maverick config-uri import --clipboard --dry-run
maverick config-uri import --uri 'maverick://profile/v1?...' --output client.yaml
maverick config-uri import --uri - --output client.yaml
maverick config-uri import --clipboard --output client.yaml
```

Export omits secrets by default. `--include-secret` is explicit and should be
used only for controlled local transfer. `--qr` renders a terminal QR for the
secret-free URI and refuses `--include-secret` to avoid making durable
credentials easy to photograph or screenshot. Import without `--output` behaves
as a dry-run and prints parsed fields with secret redacted. Import with
`--output` requires both `credential_id` and `secret`, writes a validated client
config, prints only redacted secret status, and refuses to overwrite existing
files. `--clipboard` is explicit and mutually exclusive with `--uri`.
Secret-bearing imports should prefer `--uri -` or `--clipboard`; if `secret=`
is detected in argv, the CLI prints a warning without echoing the URI. Clipboard
imports clear the OS clipboard on success when a supported local clipboard
command is available.

Implemented baseline:

- parse minimal `maverick://profile/v1` URI;
- reject unknown versions;
- reject invalid secrets;
- reject unsupported `experimental_ech=true`;
- preserve explicit `experimental_tun=true` for an embedding client while
  keeping it absent/default-false otherwise;
- export client config as a profile URI without secrets by default;
- render a terminal QR for secret-free profile URIs;
- reject secret-bearing QR export;
- materialize a valid client config from an explicit secret-bearing URI;
- materialize a valid client config from an explicit clipboard payload;
- reject materialization without required credential material;
- refuse to overwrite existing output files.
- accept single-URI QR/clipboard text payloads with leading/trailing whitespace;
- reject multi-URI clipboard payloads.
- accept `--uri -` as a stdin sentinel and warn for secret-bearing argv URIs.

## Tests

- Parse minimal URI.
- Parse and redact secret-bearing URI.
- Reject invalid version.
- Reject invalid secret.
- Roundtrip generated config through URI without changing defaults.
- Accept trimmed QR/clipboard text payloads.
- Reject multi-URI clipboard payloads.
- Render secret-free terminal QR without printing the raw URI.
- Reject secret-bearing QR export.
- Write explicit import output with owner-only permissions on Unix and reject
  overwrite.
- Parse explicit `--clipboard` imports and reject `--uri` plus `--clipboard`.
- Parse explicit `--uri -` stdin sentinel.
- Materialize and reject clipboard payloads through a fake provider only; tests
  do not read the real OS clipboard.
