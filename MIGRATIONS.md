# Maverick Migrations

Status: no mandatory config migration is currently required.

## Current Config Version

All configs use:

```yaml
version: 1
```

Validate configs with:

```sh
maverick check-config --kind client -c client.yaml
maverick check-config --kind server -c server.yaml
```

Preview migration defaults with:

```sh
maverick migrate-config --kind client -c client.yaml
maverick migrate-config --kind server -c server.yaml
```

`migrate-config` is currently dry-run only. It validates the config and reports
which safe default fields would be materialized; it does not rewrite files or
print secrets.

## v1.0.0 To v1.1.0

No mandatory schema, protocol, credential, or operator migration is required.

- Auth v1 hello protocol version remains `1`.
- Explicit Auth v2 hello protocol version remains `2`.
- Config `version: 1` remains current.
- Existing valid v1.0.0 client and server configs continue to validate.
- H2 connection reuse is automatic and keeps existing timeout and limit fields.
- New browser-TLS, H3, CDN-fronted WebSocket, cryptography, and TUN paths remain
  optional or default-off and require their documented build/runtime gates.
- Product and release support remains IPv4-only. Experimental IPv6 code does
  not require migration and is not a current support commitment.

Before upgrading, operators should run both `check-config` and the dry-run
`migrate-config` command with their existing configuration. No file is rewritten
by these checks.

## v1.1.0 To v1.2.0 Candidate

No protocol, Auth, or config-schema migration is planned. Software/package,
protocol, Auth, config, helper IPC, recovery journal, and platform-plan versions
must be recorded separately at freeze as described in `COMPATIBILITY.md`.

Adopting the packaged Linux reference client is an operator and platform
migration, not a config-version change. Before adoption:

1. confirm Ubuntu 24.04 LTS `amd64` and IPv4 are the intended target;
2. verify the exact signed package and repository metadata;
3. generate a secret-free profile and import the service credential through the
   fixed encrypted credential path;
4. verify install is default-inactive, then run preflight before enabling it;
5. record the previous client, route, DNS, service, package, and credential state;
6. keep a tested rollback/removal path and do not treat manual file copies as an
   equivalent package migration.

The candidate does not migrate or enable IPv6, H3, GUI, mobile, or another Linux
distribution.

## Beta / RC To v1.0.0

No mandatory schema migration is required from `v0.1.0-beta.2`,
`v0.1.0-rc.1`, or `v0.1.0-rc.2` to `v1.0.0`.

The stable v1.0.0 boundary is:

- Auth v1 hello protocol version remains `1`;
- explicit Auth v2 hello protocol version remains `2`;
- config `version: 1` remains current;
- existing valid v1 client and server configs continue to validate.

The beta, RC, and v1.0.0 software tags advanced the package/release version
only. They did not change config schema version, Auth v1 hello version, or
explicit Auth v2 hello version.

## Historical Internal Baseline v1/v1.1 To v1.2

These labels predate the stable software SemVer line. They are not migration
instructions for planned post-v1 software releases.

No schema migration is required. Recommended checks:

- regenerate example configs with `maverick gen-config` for comparison;
- ensure client local listeners are loopback-only unless intentionally exposed;
- ensure timeout and limit values are greater than zero;
- keep file permissions restricted for configs containing secrets.

## Historical Internal Baseline v1.2 To v2 Experimental H3

No migration is required. Existing configs continue to default to H2/TLS.

The optional `advanced.experimental_h3` field defaults to `false`. It should be
set only for local/controlled H3 experiments where both client and server are
built with the `h3` feature.

The optional client `advanced.experimental_tun` field also defaults to `false`.
Existing configs require no migration. Enabling it requires the `tun-runtime`
build feature and an embedding application that supplies packet I/O; it does
not enable platform TUN or network setup by itself.

The optional `advanced.udp_idle_timeout_ms` field defaults to `30000` on both
client and server. Existing configs inherit that value.

The optional server auth pressure controls default to:

```yaml
advanced:
  pre_auth_max_concurrent: 512
  auth_failure_window_secs: 60
  max_auth_failures_per_window: 24
  auth_failure_cache_max_entries: 4096
```

Existing server configs inherit these values. `migrate-config --kind server`
reports them for older configs so operators can materialize them before a
stable or production-scoped rollout.

## Historical Internal v3 Credential-Rotation Baseline

No mandatory migration is required for existing clients. The optional
`auth.rotation.auto_switch` field defaults to `false`, and
`auth.rotation.next` defaults to `null`.

`migrate-config --kind client` reports these defaults for older configs. Do not
set `auto_switch=true` unless the client config already contains validated next
credential material and the server rollout plan is ready for that activation
time.

## Future Migration Rules

- Every schema-changing release must document old fields, new fields, defaults,
  and manual steps here.
- Migration tooling must support dry-run behavior before rewriting files.
- Migration tooling must not print secrets.
- Migration tooling must preserve comments only when the implementation can do
  so reliably; otherwise it must say that comments are not preserved.
