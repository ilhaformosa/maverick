# Credential Rotation Plan

Status: v3 runtime baseline implemented for v1-compatible previous
credentials and explicit opt-in client next-credential switching. Config
parsing, validation, runtime lookup, and redacted dry-run linting are
implemented. The server accepts configured `previous` credentials only during
bounded overlap windows. Clients can carry next credential material and switch
locally after `not_before` only when `auto_switch=true`.

Credential rotation must let operators replace user secrets without breaking
all clients at once, while keeping secrets out of logs, command output, and
long-lived process diagnostics.

## Goals

- Support overlapping old and new credential material.
- Keep v1 compatibility during the first rotation implementation.
- Make rotation state visible through redacted validation reports.
- Prevent accidental downgrade to short or reused secrets.
- Avoid changing host proxy, DNS, route, firewall, VPN, or other network-service settings in
  local tests.

## Non-Goals

- Centralized account management.
- Remote secret distribution.
- Printing secret values in any CLI report.
- Strong anonymous credential claims.

## Proposed Server Config

```yaml
users:
  - id: "u_example"
    name: "alice"
    enabled: true
    secret: "mv1_current_redacted_example"
    rotation:
      previous:
        - id: "u_example_2026_06"
          secret: "mv1_previous_redacted_example"
          not_before: "2026-06-01T00:00:00Z"
          not_after: "2026-07-15T00:00:00Z"
      next:
        id: "u_example_2026_08"
        not_before: "2026-07-15T00:00:00Z"
```

The current runtime keeps `secret` as the active credential and accepts a
bounded `previous` list during overlap windows. A future Auth v2 implementation
can replace explicit ids with epoch hints or blinded lookup keys.

## Proposed Client Config

```yaml
server:
  credential_id: "u_example"
  secret: "mv1_current_redacted_example"

auth:
  rotation:
    active_epoch: "2026-07"
    next_credential_id: null
    auto_switch: false
    next: null
```

Explicit opt-in next credential switching:

```yaml
auth:
  rotation:
    active_epoch: "202607"
    next_credential_id: "u_example_2026_08"
    auto_switch: true
    next:
      id: "u_example_2026_08"
      secret: "mv1_next_redacted_example"
      not_before: "2026-07-15T00:00:00Z"
```

The client does not switch credentials based only on wall-clock time unless
`auto_switch=true` and validated next credential material is present. This is a
local selection workflow only; it does not distribute secrets or rewrite config
files.

## Implemented Baseline

- Client config accepts `auth.rotation.active_epoch` and
  `auth.rotation.next_credential_id`.
- Client config accepts optional `auth.rotation.auto_switch` plus
  `auth.rotation.next.{id,secret,not_before}` and validates next-secret
  material without printing it.
- Client runtime selects the next credential for v1/Auth v2 handshakes only
  after `not_before` when `auto_switch=true`; otherwise it keeps using
  `server.credential_id` and `server.secret`.
- Server config accepts `users[].rotation.previous` and
  `users[].rotation.next`.
- Server runtime authenticates configured previous credentials only when the
  current time is inside their `not_before` / `not_after` window.
- Previous credentials map back to the active user for rate limits and flow
  limits while using the previous secret for ServerHello authentication.
- Previous rotated secrets must pass the existing high-entropy secret
  validation.
- Previous rotation windows must use RFC3339 timestamps and bounded
  `not_before` / `not_after` ordering.
- Active, previous, and next credential ids must be unique per user.
- Server runtime rejects duplicate active/previous credential ids across its
  lookup index instead of silently overriding entries.
- Each user can keep at most four previous credentials.
- Generated configs and migration dry-run expose `auth.v2.enabled=false`.
- `maverick rotate-credential --server <path> --dry-run [--user <id>]` reports
  redacted rotation state and warnings without writing config files.
- `maverick key-inventory --kind client` reports whether next credential
  material is configured but redacts the next secret.

## CLI Workflow

Generate a replacement credential:

```sh
maverick gen-user --name alice
```

Implemented dry-run command:

```sh
maverick rotate-credential --server server.yaml --user u_example --dry-run
```

The dry run should report:

- user id, redacted;
- whether previous credential windows are pending, active, or expired;
- whether a configured next credential is scheduled or ready for promotion;
- disabled users that still carry rotation state;
- warning count for operator follow-up.

It must not print secret values.

## Rollout Sequence

1. Generate the new secret offline.
2. Add the new credential as `next` or add the old credential under
   `previous`, depending on the chosen config model.
3. Deploy server config that accepts both credentials during a bounded overlap.
4. Update clients to the new credential directly, or preload
   `auth.rotation.next` with `auto_switch=true` and a conservative
   `not_before`.
5. Run `rotate-credential --dry-run` until expired previous credentials and
   ready next credentials are resolved.
6. Remove the old credential after the overlap expires.

## Required Tests

Implemented:

- Config rejects short rotated secrets.
- Config rejects unbounded overlap windows.
- Config rejects duplicate active and previous credential ids.
- Server accepts active credential.
- Server accepts previous credential only inside the overlap window.
- Server rejects previous credential after `not_after`.
- Disabled users remain disabled even if a rotated credential is present.
- CLI dry-run output is redacted.
- Client-side next credential switching succeeds after `not_before`.
- Client-side next credential switching does not happen before `not_before`.
- Client key inventory redacts next credential secret material.

## Operational Notes

- Rotation windows should be short enough to limit blast radius but long enough
  for manual client updates.
- Server logs should show only redacted user ids and coarse rotation state.
- Operators should keep old secrets available only for rollback during the
  overlap window.

## Failure And Recovery

- If the new credential is malformed, not yet valid, or rejected, stop automatic
  switching and keep the last valid credential only when it is not compromised.
- If the active credential is compromised, revoke it first; do not extend an
  overlap window just to preserve availability.
- Keep server and client clocks healthy, but do not use clock correction as a
  reason to print or redistribute secret material.
- A partial client rollout must remain visible through redacted inventory and
  authentication metrics. Do not delete the old credential until intended
  clients are accounted for or explicitly retired.
- After rollback, remove partial `next` material, validate configs, verify old/new
  authentication behavior, and record the reason without credential values.
- The packaged Linux service must prove restart, reboot, active-to-next rotation,
  upgrade, and fail-closed behavior under its production credential-root gate.

Suspected compromise follows `docs/INCIDENT_RESPONSE.md`; ordinary planned
rotation follows this document.
