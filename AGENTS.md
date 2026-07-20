# Maverick Agent Guide

Maverick is an experimental Rust privacy proxy. Keep changes local, small, and
verifiable. Do not rebuild the former coordination system.

## Non-Negotiable Safety Boundary

Do not change this machine's system proxy, DNS, route table, firewall, VPN,
interfaces, or other network-service settings. Local tests and demos use
`127.0.0.1` plus OS-assigned ephemeral ports. A real-network pilot requires a
separately named owner-controlled environment and explicit authorization.

## Product Map

- `crates/maverick-core`: config, auth, frames, replay, padding, metrics.
- `crates/maverick-client`: local listeners, TLS/H2 transport, relay session.
- `crates/maverick-server`: TLS/H2 acceptor, auth gate, fallback, relay policy.
- `crates/maverick-cli`: operator commands and local product smoke.
- `crates/maverick-sdk`: embedded API.
- `crates/maverick-tests`: Rust loopback integration coverage.
- `STATUS.md`: the only active current-truth document.
- `ROADMAP.md`: the user-first execution order.
- `docs/archive/` and `scripts/archive/`: provenance only.

## Progress Rule

Use `STATUS.md` as the only definition of current product truth, progress,
audit status, and authorization. Do not promote tests, hashes, safe rejection,
or tooling into product results.

Do not restart Phase 3, add a successor certification framework, or create new
receipt, seal, registry, watchdog, evidence-schema, or Python coordination
layers.

## Default Verification

Run:

```sh
./scripts/user-smoke.sh
./scripts/local-harness.sh
```

Both commands must remain local-only.

## Development Rules

- Preserve the project name `Maverick`.
- Preserve honest alpha/non-production claim boundaries.
- Keep generated credentials and real endpoints out of git.
- Prefer Rust product tests over new orchestration tools.
- Keep `scripts/user-smoke.sh` under 200 lines and understandable in one read.
- Update `STATUS.md` when current product truth changes.
- Update `ROADMAP.md` only when execution order changes.
- Do not maintain consistency inside archived documents.

Before a commit, inspect staged changes, the message, and generated artifacts
for private identity, infrastructure, account, location, credential, hostname,
address, local-path, or environment strings. Replace any such material with
neutral placeholders.
