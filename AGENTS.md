# Maverick Agent Guide

Maverick is an experimental Rust privacy proxy prototype. Keep changes local,
small, and verifiable.

## Non-Negotiable Safety Boundary

Do not change this machine's system proxy, DNS, route table, firewall, VPN,
or other network-service settings. Tests and demos must use
`127.0.0.1` plus OS-assigned ephemeral ports unless the user explicitly
provides a separate VM or test machine.

## Project Map

- `crates/maverick-core`: shared config, auth, wire frames, replay, padding, metrics.
- `crates/maverick-client`: local SOCKS5, DNS, HTTP CONNECT, H2 transport, relay session.
- `crates/maverick-server`: TLS/H2 acceptor, auth gate, fallback, relay, user policy.
- `crates/maverick-cli`: `maverick` command-line entry point and local benchmark.
- `crates/maverick-tests`: loopback-only integration tests and reusable test harness.
- `config/`: checked-in placeholder configs only; do not commit real secrets.
- `docs/PLAN_POST_V1.md`: active post-v1 execution plan and milestone gates.
- `ROADMAP.md`: concise current and long-term direction.
- `COMPATIBILITY.md`, `MIGRATIONS.md`, `RELEASE_CHECKLIST.md`: stabilization and release gates.
- `docs/HARNESS_ENGINEERING.md`: repo-local harness engineering rules.

## Default Verification

Run this before committing:

```sh
./scripts/local-harness.sh
```

The script runs formatting, Clippy, tests, config generation checks, and repo
hygiene scans. It must remain local-only.

## Development Rules

- Preserve the project name `Maverick`; do not reintroduce names from earlier prompts.
- Keep generated credentials out of git. Use placeholder strings in examples.
- Prefer extending the integration harness in `crates/maverick-tests/tests/support`.
- Update `TEST_PLAN.md` when adding or removing meaningful coverage.
- Update docs when config fields, CLI commands, or operator behavior change.
- Keep roadmap phase status current when completing a phase gate.
