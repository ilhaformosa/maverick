# Contributing To Maverick

Maverick is an experimental Rust privacy proxy prototype. Keep contributions
small, reviewable, and honest about security boundaries.

Participation is also governed by `CODE_OF_CONDUCT.md`.

## Safety Boundary

Do not change a contributor machine's system proxy, DNS, route table, firewall,
VPN, or other network-service settings in tests, examples, or scripts.
Default tests must bind to `127.0.0.1` and use OS-assigned ephemeral ports.

VM, TUN, public-port, or route/DNS experiments must be isolated behind an
explicit approved-host harness and documented rollback behavior.

## Before Opening A Pull Request

Run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
```

If your change touches H3/QUIC behavior, also run:

```sh
./scripts/h3-harness.sh
```

Before commit or review, scan the staged diff, author/committer identity, commit
message, and generated artifacts for private email, paths, hosts, accounts,
infrastructure, credentials, and raw evidence. Public identity and signing rules
are in `docs/MAINTAINER_IDENTITY_AND_SIGNING.md`.

Every public pull request runs `public-pr-ci`. Documentation hygiene always
runs, and the core harness always runs. Only H3, ECH, shape-lab, and browser-TLS
jobs are selected by changed paths. The stable required result is
`public-pr-ci / public-pr-gate`. Contributors do not dispatch the separate
release-candidate workflow; that gate requires a coordinator-approved frozen
commit. See `docs/CI_AND_RELEASE_GATES.md`.

## Documentation Expectations

- Update `CONFIG.md` for config fields.
- Update `SPEC.md` or `WIRE_FORMAT.md` for protocol or frame changes.
- Update `TEST_PLAN.md` when adding or removing meaningful coverage.
- Keep experimental features default-off unless their release gate says
  otherwise.
- Do not add audited, production-ready, anonymity, censorship-resistance, or
  browser-fingerprint claims without matching evidence.

## Security Issues

Do not open public issues with working exploit details or secrets. Follow
`SECURITY.md` and contact the maintainer privately when a report could put
users or operators at risk.

A contributor, maintainer, Codex agent, or AI tool may provide review input but
cannot label review of its own work as the independent production audit.
