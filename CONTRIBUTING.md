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
