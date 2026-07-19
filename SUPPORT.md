# Maverick Support Policy

Maverick is an experimental open source prototype. No release train is active;
the archived `v1.2.0-alpha.1` candidate is No-Go. The completed `v1.1.0`
boundary predates the sanitized public Git history.

## Supported Versions

| Version line | Status | Security fixes | Compatibility promise |
| --- | --- | --- | --- |
| `v0.1.0-alpha.N` | Historical experimental snapshots | Upgrade only | None |
| `v0.1.0-beta.N` and `v0.1.0-rc.N` | Historical candidates | Upgrade only | Narrow historical scope only |
| `v1.0.x` | Pre-publication historical line | Upgrade when a public release is available | Frozen `maverick-tls-h2-cli-v1` scope |
| `v1.1.x` | Pre-publication maintenance boundary | Superseded by the next public release | Frozen `maverick-tls-h2-cli-v1` scope |
| `main` | Experimental development snapshot; no active release target | None before a future release | Auth v1 remains 1, explicit Auth v2 remains 2, and config remains 1 |

No stable tag exists in the sanitized public history yet. After the first
public release, only the latest public stable tag receives best-effort fixes
for this personal, as-is project. This support policy is not a production
support SLA.

## Named v1.2.0 Candidate Platform

| component | candidate support target | current status |
| --- | --- | --- |
| `maverick` server/CLI | Ubuntu 26.04 LTS `amd64`, IPv4, TLS 1.3 + HTTP/2 | archived No-Go candidate; unsupported |
| `maverick-reference-client` Debian package/service | Ubuntu 26.04 LTS `amd64`, IPv4 | archived No-Go candidate; unsupported |

Formal target-platform evidence must be collected in a source-bound disposable
Ubuntu 26.04 LTS `amd64` VM or fixture. Results from another host OS do not create
support for Ubuntu or any additional platform. Other Linux distributions,
architectures, containers, routers, macOS, Windows, mobile, GUI, and IPv6 are
outside the candidate support promise.

This table is an archived target definition, not a supported release.

## Breaking Changes

Development snapshots may change CLI or operator behavior when the change
improves safety or removes a bad design. The archived `v1.2.0-alpha.1` source
keeps protocol, authentication, and config versions at 1. Breaking changes
must be listed in `CHANGELOG.md`, `MIGRATIONS.md`, and release notes.

Stable-scoped releases must not break the documented stable scope without:

- a migration note;
- a compatibility note;
- a new minor version or clearly labeled breaking release;
- tests proving old supported configs are handled or intentionally rejected.

## Security Reports

Please avoid opening public issues with secrets, exploit details, private server
addresses, or generated `mv1_` credentials. Use GitHub private vulnerability
reporting when available. If it is unavailable, open a public issue with only a
short, non-sensitive coordination request and no exploit details.

Security reports should include:

- affected commit or tag;
- minimal reproduction steps;
- whether the issue requires authentication;
- logs with secrets redacted;
- expected impact.

The private report lifecycle and disclosure process are in
`docs/SECURITY_DISCLOSURE_WORKFLOW.md`. Incident playbooks are in
`docs/INCIDENT_RESPONSE.md`.

## Non-Claims

Support does not imply that Maverick is audited, production-ready, anonymous,
censorship-proof, or a replacement for mature VPN/proxy products.
