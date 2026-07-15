# Maverick Compatibility

Status: compatibility policy for the narrow `maverick-tls-h2-cli-v1` scope.
The completed `v1.1.0` boundary predates the sanitized public Git history.
This is not a production, formal-audit, anonymity, censorship-resistance, or
standardization claim.

## Protocol Compatibility

- Current Auth v1 hello protocol version: `1`.
- Current explicit Auth v2 hello protocol version: `2`.
- Current config version: `1`.
- v1 frames are carried over TLS 1.3 + HTTP/2 by default.
- Experimental H3/QUIC can carry the same authenticated frame protocol when the
  `h3` feature is compiled and `advanced.experimental_h3` is enabled.
- historical internal baseline v1.1 additions use existing frame semantics for
  DNS, UDP, HTTP CONNECT local inbound, reverse proxy fallback, and metrics;
  that label is not the post-v1 software release `v1.1.x`.
- Unsupported protocol versions are handled as unauthenticated remote behavior
  before detailed protocol errors are exposed.

## Configuration Compatibility

Existing config files using `version: 1` should remain valid through the
`v1.0.0` narrow stable scope and compatible follow-up releases when:

- `version: 1` is present;
- credentials use high-entropy `mv1_` secrets;
- local client listeners are loopback-only unless explicitly opted into
  non-loopback listeners;
- timeout and limit values are greater than zero.

New fields should prefer safe defaults so older configs keep working. If a
previously accepted config value becomes rejected for safety, the release must
document it in `MIGRATIONS.md`, `CHANGELOG.md`, and release notes.

The optional client `advanced.experimental_tun` field defaults to `false`, so
existing config-version-1 files remain valid. It is outside the stable v1.0.0
scope, requires the `tun-runtime` client/SDK feature, and does not change the
wire or authentication versions.

Current product and release support remains IPv4-only. Experimental IPv6 packet
code and synthetic tests do not create an IPv6 support promise. IPv6 has no
scheduled milestone and requires a new explicit decision before it can enter a
future release claim.

## v1.1.0 Compatibility Boundary

`v1.1.0` is a software-version advance with no mandatory protocol or
configuration migration:

- Auth v1 hello protocol version remains `1`;
- explicit Auth v2 hello protocol version remains `2`;
- config version remains `1`;
- the default carrier remains TLS 1.3 plus HTTP/2;
- H2 connection reuse is internal and uses existing frame semantics;
- browser-TLS, H3, CDN-fronted WebSocket, experimental cryptography, and TUN
  remain optional, feature-gated, runtime-gated, or default-off as documented;
- existing valid `v1.0.0` client and server configs continue to validate.

## v1.2.0 Candidate Compatibility Boundary

The planned first public line keeps these versions separate:

- release train: `1.2.0`;
- planned release tag: `v1.2.0-alpha.1`;
- planned Maverick software version: `1.2.0-alpha.1`;
- planned reference-client software version: `1.2.0-alpha.1`;
- planned reference-client Debian package version: `1.2.0~alpha.1-1`;
- Auth v1 protocol version: `1`;
- explicit Auth v2 protocol version: `2`;
- config version: `1`;
- platform-helper IPC version: `1`;
- recovery journal version: `2`;
- current platform plan version: `3`.

These planned version strings identify the next stage. They do not freeze its
commits, SDK pin, package hash, evidence, or approval.

The supported-platform candidate is Ubuntu 24.04 LTS `amd64`, IPv4, with the
default TLS 1.3 plus HTTP/2 path. Its reference client must pin the exact
Maverick SDK commit recorded separately from the Maverick release commit. A
public documentation-only commit after that SDK commit does not silently change
the pin or transfer runtime evidence.

Other host operating systems may run local or isolation checks, but only a
source-bound disposable Ubuntu 24.04 fixture can satisfy the candidate platform
gate. No cross-distribution, cross-architecture, IPv6, H3, GUI, or mobile
compatibility promise is made.

## Stable v1.0.0 Boundary

The `v1.0.0` software tag stabilizes only the documented
`maverick-tls-h2-cli-v1` scope:

- Auth v1 hello protocol version remains `1`;
- explicit Auth v2 hello protocol version remains `2`;
- config version remains `1`;
- no mandatory migration is planned;
- any later protocol or config change must update this document,
  `MIGRATIONS.md`, `CHANGELOG.md`, and the release notes before tagging.

`v0.1.0-beta.2`, `v0.1.0-rc.1`, `v0.1.0-rc.2`, and `v1.0.0` all keep the same
config/protocol boundary: software version advanced, while config version `1`,
Auth v1 hello version `1`, and explicit Auth v2 hello version `2` remained
unchanged.

## Transport Compatibility

H2/TLS is the mandatory fallback transport. H3/QUIC support is optional,
feature-gated, and disabled by default. Ordinary users should not need to choose
H2 or H3 directly; modes such as `auto`, `stable`, and `private` should drive
the current scheduler policy.

## Stability Caveat

The pre-publication Maverick `v1.1.0` release was stable only for the narrow
CLI-managed TLS/H2 scope. It is not production-ready, formally audited,
anonymous, censorship-resistant, or standardized. Breaking changes must be
documented in `MIGRATIONS.md` before release.
