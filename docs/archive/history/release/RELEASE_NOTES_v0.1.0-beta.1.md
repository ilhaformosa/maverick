# Maverick v0.1.0-beta.1 Release Notes

Status: first beta source snapshot for the frozen `maverick-tls-h2-cli-v1`
release train.

Maverick remains an experimental as-is prototype. Beta.1 means the narrow
v1.0 scope is frozen and runtime hardening has begun. It does not mean
production-ready, audited, stable protocol freeze, anonymity, or
censorship-resistance.

## Highlights

- Runtime hardening: server-side global connection caps, per-source connection
  caps, pre-auth admission bounds, fallback concurrency bounds, and failed-auth
  pacing are now documented and covered by loopback tests.
- Observability: the loopback metrics endpoint reports authenticated sessions,
  unauthenticated rejections, fallback load, overload rejections, active
  connections, active pre-auth work, active fallbacks, active flows, and flow
  limit pressure without exposing secrets or payload bytes.
- Log hygiene: the default gate rejects logging of secrets, raw payload/body
  data, auth tags, credential identifiers, client nonces, and replay keys.
- Deployment hardening: operations docs cover least-privilege service layout,
  owner-only config and state paths, systemd examples, cert renewal, rollback,
  overload controls, and public-report redaction.
- Scope cleanup: v1.0 remains the narrow TLS 1.3 plus HTTP/2 CLI-managed path.
  Native server-side ECH, stable H3/QUIC, TUN apply, GUI, anonymity, and
  censorship-resistance remain outside the v1.0 claim.

## Version Boundaries

- software release tag: `v0.1.0-beta.1`;
- package version: `0.1.0-beta.1`;
- default `protocol_version: 1`, unchanged;
- config `version: 1`, unchanged;
- no mandatory migration from `v0.1.0-alpha.4`.

New server `advanced.*` overload fields have defaults. Existing configs should
continue to parse, but operators should review `CONFIG.md` and
`docs/OPERATIONS.md` and set explicit values for public deployments.

## Known Limitations

- No native server-side ECH.
- No stable protocol freeze.
- No formal security audit.
- No production-ready claim.
- No strong anonymity, traffic-analysis resistance, or censorship-resistance
  claim.
- No GUI/App runtime claim in this repository.
- Abuse/DoS controls are resource bounds and observability aids, not a full WAF
  or DDoS mitigation layer.
- S2 still requires independent approved-client-host evidence before the
  release train can move toward RC.

## Verification

Before tagging, run:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

Record the final tagged commit hash, release artifact names, and checksums in
the GitHub Pre-release body. Publish this tag as a GitHub Pre-release with
`--latest=false`.
