# Operations Guide

This guide is for self-hosted Maverick operators. It does not make Maverick a
production-ready security product by itself.

## Deployment Scope

The first stable-scope target is:

- CLI-managed client and server;
- TLS 1.3 plus HTTP/2 as the default carrier;
- explicit config files owned by the operator;
- loopback-only local client listeners by default;
- no native server-side ECH claim.

For development and pre-release harness work, prefer loopback tests or a
dedicated VM. Operators may intentionally configure system proxy, DNS, route,
firewall, VPN, or platform network-extension behavior for their own deployments,
but those host-level changes should be tested on a machine where rollback is
acceptable.

## Files And Permissions

Recommended Linux layout:

```text
/usr/local/bin/maverick              mode 0755
/etc/maverick/server.yaml            mode 0600
/etc/maverick/fullchain.pem          mode 0644
/etc/maverick/privkey.pem            mode 0600
/etc/maverick/maverick-server.env    mode 0600
/var/lib/maverick/                   mode 0700
/var/log/maverick/                   mode 0700
```

Use a dedicated `maverick` service account. Do not reuse a personal shell user
for unattended services.

## Certificates

Maverick server TLS requires a certificate chain and private key:

```yaml
tls:
  cert_path: "/etc/maverick/fullchain.pem"
  key_path: "/etc/maverick/privkey.pem"
```

For public deployments, use a normal ACME-issued certificate and reload or
restart the service after renewal. Keep private keys readable only by the
service account or root.

## Metrics

Metrics are disabled by default. When enabled, the listener must be loopback:

```yaml
metrics:
  enabled: true
  listen: "127.0.0.1:19090"
```

Important counters:

- `authenticated_sessions`: accepted tunnel sessions.
- `unauthenticated_rejections`: tunnel-like requests rejected before auth.
- `fallback_requests`: fallback responses served.
- `fallback_overload_rejections`: fallback responses skipped because fallback
  work was already at its configured concurrency limit.
- `active_connections`: currently accepted server connections.
- `connection_limit_rejections`: connections rejected by the global connection
  cap.
- `source_connection_limit_rejections`: connections rejected by the per-source
  cap.
- `active_pre_auth`: currently admitted pre-auth connection or request work.
- `pre_auth_admission_rejections`: concurrent pre-auth work rejected.
- `active_fallbacks`: currently running fallback responses.
- `auth_rate_limit_rejections`: repeated failed auth attempts rate-limited.
- `flow_limit_rejections`: authenticated user flow limit rejections.

Do not expose the metrics listener directly to the internet.

## Abuse And Pressure Controls

Relevant server settings:

```yaml
advanced:
  max_concurrent_connections: 2048
  max_concurrent_connections_per_source: 256
  pre_auth_max_concurrent: 512
  fallback_max_concurrent: 512
  auth_failure_window_secs: 60
  max_auth_failures_per_window: 24
  auth_failure_cache_max_entries: 4096
  idle_timeout_secs: 300
  tcp_connect_timeout_ms: 10000
  handshake_timeout_ms: 10000
```

These are overload controls, not DDoS protection. Put public deployments behind
normal host firewall and provider-level abuse controls.

Connection caps reject excess TCP/TLS work before it can become an authenticated
tunnel. Pre-auth caps bound unauthenticated handshake and tunnel-sniffing work.
Fallback caps bound ordinary website fallback work, including reverse-proxy
fallbacks, so a flood cannot create unbounded fallback load.

## systemd

Example files:

```text
examples/systemd/maverick-server.service
examples/systemd/maverick-server.env.example
```

Typical install flow on an approved Linux server:

```sh
sudo install -m 0755 dist/maverick-<version>-<target>/maverick /usr/local/bin/maverick
sudo install -d -m 0700 -o maverick -g maverick /var/lib/maverick /var/log/maverick
sudo install -d -m 0750 -o root -g maverick /etc/maverick
sudo install -m 0600 -o root -g maverick server.yaml /etc/maverick/server.yaml
sudo install -m 0644 fullchain.pem /etc/maverick/fullchain.pem
sudo install -m 0600 -o root -g maverick privkey.pem /etc/maverick/privkey.pem
sudo install -m 0644 examples/systemd/maverick-server.service /etc/systemd/system/maverick-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now maverick-server
```

Before enabling, run:

```sh
maverick check-config --kind server -c /etc/maverick/server.yaml
```

## Credential Rotation

Use the documented rotation commands and config fields in
`docs/CREDENTIAL_ROTATION.md` and `docs/KEY_LIFECYCLE.md`.

Operational sequence:

1. Generate next credential material.
2. Add next/previous credential windows to server config.
3. Validate server config.
4. Roll out server config.
5. Roll out client config.
6. Monitor `authenticated_sessions`, `unauthenticated_rejections`, and support
   reports.
7. Remove expired previous credentials after the overlap window.

Never publish or paste generated `mv1_` secrets in issues, logs, release notes,
or support threads.

## Public Support Data Hygiene

When reporting operational issues publicly, redact:

- generated credentials and private keys;
- real server addresses, private hostnames, account names, and cloud resource
  names;
- certificate and key paths;
- local private filesystem paths;
- raw payload data and HMAC tags;
- provider regions or infrastructure labels that are not necessary for a
  loopback reproduction.

Prefer loopback reproductions and neutral placeholders such as
`REPLACE_WITH_TEST_HOSTNAME`. If a report needs real infrastructure details or
exploit steps, use a private security-reporting channel instead of a public
issue.

## Upgrade And Rollback

Before upgrade:

```sh
./scripts/local-harness.sh
./scripts/security-dependency-inventory.sh
./scripts/release-artifacts.sh
```

On the server:

```sh
maverick check-config --kind server -c /etc/maverick/server.yaml
sudo cp /usr/local/bin/maverick /usr/local/bin/maverick.previous
sudo install -m 0755 dist/maverick-<version>-<target>/maverick /usr/local/bin/maverick
sudo systemctl restart maverick-server
sudo systemctl status maverick-server
```

Rollback:

```sh
sudo install -m 0755 /usr/local/bin/maverick.previous /usr/local/bin/maverick
sudo systemctl restart maverick-server
```

If config fields changed, keep a copy of the previous validated config and
restore it with the binary rollback.

## Incident Handling

For suspected credential compromise:

1. Disable the affected user or credential.
2. Restart or reload the service.
3. Rotate to a new credential.
4. Review redacted logs and metrics.
5. Open a private security report if the issue may be a Maverick vulnerability.

For overload:

1. Check `pre_auth_admission_rejections` and `auth_rate_limit_rejections`.
2. Tighten provider firewall or host firewall rules.
3. Lower public exposure or move to a fresh host if traffic is abusive.
4. Do not weaken fallback/auth behavior to debug live abuse.
