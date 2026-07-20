# ECH Runtime Blocker Plan

Status: frozen upstream-tracking plan, not an active post-v1 milestone. It may
be reactivated only by `docs/PLAN_POST_V1.md`. This document records how
Maverick could reduce the ECH blocker without mutating the developer
workstation network or claiming runtime support before the TLS stack can
provide it.

The active workaround decision is documented in `docs/ECH_WORKAROUND.md`:
Cloudflare-fronted WebSocket is the immediate ECH workaround, while native
Maverick server-side ECH remains an upstream dependency.

ECH work is split into small gates because three concerns are independent:

- local client API tracking;
- controlled DNS/ECHConfig distribution;
- Maverick server-side runtime support.

`docs/history/manifests/ech-runtime-blockers.json` is the machine-readable execution registry for this
plan. It is intentionally separate from `docs/history/manifests/ech-runtime-approval.json`: the
approval manifest keeps runtime ECH disabled, while the blocker registry tracks
which preparation slices are complete and which still require external state.

## Current State

Completed locally:

- rustls client-side ECH API tracking through `scripts/ech-harness.sh`;
- config fallback-policy tests that reject `advanced.experimental_ech: true`
  and reject `allow_plain_sni` in private mode.

Approved host:

- `approved-linux-vm` can be the ECH integration host when runtime network activity
  is explicitly approved. It has already been used for the Cloudflare edge
  preflight, origin reachability probe, and Cloudflare-fronted WebSocket
  runtime smoke.

Completed externally/on approved host:

- A dedicated proxied Cloudflare DNS record existed in the private operator
  environment, pointing at an approved origin address. Public docs use
  `maverick-ech.example.com` as a placeholder.
- Cloudflare published an HTTPS/SVCB record for that private test subdomain
  with an `ech` parameter.
- `scripts/approved-vm-ech-edge-preflight.sh` passed from `approved-linux-vm`
  on 2026-06-27 against that private test hostname: rustls completed a TLS 1.3
  handshake to Cloudflare edge and reported `EchStatus::Accepted`.

Reproduce with:

```sh
MAVERICK_ECH_EDGE_PREFLIGHT_APPROVED=1 \
MAVERICK_ECH_EDGE_ALLOW_CUSTOM_DOMAIN=1 \
MAVERICK_ECH_EDGE_DOMAIN=REPLACE_WITH_ECH_TEST_HOSTNAME \
  ./scripts/approved-vm-ech-edge-preflight.sh REPLACE_WITH_APPROVED_CLIENT_SSH_HOST
```

Completed externally/on approved host, continued:

- `scripts/approved-vm-ech-cloudflare-origin-probe.sh` can now probe whether a
  Cloudflare-fronted runtime path can reach an approved origin. It starts
  temporary TCP/80 and TCP/443 listeners on `approved-linux-vm`, probes them
  from a separate approved external VM, probes the Cloudflare front door, then
  removes listeners and checks for residue.
- The current origin reachability probe passes: direct HTTP and HTTPS from an
  approved external probe VM to the approved origin IP work, and Cloudflare
  reaches a temporary HTTPS origin on `approved-linux-vm`.

Reproduce with:

```sh
MAVERICK_ECH_ORIGIN_PROBE_APPROVED=1 \
MAVERICK_ECH_ORIGIN_DOMAIN=REPLACE_WITH_ECH_TEST_HOSTNAME \
MAVERICK_ECH_ORIGIN_IP=REPLACE_WITH_APPROVED_ORIGIN_IP \
MAVERICK_ECH_ORIGIN_PROBE_HOST=REPLACE_WITH_APPROVED_PROBE_SSH_HOST \
  ./scripts/approved-vm-ech-cloudflare-origin-probe.sh REPLACE_WITH_APPROVED_ORIGIN_SSH_HOST
```

Completed on approved hosts:

- `scripts/approved-vm-ech-cloudflare-fronted-runtime-smoke.sh` starts a
  temporary Maverick origin on `approved-linux-vm`, starts a temporary Maverick
  client on an approved VM, and sends one SOCKS5 TCP echo flow through the
  configured Cloudflare-fronted test hostname.
- Current result: ordinary Cloudflare front-door GET returns 200, finite POST to
  the Maverick tunnel path returns 200 and reaches origin, and the WebSocket
  carrier successfully sends one SOCKS5 TCP echo flow through
  the private Cloudflare-fronted test hostname.
- Earlier H2/gRPC attempts remained blocked by Cloudflare `400 Bad Request`
  after Cloudflare gRPC was enabled for the zone, Maverick's H2 request used
  `content-type: application/grpc` plus `te: trailers`, Maverick H2 body frames
  were wrapped in gRPC message envelopes, and the smoke used a gRPC-shaped
  tunnel path. That evidence is retained as provider behavior, but the
  Cloudflare-fronted runtime path now uses WebSocket.

Reproduce the current Cloudflare-fronted runtime smoke with:

```sh
MAVERICK_ECH_CF_RUNTIME_APPROVED=1 \
MAVERICK_ECH_CF_DOMAIN=REPLACE_WITH_ECH_TEST_HOSTNAME \
MAVERICK_ECH_CF_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
  ./scripts/approved-vm-ech-cloudflare-fronted-runtime-smoke.sh REPLACE_WITH_APPROVED_ORIGIN_SSH_HOST
```

Blocked:

- native Maverick server-side ECH, because Maverick's server TLS stack is
  rustls and rustls server-side ECH is still tracked upstream. See
  `docs/ECH_NATIVE_TLS_LIMITATION.md` for the non-technical explanation;
- runtime ECHConfig distribution and runtime config acceptance, because both
  depend on native server-side support plus a native config-source design;
- native runtime ECH handshake smoke, because no server-side ECH backend exists
  for Maverick's Rust server role yet. The completed Cloudflare-fronted
  WebSocket smoke is an edge-fronted runtime result, not native server-side ECH.

## Cloudflare DNS Preparation

The operator-action slice used a controlled Cloudflare subdomain for an
edge-only ECH preflight. This validates DNS distribution and client-side ECH
behavior against Cloudflare's edge, not Maverick's native Rust server.

Recommended subdomain:

```text
maverick-ech.example.com
```

Cloudflare setup used for this phase:

- create a dedicated DNS record such as `maverick-ech.example.com`;
- keep it proxied through Cloudflare;
- point it at a disposable or test origin, preferably `approved-linux-vm`;
- ensure Cloudflare edge ECH is enabled for the zone;
- wait until Cloudflare publishes HTTPS/SVCB records with an `ech` parameter;
- do not change existing production, proxy, or unrelated service records.

The first preflight ran from `approved-linux-vm`, not from the developer Mac. It
only queried DNS and performed a controlled TLS client handshake to Cloudflare
edge. It did not change system DNS, routes, firewall, proxy settings, or
VM route tables.

The origin reachability probe now passes with approved-origin TCP/443 access
and Cloudflare SSL/TLS mode set to Full. Full mode is suitable for this
temporary smoke because the script generates a short-lived self-signed origin
certificate.
Full (Strict) is the better long-term mode, but it requires a certificate that
Cloudflare can validate, such as a Cloudflare Origin CA certificate or a public
CA certificate for the hostname.

The current repository does not mutate Cloudflare settings or cloud firewall
rules.

## Runtime Integration Boundary

An edge-only Cloudflare ECH preflight is useful but limited:

- it can prove that a controlled domain publishes ECHConfig and that a client
  stack can attempt ECH;
- it cannot prove Maverick server-side ECH, because Cloudflare terminates TLS
  at the edge;
- it cannot unblock `advanced.experimental_ech: true` for Maverick runtime by
  itself.

Native runtime ECH remains blocked until a reviewed server-side TLS backend
path exists for Maverick's Rust server role. Once that exists, the runtime plan
needs a new approved-host smoke that verifies:

- ECHConfig source freshness and public-name/origin-name consistency;
- certificate validation after handshake;
- H2 and H3 ALPN behavior separately;
- fail-closed behavior for private mode;
- explicit plain-SNI fallback only outside private mode;
- no 0-RTT for authenticated tunnel setup.

## Cloudflare-Fronted Runtime Experiment

Cloudflare-fronted ECH is a practical interim experiment, not the same thing as
native Maverick server-side ECH:

- the client negotiates ECH with Cloudflare edge;
- Cloudflare terminates client TLS and proxies an origin request;
- Maverick origin traffic is protected from the public client-facing SNI leak,
  but Maverick itself does not receive or process ECH;
- WebSocket tunnel semantics have passed one approved-host full-duplex TCP echo
  smoke through Cloudflare. The earlier H2/gRPC attempt remains documented as
  blocked by Cloudflare `400 Bad Request`.

This experiment can reduce deployment risk for an edge-fronted mode. It cannot
clear the native runtime ECH gate by itself while Maverick's server TLS backend
lacks server-side ECH support.

The approval manifest therefore treats this as completed evidence for the
Cloudflare-fronted path, not as native runtime ECH acceptance.

## Safety Boundary

ECH work must not:

- mutate this Mac's DNS, routes, proxy settings, firewall, VPN, or other network-service settings;
- mutate the approved external probe/client VM network stack;
- use ad hoc public test domains as blocker evidence;
- mark runtime ECH as allowed before server TLS, config distribution,
  controlled DNS, approved-host smoke, and fallback-policy gates all pass.
