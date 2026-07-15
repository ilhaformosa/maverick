# Maverick Harness Engineering

This repo follows harness engineering as described by
[OpenAI](https://openai.com/index/harness-engineering/): shape the environment
so coding agents can understand the system, make bounded changes, and get fast
feedback from executable checks.

## Goals

- Make repo knowledge discoverable without reading every file.
- Encode safety constraints in docs, config validation, tests, and scripts.
- Keep local checks deterministic and safe for the developer's machine.
- Turn recurring manual review concerns into mechanical checks.
- Keep plans, tests, and docs close to the code they govern.

## Safety Harness

Maverick development must not disturb the host machine's existing proxy or VPN
setup. The local safety harness is:

- all integration tests bind to `127.0.0.1`;
- tests request ephemeral ports with port `0`;
- client config rejects non-loopback local listeners by default;
- server metrics must bind to loopback when enabled;
- `scripts/local-harness.sh` performs no system network configuration.
- `scripts/log-hygiene.py` blocks direct logging of secrets, auth tags,
  credential hints, and credential ids.
- `scripts/claim-hygiene.py` requires key docs to keep explicit non-audit,
  non-production, non-anonymity, and non-standardization disclaimers.
- `scripts/network-safety-hygiene.py` scans Rust source, scripts, and CI
  workflows for commands that would mutate system proxy, DNS, route, firewall,
  VPN, interfaces, or other network-service state.

If a test needs real WAN behavior, use a separate VM or machine supplied by the
user.

## Knowledge Harness

Use these files as the repo-local source of truth:

- `AGENTS.md`: short entry point for future coding agents.
- `STATUS.md`: current claim boundary and ready/not-ready summary.
- `docs/PLAN_POST_V1.md`: active milestones, gates, and sequencing.
- `ROADMAP.md`: concise public direction and version policy.
- `README.md`: user-facing capability summary and quick start.
- `CONFIG.md`: config schema examples and operational behavior.
- `SPEC.md`: v1 protocol behavior.
- `WIRE_FORMAT.md`: frame and handshake layout.
- `THREAT_MODEL.md`: assets, attacker model, and deferred security work.
- `SECURITY.md`: security posture and limitations.
- `TEST_PLAN.md`: current and planned validation coverage.
- `COMPATIBILITY.md`, `MIGRATIONS.md`, `RELEASE_CHECKLIST.md`: stabilization gates.
- `docs/TRANSPORT_ARCHITECTURE.md`: transport abstraction and scheduler plan.
- `docs/STEALTH_PRIORITY.md`: active-probing, TLS fingerprint, CDN-fronting,
  and shaping priority queue.
- `docs/H3_QUIC_PLAN.md`: H3/QUIC feature-gated implementation plan.
- `docs/AUTH_V2_SPEC.md`, `docs/CREDENTIAL_ROTATION.md`,
  `docs/SHAPING_ENGINE.md`, `docs/ECH_FEATURE_GATE.md`: focused privacy
  enhancement designs.
- `docs/SHAPE_LAB_BASELINE.md`: loopback-only shape diagnostics baseline.
- `docs/PRODUCT_TUN_ECOSYSTEM_PLAN.md`, `docs/TUN_MODE_DESIGN.md`,
  `docs/TUN_ENGINE_RESEARCH.md`, `docs/TUN_PACKET_ADAPTER_CONTRACT.md`,
  `docs/TUN_SYNTHETIC_TEST_MATRIX.md`,
  `docs/REFERENCE_CLIENT_SDK_BOUNDARY_REVIEW.md`, `docs/CONFIG_URI.md`,
  `docs/SDK_PLAN.md`, and `docs/GUI_TRAY_ARCHITECTURE.md`: platformization
  sequence, preparation, and historical baselines.
- `docs/CRYPTO_AGILITY.md`, `docs/HPKE_NOISE_EXPERIMENTS.md`,
  `docs/ML_KEM_HYBRID.md`, `docs/KEY_LIFECYCLE.md`: frozen crypto-agility
  designs.
- `docs/SPEC_FREEZE_PROCESS.md`, `docs/CONFORMANCE_SUITE.md`,
  `docs/GOVERNANCE.md`: conformance and long-term ecosystem references.
- `docs/EXPERIMENTAL_TRACKS.md`: status and guardrails for experimental work.
- Historical blocker and approval manifests are evidence indexes, not runtime
  proof by themselves. They are not part of the default local gate.

When behavior changes, update the file that would have prevented a future
agent from misunderstanding it.

## Evaluation Harness

The integration harness lives in `crates/maverick-tests/tests/support`. It owns:

- temporary TLS certificates and fallback content;
- loopback server/client startup;
- fake DNS, TCP echo, UDP echo, and hold-open services;
- tunnel attempt helpers for auth/fallback regression tests.

Add new protocol scenarios as tests in `crates/maverick-tests/tests/` and keep
shared setup in `support`. Avoid duplicating ad hoc fixture setup in every
test.

The local harness also validates non-network CLI workflows such as generated
config validation, migration dry-runs, and config URI export/import dry-runs
with secret-leak checks. Clipboard import coverage uses fake providers in unit
tests; the harness must not read or overwrite the developer machine's real OS
clipboard. Repo hygiene also scans logging macros for sensitive auth material.
The logging hygiene scanner has its own unit smoke under
`scripts/test-log-hygiene.py` so the deny patterns are checked before the
repository scan runs.

## Mechanical Checks

Before pushing, run:

```sh
./scripts/local-harness.sh
```

This is the default pre-commit gate. Public CI reuses it for code-affecting pull
requests, while a separate docs job avoids making prose-only changes compile the
workspace. `MAVERICK_SKIP_DOCS_HYGIENE=1` is reserved for that public CI job
because the same workflow has already run the standalone docs gate.

GitHub Actions may run the full public checks needed for the change:

- every pull request runs documentation hygiene and the stable required
  `public-pr-gate` result;
- Rust, config, conformance, script, workflow, and machine-metadata changes run
  the core local harness once;
- H3, ECH, shape-lab, and browser-TLS jobs run only when their relevant inputs
  change;
- one manual release-candidate job reruns the exact frozen source plus
  dependency and artifact checks on Ubuntu 24.04;
- there is no operating-system or Rust-version matrix without a matching
  support claim.

The manual release-candidate workflow must not be dispatched until the
coordinator approves the frozen inputs. See `docs/CI_AND_RELEASE_GATES.md` for
the exact public/private boundary.

The local harness also runs `maverick experimental list` and rejects any
experimental registry entry that becomes default-on without an explicit review.
It also validates claim hygiene and host network safety hygiene. Historical
blocker/approval JSON checks are metadata checks; run their dedicated scripts
only when editing those manifests.

For a broader local-only regression pass before larger roadmap updates, run:

```sh
./scripts/extended-harness.sh
```

The extended harness runs the default local harness, H3/ECH feature harnesses,
parser benchmark smoke, a temporary one-size shape-lab report, and a small
loopback benchmark smoke. It writes only temporary files.

To reproduce the default or extended harness on an explicitly supplied VM over
SSH, run:

```sh
./scripts/remote-vm-harness.sh <ssh-host> local
./scripts/remote-vm-harness.sh <ssh-host> extended
```

The remote harness syncs the workspace with `rsync`, excludes `.git`, `target`,
and `target-public-h3`, uses `CARGO_BUILD_JOBS=1` by default, and still runs
only the repository harnesses. It does not allocate public ports or mutate host
network settings.

For an explicitly approved public TCP smoke on a disposable or operator-owned
VM, run:

```sh
MAVERICK_PUBLIC_SMOKE_REMOTE_ADDR="203.0.113.10" \
MAVERICK_PUBLIC_SMOKE_SERVER_NAME="example.com" \
MAVERICK_PUBLIC_SMOKE_REMOTE_CERT="/etc/letsencrypt/live/example.com/fullchain.pem" \
MAVERICK_PUBLIC_SMOKE_REMOTE_KEY="/etc/letsencrypt/live/example.com/privkey.pem" \
MAVERICK_PUBLIC_SMOKE_CLIENT_HOST="<client-ssh-host>" \
./scripts/public-tcp-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It requires explicit
operator approval, an already-open remote TCP port, a valid remote certificate,
and a prepared remote repo. The script starts temporary remote Maverick and
loopback echo processes, runs one SOCKS5 TCP echo flow, and removes temporary
files on exit. It does not change local system proxy, DNS, route, firewall,
VPN, or other network-service settings.

When `MAVERICK_PUBLIC_SMOKE_CLIENT_HOST` is set, the client data plane also runs
on that SSH host and the local machine only orchestrates over SSH. This is the
preferred WAN mode when the local workstation uses always-on proxy or split
routing software, because local-origin tests only prove the workstation's
current effective egress path and may include proxy exits. Do not treat local
origin public tests as censorship-path evidence.

For a raw UDP reachability check between two explicitly approved SSH hosts, run:

```sh
MAVERICK_PUBLIC_UDP_REMOTE_ADDR="203.0.113.10" \
MAVERICK_PUBLIC_UDP_PORT=24443 \
./scripts/public-udp-probe.sh <server-ssh-host> <client-ssh-host>
```

This checks only one UDP datagram and reply between the two remote hosts. It is
useful before H3/WAN experiments, but it is not a Maverick protocol test. Cloud
inbound rules, guest OS policy, and the listening process are separate gates and
must all be checked for public-port work.

For an explicitly approved public H3/QUIC runtime smoke between two SSH hosts,
run:

```sh
MAVERICK_PUBLIC_H3_REMOTE_ADDR="203.0.113.10" \
MAVERICK_PUBLIC_H3_SERVER_NAME="example.com" \
MAVERICK_PUBLIC_H3_REMOTE_CERT="/etc/letsencrypt/live/example.com/fullchain.pem" \
MAVERICK_PUBLIC_H3_REMOTE_KEY="/etc/letsencrypt/live/example.com/privkey.pem" \
MAVERICK_PUBLIC_H3_PORT=24443 \
./scripts/public-h3-smoke.sh <server-ssh-host> <client-ssh-host>
```

This is not part of the default or extended harness. It builds a feature-gated
H3 binary in a separate remote target directory on both hosts, starts temporary
server/client/echo processes, runs one SOCKS5 TCP echo flow over H3/QUIC, and
verifies the server log contains an authenticated H3 session. It requires a
remote client host so the local workstation only orchestrates over SSH.

For an explicitly approved Linux VM TUN/route/namespaced-DNS apply and rollback
smoke, run:

```sh
MAVERICK_TUN_APPLY_APPROVED=1 \
./scripts/approved-vm-tun-apply-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It refuses localhost,
requires non-interactive sudo on the remote VM, creates a temporary TUN device,
adds only the documentation prefix `192.0.2.0/24`, writes DNS only inside a
temporary Linux network namespace, rolls everything back, and verifies no
device, route, namespace, or namespace DNS residue remains.

For an explicitly approved Linux VM TUN Phase B namespace runtime smoke, run:

```sh
MAVERICK_TUN_RUNTIME_APPROVED=1 \
./scripts/approved-vm-tun-runtime-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It refuses localhost,
requires non-interactive sudo on the remote VM, creates a temporary network
namespace, veth pair, namespace-local TUN device, namespace policy route, and
namespace-scoped DNS file, runs a namespace veth TCP echo and leak sentries,
rolls everything back, and verifies no namespace, link, or namespace DNS
residue remains. It also verifies the host default route and global
`/etc/resolv.conf` baseline are unchanged.

For an explicitly approved Linux VM TUN Phase C namespace policy smoke, run:

```sh
MAVERICK_TUN_POLICY_APPROVED=1 \
./scripts/approved-vm-tun-policy-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It refuses localhost,
requires non-interactive sudo on the remote VM, creates a temporary network
namespace, veth pair, namespace-local TUN device, namespace-scoped DNS file,
preserved control-plane route, and namespace-local default route to the TUN
device. It verifies default-route and DNS probes select the TUN path while the
control-plane route still reaches the host veth peer, then rolls everything
back and verifies no namespace, link, or namespace DNS residue remains. It also
verifies the host default route and global `/etc/resolv.conf` baseline are
unchanged.

For an explicitly approved Linux VM TUN service-manager lifecycle smoke, run:

```sh
MAVERICK_TUN_SERVICE_APPROVED=1 \
./scripts/approved-vm-tun-service-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It refuses localhost,
requires non-interactive sudo on the remote VM, starts transient systemd units
only, exercises privileged helper success and intentional-failure cleanup paths
with temporary namespaces/TUN devices, then verifies no namespace, link, unit,
or script residue remains. It does not install permanent services and verifies
the host default route and global `/etc/resolv.conf` baseline are unchanged.

For an explicitly approved Linux VM TUN leak/coexistence smoke, run:

```sh
MAVERICK_TUN_LEAK_APPROVED=1 \
./scripts/approved-vm-tun-leak-coexistence-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It refuses localhost,
requires non-interactive sudo on the remote VM, creates a temporary namespace,
veth pair, namespace-local TUN device, preserved control-plane route,
namespace-local default route, and namespace-scoped DNS file. It verifies public
and DNS route probes select the TUN path while control-plane echo traffic stays
on veth, rolls everything back, and verifies host listener, default-route, and
global-DNS baselines are unchanged.

For an explicitly approved Linux VM TUN full-helper integration smoke, run:

```sh
MAVERICK_TUN_FULL_HELPER_APPROVED=1 \
./scripts/approved-vm-tun-full-helper-smoke.sh <ssh-host>
```

This is not part of the default or extended harness. It refuses localhost,
requires the same approved SSH host boundary, chains the namespace runtime,
namespace policy, service-manager lifecycle, and leak/coexistence smokes, then
performs an independent final residue check. It is the current prototype's
privileged-helper integration gate; it does not install permanent services and
does not claim production-grade full-device TCP/IP relay behavior.

For benchmark baselines, run:

```sh
./scripts/benchmark-baseline.sh
./scripts/criterion-regression.sh smoke
```

For H3 feature-gate builds, run:

```sh
./scripts/h3-harness.sh
```

For ECH feature-gate builds, run:

```sh
./scripts/ech-harness.sh
```

This checks config/readiness gates and the tracked rustls client ECH API surface
without DNS, WAN, or host network changes.

For Noise feature-gate readiness checks, run:

```sh
./scripts/noise-harness.sh
```

This checks the `noise-experimental` feature build, canonical Maverick prologue
context metadata, Snow-backed deterministic Noise vectors, and the Noise
runtime approval manifest, including the feature-gated core Noise session
harness. It does not enable Noise as a product transport, run WAN tests, or
mutate host network settings.

For an explicitly approved Cloudflare-fronted Maverick runtime smoke, run:

```sh
MAVERICK_ECH_CF_RUNTIME_APPROVED=1 \
MAVERICK_ECH_CF_DOMAIN=REPLACE_WITH_ECH_TEST_HOSTNAME \
MAVERICK_ECH_CF_CLIENT_HOST=REPLACE_WITH_APPROVED_CLIENT_SSH_HOST \
  ./scripts/approved-vm-ech-cloudflare-fronted-runtime-smoke.sh REPLACE_WITH_APPROVED_ORIGIN_SSH_HOST
```

This is not part of the default or extended harness. It uses the approved VM as
the temporary Maverick origin, uses a separate approved SSH host for the client
data plane when configured by the script, and requires an operator-controlled
Cloudflare proxied test name. The smoke verifies ordinary Cloudflare origin
reachability and one authenticated SOCKS5 TCP echo flow over the explicit
Cloudflare-fronted WebSocket carrier. It does not prove native Maverick
server-side ECH, and it does not change local system proxy, DNS, route,
firewall, VPN, or other network-service settings.

For an explicitly approved Cloudflare edge-only ECH preflight, run:

```sh
MAVERICK_ECH_EDGE_PREFLIGHT_APPROVED=1 \
MAVERICK_ECH_EDGE_ALLOW_CUSTOM_DOMAIN=1 \
MAVERICK_ECH_EDGE_DOMAIN=REPLACE_WITH_ECH_TEST_HOSTNAME \
  ./scripts/approved-vm-ech-edge-preflight.sh REPLACE_WITH_APPROVED_CLIENT_SSH_HOST
```

This runs from the approved VM, queries HTTPS/SVCB records for the configured
test hostname, extracts the `ech` parameter, and requires a rustls TLS 1.3
client handshake to report `EchStatus::Accepted`. It validates controlled
Cloudflare edge ECH distribution only; it does not enable Maverick runtime ECH
or prove native Maverick server-side ECH support.

For loopback-only shape diagnostics, run:

```sh
./scripts/shape-lab.sh docs/SHAPE_LAB_BASELINE.md
```

Shape lab reports are engineering diagnostics only. They do not capture packets
and do not prove traffic-analysis resistance. The generated report compares an
unshaped auto baseline with stable, auto, and private bounded-shaping
scenarios.

For parser-vector conformance checks, run:

```sh
./scripts/conformance.sh
```

This also validates spec/wire frame type alignment, the pre-freeze vector
manifest, the current freeze-readiness blocker list, and the frozen-release
policy.

For optional parser fuzzing with `cargo-fuzz` installed, run targets from the
separate fuzz workspace:

```sh
./scripts/fuzz-smoke.sh
MAVERICK_RUN_CARGO_FUZZ=1 MAVERICK_FUZZ_RUNS=256 ./scripts/fuzz-smoke.sh
```

These targets are parser-only and require no network listeners.

## Planning Loop

For autonomous work, use this loop:

1. Read `AGENTS.md`, `TEST_PLAN.md`, and the files in the area being changed.
2. Pick one bounded tranche that can be verified locally.
3. Add or update harness coverage before broad refactors.
4. Run `./scripts/local-harness.sh`.
5. Commit and push only after checks pass.

Keep future tasks explicit in `TEST_PLAN.md`, `THREAT_MODEL.md`, or a nearby
doc instead of relying on chat history.
