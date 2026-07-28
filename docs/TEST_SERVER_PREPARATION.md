# Test Server Preparation

This is Maverick's active, fail-closed host policy for separately authorized
Ubuntu test origins. It is not part of the wire protocol and it does not grant
authority to create, modify, reboot, or delete a server.

## Default OS Policy

- Use Ubuntu 26.04 LTS by default.
- Use Ubuntu 24.04 LTS only when 26.04 cannot perform the test, with an explicit
  fallback flag and a non-secret reason.
- Before Maverick is installed or started, refresh package metadata, complete a
  full package upgrade, and obey Ubuntu's reboot-required signal.
- Never hide held packages, approve package removals, run `autoremove`, or start
  Maverick before the post-reboot verification passes.

## Default Network Policy

Maverick test origins use the stock Ubuntu kernel implementation named `bbr`
with the `fq` queueing discipline. The mainline implementation is commonly
called BBRv1. This replaces the earlier request for BBRv3: Maverick does not
compile, install, or maintain a custom kernel merely to obtain BBRv3.

The gate accepts only Ubuntu's `generic` or `virtual` default-kernel tracks. It
checks the running kernel's meta-package and module-owning package with
`dpkg-query` and `apt-cache`, requires each installed version to equal its APT
candidate, and compares the kernel image and `tcp_bbr` module with their owning
packages' checksum manifests. A custom flavour, unowned module, changed package
file, non-Ubuntu package candidate, stale kernel package, or meta-package that
does not select the running image is rejected without printing identifying host
details.

Mainline `tcp_bbr` normally has no numeric module-version field, so the gate
does not pretend that `version=1` is required proof. Missing version metadata
is accepted after the stock-package checks. An explicit `1` is also accepted;
an explicitly declared different version is rejected so the host cannot
silently move away from the requested BBRv1 baseline.

These checks establish current Ubuntu package provenance, local
package-checksum agreement, successful BBR loading, and the requested runtime
settings. They do not independently inspect every line of the running
algorithm and must not be described as a cryptographic or formal proof of BBRv1
semantics.

## Commands

On the authorized test server, from a reviewed checkout:

```sh
sudo ./scripts/prepare-test-server.sh preflight
sudo ./scripts/prepare-test-server.sh prepare
sudo ./scripts/prepare-test-server.sh verify
```

For an explicitly approved Ubuntu 24.04 fallback, add both options to every
command:

```sh
--allow-24.04-fallback --fallback-reason "non-secret reason"
```

`preflight` is read-only, but it is run with `sudo` so it can verify protected
Ubuntu kernel-package files under `/boot`. It evaluates the current package
index; because it runs before any refresh, a stale cache may block it.
`prepare` performs the authoritative refresh with APT's any-fetch-error mode,
simulates a full upgrade, blocks held packages or removals, and then runs a full
upgrade with removals forbidden. It simulates the upgrade again afterward; any
remaining installation, removal, kept-back package, or nonzero not-upgraded
count blocks the host.

“All updates” here means every package and default-kernel update offered by the
configured, authenticated APT sources. It does not update or make claims about
Snaps, containers, device firmware, manually installed software, or a
provider-managed layer. The script never runs `autoremove` and never reboots.

If Ubuntu requires a reboot, the command exits 20 before it writes the network
policy. Reboot manually, then run `prepare` again. If applying the persistent
policy leaves an already-running interface on an older qdisc, it also exits 20
instead of using an online `tc qdisc replace`; reboot manually and run `verify`.

After the package and configuration safety gates pass, `prepare` atomically
installs these managed files:

```text
/etc/modules-load.d/99-maverick-test-network.conf
  tcp_bbr
  sch_fq

/etc/sysctl.d/99-maverick-test-network.conf
  net.core.default_qdisc = fq
  net.ipv4.tcp_congestion_control = bbr
```

Existing conflicting sysctl values, module blacklists, install overrides,
symbolic-link targets, or unexpected content in Maverick's managed files stop
the operation. The conservative scan covers effective configuration directories
under `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, and `/lib`; it rejects a
conflict even when filename precedence might mask it. Managed parents and files
must be root-owned, non-symbolic, and not group- or world-writable. The script
does not overwrite conflicting content. A two-file persistence failure or
runtime-apply failure triggers rollback of files created by that run and a
best-effort restoration of the previous runtime values.

`verify` checks the stock Ubuntu kernel and module packages, persisted files,
available and selected TCP congestion control, runtime
`net.core.default_qdisc=fq`, and the qdisc on the first IPv4 default-route
interface. A direct `fq` root is accepted. A multiqueue (`mq`) root is accepted
only when all detected queue leaves use `fq`. This does not verify IPv6-only or
non-default interfaces. Output deliberately omits interface names, addresses,
hostnames, regions, and provider details.

Exit code 22 means the stock Ubuntu BBR path is unavailable or its declared
metadata conflicts with the BBRv1 policy. It no longer means “wait for BBRv3.”

## Installation Integration

There is not yet a complete server installer, so the repository must not claim
that an ordinary Maverick installation already prepares the host
automatically. A future installation workflow can safely use this existing
gate:

1. Run `prepare`.
2. On exit 20, ask the operator to reboot and then run it again.
3. On any other nonzero exit, stop without starting Maverick.
4. Run `verify`.
5. Only after exit 0, install and start the Maverick service.

Package upgrades do not belong in a recurring systemd `ExecStartPre`. A future
unit may call a small read-only verifier there, but provisioning must remain a
separate, explicit operation.

## How the Three Modes Use It

The three Maverick modes are policy labels, not three different Linux network
stacks:

- `stable` always uses H2/TCP as its outer carrier, so the server-sent half uses
  BBRv1 and `fq`.
- `auto` defaults to H2/TCP, whose server-sent half uses the same host policy.
- `private` also defaults to H2/TCP and uses the same server-sent policy while
  applying stricter privacy rules.

The exception is explicitly enabled experimental H3/QUIC in `auto` or
`private`. QUIC uses UDP and its own userspace congestion controller, so Linux
TCP BBR does not control that carrier. `fq` can still queue packets leaving the
server. H3 failure falls back to H2, which uses the normal TCP policy.

The server-sent half of all three modes' server-to-target TCP connections uses
the server's TCP congestion-control default. UDP and DNS relay sockets do not
use TCP BBR, although their outgoing packets still pass through the server's
queueing layer.

## Why This Is a Host Setting

BBR controls TCP sending and `fq` controls a server's outgoing packet queue.
Putting their names in Maverick's client/server YAML would not configure the
Linux kernel and would create a false sense of safety. The operational default
is therefore enforced by host preparation and verification.

Congestion control belongs to the machine sending a packet. Server-side BBR
cannot make a Mac, a provider edge, or a remote website use BBR. On a
provider-fronted H2 path, the origin server setting covers the origin-to-provider
sending direction and the server-sent half of its TCP connections to targets.
The provider chooses its edge-to-client sending behavior, and the client
chooses its client-to-provider sending behavior.

Hysteria 2 is useful as a design comparison, but not as a kernel recipe. Its
BBR option is a userspace controller for QUIC. Maverick borrows the idea of an
explicit and verifiable local policy, while configuring native Linux TCP BBR at
the server layer.

Run the isolated fake-host tests on a development machine:

```sh
./scripts/test-prepare-test-server.sh
```

The tests never change the development machine's packages, sysctls, modules,
routes, interfaces, or qdiscs.
