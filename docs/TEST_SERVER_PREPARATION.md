# Test Server Preparation

This is Maverick's active, fail-closed host policy for separately authorized
Ubuntu test origins. It is not part of the wire protocol and it does not grant
authority to create, modify, reboot, or delete a server.

## Provisioning Address Gate

When Codex creates an already authorized Maverick test origin through a provider
API, it must inspect the public IPv4 address before DNS, certificates, or
deployment. If the first octet is `64`, it deletes that exact new resource by
provider ID and creates a replacement only within the same approved team,
region, specification, lifetime, and total-spend boundary. It must stop and ask
the owner if that boundary cannot produce a non-`64` address; it must not create
servers without limit.

This is an owner-selected test-environment exclusion, not evidence that all of
`64.0.0.0/8` is technically defective. It does not automatically apply when the
owner has said they are creating the replacement manually; that path follows
the owner's live instructions.

## Default OS Policy

- Use Ubuntu 26.04 LTS by default.
- Use Ubuntu 24.04 LTS only when 26.04 cannot perform the test, with an explicit
  fallback flag and a non-secret reason.
- Before Maverick is installed or started, refresh package metadata, complete a
  full package upgrade, and obey Ubuntu's reboot-required signal.
- Never hide held packages, approve package removals, run `autoremove`, or start
  Maverick before the post-reboot verification passes.

## Reference-Origin Reuse

A test origin may be reused as a fixed reference only while `STATUS.md` records
current authorization for that role. Its first from-scratch run may satisfy a
stage's fresh-origin gate when `STATUS.md` records that decision. Later reuse
holds origin-side variables constant; it is not a production deployment and
does not satisfy a later fresh-origin gate such as the Stable gate.

Before every authorized session, complete the normal package and
default-kernel update, obey any reboot requirement, and pass `verify` before
Maverick starts. Use a reviewed Maverick artifact and fresh test credentials.
Do not add unrelated workloads merely because the host is being retained. Do
not erase a healthy host between comparisons without a reproduced reason,
because doing so would also remove the stable baseline.

Retire the origin when its authorization expires, its ordinary-browsing
baseline or verifier fails, its state can no longer be accounted for,
compromise or credential exposure is suspected, or its routing or reputation
is no longer suitable for comparison. Creating a replacement always requires
the authority recorded in `STATUS.md`.

## Default Network Policy

Maverick test origins must use the stock Ubuntu kernel implementation named
`bbr`. The mainline implementation is commonly called BBRv1. The queueing
discipline must be either `fq` or `fq_codel`; both are equally supported and
neither is the project default. The gate preserves whichever of those two the
active interface already uses. If the active interface uses something else,
the gate uses an already configured approved sysctl default; if no approved
choice exists, it stops instead of silently choosing for the operator. This
replaces the earlier request for BBRv3: Maverick does not compile, install, or
maintain a custom kernel merely to obtain BBRv3.

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
upgrade with removals forbidden. The simulations and real upgrade explicitly
include Ubuntu phased updates so that the later “nothing pending” gate cannot
contradict APT's rollout selection. It simulates the upgrade again afterward;
any remaining installation, removal, kept-back package, or nonzero
not-upgraded count blocks the host.

“All updates” here means every package and default-kernel update offered by the
configured, authenticated APT sources. It does not update or make claims about
Snaps, containers, device firmware, manually installed software, or a
provider-managed layer. The script never runs `autoremove` and never reboots.

If Ubuntu requires a reboot, the command exits 20 before it writes the network
policy. Reboot manually, then run `prepare` again.

`net.core.default_qdisc` controls a default; it is not proof of what an
already-created interface is using. The gate therefore checks both that sysctl
and the qdisc on the first IPv4 default-route interface. If the configured
default is neither `fq` nor `fq_codel`, it stops without choosing one. If the
active interface already uses either approved qdisc, that active choice is
preserved and persisted; the script has no preference between the two. If the
active interface uses something else, `prepare` persists the existing approved
sysctl default through the effective systemd-networkd `.network` file's native
drop-in and exits 20 for one manual reboot. This is necessary because changing
the sysctl default alone does not replace a qdisc already attached by the
network renderer. If `verify` still finds an unsupported active qdisc
afterward, the host is not ready and Maverick must not start. The script does
not perform a live `tc` change, `networkctl reload`, or `networkctl
reconfigure`, and installs no helper or systemd unit. If the active qdisc
cannot be inspected reliably, `prepare` exits 24 and rolls back files created
by that run.

After the package and configuration safety gates pass, `prepare` atomically
installs these managed files:

```text
/etc/modules-load.d/99-maverick-test-network.conf
  tcp_bbr
  sch_fq or sch_fq_codel, matching the host's existing approved choice

/etc/sysctl.d/99-maverick-test-network.conf
  net.core.default_qdisc = fq or fq_codel, preserving that choice
  net.ipv4.tcp_congestion_control = bbr

/etc/systemd/network/<effective-file>.network.d/99-maverick-test-qdisc.conf
  [FairQueueing] or [FairQueueingControlledDelay]
  Parent=root
```

Existing unsupported sysctl values, relevant module blacklists or install
overrides, an unsafe networkd drop-in path, symbolic-link targets, or unexpected
content in Maverick's managed files stop the operation. The effective
`.network` filename is discovered read-only with `networkctl`; only a regular
file in a standard systemd-networkd configuration directory is accepted. The
drop-in under `/etc` remains persistent even when Netplan regenerates its main
file under `/run`. The conservative sysctl scan covers effective configuration
directories under `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, and `/lib`.
Every qdisc assignment it finds must be either `fq` or `fq_codel`; every
congestion-control assignment must be `bbr`. A later file or `/etc/sysctl.conf`
that would replace the qdisc selected at `prepare` time is rejected; an earlier
supported default may remain because Maverick's managed `99-` file supersedes
it. Managed parents and files must be root-owned, non-symbolic, and not
group- or world-writable. The script does not overwrite conflicting content. A
managed-file persistence failure or runtime-apply failure triggers rollback of
files created by that run and a best-effort restoration of the previous runtime
values.

`verify` checks the stock Ubuntu kernel and module packages, persisted files,
available and selected TCP congestion control, a runtime
`net.core.default_qdisc` of `fq` or `fq_codel`, and the qdisc on the first IPv4
default-route interface. It also confirms that the managed native drop-in still
belongs to the effective `.network` filename. A direct `fq` or `fq_codel` root
is accepted. A multiqueue (`mq`) root is accepted only when it has queue leaves
and every leaf uses the same approved qdisc. This does not verify IPv6-only or
non-default interfaces. Output deliberately omits interface names, addresses,
hostnames, regions, and provider details.

Exit code 22 means the stock Ubuntu BBR path is unavailable or its declared
metadata conflicts with the BBRv1 policy. It no longer means “wait for BBRv3.”

## Installation Integration

The [deployment runbook and service template](DEPLOYMENT.md) now cover manual
application installation and lifecycle. They are not a host provisioner. For
this specifically authorized test-origin policy, run `prepare`, honor exit 20
with the documented manual reboot, and require a successful `verify` before
starting Maverick. A reboot requested before network-policy persistence must
be followed by `prepare` again; one requested after qdisc persistence is followed
by `verify`. Other nonzero results stop installation/startup.

Package upgrades do not belong in a recurring systemd `ExecStartPre`. A future
unit may call a small read-only verifier there, but provisioning must remain a
separate, explicit operation.

## How the Three Modes Use It

The three Maverick modes are policy labels, not three different Linux network
stacks:

Legacy `stable`, `auto` and `private` labels do not choose the transport by
themselves. Omitted carrier settings retain H2/TCP; new direct generation uses
client `auto_h3`, server `dual_h2_h3` and explicit UDP policy. Fixed H2/H3 remain
available. `experimental_h3` stays retired. H3 uses QUIC/UDP and quiche's
userspace congestion control, not kernel TCP BBR. Automatic selection applies
only to new connections/sessions under the documented network/capability and
security rules; it does not score performance or migrate active sessions. See
[NATIVE_UDP_AND_SELECTION.md](NATIVE_UDP_AND_SELECTION.md).

The server-sent half of all three modes' server-to-target TCP connections uses
the server's TCP congestion-control default. UDP and DNS relay sockets do not
use TCP BBR, although their outgoing packets still pass through the server's
queueing layer; this is not H3 or native-Datagram evidence.

## Why This Is a Host Setting

BBR controls TCP sending and the qdisc controls a server's outgoing packet
queue. Putting their names in Maverick's client/server YAML would not configure
the Linux kernel and would create a false sense of safety. The operational
policy is therefore enforced by host preparation and verification.

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
