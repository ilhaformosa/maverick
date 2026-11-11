# Server deployment preparation

This is an operator runbook and a service template, not an automatic installer.
The source is experimental Beta; RC.2 binaries do not contain later protocol
changes. Field validation remains deferred. These instructions are for a later,
explicitly authorized owner-controlled Linux host, not the development Mac.

## Select and verify the build

Use one reviewed source revision for client, server and integration tests.
The RC.5 candidate archive includes H2 and H3, SOURCE.txt, VERSION.txt and
checksums. It is a candidate artifact, not an independently published Stable
release. To build the same feature set on supported Linux x86_64:

```sh
cargo build --locked --release -p maverick-cli --no-default-features --features experimental-h3
./target/release/maverick version
./target/release/maverick user-smoke
./target/release/maverick user-smoke --quiche-h3
```

Both smoke variants exercise TCP plus persistent UDP, authentication rejection,
port continuity and independent replies on loopback. Keep source identity,
features, digest and results with the binary. These do not validate deployment
certificates, a real intermediary or network. `build-pilot.sh`, native artifact,
SBOM and rollback gates verify the full candidate; immutable Beta/RC.2 archives
keep their older H2-only verification profile. Do not overwrite those releases.

## Prepare private configuration

Generate credentials/configuration in a private directory using one recipe:

| Purpose | Generator |
|---|---|
| Direct dual/auto, reliable-compatible UDP | `maverick gen-config` |
| Fixed H2 | `maverick gen-config --h2` |
| Protected H2 intermediary | `maverick gen-config --relay --origin-name origin.example.invalid --origin-cert origin.pem` (add `--origin-ca ca.pem` for private roots) |
| Explicit H3 TCP/native UDP | `maverick gen-config --quiche-h3` |
| Auto with native-required UDP | `maverick gen-config --udp-policy native_required` |

Replace template endpoints and paths. Deploy the certificate matching the
owner-verified origin pin; keep its private key solely at the origin. H3/dual
and protected intermediary H2 are separate configurations. The source does not
promise real-provider streaming compatibility. Deliver client credentials and
the origin pin through a trusted channel. Leave server egress restrictions in
place; the loopback allowance used by tests is not a deployment setting.

The service template uses this public layout, with actual values kept private:

```text
/opt/maverick/releases/<reviewed-build>/maverick
/opt/maverick/current -> releases/<reviewed-build>
/etc/maverick/server.yaml
/etc/maverick/certs/fullchain.pem
/etc/maverick/certs/privkey.pem
/etc/maverick/public/index.html
```

Create a dedicated unprivileged `maverick` system account. Keep installation
directories, executable, unit and `current` symlink root-owned. Keep
`/etc/maverick` root-owned and readable/traversable only by root and the service
group. The configuration must be owned by `maverick` and mode 0600; the CLI
rejects broader permissions. Give only that account read access to the private
key (for example owner `maverick`, mode 0400). Public certificate/static content
can be root-owned and readable by the service. Do not use loose-permission
overrides. Resolve relative YAML paths from `/etc/maverick`, or use absolute
paths within that directory. The template protects home directories and makes
the filesystem read-only for the service.

No host package, kernel, firewall, routing, DNS or proxy changes are performed
by Maverick or this template. If using the separately authorized Ubuntu test
origin policy, follow [test-server preparation](TEST_SERVER_PREPARATION.md)
first; provisioning stays separate from service startup. H2 uses TCP on the
configured listen port; H3 uses UDP; dual uses both on the same port. Any later
host/provider access-rule changes require their own authorized operator action.

## Install and operate the prepared unit

After the preceding private files/account/binary are ready on the authorized
host, install the reviewed [maverick.service](../deploy/maverick.service) at
`/etc/systemd/system/maverick.service`, then run:

```sh
sudo -u maverick /opt/maverick/current/maverick check-config --kind server -c /etc/maverick/server.yaml
sudo systemd-analyze verify /etc/systemd/system/maverick.service
sudo systemctl daemon-reload
sudo systemctl enable --now maverick.service
sudo systemctl status maverick.service
sudo journalctl -u maverick.service --since '5 minutes ago'
```

`check-config` checks syntax/policy, not certificate files. Actual server
startup validates the certificate/key before announcing listener readiness.
`Type=exec` confirms process execution, not successful proxy forwarding; verify
the expected Maverick listening message, and only perform a real client test
when field verification is authorized. Metrics should remain bound to loopback.
Do not paste private logs, endpoint details or configuration into public reports.

The unit grants only the low-port bind capability, uses `NoNewPrivileges`, and
lets systemd send SIGTERM on stop. The CLI also accepts SIGINT. These signals
use the same shutdown path as the embedded server handle: active transfers end,
pending setup is cancelled, H3 peers receive best-effort close, and listeners
are released. They do not drain every active application transfer to completion.
A forced kill or lost close packet can still require peer timeout detection.

```sh
sudo systemctl stop maverick.service
sudo systemctl restart maverick.service
```

There is no live configuration/certificate reload. For an upgrade, first
validate the new binary/config and preserve the previous binary and private
configuration as a matched pair. Stop the service, point the root-owned
`current` link at the reviewed new build, then start and verify it. Roll back
the matched binary/config pair if startup or later authorized use fails.
Older RC.2 does not understand the new protection/H3 settings; never weaken
the configuration to make an old binary appear compatible.

## Evidence boundary

CI parses the shipped unit with native `systemd-analyze verify` on Linux,
substituting only its test executable/working directory without installing or
starting a system service. Ordinary CLI loopback tests send SIGTERM/SIGINT,
verify successful process exit, active peer cleanup and same-port restart for
H2, H3 and dual listeners. This is not a real-host installation or a substitute
for the deferred field trial/rollback qualification.

Unit semantics follow the primary
[systemd service manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
and [execution manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
