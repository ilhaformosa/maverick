# Server deployment preparation

This runbook covers the Maverick 1.2.1 Linux server. The maintainer deferred
field validation for this release. Deployment requires a separately authorized
environment.

## Select and verify the build

Download the archive, checksum and matching `.cdx.json` software bill of
materials from the entry tagged `v1.2.1` on [GitHub Releases](https://github.com/ilhaformosa/maverick/releases).
Select `aarch64-apple-darwin` for Apple Silicon macOS or
`x86_64-unknown-linux-gnu` for Linux x86_64. The `pilot` segment in the
filename is retained for compatibility.

For example, on Linux run the following in the download directory. Extract
into an empty directory after the first check succeeds.

```sh
sha256sum -c maverick-1.2.1-pilot-x86_64-unknown-linux-gnu.tar.gz.sha256 &&
mkdir maverick-1.2.1 &&
tar -xzf maverick-1.2.1-pilot-x86_64-unknown-linux-gnu.tar.gz -C maverick-1.2.1 &&
cd maverick-1.2.1/maverick-pilot &&
sha256sum -c SHA256SUMS
```

On macOS use the Apple Silicon filename and `shasum -a 256 -c` for both checks.
In `SOURCE.txt`, check the target and version (`1.2.1`). Compare the full
`git_revision` to the output of `git rev-parse 'v1.2.1^{commit}'` in a source
checkout containing the release tag. Use that commit for SDK clients.

For a local source-build check on Linux x86_64, run:

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
SBOM and rollback gates check the release build; immutable Beta/RC.2 archives
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
For a manual CLI upgrade or rollback on macOS, stop the process and copy the
verified executable to a fresh file in the installation directory. Then
rename it over the live path (for example, `mv -f maverick.incoming maverick`).
Overwriting a previously executed file in place can cause macOS to terminate
the replacement during code-signature verification. [Apple’s guidance on updating signed executables](https://developer.apple.com/documentation/security/updating-mac-software).

Older RC.2 does not understand the new protection/H3 settings; never weaken
the configuration to make an old binary appear compatible.

### Rotate the origin certificate for a protected H2 intermediary

The client pins the SHA-256 digest of the complete origin leaf certificate.
A renewed leaf normally has a different pin even if its public key is reused.
The procedure below assumes the same origin hostname and trusted CA. The
outer endpoint and its trust settings stay fixed throughout.

1. While the original pair works, save the origin certificate chain, its
   matching private key, and the working client and server YAML as a set.
   Preserve the private file permissions. Keep the key and its backup at the
   origin. Verify a fresh TCP transfer and independent reliable UDP replies.
2. Obtain the replacement leaf through the owner's trusted channel. Verify
   its hostname, certificate chain and matching key. Run
   `maverick pin-cert --cert replacement-chain.pem` on the verified public
   file, with the leaf first. Stage the new client YAML by changing only
   `advanced.end_to_end.cert_pin`. The outer `server.cert_pin` identifies a
   different TLS endpoint. Run `check-config` on the staged files.
3. Coordinate the restart. Stop the origin, install the replacement chain
   and key together, and start it on the original listener. Restart clients
   with the staged YAML to force fresh handshakes. Test TCP bytes in both
   directions and independent UDP replies through the same intermediary.
   In a controlled rehearsal, also try one client with the old pin before
   applying the new one. Its opens must fail before the target is reached.
4. To roll back a routine renewal while the original identity is still valid
   and trusted, stop the service, restore the backed-up chain, key and server
   YAML, then restart it. Restore the matching client YAML and restart the
   client. Recheck the restored files, TCP contents and UDP replies.

Run the [regression](../crates/maverick-tests/tests/support/origin_rotation.rs)
locally with `cargo test --locked -p maverick-tests --test end_to_end protected_h2_origin_certificate_rotation_and_rollback`.
The coordinated restart interrupts service until clients and the origin
have matching credentials again.

## Evidence boundary

The [field acceptance plan](../ROADMAP.md#proposed-field-acceptance--discussion-only)
lists the test client, evidence of the actual H2/H3 session and pass criteria
for direct H2, direct H3, automatic selection and the protected H2 intermediary.

CI parses the shipped unit with native `systemd-analyze verify` on Linux,
substituting only its test executable/working directory without installing or
starting a system service. Ordinary CLI loopback tests send SIGTERM/SIGINT,
verify successful process exit, active peer cleanup and same-port restart for
H2, H3 and dual listeners. This is not a real-host installation or a substitute
for the deferred field trial/rollback qualification.

Unit semantics follow the primary
[systemd service manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
and [execution manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
