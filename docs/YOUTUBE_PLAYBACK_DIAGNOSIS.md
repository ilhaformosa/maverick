# YouTube Playback Diagnosis

Status: privacy-safe field checklist for an unexplained `Video unavailable`
result. This document is a diagnostic aid, not proof of compatibility.

## The One-Change Rule

Think of this like finding which light switch controls one lamp: change only
one switch, then look again.

For every test:

1. Use the same public, non-age-restricted video.
2. Stay signed out of the video service.
3. Use the same Mac, client build, network, exit, carrier, and test period.
4. Keep the same browser and profile unless that test explicitly changes it.
5. Record only the small result categories listed below.

Call the video `Video A` in notes. Do not copy its full URL.

If any changed test plays for the first time, return to Test A immediately:

1. Restore the exact Test A setup and try `Video A` again.
2. If A now plays too, mark the comparison `temporary/inconclusive`.
3. If A still fails, restore the changed test and try it one more time.
4. Treat the changed result as stable only if it plays again.

This prevents a short-lived recovery from looking like a real fix.

## Tiny Glossary

- **SOCKS5 listener:** a local door through which the selected browser gives
  traffic to a proxy.
- **carrier:** the road that carries Maverick data between its client and
  server.
- **exit:** the last server that connects to the website. The website sees the
  exit network, not the Mac's home network.
- **origin:** the Maverick server behind a fronting provider.
- **provider-fronted:** the outer Maverick TLS connection ends at a provider
  such as Cloudflare, and a second outer connection goes to the origin.

On the provider-fronted path, Cloudflare opens the **outer Maverick TLS**
connection. The browser-to-YouTube HTTPS connection is a separate encrypted
connection carried inside Maverick. Provider fronting can still change routing,
timing, connection handling, or service policy, but it does not by itself
decrypt the inner YouTube HTTPS content.

## Privacy Rules

Never save, paste, commit, or share:

- a full media or player URL;
- cookies, authorization values, request headers, or response bodies;
- a HAR file;
- a private Maverick IP address or hostname, a full request hostname, an
  account name, a credential, or a certificate;
- screenshots that expose any of the above.

It is safe to recognize the public suffix `googlevideo.com` while Network
Monitor is open. Do not copy the complete host name shown before that suffix.

Safe notes look like:

```text
Test: E
Player request: 2xx
Media request: 403
Playback: Video unavailable
```

Use only these categories:

- request: `not seen`, `2xx/206`, `403`, `429`, `other 4xx`, `5xx`,
  `reset`, or `timeout`;
- playback: `plays`, `buffers`, or `Video unavailable`.

In child-simple words:

- `2xx/206`: the server said yes; `206` means it sent one piece of the video;
- `403`: the server saw the request but refused it;
- `429`: the server wants the client to slow down and try later;
- `reset`: the connection was cut off before it finished;
- `timeout`: the client waited too long without getting an answer.

## Before Starting

- A real Maverick server test must already be inside an owner-approved field
  test.
- Keep the proxy inside the selected Firefox profile or isolated Chrome
  instance. Do not change the Mac system proxy, DNS, VPN, route table, or
  firewall.
- A new server, a paid resource, a different exit, a DNS/provider change, or a
  direct-origin carrier comparison needs separate, explicit authorization.
- A temporary SSH SOCKS comparison also needs separate, explicit
  authorization. Existing SSH access is not permission to expose a direct
  origin connection or address to the access network.
- The person operating the server keeps all real endpoints and credentials
  private.

If no approved field environment exists, stop here. The browser-only procedure
does not authorize creating one.

## Test A: Current Firefox Profile

1. Start Maverick normally.
2. Confirm that Firefox alone uses its loopback SOCKS listener.
3. Open `Video A` and press Play once.
4. Record only `plays`, `buffers`, or `Video unavailable`.

This is the reference result. Do not change anything else yet.

## Test B: Firefox Troubleshoot Mode

1. In Firefox, open the menu.
2. Choose **Help**, then **Troubleshoot Mode**.
3. Choose **Restart**, then **Open**. Do not choose **Refresh Firefox**.
4. Recheck the Firefox-only SOCKS setting if Firefox did not retain it.
5. Test `Video A` once and record the result.
6. Quit Firefox to leave Troubleshoot Mode.

How to read it:

- If B works but A fails, an extension, theme, hardware acceleration, or
  another temporarily disabled Firefox feature is the leading cause.
- If A and B both fail, continue. This does not yet clear every saved Firefox
  preference or cookie.

If B works under the return-to-A rule, stop the carrier and exit comparisons.
Investigate the Firefox items disabled by Troubleshoot Mode first.

## Test C: Clean Firefox Profile

1. Enter `about:profiles` in Firefox.
2. Choose **Create a New Profile** and give it a neutral local name.
3. Launch that profile in a new browser, then close every other Firefox window
   and tab.
4. Keep only one tab for this test. Do not sign in to Firefox Sync or the video
   service. Do not install extensions.
5. Configure only this Firefox profile to use Maverick's loopback listener as
   SOCKS v5, with **Proxy DNS when using SOCKS v5** enabled.
6. Confirm one ordinary HTTPS control page loads.
7. Stop the Maverick client, open an uncached ordinary HTTPS page, and require
   a proxy-connection failure. If it loads, mark the comparison `invalid`.
8. Restart the same Maverick client and confirm the control page works again.
9. Test `Video A` once and record the result.

How to read it:

- If C works but A and B fail, saved cookies, site data, or a Firefox preference
  in the old profile is the leading cause.
- If C also fails, keep the clean profile for the remaining tests.

If C works under the return-to-A rule, stop. Do not continue to the carrier or
exit comparisons: the clean profile has already separated the problem from
Maverick's shared path.

Do not delete the old profile or its files as part of diagnosis.

## Test D: Isolated Chrome on the Same Maverick Path

This test changes only the browser family. Keep the Mac, network, exit,
Maverick build, carrier, loopback SOCKS5 listener, test period, and `Video A`
the same as Test C. Do not change the macOS system proxy and do not use Safari.

Quit every Chrome window first so an existing process cannot make the launch
ambiguous. From a Terminal opened by the owner on the test Mac, replace
`<SOCKS_PORT>` with the loopback port printed by Maverick and launch:

```sh
test_profile="$(mktemp -d)"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir="$test_profile" \
  --proxy-server="socks5://127.0.0.1:<SOCKS_PORT>" \
  --host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" \
  --disable-quic \
  --no-default-browser-check \
  --no-first-run
```

The command deliberately contains no `direct://` fallback. The QUIC flag is a
diagnostic constraint so this SOCKS5/TCP comparison has one clear path; it is
not a claimed fix for a known leak. Do not sign in to Chrome or the video
service, enable Sync, install extensions, or reuse a daily Chrome data
directory.

Before reading the video result:

1. Open `chrome://version` and confirm its **Command Line** includes the new
   data directory, SOCKS5 proxy, resolver rules, and QUIC-disable arguments.
   Do not screenshot or record the temporary profile path.
2. Confirm one ordinary HTTPS control page loads.
3. Stop the Maverick client, open an uncached ordinary HTTPS page, and require
   a proxy-connection failure. If it loads, mark the comparison `invalid` and
   close the test Chrome.
4. Restart the same Maverick client and confirm the control page works again.
5. Test `Video A` once and record only the playback category.

Quit the isolated Chrome instance after the comparison. The new temporary data
directory may then be removed by exact path; do not delete any daily Chrome
profile.

How to read it:

- Chrome plays while clean Firefox still fails: a browser-specific profile,
  player, or service interaction becomes the leading cause. The shared
  Maverick/provider path is not universally unable to carry the video.
- Both clean browsers fail: a Firefox-only explanation becomes less likely;
  continue with the privacy-safe request categories and later carrier tests.
- Chrome plays: return to clean Firefox Test C immediately. If C still fails,
  repeat Chrome once before treating the browser difference as stable.
- Both play: apply the return-to-A rule before calling the earlier result fixed.
- Chrome alone fails: verify the command-line and fail-closed gates before
  drawing any product conclusion.

## Test E: Record Only the Failure Category

Use the clean profile and Maverick path from Test C.

1. Press **Command-Option-E** to open Firefox Network Monitor.
2. Clear the request list.
3. Reload `Video A`, then press Play once.
4. Look for player requests and media requests. A media request commonly has a
   host name ending in `googlevideo.com`.
5. Write down only the request categories and the playback category.
6. Close Network Monitor without exporting a HAR.

The earlier observation of four aggregate target-connection failures does not
identify which website caused them. For the next single playback attempt, an
operator may record only the before and after totals for these four fixed
counters:

```text
target_resolution_timeouts
target_resolution_failures
target_connect_timeouts
target_connect_failures
```

Write down only each counter's change, such as `+0` or `+1`. Do not add a
destination, address, URL, header, or exact timestamp. A counter increasing
during the attempt is a time correlation, not proof that `Video A` caused it.

How to read it:

- `player 403/429` means the service rejected or rate-limited the player
  decision before useful media transfer.
- `player 2xx` plus `media 403/429` means the media edge rejected or
  rate-limited the stream request.
- `media reset/timeout` points toward the proxy, carrier, or target-connection
  path.
- `media not seen` means the player did not begin a media request; Firefox
  state, service policy, or the player response remains more likely.
- `media 2xx/206` followed by immediate failure needs a browser/player
  comparison before changing Maverick.

One or a few aggregate Maverick target-connection failures cannot be assigned
to this video. Even matching timing and category show correlation only, not
attribution. Do not add destination names to project metrics to try to turn
that correlation into attribution.

## Test F: Same Exit, Standard SSH SOCKS

This test separates “Maverick/provider path” from “the exit itself.” Run it only
after separate, explicit authorization for this exact comparison. A direct SSH
SOCKS connection exposes the origin connection and address to the access
network. Having an authorized server and working SSH access is not enough
authority.

After approval, the operator may create a temporary, loopback-only SSH SOCKS
listener, then point only the clean Firefox profile at that listener. Do not
publish the command, endpoint, user name, or port.

Keep `Video A`, the Firefox profile, the Mac, the network, and the server exit
unchanged. Change only Maverick SOCKS to SSH SOCKS.

Before reading the video result, pass this validity gate:

1. Both paths use SOCKS5.
2. Firefox's **Proxy DNS when using SOCKS v5** setting is identical on both.
3. The same ordinary HTTPS control page works on both.

If any check fails, mark the comparison `invalid` and stop. A broken control
page is not a YouTube-specific result.

How to read it:

- SSH SOCKS works and Maverick fails: investigate Maverick or its
  provider-fronted carrier.
- Both fail through the same exit: the exit IP, network owner, geolocation, or
  service policy is more likely than Maverick.
- Both work: repeat once before drawing a conclusion; the earlier result may
  have been temporary.

Stop the temporary SSH SOCKS listener after the comparison.

## Test G: Direct Carrier Versus Provider-Fronted Carrier

Run this only after explicit authorization. A direct carrier can expose the
origin address and may require a provider or server configuration change.

Use the same clean Firefox profile, `Video A`, server exit, and Maverick build.
Compare:

1. the approved provider-fronted carrier;
2. an approved direct Maverick carrier.

Apply the same SOCKS5, Proxy DNS, and ordinary HTTPS validity gate from Test F
to both carriers. If either side fails the gate, the comparison is invalid.

How to read it:

- Direct works and provider-fronted fails: provider-path compatibility is the
  leading cause.
- Both fail: the provider is not the sole cause.
- Both work: repeat once before changing code.

Restore the authorized baseline after the comparison. Do not change unrelated
DNS records, zone-wide TLS settings, or other provider settings.

Provider operations are API-first. The dedicated test zone keeps gRPC enabled,
and the dedicated hostname's hostname-only Full (strict) rule remains in place
between runs; restoring the baseline does not toggle or rebuild either setting.
When an authorized replacement exit is introduced, change only the dedicated
DNS target and issue a new short-lived Origin CA certificate from that node's
own private key and CSR. Remove the DNS target when no origin owns the released
address. Use browser control only for a required capability that has no
documented usable API.

## Test H: Same Maverick Path, Different Exit

Run this only after explicit authorization to create or use the second exit.
Keep the clean Firefox profile, `Video A`, Maverick build, and carrier the same.
Change only the exit.

Apply the same SOCKS5, Proxy DNS, and ordinary HTTPS validity gate from Test F
to both exits. If either side fails the gate, the comparison is invalid.

How to read it:

- Exit B works and Exit A fails: something about the exit environment is the
  leading cause. Possibilities include reputation, geolocation, ASN, service
  policy, routing or peering, host load, and host/network quality.
- Both exits fail in the same way: Firefox or the shared Maverick/carrier path
  remains more likely.

Do not record the real exit addresses. Call them `Exit A` and `Exit B`.

## Small Result Sheet

Copy only this table into private test notes:

| Test | One changed item | Player | Media | Playback |
| --- | --- | --- | --- | --- |
| A | none, reference | not measured | not measured | category |
| B | Troubleshoot Mode | not measured | not measured | category |
| C | clean profile | not measured | not measured | category |
| D | isolated Chrome | not measured | not measured | category |
| E | Network Monitor | category | category | category |
| F | SSH SOCKS | not measured | not measured | category |
| G | direct carrier | not measured | not measured | category |
| H | Exit B | not measured | not measured | category |

## Decision Point

Do not tune random Cloudflare, Firefox, or Maverick settings between tests.
Choose the smallest next fix only after one comparison separates two causes:

- A versus B/C separates Firefox local state;
- C versus D separates a clean Firefox result from an isolated Chrome result;
- E identifies player rejection, media rejection, or a network failure class;
- C versus F separates Maverick/provider behavior from the same exit;
- fronted versus direct separates the provider-fronted carrier;
- Exit A versus Exit B separates the wider exit environment.

A Mozilla report described the same visible symptom in Firefox Beta 143 on
Windows while the Firefox IP Protection Alpha experiment was active. Mozilla
moved the issue from the Firefox component to its proxy service. The public
Bugzilla record does not contain the final root cause. It is therefore a useful
analogy, not proof that Maverick has the same cause. The comparisons above are
needed before making that claim. It also does not prove that the video service
recognizes ordinary Firefox, Maverick, or every proxy or VPN in the same way.

## Official References

- [Firefox Troubleshoot Mode](https://support.mozilla.org/en-US/kb/diagnose-firefox-issues-using-troubleshoot-mode)
- [Firefox Profile Manager](https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-firefox-profiles)
- [Firefox Network Monitor](https://firefox-source-docs.mozilla.org/devtools-user/network_monitor/)
- [Chromium proxy behavior](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md)
- [Chrome command-line data directories](https://developer.chrome.com/docs/web-platform/chrome-flags/#set-the-user-data-directory)
- [Safari opens macOS Network proxy settings](https://support.apple.com/guide/safari/ibrw1053/mac)
- [Mozilla proxy-service comparison report](https://bugzilla.mozilla.org/show_bug.cgi?id=1986666)
