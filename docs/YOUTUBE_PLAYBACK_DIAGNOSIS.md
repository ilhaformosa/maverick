# YouTube Playback Diagnosis

Status: privacy-safe field checklist for an unexplained `Video unavailable`
result. This document is a diagnostic aid, not proof of compatibility.

## The One-Change Rule

Think of this like finding which light switch controls one lamp: change only
one switch, then look again.

For every test:

1. Use the same public, non-age-restricted video.
2. Stay signed out of the video service.
3. Use the same Mac, Firefox version, client build, network, and test period.
4. Change only the item named by that test.
5. Record only the small result categories listed below.

Call the video `Video A` in notes. Do not copy its full URL.

If any changed test plays for the first time, return to Test A immediately:

1. Restore the exact Test A setup and try `Video A` again.
2. If A now plays too, mark the comparison `temporary/inconclusive`.
3. If A still fails, restore the changed test and try it one more time.
4. Treat the changed result as stable only if it plays again.

This prevents a short-lived recovery from looking like a real fix.

## Tiny Glossary

- **SOCKS5 listener:** a local door through which Firefox gives traffic to a
  proxy.
- **carrier:** the road that carries Maverick data between its client and
  server.
- **exit:** the last server that connects to the website. The website sees the
  exit network, not the Mac's home network.
- **origin:** the Maverick server behind a fronting provider.
- **provider-fronted:** the outer Maverick TLS connection ends at a provider
  such as Cloudflare, and a second outer connection goes to the origin.

On the provider-fronted path, Cloudflare opens the **outer Maverick TLS**
connection. The Firefox-to-YouTube HTTPS connection is a separate encrypted
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
Test: D
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
- Keep the proxy inside Firefox. Do not change the Mac system proxy, DNS, VPN,
  route table, or firewall.
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
5. Configure only this Firefox profile to use Maverick's loopback SOCKS
   listener.
6. Test `Video A` once and record the result.

How to read it:

- If C works but A and B fail, saved cookies, site data, or a Firefox preference
  in the old profile is the leading cause.
- If C also fails, keep the clean profile for the remaining tests.

If C works under the return-to-A rule, stop. Do not continue to the carrier or
exit comparisons: the clean profile has already separated the problem from
Maverick's shared path.

Do not delete the old profile or its files as part of diagnosis.

## Test D: Record Only the Failure Category

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

## Test E: Same Exit, Standard SSH SOCKS

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

## Test F: Direct Carrier Versus Provider-Fronted Carrier

Run this only after explicit authorization. A direct carrier can expose the
origin address and may require a provider or server configuration change.

Use the same clean Firefox profile, `Video A`, server exit, and Maverick build.
Compare:

1. the approved provider-fronted carrier;
2. an approved direct Maverick carrier.

Apply the same SOCKS5, Proxy DNS, and ordinary HTTPS validity gate from Test E
to both carriers. If either side fails the gate, the comparison is invalid.

How to read it:

- Direct works and provider-fronted fails: provider-path compatibility is the
  leading cause.
- Both fail: the provider is not the sole cause.
- Both work: repeat once before changing code.

Restore the authorized baseline after the comparison. Do not change unrelated
DNS records, zone-wide TLS settings, or other provider settings.

## Test G: Same Maverick Path, Different Exit

Run this only after explicit authorization to create or use the second exit.
Keep the clean Firefox profile, `Video A`, Maverick build, and carrier the same.
Change only the exit.

Apply the same SOCKS5, Proxy DNS, and ordinary HTTPS validity gate from Test E
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
| D | Network Monitor | category | category | category |
| E | SSH SOCKS | not measured | not measured | category |
| F | direct carrier | not measured | not measured | category |
| G | Exit B | not measured | not measured | category |

## Decision Point

Do not tune random Cloudflare, Firefox, or Maverick settings between tests.
Choose the smallest next fix only after one comparison separates two causes:

- A versus B/C separates Firefox local state;
- D identifies player rejection, media rejection, or a network failure class;
- C versus E separates Maverick/provider behavior from the same exit;
- fronted versus direct separates the provider-fronted carrier;
- Exit A versus Exit B separates the wider exit environment.

A Mozilla report described the same visible symptom in Firefox Beta 143 on
Windows while the Firefox IP Protection Alpha experiment was active. Mozilla
moved the issue from the Firefox component to its proxy service. The public
Bugzilla record does not contain the final root cause. It is therefore a useful
analogy, not proof that Maverick has the same cause. The comparisons above are
needed before making that claim.

## Official References

- [Firefox Troubleshoot Mode](https://support.mozilla.org/en-US/kb/diagnose-firefox-issues-using-troubleshoot-mode)
- [Firefox Profile Manager](https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-firefox-profiles)
- [Firefox Network Monitor](https://firefox-source-docs.mozilla.org/devtools-user/network_monitor/)
- [Mozilla proxy-service comparison report](https://bugzilla.mozilla.org/show_bug.cgi?id=1986666)
