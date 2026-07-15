# Release Signing

This directory contains public verification material for Maverick release
artifacts. It must never contain private keys, private key passphrases, local
paths, hostnames, account names, or operator-only environment details.

## Current Signer

`allowed_signers` contains the public OpenSSH signer accepted for
`SHA256SUMS.sig` verification. The current signer identity is:

```text
maverick-release
```

Verification namespace:

```text
maverick-release
```

## Verify Stable Checksums

From inside an unpacked release artifact directory:

```sh
ssh-keygen -Y verify \
  -f /path/to/maverick/docs/release-signing/allowed_signers \
  -I maverick-release \
  -n maverick-release \
  -s SHA256SUMS.sig <SHA256SUMS
```

Then verify the checksums:

```sh
shasum -a 256 -c SHA256SUMS
```

Use `sha256sum -c SHA256SUMS` on Linux.

## Key Rotation

Release signing keys may be rotated. Append new public signer lines to
`allowed_signers` before publishing a release with a new private key.

Keep old public signer lines unless the old key was never used for any
published release. Old release signatures need the old public signer line for
future verification.

If a private key or its passphrase is lost, old release signatures remain
verifiable with the existing public signer line, but future releases must use a
new signing key.
