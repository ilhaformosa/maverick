# Distrusted public keys

These eight public SubjectPublicKeyInfo values come from rustls-webpki
0.103.16, `src/data/distrusted`, at upstream revision
`8ecdcc76f56b68fda67a6adf7976f5eed5006a4c`. They are the keys rejected for
RUSTSEC-2026-0382 / CVE-2026-111943. The upstream ISC license is retained here.

Upstream stores the 118-byte contents of each ASN.1 SubjectPublicKeyInfo
SEQUENCE. These copies add its outer DER SEQUENCE tag and length (`30 76`)
so they match BoringSSL's canonical `public_key_to_der()` output. No public-key
contents were changed. These files contain no private keys or credentials.

The application compares SHA-256 public-key identifiers across the verified
certificate chain, including a trusted anchor and the leaf. The DER copies
are test fixtures; production binaries contain only the computed identifiers. This supplements platform/custom CA validation without
replacing its trust store or bypassing any existing validation failure.

[Upstream fix](https://github.com/rustls/webpki/pull/546)
