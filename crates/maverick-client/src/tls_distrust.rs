use boring::x509::{X509Ref, X509StoreContextRef, X509VerifyError};
use sha2::{Digest, Sha256};

// SHA-256 identifiers of the public keys rejected by rustls-webpki 0.103.16.
// The public DER fixtures and their ISC attribution are used only by tests.
const DISTRUSTED_SPKI_SHA256: &[[u8; 32]] = &[
    // EMDVTLSCAG3B
    [
        0xeb, 0xed, 0x64, 0x75, 0xc2, 0xc2, 0xd8, 0x0f, 0xcb, 0x19, 0x9f, 0x3f, 0xe8, 0xdd, 0x6e,
        0x6b, 0x3c, 0xe6, 0x0b, 0x77, 0xeb, 0x15, 0xd4, 0xe4, 0x2c, 0x3d, 0xec, 0x0c, 0x6f, 0x5b,
        0x51, 0x05,
    ],
    // EMDVTLSCAG3C
    [
        0x49, 0xdd, 0x35, 0x3d, 0xc2, 0xb9, 0x19, 0xa3, 0x77, 0x06, 0x45, 0x11, 0x7d, 0x0e, 0x60,
        0xc1, 0x61, 0x15, 0xe7, 0xd1, 0xbc, 0x25, 0x9e, 0xef, 0xe7, 0x34, 0xb0, 0x0e, 0xa4, 0x34,
        0xfe, 0x5f,
    ],
    // EMEVTLSCAG3B
    [
        0xe0, 0x25, 0x4c, 0x7f, 0xcd, 0xc2, 0x65, 0xe2, 0xf0, 0xf8, 0xa4, 0x28, 0xda, 0xbb, 0x75,
        0xab, 0x4a, 0xe0, 0x39, 0xb4, 0x87, 0x2d, 0x62, 0xf5, 0xee, 0x57, 0xf0, 0x87, 0x7d, 0x5a,
        0x8a, 0x41,
    ],
    // EMEVTLSCAG3C
    [
        0x5c, 0x06, 0x60, 0xa2, 0xb1, 0x64, 0x91, 0x0d, 0x8f, 0xf5, 0x89, 0xc1, 0x8e, 0x14, 0x55,
        0x2e, 0x9e, 0x0e, 0xc2, 0x37, 0xdc, 0xef, 0xe2, 0xcb, 0x73, 0x6d, 0x41, 0xa4, 0x81, 0x1f,
        0x81, 0xa0,
    ],
    // EMOVTLSCAG3B
    [
        0x43, 0xbf, 0xfa, 0x19, 0xd6, 0xef, 0x65, 0x14, 0x51, 0xf6, 0x84, 0x1e, 0x01, 0x99, 0x31,
        0xe9, 0x6f, 0x6f, 0x2e, 0xae, 0xff, 0x28, 0xab, 0x4b, 0x6f, 0x1c, 0xe4, 0x57, 0x6d, 0xe2,
        0x71, 0x7b,
    ],
    // EMOVTLSCAG3C
    [
        0x63, 0xec, 0xef, 0xee, 0x43, 0x1d, 0x49, 0x52, 0x3b, 0xc1, 0x13, 0x6c, 0x4e, 0x72, 0xd0,
        0x20, 0x6a, 0x47, 0x70, 0x86, 0xca, 0xf6, 0x06, 0xcd, 0x5c, 0xf0, 0x25, 0x68, 0x6c, 0x10,
        0x9c, 0xf8,
    ],
    // EMOVCSCAG3B
    [
        0xec, 0x4f, 0xfa, 0x1a, 0xd0, 0xac, 0x88, 0x08, 0x13, 0x14, 0xb7, 0xaa, 0xff, 0xef, 0x6a,
        0x91, 0xf9, 0x7c, 0xd5, 0x72, 0x91, 0xbb, 0x5b, 0xa6, 0x86, 0xc5, 0x41, 0x5f, 0x5e, 0xb4,
        0xf6, 0xb6,
    ],
    // EMOVCSCAG3C
    [
        0x92, 0xc0, 0x63, 0xd6, 0x7e, 0x8f, 0x14, 0xdb, 0x71, 0xd2, 0x88, 0xe1, 0x12, 0x66, 0xff,
        0xda, 0xf6, 0x9c, 0xbf, 0x11, 0x5f, 0x7b, 0xab, 0x14, 0xf3, 0xbc, 0x2f, 0x68, 0xd2, 0x5e,
        0x0e, 0x30,
    ],
];

#[cfg(test)]
const DISTRUSTED_SPKIS: &[&[u8]] = &[
    include_bytes!("tls-distrust/EMDVTLSCAG3B.spki.der"),
    include_bytes!("tls-distrust/EMDVTLSCAG3C.spki.der"),
    include_bytes!("tls-distrust/EMEVTLSCAG3B.spki.der"),
    include_bytes!("tls-distrust/EMEVTLSCAG3C.spki.der"),
    include_bytes!("tls-distrust/EMOVTLSCAG3B.spki.der"),
    include_bytes!("tls-distrust/EMOVTLSCAG3C.spki.der"),
    include_bytes!("tls-distrust/EMOVCSCAG3B.spki.der"),
    include_bytes!("tls-distrust/EMOVCSCAG3C.spki.der"),
];

fn certificate_is_allowed(cert: &X509Ref) -> bool {
    cert.public_key()
        .and_then(|key| key.public_key_to_der())
        .is_ok_and(|spki| {
            let digest: [u8; 32] = Sha256::digest(&spki).into();
            !DISTRUSTED_SPKI_SHA256.contains(&digest)
        })
}

pub(crate) fn verify(preverified: bool, context: &mut X509StoreContextRef) -> bool {
    // This callback only adds a rejection condition. It never converts an
    // existing trust, signature, validity, or hostname failure into success.
    if !preverified {
        return false;
    }
    let allowed = context
        .chain()
        .is_some_and(|chain| !chain.is_empty() && chain.iter().all(certificate_is_allowed));
    if !allowed {
        context.set_error(Err(X509VerifyError::CERT_REJECTED));
    }
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::asn1::Asn1Time;
    use boring::bn::BigNum;
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::{HasPublic, PKey, PKeyRef, Private};
    use boring::stack::Stack;
    use boring::x509::extension::{BasicConstraints, KeyUsage};
    use boring::x509::store::X509StoreBuilder;
    use boring::x509::{X509NameBuilder, X509StoreContext, X509};

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn certificate<T: HasPublic>(
        subject: &str,
        public_key: &PKeyRef<T>,
        issuer: Option<&X509Ref>,
        signer: &PKeyRef<Private>,
        ca: bool,
    ) -> X509 {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", subject).unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(
            &BigNum::from_u32(if ca { 1 } else { 2 })
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(issuer.map_or(&*name, X509Ref::subject_name))
            .unwrap();
        cert.set_pubkey(public_key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let mut constraints = BasicConstraints::new();
        constraints.critical();
        if ca {
            constraints.ca();
        }
        cert.append_extension(&constraints.build().unwrap())
            .unwrap();
        let mut usage = KeyUsage::new();
        usage.digital_signature();
        if ca {
            usage.key_cert_sign();
        }
        cert.append_extension(&usage.build().unwrap()).unwrap();
        cert.sign(signer, MessageDigest::sha256()).unwrap();
        cert.build()
    }

    fn check(root: &X509, leaf: &X509, extra: Option<X509>) -> (bool, bool) {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(root.clone()).unwrap();
        let store = store.build();
        let mut chain = Stack::new().unwrap();
        if let Some(cert) = extra {
            chain.push(cert).unwrap();
        }
        X509StoreContext::new()
            .unwrap()
            .init(&store, leaf, &chain, |context| {
                let preverified = context.verify_cert()?;
                let allowed = verify(preverified, context);
                assert!(
                    !verify(false, context),
                    "must preserve existing verification failure"
                );
                Ok((preverified, allowed))
            })
            .unwrap()
    }

    #[test]
    fn browser_trust_rejects_every_known_distrusted_public_key() {
        let root_key = key();
        let root = certificate("Test Root", &root_key, None, &root_key, true);
        for spki in DISTRUSTED_SPKIS {
            let compromised_key = PKey::public_key_from_der(spki).unwrap();
            assert_eq!(compromised_key.public_key_to_der().unwrap(), *spki);
            let leaf = certificate(
                "test.invalid",
                &compromised_key,
                Some(&root),
                &root_key,
                false,
            );
            // Normal CA validation accepts this signed test certificate. The
            // additional policy rejects its known compromised public key.
            assert_eq!(check(&root, &leaf, None), (true, false));
        }
    }

    #[test]
    fn browser_trust_rejects_a_directly_trusted_distrusted_key() {
        let signer = key();
        let compromised_key = PKey::public_key_from_der(DISTRUSTED_SPKIS[0]).unwrap();
        let trusted = certificate(
            "Explicit Test Anchor",
            &compromised_key,
            None,
            &signer,
            true,
        );
        assert_eq!(check(&trusted, &trusted, None), (true, false));
    }

    #[test]
    fn browser_trust_preserves_valid_chain_and_ignores_unused_certificates() {
        let root_key = key();
        let root = certificate("Test Root", &root_key, None, &root_key, true);
        let leaf = certificate("test.invalid", &key(), Some(&root), &root_key, false);
        assert_eq!(check(&root, &leaf, None), (true, true));
        let compromised_key = PKey::public_key_from_der(DISTRUSTED_SPKIS[0]).unwrap();
        let unused = certificate(
            "Unused Certificate",
            &compromised_key,
            Some(&root),
            &root_key,
            false,
        );
        assert_eq!(check(&root, &leaf, Some(unused)), (true, true));
    }
}
