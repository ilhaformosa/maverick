//! Boring client settings shared by H2 and the local H3 integration test.
//! Protocol versions, ALPN, and trust roots are selected by each transport.

use anyhow::{Context, Result};
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslContextBuilder, SslVerifyMode,
};

pub(crate) fn configure(builder: &mut SslContextBuilder) -> Result<()> {
    builder
        .set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
             ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
             ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:\
             AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
        )
        .context("set browser TLS cipher list")?;
    builder
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .context("set browser TLS supported groups")?;
    builder
        .set_sigalgs_list(
            "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
             ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
             rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
        )
        .context("set browser TLS signature algorithms")?;
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    builder
        .add_certificate_compression_algorithm(BrotliCertificateDecompressor)
        .context("enable browser TLS certificate compression")?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_verify_callback(SslVerifyMode::PEER, crate::tls_distrust::verify);
    Ok(())
}

struct BrotliCertificateDecompressor;

impl CertificateCompressor for BrotliCertificateDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc};

        // Certificate compression uses RFC 7932 Brotli, not the large-window
        // extension. An output limit alone does not bound the decoder's window.
        let mut state = BrotliState::new_strict(
            HeapAlloc::default(),
            HeapAlloc::default(),
            HeapAlloc::default(),
        );
        let (mut available_in, mut input_offset, mut total_out) = (input.len(), 0, 0);
        let mut buffer = [0; 4096];
        loop {
            let (mut available_out, mut output_offset) = (buffer.len(), 0);
            let result = BrotliDecompressStream(
                &mut available_in,
                &mut input_offset,
                input,
                &mut available_out,
                &mut output_offset,
                &mut buffer,
                &mut total_out,
                &mut state,
            );
            match result {
                BrotliResult::ResultSuccess if available_in == 0 => {
                    output.write_all(&buffer[..output_offset])?;
                    return Ok(());
                }
                BrotliResult::NeedsMoreOutput if output_offset > 0 => {
                    output.write_all(&buffer[..output_offset])?;
                }
                _ => return Err(std::io::ErrorKind::InvalidData.into()),
            }
        }
    }
}

#[cfg(test)]
mod certificate_compression_tests {
    use super::BrotliCertificateDecompressor;
    use boring::ssl::CertificateCompressor;
    use std::io::{ErrorKind, Write};

    fn compress(input: &[u8], window_bits: u32) -> Vec<u8> {
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 4, window_bits);
            writer.write_all(input).unwrap();
        }
        compressed
    }

    #[test]
    fn brotli_certificate_decompression_rejects_large_window() {
        // Includes upstream RUSTSEC-2026-0348 input [0x11, 0xd0]: empty
        // non-RFC streams exercise the extension without a large allocation.
        for window_bits in 10..=30 {
            let error = BrotliCertificateDecompressor
                .decompress(&[0x11, 0xc0 | window_bits], &mut Vec::new())
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }

    #[test]
    fn brotli_certificate_decompression_roundtrips_standard_streams() {
        for size in [0, 16, 4096, 4097, 16384] {
            let original: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            for window_bits in [22, 24] {
                let mut decoded = Vec::new();
                BrotliCertificateDecompressor
                    .decompress(&compress(&original, window_bits), &mut decoded)
                    .unwrap();
                assert_eq!(decoded, original);
            }
        }
    }

    #[test]
    fn brotli_certificate_decompression_rejects_truncated_and_trailing_data() {
        let compressed = compress(&vec![42; 8192], 22);
        let mut trailing = compressed.clone();
        trailing.push(0);
        let mut concatenated = compressed.clone();
        concatenated.extend_from_slice(&compressed);
        for invalid in [
            &compressed[..compressed.len() - 1],
            trailing.as_slice(),
            concatenated.as_slice(),
        ] {
            assert!(BrotliCertificateDecompressor
                .decompress(invalid, &mut Vec::new())
                .is_err());
        }
    }

    #[test]
    fn brotli_certificate_decompression_preserves_output_bound() {
        let compressed = compress(&vec![42; 8192], 22);
        let mut output = [0; 4096];
        let error = BrotliCertificateDecompressor
            .decompress(&compressed, &mut output.as_mut_slice())
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WriteZero);
    }
}
