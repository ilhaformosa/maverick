use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
#[cfg(feature = "browser-tls")]
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode,
    SslVersion,
};
use bytes::Bytes;
use h2::client::SendRequest;
use maverick_core::auth::{TlsChannelBinding, TLS_CHANNEL_BINDING_EXPORTER_LABEL};
use maverick_core::config::TlsFingerprintMode;
use maverick_core::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::transport::H2TunnelRequestSender;

pub(crate) struct H2Connection {
    pub transport: H2TunnelRequestSender,
    pub connection_closed: watch::Receiver<bool>,
}

pub async fn connect(config: &ClientConfig) -> Result<H2TunnelRequestSender> {
    Ok(connect_with_status(config).await?.transport)
}

pub(crate) async fn connect_with_status(config: &ClientConfig) -> Result<H2Connection> {
    timeout(
        Duration::from_millis(config.advanced.connect_timeout_ms),
        connect_inner(config),
    )
    .await
    .context("Maverick server connection timed out")?
}

async fn connect_inner(config: &ClientConfig) -> Result<H2Connection> {
    match config.advanced.stealth.tls_fingerprint {
        TlsFingerprintMode::RustlsDefault => connect_rustls_inner(config).await,
        TlsFingerprintMode::BrowserMimic => connect_browser_mimic_inner(config).await,
    }
}

async fn connect_rustls_inner(config: &ClientConfig) -> Result<H2Connection> {
    let tcp = TcpStream::connect(&config.server.address)
        .await
        .with_context(|| format!("connect {}", config.server.address))?;
    let mut tls_config = rustls_client_config(config)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name =
        ServerName::try_from(config.server.server_name.clone()).context("invalid server_name")?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;
    let channel_binding =
        rustls_client_channel_binding(tls.get_ref().1, end_to_end_channel_binding_enabled(config))?;
    let (sender, connection_closed) =
        finish_h2_handshake(tls, H2FingerprintProfile::MaverickDefault).await?;
    Ok(H2Connection {
        transport: H2TunnelRequestSender {
            sender,
            channel_binding,
        },
        connection_closed,
    })
}

#[cfg(not(feature = "browser-tls"))]
async fn connect_browser_mimic_inner(_config: &ClientConfig) -> Result<H2Connection> {
    anyhow::bail!("advanced.stealth.tls_fingerprint=browser_mimic requires the browser-tls feature")
}

#[cfg(feature = "browser-tls")]
async fn connect_browser_mimic_inner(config: &ClientConfig) -> Result<H2Connection> {
    let tcp = TcpStream::connect(&config.server.address)
        .await
        .with_context(|| format!("connect {}", config.server.address))?;
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("build browser TLS connector")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .context("set browser TLS minimum version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("set browser TLS maximum version")?;
    builder
        .set_alpn_protos(b"\x02h2\x08http/1.1")
        .context("set browser TLS ALPN")?;
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
    builder.set_verify(SslVerifyMode::PEER);
    if let Some(path) = &config.server.ca_cert {
        builder
            .set_ca_file(path)
            .with_context(|| format!("open CA cert {}", path.display()))?;
    } else {
        builder
            .set_default_verify_paths()
            .context("load platform default CA roots")?;
    }
    let connector = builder.build();
    let connect_config = connector
        .configure()
        .context("configure browser TLS connector")?;
    connect_config.set_enable_ech_grease(true);
    let tls = tokio_boring::connect(connect_config, &config.server.server_name, tcp)
        .await
        .context("browser TLS handshake failed")?;
    if let Some(pin) = &config.server.cert_pin {
        let expected_sha256 = parse_cert_pin(pin)?;
        let cert = tls
            .ssl()
            .peer_certificate()
            .context("browser TLS peer certificate missing")?;
        let cert_der = cert.to_der().context("encode browser TLS peer cert")?;
        let digest = Sha256::digest(&cert_der);
        if !bool::from(digest.as_slice().ct_eq(&expected_sha256)) {
            anyhow::bail!("browser TLS server certificate pin mismatch");
        }
    }
    let channel_binding =
        boring_client_channel_binding(tls.ssl(), end_to_end_channel_binding_enabled(config))?;
    let (sender, connection_closed) =
        finish_h2_handshake(tls, H2FingerprintProfile::ChromeReference).await?;
    Ok(H2Connection {
        transport: H2TunnelRequestSender {
            sender,
            channel_binding,
        },
        connection_closed,
    })
}

#[cfg(feature = "browser-tls")]
struct BrotliCertificateDecompressor;

#[cfg(feature = "browser-tls")]
impl CertificateCompressor for BrotliCertificateDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)
    }
}

#[cfg(feature = "browser-tls")]
fn boring_client_channel_binding(
    connection: &boring::ssl::SslRef,
    enabled: bool,
) -> Result<Option<TlsChannelBinding>> {
    if !enabled {
        return Ok(None);
    }
    let label = std::str::from_utf8(TLS_CHANNEL_BINDING_EXPORTER_LABEL)
        .context("TLS channel-binding exporter label is not UTF-8")?;
    let mut output = [0u8; 32];
    connection
        .export_keying_material(&mut output, label, None)
        .context("export browser TLS channel binding")?;
    Ok(Some(TlsChannelBinding::new(output)))
}

fn rustls_client_channel_binding(
    connection: &rustls::ClientConnection,
    enabled: bool,
) -> Result<Option<TlsChannelBinding>> {
    if !enabled {
        return Ok(None);
    }
    let output = connection
        .export_keying_material([0u8; 32], TLS_CHANNEL_BINDING_EXPORTER_LABEL, None)
        .context("export TLS channel binding")?;
    Ok(Some(TlsChannelBinding::new(output)))
}

pub(crate) fn end_to_end_channel_binding_enabled(config: &ClientConfig) -> bool {
    config.auth.channel_binding.enabled && !config.advanced.tls_terminating_fronting_enabled()
}

#[derive(Clone, Copy)]
enum H2FingerprintProfile {
    MaverickDefault,
    #[cfg(feature = "browser-tls")]
    ChromeReference,
}

async fn finish_h2_handshake<T>(
    tls: T,
    profile: H2FingerprintProfile,
) -> Result<(SendRequest<Bytes>, watch::Receiver<bool>)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    match profile {
        H2FingerprintProfile::MaverickDefault => {
            builder
                .initial_window_size(1024 * 1024)
                .initial_connection_window_size(4 * 1024 * 1024);
        }
        #[cfg(feature = "browser-tls")]
        H2FingerprintProfile::ChromeReference => {
            builder
                .header_table_size(65_536)
                .enable_push(false)
                .initial_window_size(6 * 1024 * 1024)
                .max_header_list_size(256 * 1024)
                .initial_connection_window_size(15 * 1024 * 1024);
        }
    }
    let (client, connection) = builder
        .handshake(tls)
        .await
        .context("h2 handshake failed")?;
    let (closed_tx, closed_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!(error = %err, "h2 client connection closed");
        }
        let _ = closed_tx.send(true);
    });
    Ok((client, closed_rx))
}

pub(crate) fn rustls_client_config(config: &ClientConfig) -> Result<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = &config.server.ca_cert {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
            .with_context(|| format!("open CA cert {}", path.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse CA certs")?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            anyhow::bail!("no valid CA certificates found in {}", path.display());
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    if let Some(pin) = &config.server.cert_pin {
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .context("build WebPKI verifier")?;
        let verifier = Arc::new(PinnedServerVerifier {
            inner: verifier,
            expected_sha256: parse_cert_pin(pin)?,
        });
        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth())
    } else {
        Ok(builder.with_root_certificates(roots).with_no_client_auth())
    }
}

fn parse_cert_pin(pin: &str) -> Result<[u8; 32]> {
    let encoded = pin
        .strip_prefix("sha256/")
        .context("cert_pin must use sha256/<base64url-no-pad>")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .context("cert_pin is not valid base64url")?;
    let expected_sha256: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("cert_pin SHA-256 value must be 32 bytes"))?;
    Ok(expected_sha256)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    expected_sha256: [u8; 32],
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let digest = Sha256::digest(end_entity.as_ref());
        if bool::from(digest.as_slice().ct_eq(&self.expected_sha256)) {
            Ok(verified)
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(all(test, feature = "ech"))]
mod ech_api_tests {
    #[test]
    fn rustls_client_ech_api_is_present_for_feature_harness() {
        let _ = std::any::type_name::<rustls::client::EchConfig>();
        let _ = std::any::type_name::<rustls::client::EchMode>();
        let _ = std::any::type_name::<rustls::client::EchStatus>();
        let _ = std::any::type_name::<rustls::pki_types::EchConfigListBytes<'static>>();
        let _with_ech =
            rustls::ConfigBuilder::<rustls::ClientConfig, rustls::WantsVersions>::with_ech;
    }
}
