//! Explicit quiche dialer for the existing TCP tunnel/session path.
use anyhow::{Context, Result};
use boring::ssl::{SslContext, SslMethod, SslVersion};
use maverick_core::ClientConfig;
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

pub(crate) async fn connect(config: &ClientConfig) -> Result<maverick_quiche::Connected> {
    config.validate()?;
    let budget = Duration::from_millis(config.advanced.connect_timeout_ms);
    tokio::time::timeout(budget, async {
        let mut tls = SslContext::builder(SslMethod::tls())?;
        tls.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        tls.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        crate::browser_tls::configure(&mut tls)?;
        if let Some(path) = &config.server.ca_cert {
            tls.set_ca_file(path).context("load H3 trust roots")?;
        } else {
            tls.set_default_verify_paths()
                .context("load default H3 trust roots")?;
        }
        let peer = tokio::net::lookup_host(&config.server.address)
            .await?
            .next()
            .context("H3 endpoint has no addresses")?;
        let connection = maverick_quiche::connect(
            peer,
            &config.server.server_name,
            &config.server.tunnel_path,
            tls,
            maverick_quiche::Limits {
                max_frame_size: 1024 * 1024,
                handshake_timeout: budget,
                idle_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
            },
        )
        .await?;
        if let Some(pin) = &config.server.cert_pin {
            let expected = crate::h2_transport::parse_cert_pin(pin)?;
            let cert = connection
                .peer_certificate_der
                .as_ref()
                .context("H3 peer certificate missing")?;
            let digest = Sha256::digest(cert);
            anyhow::ensure!(
                bool::from(digest.as_slice().ct_eq(&expected)),
                "H3 server certificate pin mismatch"
            );
        }
        Ok(connection)
    })
    .await
    .context("H3 connection timed out")?
}
