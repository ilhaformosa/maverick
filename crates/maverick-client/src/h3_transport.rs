//! Explicit quiche dialer for the existing TCP tunnel/session path.
use anyhow::{Context, Result};
use boring::ssl::{SslContext, SslContextBuilder, SslMethod, SslVersion};
use maverick_core::frame::MAX_NEGOTIATED_FRAME_SIZE;
use maverick_core::ClientConfig;
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

pub(crate) async fn connect(config: &ClientConfig) -> Result<maverick_quiche::Connected> {
    connect_to(config, &config.server.address).await
}

/// A failed identity, protocol or authentication check never returns None.
pub(crate) async fn auto_connect(
    config: &ClientConfig,
) -> Result<Option<maverick_quiche::Connected>> {
    let budget = Duration::from_millis((config.advanced.connect_timeout_ms / 2).clamp(1, 1000));
    match connect_with_budget(config, &config.server.address, budget).await {
        Ok(connection) => Ok(Some(connection)),
        Err(error)
            if error
                .downcast_ref::<maverick_quiche::NetworkUnavailable>()
                .is_some() =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

async fn connect_to(
    config: &ClientConfig,
    address: impl tokio::net::ToSocketAddrs,
) -> Result<maverick_quiche::Connected> {
    connect_with_budget(
        config,
        address,
        Duration::from_millis(config.advanced.connect_timeout_ms),
    )
    .await
}

async fn connect_with_budget(
    config: &ClientConfig,
    address: impl tokio::net::ToSocketAddrs,
    budget: Duration,
) -> Result<maverick_quiche::Connected> {
    config.validate()?;
    let deadline = tokio::time::Instant::now() + budget;
    let mut tls = tls_context(config)?;
    let addresses = tokio::time::timeout_at(deadline, tokio::net::lookup_host(address))
        .await
        .context(maverick_quiche::NetworkUnavailable)??;
    let mut last_error = None;
    for peer in addresses {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let connection = match maverick_quiche::connect(
            peer,
            &config.server.server_name,
            &config.server.tunnel_path,
            tls,
            maverick_quiche::Limits {
                max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
                handshake_timeout: remaining,
                idle_timeout: Duration::from_secs(config.advanced.idle_timeout_secs),
            },
        )
        .await
        {
            Ok(connection) => connection,
            Err(error)
                if error
                    .downcast_ref::<maverick_quiche::NetworkUnavailable>()
                    .is_some() =>
            {
                last_error = Some(error);
                tls = tls_context(config)?;
                continue;
            }
            // Do not hide a TLS failure by trying another address, then reporting
            // that address's network failure as permission to downgrade.
            Err(error) => return Err(error),
        };
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
        return Ok(connection);
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("H3 endpoint has no usable addresses")))
}

fn tls_context(config: &ClientConfig) -> Result<SslContextBuilder> {
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
    Ok(tls)
}

#[cfg(test)]
mod tests;
