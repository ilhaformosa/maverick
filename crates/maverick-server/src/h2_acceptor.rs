use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use maverick_core::ServerConfig;

pub fn rustls_server_config(config: &ServerConfig) -> Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&config.tls.cert_path)
        .with_context(|| format!("open cert {}", config.tls.cert_path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse certificate chain")?;
    if certs.is_empty() {
        anyhow::bail!("certificate chain is empty");
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(&config.tls.key_path)
        .with_context(|| format!("parse private key {}", config.tls.key_path.display()))?;

    let mut tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("build TLS server config")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    if config.advanced.cloudflare_ws_enabled() {
        tls_config.alpn_protocols.push(b"http/1.1".to_vec());
    }
    Ok(tls_config)
}

pub fn acceptor(config: &ServerConfig) -> Result<tokio_rustls::TlsAcceptor> {
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls_server_config(config)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        CdnFrontingConfig, FallbackConfig, LogConfig, MaverickServerConfig, Mode, SecretString,
        ServerAdvancedConfig, ServerAuthConfig, TlsConfig, UserConfig,
    };
    use tempfile::TempDir;

    fn test_config(tmp: &TempDir, experimental_cloudflare_ws: bool) -> ServerConfig {
        let cert_path = tmp.path().join("cert.pem");
        let key_path = tmp.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        std::fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();

        ServerConfig {
            version: 1,
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: TlsConfig {
                cert_path,
                key_path,
            },
            maverick: MaverickServerConfig {
                tunnel_path: "/assets/upload".into(),
                mode_default: Mode::Auto,
                replay_window_secs: 120,
                replay_cache_entries_per_credential: 16,
                replay_cache_max_credentials_per_shard: 16,
                max_concurrent_flows_per_user: 128,
            },
            users: vec![UserConfig {
                id: "u_abc123".into(),
                name: None,
                secret: SecretString::generate(),
                enabled: true,
                rate_limit: None,
                max_concurrent_flows: None,
                rotation: None,
            }],
            fallback: FallbackConfig::Static {
                static_dir: tmp.path().into(),
                index: "index.html".into(),
            },
            auth: ServerAuthConfig::default(),
            dns: None,
            metrics: None,
            log: LogConfig::default(),
            advanced: ServerAdvancedConfig {
                experimental_cloudflare_ws,
                ..ServerAdvancedConfig::default()
            },
        }
    }

    fn cdn_fronting_config(tmp: &TempDir) -> ServerConfig {
        let mut config = test_config(tmp, false);
        config.advanced.stealth.cdn_fronting = CdnFrontingConfig {
            enabled: true,
            trusted_tls_terminating_provider: true,
            ..CdnFrontingConfig::default()
        };
        config
    }

    #[test]
    fn rustls_server_config_advertises_h2_by_default() -> Result<()> {
        let tmp = TempDir::new()?;
        let config = test_config(&tmp, false);

        let tls_config = rustls_server_config(&config)?;

        assert_eq!(tls_config.alpn_protocols, vec![b"h2".to_vec()]);
        Ok(())
    }

    #[test]
    fn rustls_server_config_adds_http11_for_cloudflare_ws() -> Result<()> {
        let tmp = TempDir::new()?;
        let config = test_config(&tmp, true);

        let tls_config = rustls_server_config(&config)?;

        assert_eq!(
            tls_config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        Ok(())
    }

    #[test]
    fn rustls_server_config_adds_http11_for_cdn_fronting() -> Result<()> {
        let tmp = TempDir::new()?;
        let config = cdn_fronting_config(&tmp);

        let tls_config = rustls_server_config(&config)?;

        assert_eq!(
            tls_config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        Ok(())
    }
}
