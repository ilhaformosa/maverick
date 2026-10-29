use anyhow::{bail, ensure, Context, Result};
use maverick_sdk::{server_config_builder, MaverickServer, SecretString, ServerConfig};
use std::fs;
use std::io::ErrorKind;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::timeout;

async fn start_error(config: ServerConfig, expected: &str) -> Result<anyhow::Error> {
    match MaverickServer::start(config).await {
        Err(error) => {
            ensure!(
                error
                    .chain()
                    .any(|cause| cause.to_string().contains(expected)),
                "SDK failed without the expected TLS startup error category"
            );
            Ok(error)
        }
        Ok(runtime) => {
            // Reap the old implementation's failed background startup without
            // printing its error or leaving its listener/task behind.
            let _ = runtime.shutdown().await;
            bail!("SDK reported a successful start with invalid TLS material")
        }
    }
}

async fn rejects_tls_then_starts_after_correction(fault: &str) -> Result<()> {
    timeout(Duration::from_secs(30), async {
        let directory = TempDir::new()?;
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let valid = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let valid_cert = valid.cert.pem();
        let valid_key = valid.key_pair.serialize_pem();
        fs::write(&key_path, &valid_key)?;
        let expected = match fault {
            "missing" => "open cert",
            "malformed" => {
                fs::write(&cert_path, b"not a PEM certificate")?;
                "certificate chain is empty"
            }
            "mismatched" => {
                fs::write(&cert_path, &valid_cert)?;
                let other = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
                fs::write(&key_path, other.key_pair.serialize_pem())?;
                "build TLS server config"
            }
            _ => unreachable!(),
        };
        let config = server_config_builder()
            .listen("127.0.0.1:0".parse()?)
            .tls_paths(&cert_path, &key_path)
            .static_fallback_dir(directory.path())
            .user("startup-test", SecretString::generate())
            .build()?;
        start_error(config.clone(), expected).await?;

        // Hold an OS-assigned port throughout the check: invalid TLS must be
        // reported before attempting to bind, without a free-port race.
        let held = TcpListener::bind("127.0.0.1:0").await?;
        let mut occupied = config.clone();
        occupied.listen = held.local_addr()?;
        let error = start_error(occupied, expected).await?;
        ensure!(
            !error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::AddrInUse)),
            "SDK attempted to bind before checking its TLS material"
        );
        drop(held);

        fs::write(&cert_path, valid_cert)?;
        fs::write(&key_path, valid_key)?;
        let runtime = MaverickServer::start(config)
            .await
            .map_err(|_| anyhow::anyhow!("SDK rejected corrected TLS material"))?;
        let address = runtime
            .local_addr()
            .context("SDK omitted its listener address")?;
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "SDK did not report its assigned loopback address"
        );
        runtime
            .shutdown()
            .await
            .map_err(|_| anyhow::anyhow!("SDK shutdown failed after corrected startup"))?;
        let _released = TcpListener::bind(address)
            .await
            .context("SDK shutdown retained its listener port")?;
        Ok(())
    })
    .await
    .context("SDK startup regression test timed out")?
}

#[tokio::test]
async fn missing_certificate_is_a_start_error() -> Result<()> {
    rejects_tls_then_starts_after_correction("missing").await
}

#[tokio::test]
async fn malformed_certificate_is_a_start_error() -> Result<()> {
    rejects_tls_then_starts_after_correction("malformed").await
}

#[tokio::test]
async fn mismatched_certificate_key_is_a_start_error() -> Result<()> {
    rejects_tls_then_starts_after_correction("mismatched").await
}
