use anyhow::{ensure, Context, Result};
use maverick_core::{SecretString, ServerConfig};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::timeout;

async fn rejects_tls_without_announcing_ready(fault: &str) -> Result<()> {
    let directory = TempDir::new()?;
    let valid = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    fs::write(
        directory.path().join("key.pem"),
        valid.key_pair.serialize_pem(),
    )?;
    let expected = match fault {
        "missing" => "open cert",
        "malformed" => {
            fs::write(directory.path().join("cert.pem"), b"not a PEM certificate")?;
            "certificate chain is empty"
        }
        "mismatched" => {
            fs::write(directory.path().join("cert.pem"), valid.cert.pem())?;
            let other = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            fs::write(
                directory.path().join("key.pem"),
                other.key_pair.serialize_pem(),
            )?;
            "build TLS server config"
        }
        _ => unreachable!(),
    };
    let secret = SecretString::generate();
    let yaml = format!(
        "version: 1\nlisten: '127.0.0.1:0'\ntls:\n  cert_path: cert.pem\n  key_path: key.pem\nmaverick:\n  tunnel_path: /startup-test\nusers:\n  - id: startup-test\n    secret: '{}'\nfallback:\n  type: static\n  static_dir: .\nmetrics:\n  enabled: true\n  listen: '127.0.0.1:0'\nlog:\n  level: info\n",
        secret.expose_secret()
    );
    ServerConfig::from_yaml_str(&yaml)
        .map_err(|_| anyhow::anyhow!("startup fixture is not valid server YAML"))?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(directory.path().join("server.yaml"))?
        .write_all(yaml.as_bytes())?;
    let output = timeout(
        Duration::from_secs(30),
        Command::new(env!("CARGO_BIN_EXE_maverick"))
            .args(["server", "-c", "server.yaml"])
            .current_dir(directory.path())
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("invalid-TLS CLI startup did not terminate")??;
    ensure!(
        !output.status.success(),
        "CLI accepted invalid TLS material"
    );
    ensure!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "CLI failed without the expected TLS startup error category"
    );
    // Inspect captured output without printing certificate paths or raw errors.
    for captured in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(captured);
        ensure!(
            !text.contains("Maverick server listening"),
            "CLI announced server readiness before TLS initialization"
        );
        ensure!(
            !text.contains("Maverick local metrics listening"),
            "CLI announced metrics readiness before TLS initialization"
        );
        ensure!(
            !text.contains(secret.expose_secret()) && !text.contains("PRIVATE KEY"),
            "CLI startup failure disclosed credentials or key material"
        );
    }
    Ok(())
}

#[tokio::test]
async fn missing_certificate_never_announces_ready() -> Result<()> {
    rejects_tls_without_announcing_ready("missing").await
}

#[tokio::test]
async fn malformed_certificate_never_announces_ready() -> Result<()> {
    rejects_tls_without_announcing_ready("malformed").await
}

#[tokio::test]
async fn mismatched_certificate_key_never_announces_ready() -> Result<()> {
    rejects_tls_without_announcing_ready("mismatched").await
}
