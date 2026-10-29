use anyhow::{ensure, Context, Result};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

async fn user_smoke(args: &[&str]) -> Result<Output> {
    timeout(
        Duration::from_secs(90),
        Command::new(env!("CARGO_BIN_EXE_maverick"))
            .arg("user-smoke")
            .args(args)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("user-smoke process timed out")?
    .context("run ordinary user-smoke command")
}

fn assert_success(output: Output, carrier: &str) -> Result<()> {
    // Report fixed checks and exit status, never dump captured process output.
    ensure!(
        output.status.success(),
        "user-smoke failed with status {}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).context("user-smoke stdout is not UTF-8")?;
    ensure!(
        stdout
            .lines()
            .filter(|line| line.starts_with("carrier: "))
            .eq([carrier]),
        "user-smoke reported an unexpected carrier"
    );
    for expected in [
        "wrong_credential_rejected: PASS",
        "correct_credential_roundtrip: PASS",
    ] {
        ensure!(
            stdout.lines().any(|line| line == expected),
            "user-smoke did not report {expected}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn default_user_smoke_remains_h2() -> Result<()> {
    assert_success(user_smoke(&[]).await?, "carrier: h2")
}

#[cfg(feature = "experimental-h3")]
#[tokio::test]
async fn explicit_user_smoke_uses_h3() -> Result<()> {
    let output = user_smoke(&["--quiche-h3"]).await?;
    ensure!(
        !String::from_utf8_lossy(&output.stdout).contains("tls_fingerprint:"),
        "H3 self-check must not report the H2 fingerprint selector"
    );
    assert_success(output, "carrier: h3")
}

#[cfg(not(feature = "experimental-h3"))]
#[tokio::test]
async fn h3_user_smoke_requires_the_build_feature() -> Result<()> {
    let output = user_smoke(&["--quiche-h3"]).await?;
    ensure!(!output.status.success(), "unsupported H3 smoke succeeded");
    ensure!(
        output.stdout.is_empty(),
        "unsupported H3 smoke produced output instead of rejecting before startup"
    );
    let stderr = String::from_utf8(output.stderr).context("user-smoke stderr is not UTF-8")?;
    ensure!(
        stderr.contains("--quiche-h3 requires a build with --features experimental-h3"),
        "missing explicit H3 build-feature error"
    );
    ensure!(
        !stderr.contains("PASS"),
        "unsupported H3 smoke reported success"
    );
    Ok(())
}
