use super::*;

// A ratio of one gives even a one-byte TCP read a nonzero padding budget.
// The small frame cap bounds this test independently of TCP read boundaries.
const SHAPING: &str = "advanced:\n  shaping:\n    enabled: true\n    max_padding_bytes_per_frame: 8\n    max_overhead_ratio: 1.0\n    max_delay_ms: 1\n    max_batch_bytes: 128\n    cover_traffic: true\n    cover_traffic_operator_approved: true\n    cover_traffic_window_ms: 1000\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_h3_shaping_respects_auto_and_stable_modes() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        for mode in ["auto", "stable"] {
            let fixture = Fixture::new()?;
            fixture.server_config_with_metrics(true)?;
            let server_path = fixture.directory.path().join("server.yaml");
            let server_config = std::fs::read_to_string(&server_path)?
                .replacen(
                    "maverick:\n",
                    &format!("maverick:\n  mode_default: {mode}\n"),
                    1,
                )
                .replacen("advanced:\n", SHAPING, 1);
            // Update the existing private fixture files without serializing secrets.
            std::fs::write(&server_path, server_config)?;
            let mut server = Cli::start(fixture.directory.path(), "server", "server.yaml")?;
            let address = server.ready(SERVER_READY).await?;
            let metrics = server.ready(METRICS_READY).await?;

            fixture.client_config("client.yaml", address, true, Fault::None)?;
            let client_path = fixture.directory.path().join("client.yaml");
            let client_config = std::fs::read_to_string(&client_path)?
                .replacen("version: 1\n", &format!("version: 1\nmode: {mode}\n"), 1)
                .replacen("advanced:\n", SHAPING, 1);
            std::fs::write(&client_path, client_config)?;
            let mut client = Cli::start(fixture.directory.path(), "client", "client.yaml")?;
            let socks = client.ready(SOCKS_READY).await?;
            let http = client.ready(HTTP_READY).await?;

            // Includes exact payload, TCP half-close and admission cleanup for
            // sequential and concurrent SOCKS/HTTP CONNECT requests.
            successful_flows(socks, http, metrics)
                .await
                .with_context(|| format!("{mode} shaped H3 forwarding"))?;
            let state = soak::metrics(metrics).await?;
            let counter = |name: &str| {
                state[name]
                    .as_u64()
                    .with_context(|| format!("missing shaping metric {name}"))
            };
            let counters = [
                counter("shaping_padding_frames")?,
                counter("shaping_padding_bytes")?,
                counter("cover_traffic_padding_frames")?,
                counter("cover_traffic_padding_bytes")?,
            ];
            if mode == "auto" {
                let [total_frames, total_bytes, cover_frames, cover_bytes] = counters;
                ensure!(
                    cover_frames > 0 && cover_bytes > 0,
                    "approved H3 cover traffic was not emitted; counters: {counters:?}"
                );
                // Server totals include cover traffic. A positive total alone
                // would not prove that ordinary padding was also emitted.
                ensure!(
                    total_frames > cover_frames && total_bytes > cover_bytes,
                    "H3 ordinary padding was not emitted; counters: {counters:?}"
                );
            } else {
                ensure!(
                    counters == [0; 4],
                    "stable mode emitted H3 shaping traffic; counters: {counters:?}"
                );
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("configured H3 shaping test timed out")?
}
