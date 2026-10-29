use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_generated_h3_configs_relay_and_cleanup() -> Result<()> {
    timeout(Duration::from_secs(90), async {
        let fixture = Fixture::new()?;
        let output = Command::new(env!("CARGO_BIN_EXE_maverick"))
            .args(["gen-config", "--quiche-h3"])
            .current_dir(fixture.directory.path())
            .output()
            .context("run public H3 config generator")?;
        ensure!(
            output.status.success(),
            "H3 config generator failed with status {:?}",
            output.status.code()
        );

        // Use the generated pair, including its carrier and shared credentials.
        // Change only local test endpoints, TLS files, egress and observation.
        let server_path = fixture.directory.path().join("server.generated.yaml");
        let server_config = std::fs::read_to_string(&server_path)?
            .replacen("listen: \"0.0.0.0:443\"", "listen: \"127.0.0.1:0\"", 1)
            .replacen("./certs/fullchain.pem", "cert.pem", 1)
            .replacen("./certs/privkey.pem", "key.pem", 1)
            .replacen("allow_loopback: false", "allow_loopback: true", 1)
            .replacen(
                "metrics:\n  enabled: false\n  listen: \"127.0.0.1:19090\"",
                "metrics:\n  enabled: true\n  listen: \"127.0.0.1:0\"",
                1,
            );
        let parsed_server = maverick_core::ServerConfig::from_yaml_str(&server_config)?;
        ensure!(
            parsed_server.advanced.quiche_h3,
            "generator did not enable server H3"
        );
        let loopback: SocketAddr = "127.0.0.1:0".parse()?;
        ensure!(
            parsed_server.listen == loopback
                && parsed_server
                    .metrics
                    .as_ref()
                    .is_some_and(|metrics| metrics.enabled && metrics.listen == loopback),
            "generated server test listeners must use ephemeral loopback ports"
        );
        std::fs::write(&server_path, server_config)?;
        let mut server = Cli::start(fixture.directory.path(), "server", "server.generated.yaml")?;
        let address = server.ready(SERVER_READY).await?;
        let metrics = server.ready(METRICS_READY).await?;

        let client_path = fixture.directory.path().join("client.generated.yaml");
        let client_config = std::fs::read_to_string(&client_path)?
            .replacen("127.0.0.1:1080", "127.0.0.1:0", 1)
            .replacen("127.0.0.1:18080", "127.0.0.1:0", 1)
            .replacen(
                "http_connect:\n    enabled: false",
                "http_connect:\n    enabled: true",
                1,
            )
            .replacen("example.com:443", &address.to_string(), 1)
            .replacen(
                "server_name: \"example.com\"",
                "server_name: \"localhost\"",
                1,
            )
            .replacen("ca_cert: null", "ca_cert: \"ca.pem\"", 1);
        let parsed_client = maverick_core::ClientConfig::from_yaml_str(&client_config)?;
        ensure!(
            parsed_client.advanced.quiche_h3,
            "generator did not enable client H3"
        );
        ensure!(
            parsed_client.server.address == address.to_string()
                && parsed_client.local.socks5.listen == loopback
                && parsed_client
                    .local
                    .http_connect
                    .as_ref()
                    .is_some_and(|http| http.enabled && http.listen == Some(loopback)),
            "generated client test endpoints must use the loopback fixture"
        );
        std::fs::write(&client_path, client_config)?;
        let mut client = Cli::start(fixture.directory.path(), "client", "client.generated.yaml")?;
        let socks = client.ready(SOCKS_READY).await?;
        let http = client.ready(HTTP_READY).await?;
        successful_flows(socks, http, metrics)
            .await
            .context("public generated H3 config forwarding")
    })
    .await
    .context("generated H3 config test timed out")?
}
