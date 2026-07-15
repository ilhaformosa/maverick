#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("maverick-tun-phase2 requires Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
#[path = "maverick-tun-phase2/linux_tun.rs"]
mod linux_tun;

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use clap::Parser;
    use maverick_core::ClientConfig;
    use maverick_tun::{
        BoxFuture, PacketIo, PacketRead, PacketReader, PacketRuntimeConfig, PacketRuntimeSnapshot,
        PacketWriter,
    };
    use serde_json::{json, Value};
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::time::{interval, MissedTickBehavior};

    use super::linux_tun::TunEndpoint;

    #[derive(Debug, Parser)]
    #[command(name = "maverick-tun-phase2")]
    #[command(about = "Approved-host Phase 2 Linux TUN evidence runner")]
    struct Args {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, value_parser = validate_device_name)]
        device: String,
        #[arg(long, default_value_t = 1500, value_parser = parse_mtu)]
        mtu: usize,
        #[arg(long, default_value_t = 32, value_parser = parse_flow_limit)]
        max_flows: usize,
        #[arg(long, default_value_t = 64, value_parser = parse_queue_depth)]
        packet_queue_depth: usize,
        #[arg(long, default_value_t = 256, value_parser = parse_event_queue_depth)]
        event_queue_depth: usize,
        #[arg(long, default_value_t = 1000, value_parser = parse_snapshot_interval)]
        snapshot_interval_ms: u64,
        #[arg(long, value_parser = parse_run_seconds)]
        run_seconds: Option<u64>,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        ipv6: bool,
    }

    struct TunReader(Arc<TunEndpoint>);

    impl PacketReader for TunReader {
        fn receive<'a>(
            &'a mut self,
            buffer: &'a mut [u8],
        ) -> BoxFuture<'a, io::Result<PacketRead>> {
            Box::pin(async move {
                let length = self.0.recv(buffer).await?;
                if length == 0 {
                    Ok(PacketRead::Eof)
                } else {
                    Ok(PacketRead::Packet(length))
                }
            })
        }
    }

    struct TunWriter(Arc<TunEndpoint>);

    impl PacketWriter for TunWriter {
        fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async move {
                let written = self.0.send(packet).await?;
                if written != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN packet write was incomplete",
                    ));
                }
                Ok(())
            })
        }
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build Tokio runtime")?;
        runtime.block_on(run(args))
    }

    async fn run(args: Args) -> Result<()> {
        let raw = std::fs::read_to_string(&args.config).context("read client config")?;
        let config = ClientConfig::from_yaml_str(&raw).context("parse client config")?;
        anyhow::ensure!(
            config.advanced.experimental_tun,
            "advanced.experimental_tun must be enabled"
        );

        let device = TunEndpoint::open_existing(&args.device)
            .context("attach to pre-created IFF_TUN | IFF_NO_PI endpoint")?;
        let actual_name = device.name().to_owned();
        anyhow::ensure!(actual_name == args.device, "attached TUN name changed");
        let device = Arc::new(device);

        let mut client = maverick_client::start_client(config)
            .await
            .context("start Maverick client")?;
        let runtime_config = PacketRuntimeConfig {
            mtu: args.mtu,
            ipv6_enabled: args.ipv6,
            max_tcp_flows: args.max_flows,
            max_udp_targets: args.max_flows,
            max_udp_associations: args.max_flows,
            max_dns_queries: args.max_flows,
            packet_queue_depth: args.packet_queue_depth,
            event_queue_depth: args.event_queue_depth,
            ..PacketRuntimeConfig::default()
        };
        client
            .start_tun_runtime(
                runtime_config,
                PacketIo::new(
                    TunReader(Arc::clone(&device)),
                    TunWriter(Arc::clone(&device)),
                ),
            )
            .await
            .context("start packet runtime")?;

        emit(json!({
            "event": "runner_started",
            "device": actual_name,
            "pid": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
        }));

        let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut interrupt = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
        let deadline = args
            .run_seconds
            .map(|seconds| tokio::time::sleep(Duration::from_secs(seconds)));
        tokio::pin!(deadline);
        let mut snapshots = interval(Duration::from_millis(args.snapshot_interval_ms));
        snapshots.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let stop_reason = loop {
            tokio::select! {
                _ = terminate.recv() => break "sigterm",
                _ = interrupt.recv() => break "sigint",
                _ = async {
                    match deadline.as_mut().as_pin_mut() {
                        Some(deadline) => deadline.await,
                        None => std::future::pending().await,
                    }
                } => break "duration",
                _ = snapshots.tick() => {
                    let snapshot = client
                        .tun_runtime_snapshot()
                        .context("packet runtime disappeared")?;
                    emit(snapshot_event("snapshot", &snapshot));
                }
            }
        };

        let final_snapshot = client
            .tun_runtime_snapshot()
            .context("packet runtime disappeared before shutdown")?;
        emit(snapshot_event("runner_stopping", &final_snapshot));
        client
            .shutdown()
            .await
            .context("shutdown Maverick client")?;
        emit(json!({"event": "runner_stopped", "reason": stop_reason}));
        Ok(())
    }

    fn validate_device_name(value: &str) -> Result<String, String> {
        if value.is_empty()
            || value.len() > 15
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err("device must be 1-15 ASCII letters, digits, '_', '-', or '.'".into());
        }
        Ok(value.to_owned())
    }

    fn parse_mtu(value: &str) -> Result<usize, String> {
        parse_usize(value, 1280, 65_535, "MTU")
    }

    fn parse_flow_limit(value: &str) -> Result<usize, String> {
        parse_usize(value, 1, 4096, "flow limit")
    }

    fn parse_queue_depth(value: &str) -> Result<usize, String> {
        parse_usize(value, 1, 4096, "packet queue depth")
    }

    fn parse_event_queue_depth(value: &str) -> Result<usize, String> {
        parse_usize(value, 1, 16_384, "event queue depth")
    }

    fn parse_snapshot_interval(value: &str) -> Result<u64, String> {
        parse_u64(value, 100, 60_000, "snapshot interval")
    }

    fn parse_run_seconds(value: &str) -> Result<u64, String> {
        parse_u64(value, 1, 604_800, "run duration")
    }

    fn parse_usize(
        value: &str,
        minimum: usize,
        maximum: usize,
        name: &str,
    ) -> Result<usize, String> {
        let parsed = value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be an integer"))?;
        if !(minimum..=maximum).contains(&parsed) {
            return Err(format!("{name} must be between {minimum} and {maximum}"));
        }
        Ok(parsed)
    }

    fn parse_u64(value: &str, minimum: u64, maximum: u64, name: &str) -> Result<u64, String> {
        let parsed = value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an integer"))?;
        if !(minimum..=maximum).contains(&parsed) {
            return Err(format!("{name} must be between {minimum} and {maximum}"));
        }
        Ok(parsed)
    }

    fn snapshot_event(event: &str, snapshot: &PacketRuntimeSnapshot) -> Value {
        json!({
            "event": event,
            "state": format!("{:?}", snapshot.state),
            "last_failure": snapshot.last_failure.map(|failure| format!("{failure:?}")),
            "packets_received": snapshot.packets_received,
            "packets_sent": snapshot.packets_sent,
            "packets_rejected": snapshot.packets_rejected,
            "malformed_packets": snapshot.malformed_packets,
            "unsupported_packets": snapshot.unsupported_packets,
            "tcp_flows_opened": snapshot.tcp_flows_opened,
            "tcp_flows_rejected": snapshot.tcp_flows_rejected,
            "tcp_flows_failed": snapshot.tcp_flows_failed,
            "active_tcp_flows": snapshot.active_tcp_flows,
            "peak_tcp_flows": snapshot.peak_tcp_flows,
            "udp_associations_opened": snapshot.udp_associations_opened,
            "udp_associations_failed": snapshot.udp_associations_failed,
            "udp_datagrams_dropped": snapshot.udp_datagrams_dropped,
            "active_udp_associations": snapshot.active_udp_associations,
            "peak_udp_associations": snapshot.peak_udp_associations,
            "dns_queries_started": snapshot.dns_queries_started,
            "dns_queries_rejected": snapshot.dns_queries_rejected,
            "dns_queries_failed": snapshot.dns_queries_failed,
            "active_dns_queries": snapshot.active_dns_queries,
            "peak_dns_queries": snapshot.peak_dns_queries,
            "active_tasks": snapshot.active_tasks,
            "peak_tasks": snapshot.peak_tasks,
            "ingress_queue_depth": snapshot.ingress_queue_depth,
            "egress_queue_depth": snapshot.egress_queue_depth,
            "peak_ingress_queue_depth": snapshot.peak_ingress_queue_depth,
            "peak_egress_queue_depth": snapshot.peak_egress_queue_depth,
            "buffered_bytes": snapshot.buffered_bytes,
            "peak_buffered_bytes": snapshot.peak_buffered_bytes,
            "configured_buffer_capacity_bytes": snapshot.configured_buffer_capacity_bytes,
        })
    }

    fn emit(value: Value) {
        println!("{}", stamp_event(value));
    }

    fn stamp_event(mut value: Value) -> Value {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if let Some(object) = value.as_object_mut() {
            object.insert("timestamp_unix_ms".into(), json!(timestamp_unix_ms));
        }
        value
    }

    #[cfg(test)]
    mod tests {
        use super::{stamp_event, validate_device_name};
        use serde_json::json;

        #[test]
        fn device_name_validation_is_strict() {
            assert_eq!(validate_device_name("mavtun123").unwrap(), "mavtun123");
            for invalid in ["", "bad/name", "name with space", "0123456789abcdef"] {
                assert!(validate_device_name(invalid).is_err(), "{invalid:?}");
            }
        }

        #[test]
        fn every_event_receives_a_unix_millisecond_timestamp() {
            let event = stamp_event(json!({"event": "snapshot"}));
            assert!(event["timestamp_unix_ms"].as_u64().unwrap() > 0);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::main()
}
