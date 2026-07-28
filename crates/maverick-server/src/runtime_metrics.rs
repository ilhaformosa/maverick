use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::relay;

#[derive(Debug, Default)]
pub(crate) struct ServerRuntimeMetrics {
    pub(crate) authenticated_sessions: AtomicU64,
    pub(crate) unauthenticated_rejections: AtomicU64,
    pub(crate) fallback_requests: AtomicU64,
    pub(crate) fallback_overload_rejections: AtomicU64,
    pub(crate) tcp_flows: AtomicU64,
    pub(crate) dns_queries: AtomicU64,
    target_resolution_timeouts: Arc<AtomicU64>,
    target_resolution_failures: Arc<AtomicU64>,
    target_connect_timeouts: Arc<AtomicU64>,
    target_connect_failures: Arc<AtomicU64>,
    target_resolution_latency: relay::CumulativeLatencyMetric,
    target_connect_latency: relay::CumulativeLatencyMetric,
    h2_stream_resets: AtomicU64,
    h2_send_stalls: AtomicU64,
    pub(crate) active_flows: AtomicU64,
    pub(crate) flow_limit_rejections: AtomicU64,
    pub(crate) active_connections: AtomicU64,
    pub(crate) connection_limit_rejections: AtomicU64,
    pub(crate) source_connection_limit_rejections: AtomicU64,
    pub(crate) active_pre_auth: AtomicU64,
    pub(crate) pre_auth_admission_rejections: AtomicU64,
    pub(crate) active_fallbacks: AtomicU64,
    pub(crate) auth_rate_limit_rejections: AtomicU64,
    shaping_padding_frames: Arc<AtomicU64>,
    shaping_padding_bytes: Arc<AtomicU64>,
    cover_traffic_padding_frames: Arc<AtomicU64>,
    cover_traffic_padding_bytes: Arc<AtomicU64>,
}

impl ServerRuntimeMetrics {
    pub(crate) fn record_shaping_padding(&self, emission: relay::PaddingEmission) {
        let total_frames = emission.padding_frames + emission.cover_traffic_padding_frames;
        let total_bytes = emission.padding_bytes + emission.cover_traffic_padding_bytes;
        if total_frames > 0 {
            self.shaping_padding_frames
                .fetch_add(total_frames as u64, Ordering::Relaxed);
        }
        if total_bytes > 0 {
            self.shaping_padding_bytes
                .fetch_add(total_bytes as u64, Ordering::Relaxed);
        }
        if emission.cover_traffic_padding_frames > 0 {
            self.cover_traffic_padding_frames.fetch_add(
                emission.cover_traffic_padding_frames as u64,
                Ordering::Relaxed,
            );
        }
        if emission.cover_traffic_padding_bytes > 0 {
            self.cover_traffic_padding_bytes.fetch_add(
                emission.cover_traffic_padding_bytes as u64,
                Ordering::Relaxed,
            );
        }
    }

    pub(crate) fn shaping_sinks(&self) -> relay::ShapingMetricSinks {
        relay::ShapingMetricSinks {
            padding_frames: Arc::clone(&self.shaping_padding_frames),
            padding_bytes: Arc::clone(&self.shaping_padding_bytes),
            cover_traffic_padding_frames: Arc::clone(&self.cover_traffic_padding_frames),
            cover_traffic_padding_bytes: Arc::clone(&self.cover_traffic_padding_bytes),
        }
    }

    pub(crate) fn target_open_sinks(&self) -> relay::TargetOpenMetricSinks {
        relay::TargetOpenMetricSinks {
            resolution_timeouts: Arc::clone(&self.target_resolution_timeouts),
            resolution_failures: Arc::clone(&self.target_resolution_failures),
            connect_timeouts: Arc::clone(&self.target_connect_timeouts),
            connect_failures: Arc::clone(&self.target_connect_failures),
            resolution_latency: self.target_resolution_latency.clone(),
            connect_latency: self.target_connect_latency.clone(),
        }
    }

    pub(crate) fn record_h2_request_error(&self, error: &anyhow::Error) {
        if error.downcast_ref::<relay::H2SendStall>().is_some() {
            self.h2_send_stalls.fetch_add(1, Ordering::Relaxed);
        } else if error
            .downcast_ref::<h2::Error>()
            .is_some_and(h2::Error::is_reset)
        {
            self.h2_stream_resets.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn target_latency_json_fields(&self) -> String {
        let resolution = self.target_resolution_latency.snapshot();
        let connect = self.target_connect_latency.snapshot();
        format!(
            concat!(
                "\"target_resolution_duration_ms_count\":{},",
                "\"target_resolution_duration_ms_sum\":{},",
                "\"target_resolution_duration_ms_le_10\":{},",
                "\"target_resolution_duration_ms_le_25\":{},",
                "\"target_resolution_duration_ms_le_50\":{},",
                "\"target_resolution_duration_ms_le_100\":{},",
                "\"target_resolution_duration_ms_le_250\":{},",
                "\"target_resolution_duration_ms_le_500\":{},",
                "\"target_resolution_duration_ms_le_1000\":{},",
                "\"target_resolution_duration_ms_le_2500\":{},",
                "\"target_resolution_duration_ms_le_5000\":{},",
                "\"target_resolution_duration_ms_le_10000\":{},",
                "\"target_resolution_duration_ms_le_inf\":{},",
                "\"target_connect_duration_ms_count\":{},",
                "\"target_connect_duration_ms_sum\":{},",
                "\"target_connect_duration_ms_le_10\":{},",
                "\"target_connect_duration_ms_le_25\":{},",
                "\"target_connect_duration_ms_le_50\":{},",
                "\"target_connect_duration_ms_le_100\":{},",
                "\"target_connect_duration_ms_le_250\":{},",
                "\"target_connect_duration_ms_le_500\":{},",
                "\"target_connect_duration_ms_le_1000\":{},",
                "\"target_connect_duration_ms_le_2500\":{},",
                "\"target_connect_duration_ms_le_5000\":{},",
                "\"target_connect_duration_ms_le_10000\":{},",
                "\"target_connect_duration_ms_le_inf\":{},"
            ),
            resolution.count,
            resolution.sum_ms,
            resolution.cumulative_buckets[0],
            resolution.cumulative_buckets[1],
            resolution.cumulative_buckets[2],
            resolution.cumulative_buckets[3],
            resolution.cumulative_buckets[4],
            resolution.cumulative_buckets[5],
            resolution.cumulative_buckets[6],
            resolution.cumulative_buckets[7],
            resolution.cumulative_buckets[8],
            resolution.cumulative_buckets[9],
            resolution.cumulative_buckets[10],
            connect.count,
            connect.sum_ms,
            connect.cumulative_buckets[0],
            connect.cumulative_buckets[1],
            connect.cumulative_buckets[2],
            connect.cumulative_buckets[3],
            connect.cumulative_buckets[4],
            connect.cumulative_buckets[5],
            connect.cumulative_buckets[6],
            connect.cumulative_buckets[7],
            connect.cumulative_buckets[8],
            connect.cumulative_buckets[9],
            connect.cumulative_buckets[10],
        )
    }

    pub(crate) fn json_snapshot(&self) -> String {
        let target_latency_fields = self.target_latency_json_fields();
        format!(
            concat!(
                "{{",
                "\"authenticated_sessions\":{},",
                "\"unauthenticated_rejections\":{},",
                "\"fallback_requests\":{},",
                "\"fallback_overload_rejections\":{},",
                "\"tcp_flows\":{},",
                "\"dns_queries\":{},",
                "\"target_resolution_timeouts\":{},",
                "\"target_resolution_failures\":{},",
                "\"target_connect_timeouts\":{},",
                "\"target_connect_failures\":{},",
                "{}",
                "\"h2_stream_resets\":{},",
                "\"h2_send_stalls\":{},",
                "\"active_flows\":{},",
                "\"flow_limit_rejections\":{},",
                "\"active_connections\":{},",
                "\"connection_limit_rejections\":{},",
                "\"source_connection_limit_rejections\":{},",
                "\"active_pre_auth\":{},",
                "\"pre_auth_admission_rejections\":{},",
                "\"active_fallbacks\":{},",
                "\"auth_rate_limit_rejections\":{},",
                "\"shaping_padding_frames\":{},",
                "\"shaping_padding_bytes\":{},",
                "\"cover_traffic_padding_frames\":{},",
                "\"cover_traffic_padding_bytes\":{}",
                "}}\n"
            ),
            self.authenticated_sessions.load(Ordering::Relaxed),
            self.unauthenticated_rejections.load(Ordering::Relaxed),
            self.fallback_requests.load(Ordering::Relaxed),
            self.fallback_overload_rejections.load(Ordering::Relaxed),
            self.tcp_flows.load(Ordering::Relaxed),
            self.dns_queries.load(Ordering::Relaxed),
            self.target_resolution_timeouts.load(Ordering::Relaxed),
            self.target_resolution_failures.load(Ordering::Relaxed),
            self.target_connect_timeouts.load(Ordering::Relaxed),
            self.target_connect_failures.load(Ordering::Relaxed),
            target_latency_fields,
            self.h2_stream_resets.load(Ordering::Relaxed),
            self.h2_send_stalls.load(Ordering::Relaxed),
            self.active_flows.load(Ordering::Relaxed),
            self.flow_limit_rejections.load(Ordering::Relaxed),
            self.active_connections.load(Ordering::Relaxed),
            self.connection_limit_rejections.load(Ordering::Relaxed),
            self.source_connection_limit_rejections
                .load(Ordering::Relaxed),
            self.active_pre_auth.load(Ordering::Relaxed),
            self.pre_auth_admission_rejections.load(Ordering::Relaxed),
            self.active_fallbacks.load(Ordering::Relaxed),
            self.auth_rate_limit_rejections.load(Ordering::Relaxed),
            self.shaping_padding_frames.load(Ordering::Relaxed),
            self.shaping_padding_bytes.load(Ordering::Relaxed),
            self.cover_traffic_padding_frames.load(Ordering::Relaxed),
            self.cover_traffic_padding_bytes.load(Ordering::Relaxed)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[test]
    fn target_metrics_render_as_fixed_numeric_fields_only() {
        let metrics = ServerRuntimeMetrics::default();
        metrics
            .target_resolution_timeouts
            .store(1, Ordering::Relaxed);
        metrics
            .target_resolution_failures
            .store(2, Ordering::Relaxed);
        metrics.target_connect_timeouts.store(3, Ordering::Relaxed);
        metrics.target_connect_failures.store(4, Ordering::Relaxed);
        metrics
            .target_resolution_latency
            .record(Duration::from_millis(25));
        metrics
            .target_connect_latency
            .record(Duration::from_millis(10_001));

        let snapshot = metrics.json_snapshot();
        assert!(snapshot.contains("\"target_resolution_timeouts\":1"));
        assert!(snapshot.contains("\"target_resolution_failures\":2"));
        assert!(snapshot.contains("\"target_connect_timeouts\":3"));
        assert!(snapshot.contains("\"target_connect_failures\":4"));
        assert!(snapshot.contains("\"target_resolution_duration_ms_count\":1"));
        assert!(snapshot.contains("\"target_resolution_duration_ms_sum\":25"));
        assert!(snapshot.contains("\"target_resolution_duration_ms_le_10\":0"));
        assert!(snapshot.contains("\"target_resolution_duration_ms_le_25\":1"));
        assert!(snapshot.contains("\"target_resolution_duration_ms_le_inf\":1"));
        assert!(snapshot.contains("\"target_connect_duration_ms_count\":1"));
        assert!(snapshot.contains("\"target_connect_duration_ms_sum\":10001"));
        assert!(snapshot.contains("\"target_connect_duration_ms_le_10000\":0"));
        assert!(snapshot.contains("\"target_connect_duration_ms_le_inf\":1"));
        for field in snapshot
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
        {
            let (_, value) = field.split_once(':').expect("fixed JSON field");
            assert!(
                !value.is_empty() && value.chars().all(|character| character.is_ascii_digit()),
                "metrics JSON values must remain numeric"
            );
        }
        for private_value in [
            "private.example",
            "192.0.2.25",
            "u_private",
            "secret-value",
            "https://private.example/path",
        ] {
            assert!(!snapshot.contains(private_value));
        }
    }

    #[test]
    fn typed_h2_send_stall_is_counted_once() {
        let metrics = ServerRuntimeMetrics::default();
        metrics.record_h2_request_error(&anyhow::Error::new(relay::H2SendStall));

        let snapshot = metrics.json_snapshot();
        assert!(snapshot.contains("\"h2_send_stalls\":1"));
        assert!(snapshot.contains("\"h2_stream_resets\":0"));
    }
}
