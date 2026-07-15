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

    pub(crate) fn json_snapshot(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"authenticated_sessions\":{},",
                "\"unauthenticated_rejections\":{},",
                "\"fallback_requests\":{},",
                "\"fallback_overload_rejections\":{},",
                "\"tcp_flows\":{},",
                "\"dns_queries\":{},",
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
