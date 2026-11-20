use std::sync::atomic::{AtomicU64, Ordering};

use maverick_core::{config::UdpPolicy, ClientConfig};

use crate::transport::{default_transport_kind, TransportKind};

const TARGET: &str = "maverick::socks_udp";

/// One observation per open attempt. Dropping the owner also covers SOCKS
/// control closure and cancellation while opening or waiting for a reply.
pub(super) struct UdpObservation {
    session: u64,
    allowed: &'static str,
    carrier: &'static str,
    saw_reply: bool,
    end_stage: &'static str,
}

impl UdpObservation {
    pub(super) fn opening(config: &ClientConfig) -> Self {
        static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
        let (session, allowed) = if tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
            let policy = config.advanced.udp_policy;
            let allowed = match default_transport_kind(config) {
                TransportKind::H3
                    if config.advanced.auto_h3 && policy == Some(UdpPolicy::AllowReliable) =>
                {
                    "h3_native,h2_reliable"
                }
                TransportKind::H3 => "h3_native",
                TransportKind::H2 if policy.is_some() => "h2_reliable",
                TransportKind::H2 => "h2_legacy",
                TransportKind::CloudflareWs => "none",
            };
            (NEXT_SESSION.fetch_add(1, Ordering::Relaxed), allowed)
        } else {
            (0, "")
        };
        let observation = Self {
            session,
            allowed,
            carrier: "unknown",
            saw_reply: false,
            end_stage: "ended",
        };
        observation.report("opening");
        observation
    }

    pub(super) fn admitted(&mut self, carrier: &'static str) {
        self.carrier = carrier;
        self.report("admitted");
    }

    pub(super) fn open_failed(&mut self) {
        self.end_stage = "open_failed";
    }

    pub(super) fn received_reply(&mut self) {
        if !self.saw_reply {
            self.saw_reply = true;
            self.report("first_reply");
        }
    }

    fn report(&self, stage: &'static str) {
        if self.session != 0 {
            tracing::debug!(target: TARGET, "SOCKS UDP session={} stage={} allowed={} carrier={} target_reply={}",
                self.session, stage, self.allowed, self.carrier,
                if self.saw_reply { "observed" } else { "not_observed" });
        }
    }
}

impl Drop for UdpObservation {
    fn drop(&mut self) {
        self.report(self.end_stage);
    }
}
