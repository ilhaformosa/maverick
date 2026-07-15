use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub(crate) struct AuthFailureTracker {
    windows: HashMap<IpAddr, AuthFailureWindow>,
}

#[derive(Debug)]
struct AuthFailureWindow {
    started_at: Instant,
    failures: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthFailureDecision {
    AllowFallback,
    RateLimited,
}

impl AuthFailureTracker {
    pub(crate) fn record_failure(
        &mut self,
        peer_ip: IpAddr,
        now: Instant,
        window: Duration,
        max_failures_per_window: u32,
        max_entries: usize,
    ) -> AuthFailureDecision {
        self.prune_expired(now, window);
        if !self.windows.contains_key(&peer_ip) && self.windows.len() >= max_entries {
            return AuthFailureDecision::RateLimited;
        }

        let entry = self
            .windows
            .entry(peer_ip)
            .or_insert_with(|| AuthFailureWindow {
                started_at: now,
                failures: 0,
            });
        if now.duration_since(entry.started_at) >= window {
            entry.started_at = now;
            entry.failures = 0;
        }
        if entry.failures >= max_failures_per_window {
            return AuthFailureDecision::RateLimited;
        }
        entry.failures = entry.failures.saturating_add(1);
        AuthFailureDecision::AllowFallback
    }

    fn prune_expired(&mut self, now: Instant, window: Duration) {
        self.windows
            .retain(|_, entry| now.duration_since(entry.started_at) < window);
    }
}

#[derive(Clone, Default)]
pub(crate) struct ActiveStreamTracker {
    count: Arc<AtomicUsize>,
}

impl ActiveStreamTracker {
    pub(crate) fn active_count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    pub(crate) fn enter(&self) -> ActiveStreamGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        ActiveStreamGuard {
            tracker: self.clone(),
        }
    }

    fn leave(&self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct ActiveStreamGuard {
    tracker: ActiveStreamTracker,
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.tracker.leave();
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionLimitTracker {
    global_limit: usize,
    per_source_limit: usize,
    global_count: Arc<AtomicUsize>,
    source_counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionLimitRejection {
    Global,
    PerSource,
}

impl ConnectionLimitTracker {
    pub(crate) fn new(global_limit: usize, per_source_limit: usize) -> Self {
        Self {
            global_limit: global_limit.max(1),
            per_source_limit: per_source_limit.max(1),
            global_count: Arc::new(AtomicUsize::new(0)),
            source_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    pub(crate) fn active_count(&self) -> usize {
        self.global_count.load(Ordering::Acquire)
    }

    pub(crate) fn try_enter(
        &self,
        peer_ip: IpAddr,
    ) -> Result<ConnectionLimitGuard, ConnectionLimitRejection> {
        self.try_enter_global()?;
        let mut source_counts = self
            .source_counts
            .lock()
            .expect("connection limit tracker mutex poisoned");
        let source_count = source_counts.entry(peer_ip).or_insert(0);
        if *source_count >= self.per_source_limit {
            self.global_count.fetch_sub(1, Ordering::AcqRel);
            return Err(ConnectionLimitRejection::PerSource);
        }
        *source_count += 1;
        Ok(ConnectionLimitGuard {
            tracker: self.clone(),
            peer_ip,
        })
    }

    fn try_enter_global(&self) -> Result<(), ConnectionLimitRejection> {
        let mut current = self.global_count.load(Ordering::Acquire);
        loop {
            if current >= self.global_limit {
                return Err(ConnectionLimitRejection::Global);
            }
            match self.global_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn leave(&self, peer_ip: IpAddr) {
        self.global_count.fetch_sub(1, Ordering::AcqRel);
        let mut source_counts = self
            .source_counts
            .lock()
            .expect("connection limit tracker mutex poisoned");
        if let Some(source_count) = source_counts.get_mut(&peer_ip) {
            *source_count = source_count.saturating_sub(1);
            if *source_count == 0 {
                source_counts.remove(&peer_ip);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectionLimitGuard {
    tracker: ConnectionLimitTracker,
    peer_ip: IpAddr,
}

impl Drop for ConnectionLimitGuard {
    fn drop(&mut self) {
        self.tracker.leave(self.peer_ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_tracker_rate_limits_after_configured_window_count() {
        let mut tracker = AuthFailureTracker::default();
        let ip = "203.0.113.10".parse().unwrap();
        let now = Instant::now();

        assert_eq!(
            tracker.record_failure(ip, now, Duration::from_secs(60), 2, 16),
            AuthFailureDecision::AllowFallback
        );
        assert_eq!(
            tracker.record_failure(ip, now, Duration::from_secs(60), 2, 16),
            AuthFailureDecision::AllowFallback
        );
        assert_eq!(
            tracker.record_failure(ip, now, Duration::from_secs(60), 2, 16),
            AuthFailureDecision::RateLimited
        );
    }

    #[test]
    fn auth_failure_tracker_resets_after_window() {
        let mut tracker = AuthFailureTracker::default();
        let ip = "203.0.113.10".parse().unwrap();
        let now = Instant::now();
        assert_eq!(
            tracker.record_failure(ip, now, Duration::from_secs(60), 1, 16),
            AuthFailureDecision::AllowFallback
        );
        assert_eq!(
            tracker.record_failure(
                ip,
                now + Duration::from_secs(61),
                Duration::from_secs(60),
                1,
                16,
            ),
            AuthFailureDecision::AllowFallback
        );
    }

    #[test]
    fn active_stream_guard_updates_count_until_drop() {
        let tracker = ActiveStreamTracker::default();
        assert_eq!(tracker.active_count(), 0);
        let guard = tracker.enter();
        assert_eq!(tracker.active_count(), 1);
        drop(guard);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn connection_limit_tracker_enforces_global_limit() {
        let tracker = ConnectionLimitTracker::new(1, 8);
        let first_ip = "203.0.113.10".parse().unwrap();
        let second_ip = "203.0.113.11".parse().unwrap();

        let guard = tracker.try_enter(first_ip).unwrap();
        assert_eq!(
            tracker.try_enter(second_ip).unwrap_err(),
            ConnectionLimitRejection::Global
        );
        assert_eq!(tracker.active_count(), 1);

        drop(guard);
        assert!(tracker.try_enter(second_ip).is_ok());
    }

    #[test]
    fn connection_limit_tracker_enforces_per_source_limit() {
        let tracker = ConnectionLimitTracker::new(8, 1);
        let ip = "203.0.113.10".parse().unwrap();

        let guard = tracker.try_enter(ip).unwrap();
        assert_eq!(
            tracker.try_enter(ip).unwrap_err(),
            ConnectionLimitRejection::PerSource
        );
        assert_eq!(tracker.active_count(), 1);

        drop(guard);
        assert!(tracker.try_enter(ip).is_ok());
    }
}
