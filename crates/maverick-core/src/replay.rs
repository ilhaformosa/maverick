use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
struct ReplayEntry {
    nonce: [u8; 32],
    timestamp_unix: i64,
}

#[derive(Debug, Default)]
struct CredentialReplayState {
    keys: HashSet<[u8; 32]>,
    entries: Vec<ReplayEntry>,
}

/// Bounded in-memory replay cache for recent ClientHello nonces.
#[derive(Debug)]
pub struct ReplayCache {
    window_secs: i64,
    max_entries_per_credential: usize,
    max_credentials: usize,
    credentials: HashMap<String, CredentialReplayState>,
}

impl ReplayCache {
    pub fn new(
        window_secs: i64,
        max_entries_per_credential: usize,
        max_credentials: usize,
    ) -> Self {
        Self {
            window_secs,
            max_entries_per_credential,
            max_credentials,
            credentials: HashMap::new(),
        }
    }

    pub fn check_and_insert(
        &mut self,
        credential_id: &str,
        nonce: [u8; 32],
        timestamp_unix: i64,
        now_unix: i64,
    ) -> Result<()> {
        let oldest_allowed = now_unix
            .checked_sub(self.window_secs)
            .ok_or(Error::Replay("timestamp window underflow"))?;
        let newest_allowed = now_unix
            .checked_add(self.window_secs)
            .ok_or(Error::Replay("timestamp window overflow"))?;
        if timestamp_unix < oldest_allowed {
            return Err(Error::Replay("timestamp too old"));
        }
        if timestamp_unix > newest_allowed {
            return Err(Error::Replay("timestamp too new"));
        }
        self.cleanup(now_unix);
        if !self.credentials.contains_key(credential_id)
            && self.credentials.len() >= self.max_credentials
        {
            return Err(Error::Replay("replay cache credential limit reached"));
        }
        let state = self
            .credentials
            .entry(credential_id.to_owned())
            .or_default();
        if state.keys.contains(&nonce) {
            return Err(Error::Replay("duplicate nonce"));
        }
        if state.entries.len() >= self.max_entries_per_credential {
            return Err(Error::Replay("replay cache full"));
        }
        state.keys.insert(nonce);
        state.entries.push(ReplayEntry {
            nonce,
            timestamp_unix,
        });
        Ok(())
    }

    pub fn cleanup(&mut self, now_unix: i64) {
        let cutoff = now_unix.saturating_sub(self.window_secs);
        self.credentials.retain(|_, state| {
            state.entries.retain(|entry| {
                let keep = entry.timestamp_unix >= cutoff;
                if !keep {
                    state.keys.remove(&entry.nonce);
                }
                keep
            });
            !state.entries.is_empty()
        });
    }

    pub fn len(&self) -> usize {
        self.credentials
            .values()
            .map(|state| state.entries.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_insert_rejects_duplicate() {
        let mut cache = ReplayCache::new(120, 1024, 1024);
        let nonce = [1u8; 32];
        cache.check_and_insert("u", nonce, 100, 100).unwrap();
        assert!(cache.check_and_insert("u", nonce, 100, 100).is_err());
    }

    #[test]
    fn timestamp_window_enforced() {
        let mut cache = ReplayCache::new(10, 1024, 1024);
        assert!(cache.check_and_insert("u", [1u8; 32], 89, 100).is_err());
        assert!(cache.check_and_insert("u", [2u8; 32], 111, 100).is_err());
        assert!(cache.check_and_insert("u", [3u8; 32], 100, 100).is_ok());
    }

    #[test]
    fn timestamp_window_overflow_is_rejected() {
        let mut cache = ReplayCache::new(i64::MAX, 1024, 1024);
        assert!(cache.check_and_insert("u", [1u8; 32], 0, i64::MAX).is_err());
    }

    #[test]
    fn cache_full_rejects_new_entries() {
        let mut cache = ReplayCache::new(10, 2, 8);
        cache.check_and_insert("u", [1u8; 32], 100, 100).unwrap();
        cache.check_and_insert("u", [2u8; 32], 101, 101).unwrap();
        assert!(cache.check_and_insert("u", [3u8; 32], 102, 102).is_err());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn full_credential_does_not_block_other_credentials() {
        let mut cache = ReplayCache::new(10, 2, 8);
        cache.check_and_insert("u_a", [1u8; 32], 100, 100).unwrap();
        cache.check_and_insert("u_a", [2u8; 32], 101, 101).unwrap();
        assert!(cache.check_and_insert("u_a", [3u8; 32], 102, 102).is_err());
        cache.check_and_insert("u_b", [3u8; 32], 102, 102).unwrap();
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn credential_key_count_is_bounded() {
        let mut cache = ReplayCache::new(10, 8, 2);
        cache.check_and_insert("u_a", [1u8; 32], 100, 100).unwrap();
        cache.check_and_insert("u_b", [2u8; 32], 100, 100).unwrap();

        assert!(cache.check_and_insert("u_c", [3u8; 32], 100, 100).is_err());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cleanup_bounds_memory() {
        let mut cache = ReplayCache::new(10, 2, 8);
        cache.check_and_insert("u", [1u8; 32], 100, 100).unwrap();
        cache.check_and_insert("u", [2u8; 32], 101, 101).unwrap();
        cache.cleanup(200);
        assert_eq!(cache.len(), 0);
        cache.check_and_insert("u", [3u8; 32], 200, 200).unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cleanup_removes_expired_entries_after_future_dated_entries() {
        let mut cache = ReplayCache::new(10, 2, 8);
        cache.check_and_insert("u", [1u8; 32], 110, 100).unwrap();
        cache.check_and_insert("u", [2u8; 32], 100, 100).unwrap();

        cache.cleanup(111);

        assert_eq!(cache.len(), 1);
        cache.check_and_insert("u", [3u8; 32], 111, 111).unwrap();
        assert_eq!(cache.len(), 2);
    }
}
