use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use maverick_core::config::{PreviousCredentialConfig, SecretString, UserConfig};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct UserStore {
    active: HashMap<String, UserConfig>,
    previous: HashMap<String, PreviousCredential>,
}

impl UserStore {
    pub fn new(users: &[UserConfig]) -> Result<Self> {
        let mut active = HashMap::new();
        for user in users {
            if active.insert(user.id.clone(), user.clone()).is_some() {
                bail!("duplicate active user credential id");
            }
        }
        let mut previous = HashMap::new();
        for user in users {
            if let Some(rotation) = &user.rotation {
                for credential in &rotation.previous {
                    if active.contains_key(&credential.id) || previous.contains_key(&credential.id)
                    {
                        bail!("duplicate rotated credential id");
                    }
                    previous.insert(
                        credential.id.clone(),
                        PreviousCredential::from_config(user, credential)?,
                    );
                }
            }
        }
        Ok(Self { active, previous })
    }

    pub fn lookup_credential(
        &self,
        credential_id: &str,
        now_unix: i64,
    ) -> Option<CredentialMatch<'_>> {
        if let Some(user) = self.active.get(credential_id) {
            if user.enabled {
                return Some(CredentialMatch {
                    user,
                    secret: &user.secret,
                    state: CredentialState::Active,
                });
            }
            return None;
        }
        let previous = self.previous.get(credential_id)?;
        if previous.user.enabled && previous.is_valid_at(now_unix) {
            return Some(CredentialMatch {
                user: &previous.user,
                secret: &previous.secret,
                state: CredentialState::Previous,
            });
        }
        None
    }

    pub fn lookup_secret(
        &self,
        credential_id: &str,
        now_unix: i64,
    ) -> Option<CredentialSecretMatch<'_>> {
        if let Some(user) = self.active.get(credential_id) {
            if user.enabled {
                return Some(CredentialSecretMatch {
                    secret: &user.secret,
                    state: CredentialState::Active,
                });
            }
            return None;
        }
        let previous = self.previous.get(credential_id)?;
        if previous.user.enabled && previous.is_valid_at(now_unix) {
            return Some(CredentialSecretMatch {
                secret: &previous.secret,
                state: CredentialState::Previous,
            });
        }
        None
    }

    pub fn get(&self, id: &str) -> Option<&UserConfig> {
        self.active.get(id)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CredentialMatch<'a> {
    pub user: &'a UserConfig,
    pub secret: &'a SecretString,
    pub state: CredentialState,
}

#[derive(Clone, Copy, Debug)]
pub struct CredentialSecretMatch<'a> {
    pub secret: &'a SecretString,
    pub state: CredentialState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialState {
    Active,
    Previous,
}

impl CredentialState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Previous => "previous",
        }
    }
}

#[derive(Clone, Debug)]
struct PreviousCredential {
    user: UserConfig,
    secret: SecretString,
    not_before_unix: i64,
    not_after_unix: i64,
}

impl PreviousCredential {
    fn from_config(user: &UserConfig, credential: &PreviousCredentialConfig) -> Result<Self> {
        let not_before = parse_window_timestamp(&credential.not_before)
            .with_context(|| format!("invalid not_before for rotated credential {}", user.id))?;
        let not_after = parse_window_timestamp(&credential.not_after)
            .with_context(|| format!("invalid not_after for rotated credential {}", user.id))?;
        Ok(Self {
            user: user.clone(),
            secret: credential.secret.clone(),
            not_before_unix: not_before.unix_timestamp(),
            not_after_unix: not_after.unix_timestamp(),
        })
    }

    fn is_valid_at(&self, now_unix: i64) -> bool {
        self.not_before_unix <= now_unix && now_unix < self.not_after_unix
    }
}

fn parse_window_timestamp(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).context("parse RFC3339 timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;
    use maverick_core::config::{
        NextCredentialConfig, PreviousCredentialConfig, UserCredentialRotationConfig,
    };

    fn user(id: &str, enabled: bool, rotation: Option<UserCredentialRotationConfig>) -> UserConfig {
        UserConfig {
            id: id.into(),
            name: Some("alice".into()),
            secret: SecretString::generate(),
            enabled,
            rate_limit: None,
            max_concurrent_flows: None,
            rotation,
        }
    }

    fn previous(id: &str, not_before: &str, not_after: &str) -> PreviousCredentialConfig {
        PreviousCredentialConfig {
            id: id.into(),
            secret: SecretString::generate(),
            not_before: not_before.into(),
            not_after: not_after.into(),
        }
    }

    #[test]
    fn active_user_lookup() {
        let user = user("u_abc", true, None);
        let store = UserStore::new(&[user]).unwrap();
        assert!(store.get("u_abc").is_some());
        assert!(store.get("missing").is_none());
        let credential = store.lookup_credential("u_abc", 0).unwrap();
        assert_eq!(credential.user.id, "u_abc");
        assert_eq!(credential.state, CredentialState::Active);
    }

    #[test]
    fn previous_credential_maps_to_active_user_inside_window() {
        let old = previous(
            "u_abc_2026_06",
            "2026-06-01T00:00:00Z",
            "2026-07-15T00:00:00Z",
        );
        let old_secret = old.secret.clone();
        let active_user = user(
            "u_abc",
            true,
            Some(UserCredentialRotationConfig {
                previous: vec![old],
                next: Some(NextCredentialConfig {
                    id: "u_abc_2026_08".into(),
                    not_before: "2026-07-15T00:00:00Z".into(),
                }),
            }),
        );
        let store = UserStore::new(&[active_user]).unwrap();

        let credential = store
            .lookup_credential("u_abc_2026_06", 1_781_294_400)
            .unwrap();
        assert_eq!(credential.user.id, "u_abc");
        assert_eq!(credential.secret, &old_secret);
        assert_eq!(credential.state, CredentialState::Previous);
    }

    #[test]
    fn previous_credential_is_rejected_outside_window() {
        let old = previous(
            "u_abc_2026_06",
            "2026-06-01T00:00:00Z",
            "2026-07-15T00:00:00Z",
        );
        let active_user = user(
            "u_abc",
            true,
            Some(UserCredentialRotationConfig {
                previous: vec![old],
                next: None,
            }),
        );
        let store = UserStore::new(&[active_user]).unwrap();

        assert!(store
            .lookup_credential("u_abc_2026_06", 1_780_000_000)
            .is_none());
        assert!(store
            .lookup_credential("u_abc_2026_06", 1_784_073_600)
            .is_none());
    }

    #[test]
    fn disabled_user_rejects_previous_credentials() {
        let old = previous(
            "u_abc_2026_06",
            "2026-06-01T00:00:00Z",
            "2026-07-15T00:00:00Z",
        );
        let user = user(
            "u_abc",
            false,
            Some(UserCredentialRotationConfig {
                previous: vec![old],
                next: None,
            }),
        );
        let store = UserStore::new(&[user]).unwrap();

        assert!(store.lookup_credential("u_abc", 1_781_294_400).is_none());
        assert!(store
            .lookup_credential("u_abc_2026_06", 1_781_294_400)
            .is_none());
    }

    #[test]
    fn rejects_duplicate_rotated_credential_ids() {
        let active_user = user(
            "u_abc",
            true,
            Some(UserCredentialRotationConfig {
                previous: vec![previous(
                    "u_other",
                    "2026-06-01T00:00:00Z",
                    "2026-07-15T00:00:00Z",
                )],
                next: None,
            }),
        );
        let other = user("u_other", true, None);

        assert!(UserStore::new(&[active_user, other]).is_err());
    }
}
