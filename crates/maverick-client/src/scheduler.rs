use std::time::Duration;

use maverick_core::Mode;

use crate::transport::TransportKind;

#[derive(Clone, Debug)]
pub struct SchedulerPolicy {
    pub mode: Mode,
    pub h3_enabled: bool,
    pub h3_cooldown: Duration,
}

impl SchedulerPolicy {
    pub fn for_mode(mode: Mode) -> Self {
        Self {
            mode,
            h3_enabled: false,
            h3_cooldown: Duration::from_secs(300),
        }
    }

    pub fn select_transport(&self, state: &SchedulerState) -> TransportKind {
        match self.mode {
            Mode::Stable => TransportKind::H2,
            Mode::Auto | Mode::Private => {
                if self.h3_enabled && !state.h3_in_cooldown {
                    TransportKind::H3
                } else {
                    TransportKind::H2
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SchedulerState {
    h3_in_cooldown: bool,
}

impl SchedulerState {
    pub fn mark_failed(&mut self, transport: TransportKind) {
        if transport == TransportKind::H3 {
            self.h3_in_cooldown = true;
        }
    }

    pub fn clear_cooldown(&mut self, transport: TransportKind) {
        if transport == TransportKind::H3 {
            self.h3_in_cooldown = false;
        }
    }

    pub fn h3_in_cooldown(&self) -> bool {
        self.h3_in_cooldown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_mode_always_selects_h2() {
        let mut policy = SchedulerPolicy::for_mode(Mode::Stable);
        policy.h3_enabled = true;
        assert_eq!(
            policy.select_transport(&SchedulerState::default()),
            TransportKind::H2
        );
    }

    #[test]
    fn auto_mode_selects_h2_until_h3_is_enabled() {
        let mut policy = SchedulerPolicy::for_mode(Mode::Auto);
        assert_eq!(
            policy.select_transport(&SchedulerState::default()),
            TransportKind::H2
        );
        policy.h3_enabled = true;
        assert_eq!(
            policy.select_transport(&SchedulerState::default()),
            TransportKind::H3
        );
    }

    #[test]
    fn h3_cooldown_falls_back_to_h2() {
        let mut policy = SchedulerPolicy::for_mode(Mode::Auto);
        policy.h3_enabled = true;
        let mut state = SchedulerState::default();
        state.mark_failed(TransportKind::H3);
        assert!(state.h3_in_cooldown());
        assert_eq!(policy.select_transport(&state), TransportKind::H2);
        state.clear_cooldown(TransportKind::H3);
        assert_eq!(policy.select_transport(&state), TransportKind::H3);
    }
}
