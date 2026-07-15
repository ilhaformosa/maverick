use rand::rngs::OsRng;
use rand::TryRngCore;
use std::time::Duration;

use crate::config::{Mode, ShapingConfig};
use crate::frame::{Frame, FrameType, FRAME_HEADER_LEN};

pub trait PaddingPolicy: Send + Sync {
    fn pad_outgoing_frame(&self, frame_type: FrameType, payload_len: usize) -> usize;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaddingKind {
    None,
    Light,
    Auto,
    Private,
}

#[derive(Clone, Copy, Debug)]
pub struct BasicPaddingPolicy {
    kind: PaddingKind,
    max_padding: usize,
}

impl BasicPaddingPolicy {
    pub fn new(kind: PaddingKind) -> Self {
        Self {
            kind,
            max_padding: 32,
        }
    }

    pub fn random_padding_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        if len > 0 {
            let _ = OsRng.try_fill_bytes(&mut bytes);
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ShapingBounds {
    pub max_padding_bytes_per_frame: usize,
    pub max_overhead_ratio: f64,
    pub max_delay_ms: u64,
    pub max_batch_bytes: usize,
}

impl Default for ShapingBounds {
    fn default() -> Self {
        Self {
            max_padding_bytes_per_frame: 256,
            max_overhead_ratio: 0.25,
            max_delay_ms: 20,
            max_batch_bytes: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BudgetedPaddingPolicy {
    kind: PaddingKind,
    bounds: ShapingBounds,
}

impl BudgetedPaddingPolicy {
    pub fn new(kind: PaddingKind, bounds: ShapingBounds) -> Self {
        Self { kind, bounds }
    }

    fn overhead_cap(&self, payload_len: usize) -> usize {
        if !self.bounds.max_overhead_ratio.is_finite() || self.bounds.max_overhead_ratio <= 0.0 {
            return 0;
        }
        ((payload_len as f64) * self.bounds.max_overhead_ratio).floor() as usize
    }
}

impl From<&ShapingConfig> for ShapingBounds {
    fn from(config: &ShapingConfig) -> Self {
        Self {
            max_padding_bytes_per_frame: config.max_padding_bytes_per_frame as usize,
            max_overhead_ratio: config.max_overhead_ratio,
            max_delay_ms: config.max_delay_ms,
            max_batch_bytes: config.max_batch_bytes as usize,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimePadding {
    enabled: bool,
    policy: BudgetedPaddingPolicy,
}

impl RuntimePadding {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            policy: BudgetedPaddingPolicy::new(PaddingKind::None, ShapingBounds::default()),
        }
    }

    pub fn from_config(mode: Mode, config: &ShapingConfig) -> Self {
        if !config.enabled || mode == Mode::Stable {
            return Self::disabled();
        }
        let kind = match mode {
            Mode::Auto => PaddingKind::Auto,
            Mode::Private => PaddingKind::Private,
            Mode::Stable => unreachable!("stable mode shaping is disabled above"),
        };
        Self {
            enabled: true,
            policy: BudgetedPaddingPolicy::new(kind, ShapingBounds::from(config)),
        }
    }

    pub fn padding_frame(
        &self,
        frame_type: FrameType,
        payload_len: usize,
        max_frame_size: usize,
    ) -> Option<Frame> {
        if !self.enabled || max_frame_size == 0 {
            return None;
        }
        let padding_len = self
            .policy
            .pad_outgoing_frame(frame_type, payload_len)
            .min(max_frame_size);
        if padding_len == 0 {
            return None;
        }
        Some(Frame::new(
            FrameType::Padding,
            0,
            0,
            BasicPaddingPolicy::random_padding_bytes(padding_len),
        ))
    }

    pub fn pacing_delay(&self, frame_type: FrameType, payload_len: usize) -> Option<Duration> {
        if !self.enabled || !is_delay_eligible(frame_type) {
            return None;
        }
        if payload_len >= self.policy.bounds.max_batch_bytes {
            return None;
        }
        let delay_ms = match self.policy.kind {
            PaddingKind::None => 0,
            PaddingKind::Light => self.policy.bounds.max_delay_ms.min(1),
            PaddingKind::Auto => self.policy.bounds.max_delay_ms.min(5),
            PaddingKind::Private => self.policy.bounds.max_delay_ms,
        };
        (delay_ms > 0).then(|| Duration::from_millis(delay_ms))
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeCoverTraffic {
    mode: Mode,
    config: ShapingConfig,
    operator_policy: CoverTrafficOperatorPolicy,
}

impl RuntimeCoverTraffic {
    pub fn disabled() -> Self {
        Self {
            mode: Mode::Stable,
            config: ShapingConfig::default(),
            operator_policy: CoverTrafficOperatorPolicy::disabled(),
        }
    }

    pub fn from_config(mode: Mode, config: &ShapingConfig) -> Self {
        if !config.enabled || !config.cover_traffic || mode == Mode::Stable {
            return Self::disabled();
        }
        let operator_policy = if config.cover_traffic_operator_approved {
            CoverTrafficOperatorPolicy::approved(Duration::from_millis(
                config.cover_traffic_window_ms,
            ))
        } else {
            CoverTrafficOperatorPolicy::disabled()
        };
        Self {
            mode,
            config: config.clone(),
            operator_policy,
        }
    }

    pub fn padding_frames(
        &self,
        frame_type: FrameType,
        observed_payload_bytes: usize,
        max_frame_size: usize,
    ) -> Vec<Frame> {
        if !is_delay_eligible(frame_type) || observed_payload_bytes == 0 || max_frame_size == 0 {
            return Vec::new();
        }
        let decision = cover_traffic_decision(
            self.mode,
            &self.config,
            observed_payload_bytes,
            self.operator_policy,
        );
        let Some(mut plan) = decision.plan else {
            return Vec::new();
        };
        plan.frame_payload_bytes = plan.frame_payload_bytes.min(max_frame_size);
        plan.max_bytes_per_window = plan.max_bytes_per_window.min(max_frame_size);
        plan.max_frames_per_window = plan.max_frames_per_window.min(1);
        CoverTrafficEmitter::new(plan)
            .next_padding_frame()
            .into_iter()
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeBatcher {
    enabled: bool,
    bounds: ShapingBounds,
    pending: Vec<Frame>,
    pending_bytes: usize,
}

impl RuntimeBatcher {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            bounds: ShapingBounds::default(),
            pending: Vec::new(),
            pending_bytes: 0,
        }
    }

    pub fn from_config(mode: Mode, config: &ShapingConfig) -> Self {
        if !config.enabled || mode == Mode::Stable || config.max_delay_ms == 0 {
            return Self::disabled();
        }
        Self {
            enabled: true,
            bounds: ShapingBounds::from(config),
            pending: Vec::new(),
            pending_bytes: 0,
        }
    }

    pub fn push(&mut self, frame: Frame) -> Vec<Frame> {
        if !self.enabled || !is_batch_eligible(frame.frame_type, frame.payload.len(), self.bounds) {
            let mut ready = self.flush();
            ready.push(frame);
            return ready;
        }

        self.pending_bytes += batch_cost(&frame);
        self.pending.push(frame);
        if self.pending_bytes >= self.bounds.max_batch_bytes {
            return self.flush();
        }
        Vec::new()
    }

    pub fn flush_due(&mut self, elapsed_since_first_frame: Duration) -> Vec<Frame> {
        if !self.pending.is_empty()
            && elapsed_since_first_frame >= Duration::from_millis(self.bounds.max_delay_ms)
        {
            return self.flush();
        }
        Vec::new()
    }

    pub fn flush(&mut self) -> Vec<Frame> {
        self.pending_bytes = 0;
        std::mem::take(&mut self.pending)
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn flush_delay(&self) -> Option<Duration> {
        (self.enabled && !self.pending.is_empty())
            .then(|| Duration::from_millis(self.bounds.max_delay_ms))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverTrafficPlan {
    pub max_frames_per_window: usize,
    pub max_bytes_per_window: usize,
    pub frame_payload_bytes: usize,
    pub spacing: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverTrafficOperatorPolicy {
    pub operator_approved: bool,
    pub window: Duration,
}

impl CoverTrafficOperatorPolicy {
    pub fn disabled() -> Self {
        Self {
            operator_approved: false,
            window: Duration::from_secs(1),
        }
    }

    pub fn approved(window: Duration) -> Self {
        Self {
            operator_approved: true,
            window,
        }
    }
}

impl Default for CoverTrafficOperatorPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverTrafficDecisionReason {
    Ready,
    Disabled,
    StableMode,
    MissingOperatorApproval,
    InvalidWindow,
    MissingObservedPayloadBudget,
    BudgetUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverTrafficDecision {
    pub reason: CoverTrafficDecisionReason,
    pub plan: Option<CoverTrafficPlan>,
}

impl CoverTrafficDecision {
    pub fn ready(plan: CoverTrafficPlan) -> Self {
        Self {
            reason: CoverTrafficDecisionReason::Ready,
            plan: Some(plan),
        }
    }

    pub fn rejected(reason: CoverTrafficDecisionReason) -> Self {
        Self { reason, plan: None }
    }

    pub fn is_ready(&self) -> bool {
        self.reason == CoverTrafficDecisionReason::Ready && self.plan.is_some()
    }
}

#[derive(Clone, Debug)]
pub struct CoverTrafficEmitter {
    plan: CoverTrafficPlan,
    emitted_frames: usize,
    emitted_bytes: usize,
}

impl CoverTrafficEmitter {
    pub fn new(plan: CoverTrafficPlan) -> Self {
        Self {
            plan,
            emitted_frames: 0,
            emitted_bytes: 0,
        }
    }

    pub fn next_padding_frame(&mut self) -> Option<Frame> {
        if self.emitted_frames >= self.plan.max_frames_per_window
            || self.emitted_bytes >= self.plan.max_bytes_per_window
        {
            return None;
        }

        let remaining_bytes = self.plan.max_bytes_per_window - self.emitted_bytes;
        let payload_len = self.plan.frame_payload_bytes.min(remaining_bytes);
        if payload_len == 0 {
            return None;
        }

        self.emitted_frames += 1;
        self.emitted_bytes += payload_len;
        Some(Frame::new(
            FrameType::Padding,
            0,
            0,
            BasicPaddingPolicy::random_padding_bytes(payload_len),
        ))
    }

    pub fn emitted_frames(&self) -> usize {
        self.emitted_frames
    }

    pub fn emitted_bytes(&self) -> usize {
        self.emitted_bytes
    }
}

pub fn cover_traffic_decision(
    mode: Mode,
    config: &ShapingConfig,
    observed_payload_bytes: usize,
    operator_policy: CoverTrafficOperatorPolicy,
) -> CoverTrafficDecision {
    if !config.enabled || !config.cover_traffic {
        return CoverTrafficDecision::rejected(CoverTrafficDecisionReason::Disabled);
    }
    if mode == Mode::Stable {
        return CoverTrafficDecision::rejected(CoverTrafficDecisionReason::StableMode);
    }
    if !operator_policy.operator_approved {
        return CoverTrafficDecision::rejected(CoverTrafficDecisionReason::MissingOperatorApproval);
    }
    if operator_policy.window.is_zero() {
        return CoverTrafficDecision::rejected(CoverTrafficDecisionReason::InvalidWindow);
    }
    if observed_payload_bytes == 0 {
        return CoverTrafficDecision::rejected(
            CoverTrafficDecisionReason::MissingObservedPayloadBudget,
        );
    }
    match cover_traffic_plan(mode, config, observed_payload_bytes, operator_policy.window) {
        Some(plan) => CoverTrafficDecision::ready(plan),
        None => CoverTrafficDecision::rejected(CoverTrafficDecisionReason::BudgetUnavailable),
    }
}

pub fn cover_traffic_plan(
    mode: Mode,
    config: &ShapingConfig,
    observed_payload_bytes: usize,
    window: Duration,
) -> Option<CoverTrafficPlan> {
    if mode == Mode::Stable
        || !config.enabled
        || !config.cover_traffic
        || observed_payload_bytes == 0
        || window.is_zero()
    {
        return None;
    }

    let bounds = ShapingBounds::from(config);
    if !bounds.max_overhead_ratio.is_finite() || bounds.max_overhead_ratio <= 0.0 {
        return None;
    }

    let overhead_budget =
        ((observed_payload_bytes as f64) * bounds.max_overhead_ratio).floor() as usize;
    let max_bytes = overhead_budget.min(bounds.max_batch_bytes);
    if max_bytes == 0 {
        return None;
    }

    let frame_payload_bytes = bounds.max_padding_bytes_per_frame.min(max_bytes);
    if frame_payload_bytes == 0 {
        return None;
    }
    let max_frames = max_bytes.div_ceil(frame_payload_bytes);
    let spacing_ms = (window.as_millis() / max_frames as u128).max(1) as u64;

    Some(CoverTrafficPlan {
        max_frames_per_window: max_frames,
        max_bytes_per_window: max_bytes,
        frame_payload_bytes,
        spacing: Duration::from_millis(spacing_ms),
    })
}

fn is_delay_eligible(frame_type: FrameType) -> bool {
    !matches!(
        frame_type,
        FrameType::ClientHello
            | FrameType::ServerHello
            | FrameType::TcpFin
            | FrameType::TcpReset
            | FrameType::CloseFlow
            | FrameType::Error
            | FrameType::Padding
    )
}

fn is_batch_eligible(frame_type: FrameType, payload_len: usize, bounds: ShapingBounds) -> bool {
    is_delay_eligible(frame_type) && batch_cost_for_payload(payload_len) < bounds.max_batch_bytes
}

fn batch_cost(frame: &Frame) -> usize {
    batch_cost_for_payload(frame.payload.len())
}

fn batch_cost_for_payload(payload_len: usize) -> usize {
    FRAME_HEADER_LEN + payload_len
}

impl PaddingPolicy for BudgetedPaddingPolicy {
    fn pad_outgoing_frame(&self, frame_type: FrameType, payload_len: usize) -> usize {
        if matches!(
            frame_type,
            FrameType::ClientHello | FrameType::ServerHello | FrameType::Error | FrameType::Padding
        ) {
            return 0;
        }
        let cap = self
            .bounds
            .max_padding_bytes_per_frame
            .min(self.overhead_cap(payload_len));
        match self.kind {
            PaddingKind::None => 0,
            PaddingKind::Light => cap.min(16),
            PaddingKind::Auto => cap.min(64),
            PaddingKind::Private => cap,
        }
    }
}

impl PaddingPolicy for BasicPaddingPolicy {
    fn pad_outgoing_frame(&self, frame_type: FrameType, payload_len: usize) -> usize {
        match self.kind {
            PaddingKind::None => 0,
            PaddingKind::Light | PaddingKind::Auto | PaddingKind::Private => {
                if matches!(
                    frame_type,
                    FrameType::ClientHello | FrameType::ServerHello | FrameType::Padding
                ) {
                    0
                } else if payload_len < 64 {
                    8.min(self.max_padding)
                } else {
                    0
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_is_bounded() {
        let policy = BasicPaddingPolicy::new(PaddingKind::Private);
        assert!(policy.pad_outgoing_frame(FrameType::TcpData, 1) <= 32);
        assert_eq!(policy.pad_outgoing_frame(FrameType::ClientHello, 1), 0);
    }

    #[test]
    fn budgeted_padding_respects_overhead_ratio_and_cap() {
        let policy = BudgetedPaddingPolicy::new(
            PaddingKind::Private,
            ShapingBounds {
                max_padding_bytes_per_frame: 256,
                max_overhead_ratio: 0.25,
                max_delay_ms: 20,
                max_batch_bytes: 65_536,
            },
        );
        assert_eq!(policy.pad_outgoing_frame(FrameType::TcpData, 1_000), 250);
        assert_eq!(policy.pad_outgoing_frame(FrameType::TcpData, 2_000), 256);
    }

    #[test]
    fn budgeted_padding_skips_handshake_and_error_frames() {
        let policy = BudgetedPaddingPolicy::new(PaddingKind::Private, ShapingBounds::default());
        assert_eq!(policy.pad_outgoing_frame(FrameType::ClientHello, 1_000), 0);
        assert_eq!(policy.pad_outgoing_frame(FrameType::ServerHello, 1_000), 0);
        assert_eq!(policy.pad_outgoing_frame(FrameType::Error, 1_000), 0);
    }

    #[test]
    fn budgeted_padding_modes_are_monotonic() {
        let bounds = ShapingBounds::default();
        let light = BudgetedPaddingPolicy::new(PaddingKind::Light, bounds);
        let auto = BudgetedPaddingPolicy::new(PaddingKind::Auto, bounds);
        let private = BudgetedPaddingPolicy::new(PaddingKind::Private, bounds);
        assert!(
            light.pad_outgoing_frame(FrameType::TcpData, 1_000)
                <= auto.pad_outgoing_frame(FrameType::TcpData, 1_000)
        );
        assert!(
            auto.pad_outgoing_frame(FrameType::TcpData, 1_000)
                <= private.pad_outgoing_frame(FrameType::TcpData, 1_000)
        );
    }

    #[test]
    fn runtime_padding_builds_padding_frames_when_enabled() {
        let config = ShapingConfig {
            enabled: true,
            max_padding_bytes_per_frame: 64,
            max_overhead_ratio: 0.5,
            ..ShapingConfig::default()
        };
        let runtime = RuntimePadding::from_config(Mode::Private, &config);
        let frame = runtime
            .padding_frame(FrameType::TcpData, 100, 65_536)
            .unwrap();
        assert_eq!(frame.frame_type, FrameType::Padding);
        assert_eq!(frame.flow_id, 0);
        assert_eq!(frame.payload.len(), 50);
    }

    #[test]
    fn runtime_padding_skips_when_disabled_or_unsafe() {
        let config = ShapingConfig::default();
        let runtime = RuntimePadding::from_config(Mode::Private, &config);
        assert!(runtime
            .padding_frame(FrameType::TcpData, 100, 65_536)
            .is_none());

        let enabled = ShapingConfig {
            enabled: true,
            ..ShapingConfig::default()
        };
        let runtime = RuntimePadding::from_config(Mode::Private, &enabled);
        assert!(runtime
            .padding_frame(FrameType::ClientHello, 100, 65_536)
            .is_none());
        assert!(runtime
            .padding_frame(FrameType::Padding, 100, 65_536)
            .is_none());
    }

    #[test]
    fn runtime_pacing_delay_is_bounded_by_mode() {
        let config = ShapingConfig {
            enabled: true,
            max_delay_ms: 20,
            max_batch_bytes: 65_536,
            ..ShapingConfig::default()
        };
        assert!(RuntimePadding::from_config(Mode::Stable, &config)
            .pacing_delay(FrameType::TcpData, 100)
            .is_none());
        assert_eq!(
            RuntimePadding::from_config(Mode::Auto, &config)
                .pacing_delay(FrameType::TcpData, 100)
                .unwrap(),
            std::time::Duration::from_millis(5)
        );
        assert_eq!(
            RuntimePadding::from_config(Mode::Private, &config)
                .pacing_delay(FrameType::TcpData, 100)
                .unwrap(),
            std::time::Duration::from_millis(20)
        );
    }

    #[test]
    fn runtime_padding_stable_mode_disables_optional_shaping() {
        let config = ShapingConfig {
            enabled: true,
            max_padding_bytes_per_frame: 64,
            max_overhead_ratio: 0.5,
            max_delay_ms: 20,
            ..ShapingConfig::default()
        };
        let runtime = RuntimePadding::from_config(Mode::Stable, &config);
        assert!(runtime
            .padding_frame(FrameType::TcpData, 100, 65_536)
            .is_none());
        assert!(runtime.pacing_delay(FrameType::TcpData, 100).is_none());

        let mut batcher = RuntimeBatcher::from_config(Mode::Stable, &config);
        let ready = batcher.push(Frame::new(FrameType::TcpData, 0, 1, b"data".as_ref()));
        assert_eq!(ready.len(), 1);
        assert!(batcher.is_empty());
    }

    #[test]
    fn runtime_pacing_delay_skips_control_and_large_frames() {
        let config = ShapingConfig {
            enabled: true,
            max_delay_ms: 20,
            max_batch_bytes: 100,
            ..ShapingConfig::default()
        };
        let runtime = RuntimePadding::from_config(Mode::Private, &config);
        assert!(runtime.pacing_delay(FrameType::ClientHello, 10).is_none());
        assert!(runtime.pacing_delay(FrameType::TcpFin, 10).is_none());
        assert!(runtime.pacing_delay(FrameType::TcpReset, 10).is_none());
        assert!(runtime.pacing_delay(FrameType::CloseFlow, 10).is_none());
        assert!(runtime.pacing_delay(FrameType::TcpData, 100).is_none());
    }

    #[test]
    fn runtime_batcher_flushes_on_byte_cap() {
        let config = ShapingConfig {
            enabled: true,
            max_delay_ms: 20,
            max_batch_bytes: 36,
            ..ShapingConfig::default()
        };
        let mut batcher = RuntimeBatcher::from_config(Mode::Private, &config);
        assert!(batcher
            .push(Frame::new(FrameType::TcpData, 0, 1, b"abcd".as_ref()))
            .is_empty());
        let ready = batcher.push(Frame::new(FrameType::TcpData, 0, 2, b"efgh".as_ref()));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].flow_id, 1);
        assert_eq!(ready[1].flow_id, 2);
        assert!(batcher.is_empty());
    }

    #[test]
    fn runtime_batcher_flushes_on_time_cap() {
        let config = ShapingConfig {
            enabled: true,
            max_delay_ms: 20,
            max_batch_bytes: 1_024,
            ..ShapingConfig::default()
        };
        let mut batcher = RuntimeBatcher::from_config(Mode::Private, &config);
        assert!(batcher
            .push(Frame::new(FrameType::TcpData, 0, 7, b"payload".as_ref()))
            .is_empty());
        assert!(batcher.flush_due(Duration::from_millis(19)).is_empty());
        let ready = batcher.flush_due(Duration::from_millis(20));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].flow_id, 7);
        assert!(batcher.is_empty());
    }

    #[test]
    fn runtime_batcher_does_not_delay_fin_or_reset() {
        let config = ShapingConfig {
            enabled: true,
            max_delay_ms: 20,
            max_batch_bytes: 1_024,
            ..ShapingConfig::default()
        };
        let mut batcher = RuntimeBatcher::from_config(Mode::Private, &config);
        assert!(batcher
            .push(Frame::new(FrameType::TcpData, 0, 9, b"payload".as_ref()))
            .is_empty());
        let ready = batcher.push(Frame::new(FrameType::TcpFin, 0, 9, b"".as_ref()));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].frame_type, FrameType::TcpData);
        assert_eq!(ready[1].frame_type, FrameType::TcpFin);
        assert!(batcher.is_empty());

        let ready = batcher.push(Frame::new(FrameType::TcpReset, 0, 9, b"".as_ref()));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].frame_type, FrameType::TcpReset);
    }

    #[test]
    fn cover_traffic_plan_is_disabled_by_default_and_in_stable_mode() {
        let disabled = ShapingConfig::default();
        assert_eq!(
            cover_traffic_plan(Mode::Private, &disabled, 4096, Duration::from_millis(1000)),
            None
        );

        let enabled = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            ..ShapingConfig::default()
        };
        assert_eq!(
            cover_traffic_plan(Mode::Stable, &enabled, 4096, Duration::from_millis(1000)),
            None
        );
    }

    #[test]
    fn cover_traffic_plan_requires_observed_payload_budget() {
        let config = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            max_overhead_ratio: 0.25,
            ..ShapingConfig::default()
        };
        assert_eq!(
            cover_traffic_plan(Mode::Private, &config, 0, Duration::from_millis(1000)),
            None
        );
        assert_eq!(
            cover_traffic_plan(Mode::Private, &config, 3, Duration::from_millis(1000)),
            None
        );
    }

    #[test]
    fn cover_traffic_plan_is_bounded_by_overhead_and_batch_cap() {
        let config = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            max_padding_bytes_per_frame: 64,
            max_overhead_ratio: 0.25,
            max_delay_ms: 20,
            max_batch_bytes: 96,
            cover_traffic_operator_approved: false,
            cover_traffic_window_ms: 1_000,
        };

        let plan =
            cover_traffic_plan(Mode::Private, &config, 1024, Duration::from_millis(1000)).unwrap();
        assert_eq!(
            plan,
            CoverTrafficPlan {
                max_frames_per_window: 2,
                max_bytes_per_window: 96,
                frame_payload_bytes: 64,
                spacing: Duration::from_millis(500),
            }
        );
    }

    #[test]
    fn cover_traffic_decision_requires_operator_approval() {
        let config = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            max_overhead_ratio: 0.25,
            ..ShapingConfig::default()
        };

        let decision = cover_traffic_decision(
            Mode::Private,
            &config,
            4096,
            CoverTrafficOperatorPolicy::disabled(),
        );
        assert_eq!(
            decision,
            CoverTrafficDecision::rejected(CoverTrafficDecisionReason::MissingOperatorApproval)
        );
        assert!(!decision.is_ready());
    }

    #[test]
    fn cover_traffic_decision_preserves_default_and_stable_gates() {
        let disabled = ShapingConfig::default();
        assert_eq!(
            cover_traffic_decision(
                Mode::Private,
                &disabled,
                4096,
                CoverTrafficOperatorPolicy::approved(Duration::from_secs(1)),
            ),
            CoverTrafficDecision::rejected(CoverTrafficDecisionReason::Disabled)
        );

        let enabled = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            ..ShapingConfig::default()
        };
        assert_eq!(
            cover_traffic_decision(
                Mode::Stable,
                &enabled,
                4096,
                CoverTrafficOperatorPolicy::approved(Duration::from_secs(1)),
            ),
            CoverTrafficDecision::rejected(CoverTrafficDecisionReason::StableMode)
        );
    }

    #[test]
    fn cover_traffic_decision_requires_valid_window_and_observed_payload() {
        let config = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            max_overhead_ratio: 0.25,
            ..ShapingConfig::default()
        };

        assert_eq!(
            cover_traffic_decision(
                Mode::Private,
                &config,
                4096,
                CoverTrafficOperatorPolicy::approved(Duration::ZERO),
            ),
            CoverTrafficDecision::rejected(CoverTrafficDecisionReason::InvalidWindow)
        );
        assert_eq!(
            cover_traffic_decision(
                Mode::Private,
                &config,
                0,
                CoverTrafficOperatorPolicy::approved(Duration::from_secs(1)),
            ),
            CoverTrafficDecision::rejected(
                CoverTrafficDecisionReason::MissingObservedPayloadBudget
            )
        );
    }

    #[test]
    fn cover_traffic_decision_reports_ready_plan_or_budget_unavailable() {
        let config = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            max_padding_bytes_per_frame: 64,
            max_overhead_ratio: 0.25,
            max_delay_ms: 20,
            max_batch_bytes: 96,
            cover_traffic_operator_approved: false,
            cover_traffic_window_ms: 1_000,
        };
        let policy = CoverTrafficOperatorPolicy::approved(Duration::from_millis(1000));

        let too_small = cover_traffic_decision(Mode::Private, &config, 3, policy);
        assert_eq!(
            too_small,
            CoverTrafficDecision::rejected(CoverTrafficDecisionReason::BudgetUnavailable)
        );

        let ready = cover_traffic_decision(Mode::Private, &config, 1024, policy);
        assert!(ready.is_ready());
        assert_eq!(
            ready.plan,
            Some(CoverTrafficPlan {
                max_frames_per_window: 2,
                max_bytes_per_window: 96,
                frame_payload_bytes: 64,
                spacing: Duration::from_millis(500),
            })
        );
    }

    #[test]
    fn runtime_cover_traffic_requires_runtime_gate_and_operator_approval() {
        let disabled = RuntimeCoverTraffic::from_config(Mode::Private, &ShapingConfig::default());
        assert!(disabled
            .padding_frames(FrameType::TcpData, 1024, 65_536)
            .is_empty());

        let missing_approval = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            cover_traffic_operator_approved: false,
            ..ShapingConfig::default()
        };
        assert!(
            RuntimeCoverTraffic::from_config(Mode::Private, &missing_approval)
                .padding_frames(FrameType::TcpData, 1024, 65_536)
                .is_empty()
        );
    }

    #[test]
    fn runtime_cover_traffic_emits_one_bounded_padding_frame() {
        let config = ShapingConfig {
            enabled: true,
            cover_traffic: true,
            cover_traffic_operator_approved: true,
            max_padding_bytes_per_frame: 64,
            max_overhead_ratio: 0.25,
            max_batch_bytes: 96,
            ..ShapingConfig::default()
        };
        let frames = RuntimeCoverTraffic::from_config(Mode::Private, &config).padding_frames(
            FrameType::TcpData,
            1024,
            65_536,
        );
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, FrameType::Padding);
        assert_eq!(frames[0].payload.len(), 64);

        assert!(RuntimeCoverTraffic::from_config(Mode::Private, &config)
            .padding_frames(FrameType::TcpFin, 1024, 65_536)
            .is_empty());
        assert!(RuntimeCoverTraffic::from_config(Mode::Stable, &config)
            .padding_frames(FrameType::TcpData, 1024, 65_536)
            .is_empty());
    }

    #[test]
    fn cover_traffic_emitter_produces_only_bounded_padding_frames() {
        let plan = CoverTrafficPlan {
            max_frames_per_window: 3,
            max_bytes_per_window: 150,
            frame_payload_bytes: 64,
            spacing: Duration::from_millis(250),
        };
        let mut emitter = CoverTrafficEmitter::new(plan);

        let first = emitter.next_padding_frame().unwrap();
        assert_eq!(first.frame_type, FrameType::Padding);
        assert_eq!(first.payload.len(), 64);
        assert_eq!(first.flow_id, 0);

        let second = emitter.next_padding_frame().unwrap();
        assert_eq!(second.frame_type, FrameType::Padding);
        assert_eq!(second.payload.len(), 64);

        let third = emitter.next_padding_frame().unwrap();
        assert_eq!(third.frame_type, FrameType::Padding);
        assert_eq!(third.payload.len(), 22);

        assert!(emitter.next_padding_frame().is_none());
        assert_eq!(emitter.emitted_frames(), 3);
        assert_eq!(emitter.emitted_bytes(), 150);
    }

    #[test]
    fn cover_traffic_emitter_respects_frame_count_cap_before_bytes() {
        let plan = CoverTrafficPlan {
            max_frames_per_window: 1,
            max_bytes_per_window: 150,
            frame_payload_bytes: 64,
            spacing: Duration::from_millis(250),
        };
        let mut emitter = CoverTrafficEmitter::new(plan);

        assert_eq!(emitter.next_padding_frame().unwrap().payload.len(), 64);
        assert!(emitter.next_padding_frame().is_none());
        assert_eq!(emitter.emitted_frames(), 1);
        assert_eq!(emitter.emitted_bytes(), 64);
    }
}
