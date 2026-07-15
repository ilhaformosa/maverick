use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    PlatformHelperOperation, PlatformHelperOutcome, PlatformHelperRequest, PlatformHelperResponse,
    PlatformRecoverySnapshot, PlatformRecoveryStatus,
};

pub type ReferenceClientFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait PlatformHelperTransport: Send {
    fn exchange(
        &mut self,
        request: PlatformHelperRequest,
    ) -> ReferenceClientFuture<'_, PlatformHelperResponse>;
}

pub trait PacketRuntimeControl: Send {
    fn start(&mut self) -> ReferenceClientFuture<'_, ()>;
    fn stop(&mut self) -> ReferenceClientFuture<'_, ()>;
    fn is_healthy(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceClientState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    CleanupRequired,
    Recovering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceClientErrorClass {
    Preflight,
    Apply,
    RuntimeStart,
    RuntimeHealth,
    RuntimeStop,
    Rollback,
    Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReferenceClientSnapshot {
    pub state: ReferenceClientState,
    pub recovery: PlatformRecoverySnapshot,
    pub last_error_class: Option<ReferenceClientErrorClass>,
}

pub struct ReferenceClientController<H, P> {
    helper: H,
    packet_runtime: P,
    allowed_journal_root: PathBuf,
    request_prefix: String,
    next_request_number: u64,
    state: ReferenceClientState,
    recovery: PlatformRecoverySnapshot,
    last_error_class: Option<ReferenceClientErrorClass>,
}

impl<H, P> ReferenceClientController<H, P>
where
    H: PlatformHelperTransport,
    P: PacketRuntimeControl,
{
    pub fn new(
        helper: H,
        packet_runtime: P,
        allowed_journal_root: impl Into<PathBuf>,
        request_prefix: impl Into<String>,
        recovery: PlatformRecoverySnapshot,
    ) -> Result<Self> {
        recovery.validate()?;
        let allowed_journal_root = allowed_journal_root.into();
        let request_prefix = request_prefix.into();
        validate_request_prefix(&request_prefix, &allowed_journal_root)?;

        Ok(Self {
            helper,
            packet_runtime,
            allowed_journal_root,
            request_prefix,
            next_request_number: 1,
            state: state_from_recovery(recovery),
            recovery,
            last_error_class: None,
        })
    }

    pub fn snapshot(&self) -> ReferenceClientSnapshot {
        ReferenceClientSnapshot {
            state: self.state,
            recovery: self.recovery,
            last_error_class: self.last_error_class,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        if self.state != ReferenceClientState::Disconnected || !self.recovery.connect_allowed() {
            anyhow::bail!("reference client is not ready to connect");
        }

        self.state = ReferenceClientState::Connecting;
        self.last_error_class = None;

        if self
            .exchange_expected(
                PlatformHelperOperation::Preflight,
                PlatformHelperOutcome::Ready,
            )
            .await
            .is_err()
        {
            return self.fail_from_recovery(
                ReferenceClientErrorClass::Preflight,
                "reference client preflight failed",
            );
        }

        if self
            .exchange_expected(
                PlatformHelperOperation::Apply,
                PlatformHelperOutcome::Applied,
            )
            .await
            .is_err()
        {
            return self.fail_from_recovery(
                ReferenceClientErrorClass::Apply,
                "reference client platform apply failed",
            );
        }

        if self.packet_runtime.start().await.is_err() {
            self.state = ReferenceClientState::Recovering;
            self.last_error_class = Some(ReferenceClientErrorClass::RuntimeStart);
            if self.stop_runtime_and_rollback().await.is_err() {
                if self.last_error_class == Some(ReferenceClientErrorClass::RuntimeStop) {
                    anyhow::bail!("reference client packet runtime cleanup failed");
                }
                anyhow::bail!("reference client recovery rollback failed");
            }
            anyhow::bail!("reference client packet runtime start failed");
        }
        if !self.packet_runtime.is_healthy() {
            self.state = ReferenceClientState::Recovering;
            self.last_error_class = Some(ReferenceClientErrorClass::RuntimeHealth);
            if self.stop_runtime_and_rollback().await.is_err() {
                if self.last_error_class == Some(ReferenceClientErrorClass::RuntimeStop) {
                    anyhow::bail!("reference client packet runtime cleanup failed");
                }
                anyhow::bail!("reference client recovery rollback failed");
            }
            anyhow::bail!("reference client packet runtime became unhealthy during startup");
        }

        self.state = ReferenceClientState::Connected;
        self.last_error_class = None;
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if self.state == ReferenceClientState::Disconnected {
            return Ok(());
        }
        if self.state != ReferenceClientState::Connected {
            anyhow::bail!("reference client is not ready to disconnect");
        }

        self.state = ReferenceClientState::Disconnecting;
        self.last_error_class = None;
        if self.stop_runtime_and_rollback().await.is_err() {
            if self.last_error_class == Some(ReferenceClientErrorClass::RuntimeStop) {
                anyhow::bail!("reference client packet runtime stop failed");
            }
            anyhow::bail!("reference client rollback failed");
        }

        self.last_error_class = None;
        Ok(())
    }

    pub async fn check_runtime_health(&mut self) -> Result<()> {
        if self.state != ReferenceClientState::Connected {
            anyhow::bail!("reference client is not connected");
        }
        if self.packet_runtime.is_healthy() {
            return Ok(());
        }

        self.state = ReferenceClientState::Recovering;
        self.last_error_class = Some(ReferenceClientErrorClass::RuntimeHealth);
        if self.stop_runtime_and_rollback().await.is_err() {
            if self.last_error_class == Some(ReferenceClientErrorClass::RuntimeStop) {
                anyhow::bail!("reference client packet runtime cleanup failed");
            }
            anyhow::bail!("reference client recovery rollback failed");
        }
        anyhow::bail!("reference client packet runtime became unhealthy");
    }

    pub async fn recover(&mut self) -> Result<()> {
        if !matches!(
            self.state,
            ReferenceClientState::Connecting
                | ReferenceClientState::Disconnecting
                | ReferenceClientState::CleanupRequired
                | ReferenceClientState::Recovering
        ) {
            anyhow::bail!("reference client recovery is not required");
        }

        self.state = ReferenceClientState::Recovering;
        self.last_error_class = None;
        if self.stop_runtime_and_rollback().await.is_err() {
            if self.last_error_class == Some(ReferenceClientErrorClass::RuntimeStop) {
                anyhow::bail!("reference client recovery runtime stop failed");
            }
            anyhow::bail!("reference client recovery rollback failed");
        }

        self.last_error_class = None;
        Ok(())
    }

    async fn stop_runtime_and_rollback(&mut self) -> Result<()> {
        let runtime_stop_failed = self.packet_runtime.stop().await.is_err();
        if self.rollback_after_failure().await.is_err() {
            self.last_error_class = Some(ReferenceClientErrorClass::Rollback);
            anyhow::bail!("reference client rollback failed");
        }
        if runtime_stop_failed {
            self.state = ReferenceClientState::CleanupRequired;
            self.last_error_class = Some(ReferenceClientErrorClass::RuntimeStop);
            anyhow::bail!("reference client packet runtime stop failed");
        }
        Ok(())
    }

    async fn rollback_after_failure(&mut self) -> Result<()> {
        self.state = ReferenceClientState::Recovering;
        match self
            .exchange_expected(
                PlatformHelperOperation::Rollback,
                PlatformHelperOutcome::RolledBack,
            )
            .await
        {
            Ok(()) => {
                self.state = ReferenceClientState::Disconnected;
                Ok(())
            }
            Err(_) => {
                self.state = state_from_recovery(self.recovery);
                if self.state == ReferenceClientState::Disconnected {
                    self.state = ReferenceClientState::CleanupRequired;
                }
                Err(anyhow::anyhow!("reference client rollback failed"))
            }
        }
    }

    async fn exchange_expected(
        &mut self,
        operation: PlatformHelperOperation,
        expected: PlatformHelperOutcome,
    ) -> Result<()> {
        let request = self.next_request(operation)?;
        let request_id = request.request_id.clone();
        let response = match self.helper.exchange(request).await {
            Ok(response) => response,
            Err(_) => {
                self.mark_apply_result_uncertain(operation);
                anyhow::bail!("reference client helper exchange failed");
            }
        };

        if response.validate().is_err() {
            if response.request_id == request_id && response.recovery.validate().is_ok() {
                self.recovery = response.recovery;
            }
            self.mark_apply_result_uncertain(operation);
            self.last_error_class = Some(ReferenceClientErrorClass::Protocol);
            anyhow::bail!("reference client helper response is invalid");
        }
        if response.request_id != request_id {
            self.mark_apply_result_uncertain(operation);
            self.last_error_class = Some(ReferenceClientErrorClass::Protocol);
            anyhow::bail!("reference client helper response id mismatch");
        }

        self.recovery = response.recovery;
        if response.outcome == PlatformHelperOutcome::Rejected {
            anyhow::bail!("reference client helper request was rejected");
        }
        if response.outcome != expected {
            self.mark_apply_result_uncertain(operation);
            self.last_error_class = Some(ReferenceClientErrorClass::Protocol);
            anyhow::bail!("reference client helper response outcome mismatch");
        }
        Ok(())
    }

    fn next_request(
        &mut self,
        operation: PlatformHelperOperation,
    ) -> Result<PlatformHelperRequest> {
        let request_id = format!("{}_{:016x}", self.request_prefix, self.next_request_number);
        self.next_request_number = self
            .next_request_number
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("reference client request counter exhausted"))?;
        PlatformHelperRequest::new(request_id, operation, &self.allowed_journal_root)
    }

    fn fail_from_recovery(
        &mut self,
        class: ReferenceClientErrorClass,
        message: &str,
    ) -> Result<()> {
        if self.last_error_class != Some(ReferenceClientErrorClass::Protocol) {
            self.last_error_class = Some(class);
        }
        if self.state != ReferenceClientState::CleanupRequired {
            self.state = state_from_recovery(self.recovery);
        }
        Err(anyhow::anyhow!(message.to_owned()))
    }

    fn mark_apply_result_uncertain(&mut self, operation: PlatformHelperOperation) {
        if operation == PlatformHelperOperation::Apply {
            self.state = ReferenceClientState::CleanupRequired;
        }
    }
}

fn validate_request_prefix(prefix: &str, allowed_journal_root: &Path) -> Result<()> {
    if prefix.is_empty() || prefix.len() > 40 {
        anyhow::bail!("reference client request prefix length is invalid");
    }
    if !prefix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!("reference client request prefix contains invalid characters");
    }
    PlatformHelperRequest::new(
        format!("{prefix}_{:016x}", 1),
        PlatformHelperOperation::Status,
        allowed_journal_root,
    )?;
    Ok(())
}

fn state_from_recovery(recovery: PlatformRecoverySnapshot) -> ReferenceClientState {
    match recovery.status {
        PlatformRecoveryStatus::Clean => ReferenceClientState::Disconnected,
        PlatformRecoveryStatus::CleanupRequired => ReferenceClientState::CleanupRequired,
        PlatformRecoveryStatus::Recovering => ReferenceClientState::Recovering,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformHelperErrorClass, PlatformRecoveryReason, PLATFORM_HELPER_IPC_VERSION};

    #[derive(Default)]
    struct FakeHelper {
        applied: bool,
        calls: Vec<PlatformHelperOperation>,
        fail_operation: Option<PlatformHelperOperation>,
        apply_before_transport_error: bool,
        apply_ready_after_mutation: bool,
        reject_apply: bool,
        reject_apply_clean: bool,
        applied_rollback_failure: bool,
        mismatch_response_id: bool,
        stall_apply_after_mutation: bool,
        stall_rollback_after_mutation: bool,
    }

    impl PlatformHelperTransport for FakeHelper {
        fn exchange(
            &mut self,
            request: PlatformHelperRequest,
        ) -> ReferenceClientFuture<'_, PlatformHelperResponse> {
            Box::pin(async move {
                self.calls.push(request.operation);
                if self.fail_operation == Some(request.operation) {
                    if request.operation == PlatformHelperOperation::Apply
                        && self.apply_before_transport_error
                    {
                        self.applied = true;
                    }
                    anyhow::bail!("private helper transport detail");
                }
                if request.operation == PlatformHelperOperation::Apply
                    && self.stall_apply_after_mutation
                {
                    self.applied = true;
                    std::future::pending::<()>().await;
                }
                if request.operation == PlatformHelperOperation::Rollback
                    && self.stall_rollback_after_mutation
                {
                    self.applied = false;
                    std::future::pending::<()>().await;
                }

                let request_id = if self.mismatch_response_id {
                    "wrong_response_id".into()
                } else {
                    request.request_id
                };
                let response = match request.operation {
                    PlatformHelperOperation::Preflight | PlatformHelperOperation::Status => {
                        PlatformHelperResponse {
                            version: PLATFORM_HELPER_IPC_VERSION,
                            request_id,
                            outcome: PlatformHelperOutcome::Ready,
                            recovery: clean_recovery(),
                            error_class: None,
                        }
                    }
                    PlatformHelperOperation::Apply if self.apply_ready_after_mutation => {
                        self.applied = true;
                        PlatformHelperResponse {
                            version: PLATFORM_HELPER_IPC_VERSION,
                            request_id,
                            outcome: PlatformHelperOutcome::Ready,
                            recovery: clean_recovery(),
                            error_class: None,
                        }
                    }
                    PlatformHelperOperation::Apply if self.reject_apply_clean => {
                        PlatformHelperResponse {
                            version: PLATFORM_HELPER_IPC_VERSION,
                            request_id,
                            outcome: PlatformHelperOutcome::Rejected,
                            recovery: clean_recovery(),
                            error_class: Some(PlatformHelperErrorClass::Permission),
                        }
                    }
                    PlatformHelperOperation::Apply if self.reject_apply => PlatformHelperResponse {
                        version: PLATFORM_HELPER_IPC_VERSION,
                        request_id,
                        outcome: PlatformHelperOutcome::Rejected,
                        recovery: cleanup_recovery(),
                        error_class: Some(PlatformHelperErrorClass::ApplyFailed),
                    },
                    PlatformHelperOperation::Apply => {
                        self.applied = true;
                        let recovery = if self.applied_rollback_failure {
                            rollback_failed_recovery()
                        } else {
                            cleanup_recovery()
                        };
                        PlatformHelperResponse {
                            version: PLATFORM_HELPER_IPC_VERSION,
                            request_id,
                            outcome: PlatformHelperOutcome::Applied,
                            recovery,
                            error_class: None,
                        }
                    }
                    PlatformHelperOperation::Rollback => {
                        self.applied = false;
                        PlatformHelperResponse {
                            version: PLATFORM_HELPER_IPC_VERSION,
                            request_id,
                            outcome: PlatformHelperOutcome::RolledBack,
                            recovery: clean_recovery(),
                            error_class: None,
                        }
                    }
                };
                Ok(response)
            })
        }
    }

    #[derive(Default)]
    struct FakePacketRuntime {
        active: bool,
        starts: usize,
        stops: usize,
        fail_start: bool,
        activate_before_start_error: bool,
        stall_start_after_effect: bool,
        fail_stop: bool,
        stall_stop_after_effect: bool,
        fail_health: bool,
    }

    impl PacketRuntimeControl for FakePacketRuntime {
        fn start(&mut self) -> ReferenceClientFuture<'_, ()> {
            Box::pin(async move {
                self.starts += 1;
                if self.fail_start {
                    if self.activate_before_start_error {
                        self.active = true;
                    }
                    anyhow::bail!("private packet runtime start detail");
                }
                if self.stall_start_after_effect {
                    self.active = true;
                    std::future::pending::<()>().await;
                }
                self.active = true;
                Ok(())
            })
        }

        fn stop(&mut self) -> ReferenceClientFuture<'_, ()> {
            Box::pin(async move {
                self.stops += 1;
                if self.stall_stop_after_effect {
                    self.active = false;
                    std::future::pending::<()>().await;
                }
                if self.fail_stop {
                    anyhow::bail!("private packet runtime stop detail");
                }
                self.active = false;
                Ok(())
            })
        }

        fn is_healthy(&self) -> bool {
            self.active && !self.fail_health
        }
    }

    fn clean_recovery() -> PlatformRecoverySnapshot {
        PlatformRecoverySnapshot {
            status: PlatformRecoveryStatus::Clean,
            reason: None,
            helper_journal_present: false,
        }
    }

    fn cleanup_recovery() -> PlatformRecoverySnapshot {
        PlatformRecoverySnapshot {
            status: PlatformRecoveryStatus::CleanupRequired,
            reason: Some(PlatformRecoveryReason::RetainedHelperJournal),
            helper_journal_present: true,
        }
    }

    fn rollback_failed_recovery() -> PlatformRecoverySnapshot {
        PlatformRecoverySnapshot {
            status: PlatformRecoveryStatus::CleanupRequired,
            reason: Some(PlatformRecoveryReason::RollbackFailed),
            helper_journal_present: true,
        }
    }

    fn controller(
        helper: FakeHelper,
        packet_runtime: FakePacketRuntime,
        recovery: PlatformRecoverySnapshot,
    ) -> Result<ReferenceClientController<FakeHelper, FakePacketRuntime>> {
        ReferenceClientController::new(
            helper,
            packet_runtime,
            "/var/lib/maverick-reference",
            "session_1",
            recovery,
        )
    }

    #[tokio::test]
    async fn repeated_connect_disconnect_is_ordered_and_bounded() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        for _ in 0..32 {
            controller.connect().await?;
            assert_eq!(controller.snapshot().state, ReferenceClientState::Connected);
            controller.disconnect().await?;
            assert_eq!(
                controller.snapshot().state,
                ReferenceClientState::Disconnected
            );
        }

        assert_eq!(controller.helper.calls.len(), 96);
        assert_eq!(controller.packet_runtime.starts, 32);
        assert_eq!(controller.packet_runtime.stops, 32);
        assert!(!controller.helper.applied);
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn cold_start_with_retained_journal_requires_recovery() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                applied: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            cleanup_recovery(),
        )?;

        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::CleanupRequired
        );
        assert!(controller.connect().await.is_err());
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert_eq!(
            controller.helper.calls,
            vec![PlatformHelperOperation::Rollback]
        );
        assert!(!controller.helper.applied);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_start_failure_rolls_back_without_leaking_detail() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime {
                fail_start: true,
                ..FakePacketRuntime::default()
            },
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client packet runtime start failed");
        assert!(!error.contains("private"));
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Disconnected,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::RuntimeStart),
            }
        );
        assert_eq!(
            controller.helper.calls,
            vec![
                PlatformHelperOperation::Preflight,
                PlatformHelperOperation::Apply,
                PlatformHelperOperation::Rollback,
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn partial_runtime_start_with_failed_stop_blocks_reconnect() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime {
                fail_start: true,
                activate_before_start_error: true,
                fail_stop: true,
                ..FakePacketRuntime::default()
            },
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client packet runtime cleanup failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::CleanupRequired,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::RuntimeStop),
            }
        );
        assert!(controller.packet_runtime.active);
        assert!(!controller.helper.applied);
        let calls_before_reconnect = controller.helper.calls.clone();
        assert!(controller.connect().await.is_err());
        assert_eq!(controller.helper.calls, calls_before_reconnect);

        controller.packet_runtime.fail_stop = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_health_failure_stops_and_rolls_back() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        controller.connect().await?;
        controller.check_runtime_health().await?;
        controller.packet_runtime.fail_health = true;

        let error = controller
            .check_runtime_health()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, "reference client packet runtime became unhealthy");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Disconnected,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::RuntimeHealth),
            }
        );
        assert_eq!(
            controller.helper.calls,
            vec![
                PlatformHelperOperation::Preflight,
                PlatformHelperOperation::Apply,
                PlatformHelperOperation::Rollback,
            ]
        );
        assert_eq!(controller.packet_runtime.stops, 1);
        assert!(!controller.packet_runtime.active);
        assert!(!controller.helper.applied);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_health_stop_failure_blocks_reconnect() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        controller.connect().await?;
        controller.packet_runtime.fail_health = true;
        controller.packet_runtime.fail_stop = true;

        let error = controller
            .check_runtime_health()
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, "reference client packet runtime cleanup failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::CleanupRequired,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::RuntimeStop),
            }
        );
        assert!(controller.packet_runtime.active);
        assert!(!controller.helper.applied);
        assert!(controller.connect().await.is_err());

        controller.packet_runtime.fail_health = false;
        controller.packet_runtime.fail_stop = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn unhealthy_runtime_never_reaches_connected_state() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime {
                fail_health: true,
                ..FakePacketRuntime::default()
            },
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(
            error,
            "reference client packet runtime became unhealthy during startup"
        );
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Disconnected,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::RuntimeHealth),
            }
        );
        assert_eq!(controller.packet_runtime.starts, 1);
        assert_eq!(controller.packet_runtime.stops, 1);
        assert!(!controller.packet_runtime.active);
        assert_eq!(
            controller.helper.calls,
            vec![
                PlatformHelperOperation::Preflight,
                PlatformHelperOperation::Apply,
                PlatformHelperOperation::Rollback,
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejected_apply_preserves_cleanup_required_state() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                reject_apply: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client platform apply failed");
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::CleanupRequired
        );
        assert_eq!(controller.packet_runtime.starts, 0);
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        Ok(())
    }

    #[tokio::test]
    async fn validated_clean_apply_rejection_does_not_require_recovery() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                reject_apply_clean: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client platform apply failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Disconnected,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::Apply),
            }
        );
        assert_eq!(controller.packet_runtime.starts, 0);
        let calls_before_retry = controller.helper.calls.len();
        let retry_error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(retry_error, "reference client platform apply failed");
        assert_eq!(controller.helper.calls.len(), calls_before_retry + 2);
        assert!(controller.recover().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn uncertain_apply_transport_result_requires_rollback() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                fail_operation: Some(PlatformHelperOperation::Apply),
                apply_before_transport_error: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client platform apply failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::CleanupRequired,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::Apply),
            }
        );
        assert_eq!(controller.packet_runtime.starts, 0);
        assert!(controller.helper.applied);
        let calls_before_reconnect = controller.helper.calls.clone();
        let reconnect_error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(reconnect_error, "reference client is not ready to connect");
        assert_eq!(controller.helper.calls, calls_before_reconnect);

        controller.helper.fail_operation = None;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        Ok(())
    }

    #[tokio::test]
    async fn uncertain_apply_protocol_result_requires_rollback() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                apply_ready_after_mutation: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client platform apply failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::CleanupRequired,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::Protocol),
            }
        );
        assert_eq!(controller.packet_runtime.starts, 0);
        assert!(controller.helper.applied);
        let calls_before_reconnect = controller.helper.calls.clone();
        let reconnect_error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(reconnect_error, "reference client is not ready to connect");
        assert_eq!(controller.helper.calls, calls_before_reconnect);

        controller.helper.apply_ready_after_mutation = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_connect_can_recover_uncertain_apply() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                stall_apply_after_mutation: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), controller.connect())
                .await
                .is_err()
        );
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Connecting,
                recovery: clean_recovery(),
                last_error_class: None,
            }
        );
        assert!(controller.helper.applied);
        assert_eq!(controller.packet_runtime.starts, 0);
        assert!(controller.connect().await.is_err());

        controller.helper.stall_apply_after_mutation = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_connect_after_runtime_start_can_recover() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime {
                stall_start_after_effect: true,
                ..FakePacketRuntime::default()
            },
            clean_recovery(),
        )?;

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), controller.connect())
                .await
                .is_err()
        );
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Connecting,
                recovery: cleanup_recovery(),
                last_error_class: None,
            }
        );
        assert!(controller.helper.applied);
        assert!(controller.packet_runtime.active);
        assert!(controller.connect().await.is_err());

        controller.packet_runtime.stall_start_after_effect = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn mismatched_response_id_fails_closed() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                mismatch_response_id: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client preflight failed");
        assert_eq!(
            controller.snapshot().last_error_class,
            Some(ReferenceClientErrorClass::Protocol)
        );
        assert_eq!(controller.packet_runtime.starts, 0);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_applied_recovery_fails_closed_and_remains_recoverable() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                applied_rollback_failure: true,
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client platform apply failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::CleanupRequired,
                recovery: rollback_failed_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::Protocol),
            }
        );
        assert_eq!(controller.packet_runtime.starts, 0);
        assert!(controller.helper.applied);

        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        Ok(())
    }

    #[tokio::test]
    async fn helper_transport_error_is_coarse_and_redacted() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                fail_operation: Some(PlatformHelperOperation::Preflight),
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;

        let error = controller.connect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client preflight failed");
        assert!(!error.contains("private"));
        assert_eq!(
            controller.snapshot().last_error_class,
            Some(ReferenceClientErrorClass::Preflight)
        );
        Ok(())
    }

    #[tokio::test]
    async fn disconnect_runtime_stop_failure_rolls_back_but_blocks_reconnect() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime {
                fail_stop: true,
                ..FakePacketRuntime::default()
            },
            clean_recovery(),
        )?;
        controller.connect().await?;

        let error = controller.disconnect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client packet runtime stop failed");
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::CleanupRequired,
                recovery: clean_recovery(),
                last_error_class: Some(ReferenceClientErrorClass::RuntimeStop),
            }
        );
        assert!(!controller.helper.applied);
        assert!(controller.packet_runtime.active);

        let calls_before_reconnect = controller.helper.calls.clone();
        assert!(controller.connect().await.is_err());
        assert_eq!(controller.helper.calls, calls_before_reconnect);
        assert_eq!(
            controller.recover().await.unwrap_err().to_string(),
            "reference client recovery runtime stop failed"
        );
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::CleanupRequired
        );
        assert!(controller.packet_runtime.active);

        controller.packet_runtime.fail_stop = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_disconnect_can_retry_stop_and_rollback() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        controller.connect().await?;
        controller.packet_runtime.stall_stop_after_effect = true;

        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            controller.disconnect()
        )
        .await
        .is_err());
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnecting
        );
        assert!(!controller.packet_runtime.active);
        assert!(controller.helper.applied);
        assert!(controller.connect().await.is_err());

        controller.packet_runtime.stall_stop_after_effect = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_disconnect_after_rollback_effect_can_recover() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        controller.connect().await?;
        controller.helper.stall_rollback_after_mutation = true;

        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            controller.disconnect()
        )
        .await
        .is_err());
        assert_eq!(
            controller.snapshot(),
            ReferenceClientSnapshot {
                state: ReferenceClientState::Recovering,
                recovery: cleanup_recovery(),
                last_error_class: None,
            }
        );
        assert!(!controller.packet_runtime.active);
        assert!(!controller.helper.applied);
        assert!(controller.connect().await.is_err());

        controller.helper.stall_rollback_after_mutation = false;
        controller.recover().await?;
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::Disconnected
        );
        assert!(!controller.helper.applied);
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn rollback_failure_remains_cleanup_required() -> Result<()> {
        let mut controller = controller(
            FakeHelper {
                fail_operation: Some(PlatformHelperOperation::Rollback),
                ..FakeHelper::default()
            },
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        controller.connect().await?;

        let error = controller.disconnect().await.unwrap_err().to_string();
        assert_eq!(error, "reference client rollback failed");
        assert_eq!(
            controller.snapshot().state,
            ReferenceClientState::CleanupRequired
        );
        assert_eq!(
            controller.snapshot().last_error_class,
            Some(ReferenceClientErrorClass::Rollback)
        );
        assert!(controller.snapshot().recovery.helper_journal_present);
        assert!(!controller.packet_runtime.active);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_lifecycle_transitions_fail_closed() -> Result<()> {
        let mut controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        assert!(controller.recover().await.is_err());
        assert!(controller.check_runtime_health().await.is_err());
        controller.connect().await?;
        controller.check_runtime_health().await?;
        assert!(controller.connect().await.is_err());
        assert!(controller.recover().await.is_err());
        controller.disconnect().await?;
        assert!(controller.check_runtime_health().await.is_err());
        controller.disconnect().await?;
        Ok(())
    }

    #[test]
    fn snapshot_is_coarse_and_omits_private_controller_fields() -> Result<()> {
        let controller = controller(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            clean_recovery(),
        )?;
        let rendered = serde_json::to_string(&controller.snapshot())?;
        assert!(!rendered.contains("var/lib"));
        assert!(!rendered.contains("session_1"));
        assert!(!rendered.contains("request"));
        Ok(())
    }

    #[test]
    fn invalid_request_prefix_is_rejected() {
        assert!(ReferenceClientController::new(
            FakeHelper::default(),
            FakePacketRuntime::default(),
            "/var/lib/maverick-reference",
            "bad/prefix",
            clean_recovery(),
        )
        .is_err());
    }
}
