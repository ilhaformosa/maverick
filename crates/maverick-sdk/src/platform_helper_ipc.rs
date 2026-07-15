use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::PlatformRecoverySnapshot;

pub const PLATFORM_HELPER_IPC_VERSION: u16 = 1;
pub const PLATFORM_HELPER_MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub const PLATFORM_HELPER_JOURNAL_FILE: &str = "maverick-recovery.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformHelperOperation {
    Preflight,
    Apply,
    Rollback,
    Status,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformHelperRequest {
    pub version: u16,
    pub request_id: String,
    pub operation: PlatformHelperOperation,
    pub journal_path: PathBuf,
}

impl PlatformHelperRequest {
    pub fn new(
        request_id: impl Into<String>,
        operation: PlatformHelperOperation,
        allowed_journal_root: &Path,
    ) -> Result<Self> {
        let request = Self {
            version: PLATFORM_HELPER_IPC_VERSION,
            request_id: request_id.into(),
            operation,
            journal_path: allowed_journal_root.join(PLATFORM_HELPER_JOURNAL_FILE),
        };
        request.validate(allowed_journal_root)?;
        Ok(request)
    }

    pub fn validate(&self, allowed_journal_root: &Path) -> Result<()> {
        validate_version_and_request_id(self.version, &self.request_id)?;
        validate_journal_path(&self.journal_path, allowed_journal_root)
    }

    pub fn from_json(input: &[u8], allowed_journal_root: &Path) -> Result<Self> {
        validate_message_size(input)?;
        let request: Self =
            serde_json::from_slice(input).context("decode platform helper request")?;
        request.validate(allowed_journal_root)?;
        Ok(request)
    }

    pub fn to_json(&self, allowed_journal_root: &Path) -> Result<Vec<u8>> {
        self.validate(allowed_journal_root)?;
        encode_bounded(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformHelperOutcome {
    Ready,
    Applied,
    RolledBack,
    CleanupRequired,
    Recovering,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformHelperErrorClass {
    InvalidRequest,
    Permission,
    Conflict,
    ApplyFailed,
    RollbackFailed,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformHelperResponse {
    pub version: u16,
    pub request_id: String,
    pub outcome: PlatformHelperOutcome,
    pub recovery: PlatformRecoverySnapshot,
    pub error_class: Option<PlatformHelperErrorClass>,
}

impl PlatformHelperResponse {
    pub fn validate(&self) -> Result<()> {
        validate_version_and_request_id(self.version, &self.request_id)?;
        self.recovery.validate()?;

        let rejected = self.outcome == PlatformHelperOutcome::Rejected;
        if rejected != self.error_class.is_some() {
            anyhow::bail!("platform helper rejection and error class must agree");
        }
        let expected_status = match self.outcome {
            PlatformHelperOutcome::Ready | PlatformHelperOutcome::RolledBack => {
                crate::PlatformRecoveryStatus::Clean
            }
            PlatformHelperOutcome::Applied | PlatformHelperOutcome::CleanupRequired => {
                crate::PlatformRecoveryStatus::CleanupRequired
            }
            PlatformHelperOutcome::Recovering => crate::PlatformRecoveryStatus::Recovering,
            PlatformHelperOutcome::Rejected => return Ok(()),
        };
        if self.recovery.status != expected_status {
            anyhow::bail!("platform helper outcome and recovery state must agree");
        }
        if self.outcome == PlatformHelperOutcome::Applied
            && self.recovery.reason != Some(crate::PlatformRecoveryReason::RetainedHelperJournal)
        {
            anyhow::bail!("platform helper applied state must retain rollback state");
        }
        Ok(())
    }

    pub fn from_json(input: &[u8]) -> Result<Self> {
        validate_message_size(input)?;
        let response: Self =
            serde_json::from_slice(input).context("decode platform helper response")?;
        response.validate()?;
        Ok(response)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_bounded(self)
    }
}

fn validate_version_and_request_id(version: u16, request_id: &str) -> Result<()> {
    if version != PLATFORM_HELPER_IPC_VERSION {
        anyhow::bail!("unsupported platform helper IPC version");
    }
    if request_id.is_empty() || request_id.len() > 64 {
        anyhow::bail!("platform helper request id length is invalid");
    }
    if !request_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!("platform helper request id contains invalid characters");
    }
    Ok(())
}

fn validate_journal_path(journal_path: &Path, allowed_journal_root: &Path) -> Result<()> {
    if !allowed_journal_root.is_absolute() || !journal_path.is_absolute() {
        anyhow::bail!("platform helper journal paths must be absolute");
    }
    let expected = allowed_journal_root.join(PLATFORM_HELPER_JOURNAL_FILE);
    if journal_path != expected {
        anyhow::bail!("platform helper journal path is outside the fixed location");
    }
    if journal_path.as_os_str().len() > 512 {
        anyhow::bail!("platform helper journal path is too long");
    }
    Ok(())
}

fn validate_message_size(input: &[u8]) -> Result<()> {
    if input.is_empty() || input.len() > PLATFORM_HELPER_MAX_MESSAGE_BYTES {
        anyhow::bail!("platform helper IPC message size is invalid");
    }
    Ok(())
}

fn encode_bounded(value: &impl Serialize) -> Result<Vec<u8>> {
    let output = serde_json::to_vec(value).context("encode platform helper IPC message")?;
    validate_message_size(&output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PlatformRecoveryReason, PlatformRecoveryStatus};
    use serde::Deserialize;
    use serde_json::Value;
    use std::collections::BTreeSet;

    const IPC_V1_VECTORS: &str =
        include_str!("../../../test-vectors/reference-client/platform-helper-ipc-v1.json");

    #[derive(Deserialize)]
    struct IpcVectorCase {
        name: String,
        message: Value,
    }

    #[derive(Deserialize)]
    struct IpcVectorFile {
        schema: String,
        version: u16,
        max_message_bytes: usize,
        journal_file: String,
        journal_root: PathBuf,
        requests: Vec<IpcVectorCase>,
        responses: Vec<IpcVectorCase>,
        invalid_requests: Vec<IpcVectorCase>,
        invalid_responses: Vec<IpcVectorCase>,
    }

    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct RecoveryShape {
        status: String,
        reason: Option<String>,
        helper_journal_present: bool,
    }

    impl RecoveryShape {
        fn new(status: &str, reason: Option<&str>, helper_journal_present: bool) -> Self {
            Self {
                status: status.to_owned(),
                reason: reason.map(str::to_owned),
                helper_journal_present,
            }
        }
    }

    fn root() -> PathBuf {
        PathBuf::from("/var/lib/maverick-reference")
    }

    fn clean_recovery() -> PlatformRecoverySnapshot {
        PlatformRecoverySnapshot {
            status: PlatformRecoveryStatus::Clean,
            reason: None,
            helper_journal_present: false,
        }
    }

    fn assert_unique_case_names(group: &str, cases: &[IpcVectorCase]) -> Result<()> {
        let mut names = BTreeSet::new();
        for case in cases {
            if !names.insert(case.name.as_str()) {
                anyhow::bail!("duplicate {group} vector name: {}", case.name);
            }
        }
        Ok(())
    }

    fn string_field<'a>(case: &'a IpcVectorCase, field: &str) -> Result<&'a str> {
        case.message
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("vector {} has no string {field}", case.name))
    }

    fn recovery_shape(case: &IpcVectorCase) -> Result<RecoveryShape> {
        let recovery = case
            .message
            .get("recovery")
            .ok_or_else(|| anyhow::anyhow!("vector {} has no recovery object", case.name))?;
        let status = recovery
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("vector {} has no recovery status", case.name))?;
        let reason = match recovery
            .get("reason")
            .ok_or_else(|| anyhow::anyhow!("vector {} has no recovery reason", case.name))?
        {
            Value::Null => None,
            value => Some(
                value
                    .as_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("vector {} has a non-string recovery reason", case.name)
                    })?
                    .to_owned(),
            ),
        };
        let helper_journal_present = recovery
            .get("helper_journal_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow::anyhow!("vector {} has no helper journal state", case.name))?;
        Ok(RecoveryShape {
            status: status.to_owned(),
            reason,
            helper_journal_present,
        })
    }

    #[test]
    fn ipc_v1_compatibility_vectors_match_contract() -> Result<()> {
        let vectors: IpcVectorFile = serde_json::from_str(IPC_V1_VECTORS)?;
        assert_eq!(vectors.schema, "maverick-platform-helper-ipc");
        assert_eq!(vectors.version, PLATFORM_HELPER_IPC_VERSION);
        assert_eq!(vectors.max_message_bytes, PLATFORM_HELPER_MAX_MESSAGE_BYTES);
        assert_eq!(vectors.journal_file, PLATFORM_HELPER_JOURNAL_FILE);

        assert_unique_case_names("request", &vectors.requests)?;
        assert_unique_case_names("response", &vectors.responses)?;
        assert_unique_case_names("invalid request", &vectors.invalid_requests)?;
        assert_unique_case_names("invalid response", &vectors.invalid_responses)?;

        let valid_recovery_shapes = vectors
            .responses
            .iter()
            .map(recovery_shape)
            .collect::<Result<BTreeSet<_>>>()?;
        let expected_valid_recovery_shapes = BTreeSet::from([
            RecoveryShape::new("clean", None, false),
            RecoveryShape::new("cleanup_required", Some("retained_helper_journal"), true),
            RecoveryShape::new("cleanup_required", Some("rollback_failed"), true),
            RecoveryShape::new("recovering", Some("retained_helper_journal"), true),
        ]);
        assert_eq!(valid_recovery_shapes, expected_valid_recovery_shapes);

        let invalid_recovery_shapes = vectors
            .invalid_responses
            .iter()
            .map(recovery_shape)
            .collect::<Result<BTreeSet<_>>>()?;
        let expected_invalid_recovery_shapes = BTreeSet::from([
            RecoveryShape::new("clean", None, true),
            RecoveryShape::new("clean", Some("retained_helper_journal"), false),
            RecoveryShape::new("clean", Some("retained_helper_journal"), true),
            RecoveryShape::new("clean", Some("rollback_failed"), false),
            RecoveryShape::new("clean", Some("rollback_failed"), true),
            RecoveryShape::new("cleanup_required", None, false),
            RecoveryShape::new("cleanup_required", None, true),
            RecoveryShape::new("cleanup_required", Some("retained_helper_journal"), false),
            RecoveryShape::new("cleanup_required", Some("rollback_failed"), false),
            RecoveryShape::new("recovering", None, false),
            RecoveryShape::new("recovering", None, true),
            RecoveryShape::new("recovering", Some("retained_helper_journal"), false),
            RecoveryShape::new("recovering", Some("rollback_failed"), false),
            RecoveryShape::new("recovering", Some("rollback_failed"), true),
        ]);
        assert_eq!(expected_valid_recovery_shapes.len(), 4);
        assert_eq!(expected_invalid_recovery_shapes.len(), 14);
        assert!(expected_valid_recovery_shapes.is_disjoint(&expected_invalid_recovery_shapes));
        let missing_invalid_recovery_shapes = expected_invalid_recovery_shapes
            .difference(&invalid_recovery_shapes)
            .collect::<Vec<_>>();
        assert!(
            missing_invalid_recovery_shapes.is_empty(),
            "missing invalid recovery vector shapes: {missing_invalid_recovery_shapes:?}"
        );

        let operations = vectors
            .requests
            .iter()
            .map(|case| string_field(case, "operation"))
            .collect::<Result<BTreeSet<_>>>()?;
        assert_eq!(
            operations,
            BTreeSet::from(["apply", "preflight", "rollback", "status"])
        );
        let outcomes = vectors
            .responses
            .iter()
            .map(|case| string_field(case, "outcome"))
            .collect::<Result<BTreeSet<_>>>()?;
        assert_eq!(
            outcomes,
            BTreeSet::from([
                "applied",
                "cleanup_required",
                "ready",
                "recovering",
                "rejected",
                "rolled_back",
            ])
        );
        let error_classes = vectors
            .responses
            .iter()
            .filter_map(|case| case.message.get("error_class").and_then(Value::as_str))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            error_classes,
            BTreeSet::from([
                "apply_failed",
                "conflict",
                "internal",
                "invalid_request",
                "permission",
                "rollback_failed",
            ])
        );
        let valid_request_ids = vectors
            .requests
            .iter()
            .map(|case| string_field(case, "request_id"))
            .collect::<Result<Vec<_>>>()?;
        assert!(valid_request_ids
            .iter()
            .any(|request_id| request_id.len() == 1));
        assert!(valid_request_ids
            .iter()
            .any(|request_id| request_id.len() == 64));
        let invalid_request_ids = vectors
            .invalid_requests
            .iter()
            .filter_map(|case| case.message.get("request_id").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(invalid_request_ids.contains(&""));
        assert!(invalid_request_ids
            .iter()
            .any(|request_id| request_id.len() > 64));
        assert!(invalid_request_ids
            .iter()
            .any(|request_id| !request_id.is_ascii()));

        for vector in vectors.requests {
            let encoded = serde_json::to_vec(&vector.message)?;
            let request = PlatformHelperRequest::from_json(&encoded, &vectors.journal_root)
                .with_context(|| format!("request vector {}", vector.name))?;
            let reencoded = request.to_json(&vectors.journal_root)?;
            assert_eq!(serde_json::from_slice::<Value>(&reencoded)?, vector.message);
        }

        for vector in vectors.responses {
            let encoded = serde_json::to_vec(&vector.message)?;
            let response = PlatformHelperResponse::from_json(&encoded)
                .with_context(|| format!("response vector {}", vector.name))?;
            let reencoded = response.to_json()?;
            assert_eq!(serde_json::from_slice::<Value>(&reencoded)?, vector.message);
        }

        for vector in vectors.invalid_requests {
            let encoded = serde_json::to_vec(&vector.message)?;
            assert!(
                PlatformHelperRequest::from_json(&encoded, &vectors.journal_root).is_err(),
                "invalid request vector accepted: {}",
                vector.name
            );
        }

        for vector in vectors.invalid_responses {
            let encoded = serde_json::to_vec(&vector.message)?;
            assert!(
                PlatformHelperResponse::from_json(&encoded).is_err(),
                "invalid response vector accepted: {}",
                vector.name
            );
        }
        Ok(())
    }

    #[test]
    fn request_roundtrips_with_fixed_journal_path() -> Result<()> {
        let request =
            PlatformHelperRequest::new("request_1", PlatformHelperOperation::Preflight, &root())?;
        let encoded = request.to_json(&root())?;
        let decoded = PlatformHelperRequest::from_json(&encoded, &root())?;
        assert_eq!(decoded, request);
        assert_eq!(
            decoded.journal_path,
            root().join(PLATFORM_HELPER_JOURNAL_FILE)
        );
        Ok(())
    }

    #[test]
    fn request_rejects_version_id_unknown_fields_and_oversize() -> Result<()> {
        let mut request =
            PlatformHelperRequest::new("request_1", PlatformHelperOperation::Status, &root())?;
        request.version += 1;
        assert!(request.to_json(&root()).is_err());

        request.version = PLATFORM_HELPER_IPC_VERSION;
        request.request_id = "bad/id".into();
        assert!(request.to_json(&root()).is_err());

        let unknown = br#"{"version":1,"request_id":"r1","operation":"status","journal_path":"/var/lib/maverick-reference/maverick-recovery.json","extra":true}"#;
        assert!(PlatformHelperRequest::from_json(unknown, &root()).is_err());

        let oversized = vec![b' '; PLATFORM_HELPER_MAX_MESSAGE_BYTES + 1];
        assert!(PlatformHelperRequest::from_json(&oversized, &root()).is_err());
        Ok(())
    }

    #[test]
    fn request_rejects_any_non_fixed_journal_path() -> Result<()> {
        let mut request =
            PlatformHelperRequest::new("request_1", PlatformHelperOperation::Apply, &root())?;
        request.journal_path = root().join("../other.json");
        assert!(request.validate(&root()).is_err());
        request.journal_path = PathBuf::from("relative.json");
        assert!(request.validate(&root()).is_err());
        Ok(())
    }

    #[test]
    fn response_roundtrips_without_free_form_error_text() -> Result<()> {
        let response = PlatformHelperResponse {
            version: PLATFORM_HELPER_IPC_VERSION,
            request_id: "request_1".into(),
            outcome: PlatformHelperOutcome::Ready,
            recovery: clean_recovery(),
            error_class: None,
        };
        let encoded = response.to_json()?;
        let decoded = PlatformHelperResponse::from_json(&encoded)?;
        assert_eq!(decoded, response);
        let rendered = String::from_utf8(encoded)?;
        assert!(!rendered.contains("message"));
        assert!(!rendered.contains("path"));
        Ok(())
    }

    #[test]
    fn response_rejects_inconsistent_outcome_and_recovery() {
        let response = PlatformHelperResponse {
            version: PLATFORM_HELPER_IPC_VERSION,
            request_id: "request_1".into(),
            outcome: PlatformHelperOutcome::Rejected,
            recovery: clean_recovery(),
            error_class: None,
        };
        assert!(response.validate().is_err());

        let response = PlatformHelperResponse {
            outcome: PlatformHelperOutcome::Ready,
            error_class: Some(PlatformHelperErrorClass::Internal),
            ..response
        };
        assert!(response.validate().is_err());

        let response = PlatformHelperResponse {
            outcome: PlatformHelperOutcome::CleanupRequired,
            recovery: PlatformRecoverySnapshot {
                status: PlatformRecoveryStatus::CleanupRequired,
                reason: Some(PlatformRecoveryReason::RetainedHelperJournal),
                helper_journal_present: false,
            },
            error_class: None,
            ..response
        };
        assert!(response.validate().is_err());

        let response = PlatformHelperResponse {
            outcome: PlatformHelperOutcome::Ready,
            recovery: PlatformRecoverySnapshot {
                status: PlatformRecoveryStatus::CleanupRequired,
                reason: Some(PlatformRecoveryReason::RetainedHelperJournal),
                helper_journal_present: true,
            },
            error_class: None,
            ..response
        };
        assert!(response.validate().is_err());

        let response = PlatformHelperResponse {
            outcome: PlatformHelperOutcome::Applied,
            recovery: PlatformRecoverySnapshot {
                status: PlatformRecoveryStatus::CleanupRequired,
                reason: Some(PlatformRecoveryReason::RollbackFailed),
                helper_journal_present: true,
            },
            error_class: None,
            ..response
        };
        assert!(response.validate().is_err());
    }
}
