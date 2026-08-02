//! Direct auth-v3 provisioning, encoding, parsing, and verification primitives.
//!
//! This module implements the fixed direct H2/H3 byte contract and a
//! startup-only singleton provisioning binding. It does not enable auth-v3 in
//! any runtime and does not manage connection generations, duplicate controls,
//! connection closure, fallback, expiry timers, revocation, reconnects, flows,
//! targets, or data-plane state.
//!
//! A parsed or verified value is metadata only. It does not prove that a
//! runtime connection has been marked authenticated. Runtime code must supply
//! truthful connection facts, enforce the one-control generation state
//! machine, and perform its own state transition only after the required I/O
//! succeeds.
//!
//! The primitive only rejects all-zero nonce/session values. A later runtime
//! must generate them with a CSPRNG and prevent reuse across physical
//! generations and connection sessions.
//!
//! The first public API is additive but intentionally non-exhaustive. Callers
//! construct trusted inputs through their `new` functions, and downstream
//! matches on public enums must retain a wildcard arm for future trusted facts
//! or fixed failure categories.

use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::SecretString;

type HmacSha256 = Hmac<Sha256>;

/// Exact byte length of a direct auth-v3 `ClientControl`.
pub const AUTH_V3_CLIENT_CONTROL_LEN: usize = 256;

/// Exact byte length of a direct auth-v3 `ServerConfirmation`.
pub const AUTH_V3_SERVER_CONFIRMATION_LEN: usize = 320;

/// Exact RFC 9266 exporter label, without a trailing NUL.
pub const AUTH_V3_EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// Exact direct auth-v3 exporter output length.
pub const AUTH_V3_EXPORTER_LEN: usize = 32;

const MAGIC: &[u8; 4] = b"MVA3";
const VERSION: u16 = 3;
const CLIENT_CONTROL_TYPE: u8 = 1;
const SERVER_CONFIRMATION_TYPE: u8 = 2;
const H2_CARRIER: u8 = 1;
const H3_CARRIER: u8 = 2;
const DIRECT_TRUST_ROUTE: u8 = 1;
const TLS_EXPORTER_BINDING: u8 = 1;
const TLS13_CLASSICAL_FLOOR: u16 = 1;
const DIRECT_CARRIER_SESSION_V1: u32 = 1;
const EXPLICIT_BOUNDED_LIMITS_V1: u16 = 1;
const DOWNGRADE_SENTINEL: &[u8; 16] = b"MVRK-AUTH-V3-REQ";
const PRINCIPAL_COMMITMENT_LABEL: &[u8] = b"Maverick auth v3 principal commitment";
const DEPLOYMENT_COMMITMENT_LABEL: &[u8] = b"Maverick auth v3 deployment profile commitment";
const NAMESPACE_COMMITMENT_LABEL: &[u8] = b"Maverick auth v3 credential namespace commitment";
const HKDF_SALT_LABEL: &[u8] = b"Maverick auth v3 hkdf salt";
const CLIENT_KEY_INFO: &[u8] = b"Maverick auth v3 client control mac key";
const SERVER_KEY_INFO: &[u8] = b"Maverick auth v3 server confirmation mac key";
const POLICY_HASH_LABEL: &[u8] = b"Maverick auth v3 policy hash";
const CLIENT_TRANSCRIPT_LABEL: &[u8] = b"Maverick auth v3 client control transcript";
const CLIENT_COMMITMENT_LABEL: &[u8] = b"Maverick auth v3 client control commitment";
const SERVER_TRANSCRIPT_LABEL: &[u8] = b"Maverick auth v3 server confirmation transcript";
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;
const MAX_SERVER_ADMISSION_SECONDS: u64 = 1_800;
const MAX_SERVER_HARD_SECONDS: u64 = 86_400;
const MAX_CLIENT_ADMISSION_SECONDS: u64 = 2_100;
const MAX_CLIENT_HARD_SECONDS: u64 = 86_700;

/// Fixed, bounded, privacy-safe direct auth-v3 failure categories.
///
/// Neither the variants nor their display strings contain peer bytes,
/// identities, commitments, secrets, exporters, times, paths, endpoints, or
/// backend errors. The enum is non-exhaustive; downstream matches must retain a
/// fallback arm.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthV3Error {
    /// A local opaque provisioning handle is all zero.
    #[error("invalid auth-v3 provisioning handle")]
    ProvisioningHandle,
    /// A direct server/listener binding does not contain exactly one profile.
    #[error("invalid auth-v3 singleton provisioning cardinality")]
    ProvisioningCardinality,
    /// The message does not have its one exact fixed length.
    #[error("invalid auth-v3 message shape")]
    Shape,
    /// The magic, version, type, or declared length is invalid.
    #[error("invalid auth-v3 header")]
    Header,
    /// A reserved byte or flag is nonzero.
    #[error("invalid auth-v3 reserved field")]
    Reserved,
    /// The canonical policy block or its hash is invalid.
    #[error("invalid auth-v3 policy")]
    Policy,
    /// The binding registry value is invalid.
    #[error("invalid auth-v3 binding")]
    Binding,
    /// The key-exchange policy registry value is invalid.
    #[error("invalid auth-v3 key-exchange policy")]
    KeyExchange,
    /// The capability bits are invalid.
    #[error("invalid auth-v3 capabilities")]
    Capabilities,
    /// The resource-class registry value is invalid.
    #[error("invalid auth-v3 resource class")]
    ResourceClass,
    /// Trusted connection facts do not match the direct wire claim.
    #[error("invalid auth-v3 connection context")]
    Context,
    /// Trusted credential provisioning or validity is invalid.
    #[error("invalid auth-v3 credential")]
    Credential,
    /// The credential epoch is zero or does not match trusted provisioning.
    #[error("invalid auth-v3 credential epoch")]
    Epoch,
    /// The client time is invalid or outside the fixed skew limit.
    #[error("invalid auth-v3 client time")]
    Time,
    /// A wire commitment does not match the trusted opaque identity input.
    #[error("invalid auth-v3 identity commitment")]
    Identity,
    /// A required nonce or session identifier is all zero.
    #[error("invalid auth-v3 nonce")]
    Nonce,
    /// The downgrade sentinel is invalid.
    #[error("invalid auth-v3 downgrade sentinel")]
    Sentinel,
    /// Expiry ordering, lifetime, or credential validity is invalid.
    #[error("invalid auth-v3 expiry")]
    Expiry,
    /// A selected or echoed field differs from `ClientControl`.
    #[error("invalid auth-v3 confirmation echo")]
    Echo,
    /// A selected resource value is zero or above a trusted local cap.
    #[error("invalid auth-v3 resource limits")]
    Limits,
    /// The complete `ClientControl` commitment is invalid.
    #[error("invalid auth-v3 client commitment")]
    Commitment,
    /// An HMAC tag is invalid for the trusted credential and exporter.
    #[error("invalid auth-v3 authenticator")]
    Mac,
}

/// The actual direct physical carrier selected before auth-v3 begins.
/// Downstream matches must retain a fallback arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthV3Carrier {
    /// Direct HTTP/2 over TLS.
    H2,
    /// Direct HTTP/3 over QUIC/TLS.
    H3,
}

impl AuthV3Carrier {
    const fn wire_id(self) -> u8 {
        match self {
            Self::H2 => H2_CARRIER,
            Self::H3 => H3_CARRIER,
        }
    }

    fn from_wire_id(value: u8) -> Result<Self, AuthV3Error> {
        match value {
            H2_CARRIER => Ok(Self::H2),
            H3_CARRIER => Ok(Self::H3),
            _ => Err(AuthV3Error::Policy),
        }
    }
}

/// Trusted observation of the actual TLS version. Downstream matches must
/// retain a fallback arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthV3TlsVersion {
    /// The actual physical connection uses TLS 1.3.
    Tls13,
    /// Any version other than TLS 1.3.
    Other,
}

/// Fixed-size opaque handle for one local direct auth-v3 provisioning binding.
///
/// The handle is not a wire value and is never derived from a wire claim,
/// readable legacy field, identity, path, or PSK. Construction rejects the
/// all-zero value. Its formatter intentionally reveals no bytes.
#[repr(transparent)]
#[derive(PartialEq, Eq)]
pub struct AuthV3ProvisioningHandle([u8; 16]);

impl AuthV3ProvisioningHandle {
    /// Construct a caller-provisioned opaque local handle.
    ///
    /// This function validates but does not generate the handle.
    pub fn new(value: [u8; 16]) -> Result<Self, AuthV3Error> {
        if all_zero(&value) {
            return Err(AuthV3Error::ProvisioningHandle);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for AuthV3ProvisioningHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("opaque auth-v3 provisioning handle")
    }
}

/// Owned local provisioning data for one direct auth-v3 profile.
///
/// This type deliberately implements neither `Clone`, `Default`, nor Serde
/// traits: cloning the value would clone its [`SecretString`], defaults cannot
/// safely invent identity or credential material, and stored/config schemas
/// remain outside this repository-local slice.
///
/// ```compile_fail
/// use maverick_core::auth_v3::AuthV3OwnedProvisioningProfile;
/// fn require_clone<T: Clone>() {}
/// require_clone::<AuthV3OwnedProvisioningProfile>();
/// ```
///
/// ```compile_fail
/// use maverick_core::auth_v3::AuthV3OwnedProvisioningProfile;
/// fn require_default<T: Default>() {}
/// require_default::<AuthV3OwnedProvisioningProfile>();
/// ```
///
/// ```compile_fail
/// use maverick_core::auth_v3::AuthV3OwnedProvisioningProfile;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<AuthV3OwnedProvisioningProfile>();
/// ```
pub struct AuthV3OwnedProvisioningProfile {
    principal_id: [u8; 16],
    deployment_profile_id: [u8; 16],
    credential_namespace_id: [u8; 16],
    expected_server_identity_id: [u8; 16],
    expected_direct_route: bool,
    expected_control_path: String,
    credential_epoch: u64,
    credential_not_after_unix: u64,
    secret: SecretString,
}

impl AuthV3OwnedProvisioningProfile {
    /// Construct and validate one caller-provisioned owned direct profile.
    ///
    /// The caller supplies every opaque ID and the PSK. This constructor does
    /// not generate or derive them, and it reuses
    /// [`validate_auth_v3_trusted_profiles`] for the frozen tuple, mapping,
    /// path, epoch, expiry, and credential rules.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal_id: [u8; 16],
        deployment_profile_id: [u8; 16],
        credential_namespace_id: [u8; 16],
        expected_server_identity_id: [u8; 16],
        expected_direct_route: bool,
        expected_control_path: String,
        credential_epoch: u64,
        credential_not_after_unix: u64,
        secret: SecretString,
    ) -> Result<Self, AuthV3Error> {
        let profile = Self {
            principal_id,
            deployment_profile_id,
            credential_namespace_id,
            expected_server_identity_id,
            expected_direct_route,
            expected_control_path,
            credential_epoch,
            credential_not_after_unix,
            secret,
        };
        validate_auth_v3_trusted_profiles(&[profile.trusted_profile()])?;
        Ok(profile)
    }

    fn trusted_profile(&self) -> AuthV3TrustedProfile<'_> {
        AuthV3TrustedProfile::new(
            &self.principal_id,
            &self.deployment_profile_id,
            &self.credential_namespace_id,
            &self.expected_server_identity_id,
            self.expected_direct_route,
            &self.expected_control_path,
            self.credential_epoch,
            self.credential_not_after_unix,
            &self.secret,
        )
    }
}

impl fmt::Debug for AuthV3OwnedProvisioningProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("owned auth-v3 provisioning profile")
    }
}

/// One direct server/listener binding containing exactly one owned profile.
///
/// A shared listener with multiple v3 profiles is deliberately blocked. Use
/// independent singleton bindings for independent listeners; this type is not
/// a wire selector or a request-path registry.
pub struct AuthV3SingletonBinding {
    handle: AuthV3ProvisioningHandle,
    profile: AuthV3OwnedProvisioningProfile,
}

impl AuthV3SingletonBinding {
    /// Validate the exact-one-profile startup cardinality and construct a
    /// singleton binding.
    pub fn new(
        handle: AuthV3ProvisioningHandle,
        mut profiles: Vec<AuthV3OwnedProvisioningProfile>,
    ) -> Result<Self, AuthV3Error> {
        if profiles.len() != 1 {
            return Err(AuthV3Error::ProvisioningCardinality);
        }
        let profile = profiles
            .pop()
            .expect("exact singleton provisioning cardinality was checked");
        validate_auth_v3_trusted_profiles(&[profile.trusted_profile()])?;
        Ok(Self { handle, profile })
    }

    /// Produce the opaque capability for the profile already selected by this
    /// validated singleton binding.
    ///
    /// This operation accepts no peer bytes, commitment, epoch, credential
    /// hint, path, SNI, Host, PSK, or other selection input. The returned value
    /// cannot switch profiles or try multiple credentials.
    pub fn preselected_profile(&self) -> AuthV3PreselectedProfile<'_> {
        AuthV3PreselectedProfile { binding: self }
    }
}

impl fmt::Debug for AuthV3SingletonBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("singleton auth-v3 provisioning binding")
    }
}

/// Opaque proof that a validated singleton binding selected its only profile
/// before any auth-v3 wire message is read.
pub struct AuthV3PreselectedProfile<'a> {
    binding: &'a AuthV3SingletonBinding,
}

impl AuthV3PreselectedProfile<'_> {
    /// Borrow a temporary view accepted by the existing production
    /// encode/verify primitive without copying or exposing the secret.
    pub fn trusted_profile(&self) -> AuthV3TrustedProfile<'_> {
        self.binding.profile.trusted_profile()
    }
}

impl fmt::Debug for AuthV3PreselectedProfile<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("preselected auth-v3 provisioning capability")
    }
}

/// One trusted local direct-auth profile and credential entry.
///
/// The three opaque IDs are local provisioning inputs; wire commitments never
/// select or replace them. `secret` is consumed as the complete UTF-8 value
/// returned by [`SecretString::expose_secret`], including its `mv1_` prefix.
/// This type is deliberately not `Debug` so ordinary formatting cannot expose
/// its credential or private mapping.
#[non_exhaustive]
pub struct AuthV3TrustedProfile<'a> {
    /// Trusted opaque principal ID.
    principal_id: &'a [u8; 16],
    /// Trusted opaque deployment-profile ID.
    deployment_profile_id: &'a [u8; 16],
    /// Trusted opaque credential-namespace ID.
    credential_namespace_id: &'a [u8; 16],
    /// Trusted expected server identity or origin ID.
    expected_server_identity_id: &'a [u8; 16],
    /// Whether this profile requires the only assigned route: direct.
    expected_direct_route: bool,
    /// Trusted exact control/tunnel path.
    expected_control_path: &'a str,
    /// Trusted current nonzero credential epoch.
    credential_epoch: u64,
    /// Trusted absolute Unix credential expiry.
    credential_not_after_unix: u64,
    /// The unique PSK bound to this exact commitment tuple and epoch.
    secret: &'a SecretString,
}

impl<'a> AuthV3TrustedProfile<'a> {
    /// Construct one caller-owned trusted direct-auth profile entry.
    ///
    /// Validation remains fail-closed in the encode/verify/registry functions,
    /// so constructing this value does not make its contents trusted or valid.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        principal_id: &'a [u8; 16],
        deployment_profile_id: &'a [u8; 16],
        credential_namespace_id: &'a [u8; 16],
        expected_server_identity_id: &'a [u8; 16],
        expected_direct_route: bool,
        expected_control_path: &'a str,
        credential_epoch: u64,
        credential_not_after_unix: u64,
        secret: &'a SecretString,
    ) -> Self {
        Self {
            principal_id,
            deployment_profile_id,
            credential_namespace_id,
            expected_server_identity_id,
            expected_direct_route,
            expected_control_path,
            credential_epoch,
            credential_not_after_unix,
            secret,
        }
    }
}

/// Independently trusted facts about the actual physical connection.
///
/// Wire policy values are checked against these facts and never substitute for
/// them. `exporter_context` must be `Some(&[])`, and the caller must set
/// `exporter_from_same_generation` only for exporter bytes obtained from the
/// exact connection generation being authenticated. This type is deliberately
/// not `Debug` because it contains private connection metadata.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AuthV3TrustedConnectionContext<'a> {
    /// Actual physical dispatch selected by the runtime.
    actual_carrier: AuthV3Carrier,
    /// Actual TLS version observed by the runtime.
    actual_tls_version: AuthV3TlsVersion,
    /// Whether the actual route is direct to Maverick.
    actual_direct_route: bool,
    /// Whether early data or 0-RTT was used.
    early_data: bool,
    /// RFC 9266 exporter bytes from the actual physical connection.
    tls_exporter: &'a [u8; AUTH_V3_EXPORTER_LEN],
    /// Whether the exporter came from this exact connection generation.
    exporter_from_same_generation: bool,
    /// Exporter context presence and bytes; only present-empty is valid.
    exporter_context: Option<&'a [u8]>,
    /// Actual deployment-profile ID selected for this connection.
    deployment_profile_id: &'a [u8; 16],
    /// Actual authenticated/expected server identity or origin ID.
    server_identity_id: &'a [u8; 16],
    /// Actual control/tunnel path used by the connection.
    control_path: &'a str,
}

impl<'a> AuthV3TrustedConnectionContext<'a> {
    /// Construct independently trusted facts for one physical connection.
    ///
    /// The verifier still checks TLS 1.3, direct routing, no early data, the
    /// exact carrier and profile mapping, same-generation exporter provenance,
    /// and present-empty exporter context.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        actual_carrier: AuthV3Carrier,
        actual_tls_version: AuthV3TlsVersion,
        actual_direct_route: bool,
        early_data: bool,
        tls_exporter: &'a [u8; AUTH_V3_EXPORTER_LEN],
        exporter_from_same_generation: bool,
        exporter_context: Option<&'a [u8]>,
        deployment_profile_id: &'a [u8; 16],
        server_identity_id: &'a [u8; 16],
        control_path: &'a str,
    ) -> Self {
        Self {
            actual_carrier,
            actual_tls_version,
            actual_direct_route,
            early_data,
            tls_exporter,
            exporter_from_same_generation,
            exporter_context,
            deployment_profile_id,
            server_identity_id,
            control_path,
        }
    }
}

/// Trusted inputs used to create one fixed `ClientControl`.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AuthV3ClientControlInput {
    /// Resolved physical carrier to authenticate.
    carrier: AuthV3Carrier,
    /// Client wall-clock time as absolute Unix seconds.
    client_time_unix: u64,
    /// Caller-supplied nonzero 32-byte client nonce.
    client_nonce: [u8; 32],
}

impl AuthV3ClientControlInput {
    /// Construct trusted local inputs for one `ClientControl` encoding.
    ///
    /// The primitive rejects an all-zero nonce but cannot prove randomness or
    /// uniqueness. Runtime code must use a CSPRNG and prevent nonce reuse across
    /// physical connection generations.
    pub const fn new(
        carrier: AuthV3Carrier,
        client_time_unix: u64,
        client_nonce: [u8; 32],
    ) -> Self {
        Self {
            carrier,
            client_time_unix,
            client_nonce,
        }
    }
}

impl fmt::Debug for AuthV3ClientControlInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("auth-v3 client control input")
    }
}

/// Trusted server-selected inputs used to create one `ServerConfirmation`.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AuthV3ServerConfirmationInput {
    /// Trusted server time used to enforce server-side lifetime caps.
    server_now_unix: u64,
    /// Absolute admission expiry, at most 1,800 seconds after server now.
    admission_expiry_unix: u64,
    /// Absolute hard expiry, at most 86,400 seconds after server now.
    hard_expiry_unix: u64,
    /// Caller-supplied nonzero 32-byte server nonce.
    server_nonce: [u8; 32],
    /// Caller-supplied nonzero 16-byte connection-session ID.
    session_id: [u8; 16],
    /// Server-selected nonzero maximum frame size.
    max_frame_size: u32,
    /// Server-selected nonzero maximum concurrent flow count.
    max_concurrent_flows: u32,
}

impl AuthV3ServerConfirmationInput {
    /// Construct trusted server inputs for one confirmation encoding.
    ///
    /// The primitive rejects all-zero nonce/session values but cannot prove
    /// randomness or uniqueness. Runtime code must use a CSPRNG and prevent
    /// reuse across physical generations and connection sessions.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        server_now_unix: u64,
        admission_expiry_unix: u64,
        hard_expiry_unix: u64,
        server_nonce: [u8; 32],
        session_id: [u8; 16],
        max_frame_size: u32,
        max_concurrent_flows: u32,
    ) -> Self {
        Self {
            server_now_unix,
            admission_expiry_unix,
            hard_expiry_unix,
            server_nonce,
            session_id,
            max_frame_size,
            max_concurrent_flows,
        }
    }
}

impl fmt::Debug for AuthV3ServerConfirmationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("auth-v3 server confirmation input")
    }
}

/// Trusted client receipt time and local resource caps.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct AuthV3ClientReceipt {
    /// Trusted client receipt time as absolute Unix seconds.
    client_now_unix: u64,
    /// Trusted local maximum accepted frame size.
    max_frame_size_cap: u32,
    /// Trusted local maximum accepted concurrent flow count.
    max_concurrent_flows_cap: u32,
}

impl AuthV3ClientReceipt {
    /// Construct trusted client receipt time and local resource caps.
    pub const fn new(
        client_now_unix: u64,
        max_frame_size_cap: u32,
        max_concurrent_flows_cap: u32,
    ) -> Self {
        Self {
            client_now_unix,
            max_frame_size_cap,
            max_concurrent_flows_cap,
        }
    }
}

impl fmt::Debug for AuthV3ClientReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("auth-v3 client receipt")
    }
}

/// Strictly parsed `ClientControl` metadata.
///
/// Parsing validates only canonical shape and wire values. It does not verify
/// the trusted connection, credential, clock, exporter, or MAC and does not
/// prove that a runtime connection is authenticated.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedAuthV3ClientControl {
    carrier: AuthV3Carrier,
    policy: [u8; 8],
    credential_epoch: u64,
    client_time_unix: u64,
    principal_commitment: [u8; 32],
    deployment_profile_commitment: [u8; 32],
    credential_namespace_commitment: [u8; 32],
    client_nonce: [u8; 32],
    auth_tag: [u8; 32],
}

impl ParsedAuthV3ClientControl {
    /// Return the carrier claimed by the canonical policy block.
    pub const fn carrier(&self) -> AuthV3Carrier {
        self.carrier
    }

    /// Return the wire credential epoch.
    pub const fn credential_epoch(&self) -> u64 {
        self.credential_epoch
    }

    /// Return the wire client time.
    pub const fn client_time_unix(&self) -> u64 {
        self.client_time_unix
    }
}

impl fmt::Debug for ParsedAuthV3ClientControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("parsed auth-v3 client control metadata")
    }
}

/// Strictly parsed `ServerConfirmation` metadata.
///
/// Parsing validates only canonical shape and wire values. It does not verify
/// trusted connection facts, echoes, expiry caps, the client commitment, or
/// the MAC and does not prove that a runtime connection is authenticated.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedAuthV3ServerConfirmation {
    carrier: AuthV3Carrier,
    policy: [u8; 8],
    credential_epoch: u64,
    admission_expiry_unix: u64,
    hard_expiry_unix: u64,
    principal_commitment: [u8; 32],
    deployment_profile_commitment: [u8; 32],
    credential_namespace_commitment: [u8; 32],
    server_nonce: [u8; 32],
    session_id: [u8; 16],
    client_control_commitment: [u8; 32],
    max_frame_size: u32,
    max_concurrent_flows: u32,
    auth_tag: [u8; 32],
}

impl ParsedAuthV3ServerConfirmation {
    /// Return the carrier selected by the canonical policy block.
    pub const fn carrier(&self) -> AuthV3Carrier {
        self.carrier
    }

    /// Return the selected credential epoch.
    pub const fn credential_epoch(&self) -> u64 {
        self.credential_epoch
    }

    /// Return the absolute admission expiry.
    pub const fn admission_expiry_unix(&self) -> u64 {
        self.admission_expiry_unix
    }

    /// Return the absolute hard expiry.
    pub const fn hard_expiry_unix(&self) -> u64 {
        self.hard_expiry_unix
    }

    /// Return the selected maximum frame size.
    pub const fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    /// Return the selected maximum concurrent flow count.
    pub const fn max_concurrent_flows(&self) -> u32 {
        self.max_concurrent_flows
    }
}

impl fmt::Debug for ParsedAuthV3ServerConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("parsed auth-v3 server confirmation metadata")
    }
}

/// Verified `ClientControl` metadata for server-side confirmation generation.
///
/// This value proves that the supplied bytes matched the supplied trusted
/// profile and connection context at one pure function call. It does not prove
/// that the current runtime connection is authenticated, that a generation
/// slot was occupied, or that failure/duplicate/no-fallback behavior occurred.
pub struct VerifiedAuthV3ClientControl {
    parsed: ParsedAuthV3ClientControl,
    encoded: [u8; AUTH_V3_CLIENT_CONTROL_LEN],
    tls_exporter: [u8; AUTH_V3_EXPORTER_LEN],
    server_mac_key: Zeroizing<[u8; 32]>,
    credential_not_after_unix: u64,
    expected_deployment_profile_id: [u8; 16],
    expected_server_identity_id: [u8; 16],
    expected_direct_route: bool,
    expected_control_path: String,
}

impl VerifiedAuthV3ClientControl {
    /// Return the verified wire carrier metadata.
    pub const fn carrier(&self) -> AuthV3Carrier {
        self.parsed.carrier
    }

    /// Return the verified wire credential epoch metadata.
    pub const fn credential_epoch(&self) -> u64 {
        self.parsed.credential_epoch
    }

    /// Return the verified wire client-time metadata.
    pub const fn client_time_unix(&self) -> u64 {
        self.parsed.client_time_unix
    }
}

impl fmt::Debug for VerifiedAuthV3ClientControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("verified auth-v3 client control metadata")
    }
}

/// Verified `ServerConfirmation` metadata.
///
/// This value does not mark a runtime connection authenticated. The runtime
/// remains responsible for the atomic generation state transition and all
/// close, expiry, revocation, no-fallback, and data-plane behavior.
pub struct VerifiedAuthV3ServerConfirmation {
    parsed: ParsedAuthV3ServerConfirmation,
}

impl VerifiedAuthV3ServerConfirmation {
    /// Return the verified absolute admission expiry metadata.
    pub const fn admission_expiry_unix(&self) -> u64 {
        self.parsed.admission_expiry_unix
    }

    /// Return the verified absolute hard expiry metadata.
    pub const fn hard_expiry_unix(&self) -> u64 {
        self.parsed.hard_expiry_unix
    }

    /// Return the verified maximum frame-size metadata.
    pub const fn max_frame_size(&self) -> u32 {
        self.parsed.max_frame_size
    }

    /// Return the verified maximum concurrent-flow metadata.
    pub const fn max_concurrent_flows(&self) -> u32 {
        self.parsed.max_concurrent_flows
    }
}

impl fmt::Debug for VerifiedAuthV3ServerConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("verified auth-v3 server confirmation metadata")
    }
}

/// Validate consistency across independent singleton bindings at startup or
/// config reload.
///
/// This bounded O(n²) helper rejects duplicate local handles, then delegates
/// tuple, PSK, and deployment-mapping consistency to
/// [`validate_auth_v3_trusted_profiles`]. It is not a shared-listener selector,
/// provisioning registry, wire lookup, PSK trial loop, or request hot path.
pub fn validate_auth_v3_singleton_bindings(
    bindings: &[AuthV3SingletonBinding],
) -> Result<(), AuthV3Error> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[index + 1..]
            .iter()
            .any(|other| binding.handle == other.handle)
        {
            return Err(AuthV3Error::ProvisioningHandle);
        }
    }

    let profiles: Vec<_> = bindings
        .iter()
        .map(|binding| binding.profile.trusted_profile())
        .collect();
    validate_auth_v3_trusted_profiles(&profiles)
}

/// Validate a bounded caller-owned set of trusted direct-auth profile entries.
///
/// This pure O(n²) helper is a one-time startup/config-reload consistency gate,
/// not a provisioning registry and never a per-untrusted-control hot-path
/// operation. It rejects invalid or duplicate entries, a tuple mapped more
/// than once, a PSK reused by two tuples, and conflicting server/path mappings
/// for one deployment-profile ID.
pub fn validate_auth_v3_trusted_profiles(
    profiles: &[AuthV3TrustedProfile<'_>],
) -> Result<(), AuthV3Error> {
    for profile in profiles {
        validate_trusted_profile(profile)?;
    }

    for (index, profile) in profiles.iter().enumerate() {
        for other in &profiles[index + 1..] {
            if profile.deployment_profile_id == other.deployment_profile_id
                && (profile.expected_server_identity_id != other.expected_server_identity_id
                    || profile.expected_direct_route != other.expected_direct_route
                    || profile.expected_control_path != other.expected_control_path)
            {
                return Err(AuthV3Error::Context);
            }

            let same_tuple = trusted_credential_tuple(profile) == trusted_credential_tuple(other);
            let same_psk = constant_time_bytes_equal(
                profile.secret.expose_secret().as_bytes(),
                other.secret.expose_secret().as_bytes(),
            );
            if same_tuple || same_psk {
                return Err(AuthV3Error::Credential);
            }
        }
    }
    Ok(())
}

/// Encode one exact 256-byte direct auth-v3 `ClientControl`.
///
/// The MAC binds the complete [`SecretString`] UTF-8 bytes and the exporter
/// from the supplied trusted connection context. This function performs no
/// runtime I/O or state transition.
pub fn encode_auth_v3_client_control(
    profile: &AuthV3TrustedProfile<'_>,
    connection: &AuthV3TrustedConnectionContext<'_>,
    input: &AuthV3ClientControlInput,
) -> Result<[u8; AUTH_V3_CLIENT_CONTROL_LEN], AuthV3Error> {
    validate_trusted_profile(profile)?;
    validate_trusted_connection(profile, connection, input.carrier)?;
    if input.client_time_unix == 0 || input.client_time_unix == u64::MAX {
        return Err(AuthV3Error::Time);
    }
    if input.client_time_unix >= profile.credential_not_after_unix {
        return Err(AuthV3Error::Credential);
    }
    if all_zero(&input.client_nonce) {
        return Err(AuthV3Error::Nonce);
    }

    let policy = policy_for(input.carrier);
    let commitments = commitments_for(profile);
    let policy_hash = policy_hash(&policy);
    let key = mac_key(profile, CLIENT_KEY_INFO, &commitments);

    let mut encoded = [0u8; AUTH_V3_CLIENT_CONTROL_LEN];
    encoded[0..4].copy_from_slice(MAGIC);
    write_u16(&mut encoded, 4, VERSION);
    encoded[6] = CLIENT_CONTROL_TYPE;
    write_u16(&mut encoded, 8, AUTH_V3_CLIENT_CONTROL_LEN as u16);
    encoded[12..20].copy_from_slice(&policy);
    encoded[20] = TLS_EXPORTER_BINDING;
    write_u16(&mut encoded, 22, TLS13_CLASSICAL_FLOOR);
    write_u32(&mut encoded, 24, DIRECT_CARRIER_SESSION_V1);
    write_u16(&mut encoded, 28, EXPLICIT_BOUNDED_LIMITS_V1);
    write_u64(&mut encoded, 32, profile.credential_epoch);
    write_u64(&mut encoded, 40, input.client_time_unix);
    encoded[48..80].copy_from_slice(&commitments.principal);
    encoded[80..112].copy_from_slice(&commitments.deployment);
    encoded[112..144].copy_from_slice(&commitments.namespace);
    encoded[144..176].copy_from_slice(&input.client_nonce);
    encoded[176..192].copy_from_slice(DOWNGRADE_SENTINEL);
    encoded[192..224].copy_from_slice(&policy_hash);
    let tag = client_tag(&key, connection.tls_exporter, &encoded[..224]);
    encoded[224..256].copy_from_slice(&tag);
    Ok(encoded)
}

/// Strictly parse one exact direct auth-v3 `ClientControl`.
pub fn parse_auth_v3_client_control(
    input: &[u8],
) -> Result<ParsedAuthV3ClientControl, AuthV3Error> {
    if input.len() != AUTH_V3_CLIENT_CONTROL_LEN {
        return Err(AuthV3Error::Shape);
    }
    if &input[0..4] != MAGIC
        || read_u16(input, 4) != VERSION
        || input[6] != CLIENT_CONTROL_TYPE
        || read_u16(input, 8) as usize != AUTH_V3_CLIENT_CONTROL_LEN
    {
        return Err(AuthV3Error::Header);
    }
    validate_reserved(input)?;
    let policy = read_array::<8>(input, 12);
    let carrier = validate_policy(&policy)?;
    validate_registries(input)?;

    let credential_epoch = read_u64(input, 32);
    if credential_epoch == 0 {
        return Err(AuthV3Error::Epoch);
    }
    let client_time_unix = read_u64(input, 40);
    if client_time_unix == 0 || client_time_unix == u64::MAX {
        return Err(AuthV3Error::Time);
    }
    let client_nonce = read_array::<32>(input, 144);
    if all_zero(&client_nonce) {
        return Err(AuthV3Error::Nonce);
    }
    if &input[176..192] != DOWNGRADE_SENTINEL {
        return Err(AuthV3Error::Sentinel);
    }
    if !constant_time_array_equal(&read_array::<32>(input, 192), &policy_hash(&policy)) {
        return Err(AuthV3Error::Policy);
    }

    Ok(ParsedAuthV3ClientControl {
        carrier,
        policy,
        credential_epoch,
        client_time_unix,
        principal_commitment: read_array(input, 48),
        deployment_profile_commitment: read_array(input, 80),
        credential_namespace_commitment: read_array(input, 112),
        client_nonce,
        auth_tag: read_array(input, 224),
    })
}

/// Verify one `ClientControl` against independent trusted local facts.
///
/// `profile` must already have been selected by a non-wire, trusted local
/// mechanism. T013c-1 supplies [`AuthV3SingletonBinding`] and
/// [`AuthV3PreselectedProfile`] for the exact-one-profile server/listener case.
/// Wire commitments only prove equality with that exact tuple; they never
/// select or replace a profile, identity, epoch, or PSK. Runtime integration
/// remains deferred, so this API must not be wired into H2/H3 in this slice.
///
/// `trusted_server_now_unix` is the verifier's clock, not a wire value. Success
/// returns metadata for confirmation construction; it does not change runtime
/// connection state and does not permit legacy fallback after later failure.
pub fn verify_auth_v3_client_control(
    input: &[u8],
    profile: &AuthV3TrustedProfile<'_>,
    connection: &AuthV3TrustedConnectionContext<'_>,
    trusted_server_now_unix: u64,
) -> Result<VerifiedAuthV3ClientControl, AuthV3Error> {
    let parsed = parse_auth_v3_client_control(input)?;
    validate_trusted_profile(profile)?;
    validate_trusted_connection(profile, connection, parsed.carrier)?;
    if parsed.credential_epoch != profile.credential_epoch {
        return Err(AuthV3Error::Epoch);
    }
    if trusted_server_now_unix >= profile.credential_not_after_unix {
        return Err(AuthV3Error::Credential);
    }
    if !time_within_skew(parsed.client_time_unix, trusted_server_now_unix) {
        return Err(AuthV3Error::Time);
    }

    let commitments = commitments_for(profile);
    if !constant_time_array_equal(&parsed.principal_commitment, &commitments.principal)
        || !constant_time_array_equal(
            &parsed.deployment_profile_commitment,
            &commitments.deployment,
        )
        || !constant_time_array_equal(
            &parsed.credential_namespace_commitment,
            &commitments.namespace,
        )
    {
        return Err(AuthV3Error::Identity);
    }

    let key = mac_key(profile, CLIENT_KEY_INFO, &commitments);
    verify_client_tag(
        &key,
        connection.tls_exporter,
        &input[..224],
        &parsed.auth_tag,
    )?;
    let server_mac_key = mac_key(profile, SERVER_KEY_INFO, &commitments);
    let mut encoded = [0u8; AUTH_V3_CLIENT_CONTROL_LEN];
    encoded.copy_from_slice(input);
    Ok(VerifiedAuthV3ClientControl {
        parsed,
        encoded,
        tls_exporter: *connection.tls_exporter,
        server_mac_key,
        credential_not_after_unix: profile.credential_not_after_unix,
        expected_deployment_profile_id: *profile.deployment_profile_id,
        expected_server_identity_id: *profile.expected_server_identity_id,
        expected_direct_route: profile.expected_direct_route,
        expected_control_path: profile.expected_control_path.to_owned(),
    })
}

/// Encode one exact 320-byte direct auth-v3 `ServerConfirmation`.
///
/// The server lifetime caps are enforced against `server_now_unix`, and both
/// expiries must be no later than the trusted credential expiry. This function
/// consumes the verified capability so one verification call can produce at
/// most one confirmation. It performs no response I/O and does not mark a
/// generation authenticated. A runtime can still verify the same bytes again;
/// true atomic single-use remains a later runtime responsibility.
pub fn encode_auth_v3_server_confirmation(
    verified_client: VerifiedAuthV3ClientControl,
    connection: &AuthV3TrustedConnectionContext<'_>,
    input: &AuthV3ServerConfirmationInput,
) -> Result<[u8; AUTH_V3_SERVER_CONFIRMATION_LEN], AuthV3Error> {
    validate_verified_connection(&verified_client, connection)?;
    if input.server_now_unix >= verified_client.credential_not_after_unix {
        return Err(AuthV3Error::Credential);
    }
    if !valid_server_expiries(
        input.server_now_unix,
        input.admission_expiry_unix,
        input.hard_expiry_unix,
        verified_client.credential_not_after_unix,
    ) {
        return Err(AuthV3Error::Expiry);
    }
    if all_zero(&input.server_nonce) || all_zero(&input.session_id) {
        return Err(AuthV3Error::Nonce);
    }
    if input.max_frame_size == 0 || input.max_concurrent_flows == 0 {
        return Err(AuthV3Error::Limits);
    }

    let parsed = &verified_client.parsed;
    let commitments = Commitments {
        principal: parsed.principal_commitment,
        deployment: parsed.deployment_profile_commitment,
        namespace: parsed.credential_namespace_commitment,
    };
    let policy_hash = policy_hash(&parsed.policy);
    let client_commitment = client_control_commitment(&verified_client.encoded);
    let mut encoded = [0u8; AUTH_V3_SERVER_CONFIRMATION_LEN];
    encoded[0..4].copy_from_slice(MAGIC);
    write_u16(&mut encoded, 4, VERSION);
    encoded[6] = SERVER_CONFIRMATION_TYPE;
    write_u16(&mut encoded, 8, AUTH_V3_SERVER_CONFIRMATION_LEN as u16);
    encoded[12..20].copy_from_slice(&parsed.policy);
    encoded[20] = TLS_EXPORTER_BINDING;
    write_u16(&mut encoded, 22, TLS13_CLASSICAL_FLOOR);
    write_u32(&mut encoded, 24, DIRECT_CARRIER_SESSION_V1);
    write_u16(&mut encoded, 28, EXPLICIT_BOUNDED_LIMITS_V1);
    write_u64(&mut encoded, 32, parsed.credential_epoch);
    write_u64(&mut encoded, 40, input.admission_expiry_unix);
    write_u64(&mut encoded, 48, input.hard_expiry_unix);
    encoded[56..88].copy_from_slice(&commitments.principal);
    encoded[88..120].copy_from_slice(&commitments.deployment);
    encoded[120..152].copy_from_slice(&commitments.namespace);
    encoded[152..184].copy_from_slice(&input.server_nonce);
    encoded[184..200].copy_from_slice(&input.session_id);
    encoded[200..216].copy_from_slice(DOWNGRADE_SENTINEL);
    encoded[216..248].copy_from_slice(&policy_hash);
    encoded[248..280].copy_from_slice(&client_commitment);
    write_u32(&mut encoded, 280, input.max_frame_size);
    write_u32(&mut encoded, 284, input.max_concurrent_flows);
    let tag = server_tag(
        &verified_client.server_mac_key,
        connection.tls_exporter,
        &encoded[..288],
    );
    encoded[288..320].copy_from_slice(&tag);
    Ok(encoded)
}

/// Strictly parse one exact direct auth-v3 `ServerConfirmation`.
pub fn parse_auth_v3_server_confirmation(
    input: &[u8],
) -> Result<ParsedAuthV3ServerConfirmation, AuthV3Error> {
    if input.len() != AUTH_V3_SERVER_CONFIRMATION_LEN {
        return Err(AuthV3Error::Shape);
    }
    if &input[0..4] != MAGIC
        || read_u16(input, 4) != VERSION
        || input[6] != SERVER_CONFIRMATION_TYPE
        || read_u16(input, 8) as usize != AUTH_V3_SERVER_CONFIRMATION_LEN
    {
        return Err(AuthV3Error::Header);
    }
    validate_reserved(input)?;
    let policy = read_array::<8>(input, 12);
    let carrier = validate_policy(&policy)?;
    validate_registries(input)?;

    let credential_epoch = read_u64(input, 32);
    if credential_epoch == 0 {
        return Err(AuthV3Error::Epoch);
    }
    let admission_expiry_unix = read_u64(input, 40);
    let hard_expiry_unix = read_u64(input, 48);
    if admission_expiry_unix >= hard_expiry_unix {
        return Err(AuthV3Error::Expiry);
    }
    let server_nonce = read_array::<32>(input, 152);
    let session_id = read_array::<16>(input, 184);
    if all_zero(&server_nonce) || all_zero(&session_id) {
        return Err(AuthV3Error::Nonce);
    }
    if &input[200..216] != DOWNGRADE_SENTINEL {
        return Err(AuthV3Error::Sentinel);
    }
    if !constant_time_array_equal(&read_array::<32>(input, 216), &policy_hash(&policy)) {
        return Err(AuthV3Error::Policy);
    }
    let max_frame_size = read_u32(input, 280);
    let max_concurrent_flows = read_u32(input, 284);
    if max_frame_size == 0 || max_concurrent_flows == 0 {
        return Err(AuthV3Error::Limits);
    }

    Ok(ParsedAuthV3ServerConfirmation {
        carrier,
        policy,
        credential_epoch,
        admission_expiry_unix,
        hard_expiry_unix,
        principal_commitment: read_array(input, 56),
        deployment_profile_commitment: read_array(input, 88),
        credential_namespace_commitment: read_array(input, 120),
        server_nonce,
        session_id,
        client_control_commitment: read_array(input, 248),
        max_frame_size,
        max_concurrent_flows,
        auth_tag: read_array(input, 288),
    })
}

/// Verify one `ServerConfirmation` against the original `ClientControl` and
/// independent trusted local facts.
///
/// The client receipt caps are 2,100 and 86,700 seconds solely to compensate
/// for the already bounded 300-second clock skew. Success returns metadata and
/// does not perform the runtime authenticated-state transition.
pub fn verify_auth_v3_server_confirmation(
    input: &[u8],
    client_control: &[u8],
    profile: &AuthV3TrustedProfile<'_>,
    connection: &AuthV3TrustedConnectionContext<'_>,
    receipt: &AuthV3ClientReceipt,
) -> Result<VerifiedAuthV3ServerConfirmation, AuthV3Error> {
    let verified_client = verify_auth_v3_client_control(
        client_control,
        profile,
        connection,
        receipt.client_now_unix,
    )?;
    let parsed = parse_auth_v3_server_confirmation(input)?;
    validate_trusted_connection(profile, connection, parsed.carrier)?;

    if parsed.policy != verified_client.parsed.policy {
        return Err(AuthV3Error::Echo);
    }
    if parsed.credential_epoch != verified_client.parsed.credential_epoch {
        return Err(AuthV3Error::Epoch);
    }
    if !valid_client_expiries(
        receipt.client_now_unix,
        parsed.admission_expiry_unix,
        parsed.hard_expiry_unix,
        profile.credential_not_after_unix,
    ) {
        return Err(AuthV3Error::Expiry);
    }
    if !constant_time_array_equal(
        &parsed.principal_commitment,
        &verified_client.parsed.principal_commitment,
    ) || !constant_time_array_equal(
        &parsed.deployment_profile_commitment,
        &verified_client.parsed.deployment_profile_commitment,
    ) || !constant_time_array_equal(
        &parsed.credential_namespace_commitment,
        &verified_client.parsed.credential_namespace_commitment,
    ) {
        return Err(AuthV3Error::Echo);
    }
    if parsed.max_frame_size > receipt.max_frame_size_cap
        || parsed.max_concurrent_flows > receipt.max_concurrent_flows_cap
    {
        return Err(AuthV3Error::Limits);
    }
    if !constant_time_array_equal(
        &parsed.client_control_commitment,
        &client_control_commitment(&verified_client.encoded),
    ) {
        return Err(AuthV3Error::Commitment);
    }

    let commitments = Commitments {
        principal: verified_client.parsed.principal_commitment,
        deployment: verified_client.parsed.deployment_profile_commitment,
        namespace: verified_client.parsed.credential_namespace_commitment,
    };
    let key = mac_key(profile, SERVER_KEY_INFO, &commitments);
    verify_server_tag(
        &key,
        connection.tls_exporter,
        &input[..288],
        &parsed.auth_tag,
    )?;
    Ok(VerifiedAuthV3ServerConfirmation { parsed })
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Commitments {
    principal: [u8; 32],
    deployment: [u8; 32],
    namespace: [u8; 32],
}

fn validate_trusted_profile(profile: &AuthV3TrustedProfile<'_>) -> Result<(), AuthV3Error> {
    if profile.credential_epoch == 0
        || profile.credential_not_after_unix == 0
        || all_zero(profile.principal_id)
        || all_zero(profile.deployment_profile_id)
        || all_zero(profile.credential_namespace_id)
        || all_zero(profile.expected_server_identity_id)
        || profile.expected_control_path.is_empty()
        || profile.secret.validate().is_err()
    {
        return Err(AuthV3Error::Credential);
    }
    if !profile.expected_direct_route {
        return Err(AuthV3Error::Context);
    }
    Ok(())
}

fn validate_trusted_connection(
    profile: &AuthV3TrustedProfile<'_>,
    connection: &AuthV3TrustedConnectionContext<'_>,
    claimed_carrier: AuthV3Carrier,
) -> Result<(), AuthV3Error> {
    if claimed_carrier != connection.actual_carrier
        || connection.actual_tls_version != AuthV3TlsVersion::Tls13
        || !profile.expected_direct_route
        || !connection.actual_direct_route
        || connection.early_data
        || !connection.exporter_from_same_generation
        || !matches!(connection.exporter_context, Some(context) if context.is_empty())
        || connection.deployment_profile_id != profile.deployment_profile_id
        || connection.server_identity_id != profile.expected_server_identity_id
        || connection.control_path != profile.expected_control_path
    {
        return Err(AuthV3Error::Context);
    }
    Ok(())
}

fn validate_verified_connection(
    verified: &VerifiedAuthV3ClientControl,
    connection: &AuthV3TrustedConnectionContext<'_>,
) -> Result<(), AuthV3Error> {
    if verified.parsed.carrier != connection.actual_carrier
        || connection.actual_tls_version != AuthV3TlsVersion::Tls13
        || !verified.expected_direct_route
        || !connection.actual_direct_route
        || connection.early_data
        || !connection.exporter_from_same_generation
        || !matches!(connection.exporter_context, Some(context) if context.is_empty())
        || connection.deployment_profile_id != &verified.expected_deployment_profile_id
        || connection.server_identity_id != &verified.expected_server_identity_id
        || connection.control_path != verified.expected_control_path
        || !constant_time_array_equal(&verified.tls_exporter, connection.tls_exporter)
    {
        return Err(AuthV3Error::Context);
    }
    Ok(())
}

fn validate_reserved(input: &[u8]) -> Result<(), AuthV3Error> {
    if input[7] != 0
        || input[10..12].iter().any(|value| *value != 0)
        || input[21] != 0
        || input[30..32].iter().any(|value| *value != 0)
    {
        return Err(AuthV3Error::Reserved);
    }
    Ok(())
}

fn validate_registries(input: &[u8]) -> Result<(), AuthV3Error> {
    if input[20] != TLS_EXPORTER_BINDING {
        return Err(AuthV3Error::Binding);
    }
    if read_u16(input, 22) != TLS13_CLASSICAL_FLOOR {
        return Err(AuthV3Error::KeyExchange);
    }
    if read_u32(input, 24) != DIRECT_CARRIER_SESSION_V1 {
        return Err(AuthV3Error::Capabilities);
    }
    if read_u16(input, 28) != EXPLICIT_BOUNDED_LIMITS_V1 {
        return Err(AuthV3Error::ResourceClass);
    }
    Ok(())
}

fn policy_for(carrier: AuthV3Carrier) -> [u8; 8] {
    [1, 1, carrier.wire_id(), DIRECT_TRUST_ROUTE, 1, 1, 0, 0]
}

fn validate_policy(policy: &[u8; 8]) -> Result<AuthV3Carrier, AuthV3Error> {
    let carrier = AuthV3Carrier::from_wire_id(policy[2])?;
    if policy != &policy_for(carrier) {
        return Err(AuthV3Error::Policy);
    }
    Ok(carrier)
}

fn commitments_for(profile: &AuthV3TrustedProfile<'_>) -> Commitments {
    Commitments {
        principal: identity_commitment(PRINCIPAL_COMMITMENT_LABEL, profile.principal_id),
        deployment: identity_commitment(DEPLOYMENT_COMMITMENT_LABEL, profile.deployment_profile_id),
        namespace: identity_commitment(NAMESPACE_COMMITMENT_LABEL, profile.credential_namespace_id),
    }
}

fn trusted_credential_tuple(
    profile: &AuthV3TrustedProfile<'_>,
) -> ([u8; 32], [u8; 32], [u8; 32], u64) {
    let commitments = commitments_for(profile);
    (
        commitments.principal,
        commitments.deployment,
        commitments.namespace,
        profile.credential_epoch,
    )
}

fn identity_commitment(label: &[u8], opaque_id: &[u8; 16]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update(16u16.to_be_bytes());
    digest.update(opaque_id);
    digest.finalize().into()
}

fn policy_hash(policy: &[u8; 8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(POLICY_HASH_LABEL);
    digest.update(8u16.to_be_bytes());
    digest.update(policy);
    digest.finalize().into()
}

fn client_control_commitment(input: &[u8; AUTH_V3_CLIENT_CONTROL_LEN]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(CLIENT_COMMITMENT_LABEL);
    digest.update((AUTH_V3_CLIENT_CONTROL_LEN as u16).to_be_bytes());
    digest.update(input);
    digest.finalize().into()
}

fn mac_key(
    profile: &AuthV3TrustedProfile<'_>,
    info_label: &[u8],
    commitments: &Commitments,
) -> Zeroizing<[u8; 32]> {
    let mut salt = Vec::with_capacity(HKDF_SALT_LABEL.len() + 8);
    salt.extend_from_slice(HKDF_SALT_LABEL);
    salt.extend_from_slice(&profile.credential_epoch.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), profile.secret.expose_secret().as_bytes());
    let mut info = Vec::with_capacity(info_label.len() + 96);
    info.extend_from_slice(info_label);
    info.extend_from_slice(&commitments.principal);
    info.extend_from_slice(&commitments.deployment);
    info.extend_from_slice(&commitments.namespace);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, &mut *key)
        .expect("32-byte HKDF output length is valid");
    key
}

fn client_tag(key: &[u8; 32], exporter: &[u8; AUTH_V3_EXPORTER_LEN], prefix: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    update_client_transcript(&mut mac, exporter, prefix);
    mac.finalize().into_bytes().into()
}

fn verify_client_tag(
    key: &[u8; 32],
    exporter: &[u8; AUTH_V3_EXPORTER_LEN],
    prefix: &[u8],
    tag: &[u8; 32],
) -> Result<(), AuthV3Error> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    update_client_transcript(&mut mac, exporter, prefix);
    mac.verify_slice(tag).map_err(|_| AuthV3Error::Mac)
}

fn update_client_transcript(
    mac: &mut HmacSha256,
    exporter: &[u8; AUTH_V3_EXPORTER_LEN],
    prefix: &[u8],
) {
    mac.update(CLIENT_TRANSCRIPT_LABEL);
    mac.update(&(AUTH_V3_EXPORTER_LEN as u16).to_be_bytes());
    mac.update(exporter);
    mac.update(&224u16.to_be_bytes());
    mac.update(prefix);
}

fn server_tag(key: &[u8; 32], exporter: &[u8; AUTH_V3_EXPORTER_LEN], prefix: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    update_server_transcript(&mut mac, exporter, prefix);
    mac.finalize().into_bytes().into()
}

fn verify_server_tag(
    key: &[u8; 32],
    exporter: &[u8; AUTH_V3_EXPORTER_LEN],
    prefix: &[u8],
    tag: &[u8; 32],
) -> Result<(), AuthV3Error> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    update_server_transcript(&mut mac, exporter, prefix);
    mac.verify_slice(tag).map_err(|_| AuthV3Error::Mac)
}

fn update_server_transcript(
    mac: &mut HmacSha256,
    exporter: &[u8; AUTH_V3_EXPORTER_LEN],
    prefix: &[u8],
) {
    mac.update(SERVER_TRANSCRIPT_LABEL);
    mac.update(&(AUTH_V3_EXPORTER_LEN as u16).to_be_bytes());
    mac.update(exporter);
    mac.update(&288u16.to_be_bytes());
    mac.update(prefix);
}

fn time_within_skew(peer_time: u64, trusted_now: u64) -> bool {
    if peer_time == 0 || peer_time == u64::MAX {
        return false;
    }
    if peer_time <= trusted_now {
        trusted_now
            .checked_sub(peer_time)
            .is_some_and(|delta| delta <= MAX_CLOCK_SKEW_SECONDS)
    } else {
        peer_time
            .checked_sub(trusted_now)
            .is_some_and(|delta| delta <= MAX_CLOCK_SKEW_SECONDS)
    }
}

fn valid_server_expiries(
    trusted_now: u64,
    admission: u64,
    hard: u64,
    credential_not_after: u64,
) -> bool {
    trusted_now < admission
        && admission < hard
        && admission <= credential_not_after
        && hard <= credential_not_after
        && admission
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= MAX_SERVER_ADMISSION_SECONDS)
        && hard
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= MAX_SERVER_HARD_SECONDS)
}

fn valid_client_expiries(
    trusted_now: u64,
    admission: u64,
    hard: u64,
    credential_not_after: u64,
) -> bool {
    trusted_now < admission
        && admission < hard
        && admission <= credential_not_after
        && hard <= credential_not_after
        && admission
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= MAX_CLIENT_ADMISSION_SECONDS)
        && hard
            .checked_sub(trusted_now)
            .is_some_and(|lifetime| lifetime <= MAX_CLIENT_HARD_SECONDS)
}

fn constant_time_array_equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    bool::from(left.ct_eq(right))
}

fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn all_zero<const N: usize>(value: &[u8; N]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn read_array<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    input[offset..offset + N]
        .try_into()
        .expect("validated auth-v3 fixed message length")
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array(input, offset))
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array(input, offset))
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(read_array(input, offset))
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
