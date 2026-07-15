//! Core protocol, configuration, authentication, and framing for Maverick.
//!
//! Maverick is an experimental prototype. It uses TLS 1.3 + HTTP/2 for
//! default transport encryption, optional feature-gated H3/QUIC, and
//! HMAC-SHA256 for in-channel client authentication.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod crypto;
pub mod diagnostics;
pub mod ech;
pub mod error;
pub mod experimental;
pub mod frame;
pub mod grpc;
#[cfg(feature = "noise-experimental")]
pub mod noise;
pub mod padding;
pub mod replay;
pub mod tun;
pub mod util;

pub use auth::{
    ClientHello, ClientHelloV2, ServerHello, ServerHelloV2, AUTH_V2_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
pub use config::{
    CdnFrontingConfig, ClientConfig, Mode, SecretString, ServerConfig, StealthConfig,
    TlsFingerprintMode,
};
pub use crypto::{
    crypto_policy_diagnostics, crypto_suite_registry, CryptoPolicyConfig, CryptoPolicyDiagnostics,
    CryptoSuiteDiagnostic, CryptoSuiteId, CryptoSuiteStatus, NoisePrologueContext,
    NoiseReadinessBlocker, NoiseReadinessSnapshot, NoiseTransportContext,
};
pub use diagnostics::{
    EchDiagnosticStatus, EchDiagnosticsSnapshot, GuiConnectionState, GuiDiagnosticsSnapshot,
    GuiErrorClass, GuiRuntimeReadinessBlocker, GuiRuntimeReadinessSnapshot, GuiTransportCarrier,
    GuiTransportDebugSnapshot, GuiTransportStatus, GuiTunControlState, GuiTunSafetySnapshot,
    StealthDiagnosticStatus, StealthDiagnosticsSnapshot,
};
pub use ech::{EchReadinessBlocker, EchReadinessSnapshot};
pub use error::{Error, Result};
pub use experimental::{experimental_track_registry, ExperimentalTrackId, ExperimentalTrackStatus};
pub use frame::{Frame, FrameType, OpenTcpPayload, OpenUdpPayload, TargetAddr, UdpPacketPayload};
#[cfg(feature = "noise-experimental")]
pub use noise::{
    decode_noise_message_from, encode_noise_message, noise_static_public_key, NoiseHandshakeOutput,
    NoiseInitiator, NoiseResponder, NoiseRole, NoiseRuntimeConfig, NoiseTransportSession,
    DEFAULT_NOISE_RUNTIME_MAX_FRAME_SIZE, MAX_NOISE_MESSAGE_SIZE,
    MAX_NOISE_TRANSPORT_PLAINTEXT_SIZE, NOISE_XX_25519_CHACHAPOLY_SHA256,
};
pub use tun::{
    build_tun_runtime_plan, classify_tun_packet, evaluate_tun_apply_safety, TunApplyBlocker,
    TunApplySafetyContext, TunApplySafetyDecision, TunPacketClassification, TunPacketFlow,
    TunRoute, TunRoutePlan, TunRuntimeAction, TunRuntimePlan, TunRuntimeReadinessBlocker,
    TunRuntimeReadinessSnapshot, TunRuntimeRollbackAction, TunTransportProtocol,
};
