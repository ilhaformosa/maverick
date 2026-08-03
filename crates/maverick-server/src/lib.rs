//! Maverick server.

#![forbid(unsafe_code)]

mod auth_gate;
#[allow(dead_code)]
mod direct_v3_h2;
pub mod fallback;
pub mod h2_acceptor;
#[allow(dead_code)]
mod h3_connect;
#[cfg(feature = "quiche-foundation")]
#[allow(dead_code)]
mod quiche_registry;
#[cfg(feature = "quiche-foundation")]
#[allow(dead_code)]
mod quiche_runtime;
pub mod relay;
pub mod server;
pub mod users;

mod runtime_metrics;

pub use server::{run_server, start_server, ServerHandle};
