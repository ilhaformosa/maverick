//! Maverick server.

#![forbid(unsafe_code)]

mod auth_gate;
pub mod fallback;
pub mod h2_acceptor;
pub mod relay;
pub mod server;
pub mod users;

mod runtime_metrics;

#[cfg(feature = "experimental-h3")]
pub use server::h3;
pub use server::{run_server, start_server, ServerHandle};
