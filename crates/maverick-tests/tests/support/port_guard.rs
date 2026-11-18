use anyhow::{Context, Result};
use std::net::SocketAddr;

pub(crate) async fn with_port_guard<S, G>(
    start: impl AsyncFn() -> Result<(S, SocketAddr)>,
    mut bind_guard: impl AsyncFnMut(SocketAddr) -> std::io::Result<G>,
    stop: impl AsyncFn(S) -> Result<()>,
) -> Result<(S, G)> {
    // A live server owns its port for only one protocol. Keep both sockets on
    // success, and stop each rejected server before choosing another port.
    let mut ports_left = 4;
    loop {
        let (server, address) = start().await?;
        let error = match bind_guard(address).await {
            Ok(guard) => return Ok((server, guard)),
            Err(error) => error,
        };
        stop(server).await?;
        ports_left -= 1;
        if error.kind() != std::io::ErrorKind::AddrInUse || ports_left == 0 {
            return Err(error).context("bind companion socket on test server port");
        }
    }
}
