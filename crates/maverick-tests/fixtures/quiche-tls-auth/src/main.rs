use maverick_quiche_tls_auth::smoke::{self, TransferMode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    for v2 in [false, true] {
        for mode in [
            TransferMode::ClientFirst,
            TransferMode::ServerFirst,
            TransferMode::Simultaneous,
        ] {
            let bytes = smoke::run_with_mode(v2, mode).await?;
            println!(
                "H3 local SOCKS/TCP auth v{} {mode:?}: {bytes} bytes each direction passed",
                if v2 { 2 } else { 1 }
            );
        }
    }
    Ok(())
}
