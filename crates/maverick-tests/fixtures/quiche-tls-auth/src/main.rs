#[tokio::main]
async fn main() -> anyhow::Result<()> {
    for v2 in [false, true] {
        let bytes = maverick_quiche_tls_auth::smoke::run(v2).await?;
        println!(
            "H3 local SOCKS/TCP auth v{}: {bytes} bytes each direction, half-close passed",
            if v2 { 2 } else { 1 }
        );
    }
    Ok(())
}
