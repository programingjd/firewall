use firewall::builder::*;

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let _ = Firewall::default()
        .try_allow_cloudflare_ips()
        .await
        .unwrap();

    Ok(())
}
