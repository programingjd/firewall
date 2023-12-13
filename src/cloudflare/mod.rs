use crate::cloudflare::errors::Error;
use reqwest::Client;

mod errors;

type Result<T> = core::result::Result<T, Error>;

async fn fetch_cloudflare_ip_ranges() -> Result<Vec<String>> {
    let client = Client::new();
    let ips_v4 = client
        .get("https://www.cloudflare.com/ips-v4/")
        .send()
        .await
        .map_err(|_| Error::IpRangeFetchError)?
        .text()
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    let ips_v6 = client
        .get("https://www.cloudflare.com/ips-v6/")
        .send()
        .await
        .map_err(|_| Error::IpRangeFetchError)?
        .text()
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    Ok(ips_v4
        .lines()
        .chain(ips_v6.lines())
        .filter(|&line| !line.is_empty())
        .map(|line| line.to_owned())
        .collect())
}
