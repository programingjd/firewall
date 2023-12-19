use crate::builder::Firewall;
use crate::cloudflare::errors::Error;
use cidr::IpCidr;
use reqwest::Client;
use std::str::FromStr;

pub mod errors;

type Result<T> = core::result::Result<T, Error>;

impl Firewall {
    pub async fn try_allow_cloudflare_ips(self) -> Result<Self> {
        let ranges = fetch_cloudflare_ip_ranges().await?;
        Ok(self.allow_ip_ranges(ranges.into_iter()))
    }
}

async fn fetch_cloudflare_ip_ranges() -> Result<Vec<IpCidr>> {
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
    ips_v4
        .lines()
        .chain(ips_v6.lines())
        .filter(|&line| !line.is_empty())
        .map(|line| IpCidr::from_str(line).map_err(|_| Error::IpRangeFetchError))
        .into_iter()
        .collect()
}
