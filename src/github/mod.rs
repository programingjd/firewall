use crate::builder::Firewall;
use crate::github::errors::Error;
use cidr::IpCidr;
use read_until_slice::AsyncBufReadUntilSliceExt;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

pub mod errors;

type Result<T> = core::result::Result<T, Error>;

impl Firewall {
    pub async fn try_allow_github_webhook_ips(self) -> Result<Self> {
        let ranges = fetch_github_webhook_ip_ranges().await?;
        Ok(self.allow_ip_ranges(ranges.into_iter()))
    }
}

pub async fn fetch_github_webhook_ip_ranges() -> Result<Vec<IpCidr>> {
    let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect("api.github.com:443")
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    let stream = connector
        .connect(ServerName::try_from("api.github.com").unwrap(), tcp_stream)
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    let mut stream = BufStream::new(stream);
    stream
        .write_all(
            b"\
        GET /meta HTTP/1.0\r\n\
        Host: api.github.com\r\n\
        Accept-Encoding: identity\r\n\
        Accept: application/json\r\n\
        Connection: close\r\n\
        Cache-Control: no-cache\r\n\
        User-Agent: firewall\r\n\
        \r\n\
    ",
        )
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    stream.flush().await.map_err(|_| Error::IpRangeFetchError)?;
    let mut bytes = vec![];
    stream
        .read_until_slice(b"\r\n\r\n", &mut bytes)
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    bytes.clear();
    stream
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    let meta: Meta = serde_json::from_slice(&bytes).map_err(|_| Error::IpRangeFetchError)?;
    meta.hooks
        .into_iter()
        .map(|line| IpCidr::from_str(line.as_str()).map_err(|_| Error::IpRangeFetchError))
        .collect()
}

#[derive(Deserialize)]
struct Meta {
    hooks: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Accept, NoClientHello};
    use std::net::IpAddr;

    #[test]
    fn github_webhook_firewall() {
        let firewall = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                Firewall::default()
                    .try_allow_github_webhook_ips()
                    .await
                    .unwrap()
            });
        assert!(!firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            None::<NoClientHello>
        ));
        assert!(firewall.accept(
            IpAddr::from_str("185.199.108.3").unwrap(),
            None::<NoClientHello>,
        ));
        assert!(firewall.accept(
            IpAddr::from_str("::ffff:185.199.108.12").unwrap(),
            None::<NoClientHello>,
        ));
        assert!(firewall.accept(
            IpAddr::from_str("2a0a:a440::9").unwrap(),
            None::<NoClientHello>
        ));
    }
}
