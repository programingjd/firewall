use crate::builder::Firewall;
use crate::cloudflare::errors::Error;
use cidr::IpCidr;
use read_until_slice::AsyncBufReadUntilSliceExt;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::io::BufRead;
use std::str::{from_utf8, FromStr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

pub mod errors;

type Result<T> = core::result::Result<T, Error>;

impl Firewall {
    pub async fn try_allow_cloudflare_ips(self) -> Result<Self> {
        let ranges = fetch_cloudflare_ip_ranges().await?;
        Ok(self.allow_ip_ranges(ranges.into_iter()))
    }
}

pub async fn fetch_cloudflare_ip_ranges() -> Result<Vec<IpCidr>> {
    let root_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect("www.cloudflare.com:443")
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    let stream = connector
        .connect(
            ServerName::try_from("www.cloudflare.com").unwrap(),
            tcp_stream,
        )
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    let mut stream = BufStream::new(stream);
    stream
        .write_all(
            b"\
        GET /ips-v4/ HTTP/1.1\r\n\
        Host: www.cloudflare.com\r\n\
        Accept-Encoding: identity\r\n\
        Accept: text/plain\r\n\
        Connection: keep-alive\r\n\
        Cache-Control: no-cache\r\n\
        User-Agent: firewall\r\n\
        \r\n\
    ",
        )
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    stream.flush().await.map_err(|_| Error::IpRangeFetchError)?;
    let mut ips_v4 = vec![];
    let length = content_length(&mut stream, &mut ips_v4)
        .await
        .ok_or(Error::IpRangeFetchError)?;
    ips_v4.resize(length, 0u8);
    stream
        .read_exact(&mut ips_v4)
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    stream
        .write_all(
            b"\
        GET /ips-v6/ HTTP/1.1\r\n\
        Host: www.cloudflare.com\r\n\
        Accept-Encoding: identity\r\n\
        Accept: text/plain\r\n\
        Connection: close\r\n\
        Cache-Control: no-cache\r\n\
        User-Agent: firewall\r\n\
        \r\n\
    ",
        )
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    stream.flush().await.map_err(|_| Error::IpRangeFetchError)?;
    let mut ips_v6 = vec![];
    let content_length = content_length(&mut stream, &mut ips_v6)
        .await
        .ok_or(Error::IpRangeFetchError)?;
    ips_v6.clear();
    stream
        .read_to_end(&mut ips_v6)
        .await
        .map_err(|_| Error::IpRangeFetchError)?;
    assert_eq!(ips_v6.len(), content_length);
    ips_v4
        .lines()
        .chain(ips_v6.lines())
        .filter_map(|line| {
            if let Ok(line) = line {
                if line.is_empty() {
                    None
                } else {
                    Some(line)
                }
            } else {
                None
            }
        })
        .map(|line| IpCidr::from_str(line.as_str()).map_err(|_| Error::IpRangeFetchError))
        .collect()
}

async fn content_length(
    stream: &mut BufStream<TlsStream<TcpStream>>,
    buf: &mut Vec<u8>,
) -> Option<usize> {
    stream.read_until_slice(b"\r\n\r\n", buf).await.ok()?;
    assert!(buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let indices = buf
        .windows(2)
        .enumerate()
        .filter_map(|it| if it.1 == b"\r\n" { Some(it.0) } else { None })
        .collect::<Vec<_>>();
    indices.windows(2).find_map(|it| {
        let mut split = buf[it[0] + 2..it[1]].split(|&it| it == b':');
        if let Some(key) = split.next() {
            if key.eq_ignore_ascii_case(b"content-length") {
                split
                    .next()
                    .and_then(|it| from_utf8(it).ok())
                    .and_then(|it| it.trim().parse::<usize>().ok())
            } else {
                None
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Accept, NoClientHello};
    use std::net::IpAddr;

    #[test]
    fn cloudflare_firewall() {
        let firewall = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                Firewall::default()
                    .try_allow_cloudflare_ips()
                    .await
                    .unwrap()
            });
        assert!(!firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            None::<NoClientHello>
        ));
        assert!(firewall.accept(
            IpAddr::from_str("108.162.192.0").unwrap(),
            None::<NoClientHello>,
        ));
        assert!(firewall.accept(
            IpAddr::from_str("::ffff:108.162.192.0").unwrap(),
            None::<NoClientHello>,
        ));
        assert!(firewall.accept(
            IpAddr::from_str("2a06:98c0:1::").unwrap(),
            None::<NoClientHello>
        ));
    }
}
