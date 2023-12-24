use firewall::builder::Firewall;
use firewall::Accept;
use rcgen::generate_simple_self_signed;
extern crate rustls as extern_rustls;
use extern_rustls::crypto::ring::sign::any_supported_type;
use extern_rustls::pki_types::PrivateKeyDer;
use extern_rustls::server::{
    Acceptor, ClientHello as RustClientHello, ResolvesServerCert, ServerConfig,
};
use extern_rustls::sign::CertifiedKey;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::io::{copy, sink, split, AsyncWriteExt};
use tokio::join;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;

#[derive(Debug)]
struct LocalhostResolver {
    key: Arc<CertifiedKey>,
}

impl Default for LocalhostResolver {
    /// Create self signed certificate for domain "localhost" and ip "127.0.0.1".
    fn default() -> Self {
        let cert = generate_simple_self_signed(vec![
            "localhost".to_string(),
            format!("{}", Ipv4Addr::LOCALHOST),
        ])
        .expect("failed to generate self-signed certificate for localhost");
        let key = Arc::new(CertifiedKey::new(
            vec![cert
                .serialize_der()
                .expect("failed to generate certificate")
                .into()],
            any_supported_type(&PrivateKeyDer::Pkcs8(
                cert.serialize_private_key_der().into(),
            ))
            .expect("failed to generate signing key"),
        ));
        Self { key }
    }
}

impl ResolvesServerCert for LocalhostResolver {
    fn resolve(&self, _client_hello: RustClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

/// The only remote addresses allowed are 127.0.0.1 (localhost ipv4) and ::1 (localhost ipv6).
/// The SNI server name is not required, but if it's there, only "localhost" is accepted.
#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let firewall = Firewall::default()
        .allow_missing_sni()
        .allow_server_names(["localhost"].into_iter())
        .try_allow_ip("127.0.0.1")
        .unwrap()
        .try_allow_ip("::1")
        .unwrap();
    start_server(firewall).await
}

async fn start_server(firewall: Firewall) -> tokio::io::Result<()> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(LocalhostResolver::default()));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 443)).await?;
    println!("https://localhost");
    loop {
        let (tcp_stream, remote_addr) = listener.accept().await?;
        let firewall = firewall.clone();
        let config = config.clone();
        let handler = async move {
            let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);
            if let Ok(start_handshake) = acceptor.await {
                // Enforce the firewall rules
                if firewall.accept(remote_addr.ip(), Some(&start_handshake.client_hello())) {
                    if let Ok(stream) = start_handshake.into_stream(Arc::new(config)).await {
                        let (mut reader, mut writer) = split(stream);
                        join!(
                            async move {
                                let _ = writer
                                    .write(
                                        b"\
                                            HTTP/1.1 200 OK\r\n\
                                            Cache-Control: no-cache\r\n\
                                            Connection: close\r\n\
                                            Content-Type: text/plain;charset=UTF-8\r\n\
                                            Content-Length: 2\r\n\
                                            \r\n\
                                            OK\
                                        ",
                                    )
                                    .await;
                            },
                            async move {
                                let _ = copy(&mut reader, &mut sink()).await;
                            }
                        );
                    } else {
                        eprintln!("failed handshake")
                    }
                }
            } else {
                eprintln!("failed start handshake")
            }
        };
        tokio::spawn(handler);
    }
}
