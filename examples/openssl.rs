use firewall::builder::{AcceptDenyOverride, Firewall, TlsAccept};
use firewall::openssl::init;
use firewall::{Accept, ClientHello};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{HandshakeError, SslAcceptor, SslMethod, SslVerifyMode};
use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509};
use std::fmt::{Debug, Display, Formatter};
use std::io::{copy, sink, Error as IOError, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Error conversions
#[derive(Debug)]
enum Error {
    OpenSSL(ErrorStack),
    Handshake(HandshakeError<TcpStream>),
    IO(IOError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OpenSSL(err) => write!(f, "{:?}", err),
            Error::Handshake(err) => write!(f, "{:?}", err),
            Error::IO(err) => write!(f, "{:?}", err),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(value: ErrorStack) -> Self {
        Self::OpenSSL(value)
    }
}

impl From<HandshakeError<TcpStream>> for Error {
    fn from(value: HandshakeError<TcpStream>) -> Self {
        Self::Handshake(value)
    }
}

impl From<IOError> for Error {
    fn from(value: IOError) -> Self {
        Self::IO(value)
    }
}

/// Generate self signed certificate for domain "localhost".
fn generate_self_signed_certificates() -> Result<(PKey<Private>, X509), Error> {
    let pkey: PKey<Private> = Rsa::generate(2048)?.try_into()?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(BigNum::from_u32(1)?.to_asn1_integer()?.as_ref())?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "localhost")?;
    let name = name.build();
    builder.set_issuer_name(&name)?;
    builder.set_subject_name(&name)?;
    builder.set_pubkey(&pkey)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    let mut san1 = SubjectAlternativeName::new();
    san1.dns("localhost");
    let extension1 = san1.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(extension1)?;
    builder.append_extension(KeyUsage::new().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    builder.sign(&pkey, MessageDigest::sha512())?;
    let cert = builder.build();
    Ok((pkey, cert))
}

struct RequireHttp1 {}

impl TlsAccept for RequireHttp1 {
    fn accept(&self, client_hello: impl ClientHello) -> AcceptDenyOverride {
        if client_hello.has_alpn(b"http/1.1") || client_hello.has_alpn(b"http/1.0") {
            AcceptDenyOverride::Accept
        } else {
            AcceptDenyOverride::Deny
        }
    }
}

/// The only remote addresses allowed are 127.0.0.1 (localhost ipv4) and ::1 (localhost ipv6).
/// The SNI server name is required and should be "localhost".
/// The ALPN extension is required and should include "http/1.1" and/or "http/1.0".
fn main() -> Result<(), Error> {
    let firewall = Firewall::default()
        .require_sni()
        .allow_server_name("localhost")
        .try_allow_ip("127.0.0.1")
        .unwrap()
        .try_allow_ip("::1")
        .unwrap()
        .with_exception(RequireHttp1 {});
    start_server(firewall)
}

fn start_server(firewall: Firewall<RequireHttp1>) -> Result<(), Error> {
    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls())?;
    let (pkey, cert) = generate_self_signed_certificates()?;
    acceptor.set_private_key(&pkey)?;
    acceptor.set_certificate(&cert)?;
    acceptor.set_verify(SslVerifyMode::NONE);
    // acceptor.
    let index = init(&mut acceptor, vec![b"http/1.1"])?;
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:443")?;
    println!("https://localhost");
    loop {
        let (tcp_stream, remote_addr) = listener.accept()?;
        if let Ok(mut tls_stream) = acceptor.accept(tcp_stream) {
            let ssl = tls_stream.ssl();
            if firewall.accept(remote_addr.ip(), Some((ssl, index))) {
                thread::spawn(move || {
                    let _ = tls_stream
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
                        .unwrap();
                    let _ = copy(&mut tls_stream, &mut sink()).unwrap();
                    let _ = tls_stream.shutdown();
                });
            }
        }
    }
}
