use crate::cloudflare::errors::Error::IpRangeFetchError;
use crate::{Accept, ClientHello, Firewall, TlsAccept};
use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

#[derive(Debug, PartialEq)]
pub enum Error {
    IpRangeFetchError,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            IpRangeFetchError => {
                write!(f, "failed to fetch cloudflare ip ranges")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            IpRangeFetchError => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CloudflareFirewall<T: TlsAccept> {
    inner: Arc<RwLock<Firewall<T>>>,
}

impl<T: TlsAccept> Accept for CloudflareFirewall<T> {
    fn accept(&self, ip: impl Borrow<IpAddr>, client_hello: Option<impl ClientHello>) -> bool {
        self.inner.read().unwrap().accept(ip, client_hello)
    }
}

impl<T: TlsAccept> CloudflareFirewall<T> {}
