#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "builder")]
pub mod builder;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

use std::borrow::Borrow;
use std::net::IpAddr;

pub trait Accept {
    fn accept(&self, ip: impl Borrow<IpAddr>, client_hello: Option<impl ClientHello>) -> bool;
}

pub trait ClientHello {
    fn server_name(&self) -> Option<&str>;
    fn has_alpn(&self, alpn: &[u8]) -> bool;
}
