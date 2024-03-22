#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;

#[cfg(feature = "builder")]
pub mod builder;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

#[cfg(feature = "github_webhook")]
pub mod github;

#[cfg(feature = "cloudflare")]
mod https;

use std::borrow::Borrow;
use std::net::IpAddr;

// TODO replace NoClientHello with Never (!) type when stable.
pub trait Accept<CH: ClientHello = NoClientHello> {
    fn accept(&self, ip: impl Borrow<IpAddr>, client_hello: Option<CH>) -> bool;
}

pub trait ClientHello {
    fn server_name(&self) -> Option<&str>;
    fn has_alpn(&self, alpn: &[u8]) -> bool;
}

pub struct NoClientHello {}

impl ClientHello for NoClientHello {
    fn server_name(&self) -> Option<&str> {
        unimplemented!()
    }

    fn has_alpn(&self, _alpn: &[u8]) -> bool {
        unimplemented!()
    }
}
