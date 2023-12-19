//! [`rustls`] implementation of the [`ClientHello`] trait.

use crate::ClientHello;
extern crate rustls as extern_rustls;
use extern_rustls::server::ClientHello as RustlsClientHello;

impl<'a> ClientHello for &'a RustlsClientHello<'a> {
    fn server_name(&self) -> Option<&str> {
        RustlsClientHello::server_name(self)
    }
    fn has_alpn(&self, alpn: &[u8]) -> bool {
        if let Some(mut iter) = self.alpn() {
            iter.any(|it| it == alpn)
        } else {
            false
        }
    }
}
