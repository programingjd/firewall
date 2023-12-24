//! [`openssl`] implementation of the [`ClientHello`] trait.

use crate::ClientHello;
extern crate openssl as extern_openssl;
use extern_openssl::error::ErrorStack;
use extern_openssl::ex_data::Index;
use extern_openssl::ssl::Ssl;
use extern_openssl::ssl::SslRef;
use extern_openssl::ssl::{AlpnError, NameType, SslAcceptorBuilder};

pub fn init<'a>(
    builder: &mut SslAcceptorBuilder,
    alpn_protocols: Vec<&'static [u8]>,
) -> Result<Index<Ssl, &'a [u8]>, ErrorStack> {
    let index = Ssl::new_ex_index()?;
    let server_protos = alpn_protocols.clone();
    builder.set_alpn_protos(to_alpn_wire(alpn_protocols).as_slice())?;
    builder.set_alpn_select_callback(move |ssl, alpn| {
        ssl.set_ex_data(index, alpn);
        from_alpn_wire(alpn)
            .into_iter()
            .find(|it| server_protos.contains(it))
            .ok_or(AlpnError::ALERT_FATAL)
    });
    Ok(index)
}

fn to_alpn_wire(protos: Vec<&[u8]>) -> Vec<u8> {
    protos
        .iter()
        .flat_map(|&it| [&[it.len() as u8], it].concat())
        .collect()
}

fn from_alpn_wire(wire: &[u8]) -> Vec<&[u8]> {
    let mut vec = Vec::new();
    let mut i = 0;
    while i < wire.len() {
        let len = wire[i] as usize;
        vec.push(&wire[i + 1..i + 1 + len]);
        i += len + 1;
    }
    vec
}

impl<'a> ClientHello for (&'a SslRef, Index<Ssl, &'a [u8]>) {
    fn server_name(&self) -> Option<&str> {
        self.0.servername(NameType::HOST_NAME)
    }
    fn has_alpn(&self, alpn: &[u8]) -> bool {
        if let Some(wire) = self.0.ex_data(self.1) {
            let vec = from_alpn_wire(wire);
            vec.contains(&alpn)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protos_to_alpn_wire() {
        assert_eq!(
            to_alpn_wire(vec![b"http/1.1", b"acme-tls/1"]),
            b"\x08http/1.1\x0aacme-tls/1"
        );
    }

    #[test]
    fn protos_from_alpn_wire() {
        let protos = from_alpn_wire(b"\x08http/1.1\x0aacme-tls/1");
        assert_eq!(protos.len(), 2);
        assert_eq!(protos[0], b"http/1.1");
        assert_eq!(protos[1], b"acme-tls/1");
    }
}
