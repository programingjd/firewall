#[cfg(any(feature = "cloudflare", test))]
pub mod cloudflare;
mod errors;

use crate::errors::Error;
use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use rustls::server::ClientHello as RustlsClientHello;
use std::borrow::Borrow;
use std::net::IpAddr;
use std::str::FromStr;

type Result<T> = core::result::Result<T, Error>;

trait ClientHello {
    fn server_name(&self) -> Option<&str>;
    fn has_alpn(&self, alpn: &[u8]) -> bool;
}

impl<'a> ClientHello for &'a RustlsClientHello<'a> {
    fn server_name(&self) -> Option<&str> {
        self.server_name()
    }
    fn has_alpn(&self, alpn: &[u8]) -> bool {
        if let Some(mut iter) = self.alpn() {
            iter.any(|it| it == alpn)
        } else {
            false
        }
    }
}

pub trait Accept {
    fn accept(&self, ip: impl Borrow<IpAddr>, client_hello: Option<impl ClientHello>) -> bool;
}

pub enum AcceptDenyOverride {
    AcceptAndBypassAllowList,
    Accept,
    Deny,
}

pub trait TlsAccept {
    fn accept(&self, _client_hello: impl ClientHello) -> AcceptDenyOverride {
        AcceptDenyOverride::Accept
    }
}

#[derive(Debug, Clone)]
struct NoAcmeChallengeException {}

impl TlsAccept for NoAcmeChallengeException {}

#[derive(Debug, Clone)]
pub struct Firewall<T: TlsAccept> {
    allow: Allow,
    deny: Deny,
    tls_accept: Option<T>,
    sni: Sni,
}

impl<T: TlsAccept + Default> Default for Firewall<T> {
    fn default() -> Self {
        Firewall {
            allow: Allow::default(),
            deny: Deny::default(),
            tls_accept: Some(T::default()),
            sni: Sni::default(),
        }
    }
}

impl Default for Firewall<NoAcmeChallengeException> {
    fn default() -> Self {
        Firewall {
            allow: Allow::default(),
            deny: Deny::default(),
            tls_accept: None,
            sni: Sni::default(),
        }
    }
}

#[derive(Debug, Clone)]
enum Allow {
    All,
    Only(Vec<IpCidr>),
}

impl Default for Allow {
    fn default() -> Self {
        Self::All
    }
}

#[derive(Debug, Clone)]
enum Deny {
    None,
    Only(Vec<IpCidr>),
}

impl Default for Deny {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone)]
enum Sni {
    AcceptIfMissing,
    DenyIfMissing,
    AllowOnly(Vec<String>),
}

impl Default for Sni {
    fn default() -> Self {
        Self::DenyIfMissing
    }
}

pub fn default_firewall() -> Firewall<NoAcmeChallengeException> {
    Firewall::default()
}

impl<T: TlsAccept> Firewall<T> {
    pub fn allow_ip_range(self, cidr: IpCidr) -> Self {
        Firewall {
            allow: match self.allow {
                Allow::All => Allow::Only(vec![cidr]),
                Allow::Only(mut vec) => {
                    vec.push(cidr);
                    Allow::Only(vec)
                }
            },
            deny: self.deny,
            tls_accept: self.tls_accept,
            sni: self.sni,
        }
    }
    pub fn try_allow_ip_range(self, cidr: impl AsRef<str>) -> Result<Self> {
        Ok(self.allow_ip_range(parse_cidr(cidr)?))
    }
    pub fn allow_ip(self, ip: IpAddr) -> Self {
        self.allow_ip_range(IpCidr::new_host(ip))
    }
    pub fn try_allow_ip(self, ip: impl AsRef<str>) -> Result<Self> {
        Ok(self.allow_ip_range(IpCidr::new_host(parse_ip(ip)?)))
    }
    pub fn deny_ip_range(self, cidr: IpCidr) -> Self {
        Firewall {
            allow: self.allow,
            deny: match self.deny {
                Deny::None => Deny::Only(vec![cidr]),
                Deny::Only(mut vec) => {
                    vec.push(cidr);
                    Deny::Only(vec)
                }
            },
            tls_accept: self.tls_accept,
            sni: self.sni,
        }
    }
    pub fn try_deny_ip_range(self, cidr: impl AsRef<str>) -> Result<Self> {
        Ok(self.deny_ip_range(parse_cidr(cidr)?))
    }
    pub fn deny_ip(self, ip: IpAddr) -> Self {
        self.deny_ip_range(IpCidr::new_host(ip))
    }
    pub fn try_deny_ip(self, ip: impl AsRef<str>) -> Result<Self> {
        Ok(self.deny_ip(parse_ip(ip)?))
    }
    pub fn allow_missing_sni(self) -> Self {
        Firewall {
            allow: self.allow,
            deny: self.deny,
            tls_accept: self.tls_accept,
            sni: Sni::AcceptIfMissing,
        }
    }
    pub fn require_sni(self) -> Self {
        Firewall {
            allow: self.allow,
            deny: self.deny,
            tls_accept: self.tls_accept,
            sni: Sni::DenyIfMissing,
        }
    }
    pub fn allow_server_names(self, names: impl Iterator<Item = impl Into<String>>) -> Self {
        Firewall {
            allow: self.allow,
            deny: self.deny,
            tls_accept: self.tls_accept,
            sni: match self.sni {
                Sni::AcceptIfMissing => Sni::AllowOnly(names.map(|it| it.into()).collect()),
                Sni::DenyIfMissing => Sni::AllowOnly(names.map(|it| it.into()).collect()),
                Sni::AllowOnly(mut list) => {
                    for it in names {
                        list.push(it.into());
                    }
                    Sni::AllowOnly(list)
                }
            },
        }
    }
    pub fn with_acme_challenge_exception<R: TlsAccept>(
        self,
        acme_challenge_exception: R,
    ) -> Firewall<R> {
        Firewall {
            allow: self.allow,
            deny: self.deny,
            tls_accept: Some(acme_challenge_exception),
            sni: self.sni,
        }
    }
}

impl<T: TlsAccept> Accept for Firewall<T> {
    fn accept(&self, ip: impl Borrow<IpAddr>, client_hello: Option<impl ClientHello>) -> bool {
        if let Some(client_hello) = client_hello {
            match self.sni {
                Sni::AcceptIfMissing => {}
                Sni::DenyIfMissing => {
                    if client_hello.server_name().is_none() {
                        return false;
                    }
                }
                Sni::AllowOnly(ref names) => {
                    if let Some(name) = client_hello.server_name() {
                        if !names.iter().any(|it| it.as_str() == name) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
            if let Some(ref tls_accept) = self.tls_accept {
                match tls_accept.accept(client_hello) {
                    AcceptDenyOverride::Deny => return false,
                    AcceptDenyOverride::Accept => {}
                    AcceptDenyOverride::AcceptAndBypassAllowList => {
                        if let Deny::Only(ref list) = self.deny {
                            if matches(ip.borrow(), list.iter()) {
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
        }
        if let Allow::Only(ref list) = self.allow {
            if !matches(ip.borrow(), list.iter()) {
                return false;
            }
        }
        if let Deny::Only(ref list) = self.deny {
            if matches(ip.borrow(), list.iter()) {
                return false;
            }
        }
        true
    }
}

fn matches<'a>(addr: &IpAddr, ranges: impl IntoIterator<Item = &'a IpCidr>) -> bool {
    match addr {
        IpAddr::V4(ipv4) => ranges.into_iter().any(|cidr| match cidr {
            IpCidr::V4(cidr) => cidr.contains(ipv4),
            _ => false,
        }),
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                matches(&IpAddr::V4(ipv4), ranges)
            } else {
                ranges.into_iter().any(|cidr| match cidr {
                    IpCidr::V6(cidr) => cidr.contains(ipv6),
                    _ => false,
                })
            }
        }
    }
}

fn parse_ip(ip: impl AsRef<str>) -> Result<IpAddr> {
    let ip = ip.as_ref();
    Ok(IpAddr::from_str(ip).map_err(|_| Error::new_parse_ip_addr_error(ip))?)
}

fn parse_cidr(cidr: impl AsRef<str>) -> Result<IpCidr> {
    let cidr = cidr.as_ref();
    if let Some((address, range)) = cidr.split_once('/') {
        let address = parse_ip(address)?;
        let range = range
            .parse::<u8>()
            .map_err(|_| Error::new_parse_cidr_error(cidr))?;
        Ok(IpCidr::new(address, range).map_err(|_| Error::new_parse_cidr_error(cidr))?)
    } else {
        Err(Error::new_parse_cidr_error(cidr))
    }
}

impl Error {
    fn new_parse_cidr_error(cidr: impl Into<String>) -> Self {
        Self::CidrParseError { cidr: cidr.into() }
    }
    fn new_parse_ip_addr_error(addr: impl Into<String>) -> Self {
        Self::IpAddrParseError { addr: addr.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    macro_rules! ipv4 {
        ($a:expr) => {
            Ipv4Addr::from_str($a).unwrap()
        };
    }

    macro_rules! ipv6 {
        ($a:expr) => {
            Ipv6Addr::from_str($a).unwrap()
        };
    }

    macro_rules! cidr4 {
        ($a:expr, $b:expr) => {
            IpCidr::V4(Ipv4Cidr::new(ipv4!($a), $b).unwrap())
        };
    }

    macro_rules! cidr6 {
        ($a:expr, $b:expr) => {
            IpCidr::V6(Ipv6Cidr::new(ipv6!($a), $b).unwrap())
        };
    }

    struct TestClientHelloNoSni {}

    impl ClientHello for TestClientHelloNoSni {
        fn server_name(&self) -> Option<&str> {
            None
        }
        fn has_alpn(&self, alpn: &[u8]) -> bool {
            match alpn {
                b"http/1.1" => true,
                _ => false,
            }
        }
    }

    struct TestClientHello {}

    const NONE: Option<TestClientHello> = None;

    impl ClientHello for TestClientHello {
        fn server_name(&self) -> Option<&str> {
            Some("www.example.com")
        }
        fn has_alpn(&self, alpn: &[u8]) -> bool {
            match alpn {
                b"acme-tls/1" => true,
                _ => false,
            }
        }
    }

    #[test]
    fn cidr_list() {
        let list = vec![
            cidr4!("173.245.48.0", 20),
            cidr4!("103.21.244.0", 22),
            cidr6!("2400:cb00::", 32),
        ];
        assert!(matches(&IpAddr::V4(ipv4!("173.245.48.100")), &list));
        assert!(!matches(&IpAddr::V4(ipv4!("173.245.40.20")), &list));
        assert!(matches(&IpAddr::V6(ipv6!("2400:cb00:a0::")), &list));
        assert!(!matches(&IpAddr::V6(ipv6!("2400:cb01::")), &list));
        assert!(matches(
            &IpAddr::V6(ipv6!(&format!(
                "::ffff:{:x}{:x}:{:x}{:x}",
                173, 245, 48, 100
            ))),
            &list
        ));
        assert!(matches(&IpAddr::V6(ipv6!("::ffff:173.245.48.100")), &list));
        assert!(!matches(&IpAddr::V6(ipv6!("::ffff:173.245.40.20")), &list));
    }

    #[test]
    fn firewall_ranges() {
        let firewall = default_firewall();
        assert!(firewall.accept(&IpAddr::V4(ipv4!("1.2.3.4")), NONE));
        assert!(firewall.accept(&IpAddr::V4(ipv4!("173.245.48.100")), NONE));
        let firewall = firewall.allow_ip_range(cidr4!("173.245.48.0", 20));
        assert!(!firewall.accept(&IpAddr::V4(ipv4!("1.2.3.4")), NONE));
        assert!(firewall.accept(&IpAddr::V4(ipv4!("173.245.48.100")), NONE));
        let firewall = firewall.deny_ip_range(cidr4!("173.245.48.10", 32));
        assert!(!firewall.accept(&IpAddr::V4(ipv4!("1.2.3.4")), NONE));
        assert!(!firewall.accept(&IpAddr::V4(ipv4!("173.245.48.10")), NONE));
        assert!(firewall.accept(&IpAddr::V4(ipv4!("173.245.48.100")), NONE));
    }

    #[test]
    fn firewall_tls_sni() {
        let firewall = default_firewall()
            .allow_ip_range(cidr4!("173.245.48.0", 20))
            .deny_ip_range(cidr4!("173.245.48.10", 32));
        assert!(!firewall.accept(
            &IpAddr::V4(ipv4!("173.245.48.100")),
            Some(TestClientHelloNoSni {})
        ));
        assert!(firewall.accept(
            &IpAddr::V4(ipv4!("173.245.48.100")),
            Some(TestClientHello {})
        ));
        let firewall = firewall.allow_missing_sni();
        assert!(firewall.accept(
            &IpAddr::V4(ipv4!("173.245.48.100")),
            Some(TestClientHelloNoSni {})
        ));
        let firewall = firewall.allow_server_names(vec!["example.com"].into_iter());
        assert!(!firewall.accept(
            &IpAddr::V4(ipv4!("173.245.48.100")),
            Some(TestClientHello {})
        ));
        let firewall = firewall.allow_server_names(vec!["www.example.com"].into_iter());
        assert!(firewall.accept(
            &IpAddr::V4(ipv4!("173.245.48.100")),
            Some(TestClientHello {})
        ));
    }

    #[test]
    fn firewall_tls_alpn() {
        let firewall = default_firewall()
            .allow_ip_range(cidr4!("173.245.48.0", 20))
            .deny_ip_range(cidr4!("173.245.48.10", 32))
            .allow_missing_sni();
        todo!()
    }
}
