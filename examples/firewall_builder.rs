use firewall::builder::*;
use firewall::{Accept, ClientHello};

#[allow(dead_code)]
fn main() {}

#[allow(dead_code)]
fn default_firewall() -> impl Accept<SimulatedClientHello> {
    Firewall::default()
}

#[allow(dead_code)]
fn firewall_enforcing_tls_with_domain_name() -> impl Accept<SimulatedClientHello> {
    Firewall::default()
        .require_tls()
        .allow_server_name("example.com")
}

#[allow(dead_code)]
fn firewall_only_accepting_ip_range() -> impl Accept<SimulatedClientHello> {
    Firewall::default()
        .try_allow_ip_range("197.234.240.0/22")
        .unwrap()
}

#[allow(dead_code)]
fn firewall_only_accepting_ip_range_with_exception() -> impl Accept<SimulatedClientHello> {
    Firewall::default()
        .try_allow_ip_range("197.234.240.0/22")
        .unwrap()
        .with_exception(AlpnException {})
}

struct AlpnException {}

impl TlsAccept for AlpnException {
    /// Require acme-tls/1 and bypass the allowed list,
    /// or require http1, http2 or http3 and enforce the allowed list.
    fn accept(&self, client_hello: impl ClientHello) -> AcceptDenyOverride {
        if client_hello.has_alpn(b"acme-tls/1") {
            // Accept ACME TLS challenge protocol for renewing certificates
            // This needs to bypass the allow list because the ip ranges
            // of the clients used to verify the challenges is not known.
            AcceptDenyOverride::AcceptAndBypassAllowList
        } else if client_hello.has_alpn(b"http/1.1")
            || client_hello.has_alpn(b"h2")
            || client_hello.has_alpn(b"h3")
        {
            // Require http1.1, http2 or http3
            AcceptDenyOverride::Accept
        } else {
            AcceptDenyOverride::Deny
        }
    }
}

struct SimulatedClientHello {
    server_name: Option<&'static str>,
    alpn: Vec<&'static [u8]>,
}

impl Default for SimulatedClientHello {
    fn default() -> Self {
        Self {
            server_name: None,
            alpn: vec![b"http/1.1"],
        }
    }
}

impl ClientHello for SimulatedClientHello {
    fn server_name(&self) -> Option<&str> {
        self.server_name
    }

    fn has_alpn(&self, alpn: &[u8]) -> bool {
        self.alpn.iter().any(|&it| it == alpn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn default_firewall() {
        let firewall = super::default_firewall();

        // The default firewall configuration accepts all remote connections
        // localhost ipv4
        assert!(firewall.accept(IpAddr::from_str("127.0.0.1").unwrap(), None));
        // example.com ipv4
        assert!(firewall.accept(IpAddr::from_str("93.184.216.34").unwrap(), None));
        // localhost ipv6
        assert!(firewall.accept(IpAddr::from_str("::1").unwrap(), None));
        // example.com ipv6
        assert!(firewall.accept(
            IpAddr::from_str("2606:2800:220:1:248:1893:25c8:1946").unwrap(),
            None
        ));

        // The default firewall configuration requires an SNI extension if Tls is enabled.
        assert!(!firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                ..SimulatedClientHello::default()
            })
        ));
        assert!(firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("localhost"),
                ..SimulatedClientHello::default()
            })
        ));

        // The default firewall configuration requires http/1.1 in the alpn extension if Tls is enabled.
        assert!(!firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("localhost"),
                alpn: vec![]
            })
        ));
    }

    #[test]
    fn firewall_enforcing_domain_name() {
        let firewall = super::firewall_enforcing_tls_with_domain_name();
        assert!(!firewall.accept(IpAddr::from_str("127.0.0.1").unwrap(), None));
        assert!(!firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: None,
                ..SimulatedClientHello::default()
            })
        ));
        assert!(!firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("localhost"),
                ..SimulatedClientHello::default()
            })
        ));
        assert!(firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("example.com"),
                ..SimulatedClientHello::default()
            })
        ));
    }

    #[test]
    fn firewall_only_accepting_ip_range() {
        let firewall = super::firewall_only_accepting_ip_range();
        assert!(!firewall.accept(IpAddr::from_str("127.0.0.1").unwrap(), None));
        assert!(firewall.accept(IpAddr::from_str("197.234.240.1").unwrap(), None));
        assert!(firewall.accept(IpAddr::from_str("197.234.240.10").unwrap(), None));
    }

    #[test]
    fn firewall_only_accepting_ip_range_with_exception() {
        let firewall = super::firewall_only_accepting_ip_range_with_exception();
        assert!(!firewall.accept(IpAddr::from_str("127.0.0.1").unwrap(), None));
        assert!(firewall.accept(
            IpAddr::from_str("197.234.240.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("localhost"),
                alpn: vec![b"h2"]
            })
        ));
        assert!(!firewall.accept(
            IpAddr::from_str("197.234.240.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("localhost"),
                alpn: vec![b"spdy/3"]
            })
        ));
        assert!(firewall.accept(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Some(SimulatedClientHello {
                server_name: Some("localhost"),
                alpn: vec![b"acme-tls/1"]
            })
        ));
    }
}
