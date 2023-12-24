[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![crates.io Version](https://img.shields.io/crates/v/firewall.svg)](https://crates.io/crates/firewall)
[![Documentation](https://docs.rs/firewall/badge.svg)](https://docs.rs/firewall)

The `Firewall` trait is meant to be used by servers to abstract the logic of blocking incoming requests.

Its `accept` method is provided an ip address (v4 or v6) and if the connection is over TLS,
access to the server name from the [SNI extension](https://en.wikipedia.org/wiki/Server_Name_Indication), and the client supported protocols from the [ALPN extension](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).

The `ClientHello` trait is used to make the `Firewall` trait agnostic over the TLS implementation.

---

For servers who only need/want those 2 traits, the default features should be disabled.

`Cargo.toml`
```toml
[dependencies.firewall]
version = "0.1"
default-features = false
```

---

The `rustls` feature provides an implementation of the `ClientHello` trait for [rustls](https://crates.io/crates/rustls).

The `openssl` feature provides an implementation of the `ClientHello` trait for [openssl](https://crates.io/crates/openssl).

---

The `builder` feature provides an implementation of the `Firewall` trait.


```rust
let firewall = Firewall::default()
  .require_sni()
  .allow_server_name("example.com")
  .allow_ip_range("1.2.3.4/30")
```

You can have a list of allowed ip ranges, and a list of denied ip ranges (both ipv4 and ipv6).

You can also add an exception based on the TLS ClientHello content.

A good use case for this is if you want to renew [Let's Encrypt](https://letsencrypt.org/) certificates with the `TLS-ALPN-01` challenge. `Let's Encrypt` doesn't provide a list of ips that they use to validate the challenges. You can add an exception to bypass the allow list if the `acme-tls/1` protocol is listed in the TLS [ALPN extension](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).

```rust
struct AcmeTlsSni01Exception {}
impl TlsAccept for AcmeTlsSni01Exception {
    fn accept(&self, client_hello: impl ClientHello) -> AcceptDenyOverride {
        if client_hello.has_alpn(b"acme-tls/1") {
            AcceptDenyOverride::AcceptAndBypassAllowList
        } else if client_hello.has_alpn(b"http/1.1") {
            AcceptDenyOverride::Accept
        } else {
            AcceptDenyOverride::Deny
        }
    }
}

let firewall = firewall
  .with_exception(AcmeTlsSni01Exception {});
```

---

The `cloudflare` feature adds a method on `Firewall` to apply the official allow list for Cloudflare servers.

```rust
let firewall = Firewall::default()
    .try_allow_cloudflare_ips()
    .await
    .unwrap();
```

This is useful if your server is behind the Cloudflare CDN and you don't want to allow any other server to contact your origin server directly.

There's a public `fetch_cloudflare_ip_ranges()` function available if you want to make sure that the list is up to date.
