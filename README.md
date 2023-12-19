
The `Firewall` trait is meant to be used by servers to abstract the logic of blocking incoming requests.

Its `accept` method is provided an ip address (v4 or v6) and if the connection is over TLS,
access to the server name from the [SNI extension](https://en.wikipedia.org/wiki/Server_Name_Indication), and the client supported protocols from the [ALPN extension](https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation).

The `ClientHello` trait is used to make the Firewall trait agnostic over the TLS implementation.

---

For servers who only need/want those 2 traits, the default features should be disabled.

`Cargo.toml`
```toml
[dependencies.firewall]
version = "0.1"
default-features = false
```

---

The `default` feature provides an implementation 
