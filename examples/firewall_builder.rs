use firewall::builder::*;
use firewall::Accept;

#[allow(dead_code)]
fn main() {}

#[allow(dead_code)]
fn default_firewall() -> impl Accept {
    Firewall::default()
}

#[allow(dead_code)]
fn firewall_only_accepting_ip_range() -> impl Accept {
    Firewall::default()
        .try_allow_ip_range("197.234.240.0/22")
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_firewall() {
        let firewall = super::default_firewall();
    }
}
