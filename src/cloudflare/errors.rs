use crate::cloudflare::errors::Error::IpRangeFetchError;
use std::fmt::{Display, Formatter};

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
