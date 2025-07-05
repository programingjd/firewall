use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq)]
pub enum Error {
    CidrParseError { cidr: String },
    IpAddrParseError { addr: String },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::CidrParseError { ref cidr } => write!(f, "could not parse \"{cidr}\" as cidr"),
            Self::IpAddrParseError { ref addr } => {
                write!(f, "could not parse \"{addr}\" as ip address")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::CidrParseError { cidr: _ } => None,
            Self::IpAddrParseError { addr: _ } => None,
        }
    }
}
