use core::fmt;
use minicbor::{decode, encode};
use std::io;

#[derive(Debug)]
pub struct Error(ErrorImpl);

impl Error {
    pub fn message<T: fmt::Display>(msg: T) -> Self {
        Error(ErrorImpl::Message(msg.to_string()))
    }
}

#[derive(Debug)]
enum ErrorImpl {
    Encode(encode::Error<io::Error>),
    Decode(decode::Error),
    Io(io::Error),
    Message(String),
    #[cfg(feature = "ssh")]
    Ssh(ssh_key::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ErrorImpl::Decode(e) => e.fmt(f),
            ErrorImpl::Encode(e) => e.fmt(f),
            ErrorImpl::Message(m) => m.fmt(f),
            ErrorImpl::Io(e) => e.fmt(f),
            #[cfg(feature = "ssh")]
            ErrorImpl::Ssh(e) => e.fmt(f),
        }
    }
}

impl From<encode::Error<io::Error>> for Error {
    fn from(e: encode::Error<io::Error>) -> Self {
        Error(ErrorImpl::Encode(e))
    }
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Error(ErrorImpl::Decode(e))
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error(ErrorImpl::Io(e))
    }
}

#[cfg(feature = "ssh")]
impl From<ssh_key::Error> for Error {
    fn from(e: ssh_key::Error) -> Self {
        Error(ErrorImpl::Ssh(e))
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match &self.0 {
            ErrorImpl::Decode(e) => Some(e),
            ErrorImpl::Encode(e) => Some(e),
            ErrorImpl::Io(e) => Some(e),
            #[cfg(feature = "ssh")]
            ErrorImpl::Ssh(e) => Some(e),
            ErrorImpl::Message(_) => None,
        }
    }
}
