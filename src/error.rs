use std::fmt;
use std::io;

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while running the rathole-socks5 client.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O error.
    Io(io::Error),
    /// Protocol-level decoding error with a static description.
    Protocol(&'static str),
    /// Server reported the service does not exist.
    ServiceNotExist,
    /// Authentication with the server failed (wrong token).
    AuthFailed,
    /// Server replied with an unsupported protocol version.
    ProtocolMismatch {
        /// Version this client speaks.
        expected: u8,
        /// Version the server reported.
        got: u8,
    },
    /// No traffic seen from the server within the configured heartbeat timeout.
    HeartbeatTimeout,
    /// SOCKS5 handshake error with a static description.
    Socks5(&'static str),
    /// Configuration error.
    Config(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Protocol(s) => write!(f, "protocol error: {s}"),
            Error::ServiceNotExist => write!(f, "server reported service not exist"),
            Error::AuthFailed => write!(f, "authentication failed (wrong token?)"),
            Error::ProtocolMismatch { expected, got } => write!(
                f,
                "protocol version mismatch: expected v{expected}, got v{got}"
            ),
            Error::HeartbeatTimeout => write!(f, "heartbeat timeout"),
            Error::Socks5(s) => write!(f, "socks5 error: {s}"),
            Error::Config(s) => write!(f, "config error: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
