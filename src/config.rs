//! Configuration types for the rathole-socks5 client.

use crate::error::{Error, Result};

/// Default heartbeat timeout (seconds) — must be larger than the server's
/// `heartbeat_interval` (default 30s in upstream rathole).
pub const DEFAULT_HEARTBEAT_TIMEOUT: u64 = 40;

/// Default retry interval (seconds) used between reconnection attempts.
pub const DEFAULT_RETRY_INTERVAL: u64 = 1;

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// `host:port` of the rathole server's control listener.
    pub remote_addr: String,
    /// Service name. Must match a `[server.services.<name>]` entry on the
    /// rathole server.
    pub service_name: String,
    /// Shared secret token for the service.
    pub token: String,
    /// How long the client waits without receiving any control frame before
    /// declaring the connection dead and reconnecting. `0` disables.
    pub heartbeat_timeout: u64,
    /// Sleep between reconnection attempts (seconds).
    pub retry_interval: u64,
    /// SOCKS5 username. When set together with `socks5_password`, incoming
    /// connections must authenticate via RFC 1929 username/password.
    /// When `None`, no authentication is required.
    pub socks5_username: Option<String>,
    /// SOCKS5 password. Must be set together with `socks5_username`.
    pub socks5_password: Option<String>,
}

impl ClientConfig {
    /// Convenience constructor with default timeouts and no SOCKS5 auth.
    pub fn new(
        remote_addr: impl Into<String>,
        service_name: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            remote_addr: remote_addr.into(),
            service_name: service_name.into(),
            token: token.into(),
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            retry_interval: DEFAULT_RETRY_INTERVAL,
            socks5_username: None,
            socks5_password: None,
        }
    }

    /// Returns `Some((username, password))` when SOCKS5 auth is configured.
    pub fn socks5_auth(&self) -> Option<(&str, &str)> {
        match (&self.socks5_username, &self.socks5_password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.remote_addr.is_empty() {
            return Err(Error::Config("remote_addr is empty"));
        }
        if self.service_name.is_empty() {
            return Err(Error::Config("service_name is empty"));
        }
match (&self.socks5_username, &self.socks5_password) {
            (Some(_), None) => return Err(Error::Config("socks5_password missing")),
            (None, Some(_)) => return Err(Error::Config("socks5_username missing")),
            _ => {}
        }
        Ok(())
    }
}
