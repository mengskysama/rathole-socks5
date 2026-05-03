//! `clap` definitions for the `rathole-socks5` binary.

use crate::config::{ClientConfig, DEFAULT_HEARTBEAT_TIMEOUT, DEFAULT_RETRY_INTERVAL};
use clap::Parser;

/// Parsed command-line arguments for the `rathole-socks5` binary.
#[derive(Debug, Parser)]
#[command(
    name = "rathole-socks5",
    about = "rathole client that exposes a SOCKS5 entry point at the server-side public port",
    version
)]
pub struct Cli {
    /// `host:port` of the rathole server's control listener.
    #[arg(long, value_name = "HOST:PORT")]
    pub remote_addr: String,

    /// Service name (must match `[server.services.<name>]` on the server).
    #[arg(long, value_name = "NAME")]
    pub service: String,

    /// Shared-secret token for the service.
    #[arg(long, value_name = "TOKEN")]
    pub token: String,

    /// Heartbeat timeout in seconds. `0` disables the timeout.
    #[arg(long, default_value_t = DEFAULT_HEARTBEAT_TIMEOUT)]
    pub heartbeat_timeout: u64,

    /// Sleep between reconnection attempts in seconds.
    #[arg(long, default_value_t = DEFAULT_RETRY_INTERVAL)]
    pub retry_interval: u64,

    /// SOCKS5 username for incoming connections. Must be paired with
    /// `--socks5-password`. When omitted, no authentication is required.
    #[arg(long, value_name = "USERNAME", requires = "socks5_password")]
    pub socks5_username: Option<String>,

    /// SOCKS5 password for incoming connections. Must be paired with
    /// `--socks5-username`.
    #[arg(long, value_name = "PASSWORD", requires = "socks5_username")]
    pub socks5_password: Option<String>,
}

impl Cli {
    /// Convert the parsed CLI into a [`ClientConfig`].
    pub fn into_config(self) -> ClientConfig {
        ClientConfig {
            remote_addr: self.remote_addr,
            service_name: self.service,
            token: self.token,
            heartbeat_timeout: self.heartbeat_timeout,
            retry_interval: self.retry_interval,
            socks5_username: self.socks5_username,
            socks5_password: self.socks5_password,
        }
    }
}
