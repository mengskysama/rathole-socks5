//! `rathole-socks5` — minimal Rust client that exposes a SOCKS5 entry point
//! at the public side of an upstream `rathole` server.
//!
//! ## Quick start (library)
//!
//! ```no_run
//! use rathole_socks5::ClientConfig;
//! use tokio::sync::broadcast;
//!
//! # async fn run() -> rathole_socks5::Result<()> {
//! let cfg = ClientConfig::new(
//!     "rathole.example.com:2333",
//!     "my_socks",
//!     "shared-secret-token",
//! );
//! let (_tx, rx) = broadcast::channel(1);
//! rathole_socks5::run(cfg, rx).await
//! # }
//! ```
//!
//! ## Quick start (CLI)
//!
//! ```bash
//! rathole-socks5 \
//!   --remote-addr rathole.example.com:2333 \
//!   --service my_socks \
//!   --token shared-secret-token
//! ```

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod client;
mod config;
mod error;
mod protocol;
mod socks5;

#[cfg(feature = "cli")]
pub mod cli;

pub use client::run;
pub use config::{ClientConfig, DEFAULT_HEARTBEAT_TIMEOUT, DEFAULT_RETRY_INTERVAL};
pub use error::{Error, Result};
