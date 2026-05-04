//! Binary entrypoint for `rathole-socks5`.
//!
//! Parses CLI flags, installs a tracing subscriber, then runs the client
//! until SIGINT or SIGTERM. Behind the `cli` cargo feature so library-only
//! consumers do not pay for `clap`.

use clap::Parser;
use rathole_socks5::cli::Cli;
use tokio::signal;
use tokio::sync::broadcast;
use tracing_subscriber::filter::LevelFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);
    tracing_subscriber::fmt().with_max_level(level).init();

    let cli = Cli::parse();
    let config = cli.into_config();

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let client = tokio::spawn(async move {
        if let Err(e) = rathole_socks5::run(config, shutdown_rx).await {
            tracing::error!(error = %e, "client exited with error");
        }
    });

    wait_for_signal().await;
    let _ = shutdown_tx.send(true);
    let _ = client.await;
    Ok(())
}

#[cfg(unix)]
async fn wait_for_signal() {
    use signal::unix::{signal as unix_signal, SignalKind};
    let mut sigint = unix_signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => tracing::info!("received SIGINT"),
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = signal::ctrl_c().await;
    tracing::info!("received Ctrl-C");
}

