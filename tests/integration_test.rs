//! End-to-end test against a real upstream rathole server.
//!
//! Topology:
//!
//! ```text
//!     test                                  rathole-socks5
//!      │                                    (this crate)
//!      │ SOCKS5 CONNECT                      │
//!      ▼                                     │
//!   127.0.0.1:13334  ◄── data channels ──────┤
//!   (rathole server                          │
//!    visitor port)                           │
//!      ▲                                     │
//!      │ control channel                     │
//!      └─── 127.0.0.1:13333 ─────────────────┘
//!                rathole server
//!
//!     SOCKS5 target → 127.0.0.1:<echo_port>  (in-test echo origin)
//! ```
//!
//! The test boots a rathole server (using a git dev-dependency on
//! `github.com/rathole-org/rathole`, pinned by `rev` — exactly like
//! upstream's own integration tests use the rathole crate), then our
//! client, then drives a SOCKS5 CONNECT through the visitor port and
//! verifies bytes echo back.

use std::time::Duration;

use anyhow::Result;
use rand::RngCore;
use rathole_socks5::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time;
use tracing_subscriber::EnvFilter;

mod common;

const SERVER_CONTROL_ADDR: &str = "127.0.0.1:13333";
const SERVER_VISITOR_ADDR: &str = "127.0.0.1:13334";
const SERVICE_NAME: &str = "socks_test";
const SERVICE_TOKEN: &str = "rathole_socks5_test_token";
const SERVER_CONFIG: &str = "tests/fixtures/server.toml";

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
}

/// Drives one SOCKS5 round-trip with random payload.
async fn echo_once(echo_addr: &str) -> Result<()> {
    let host_port: Vec<&str> = echo_addr.rsplitn(2, ':').collect();
    let port: u16 = host_port[0].parse()?;
    let host = host_port[1];

    let mut conn = common::socks5_connect(SERVER_VISITOR_ADDR, host, port).await?;
    let mut wr = [0u8; 1024];
    let mut rd = [0u8; 1024];
    rand::thread_rng().fill_bytes(&mut wr);
    conn.write_all(&wr).await?;
    conn.read_exact(&mut rd).await?;
    anyhow::ensure!(wr == rd, "echo payload mismatch");
    conn.shutdown().await.ok();
    Ok(())
}

#[tokio::test]
async fn end_to_end_socks5_through_real_rathole_server() -> Result<()> {
    init_tracing();

    // 1. Echo origin that visitors will reach via SOCKS5 CONNECT.
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?.to_string();
    drop(echo_listener); // free the port for the spawned server below
    let echo_addr_clone = echo_addr.clone();
    tokio::spawn(async move {
        let _ = common::spawn_echo_server(&echo_addr_clone).await;
    });
    common::wait_until(Duration::from_secs(2), || {
        let addr = echo_addr.clone();
        async move {
            TcpStream::connect(&addr).await?;
            Ok(())
        }
    })
    .await?;

    // 2. Real rathole server.
    let (server_shutdown_tx, server_shutdown_rx) = broadcast::channel(1);
    let server = tokio::spawn(async move {
        common::run_rathole_server(SERVER_CONFIG, server_shutdown_rx)
            .await
            .unwrap();
    });
    common::wait_until(Duration::from_secs(5), || async {
        TcpStream::connect(SERVER_CONTROL_ADDR).await?;
        Ok(())
    })
    .await?;

    // 3. Our client.
    let (client_shutdown_tx, client_shutdown_rx) = broadcast::channel(1);
    let client_cfg = ClientConfig {
        remote_addr: SERVER_CONTROL_ADDR.to_string(),
        service_name: SERVICE_NAME.to_string(),
        token: SERVICE_TOKEN.to_string(),
        heartbeat_timeout: 40,
        retry_interval: 1,
        socks5_username: None,
        socks5_password: None,
    };
    let client = tokio::spawn(async move {
        rathole_socks5::run(client_cfg, client_shutdown_rx)
            .await
            .unwrap();
    });

    // 4. Wait for the visitor port to start accepting (rathole opens it
    // only after the client has authenticated).
    common::wait_until(Duration::from_secs(10), || async {
        TcpStream::connect(SERVER_VISITOR_ADDR).await?;
        Ok(())
    })
    .await?;
    // small grace so the server fully wires up the new control channel
    time::sleep(Duration::from_millis(300)).await;

    // 5. Drive several echo round-trips.
    for _ in 0..5 {
        echo_once(&echo_addr).await?;
    }

    // 6. Concurrent visitors.
    let mut hs = Vec::new();
    for _ in 0..4 {
        let a = echo_addr.clone();
        hs.push(tokio::spawn(async move { echo_once(&a).await }));
    }
    for h in hs {
        h.await??;
    }

    // 7. Shutdown.
    let _ = client_shutdown_tx.send(true);
    let _ = server_shutdown_tx.send(true);
    let _ = client.await;
    let _ = server.await;
    Ok(())
}
