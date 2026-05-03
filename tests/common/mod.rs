//! Test helpers: spin up a real rathole server (via a git dev-dependency
//! on `github.com/rathole-org/rathole`, pinned by `rev` in `Cargo.toml`)
//! and a tiny TCP echo origin so each integration test gets a fresh,
//! end-to-end environment.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

/// Boot a real upstream rathole server using the provided TOML config.
///
/// Mirrors `rathole/tests/common/mod.rs` upstream, so we exercise the
/// same public entrypoint the upstream test suite uses.
pub async fn run_rathole_server(
    config_path: &str,
    shutdown_rx: broadcast::Receiver<bool>,
) -> Result<()> {
    let cli = rathole::Cli {
        config_path: Some(PathBuf::from(config_path)),
        server: true,
        client: false,
        ..Default::default()
    };
    rathole::run(cli, shutdown_rx).await
}

/// Spawn an echo server on `addr` (drops on first error / accept failure).
pub async fn spawn_echo_server(addr: &str) -> Result<()> {
    let l = TcpListener::bind(addr).await?;
    loop {
        let (conn, _) = l.accept().await?;
        tokio::spawn(async move {
            let _ = echo(conn).await;
        });
    }
}

async fn echo(conn: TcpStream) -> Result<()> {
    let (mut rd, mut wr) = conn.into_split();
    io::copy(&mut rd, &mut wr).await?;
    Ok(())
}

/// Open a TCP connection to `proxy_addr` and complete a SOCKS5 CONNECT
/// handshake to `target` (`host:port`). Returns the stream ready for
/// payload bytes.
pub async fn socks5_connect(proxy_addr: &str, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect(proxy_addr).await?;

    // greeting: VER=5 NMETHODS=1 NO_AUTH
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).await?;
    anyhow::ensure!(greet == [0x05, 0x00], "bad greeting reply: {greet:?}");

    // request: VER=5 CMD=CONNECT RSV=0 ATYP=domain
    let host = target_host.as_bytes();
    anyhow::ensure!(host.len() <= 255, "host name too long");
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    anyhow::ensure!(head[0] == 0x05, "bad reply version");
    anyhow::ensure!(head[1] == 0x00, "socks5 reply error code: {}", head[1]);

    // skip BND.ADDR / BND.PORT
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        atyp => anyhow::bail!("unexpected ATYP in reply: {atyp}"),
    };
    let mut junk = vec![0u8; skip];
    s.read_exact(&mut junk).await?;

    Ok(s)
}

/// Wait until `f()` returns `Ok(())`, polling every 50ms, up to `timeout`.
pub async fn wait_until<F, Fut>(timeout: Duration, mut f: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if f().await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("wait_until timed out after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
