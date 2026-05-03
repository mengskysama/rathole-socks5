//! The rathole client: opens a control channel, then for each
//! `CreateDataChannel` command from the server it opens a data channel and
//! lets [`crate::socks5`] handle the SOCKS5 negotiation that the visitor
//! pipes through that channel.

use crate::config::ClientConfig;
use crate::error::{Error, Result};
use crate::protocol::{
    self, encode_hello, read_ack, read_control_cmd, read_data_cmd, read_hello, write_auth, Ack,
    ControlCmd, DataCmd, HelloKind, PROTO_V1,
};
use crate::socks5;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::{self, Instant};
use tracing::{debug, error, info, warn};

/// Run the client until shutdown is signalled.
pub async fn run(config: ClientConfig, mut shutdown: broadcast::Receiver<bool>) -> Result<()> {
    config.validate()?;
    info!(
        remote = %config.remote_addr,
        service = %config.service_name,
        "rathole-socks5 client starting"
    );

    let handle = tokio::spawn(run_service(config, shutdown.resubscribe()));
    let _ = shutdown.recv().await;
    info!("shutdown signal received");
    handle.abort();
    Ok(())
}

/// Keep a control channel alive, reconnecting on failure.
async fn run_service(config: ClientConfig, mut shutdown: broadcast::Receiver<bool>) {
    let retry = Duration::from_secs(config.retry_interval.max(1));
    loop {
        let started = Instant::now();
        let res = tokio::select! {
            _ = shutdown.recv() => return,
            r = run_control_channel(&config) => r,
        };

        match res {
            Ok(()) => debug!(service = %config.service_name, "control channel closed"),
            Err(e) => {
                if started.elapsed() > Duration::from_secs(3) {
                    warn!(service = %config.service_name, error = %e, "control channel lost, reconnecting");
                } else {
                    error!(service = %config.service_name, error = %e, "control channel failed");
                }
            }
        }

        tokio::select! {
            _ = shutdown.recv() => return,
            _ = time::sleep(retry) => {}
        }
    }
}

/// Establish the control channel and loop on server commands.
async fn run_control_channel(cfg: &ClientConfig) -> Result<()> {
    let mut conn = TcpStream::connect(&cfg.remote_addr).await?;
    conn.set_nodelay(true).ok();

    let svc_digest = protocol::digest(cfg.service_name.as_bytes());
    conn.write_all(&encode_hello(HelloKind::Control, PROTO_V1, &svc_digest))
        .await?;
    conn.flush().await?;

    let (kind, version, nonce) = read_hello(&mut conn).await?;
    if version != PROTO_V1 {
        return Err(Error::ProtocolMismatch { expected: PROTO_V1, got: version });
    }
    if kind != HelloKind::Control {
        return Err(Error::Protocol("server returned unexpected hello kind"));
    }

    let session_key = protocol::session_key(&cfg.token, &nonce);
    write_auth(&mut conn, &session_key).await?;

    match read_ack(&mut conn).await? {
        Ack::Ok => {}
        Ack::ServiceNotExist => return Err(Error::ServiceNotExist),
        Ack::AuthFailed => return Err(Error::AuthFailed),
    }

    info!(service = %cfg.service_name, "control channel established");

    loop {
        let read = read_control_cmd(&mut conn);
        let cmd = if cfg.heartbeat_timeout > 0 {
            tokio::select! {
                r = read => r?,
                _ = time::sleep(Duration::from_secs(cfg.heartbeat_timeout)) => {
                    return Err(Error::HeartbeatTimeout);
                }
            }
        } else {
            read.await?
        };

        match cmd {
            ControlCmd::HeartBeat => debug!(service = %cfg.service_name, "heartbeat"),
            ControlCmd::CreateDataChannel => {
                let remote = cfg.remote_addr.clone();
                let key = session_key;
                let svc = cfg.service_name.clone();
                let auth = cfg.socks5_auth().map(|(u, p)| (u.to_owned(), p.to_owned()));
                tokio::spawn(async move {
                    if let Err(e) = run_data_channel(&remote, &key, auth).await {
                        debug!(service = %svc, error = %e, "data channel ended");
                    }
                });
            }
        }
    }
}

/// One data channel: handshake, SOCKS5, bidirectional copy.
async fn run_data_channel(
    remote_addr: &str,
    session_key: &protocol::Digest,
    auth: Option<(String, String)>,
) -> Result<()> {
    let mut conn = TcpStream::connect(remote_addr).await?;
    conn.set_nodelay(true).ok();

    conn.write_all(&encode_hello(HelloKind::Data, PROTO_V1, session_key))
        .await?;
    conn.flush().await?;

    match read_data_cmd(&mut conn).await? {
        DataCmd::StartForwardTcp => {}
        DataCmd::StartForwardUdp => {
            return Err(Error::Protocol("server requested UDP; only TCP/SOCKS5 supported"));
        }
        DataCmd::StartForwardSocketStream => {
            return Err(Error::Protocol("server requested unix-socket; not supported"));
        }
    }

    let auth_ref = auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
    let (mut upstream, target) = socks5::accept(&mut conn, auth_ref).await?;
    debug!(target = %target, "relay started");
    let _ = tokio::io::copy_bidirectional(&mut conn, &mut upstream).await;
    debug!(target = %target, "relay closed");
    Ok(())
}
